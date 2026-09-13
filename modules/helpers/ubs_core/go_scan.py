"""ubs_core.go_scan — contract-v2 orchestrator for the Go module (bead 0xjg.6).

ONE process replacing the legacy ~250-400-spawn scan (modules/ubs-golang.sh,
v7.1.4): pattern tables (ubs_core.go_patterns.*, ports of the rg pipelines),
heredoc detector ports (ubs_core.go_detectors.*), the registered Go analyzers
(taint_go + ctcompare_go; guards_generic/narrowing_go have no legacy Go
counterpart and stay gated behind --enable-new-analyzers), the consolidated
ast-grep pack bridge (ubs_core.go_ast over ubs_core.go_rules), the computed
ratio/fallback checks that legacy expressed as multi-count bash comparisons,
and the project-inventory checks (go.mod/go.sum/go.work/test-file presence).

Output contract mirrors js_scan/py_scan: NDJSON findings sink, legacy text
renderer, fd-3/`--json-out` summary object with module-level findings[].
Contract-v2 orchestrator for modules/ubs-golang.sh (beads 0xjg.6 and 0xjg.18).

Parity notes:
- Grep-pipeline counts are DISTINCT MATCHING LINES across the file list with
  `ubs:ignore` lines dropped (legacy count_lines, ubs-golang.sh 365).
- ast-grep records carry NO marker filtering and text severities come from
  the per-callsite consumption table — the legacy ast_count walk had no
  marker awareness and every print_finding hardcoded its severity.
- go.tls-insecure-skip / go.exec-sh-c / go.time-after-in-loop /
  go.http-response-body-not-closed / go.sql.rows-not-closed keep their legacy
  "AST count, else regex fallback" semantics in computed_checks(); the
  multi-count ratio checks (WaitGroup, mutex, Tx, os.Open/Close, DB context,
  Shutdown) and the inventory checks live there too.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ubs_core.registry import RunContext
from ubs_core.io import read_ndjson

MARKER = "ubs:ignore"

_CATEGORY_SLUGS = {
    1: "concurrency", 2: "channels", 3: "context", 4: "http",
    5: "resource-lifecycle", 6: "error-handling", 7: "json-encoding",
    8: "filesystem", 9: "security", 10: "reflection-unsafe",
    11: "imports", 12: "build", 13: "testing", 14: "logging",
    15: "style", 16: "panic-time", 17: "lifecycle-correlation",
    18: "tooling", 19: "dependencies", 20: "defer-nil", 21: "database",
    22: "shutdown",
}

# Legacy print_header titles, in category order (rendered before a section).
_SECTION_HEADERS = {
    1: "1. CONCURRENCY & GOROUTINE SAFETY",
    2: "2. CHANNELS & SELECT",
    3: "3. CONTEXT PROPAGATION & CANCELLATION",
    4: "4. HTTP CLIENT/SERVER SAFETY",
    5: "5. RESOURCE LIFECYCLE & DEFER",
    6: "6. ERROR HANDLING & WRAPPING",
    7: "7. JSON & ENCODING",
    8: "8. FILESYSTEM & I/O",
    9: "9. CRYPTOGRAPHY & SECURITY",
    10: "10. REFLECTION & UNSAFE",
    11: "11. IMPORT HYGIENE",
    12: "12. MODULE & BUILD HYGIENE",
    13: "13. TESTING PRACTICES",
    14: "14. LOGGING & PRINTF",
    15: "15. STYLE & MODERNIZATION",
    16: "16. PANIC/RECOVER & TIME PATTERNS (AST Pack)",
    17: "17. RESOURCE LIFECYCLE CORRELATION",
    18: "18. GO TOOLING (OPTIONAL)",
    19: "19. DEPENDENCY & BUILD DRIFT",
    20: "20. NIL PANICS FROM DEFER ORDERING (AST)",
    21: "21. DATABASE & SQL ROBUSTNESS",
    22: "22. SHUTDOWN & RESOURCE RELEASE (HTTP/NET)",
}

# Legacy print_subheader texts that manifest cases assert, keyed by the rule
# prefix they announce (the taint heredoc prints its own subheader, 736).
_SUBHEADERS = {
    9: {"go.taint.": "Lightweight taint analysis"},
}

# Legacy print_finding "good" notes rendered when a category produced no
# records at all.
_GOOD_NOTES = {
    1: "All goroutines handle errors explicitly",
    17: "All tracked resource acquisitions have matching cleanups",
}

# Rule-id prefix → legacy category (analyzer findings).
_RULE_CATEGORY = (
    ("go.taint.", 9),
    ("go.ctcompare.", 9),
)

# Legacy index_project inventory (ubs-golang.sh 2829-2874).
_INVENTORY_NAMES = ("go.mod", "go.sum", "go.work", "go.work.sum")
_INVENTORY_EXCLUDES = {
    ".git", ".svn", ".hg", "vendor", "third_party", "Godeps", "node_modules",
    ".cache", "build", "dist", "out", "tmp", ".idea", ".vscode", ".vs",
    "go.work.d",
}

_GO_DIRECTIVE_RE = re.compile(r"^[ \t]*go[ \t]+([0-9]+\.[0-9]+)", re.MULTILINE)


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity); the
    first entry whose count > min_count wins. exclude_regex drops matching
    lines (legacy `grep -v` post-filters); require_regex keeps only matching
    lines (legacy `grep -E` post-filters); marker lines are always dropped
    (legacy count_lines).
    """

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...]
    case_insensitive: bool = False
    exclude_regex: re.Pattern[str] | None = None
    require_regex: re.Pattern[str] | None = None


def iter_matches(pattern: Pattern, text: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for matches, skipping filtered lines."""
    for match in pattern.regex.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.start())
        if line_end == -1:
            line_end = len(text)
        line_text = text[line_start:line_end]
        if MARKER in line_text:
            continue  # legacy count_lines drops marker lines from counts
        if pattern.exclude_regex is not None and pattern.exclude_regex.search(line_text):
            continue
        if pattern.require_regex is not None and not pattern.require_regex.search(line_text):
            continue
        yield line_no, line_text.strip()[:240]


def resolve_severity(pattern: Pattern, count: int) -> str | None:
    for min_count, severity in pattern.thresholds:
        if count > min_count:
            return severity
    return None


def scan_patterns(patterns: Sequence[Pattern], files: Sequence[Path], sink, skip: set[int], prefilter: Any = None) -> dict[str, int]:
    """Run every pattern over the file list, writing sink records.

    Legacy parity semantics: counts are DISTINCT MATCHING LINES across the
    whole file list and severity resolves ONCE per pattern from that
    project-wide count. Returns severity counters.
    """
    counters = {"critical": 0, "warning": 0, "info": 0}
    active = [p for p in patterns if p.category not in skip]
    if not active:
        return counters
    texts: dict[Path, str] = {}
    for path in files:
        try:
            texts[path] = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    for pattern in active:
        flags = re.IGNORECASE if pattern.case_insensitive else 0
        regex = pattern.regex
        if flags and not (regex.flags & re.IGNORECASE):
            regex = re.compile(regex.pattern, flags)
        hits: list[tuple[Path, int, str]] = []
        seen: set[tuple[Path, int]] = set()
        for path, text in texts.items():
            if prefilter is not None and pattern.rule_id not in prefilter.candidate_rules_for(path):
                continue
            for line_no, line_text in iter_matches(pattern, text):
                key = (path, line_no)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((path, line_no, line_text))
        if not hits:
            continue
        severity = resolve_severity(pattern, len(hits))
        if severity is None:
            continue
        counters[severity] = counters.get(severity, 0) + len(hits)
        for path, line_no, line_text in hits:
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"golang.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "message": f"{pattern.title} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def load_patterns() -> list[Pattern]:
    """Aggregate PATTERNS from every ubs_core.go_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import go_patterns

    patterns: list[Pattern] = []
    for module_info in pkgutil.iter_modules(go_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"ubs_core.go_patterns.{module_info.name}")
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns


def _record_category(finding: dict) -> int | None:
    """Map an analyzer finding's rule id to its legacy category number."""
    rule = str(finding.get("rule", ""))
    for prefix, category in _RULE_CATEGORY:
        if rule.startswith(prefix):
            return category
    return None


def run_analyzers(files: Sequence[Path], sink, skip: set[int] | None = None,
                  enable_new: bool = False, prefilter: Any = None) -> None:
    """Run registered Go analyzers (taint, ctcompare).

    ``guards_generic``/``narrowing_go`` have no legacy Go counterpart — they
    stay off unless --enable-new-analyzers is set, so v2 totals match legacy.
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import analyzers_for_lang

    for analyzer in analyzers_for_lang("go"):
        if analyzer.layer in ("guards", "narrowing") and not enable_new:
            continue
        if prefilter is not None:
            target_files = prefilter.filter_files_for_analyzer(analyzer.name, files)
        else:
            target_files = list(files)
        if not target_files:
            continue
        ctx = RunContext(lang="go", files=target_files)
        for finding in analyzer.run(ctx):
            if skip and _record_category(finding) in skip:
                continue
            sink.write(json.dumps({
                "rule": finding.get("rule", ""),
                "category_id": finding.get("category_id", "golang.security"),
                "path": finding.get("path", ""),
                "line": int(finding.get("line", 0) or 0),
                "col": int(finding.get("col", 1) or 1),
                "severity": finding.get("severity", "warning"),
                "message": finding.get("message", ""),
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def run_detectors(files: Sequence[Path], sink, skip: set[int] | None = None) -> None:
    """Run ubs_core.go_detectors.* modules (legacy heredoc detector ports).

    Protocol (mirrors py_detectors): RULE_ID, CATEGORY, TITLE, SEVERITY,
    DESCRIPTION constants and ``find(files)`` yielding
    (path, line, col, detail).
    """
    import importlib
    import pkgutil

    from ubs_core import go_detectors

    for module_info in pkgutil.iter_modules(go_detectors.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.go_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.go_scan] detector module {module_info.name} failed: {exc}\n")
            continue
        find = getattr(module, "find", None)
        if find is None:
            continue
        category = int(getattr(module, "CATEGORY", 9))
        if skip and category in skip:
            continue
        rule_id = str(getattr(module, "RULE_ID", f"go.cat{category}.{module_info.name}"))
        title = str(getattr(module, "TITLE", rule_id))
        severity = str(getattr(module, "SEVERITY", "warning"))
        slug = slug_for_category(category)
        for hit in find(files):
            path, line_no, col, detail = hit
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"golang.{slug}",
                "path": str(path),
                "line": int(line_no),
                "col": int(col),
                "severity": severity,
                "message": f"{title} — {detail}"[:300] if detail else title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Computed checks: legacy bash multi-count ratios, AST-count-gated regex
# fallbacks, and the project inventory. Each returns sink records.
# ─────────────────────────────────────────────────────────────────────────────

def _iter_file_lines(files: Sequence[Path], go_only: bool = True):
    for path in files:
        if go_only and path.suffix != ".go":
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        yield path, lines


def _match_lines(files: Sequence[Path], regex: re.Pattern[str], go_only: bool = True,
                 drop_markers: bool = True) -> list[tuple[Path, int, str]]:
    """Distinct matching lines across the file list (legacy grep_count_scoped)."""
    hits: list[tuple[Path, int, str]] = []
    seen: set[tuple[str, int]] = set()
    for path, lines in _iter_file_lines(files, go_only=go_only):
        for idx, line in enumerate(lines, 1):
            if drop_markers and MARKER in line:
                continue
            if regex.search(line):
                key = (str(path), idx)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((path, idx, line.strip()[:240]))
    return hits


def _count(files: Sequence[Path], regex: re.Pattern[str], go_only: bool = True,
           drop_markers: bool = True) -> int:
    return len(_match_lines(files, regex, go_only=go_only, drop_markers=drop_markers))


def _rec(rule_id: str, category: int, severity: str, path, line_no: int,
         message: str) -> dict:
    return {
        "rule": rule_id,
        "category_id": f"golang.{slug_for_category(category)}",
        "path": str(path),
        "line": int(line_no),
        "col": 1,
        "severity": severity,
        "message": message[:300],
        "suppressed": False,
    }


def _ratio_records(rule_id: str, category: int, severity: str, title: str,
                   numerator: list[tuple[Path, int, str]], diff: int) -> list[dict]:
    """Anchor a legacy diff-count finding at the first `diff` numerator lines."""
    return [
        _rec(rule_id, category, severity, path, line_no, f"{title} — {text}")
        for path, line_no, text in numerator[:max(0, diff)]
    ]


def _wg_balance(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 4969-4976
    add_re = re.compile(r"(wg|WaitGroup|waitGroup|waitgroup|group)\.Add\(")
    done_re = re.compile(r"(wg|WaitGroup|waitGroup|waitgroup|group)\.Done\(")
    add = _count(files, add_re)
    done = _count(files, done_re)
    if add > done + 1:
        return _ratio_records(
            "go.concurrency.waitgroup-imbalance", 1, "warning",
            "WaitGroup Add exceeds Done (heuristic)",
            _match_lines(files, add_re), add - done,
        )
    return []


def _mutex_pair(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 4980-4989
    lock_re = re.compile(r"\.Lock\(")
    defer_unlock_re = re.compile(r"defer[ \t]+.*\.Unlock\(")
    locks = _count(files, lock_re)
    defer_unlock = _count(files, defer_unlock_re)
    if locks > 0 and defer_unlock * 2 < locks:
        return _ratio_records(
            "go.concurrency.mutex-manual-lock", 1, "warning",
            "Manual Lock without matching defer Unlock (heuristic)",
            _match_lines(files, lock_re), locks,
        )
    return []


def _time_after(files: Sequence[Path], ast_matches: dict) -> list[dict]:
    # ubs-golang.sh 5014-5027: AST count first, regex window fallback.
    title = "time.After allocations in loops - prefer reusable timer"
    hits = ast_matches.get("go.time-after-in-loop") or []
    if hits:
        return [
            _rec("go.channels.time-after-in-loop", 2, "info", m["path"], m["line"],
                 f"{title}: {m['text']}" if m["text"] else title)
            for m in hits
        ]
    for_re = re.compile(r"for[ \t]*.*\{")
    after_re = re.compile(r"time\.After\(")
    records: list[dict] = []
    for path, lines in _iter_file_lines(files):
        for idx, line in enumerate(lines):
            if MARKER in line or not for_re.search(line):
                continue
            for probe in range(idx + 1, min(len(lines), idx + 9)):
                probe_line = lines[probe]
                if MARKER in probe_line:
                    continue
                if after_re.search(probe_line):
                    records.append(_rec(
                        "go.channels.time-after-in-loop", 2, "info",
                        path, probe + 1, f"{title} — {probe_line.strip()[:240]}",
                    ))
    return records


def _body_close(files: Sequence[Path], ast_matches: dict) -> list[dict]:
    # ubs-golang.sh 5115-5131
    if ast_matches.get("go.http-response-body-not-closed"):
        return [
            _rec("go.http-response-body-not-closed", 4, "warning", m["path"], m["line"],
                 "HTTP response bodies not obviously closed (AST heuristic)")
            for m in ast_matches["go.http-response-body-not-closed"]
        ]
    http_re = re.compile(r"http\.(Get|Post|Head)\(|(client|Client|httpClient|c)\.Do\(")
    close_re = re.compile(r"\.Body\.Close\(")
    http_calls = _match_lines(files, http_re)
    body_close = _count(files, close_re)
    if http_calls and body_close < len(http_calls):
        return _ratio_records(
            "go.http.body-close-regex-fallback", 4, "warning",
            "Possible missing resp.Body.Close() (regex heuristic)",
            http_calls, len(http_calls) - body_close,
        )
    return []


def _rows_not_closed(files: Sequence[Path], ast_matches: dict) -> list[dict]:
    # ubs-golang.sh 5172-5184
    if ast_matches.get("go.sql.rows-not-closed"):
        return [
            _rec("go.sql.rows-not-closed", 5, "warning", m["path"], m["line"],
                 "sql.Rows from Query/QueryContext not obviously closed (defer rows.Close())")
            for m in ast_matches["go.sql.rows-not-closed"]
        ]
    query_re = re.compile(r"\.Query(Row|Context)?\(")
    close_re = re.compile(r"\.Close\(\)")
    queries = _match_lines(files, query_re)
    closes = _count(files, close_re)
    if queries and closes < len(queries):
        return _ratio_records(
            "go.sql.close-regex-fallback", 5, "info",
            "Potential missing Close() calls for rows/files/etc. (broad heuristic)",
            queries, len(queries) - closes,
        )
    return []


def _tx_balance(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 5200-5206
    begin_re = re.compile(r"\b(Begin|BeginTx)\(")
    end_re = re.compile(r"\.(Commit|Rollback)\(")
    begins = _match_lines(files, begin_re)
    ends = _count(files, end_re)
    if begins and ends < len(begins):
        return _ratio_records(
            "go.sql.tx-balance", 5, "warning",
            "Tx started without Commit/Rollback (heuristic)",
            begins, len(begins) - ends,
        )
    return []


def _open_close(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 5542-5548
    open_re = re.compile(r"os\.Open(File)?\(")
    close_re = re.compile(r"\.Close\(")
    opens = _match_lines(files, open_re)
    closes = _count(files, close_re)
    if opens and closes < len(opens):
        return _ratio_records(
            "go.filesystem.open-close-imbalance", 8, "warning",
            "Potential missing Close() calls (heuristic)",
            opens, len(opens) - closes,
        )
    return []


def _tls_skip(files: Sequence[Path], ast_matches: dict) -> list[dict]:
    # ubs-golang.sh 7521-7533: AST literal count + rg literal fallback +
    # rg assignment count + the indirect python helper (7427-7489), all
    # summed into ONE "InsecureSkipVerify enabled" finding. The legacy rg
    # counts used wc_num (NO marker filtering); the indirect helper keeps
    # its own marker checks.
    rule = "go.crypto.insecureskipverify"
    title = "InsecureSkipVerify enabled"
    records: list[dict] = []
    ast_hits = ast_matches.get("go.tls-insecure-skip") or []
    for m in ast_hits:
        records.append(_rec(rule, 9, "warning", m["path"], m["line"],
                            f"{title}: {m['text']}" if m["text"] else title))
    if not ast_hits:
        # rg fallback for the literal — NOT marker filtered (wc_num parity).
        for path, line_no, text in _match_lines(
            files, re.compile(r"InsecureSkipVerify:[ \t]*true"), drop_markers=False
        ):
            records.append(_rec(rule, 9, "warning", path, line_no, f"{title} — {text}"))
    for path, line_no, text in _match_lines(
        files, re.compile(r"\.InsecureSkipVerify[ \t]*=[ \t]*true"), drop_markers=False
    ):
        records.append(_rec(rule, 9, "warning", path, line_no, f"{title} — {text}"))
    records.extend(_tls_indirect(files, title, rule))
    return records


def _tls_indirect(files: Sequence[Path], title: str, rule: str) -> list[dict]:
    # Port of count_indirect_tls_insecure_skip (ubs-golang.sh 7427-7489):
    # `InsecureSkipVerify: <var>` / `.InsecureSkipVerify = <var>` where the
    # variable is assigned true anywhere in the same file.
    true_assignment_re = re.compile(
        r"\b(?:const|var)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?:\s+bool)?\s*=\s*true\b"
    )
    short_true_assignment_re = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:=\s*true\b")
    insecure_field_re = re.compile(
        r"\bInsecureSkipVerify\s*:\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
        r"|\.\s*InsecureSkipVerify\s*=\s*(?P<assign>[A-Za-z_][A-Za-z0-9_]*)\b"
    )

    def code_line(line: str) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return ""
        return re.sub(r"//.*", "", line)

    records: list[dict] = []
    for path, lines in _iter_file_lines(files):
        names: set[str] = set()
        for raw in lines:
            line = code_line(raw)
            if not line or MARKER in line:
                continue
            for regex in (true_assignment_re, short_true_assignment_re):
                match = regex.search(line)
                if match:
                    names.add(match.group("name"))
        if not names:
            continue
        for idx, raw in enumerate(lines, 1):
            line = code_line(raw)
            if MARKER in line or "InsecureSkipVerify" not in line:
                continue
            for match in insecure_field_re.finditer(line):
                name = match.group("name") or match.group("assign")
                if name in names:
                    records.append(_rec(rule, 9, "warning", path, idx, f"{title} — {raw.strip()[:240]}"))
                    break
    return records


def _exec_shell(files: Sequence[Path], ast_matches: dict) -> list[dict]:
    # ubs-golang.sh 7535-7543: AST rule first, regex fallback through
    # count_lines (marker-filtered).
    title = "exec.Command shell interpreter detected"
    hits = ast_matches.get("go.exec-sh-c") or []
    if hits:
        return [
            _rec("go.exec-sh-c", 9, "critical", m["path"], m["line"],
                 f"{title}: {m['text']}" if m["text"] else title)
            for m in hits
        ]
    rule = "go.security.exec-shell"
    fallback_re = re.compile(
        r'exec\.Command(Context)?\(\s*"(sh|bash)"\s*,\s*"-?c"'
        r'|exec\.Command(Context)?\(\s*"cmd"\s*,\s*"/C"'
        r'|exec\.Command(Context)?\(\s*"powershell"\s*,\s*"-Command"'
    )
    return _ratio_records(rule, 9, "critical", title,
                          _match_lines(files, fallback_re), _count(files, fallback_re))


def _db_context(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 7904-7909
    noctx_re = re.compile(r"\.(Query|Exec|QueryRow)\(")
    ctx_re = re.compile(r"\.(QueryContext|ExecContext|QueryRowContext)\(")
    noctx = _match_lines(files, noctx_re)
    ctx = _count(files, ctx_re)
    if noctx and ctx == 0:
        return _ratio_records(
            "go.database.context-less-calls", 21, "info",
            "DB calls without context; consider *Context variants",
            noctx, len(noctx),
        )
    return []


def _server_shutdown(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 7924-7929
    srv_re = re.compile(r"http\.Server\{")
    sd_re = re.compile(r"\.Shutdown\(")
    servers = _match_lines(files, srv_re)
    shutdowns = _count(files, sd_re)
    if servers and shutdowns == 0:
        return _ratio_records(
            "go.shutdown.server-no-shutdown", 22, "info",
            "http.Server constructed but no Shutdown() call seen; ensure graceful shutdown",
            servers, len(servers),
        )
    return []


def _t_parallel(files: Sequence[Path]) -> list[dict]:
    # ubs-golang.sh 7665-7668
    test_re = re.compile(r"^func[ \t]+Test[A-Za-z0-9_]*\(t[ \t]+\*testing\.T\)")
    par_re = re.compile(r"t\.Parallel\(\)")
    tests = _match_lines(files, test_re)
    par = _count(files, par_re)
    if tests and par == 0:
        return _ratio_records(
            "go.testing.t-parallel", 13, "info",
            "Consider t.Parallel() for independent tests",
            tests, len(tests),
        )
    return []


def _inventory_records(files: Sequence[Path], names: dict[str, list[Path]],
                       go_files_count: int, single_file: bool) -> list[dict]:
    """Cats 12/13/19: go.mod/go.sum/go.work/test-file inventory (index_project
    consumers, ubs-golang.sh 7604-7648 + 7653-7669 + 7831-7861)."""
    records: list[dict] = []
    mods = names.get("go.mod", [])
    go_sums = names.get("go.sum", [])
    go_works = names.get("go.work", [])
    project = _inventory_project(files)

    if mods:
        for mod in mods:
            records.append(_rec("go.build.go-mod-present", 12, "info", mod, 1,
                                "go.mod file(s) present"))
        outdated = 0
        for mod in mods:
            try:
                text = mod.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            match = _GO_DIRECTIVE_RE.search(text)
            version = match.group(1) if match else ""
            if version and re.match(r"^1\.(2[3-9]|[3-9][0-9])(\.[0-9]+)?$", version):
                continue
            outdated += 1
            directive_line = 1
            for idx, line in enumerate(text.splitlines(), 1):
                if _GO_DIRECTIVE_RE.match(line):
                    directive_line = idx
                    break
            records.append(_rec(
                "go.build.go-mod-outdated", 12, "warning", mod, directive_line,
                "go.mod with go directive < 1.23 — Set 'go 1.23' (or newer) where appropriate",
            ))
    else:
        if single_file or go_files_count <= 1:
            records.append(_rec(
                "go.build.go-mod-missing", 12, "info", project, 0,
                "No go.mod found for focused scan — Module hygiene requires a project root; "
                "focused file scans skip go.mod enforcement",
            ))
        else:
            records.append(_rec(
                "go.build.go-mod-missing", 12, "warning", project, 0,
                "No go.mod found — Use modules; GOPATH mode is legacy",
            ))

    # Cat 12: go.sum / go.work presence.
    if not go_sums:
        records.append(_rec("go.build.go-sum-missing", 12, "info", project, 0,
                            "go.sum not found"))
    for work in go_works:
        records.append(_rec("go.build.go-work", 12, "info", work, 1,
                            "go.work detected (workspace mode)"))

    # Cat 13: test files.
    test_files = [p for p in files if p.name.endswith("_test.go")]
    for test_file in test_files:
        records.append(_rec("go.testing.test-files", 13, "info", test_file, 1,
                            "Test files detected"))

    # Cat 19: multi-module drift.
    if len(mods) > 1:
        for mod in mods:
            records.append(_rec("go.dependencies.multi-module", 19, "info", mod, 1,
                                "Multiple go.mod; check for monorepo consistency"))
        versions: list[tuple[str, Path]] = []
        for mod in mods:
            try:
                text = mod.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            match = _GO_DIRECTIVE_RE.search(text)
            versions.append((match.group(1) if match else "unknown", mod))
        base_ver = versions[0][0] if versions else "unknown"
        drift = [mod for version, mod in versions[1:] if version != base_ver]
        for mod in drift:
            records.append(_rec(
                "go.dependencies.mixed-go-directive", 19, "info", mod, 1,
                "Mixed module 'go' directives; align to a single baseline",
            ))
    return records


def _inventory_project(files: Sequence[Path]) -> str:
    for path in files:
        parent = path.parent
        if str(parent) not in ("", "."):
            return str(parent)
    return "."


def computed_checks(files: Sequence[Path], ast_matches: dict, skip: set[int],
                    single_file: bool) -> list[dict]:
    """Every legacy bash/computed check, in category order."""
    records: list[dict] = []
    names: dict[str, list[Path]] = {name: [] for name in _INVENTORY_NAMES}
    go_files_count = 0
    for path in files:
        if path.name in names:
            names[path.name].append(path)
        if path.suffix == ".go":
            go_files_count += 1

    def active(category: int) -> bool:
        return category not in skip

    if active(1):
        records.extend(_wg_balance(files))
        records.extend(_mutex_pair(files))
    if active(2):
        records.extend(_time_after(files, ast_matches))
    if active(4):
        records.extend(_body_close(files, ast_matches))
    if active(5):
        records.extend(_rows_not_closed(files, ast_matches))
        records.extend(_tx_balance(files))
    if active(8):
        records.extend(_open_close(files))
    if active(9):
        records.extend(_tls_skip(files, ast_matches))
        records.extend(_exec_shell(files, ast_matches))
    if active(13):
        records.extend(_t_parallel(files))
    if active(19) or active(12):
        records.extend(_inventory_records(files, names, go_files_count, single_file))
    if active(21):
        records.extend(_db_context(files))
    if active(22):
        records.extend(_server_shutdown(files))
    return records


def _finding_title(rec: dict) -> str:
    return str(rec.get("message", rec.get("rule", "")))


def _render_text(args, files: Sequence[Path], counters: dict[str, int]) -> None:
    """Render the legacy-format text report from the NDJSON sink."""
    import datetime

    records = read_ndjson(args.sink)
    by_rule: dict[str, list[dict]] = {}
    for rec in records:
        by_rule.setdefault(rec["rule"], []).append(rec)

    slug_to_category = {slug: num for num, slug in _CATEGORY_SLUGS.items()}

    def category_of(rec: dict) -> int | None:
        category_id = str(rec.get("category_id", ""))
        slug = category_id.rsplit(".", 1)[-1] if "." in category_id else category_id
        if category_id.startswith("golang.") and slug in slug_to_category:
            return slug_to_category[slug]
        return _record_category(rec)

    category_order = {num: i for i, num in enumerate(sorted(_CATEGORY_SLUGS))}
    ordered_rules = sorted(
        by_rule,
        key=lambda rule: (
            category_order.get(category_of(by_rule[rule][0]) or 99, 99),
            rule,
        ),
    )
    lines = [
        f"UBS module: golang (contract v2) — {args.project or args.project_dir}",
        f"Files scanned: {len(files)}",
    ]
    current_section = None
    emitted_subheaders: set[str] = set()
    for rule in ordered_rules:
        recs = by_rule[rule]
        category_num = category_of(recs[0])
        section = _SECTION_HEADERS.get(category_num or 0)
        subheader = None
        if category_num is not None:
            for prefix, text in _SUBHEADERS.get(category_num, {}).items():
                if rule.startswith(prefix):
                    subheader = text
        if section is not None and section != current_section:
            lines.append("")
            lines.append(section)
            current_section = section
        if subheader and subheader not in emitted_subheaders:
            lines.append(subheader)
            emitted_subheaders.add(subheader)
        severity = recs[0]["severity"]
        title = _finding_title(recs[0])
        lines.append(f"[{severity}] {title} ({len(recs)} found) — {rule}")
        for rec in recs[:25]:  # legacy heredoc sample cap (issues[:25])
            lines.append(f"    {rec['path']}:{rec['line']}  {str(rec.get('message', ''))[:180]}")

    # Legacy "good" notes for categories with no records at all.
    categories_with_records = {category_of(rec) for rec in records}
    for num, note in _GOOD_NOTES.items():
        if num not in categories_with_records and num not in _skip_set(args):
            lines.append(f"good: {note}")

    lines += [
        f"Go files: {sum(1 for p in files if p.suffix == '.go')}",
        f"Critical issues: {counters['critical']}",
        f"Warning issues: {counters['warning']}",
        f"Info items: {counters['info']}",
        f"Report generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
    ]
    Path(args.text_out).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _skip_set(args) -> set[int]:
    return {int(part) for part in (args.skip or "").split(",") if part.strip().isdigit()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.go_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="base dir recorded in outputs")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--ast-rule-dir", default="", help="consolidated ast-grep rule dir (sgconfig-*.yml + manifest.json)")
    parser.add_argument("--tally-out", default="", help="write the category-16 rule tally JSON here")
    parser.add_argument("--text-out", default="", help="write the legacy-format text report here")
    parser.add_argument("--json-out", default="", help="write the UBS summary JSON document here")
    parser.add_argument("--project", default="", help="project path recorded in the json summary")
    parser.add_argument("--version", default="", help="module version recorded in the json summary")
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--enable-new-analyzers", action="store_true",
                        help="run analyzers with no legacy counterpart (guards_generic/narrowing_go)")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)
    single_file = bool(args.project_dir) and Path(args.project_dir).is_file()

    # Legacy index_project scanned the whole project dir for the inventory
    # names (go.mod/go.sum/go.work/go.work.sum) even though the rg pipelines
    # include them via INCLUDE_NAMES — augment the ext-based file list so cat
    # 12/19 and the "Files scanned" total match the legacy find.
    if args.project_dir and Path(args.project_dir).is_dir():
        listed = {str(p) for p in files}
        for extra in _inventory_files(Path(args.project_dir)):
            if str(extra) not in listed:
                files.append(extra)

    patterns = load_patterns()

    from ubs_core.cache import CapturingSink, ScanCache

    cache = ScanCache(
        lang="golang",
        project_dir=args.project_dir or args.project or ".",
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"new_analyzers={args.enable_new_analyzers}",
    )
    cached_findings, files_to_scan = cache.partition_files(files)

    capturing_sink = None
    ast_tally: Counter = Counter()
    ast_matches: dict[str, list[dict]] = {}
    if files_to_scan:
        from ubs_core.prefilter import build_prefilter_index, run_prefilter
        from ubs_core.registry import analyzers_for_lang
        from ubs_core.go_rules import _RULES

        go_analyzers = [a.name for a in analyzers_for_lang("go")]
        ast_rules_input = list(_RULES)
        if args.ast_rule_dir:
            rules_dir = Path(args.ast_rule_dir)
            for rf in rules_dir.glob("*.yml"):
                if rf.name.startswith(("sgconfig", "sgbase")):
                    continue
                try:
                    text = rf.read_text(encoding="utf-8", errors="ignore")
                    id_m = re.search(r"id:\s*(\S+)", text)
                    rid = id_m.group(1) if id_m else rf.stem
                    ast_rules_input.append((rid, text))
                except OSError:
                    pass

        prefilter_index = build_prefilter_index(
            ast_rules=ast_rules_input,
            patterns=patterns,
            analyzers=go_analyzers,
            lang="go",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        capturing_sink = CapturingSink()
        counters = scan_patterns(patterns, files_to_scan, capturing_sink, skip, prefilter=prefilter_res)
        run_detectors(files_to_scan, capturing_sink, skip)
        run_analyzers(files_to_scan, capturing_sink, skip, enable_new=args.enable_new_analyzers, prefilter=prefilter_res)
        if args.ast_rule_dir:
            from ubs_core.go_ast import scan_all

            ast_files = prefilter_res.ast_files if not prefilter_res.is_bypass else files_to_scan
            ast_tally, ast_matches = scan_all(
                Path(args.ast_rule_dir), ast_files, AST_CONSUMPTION, capturing_sink,
                skip=skip, slug_for_category=slug_for_category,
            )
        for record in computed_checks(files_to_scan, ast_matches, skip, single_file):
            capturing_sink.write(json.dumps(record, ensure_ascii=False) + "\n")
        cache.store_scanned_files(files_to_scan, capturing_sink.by_file)
    else:
        from ubs_core.prefilter import PrefilterResult
        prefilter_res = PrefilterResult(
            files_considered=0,
            files_after_prefilter=0,
            prefilter_ms=0,
            is_bypass=False,
        )

    prefilter_file = os.environ.get("UBS_PREFILTER_FILE")
    if prefilter_file:
        try:
            Path(prefilter_file).write_text(json.dumps(prefilter_res.to_dict()), encoding="utf-8")
        except OSError:
            pass

    ast_records: list[dict] = []
    with open(args.sink, "w", encoding="utf-8") as sink_file:
        for f in files:
            recs = cached_findings.get(f)
            if recs is None and capturing_sink is not None:
                recs = capturing_sink.get_for_file(f, project_dir=args.project_dir or args.project)
            if recs:
                for cached_record in recs:
                    record = dict(cached_record)
                    is_ast = record.pop("_ast_pack", False)
                    report_only = record.pop("_report_only", False)
                    if is_ast:
                        ast_records.append(record)
                    if not report_only:
                        sink_file.write(json.dumps(record, ensure_ascii=False) + "\n")

    cache_file = os.environ.get("UBS_CACHE_FILE") or (os.path.splitext(args.sink)[0] + ".cache")
    cache.write_stats(cache_file)

    # The sink is the single source of truth: recount severities from it so
    # every layer (patterns, detectors, analyzers, ast, computed) is
    # reflected in totals.
    counters = {"critical": 0, "warning": 0, "info": 0}
    for line in Path(args.sink).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            severity = json.loads(line).get("severity", "info")
        except ValueError:
            continue
        counters[severity] = counters.get(severity, 0) + 1

    exit_code = 1 if counters["critical"] else 0
    if args.fail_on_warning and (counters["critical"] + counters["warning"]) > 0:
        exit_code = 1

    if args.json_out:
        records = read_ndjson(args.sink)
        import datetime

        doc = {
            "language": "golang",
            "project": args.project or args.project_dir,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": len(files),
            "critical": counters["critical"],
            "warning": counters["warning"],
            "info": counters["info"],
            "version": args.version,
            "status": "ok",
            "findings": records,
        }
        profile_data = {
            "files_considered": prefilter_res.files_considered if files_to_scan else len(files),
            "files_after_prefilter": prefilter_res.files_after_prefilter if files_to_scan else 0,
            "prefilter_ms": prefilter_res.prefilter_ms if files_to_scan else 0,
            "cache_hits": cache.stats["hits"],
            "cache_misses": cache.stats["misses"],
            "cache_hit_rate": cache.stats["hit_rate"],
        }
        if os.environ.get("UBS_PROFILE") == "1":
            doc["profile"] = profile_data
        extras = doc.get("extras", {}) if isinstance(doc.get("extras"), dict) else {}
        extras["profile"] = profile_data
        extras["ast_findings"] = ast_records
        doc["extras"] = extras
        Path(args.json_out).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.tally_out:
        Path(args.tally_out).write_text(
            json.dumps(dict(sorted(ast_tally.items())), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    if args.text_out:
        _render_text(args, files, counters)

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns),
                                 "ast_rules": len(ast_tally),
                                 "prefilter": prefilter_res.to_dict(),
                                 "cache": cache.stats}) + "\n")
    return exit_code


def _inventory_files(project_dir: Path) -> list[Path]:
    """Legacy index_project inventory: find the INCLUDE_NAMES files anywhere
    under project_dir, pruning EXCLUDE_DIRS (ubs-golang.sh 2821-2874)."""
    found: list[Path] = []
    if not project_dir.is_dir():
        return found

    def prune(directory: Path) -> bool:
        return directory.name in _INVENTORY_EXCLUDES

    stack = [project_dir]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if not prune(entry):
                    stack.append(entry)
            elif entry.name in _INVENTORY_NAMES:
                found.append(entry)
    return found


# AST consumption table (ubs_core.go_ast): rule id -> [(category, severity,
# legacy print_finding title), …]. Sources are the category blocks
# (ubs-golang.sh 4942-7932). Rules absent here are tally-only (category 16
# inventory, category 20's already-counted rules excepted) or computed.
AST_CONSUMPTION: dict[str, list[tuple[int, str, str]]] = {
    # Cat 1
    "go.goroutine-in-loop": [(1, "info", "goroutine launches inside loops")],
    "go.loop-var-capture": [(1, "warning", "Loop variable captured by goroutine closure")],
    "go.loop-var-capture-for": [(1, "warning", "For-loop variable captured by goroutine closure")],
    "go.waitgroup-add-no-done": [(1, "info", "WaitGroup.Add without nearby Done (AST heuristic)")],
    "go.resource.ticker-no-stop": [(1, "warning", "Ticker created without Stop (AST)")],
    "go.async.goroutine-err-no-check": [(1, "warning", "goroutine body ignores returned error")],
    # Cat 2
    "go.select-no-default": [(2, "info", "select without default (check for intended blocking/timeouts)")],
    # Cat 3
    "go.context.cancel-defer-in-if": [(3, "warning", "cancel() deferred conditionally inside if after context.With* (prefer unconditional defer cancel())")],
    "go.context-without-cancel": [(3, "warning", "context.With* assigns cancel but no defer cancel() in containing scope (AST heuristic)")],
    "go.http-handler-background": [(3, "warning", "Use r.Context() instead of context.Background() in handlers")],
    "go.context-todo": [(3, "info", "context.TODO() present - ensure it\u2019s not shipping to prod")],
    # Cat 4
    "go.http-default-client": [(4, "info", "Default http.Client without Timeout")],
    "go.http-client-without-timeout": [(4, "warning", "http.Client constructed without Timeout")],
    "go.http-client-without-transport": [(4, "info", "http.Client created without explicit Transport")],
    "go.http-transport-missing-timeouts": [(4, "info", "http.Transport missing key timeouts")],
    "go.http-server-no-timeouts": [(4, "info", "http.Server lacks timeouts")],
    "go.http-newrequest-without-context": [(4, "info", "Prefer http.NewRequestWithContext")],
    "go.http.defer-body-close-delayed": [(4, "info", "defer resp.Body.Close() placed late after success (early returns between may leak connections)")],
    "go.http.defer-body-before-err-check": [
        (4, "critical", "defer resp.Body.Close() before checking err"),
        (20, "critical", "defer resp.Body.Close() before checking err"),
    ],
    "go.tls-minversion-missing": [(4, "info", "tls.Config without MinVersion")],
    # Cat 5
    "go.defer-in-loop": [(5, "warning", "defer inside loops")],
    "go.defer-close-before-err-check": [
        (5, "critical", "defer Close() before checking err"),
        (20, "critical", "defer file.Close() before checking err"),
    ],
    "go.sql.defer-rows-close-before-err-check": [
        (5, "critical", "defer rows.Close() before checking err"),
        (20, "critical", "defer rows.Close() before checking err"),
    ],
    "go.sql.defer-rows-close-delayed": [(5, "info", "defer rows.Close() is placed late after a successful Query (early returns between may leak rows/conn)")],
    "go.sql.defer-rollback-before-err-check": [(5, "critical", "defer tx.Rollback() occurs before checking err; tx may be nil/stale")],
    "go.sql.begin-without-defer-rollback": [
        (5, "warning", "Transaction begun without a deferred tx.Rollback()"),
        (21, "info", "Tx begun without deferred rollback"),
    ],
    "go.sql.defer-rollback-delayed": [(5, "warning", "defer tx.Rollback() is placed late after Begin (early returns between may skip rollback)")],
    "go.time-tick": [(5, "warning", "time.Tick leaks; prefer NewTicker")],
    "go.resource.timer-not-drained": [(5, "info", "time.NewTimer channel never drained")],
    # Cat 6
    "go.write-error-ignored": [(6, "info", "Write(...) error ignored via blank identifier (AST)")],
    "go.http.responsewriter-write-ignored": [(6, "info", "http.ResponseWriter.Write(...) return values discarded (AST)")],
    "go.fmt.fprintf-error-ignored": [(6, "info", "fmt.Fprintf return error ignored (AST)")],
    "go.json.encode-error-ignored": [(6, "warning", "json.NewEncoder(...).Encode(...) error ignored (AST)")],
    "go.template.execute-error-ignored": [(6, "warning", "template Execute(...) error ignored (AST)")],
    "go.iferr-empty": [(6, "warning", "Empty if err != nil { } blocks")],
    "go.iferr-return-nil": [(6, "critical", "err checked but dropped (return nil)")],
    "go.err-shadow": [(6, "info", "err shadowed via :=; ensure correct error is checked")],
    "go.panic-call": [(6, "warning", "panic used; prefer errors in libraries")],
    "go.recover-not-in-defer": [(6, "warning", "recover() outside defer is ineffective")],
    # Cat 7
    "go.json-decode-without-disallow": [(7, "info", "Consider Decoder.DisallowUnknownFields()")],
    "go.json.decoder-unbounded-body": [(7, "info", "Request JSON decode without MaxBytesReader (DOS risk)")],
    # Cat 8
    "go.ioutil-deprecated": [(8, "info", "Replace ioutil.* with io/os equivalents")],
    "go.close-error-ignored": [(8, "info", "Deferred Close() without checking error")],
    # Cat 9 (computed: tls-insecure-skip, exec-sh-c)
    "go.exec-command-without-context": [(9, "info", "Prefer exec.CommandContext(ctx, ...)")],
    "go.exec-strings-fields": [(9, "warning", "exec.Command called with strings.Fields(...); verify argument safety")],
    "go.sql-dynamic-string": [(9, "warning", "Potential dynamic SQL strings reaching Exec/Query")],
    # Cat 11
    "go.dot-import": [(11, "warning", "dot-imports found")],
    "go.blank-import": [(11, "info", "blank imports present")],
    # Cat 15
    "go.interface-empty": [(15, "info", "Prefer 'any' over 'interface{}'")],
    # Cat 21
    "go.sql.rows-err-not-checked": [(21, "info", "rows.Next loop without rows.Err() check")],
    # Cat 22
    "go.http-client-close-idle-missing": [(22, "info", "Consider CloseIdleConnections() during shutdown")],
}


if __name__ == "__main__":
    raise SystemExit(main())
