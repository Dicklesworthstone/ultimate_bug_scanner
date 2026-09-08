"""ubs_core.csharp_scan — contract-v2 orchestrator for the C# module (bead 0xjg.12).

ONE `python3 -m ubs_core.csharp_scan` process (js/py/go/java/ruby semantics):

1. pattern table (ubs_core.csharp_patterns.*)  — every legacy rg pipeline,
   line-anchored, marker-dropped, severity faithful;
2. detector ports (ubs_core.csharp_detectors.*) — the four cat-8 heredocs
   (archive extraction, header injection, outbound URL, security randomness);
3. registered analyzers (taint_csharp_request / taint_csharp_redirect /
   lifecycle_csharp / narrowing_csharp / async_handles_csharp) — the A2
   verbatim heredoc ports, run through RunContext; bead-D3 analyzers with no
   legacy counterpart (guards_csharp) stay off unless --enable-new-analyzers;
4. the cat-18 inventory computed check (sln/csproj census + TFM tags);
5. the consolidated ast-grep pack (csharp_rules.generate → csharp_ast.scan_all,
   one `scan -c` per 400-path batch) — legacy cat 17; the cat-20 lock/await
   heuristic stays suppressed exactly when the pack ran (legacy
   AST_GREP_STATUS used/clean).

All layers append to ONE NDJSON findings sink (K2 schema), the totals are
recounted from the sink, and a legacy-flavored text report is rendered.

Contract-v2 orchestrator for modules/ubs-csharp.sh (beads 0xjg.12 and 0xjg.18).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

MARKER = "ubs:ignore"

# Meta-runner category_slug_for csharp (ubs 5110-5137).
_CATEGORY_SLUGS = {
    1: "exceptions-null", 2: "resources", 3: "concurrency", 4: "numeric",
    5: "collections", 6: "strings", 7: "filesystem", 8: "security",
    9: "code-quality", 10: "api-misuse", 11: "debug", 12: "formatting",
    13: "build", 14: "dependencies", 15: "exceptions", 16: "aspnet",
    17: "ast-grep", 18: "inventory", 19: "resource-lifecycle",
    20: "async-locks", 21: "rethrow", 22: "casts", 23: "parsing", 24: "perf",
}

# Legacy CATEGORY_NAMES headers (ubs-csharp.sh 754-779), printed as
# "[N] Name" by the text renderer / record-less bridge.
_SECTION_HEADERS = {
    1: "[1] Exceptions & Nullability Hazards",
    2: "[2] Resources & IDisposable Footguns",
    3: "[3] Concurrency & Async Pitfalls",
    4: "[4] Numeric & Floating-Point Traps",
    5: "[5] Collections & LINQ Gotchas",
    6: "[6] Strings & Allocation Smells",
    7: "[7] Filesystem / Process / IO Risks",
    8: "[8] Security Red Flags",
    9: "[9] Code Quality Markers",
    10: "[10] API Misuse & Correctness",
    11: "[11] Tests / Debug Leftovers",
    12: "[12] Formatting & Analyzer Signals",
    13: "[13] Build & Test Health",
    14: "[14] Dependency Hygiene (NuGet)",
    15: "[15] Exception Handling Anti-patterns",
    16: "[16] ASP.NET / Web Pitfalls",
    17: "[17] AST-Grep Rule Pack",
    18: "[18] Project Inventory",
    19: "[19] Resource Lifecycle Correlation",
    20: "[20] Async Locks / Semaphores / Await-in-Lock",
    21: "[21] Exception Surfaces & Rethrow Issues",
    22: "[22] Suspicious Casts & Truncation",
    23: "[23] Parsing & Validation Robustness",
    24: "[24] Perf / DoS Hotspots",
}

# Renderer/skip metadata for analyzer + detector rule ids: rule id ->
# (category, seq, summary template with {n}, sample style). "report" samples
# print `path:line:code` (legacy print_matches over the detector TSV), "tsv"
# samples print `path:line:col - message` (legacy helper TSV loop).
_RULE_CHECKS = {
    # registered analyzers (A2 verbatim heredoc ports)
    "csharp.narrowing": (1, 25, "Null/type guard fallthrough issues ({n}) - guards do not safely narrow the fallthrough path", "tsv"),
    "csharp.async.unobserved_task_handle": (3, 175, "Task handles created but never observed ({n})", "tsv"),
    "csharp.taint.request_traversal": (8, 371, "Request-derived path reaches file read/write/serve sink ({n}) - validate with Path.GetFullPath containment or Path.GetFileName before file access", "report"),
    "csharp.taint.open_redirect": (8, 372, "Unvalidated redirect from request data ({n}) - validate with Url.IsLocalUrl/LocalRedirect or explicit redirect host allow-list checks", "report"),
    "csharp.lifecycle": (19, 710, "Potential resource lifecycle leaks (helper): {n}", "tsv"),
    # detector ports (cat-8 heredocs)
    "csharp.security.archive-extraction": (8, 370, "Archive extraction path traversal risk ({n}) - validate archive entry paths stay under destination", "report"),
    "csharp.security.header-injection": (8, 373, "Request-controlled value reaches HTTP response header ({n}) - reject or strip CR/LF, URL-encode filename fragments, or route through a header-safe helper before writing response headers", "report"),
    "csharp.security.outbound-url": (8, 374, "Request-derived URL reaches outbound HTTP client ({n}) - validate with Uri parsing plus explicit https scheme and host allow-list checks", "report"),
    "csharp.security.weak-randomness": (8, 320, "Security token generated with non-cryptographic randomness ({n}) - use RandomNumberGenerator.GetBytes/GetHexString/GetInt32 or a cryptographic helper", "report"),
}

_INVENTORY_RULE = "cs.inventory.project"

# The async-handles analyzer yields csharp.lifecycle.unobserved_task_handle;
# the legacy module recorded that helper under csharp.async.<kind> — normalize.
_ASYNC_RULE_REMAP = {"csharp.lifecycle.unobserved_task_handle": "csharp.async.unobserved_task_handle"}

_AST_ORDER = {
    "cs-async-discarded-task-run": 10,
    "cs-async-discarded-startnew": 20,
    "cs-await-in-lock": 30,
    "cs-parallel-foreach-async-lambda": 40,
}

_ICONS_UTF8 = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️", "ok": "✅"}
_ICONS_CI = {"critical": "[CRIT]", "warning": "[WARN]", "info": "[INFO]", "ok": "[OK]"}


def slug_for_category(category: int | None) -> str:
    if category is None:
        return ""
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


def bucket_key(rule: str) -> str:
    """Canonical renderer bucket: legacy printed ONE summary line per helper
    (narrowing / lifecycle), whatever per-kind rule ids the analyzers use."""
    if rule.startswith("csharp.narrowing."):
        return "csharp.narrowing"
    if rule.startswith("csharp.lifecycle."):
        return "csharp.lifecycle"
    return rule


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: category-scoped line regex + fixed severity."""

    category: int
    rule_id: str
    seq: int
    label: str
    text: str  # legacy summary line, "{n}" = hit count
    regex: re.Pattern[str]
    severity: str
    exclude_regex: object | None = None  # legacy `grep -v` post-filter
    gate_regex: object | None = None  # legacy project-wide precondition
    needs_no_ast: bool = False  # legacy skipped when the ast-grep pack ran

    @classmethod
    def from_row(cls, row) -> "Pattern":
        return cls(
            category=row.category, rule_id=row.rule_id, seq=row.seq,
            label=row.label, text=row.text, regex=row.regex,
            severity=row.severity, exclude_regex=row.exclude_regex,
            gate_regex=row.gate_regex, needs_no_ast=row.needs_no_ast,
        )


@dataclass
class CheckMeta:
    """Renderer metadata for one rule bucket: category, order, summary line."""

    category: int
    seq: int
    summary: str  # "{n}" template, or "{msg}" for the inventory record
    style: str  # "pattern" | "report" | "tsv" | "ast" | "plain"
    samples: list = field(default_factory=list)


def scan_patterns(
    patterns: Sequence,
    texts: dict,
    sink,
    skip: set,
    phase: int,
    ast_ran: bool = False,
    prefilter: Any = None,
) -> None:
    """Run one phase of patterns over the file list, writing sink records.

    phase 0 = regular checks (legacy cat order, before the ast layer);
    phase 1 = the needs_no_ast heuristic (legacy cat 20 lock/await), which
    itself only ran when the ast-grep pack had NOT covered await-in-lock.

    rg parity: matching is LINE-anchored (one hit per matching line), the
    `ubs:ignore` marker drops the line (count_lines parity), exclude_regex
    re-applies `grep -v` over the rg output form `path:line:content`, and
    gate_regex is a project-wide precondition over the whole file list.
    """
    for pattern in patterns:
        if bool(pattern.needs_no_ast) != (phase == 1):
            continue
        if pattern.needs_no_ast and ast_ran:
            continue  # legacy cat 20: exact ast-grep detection replaces the heuristic
        if pattern.category in skip:
            continue
        if pattern.gate_regex is not None and not any(
            pattern.gate_regex.search(text) for text in texts.values()
        ):
            continue
        hits = []
        for path, text in texts.items():
            if prefilter is not None and pattern.rule_id not in prefilter.candidate_rules_for(path):
                continue
            for line_no, line_text in enumerate(text.splitlines(), start=1):
                if MARKER in line_text:
                    continue
                if not pattern.regex.search(line_text):
                    continue
                if pattern.exclude_regex is not None and pattern.exclude_regex.search(
                    f"{path}:{line_no}:{line_text}"
                ):
                    continue
                hits.append((path, line_no, line_text.strip()[:240]))
        if not hits:
            continue
        for path, line_no, line_text in hits:
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"csharp.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": pattern.severity,
                "message": f"{pattern.label} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def load_patterns() -> list:
    """Aggregate PATTERNS from every ubs_core.csharp_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import csharp_patterns

    patterns: list = []
    for module_info in pkgutil.iter_modules(csharp_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.csharp_patterns.{module_info.name}")
        except Exception as exc:  # a broken pattern module must not kill the scan
            sys.stderr.write(f"[ubs_core.csharp_scan] pattern module {module_info.name} failed: {exc}\n")
            continue
        for row in getattr(module, "PATTERNS", []):
            patterns.append(Pattern.from_row(row))
    patterns.sort(key=lambda p: p.seq)
    return patterns


def _relativize(path_str: str, base_dir: Path) -> str:
    path = Path(path_str)
    if not path.is_absolute():
        if (base_dir / path).is_file():
            path = (base_dir / path).resolve()
        elif (Path.cwd() / path).is_file():
            path = (Path.cwd() / path).resolve()
        else:
            path = path.resolve()
    try:
        return str(path.resolve().relative_to(base_dir.resolve()))
    except (ValueError, OSError):
        return str(path)


def _rule_meta(rule: str):
    for prefix, meta in _RULE_CHECKS.items():
        if rule == prefix or rule.startswith(prefix + ".") or rule.startswith(prefix):
            return meta
    return None


def run_detectors(files: Sequence, sink, skip: set, base_dir: Path) -> None:
    """Run ubs_core.csharp_detectors.* modules (legacy heredoc detector ports).

    Protocol: RULE_ID / CATEGORY / TITLE / SEVERITY / DESCRIPTION constants
    and ``find(files, base_dir)`` yielding (path, line, col, detail).
    """
    import importlib
    import pkgutil

    from ubs_core import csharp_detectors

    for module_info in sorted(pkgutil.iter_modules(csharp_detectors.__path__), key=lambda m: m.name):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.csharp_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.csharp_scan] detector module {module_info.name} failed: {exc}\n")
            continue
        find = getattr(module, "find", None)
        if find is None:
            continue
        category = int(getattr(module, "CATEGORY", 8))
        if skip and category in skip:
            continue
        rule_id = str(getattr(module, "RULE_ID", f"cs.detector.{module_info.name}"))
        title = str(getattr(module, "TITLE", rule_id))
        severity = str(getattr(module, "SEVERITY", "critical"))
        for hit in find(files, base_dir):
            path, line_no, col, detail = hit[0], hit[1], hit[2], hit[3]
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"csharp.{slug_for_category(category)}",
                "path": _relativize(str(path), base_dir),
                "line": int(line_no),
                "col": int(col),
                "severity": severity,
                "message": f"{title} — {detail}"[:300] if detail else title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def run_analyzers(files: Sequence, sink, skip: set, base_dir: Path,
                  enable_new: bool = False, prefilter: Any = None) -> None:
    """Run the registered csharp analyzers (taint x2, lifecycle, narrowing, async).

    Every one replaces a legacy check that ran inside its category, so skip
    filtering applies through _RULE_CHECKS. Analyzers with NO legacy csharp
    counterpart (bead-D3 guards_csharp deep-chain engine) stay off for
    parity unless --enable-new-analyzers — the python.narrowing /
    java.guards precedent. Record paths are relativized to the project base
    (the legacy TSV display form).
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import RunContext, analyzers_for_lang

    skip_narrowing = os.environ.get("UBS_SKIP_TYPE_NARROWING", "0") == "1"
    for analyzer in analyzers_for_lang("csharp"):
        if prefilter is not None:
            target_files = prefilter.filter_files_for_analyzer(analyzer.name, files)
        else:
            target_files = list(files)
        if not target_files:
            continue
        ctx = RunContext(lang="csharp", files=target_files)
        for finding in analyzer.run(ctx):
            rule = _ASYNC_RULE_REMAP.get(str(finding.get("rule", "")), str(finding.get("rule", "")))
            if skip_narrowing and rule.startswith("csharp.narrowing."):
                continue  # legacy: UBS_SKIP_TYPE_NARROWING=1 skips the helper
            meta = _rule_meta(rule)
            if meta is None:
                if not enable_new:
                    continue
                category = 8
            else:
                category = meta[0]
            if skip and category in skip:
                continue
            sink.write(json.dumps({
                "rule": rule,
                "category_id": f"csharp.{slug_for_category(category)}",
                "path": _relativize(str(finding.get("path", "")), base_dir),
                "line": int(finding.get("line", 0) or 0),
                "col": int(finding.get("col", 1) or 1),
                "severity": str(finding.get("severity", "warning")),
                "message": str(finding.get("message", "")),
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def inventory_check(texts: dict, sink, skip: set, project_path: Path, files_n: int) -> None:
    """Legacy category_18_inventory (3324-3341): sln/csproj census (find
    -maxdepth 3 semantics over the project path), TargetFramework tag census
    over the scanned list, always exactly one info record."""
    if 18 in skip:
        return

    def depth_census(suffix: str) -> int:
        base = project_path
        if base.is_file():
            return 1 if base.name.lower().endswith(suffix) else 0
        count = 0
        stack = [(base, 1)]
        while stack:
            current, depth = stack.pop()
            try:
                entries = list(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_file() and entry.name.lower().endswith(suffix):
                    count += 1
                elif entry.is_dir() and depth < 3:
                    stack.append((entry, depth + 1))
        return count

    sln_count = depth_census(".sln")
    csproj_count = depth_census(".csproj")
    tfm = re.compile(r"<TargetFramework")
    tfm_hits = sum(1 for text in texts.values() for line in text.splitlines() if tfm.search(line))
    message = (
        f"Solutions: {sln_count}, Projects: {csproj_count}, "
        f"TargetFramework tags: {tfm_hits}, C# files scanned: {files_n}"
    )
    sink.write(json.dumps({
        "rule": _INVENTORY_RULE,
        "category_id": f"csharp.{slug_for_category(18)}",
        "path": "",
        "line": 0,
        "col": 1,
        "severity": "info",
        "message": message,
        "suppressed": False,
    }, ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Text rendering — legacy-flavored report from the sink (record-backed
# sections; the shell bridge appends record-less headers + Summary Statistics).
# ─────────────────────────────────────────────────────────────────────────────

def _bucket_meta(rule: str, patterns: Sequence) -> CheckMeta:
    for pattern in patterns:
        if pattern.rule_id == rule:
            return CheckMeta(pattern.category, pattern.seq, pattern.text, "pattern")
    meta = _rule_meta(rule)
    if meta is not None:
        return CheckMeta(meta[0], meta[1], meta[2], meta[3])
    if rule.startswith("cs-"):
        from ubs_core.csharp_rules import CATEGORY_MAP, SUMMARY_MAP

        title = SUMMARY_MAP.get(rule, rule)
        return CheckMeta(
            CATEGORY_MAP.get(rule, 17), 600 + _AST_ORDER.get(rule, 99),
            f"{title} ({{n}})", "ast",
        )
    if rule == _INVENTORY_RULE:
        return CheckMeta(18, 700, "{msg}", "plain")
    return CheckMeta(99, 900, f"{rule} ({{n}})", "plain")


def _sample_line(meta: CheckMeta, rec: dict, detail: str) -> str:
    path = rec.get("path", "")
    line = int(rec.get("line", 0) or 0)
    if meta.style == "tsv":
        return f"  {path}:{line}:{int(rec.get('col', 1) or 1)} - {detail}"
    if detail:
        return f"  {path}:{line}:{detail}"
    return f"  {path}:{line}"


def render_text(args, ast_ran: bool, patterns: Sequence) -> None:
    """Render the record-backed sections of the legacy text report."""
    records = [
        json.loads(line)
        for line in Path(args.sink).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_rule: dict = {}
    for rec in records:
        by_rule.setdefault(bucket_key(rec["rule"]), []).append(rec)

    icons = _ICONS_CI if args.ci else _ICONS_UTF8
    detail_cap = args.detail_limit
    skip = _skip_set(args)

    buckets = []
    for rule, recs in by_rule.items():
        buckets.append((_bucket_meta(rule, patterns), rule, recs))
    buckets.sort(key=lambda item: (item[0].category, item[0].seq))

    lines: list = []
    current_section = None
    lock_note_emitted = False
    for meta, rule, recs in buckets:
        if meta.category != current_section:
            lines.append("")
            lines.append(_SECTION_HEADERS.get(meta.category, f"[{meta.category}]"))
            current_section = meta.category
            if meta.category == 17 and ast_ran:
                lines.append(f"{icons['ok']} ast-grep configured (language: cs). Running structured rule pack.")
            if meta.category == 20 and ast_ran and not lock_note_emitted:
                lines.append("Exact await-in-lock detection handled by ast-grep; skipping file-level lock/await heuristic.")
                lock_note_emitted = True
        severity = recs[0].get("severity", "info")
        summary = meta.summary.replace("{n}", str(len(recs))).replace("{msg}", str(recs[0].get("message", "")))
        lines.append(f"{icons.get(severity, icons['info'])} {summary}")
        if meta.style == "ast":
            samples = ", ".join(
                f"{rec.get('path', '')}:{int(rec.get('line', 0) or 0)}" for rec in recs[:3]
            )
            if samples:
                lines.append(f"  {samples}")
            continue
        if meta.style == "plain":
            continue  # the inventory summary line IS the legacy text
        for rec in recs[:detail_cap]:
            message = str(rec.get("message", ""))
            if meta.style in ("report", "pattern") and " — " in message:
                detail = message.split(" — ", 1)[1]
            else:
                detail = message
            lines.append(_sample_line(meta, rec, detail))

    # Cat 17 clean note: the pack ran but found nothing structurally notable.
    if ast_ran and 17 not in skip and not any(meta.category == 17 for meta, _r, _recs in buckets):
        lines.append("")
        lines.append(_SECTION_HEADERS[17])
        lines.append(f"{icons['ok']} ast-grep configured (language: cs). Running structured rule pack.")
        lines.append(f"{icons['ok']} ast-grep found no structural-only C# findings.")

    Path(args.text_out).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _skip_set(args) -> set:
    return {int(part) for part in (args.skip or "").split(",") if part.strip().isdigit()}


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.csharp_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="project path (file or dir); base for relative sink paths")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--ast-rule-dir", default="", help="consolidated ast-grep rule dir (sgconfig-csharp.yml + manifest.json)")
    parser.add_argument("--text-out", default="", help="write the record-backed text report here")
    parser.add_argument("--project", default="", help="project path recorded in the text header")
    parser.add_argument("--version", default="", help="module version")
    parser.add_argument("--detail-limit", type=int, default=5, help="samples per finding bucket (legacy DETAIL_LIMIT)")
    parser.add_argument("--ci", action="store_true", help="CI icon set")
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--fail-critical", type=int, default=-1, help="exit 1 when critical >= N")
    parser.add_argument("--fail-warning", type=int, default=-1, help="exit 1 when warning >= N")
    parser.add_argument("--enable-new-analyzers", action="store_true",
                        help="run analyzers with no legacy counterpart (guards_csharp)")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)
    project_path = Path(args.project_dir).resolve() if args.project_dir else Path.cwd().resolve()
    base_dir = project_path if project_path.is_dir() else project_path.parent

    texts: dict = {}
    for path in files:
        try:
            texts[path] = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

    patterns = load_patterns()

    from ubs_core.cache import CapturingSink, ScanCache

    cache = ScanCache(
        lang="csharp",
        project_dir=base_dir,
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"new_analyzers={args.enable_new_analyzers}",
    )
    cached_findings, files_to_scan = cache.partition_files(files)

    capturing_sink = None
    ast_ran = False
    if files_to_scan:
        from ubs_core.csharp_rules import _RULES
        from ubs_core.registry import analyzers_for_lang
        from ubs_core.prefilter import build_prefilter_index, run_prefilter
        from ubs_core import analyzers  # noqa: F401

        cs_analyzers = [a.name for a in analyzers_for_lang("csharp")]
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
            analyzers=cs_analyzers,
            lang="csharp",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        capturing_sink = CapturingSink()
        scan_patterns(patterns, texts, capturing_sink, skip, phase=0, prefilter=prefilter_res)
        run_detectors(files_to_scan, capturing_sink, skip, base_dir)
        run_analyzers(files_to_scan, capturing_sink, skip, base_dir, enable_new=args.enable_new_analyzers, prefilter=prefilter_res)
        if args.ast_rule_dir:
            from ubs_core.csharp_ast import scan_all
            from ubs_core.csharp_rules import CATEGORY_MAP, SEVERITY_MAP

            ast_files = prefilter_res.ast_files if not prefilter_res.is_bypass else files_to_scan
            scan_all(
                Path(args.ast_rule_dir), ast_files, capturing_sink,
                severity_overrides=dict(SEVERITY_MAP),
                count_only=None,  # legacy cat 17 ingested the whole pack
                skip=skip,
                rule_category=CATEGORY_MAP,
                slug_for_rule=slug_for_category,
                base_dir=base_dir,
            )
            ast_ran = True
        scan_patterns(patterns, texts, capturing_sink, skip, phase=1, ast_ran=ast_ran, prefilter=prefilter_res)
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

    inventory_records = []
    class _InvSink:
        def write(self, s: str):
            if s.strip():
                try:
                    inventory_records.append(json.loads(s))
                except Exception:
                    pass

    inventory_check({}, _InvSink(), skip, project_path, len(files))

    with open(args.sink, "w", encoding="utf-8") as sink_file:
        for f in files:
            recs = cached_findings.get(f)
            if recs is None and capturing_sink is not None:
                recs = capturing_sink.get_for_file(f, project_dir=base_dir)
            if recs:
                for r in recs:
                    sink_file.write(json.dumps(r, ensure_ascii=False) + "\n")
        for r in inventory_records:
            sink_file.write(json.dumps(r, ensure_ascii=False) + "\n")

    cache_file = os.environ.get("UBS_CACHE_FILE") or (os.path.splitext(args.sink)[0] + ".cache")
    cache.write_stats(cache_file)

    # The sink is the single source of truth: recount severities from it so
    # every layer (patterns, detectors, analyzers, inventory, ast) is counted.
    counters = {"critical": 0, "warning": 0, "info": 0}
    for line in Path(args.sink).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            severity = json.loads(line).get("severity", "info")
        except ValueError:
            continue
        if severity not in counters:
            severity = "info"
        counters[severity] += 1

    exit_code = 1 if counters["critical"] > 0 else 0
    if args.fail_critical >= 0 and counters["critical"] >= args.fail_critical:
        exit_code = 1
    if args.fail_warning >= 0 and counters["warning"] >= args.fail_warning:
        exit_code = 1
    elif args.fail_on_warning and (counters["critical"] + counters["warning"]) > 0:
        exit_code = 1

    if args.text_out:
        render_text(args, ast_ran, patterns)

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns), "ast": ast_ran,
                                 "prefilter": prefilter_res.to_dict()}) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
