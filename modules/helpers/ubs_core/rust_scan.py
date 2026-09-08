"""ubs_core.rust_scan — contract-v2 orchestrator for the Rust module (bead 0xjg.7).

ONE process replacing the legacy module's ~250-400 spawns: the rg-pipeline
checks run as in-process line scans over ONE in-memory read of the
authoritative file list, the ~140 ad-hoc ``ast-grep run --pattern`` counts
come from the consolidated ubs_core.rust_ast bridge (one ``scan -c`` per
400-path batch), the heredoc detectors are the ubs_core.rust_detectors
(narrowing_rust via the guard-JSON pipeline, ctcompare_rust instead of the
constant-time-compare heredoc, cfg_test_only_rust for the --exclude-tests
prefilter). Findings land in the K2 NDJSON sink; the legacy text report is
rendered from the same check results; categories 12/13/14 (cargo phases),
17 (rule pack passthrough) and 18 (inventory) stay as legacy-parity bridges
in modules/ubs-rust.sh.

Parity contract: per-check counts reproduce the legacy print_finding buckets
exactly — distinct matching lines for rg checks (with the legacy
``grep -Ev`` post-filters), per-pattern distinct (file, line, col) matches
for ast checks (summed across a check's patterns), heredoc counts for the
detector ports — under the same marker/test-line filtering the legacy
``count_lines`` stage applied (``grep -v ubs:ignore`` then
``filter_test_lines``).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

MARKER = "ubs:ignore"

# Meta-runner category_slug_for rust (ubs ~4961) and the module's
# CATEGORY_NAME table (ubs-rust.sh 520-543). Category 17 has a slug
# ("ast-grep") but its passthrough never produces records.
_CATEGORY_SLUGS: dict[int, str] = {
    1: "ownership", 2: "unsafe-memory", 3: "async", 4: "numeric",
    5: "collections", 6: "allocation", 7: "filesystem", 8: "security",
    9: "code-quality", 10: "modules", 11: "tests", 12: "lints",
    13: "build", 14: "dependencies", 15: "api-misuse", 16: "domain",
    17: "ast-grep", 18: "inventory", 19: "resource-lifecycle",
    20: "async-locking", 21: "panic", 22: "casts", 23: "parsing",
    24: "perf",
}

_SLUG_TO_CATEGORY: dict[str, int] = {slug: cat for cat, slug in _CATEGORY_SLUGS.items()}

_CATEGORY_HEADERS: dict[int, str] = {
    1: "1. OWNERSHIP & ERROR HANDLING MACROS",
    2: "2. UNSAFE & MEMORY OPERATIONS",
    3: "3. CONCURRENCY & ASYNC PITFALLS",
    4: "4. NUMERIC & FLOATING-POINT",
    5: "5. COLLECTIONS & ITERATORS",
    6: "6. STRING & ALLOCATION SMELLS",
    7: "7. FILESYSTEM & PROCESS",
    8: "8. SECURITY FINDINGS",
    9: "9. CODE QUALITY MARKERS",
    10: "10. MODULE & VISIBILITY ISSUES",
    11: "11. TESTS & BENCHES HYGIENE",
    15: "15. API MISUSE (COMMON)",
    16: "16. DOMAIN-SPECIFIC HEURISTICS",
    19: "19. RESOURCE LIFECYCLE CORRELATION",
    20: "20. ASYNC LOCKING ACROSS AWAIT",
    21: "21. PANIC SURFACES & UNWINDING",
    22: "22. SUSPICIOUS CASTS & TRUNCATION",
    23: "23. PARSING & VALIDATION ROBUSTNESS",
    24: "24. PERF/DoS HOTSPOTS",
}

_CATEGORY_PRINTS: dict[int, tuple[str, str]] = {
    1: ("Detects: unwrap/expect, panic/unreachable/todo/unimplemented, dbg/println",
        "Panic-prone and debug macros frequently leak into production and cause crashes"),
    2: ("Detects: unsafe blocks, transmute/uninitialized/zeroed/forget, raw ffi hazards",
        "These patterns may introduce UB, memory leaks, or hard-to-debug crashes"),
    3: ("Detects: Arc<Mutex>, Rc<RefCell>, blocking ops in async, await-in-loop, spawn misuse",
        "Concurrency misuse leads to deadlocks, head-of-line blocking, and performance issues"),
    4: ("Detects: float equality, division/modulo by variable, potential overflow hints",
        "Numeric bugs cause subtle logic errors or panics in debug builds (overflow)"),
    5: ("Detects: clone in loops, collect then iterate, nth(0), length checks",
        "Iterator misuse often leads to unnecessary allocations or slow paths"),
    6: ("Detects: needless allocations, format!(literal), to_owned().to_string()",
        "Unnecessary allocations and conversions reduce performance"),
    7: ("Detects: blocking std::fs in async, process::Command usage heuristics",
        "I/O misuse or command construction from untrusted input can be risky"),
    8: ("Detects: TLS verification disabled, weak hash algos, security-sensitive non-crypto randomness, timing-unsafe secret comparisons, JWT verification bypasses, shell command injection, request-derived response headers/open redirects/host-header absolute URLs/outbound URLs/SQL/regex, unbounded request body reads, credentialed CORS, HTTP URLs, secrets",
        "Security misconfigurations can lead to credential leaks, command injection, and MITM attacks"),
    9: ("Detects: TODO, FIXME, HACK, NOTE",
        "Technical debt markers indicate incomplete or problematic code"),
    10: ("Detects: pub use wildcards, glob imports, re-exports",
         "Overly broad visibility complicates API stability and encapsulation"),
    11: ("Detects: ignored tests, todo! in tests, println!/dbg! in tests",
         "Ensure tests do not hide failures or produce noisy output"),
    15: ("Detects: nth(0), DefaultHasher, expect_err/unwrap_err, Option::unwrap_or_default in hot paths",
         "Common footguns and readability hazards"),
    16: ("Detects: reqwest builder, SQL string concatenation (heuristic), serde_json::from_str without context",
         "Domain patterns that often hint at bugs"),
    19: ("Detects: std::thread::spawn without join, tokio::spawn without await, TcpStream without shutdown",
         "Rust relies on explicit joins/shutdowns even with RAII—leaks create zombie work"),
    20: ("Detects: locks acquired in async fns and potentially held across await",
         "Holding locks across await can deadlock, starve tasks, and cause latency spikes; std::sync locks can block executor threads"),
    21: ("Detects: assert macros, direct indexing, unreachable_unchecked/unwrap_unchecked, panic/unwrap inside Drop",
         "Panics in destructors or UB hints can crash/abort in subtle ways; these can slip past linting depending on cfg/features"),
    22: ("Detects: pervasive `as` casts, try_into().unwrap, numeric narrowing patterns",
         "`as` casts can silently truncate or change sign; conversion panics may be missed in uncommon input paths"),
    23: ("Detects: parse/from_str/env-var unwraps, decode unwraps, missing error context",
         "Parsing and decoding failures often happen in prod on edge inputs; unwrap/expect turns them into panics"),
    24: ("Detects: regex compilation in loops, chars().nth(n), format!/allocations in loops",
         "Some perf pitfalls become DoS risks on large inputs or hot paths; these often evade linting in non-bench builds"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Legacy display fragments (print_header / print_category / print_subheader /
# print_finding / print_code_sample, ubs-rust.sh 896-951).
# ─────────────────────────────────────────────────────────────────────────────
RED = "\033[0;31m"; GREEN = "\033[0;32m"; YELLOW = "\033[1;33m"; BLUE = "\033[0;34m"
MAGENTA = "\033[0;35m"; CYAN = "\033[0;36m"; WHITE = "\033[1;37m"; GRAY = "\033[0;90m"
BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
CHECK = "✓"; WARN = "⚠"; INFO = "ℹ"; BULLET = "•"; FIRE = "🔥"

_RULE_RE = re.compile(r"[A-Za-z0-9_]")


def _alnum_class(pattern: str) -> str:
    """Translate the POSIX classes the legacy rg pipelines used."""
    return pattern.replace("[:alnum:]_", "0-9A-Za-z_").replace("[:alnum:]", "0-9A-Za-z").replace("[:space:]", r"\s")


def compile_legacy(pattern: str, ignore_case: bool = False) -> re.Pattern:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(_alnum_class(pattern), flags)


# ─────────────────────────────────────────────────────────────────────────────
# Scan state
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Hit:
    path: str
    line: int
    col: int
    text: str


class Scan:
    def __init__(self, files: Sequence[Path], project_dir: Path, exclude_tests: bool,
                 skip: set[int], detail_limit: int, jobs: int = 1) -> None:
        self.project_dir = project_dir
        self.exclude_tests = exclude_tests
        self.skip = skip
        self.detail_limit = detail_limit
        self.jobs = max(1, int(jobs))
        self.files: list[Path] = [Path(f) for f in files]
        # Authoritative-file-set membership under BOTH spellings — the legacy
        # _ubs_allowed_key_add/_ubs_file_allowed pair also matched resolved
        # paths (readlink -f), and several detector ports resolve() entries.
        self.allowed: set[str] = set()
        self.texts: dict[Path, str] = {}
        self.lines_map: dict[Path, list[str]] = {}

        def _read_entry(p: Path) -> tuple[Path, str, list[str]]:
            try:
                t = p.read_text(encoding="utf-8", errors="ignore")
                return p, t, t.splitlines()
            except OSError:
                return p, "", []

        for path in list(self.files):
            self.allowed.add(str(path))
            try:
                self.allowed.add(str(path.resolve()))
            except OSError:
                pass

        if self.jobs > 1 and len(self.files) > 1:
            from ubs_core.shards import run_work_stealing

            entries = run_work_stealing(self.files, lambda shard: [_read_entry(p) for p in shard], num_workers=self.jobs)
            for p, t, lines in entries:
                if t:
                    self.texts[p] = t
                    self.lines_map[p] = lines
        else:
            for path in list(self.files):
                p, t, lines = _read_entry(path)
                if t:
                    self.texts[p] = t
                    self.lines_map[p] = lines

        self.test_only: set[str] = set()
        self.boundary_cache: dict[str, int] = {}
        self.counters: Counter = Counter()
        self.records: list[dict] = []
        self.checks: list[dict] = []
        self.ast_matches: dict[str, list[dict]] = {}
        self._detector_cache: dict[tuple, list[Hit]] = {}

    # ── legacy filter_test_lines / _ubs_test_boundary (839-894) ────────────
    def test_boundary(self, path_str: str) -> int:
        if path_str in self.boundary_cache:
            return self.boundary_cache[path_str]
        path = Path(path_str)
        lines = self.lines_map.get(path)
        if lines is None:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                lines = []
        b1 = b2 = 0
        for idx, line in enumerate(lines, start=1):
            if b1 == 0 and "#[cfg(test)]" in line:
                b1 = idx
            if b2 == 0 and re.match(r"^\s*mod tests(\s|\{|;|$)", line):
                b2 = idx
            if b1 and b2:
                break
        if b1 and b2:
            boundary = min(b1, b2)
        else:
            boundary = b1 or b2
        self.boundary_cache[path_str] = boundary
        return boundary

    def _is_test_line(self, path_str: str, line_no: int) -> bool:
        if not self.exclude_tests:
            return False
        norm = path_str.replace("\\", "/")
        parts = norm.split("/")
        for i in range(len(parts) - 1):
            if parts[i] in ("tests", "benches"):
                return True
        if path_str in self.test_only or str(Path(path_str).resolve()) in self.test_only:
            return True
        boundary = self.test_boundary(path_str)
        return boundary > 0 and line_no >= boundary

    # ── legacy count_lines stage (grep -v marker | filter_test_lines) ──────
    def stream_line_allowed(self, path_str: str, line_no: int, code: str) -> bool:
        if MARKER in code:
            return False
        return not self._is_test_line(path_str, line_no)

    # ── rg pipeline equivalent: distinct matching lines ────────────────────
    def rg_lines(self, pattern: str, ignore_case: bool = False,
                 exclude_pattern: str | None = None,
                 word_boundary: bool = False) -> list[Hit]:
        regex = compile_legacy(pattern, ignore_case)
        exclude = compile_legacy(exclude_pattern) if exclude_pattern else None
        hits: list[Hit] = []
        for path, lines in self.lines_map.items():
            path_str = str(path)
            for line_no, line in enumerate(lines, start=1):
                if not regex.search(line):
                    continue
                stream = f"{path_str}:{line_no}:{line}"
                if exclude is not None and exclude.search(stream):
                    continue
                if MARKER in line:
                    continue  # count_lines drops marker lines
                if self._is_test_line(path_str, line_no):
                    continue
                hits.append(Hit(path_str, line_no, 1, line))
        return hits

    # legacy rust_code_match_lines (1034-1047): strip `//`-comments from the
    # code fragment, then re-match the pattern on the fragment.
    def code_match_lines(self, pattern: str, files: Iterable[Path] | None = None) -> list[Hit]:
        regex = compile_legacy(pattern)
        hits: list[Hit] = []
        targets = list(files) if files is not None else self.files
        for path in targets:
            lines = self.lines_map.get(path)
            if lines is None:
                continue
            path_str = str(path)
            for line_no, line in enumerate(lines, start=1):
                if not regex.search(line):
                    continue
                if MARKER in line or self._is_test_line(path_str, line_no):
                    continue
                code = line.split("//", 1)[0]
                if not regex.search(code):
                    continue
                hits.append(Hit(path_str, line_no, 1, line))
        return hits

    # ── ast layer ──────────────────────────────────────────────────────────
    def load_ast_matches(self, rule_dir: Path | None, ast_files: Sequence[Path] | None = None) -> None:
        if rule_dir is None:
            return
        from ubs_core import rust_ast

        targets = ast_files if ast_files is not None else self.files
        _, matches = rust_ast.scan_all(rule_dir, targets)
        allowed = self.allowed
        for rule_id, entries in matches.items():
            kept: list[dict] = []
            seen: set[tuple] = set()
            for entry in entries:
                key = (entry["path"], entry["line"], entry["col"])
                if key in seen:
                    continue  # legacy per-pattern (file,line,col) dedup
                seen.add(key)
                if entry["path"] not in allowed:
                    continue  # GH #70 authoritative-file-set enforcement
                if not self.stream_line_allowed(entry["path"], entry["line"], self._source_line(entry["path"], entry["line"])):
                    continue
                kept.append(entry)
            if kept:
                self.ast_matches.setdefault(rule_id, []).extend(kept)

    def _source_line(self, path_str: str, line_no: int) -> str:
        path = Path(path_str)
        lines = self.lines_map.get(path)
        if lines is None:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                return ""
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return ""

    def ast_hits(self, slugs: Sequence[str]) -> list[Hit]:
        hits: list[Hit] = []
        for slug in slugs:
            for entry in self.ast_matches.get(f"rust.ast.{slug}", []):
                hits.append(Hit(entry["path"], entry["line"], entry["col"], entry.get("text", "")))
        return hits

    # ── detectors (heredoc ports) ──────────────────────────────────────────
    def detector_hits(self, module_name: str, *args) -> list[Hit]:
        key = (module_name,) + args
        if key in self._detector_cache:
            return self._detector_cache[key]
        import importlib

        hits: list[Hit] = []
        try:
            module = importlib.import_module(f"ubs_core.rust_detectors.{module_name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully
            sys.stderr.write(f"[ubs_core.rust_scan] detector {module_name} failed: {exc}\n")
            self._detector_cache[key] = hits
            return hits
        find = getattr(module, "find", None)
        if find is None:
            self._detector_cache[key] = hits
            return hits
        for hit in find(self.files, *args):
            path_str, line_no, col, code = hit[0], hit[1], hit[2], hit[3]
            path_str = str(path_str)
            p = Path(path_str)
            if not p.is_file() and (self.project_dir / p).is_file():
                resolved = (self.project_dir / p).resolve()
                matched = False
                for f in self.files:
                    if f.resolve() == resolved:
                        path_str = str(f)
                        matched = True
                        break
                if not matched:
                    path_str = str(self.project_dir / p)
            # legacy: heredoc stdout -> count_lines (marker + test filter)
            if MARKER in code or self._is_test_line(path_str, int(line_no)):
                continue
            hits.append(Hit(path_str, int(line_no), int(col), code))
        self._detector_cache[key] = hits
        return hits

    # ── recording ──────────────────────────────────────────────────────────
    def emit(self, rule_id: str, category: int, severity: str, count: int,
             title: str, hits: Sequence[Hit] | None = None,
             bucket_count: int | None = None, desc: str = "",
             sample_limit: int = 0, path: str = "", line: int = 1, col: int = 1,
             subheader: str = "") -> None:
        slug = _CATEGORY_SLUGS[category]
        if bucket_count is None:
            bucket_count = count
        self.counters[severity] += bucket_count
        samples = [f"{h.path}:{h.line}:{h.text}" for h in (hits or [])[:sample_limit or 5]]
        self.checks.append({
            "severity": severity,
            "count": bucket_count,
            "category": _CATEGORY_NAME[category],
            "title": title,
            "description": desc,
            "samples": samples,
        })
        subh = subheader or _RULE_TO_SUBHEADER.get(rule_id, "")
        if hits:
            for hit in hits:
                self.records.append({
                    "rule": rule_id,
                    "category_id": f"rust.{slug}",
                    "category": category,
                    "title": title,
                    "desc": desc,
                    "subheader": subh,
                    "text": hit.text,
                    "path": hit.path,
                    "line": hit.line,
                    "col": hit.col,
                    "severity": severity,
                    "message": f"{title} — {hit.text.strip()[:240]}" if hit.text else title,
                    "suppressed": False,
                    "sample_limit": sample_limit,
                })
        else:
            if not path and self.files:
                path = str(self.files[0])
            self.records.append({
                "rule": rule_id,
                "category_id": f"rust.{slug}",
                "category": category,
                "title": title,
                "desc": desc,
                "subheader": subh,
                "text": "",
                "path": path,
                "line": line,
                "col": col,
                "severity": severity,
                "message": title,
                "suppressed": False,
                "count": bucket_count,
                "title": title,
                "category_name": _CATEGORY_NAME[category],
                "sample_limit": sample_limit,
            })



_CATEGORY_NAME = {
    1: "Ownership & Error Handling", 2: "Unsafe & Memory Operations",
    3: "Concurrency & Async Pitfalls", 4: "Numeric & Floating-Point",
    5: "Collections & Iterators", 6: "String & Allocation Smells",
    7: "Filesystem & Process", 8: "Security Findings",
    9: "Code Quality Markers", 10: "Module & Visibility Issues",
    11: "Tests & Benches Hygiene", 12: "Lints & Style (fmt/clippy)",
    13: "Build Health (check/test)", 14: "Dependency Hygiene",
    15: "API Misuse (Common)", 16: "Domain-Specific Heuristics",
    17: "AST-Grep Rule Pack Findings", 18: "Meta Statistics & Inventory",
    19: "Resource Lifecycle Correlation", 20: "Async Locking Across Await",
    21: "Panic Surfaces & Unwinding", 22: "Suspicious Casts & Truncation",
    23: "Parsing & Validation Robustness", 24: "Perf/DoS Hotspots",
}

_RULE_TO_SUBHEADER: dict[str, str] = {
    "rust.ownership.unwrap-expect": "unwrap()/expect() usage",
    "rust.ownership.panic-macro": "panic!/unreachable!/todo!/unimplemented!",
    "rust.ownership.unreachable-macro": "panic!/unreachable!/todo!/unimplemented!",
    "rust.ownership.todo-macro": "panic!/unreachable!/todo!/unimplemented!",
    "rust.ownership.unimplemented-macro": "panic!/unreachable!/todo!/unimplemented!",
    "rust.ownership.dbg-macro": "dbg!/println!/eprintln!",
    "rust.ownership.println-macro": "dbg!/println!/eprintln!",
    "rust.ownership.eprintln-macro": "dbg!/println!/eprintln!",
    "rust.ownership.guarded-later-unwrap": "Guard clauses that still unwrap later",
    "rust.resource-lifecycle.thread_join": "Resource lifecycle correlation",
    "rust.resource-lifecycle.tokio_spawn": "Resource lifecycle correlation",
    "rust.resource-lifecycle.tcp_shutdown": "Resource lifecycle correlation",
    "rust.async-locking.std-lock-async": "std::sync lock usage inside async fn (blocking risk)",
    "rust.async-locking.std-guard-await": "Potential std::sync guard held across await (heuristic)",
    "rust.async-locking.tokio-guard-await": "Potential async lock guard held across await (tokio/async locks heuristic)",
    "rust.async.tokio-task-no-await": "Async error path coverage",
    "rust.async.spawn-handle-heuristic": "tokio::spawn usage (heuristic for detached tasks)",
}


def _sub(scan: Scan, r: Renderer, hits: Sequence[Hit], rule_id: str, category: int,
         severity: str, title: str, desc: str = "", sample_limit: int = 0,
         good: str | None = None) -> int:
    if hits:
        r.finding(severity, len(hits), title, desc, hits, sample_limit)
        scan.emit(rule_id, category, severity, len(hits), title, hits,
                  desc=desc, sample_limit=sample_limit or scan.detail_limit or 3)
        return len(hits)
    if good is not None:
        r.finding("good", 0, good)
    return 0


class Renderer:
    """Legacy print_header/print_category/print_subheader/print_finding formats."""

    def __init__(self, scan: Scan, quiet: bool = False) -> None:
        self.scan = scan
        self.quiet = quiet
        self.lines: list[str] = []
        self._emitted_headers: set[int] = set()
        self._emitted_categories: set[int] = set()

    def say(self, line: str = "") -> None:
        if not self.quiet:
            self.lines.append(line)

    def header(self, category: int) -> None:
        if category in self._emitted_headers:
            return
        self._emitted_headers.add(category)
        title = _CATEGORY_HEADERS[category]
        bar = "━" * 64
        self.say("")
        self.say(f"{CYAN}{BOLD}{bar}{RESET}")
        self.say(f"{WHITE}{BOLD}{title}{RESET}")
        self.say(f"{CYAN}{bar}{RESET}")

    def category(self, category: int) -> None:
        if category in self._emitted_categories:
            return
        self._emitted_categories.add(category)
        detects, remediation = _CATEGORY_PRINTS[category]
        self.say("")
        self.say(f"{MAGENTA}{BOLD}▓▓▓ {detects}{RESET}")
        self.say(f"{DIM}{remediation}{RESET}")

    def subheader(self, text: str) -> None:
        self.say("")
        self.say(f"{YELLOW}{BOLD}{BULLET} {text}{RESET}")

    def finding(self, severity: str, count: int, title: str, desc: str = "",
                samples: Sequence[Hit] | None = None, sample_limit: int = 0) -> None:
        if severity == "good":
            self.say(f"  {GREEN}{CHECK} OK{RESET} {DIM}{title}{RESET}")
            return
        if severity == "critical":
            self.say(f"  {RED}{BOLD}{FIRE} CRITICAL{RESET} {WHITE}({count} found){RESET}")
            self.say(f"    {RED}{BOLD}{title}{RESET}")
            if desc:
                self.say(f"    {DIM}{desc}{RESET}")
        elif severity == "warning":
            self.say(f"  {YELLOW}{WARN} Warning{RESET} {WHITE}({count} found){RESET}")
            self.say(f"    {YELLOW}{title}{RESET}")
            if desc:
                self.say(f"    {DIM}{desc}{RESET}")
        else:
            self.say(f"  {BLUE}{INFO} Info{RESET} {WHITE}({count} found){RESET}")
            self.say(f"    {BLUE}{title}{RESET}")
            if desc:
                self.say(f"    {DIM}{desc}{RESET}")
        for hit in (samples or [])[:sample_limit or self.scan.detail_limit]:
            self.say(f"{GRAY}      {hit.path}:{hit.line}{RESET}")
            self.say(f"{WHITE}      {hit.text}{RESET}")

    def text(self) -> str:
        return "\n".join(self.lines) + ("\n" if self.lines else "")


def replay_findings(scan: Scan, r: Renderer, cached_records: Sequence[dict]) -> None:
    if not cached_records:
        return
    scan.records.extend(cached_records)
    for rec in cached_records:
        sev = rec.get("severity", "info")
        scan.counters[sev] += int(rec.get("count", 1) or 1)

    by_cat: dict[int, dict[tuple[str, str, str, str], list[dict]]] = {}
    for rec in cached_records:
        cat = rec.get("category")
        if cat is None:
            slug = rec.get("category_id", "").replace("rust.", "")
            cat = _SLUG_TO_CATEGORY.get(slug, 8)
        rule = rec.get("rule", "")
        sev = rec.get("severity", "info")
        title = rec.get("title")
        if not title:
            msg = rec.get("message", "Finding")
            title = msg.split(" — ", 1)[0] if " — " in msg else msg
        desc = rec.get("desc") or rec.get("description", "")
        by_cat.setdefault(cat, {}).setdefault((rule, sev, title, desc), []).append(rec)

    emitted_subheaders: set[str] = set()
    for cat in sorted(by_cat):
        if cat in scan.skip:
            continue
        if cat in _CATEGORY_HEADERS:
            r.header(cat)
        if cat in _CATEGORY_PRINTS:
            r.category(cat)
        for (rule, sev, title, desc), recs in by_cat[cat].items():
            subh = recs[0].get("subheader") or _RULE_TO_SUBHEADER.get(rule, "")
            if subh and subh not in emitted_subheaders:
                r.subheader(subh)
                emitted_subheaders.add(subh)
            total_count = sum(int(rec.get("count", 1) or 1) for rec in recs)
            hits: list[Hit] = []
            for rec in recs:
                p = rec.get("path", "")
                if p:
                    text = rec.get("text")
                    if text is None:
                        msg = rec.get("message", "")
                        text = msg.split(" — ", 1)[1] if " — " in msg else ""
                    hits.append(Hit(p, int(rec.get("line", 1) or 1), int(rec.get("col", 1) or 1), text or ""))
            sample_limit = recs[0].get("sample_limit", 0)
            if sample_limit > 0 and hits:
                r.finding(sev, total_count, title, desc, hits, sample_limit=sample_limit)
            else:
                r.finding(sev, total_count, title, desc)
            samples = [f"{h.path}:{h.line}:{h.text}" for h in hits[:5]]
            scan.checks.append({
                "severity": sev,
                "count": total_count,
                "category": _CATEGORY_NAME.get(cat, f"Category {cat}"),
                "title": title,
                "description": desc,
                "samples": samples,
            })


# ─────────────────────────────────────────────────────────────────────────────
# Analyzers (legacy invocations, in process)
# ─────────────────────────────────────────────────────────────────────────────
def run_narrowing(scan: Scan, skip_type_narrowing: bool) -> list[Hit]:
    """Legacy run_rust_type_narrowing_checks (451-501): guard-JSON pipeline
    from two `ast-grep run --pattern --json` spawns fed to
    narrowing_rust.analyze_with_ast_json, falling back to the regex walk
    when it yields nothing."""
    if skip_type_narrowing:
        return []
    from ubs_core.analyzers import narrowing_rust

    guard_json = _emit_guard_matches(scan.project_dir)
    try:
        if guard_json is not None:
            issues = narrowing_rust.analyze_with_ast_json(scan.project_dir, guard_json)
            if not issues:
                issues = narrowing_rust.analyze_with_regex(scan.project_dir)
        else:
            issues = _narrowing_regex_over_list(scan)
    finally:
        if guard_json is not None:
            guard_json.unlink(missing_ok=True)
    hits: list[Hit] = []
    allowed = scan.allowed
    for path, line, col, message in issues:
        path_str = str(path)
        if path_str not in allowed:
            # legacy guard entries came from the raw project walk; the
            # authoritative-file-set filter applied to their matches too
            continue
        if not scan.stream_line_allowed(path_str, line, scan._source_line(path_str, line)):
            continue
        hits.append(Hit(path_str, line, col, message))
    return hits


def _narrowing_regex_over_list(scan: Scan):
    from ubs_core.analyzers.narrowing_rust import analyze_file_regex

    issues = []
    for path in scan.files:
        try:
            issues.extend((path, line, col, msg) for line, col, msg in analyze_file_regex(path))
        except OSError:
            continue
    return issues


def _emit_guard_matches(project_dir: Path) -> Path | None:
    """Legacy emit_rust_guard_matches (433-449): two pattern-mode JSONL
    spawns concatenated into one file. Returns None when ast-grep is
    unavailable (the caller then uses the regex fallback over the list)."""
    import subprocess
    import tempfile

    ast_grep = _ast_grep_bin()
    if ast_grep is None:
        return None
    fd, tmp_path = tempfile.mkstemp(prefix="ubs-v2-rust-guards-", suffix=".jsonl")
    os.close(fd)
    tmp = Path(tmp_path)
    patterns = (
        "if let Some($BIND) = $SOURCE { $BODY }",
        "if let Ok($BIND) = $SOURCE { $BODY }",
    )
    with tmp.open("w", encoding="utf-8") as fh:
        for pattern in patterns:
            try:
                proc = subprocess.run(
                    [ast_grep, "run", "--pattern", pattern, "-l", "rust", "--json", str(project_dir)],
                    capture_output=True, text=True, timeout=300,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)
                except ValueError:
                    continue
                fh.write(line + "\n")
    return tmp


_AST_GREP_CACHE: str | None = None


def _ast_grep_bin() -> str | None:
    """Legacy check_ast_grep (7040-7062): ast-grep, or an ast-grep `sg`."""
    global _AST_GREP_CACHE
    if _AST_GREP_CACHE is not None:
        return _AST_GREP_CACHE or None
    import shutil

    import subprocess

    if shutil.which("ast-grep"):
        _AST_GREP_CACHE = "ast-grep"
        return _AST_GREP_CACHE
    sg = shutil.which("sg")
    if sg:
        out = subprocess.run([sg, "--version"], capture_output=True, text=True).stdout
        if "ast-grep" not in out.lower():
            out = subprocess.run([sg, "--help"], capture_output=True, text=True).stdout
        if "ast-grep" in out.lower():
            _AST_GREP_CACHE = sg
            return _AST_GREP_CACHE
    _AST_GREP_CACHE = ""
    return None


def run_ctcompare(scan: Scan) -> list[Hit]:
    """Legacy count_constant_time_compare_matches — the heredoc is the
    ctcompare_rust analyzer (A2 verbatim port); run it over the file list."""
    from ubs_core.analyzers import ctcompare_rust
    from ubs_core.registry import RunContext

    ctx = RunContext(lang="rust", files=list(scan.files))
    hits: list[Hit] = []
    for finding in ctcompare_rust.run(ctx):
        path_str = str(finding.get("path", ""))
        line = int(finding.get("line", 1))
        if not scan.stream_line_allowed(path_str, line, scan._source_line(path_str, line)):
            continue
        hits.append(Hit(path_str, line, int(finding.get("col", 1)), str(finding.get("message", ""))))
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# Computed checks (legacy bash/python hybrids)
# ─────────────────────────────────────────────────────────────────────────────
def async_error_files(scan: Scan) -> list[tuple[str, str]]:
    """Legacy run_async_error_checks (1090-1139). Returns per-file dropped
    handle lists as (path_str, missing_csv); empty list = no spawn files."""
    spawn_files = sorted({h.path for h in scan.rg_lines(r"tokio::spawn\(")})
    results: list[tuple[str, str]] = []
    name_re = re.compile(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*tokio::spawn")
    for path in scan.files:
        if str(path) not in spawn_files:
            continue
        text = scan.texts.get(path)
        if text is None:
            continue
        missing = []
        for name in name_re.findall(text):
            if re.search(rf"\b{name}\.await", text) or re.search(rf"\b{name}\.abort", text):
                continue
            missing.append(name)
        if missing:
            results.append((str(path), ",".join(missing)))
    return results


def resource_lifecycle(scan: Scan) -> list[dict]:
    """Legacy run_resource_lifecycle_checks (1049-1088)."""
    spec = (
        ("thread_join", "critical", "std::thread::spawn", r"\.join\(",
         "std::thread::spawn without join()",
         "Store the JoinHandle and call join() or detach intentionally"),
        ("tokio_spawn", "warning", "tokio::spawn", r"\.await",
         "tokio::spawn tasks not awaited/cancelled",
         "Await the JoinHandle result or abort/cancel the task explicitly"),
        ("tcp_shutdown", "warning", "TcpStream::connect", r"\.shutdown\(",
         "TcpStream without shutdown()",
         "Call shutdown() or drop connections explicitly when done"),
    )
    out: list[dict] = []
    for rid, severity, acquire, release, summary, remediation in spec:
        files = sorted({h.path for h in scan.code_match_lines(acquire)})
        for file_str in files:
            acquire_hits = len(scan.code_match_lines(acquire, [Path(file_str)]))
            release_hits = len(scan.code_match_lines(release, [Path(file_str)]))
            if acquire_hits > release_hits:
                relpath = file_str
                prefix = f"{scan.project_dir}/"
                if relpath.startswith(prefix):
                    relpath = relpath[len(prefix):]
                out.append({
                    "rid": rid, "severity": severity, "file": file_str,
                    "delta": acquire_hits - release_hits,
                    "title": f"{summary} [{relpath}]",
                    "desc": f"{remediation} (acquire={acquire_hits}, release={release_hits})",
                })
    return out


def _ladder(count: int, *tiers: tuple[int, str]) -> str | None:
    for min_count, severity in tiers:
        if count >= min_count:
            return severity
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Category flows — ubs-rust.sh 8352-9778 in legacy order
# ─────────────────────────────────────────────────────────────────────────────
def cat_1(scan: Scan, r: Renderer, narrowing: list[Hit], narrowing_skip_note: str | None) -> None:
    r.header(1); r.category(1)
    u = scan.ast_hits(["unwrap"]); e = scan.ast_hits(["expect"])
    r.subheader("unwrap()/expect() usage")
    if u or e:
        r.finding("warning", len(u) + len(e), "Potential panics via unwrap/expect",
                  "Prefer `?` or match to propagate/handle errors", u + e, 5)
        scan.emit("rust.ownership.unwrap-expect", 1, "warning", len(u) + len(e),
                  "Potential panics via unwrap/expect", u + e)
    else:
        r.finding("good", 0, "No unwrap/expect detected")
    r.subheader("panic!/unreachable!/todo!/unimplemented!")
    _sub(scan, r, scan.ast_hits(["panic"]), "rust.ownership.panic-macro", 1,
         "critical", "panic! macro(s) present", "Avoid panic! in library code", 5,
         "No panic! macros")
    _sub(scan, r, scan.ast_hits(["unreachable"]), "rust.ownership.unreachable-macro", 1,
         "warning", "unreachable! may panic if reached", "Double-check logic", 3)
    _sub(scan, r, scan.ast_hits(["todo"]), "rust.ownership.todo-macro", 1,
         "warning", "todo! placeholders present", "Implement or gate with cfg(test)", 3)
    _sub(scan, r, scan.ast_hits(["unimplemented"]), "rust.ownership.unimplemented-macro", 1,
         "warning", "unimplemented! placeholders present", "Implement or remove", 3)
    r.subheader("dbg!/println!/eprintln!")
    _sub(scan, r, scan.ast_hits(["dbg"]), "rust.ownership.dbg-macro", 1,
         "info", "dbg! macros present", "", 3)
    _sub(scan, r, scan.ast_hits(["println"]), "rust.ownership.println-macro", 1,
         "info", "println! found - prefer logging", "", 3)
    _sub(scan, r, scan.ast_hits(["eprintln"]), "rust.ownership.eprintln-macro", 1,
         "info", "eprintln! found - prefer logging", "", 3)
    r.subheader("Guard clauses that still unwrap later")
    if narrowing_skip_note is not None:
        r.finding("info", 0, "Rust type narrowing heuristics skipped",
                  "Set UBS_SKIP_TYPE_NARROWING=0 or remove --skip-type-narrowing to re-enable")
        return
    if narrowing:
        previews = [f"{h.path}:{h.line}:{h.col} → {h.text}" for h in narrowing[:3]]
        desc = "Examples: " + " ".join(previews)
        if len(narrowing) > len(previews):
            desc += f" (and {len(narrowing) - len(previews)} more)"
        r.finding("warning", len(narrowing), "Guarded Option/Result later unwrap", desc)
        scan.emit("rust.ownership.guarded-later-unwrap", 1, "warning", len(narrowing),
                  "Guarded Option/Result later unwrap", narrowing, desc=desc,
                  subheader="Guard clauses that still unwrap later")
    else:
        r.finding("good", 0, "No guard/unwrap mismatches detected")


def cat_2(scan: Scan, r: Renderer) -> None:
    r.header(2); r.category(2)
    r.subheader("unsafe { ... } blocks")
    _sub(scan, r, scan.ast_hits(["unsafe_block"]), "rust.unsafe-memory.unsafe-blocks", 2,
         "info", "unsafe blocks present", "Ensure invariants and narrow scope", 3,
         "No unsafe blocks detected")
    r.subheader("transmute, uninitialized, zeroed, assume_init, forget")
    _sub(scan, r, scan.ast_hits(["transmute_std", "transmute_mem", "transmute_bare"]),
         "rust.unsafe-memory.transmute", 2, "critical", "mem::transmute usage", "", 3)
    _sub(scan, r, scan.ast_hits(["uninit_std", "uninit_mem"]),
         "rust.unsafe-memory.uninitialized", 2, "critical", "mem::uninitialized usage", "", 3)
    _sub(scan, r, scan.ast_hits(["zeroed_std_t", "zeroed_mem_t", "zeroed_std", "zeroed_mem", "zeroed_bare"]),
         "rust.unsafe-memory.zeroed", 2, "critical", "mem::zeroed usage", "", 3)
    _sub(scan, r, scan.ast_hits(["assume_init"]), "rust.unsafe-memory.assume-init", 2,
         "critical", "MaybeUninit::assume_init usage",
         "Only call after every byte is initialized; prefer safe constructors or write() before assume_init", 3)
    _sub(scan, r, scan.ast_hits(["forget_std", "forget_mem"]),
         "rust.unsafe-memory.forget", 2, "warning", "mem::forget leaks memory", "", 3)
    r.subheader("CStr::from_bytes_with_nul_unchecked")
    _sub(scan, r, scan.ast_hits(["cstr_std", "cstr_bare"]),
         "rust.unsafe-memory.cstr-unchecked", 2, "warning", "CStr unchecked conversion used", "", 3)
    r.subheader("get_unchecked / from_utf8_unchecked / from_raw_parts")
    _sub(scan, r, scan.ast_hits(["get_unchecked", "get_unchecked_mut"]),
         "rust.unsafe-memory.unchecked-indexing", 2, "warning", "Unchecked indexing APIs in use", "", 3)
    _sub(scan, r, scan.ast_hits(["utf8_std", "utf8_str", "utf8_string_std", "utf8_string"]),
         "rust.unsafe-memory.utf8-unchecked", 2, "warning", "UTF-8 unchecked conversion APIs", "", 3)
    _sub(scan, r, scan.ast_hits(["raw_parts_std", "raw_parts_std_mut", "raw_parts_slice", "raw_parts_slice_mut"]),
         "rust.unsafe-memory.from-raw-parts", 2, "warning", "slice::from_raw_parts(_mut) usage", "", 3)
    r.subheader("Unsafe Send/Sync impls")
    _sub(scan, r, scan.ast_hits(["unsafe_impl_send", "unsafe_impl_sync"]),
         "rust.unsafe-memory.unsafe-impl-send-sync", 2, "warning", "Unsafe Send/Sync implementations", "", 3)


def cat_3(scan: Scan, r: Renderer) -> None:
    r.header(3); r.category(3)
    r.subheader("Arc<Mutex<..>> / Rc<RefCell<..>> / RwLock")
    arc = scan.rg_lines(r"Arc<\s*Mutex<")
    if arc:
        r.finding("info", len(arc), "Arc<Mutex<..>> detected - verify contention")
        scan.emit("rust.async.arc-mutex", 3, "info", len(arc), "Arc<Mutex<..>> detected - verify contention", arc)
    rc = scan.rg_lines(r"Rc<\s*RefCell<")
    if rc:
        r.finding("warning", len(rc), "Rc<RefCell<..>> borrow panics possible")
        scan.emit("rust.async.rc-refcell", 3, "warning", len(rc), "Rc<RefCell<..>> borrow panics possible", rc)
    rw = scan.rg_lines(r"RwLock<")
    if rw:
        r.finding("info", len(rw), "RwLock in use - verify read/write patterns")
        scan.emit("rust.async.rwlock", 3, "info", len(rw), "RwLock in use - verify read/write patterns", rw)
    r.subheader("Mutex::lock().unwrap()/expect()")
    mu = scan.ast_hits(["lock_unwrap", "lock_expect"]) + scan.rg_lines(r"\.lock\(\)\.(unwrap|expect)\(")
    if mu:
        r.finding("warning", len(mu), "Poisoned lock handling via unwrap/expect", "", mu[:5], 5)
        scan.emit("rust.async.lock-unwrap", 3, "warning", len(mu), "Poisoned lock handling via unwrap/expect", mu)
    r.subheader("await inside loops (sequentialism)")
    al = scan.ast_hits(["await_in_for"]) + scan.rg_lines(r"for[^(]*\{[^}]*\.[0-9A-Za-z_]+\.await")
    if al:
        r.finding("info", len(al), "await inside loop; consider batched concurrency")
        scan.emit("rust.async.await-in-loop", 3, "info", len(al), "await inside loop; consider batched concurrency", al)
    r.subheader("Blocking ops inside async (thread::sleep, std::fs)")
    _sub(scan, r, scan.detector_hits("async_context", "sleep"), "rust.async.sleep-in-async", 3,
         "warning", "thread::sleep in async", "", 3)
    _sub(scan, r, scan.detector_hits("async_context", "fs"), "rust.async.fs-in-async", 3,
         "info", "Blocking std::fs in async code", "", 3)
    r.subheader("block_on within async context")
    _sub(scan, r, scan.detector_hits("async_context", "block_on"), "rust.async.block-on-in-async", 3,
         "warning", "block_on within async function", "", 3)
    r.subheader("std::thread::spawn within async")
    _sub(scan, r, scan.detector_hits("async_context", "thread_spawn"), "rust.async.thread-spawn-in-async", 3,
         "warning", "std::thread::spawn inside async fn", "", 3)
    r.subheader("tokio::spawn usage (heuristic for detached tasks)")
    spawn = scan.rg_lines(r"tokio::spawn\(")
    handles = scan.rg_lines(r"JoinHandle<|\.await")
    if spawn and len(handles) < len(spawn):
        diff = len(spawn) - len(handles)
        desc = "Ensure detached tasks handle errors appropriately"
        r.finding("info", diff, "spawn without awaiting JoinHandle (heuristic)", desc)
        p = spawn[0].path if spawn else (str(scan.files[0]) if scan.files else "")
        l = spawn[0].line if spawn else 1
        c = spawn[0].col if spawn else 1
        scan.emit("rust.async.spawn-handle-heuristic", 3, "info", diff,
                  "spawn without awaiting JoinHandle (heuristic)", bucket_count=diff,
                  desc=desc, path=p, line=l, col=c)
    r.subheader("Async error path coverage")
    dropped = async_error_files(scan)
    if not dropped:
        r.finding("good", 0, "No tokio::spawn usage detected")
    else:
        for path_str, missing in dropped:
            relpath = path_str
            prefix = f"{scan.project_dir}/"
            if relpath.startswith(prefix):
                relpath = relpath[len(prefix):]
            desc = f"Await or abort JoinHandles returned by tokio::spawn ({relpath})"
            hit = Hit(path_str, 1, 1, f"tokio::spawn handles dropped: {missing}")
            r.finding("warning", 1, "tokio::spawn JoinHandle dropped", desc)
            scan.emit("rust.async.tokio-task-no-await", 3, "warning", 1,
                      "tokio::spawn JoinHandle dropped", [hit])


def cat_4(scan: Scan, r: Renderer) -> None:
    r.header(4); r.category(4)
    r.subheader("Floating-point equality comparisons")
    fp = scan.rg_lines(r"([0-9A-Za-z_]\s*(==|!=)\s*[0-9A-Za-z_]*\.[0-9A-Za-z_]+)|((==|!=)[\s]*[0-9]+\.[0-9]+)")
    if fp:
        r.finding("info", len(fp), "Float equality/inequality check", "Consider epsilon comparisons", fp[:3], 3)
        scan.emit("rust.numeric.float-equality", 4, "info", len(fp),
                  "Float equality/inequality check", fp)
    else:
        r.finding("good", 0, "No direct float equality checks detected")
    r.subheader("Division/modulo by variable (verify non-zero)")
    div = scan.rg_lines(r"/[\s]*[a-zA-Z_][a-zA-Z0-9_]*", exclude_pattern=r"https?://|//|/\*")
    if div:
        r.finding("info", len(div), "Division by variables - guard zero divisors")
        scan.emit("rust.numeric.division-by-var", 4, "info", len(div),
                  "Division by variables - guard zero divisors", div)
    mod = scan.rg_lines(r"%[\s]*[a-zA-Z_][a-zA-Z0-9_]*", exclude_pattern=r"//|/\*")
    if mod:
        r.finding("info", len(mod), "Modulo by variables - guard zero divisors")
        scan.emit("rust.numeric.modulo-by-var", 4, "info", len(mod),
                  "Modulo by variables - guard zero divisors", mod)


def cat_5(scan: Scan, r: Renderer) -> None:
    r.header(5); r.category(5)
    r.subheader("clone() occurrences & clone() in loops")
    clone = scan.ast_hits(["clone"])
    if clone:
        r.finding("info", len(clone), "clone() usages - audit for necessity", "", clone[:3], 3)
        scan.emit("rust.collections.clone-any", 5, "info", len(clone),
                  "clone() usages - audit for necessity", clone)
    clone_loop = scan.detector_hits("loop_context", "clone")
    if clone_loop:
        r.finding("warning", len(clone_loop), "clone() inside loops - potential perf hit", "", clone_loop[:3], 3)
        scan.emit("rust.collections.clone-in-loop", 5, "warning", len(clone_loop),
                  "clone() inside loops - potential perf hit", clone_loop)
    r.subheader("collect::<Vec<_>>() then for")
    _sub(scan, r, scan.ast_hits(["collect_vec"]), "rust.collections.collect-vec", 5,
         "info", "collect::<Vec<_>>() usage - consider streaming", "", 3)
    r.subheader("nth(0) → next()")
    _sub(scan, r, scan.ast_hits(["nth0"]), "rust.collections.nth0", 5,
         "info", "nth(0) detected - prefer next()", "", 3)


def cat_6(scan: Scan, r: Renderer) -> None:
    r.header(6); r.category(6)
    r.subheader("to_owned().to_string() chain")
    _sub(scan, r, scan.ast_hits(["to_owned_to_string"]), "rust.allocation.to-owned-to-string", 6,
         "info", "to_owned().to_string() chain - simplify", "", 3)
    r.subheader("format!(\"literal\") with no placeholders")
    _sub(scan, r, scan.detector_hits("format_literal"), "rust.allocation.format-literal", 6,
         "info", "format!(literal) allocates - use .to_string()", "", 3)


def cat_7(scan: Scan, r: Renderer) -> None:
    r.header(7); r.category(7)
    r.subheader("std::fs usage (general inventory)")
    fs = scan.rg_lines(r"std::fs::")
    if fs:
        r.finding("info", len(fs), "std::fs operations present - consider async equivalents where applicable")
        scan.emit("rust.filesystem.fs-usage", 7, "info", len(fs),
                  "std::fs operations present - consider async equivalents where applicable", fs)
    r.subheader("std::process::Command usage")
    cmd = scan.rg_lines(r"std::process::Command::new\(")
    if cmd:
        r.finding("info", len(cmd), "Command::new detected - ensure args are sanitized and errors handled", "", cmd[:3], 3)
        scan.emit("rust.filesystem.command-new", 7, "info", len(cmd),
                  "Command::new detected - ensure args are sanitized and errors handled", cmd)


def cat_8(scan: Scan, r: Renderer) -> None:
    r.header(8); r.category(8)
    r.subheader("Weak hash algorithms (MD5/SHA1)")
    weak = scan.ast_hits(["md5", "sha1"]) + scan.rg_lines(
        r"SHA1_FOR_LEGACY_USE_ONLY|MessageDigest::(md5|sha1)\(")
    if weak:
        r.finding("warning", len(weak), "Weak hash algorithm usage (MD5/SHA1)", "", weak[:5], 5)
        scan.emit("rust.security.weak-hash", 8, "warning", len(weak), "Weak hash algorithm usage (MD5/SHA1)", weak)
    else:
        r.finding("good", 0, "No MD5/SHA1 found")
    r.subheader("TLS verification disabled")
    tls = (scan.ast_hits(["tls_certs", "tls_hostnames"])
           + scan.rg_lines(r"danger_accept_invalid_certs\(\s*true\s*\)")
           + scan.rg_lines(r"danger_accept_invalid_hostnames\(\s*true\s*\)")
           + scan.detector_hits("tls_indirect", scan.project_dir)
           + scan.rg_lines(r"SslVerifyMode::NONE")
           + scan.rg_lines(r"TlsConnector::builder\(\)\.danger_accept_invalid_certs\(true\)"))
    if tls:
        r.finding("critical", len(tls), "TLS certificate or hostname verification disabled")
        scan.emit("rust.security.tls-verification", 8, "critical", len(tls),
                  "TLS certificate or hostname verification disabled", tls)
    r.subheader("Security-sensitive non-crypto randomness")
    _sub(scan, r, scan.detector_hits("security_randomness"), "rust.security.non-crypto-random", 8,
         "critical", "Security token generated with non-cryptographic randomness",
         "Use OsRng/getrandom/ring::rand/openssl::rand or a framework helper backed by OS cryptographic randomness for tokens, sessions, CSRF nonces, OTPs, salts, API keys, and secrets",
         3, "No security-sensitive non-crypto randomness detected")
    r.subheader("Secret/token comparisons without timing-safe equality")
    _sub(scan, r, run_ctcompare(scan), "rust.security.constant-time-compare", 8,
         "critical", "Secret, signature, or token compared with ==/!=",
         "Use subtle::ConstantTimeEq, ring::constant_time::verify_slices_are_equal, crypto_memcmp, or a reviewed constant-time helper for bearer tokens, HMACs, CSRF values, reset secrets, API keys, and signatures",
         3, "No secret comparisons using ==/!= detected")
    r.subheader("JWT decode, validation bypass, or missing claim binding")
    _sub(scan, r, scan.detector_hits("jwt_verification"), "rust.security.jwt-verification", 8,
         "critical", "JWT decode/validation bypass risk",
         "Use jsonwebtoken::decode with a real DecodingKey and Validation that keeps signature, expiration, issuer, and audience checks enabled and required; avoid dangerous::insecure_decode, dangerous_unsafe_decode, insecure_disable_signature_validation(), validate_exp=false, and validate_aud=false",
         3, "No JWT decode/validation bypass patterns detected")
    r.subheader("Shell command execution through -c/-lc")
    shell = (scan.ast_hits([
        "shell_std_arg_c", "shell_arg_c", "shell_std_arg_lc", "shell_arg_lc",
        "shell_std_arg_wc", "shell_arg_wc", "shell_std_arg_wcl", "shell_arg_wcl",
        "shell_std_args_c", "shell_args_c", "shell_std_args_lc", "shell_args_lc",
        "shell_std_args_wc", "shell_args_wc", "shell_std_args_wcl", "shell_args_wcl",
        "shell_std_argsref_c", "shell_argsref_c", "shell_std_argsref_lc", "shell_argsref_lc",
        "shell_std_argsref_wc", "shell_argsref_wc", "shell_std_argsref_wcl", "shell_argsref_wcl",
    ]) or scan.rg_lines(r"(std::process::)?Command::new\([^)]*\)[^;]*\.(arg|args)\([^;]*(\"(-c|-lc|/C|/c)\")"))
    if shell:
        r.finding("critical", len(shell), "Shell command execution via -c/-lc",
                  "Avoid shell interpreters; pass argv directly or strictly validate/allowlist input", shell[:5], 5)
        scan.emit("rust.security.shell-command", 8, "critical", len(shell),
                  "Shell command execution via -c/-lc", shell)
    else:
        r.finding("good", 0, "No shell -c/-lc Command usage detected")
    r.subheader("Command::new executable from untrusted-looking value")
    _sub(scan, r, scan.detector_hits("command_executable"), "rust.security.command-executable", 8,
         "critical", "Command executable from untrusted-looking value",
         "Use a fixed executable allowlist; pass user data only as argv after validation", 3)
    r.subheader("Path join/push with untrusted-looking segment")
    _sub(scan, r, scan.detector_hits("path_traversal"), "rust.security.path-traversal", 8,
         "warning", "Path join/push with untrusted-looking segment",
         "Reject absolute paths and '..' components; canonicalize and verify the result stays under the intended root", 3)
    r.subheader("Archive entry paths joined into extraction destination")
    _sub(scan, r, scan.detector_hits("archive_entry_path"), "rust.security.archive-entry-path", 8,
         "warning", "Archive entry path traversal risk",
         "Use zip::read::ZipFile::enclosed_name(), tar::Entry::unpack_in(), or canonicalize and verify destination containment before writing", 3)
    r.subheader("Predictable temp-file writes")
    _sub(scan, r, scan.detector_hits("temp_file_race"), "rust.security.temp-file-race", 8,
         "warning", "Predictable temp-file write race",
         "Use tempfile::NamedTempFile/tempfile::Builder or OpenOptions::create_new(true) with unpredictable names", 3)
    r.subheader("Request-derived open redirects")
    _sub(scan, r, scan.detector_hits("open_redirect"), "rust.security.open-redirect", 8,
         "critical", "Unvalidated redirect from request data",
         "Validate redirect targets with same-origin relative paths or explicit scheme and host allow-lists before redirects or Location headers",
         3, "No request-derived open redirect sinks detected")
    r.subheader("Host header used for absolute URL construction")
    _sub(scan, r, scan.detector_hits("host_header_url"), "rust.security.host-header-url", 8,
         "critical", "Request Host header used to build absolute URL",
         "Use a configured canonical origin or validate Host/X-Forwarded-Host against an explicit allow-list before generating links",
         3, "No Host-header-derived absolute URL construction detected")
    r.subheader("Request-derived response headers")
    _sub(scan, r, scan.detector_hits("response_header"), "rust.security.response-header", 8,
         "critical", "Request-controlled value reaches HTTP response header",
         "Reject or strip CR/LF, use HeaderValue::from_str, percent-encode filename fragments, or route through a header-safe helper before writing response headers",
         3, "No request-derived response header values detected")
    r.subheader("Request-derived outbound HTTP URLs")
    _sub(scan, r, scan.detector_hits("request_url"), "rust.security.request-url", 8,
         "critical", "Request-derived URL reaches outbound HTTP client",
         "Validate outbound URLs with explicit scheme and host allow-lists before sending client requests",
         3, "No request-derived outbound HTTP URL sinks detected")
    r.subheader("Request-derived SQL construction")
    _sub(scan, r, scan.detector_hits("sql_injection"), "rust.security.sql-injection", 8,
         "critical", "Interpolated SQL reaches execution sink",
         "Use sqlx query macros, .bind(), rusqlite params!, diesel DSL/bind(), or other parameterized placeholders instead of format!/concat SQL",
         3, "No request-derived SQL construction sinks detected")
    r.subheader("Request-controlled regex patterns")
    _sub(scan, r, scan.detector_hits("request_regex"), "rust.security.request-regex", 8,
         "warning", "Request-controlled regex pattern reaches regex engine",
         "Escape pattern fragments with regex::escape or validate against an allow-list before Regex::new/RegexSet::new",
         3, "No request-controlled regex compilation detected")
    r.subheader("Unbounded request body reads")
    _sub(scan, r, scan.detector_hits("unbounded_request_body"), "rust.security.request-body-limit", 8,
         "warning", "Request body read without explicit byte limit",
         "Use DefaultBodyLimit::max, RequestBodyLimitLayer, http_body_util::Limited, or axum::body::to_bytes(body, limit) before buffering request bodies",
         3, "No unbounded request body reads detected")
    r.subheader("CORS credential policy")
    _sub(scan, r, scan.detector_hits("cors_credential"), "rust.security.cors-credentials", 8,
         "critical", "Credentialed wildcard/reflected CORS",
         "Use an explicit trusted origin allow-list and emit Vary: Origin when Access-Control-Allow-Credentials is true",
         3, "No unsafe CORS credential policy detected")
    r.subheader("Plain http:// URLs")
    http = scan.ast_hits(["http_url"]) + scan.rg_lines(r"http://[A-Za-z0-9]")
    if http:
        r.finding("info", len(http), "Plain HTTP URL(s) detected")
        scan.emit("rust.security.http-url", 8, "info", len(http), "Plain HTTP URL(s) detected", http)
    r.subheader("Hardcoded secrets/credentials")
    secrets = scan.detector_hits("hardcoded_secrets", scan.project_dir)
    if secrets:
        r.finding("critical", len(secrets), "Possible hardcoded secrets",
                  "Use secret managers or required environment variables; do not keep literal fallbacks for secret env vars", secrets[:3], 3)
        scan.emit("rust.security.hardcoded-secrets", 8, "critical", len(secrets),
                  "Possible hardcoded secrets", secrets,
                  desc="Use secret managers or required environment variables; do not keep literal fallbacks for secret env vars",
                  sample_limit=3)
    else:
        r.finding("good", 0, "No hardcoded secrets detected")


def cat_9(scan: Scan, r: Renderer) -> None:
    r.header(9); r.category(9)
    todo = scan.rg_lines("TODO", ignore_case=True)
    fixme = scan.rg_lines("FIXME", ignore_case=True)
    hack = scan.rg_lines("HACK", ignore_case=True)
    note = scan.rg_lines("NOTE", ignore_case=True)
    total = len(todo) + len(fixme) + len(hack)
    breakdown = (f"TODO:{len(todo)}, FIXME:{len(fixme)}, HACK:{len(hack)}, NOTE:{len(note)}")
    markers = todo + fixme + hack
    p = markers[0].path if markers else (str(scan.files[0]) if scan.files else "")
    l = markers[0].line if markers else 1
    c = markers[0].col if markers else 1
    if total > 20:
        r.finding("warning", total, "Significant technical debt", breakdown)
        scan.emit("rust.code-quality.tech-debt", 9, "warning", total, "Significant technical debt",
                  bucket_count=total, desc=breakdown, path=p, line=l, col=c)
    elif total > 0:
        r.finding("info", total, "Technical debt markers present", breakdown)
        scan.emit("rust.code-quality.tech-debt", 9, "info", total, "Technical debt markers present",
                  bucket_count=total, desc=breakdown, path=p, line=l, col=c)
    else:
        r.finding("good", 0, "No TODO/FIXME/HACK markers found")


def cat_10(scan: Scan, r: Renderer) -> None:
    r.header(10); r.category(10)
    r.subheader("Wildcard imports (use crate::* or ::*)")
    globs = scan.rg_lines(r"use\s+[a-zA-Z0-9_:]+::\*\s*;")
    if globs:
        r.finding("info", len(globs), "Wildcard imports found; prefer explicit names", "", globs[:3], 3)
        scan.emit("rust.modules.wildcard-imports", 10, "info", len(globs),
                  "Wildcard imports found; prefer explicit names", globs)
    else:
        r.finding("good", 0, "No wildcard imports detected")
    r.subheader("pub use re-exports (inventory)")
    pub_use = scan.rg_lines(r"pub\s+use\s+")
    if pub_use:
        r.finding("info", len(pub_use), "pub use re-exports present - verify API surface")
        scan.emit("rust.modules.pub-use", 10, "info", len(pub_use),
                  "pub use re-exports present - verify API surface", pub_use)


def cat_11(scan: Scan, r: Renderer) -> None:
    r.header(11); r.category(11)
    r.subheader("#[ignore] tests")
    ignored = scan.rg_lines(r"#\[ignore\]")
    if ignored:
        r.finding("info", len(ignored), "#[ignore] tests present - verify intent")
        scan.emit("rust.tests.ignored-tests", 11, "info", len(ignored),
                  "#[ignore] tests present - verify intent", ignored)
    r.subheader("todo!/unimplemented! in tests")
    count, p, l = _test_todo_count(scan)
    if count > 0:
        r.finding("info", count, "todo!/unimplemented! seen near #[test]")
        scan.emit("rust.tests.test-todo", 11, "info", count,
                  "todo!/unimplemented! seen near #[test]", bucket_count=count,
                  path=p, line=l)


def _test_todo_count(scan: Scan) -> tuple[int, str, int]:
    """Legacy 9259: rg '#\\[test\\]' stream -> grep -A5 -E 'todo!|unimplemented!'
    over the rg OUTPUT lines (i.e. the next 5 '#[test]' stream lines), and
    overlapping blocks count a line twice — reproduce that faithfully."""
    pattern = re.compile(_alnum_class(r"todo!|unimplemented!"))
    stream: list[tuple[str, int, str]] = []
    for path, lines in scan.lines_map.items():
        path_str = str(path)
        for line_no, line in enumerate(lines, start=1):
            if "#[test]" in line:
                stream.append((path_str, line_no, line))
    total = 0
    first_path = str(scan.files[0]) if scan.files else ""
    first_line = 1
    found_first = False
    for idx in range(len(stream)):
        for path_str, line_no, line in stream[idx: idx + 6]:
            if pattern.search(line):
                if scan.stream_line_allowed(path_str, line_no, line):
                    if not found_first:
                        first_path = path_str
                        first_line = line_no
                        found_first = True
                    total += 1
    return total, first_path, first_line


def cat_15(scan: Scan, r: Renderer) -> None:
    r.header(15); r.category(15)
    r.subheader("std::collections::hash_map::DefaultHasher")
    hasher = scan.rg_lines(r"DefaultHasher")
    if hasher:
        r.finding("info", len(hasher), "DefaultHasher detected - not for cryptographic or stable hashing")
        scan.emit("rust.api-misuse.default-hasher", 15, "info", len(hasher),
                  "DefaultHasher detected - not for cryptographic or stable hashing", hasher)
    r.subheader("unwrap_err()/expect_err() usage inventory")
    errs = scan.rg_lines(r"unwrap_err\(") + scan.rg_lines(r"expect_err\(")
    if errs:
        r.finding("info", len(errs), "unwrap_err/expect_err present - ensure test-only or justified")
        scan.emit("rust.api-misuse.unwrap-err", 15, "info", len(errs),
                  "unwrap_err/expect_err present - ensure test-only or justified", errs)
    r.subheader("Option::unwrap_or_default inventory")
    uod = scan.rg_lines(r"\.unwrap_or_default\(")
    if uod:
        r.finding("info", len(uod), "unwrap_or_default present - validate default semantics")
        scan.emit("rust.api-misuse.unwrap-or-default", 15, "info", len(uod),
                  "unwrap_or_default present - validate default semantics", uod)


def cat_16(scan: Scan, r: Renderer) -> None:
    r.header(16); r.category(16)
    r.subheader("reqwest::ClientBuilder inventory")
    builder = scan.rg_lines(r"reqwest::ClientBuilder::new\(")
    if builder:
        r.finding("info", len(builder), "reqwest ClientBuilder usage - review TLS, timeouts, redirects")
        scan.emit("rust.domain.reqwest-builder", 16, "info", len(builder),
                  "reqwest ClientBuilder usage - review TLS, timeouts, redirects", builder)
    r.subheader("serde_json::from_str without error context (heuristic)")
    from_str = scan.rg_lines(r"serde_json::from_str::<")
    if from_str:
        r.finding("info", len(from_str), "serde_json::from_str uses - ensure error context and validation")
        scan.emit("rust.domain.from-str", 16, "info", len(from_str),
                  "serde_json::from_str uses - ensure error context and validation", from_str)
    r.subheader("SQL string concatenation (heuristic)")
    concat = scan.rg_lines(r"(SELECT|INSERT|UPDATE|DELETE)[^;]*\+[\s]*[_a-zA-Z0-9\"]")
    if concat:
        r.finding("warning", len(concat), "Possible SQL construction via concatenation - prefer parameters")
        scan.emit("rust.domain.sql-concat", 16, "warning", len(concat),
                  "Possible SQL construction via concatenation - prefer parameters", concat)


def cat_19(scan: Scan, r: Renderer) -> None:
    r.header(19); r.category(19)
    entries = resource_lifecycle(scan)
    r.subheader("Resource lifecycle correlation")
    if entries:
        for entry in entries:
            r.finding(entry["severity"], entry["delta"], entry["title"], entry["desc"])
            file_path = entry.get("file", "")
            hit = Hit(file_path, 1, 1, entry["title"]) if file_path else None
            scan.emit(
                f"rust.resource-lifecycle.{entry['rid']}",
                19,
                entry["severity"],
                entry["delta"],
                entry["title"],
                hits=[hit] if hit else None,
                bucket_count=entry["delta"],
                desc=entry["desc"],
                path=file_path,
            )
    else:
        r.finding("good", 0, "All tracked resource acquisitions have matching cleanups")


def cat_20(scan: Scan, r: Renderer) -> None:
    r.header(20); r.category(20)
    r.subheader("std::sync lock usage inside async fn (blocking risk)")
    locks = (scan.ast_hits(["std_lock_async_lock", "std_lock_async_read", "std_lock_async_write"])
             + scan.rg_lines(r"async\s+fn[^{]*\{[^}]*\.(lock|read|write)\("))
    if locks:
        r.finding("warning", len(locks), "Blocking std::sync locks in async functions",
                  "Prefer tokio::sync locks or spawn_blocking; avoid blocking executor threads", locks[:3], 3)
        scan.emit("rust.async-locking.std-lock-async", 20, "warning", len(locks),
                  "Blocking std::sync locks in async functions", locks)
    else:
        r.finding("good", 0, "No obvious std::sync lock usage inside async fns")
    r.subheader("Potential std::sync guard held across await (heuristic)")
    std_guard = scan.ast_hits(["std_guard_await_unwrap", "std_guard_await_expect"])
    if std_guard:
        r.finding("warning", len(std_guard), "Potential lock guard across await (std::sync)",
                  "Drop the guard before awaiting (scoped blocks or drop(guard))")
        scan.emit("rust.async-locking.std-guard-await", 20, "warning", len(std_guard),
                  "Potential lock guard across await (std::sync)", std_guard)
    r.subheader("Potential async lock guard held across await (tokio/async locks heuristic)")
    tokio_guard = (scan.ast_hits(["tokio_guard_lock", "tokio_guard_read", "tokio_guard_write"])
                   + scan.rg_lines(r"let\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]*\.(lock|read|write)\(\)\.await"))
    if tokio_guard:
        r.finding("warning", len(tokio_guard), "Potential async lock guard across await",
                  "Reduce critical section; prefer copying needed data out; explicit drop() before await")
        scan.emit("rust.async-locking.tokio-guard-await", 20, "warning", len(tokio_guard),
                  "Potential async lock guard across await", tokio_guard)


def cat_21(scan: Scan, r: Renderer) -> None:
    r.header(21); r.category(21)
    r.subheader("assert!/assert_eq!/assert_ne! inventory")
    asserts = scan.ast_hits(["assert", "assert_eq", "assert_ne"]) + scan.rg_lines(r"assert(_eq|_ne)?!\(")
    if asserts:
        r.finding("warning", len(asserts), "assert! macros present (panic surface)",
                  "If these are runtime invariants, consider explicit error handling; ensure not reachable by untrusted input", asserts[:3], 3)
        scan.emit("rust.panic.assert-macros", 21, "warning", len(asserts),
                  "assert! macros present (panic surface)", asserts)
    else:
        r.finding("good", 0, "No assert! macros detected")
    r.subheader("unreachable_unchecked / unwrap_unchecked")
    _sub(scan, r, scan.ast_hits(["unreachable_unchecked_std", "unreachable_unchecked_core", "unwrap_unchecked"]),
         "rust.panic.unchecked-ub", 21, "critical", "Unchecked UB-adjacent APIs used",
         "unreachable_unchecked is UB if reached; unwrap_unchecked requires strict invariants", 3)
    r.subheader("direct indexing / slicing panic surfaces")
    _sub(scan, r, scan.ast_hits(["direct_index"]), "rust.panic.direct-indexing", 21,
         "warning", "Direct indexing/slicing may panic",
         "Use get()/get_mut(), checked ranges, or prior bounds checks when indexes can come from input", 3)
    r.subheader("panic!/unwrap/expect inside Drop")
    _sub(scan, r, scan.detector_hits("drop_panic"), "rust.panic.drop", 21,
         "warning", "Potential panics inside Drop implementations",
         "Panics during Drop + unwinding can abort; avoid unwrap/expect/panic in destructors", 3)


def cat_22(scan: Scan, r: Renderer) -> None:
    r.header(22); r.category(22)
    r.subheader("`as` cast inventory")
    casts = scan.ast_hits([
        "as_u8", "as_u16", "as_u32", "as_u64", "as_usize", "as_i8", "as_i16",
        "as_i32", "as_i64", "as_isize", "as_f32", "as_f64"])
    if casts:
        r.finding("info", len(casts), "`as` casts present (possible truncation/sign bugs)",
                  "Prefer TryFrom/TryInto for correctness or document invariants", casts[:3], 3)
        scan.emit("rust.casts.as-casts", 22, "info", len(casts),
                  "`as` casts present (possible truncation/sign bugs)", casts)
    else:
        r.finding("good", 0, "No obvious `as` casts detected")
    r.subheader("len()/count() narrowed via `as`")
    _sub(scan, r, scan.ast_hits([
        "len_as_u8", "len_as_u16", "len_as_u32", "len_as_i8", "len_as_i16", "len_as_i32",
        "count_as_u8", "count_as_u16", "count_as_u32", "count_as_i8", "count_as_i16", "count_as_i32"]),
        "rust.casts.len-count-narrow", 22, "warning", "Length/count narrowed with `as` cast",
        "Use TryFrom/TryInto or explicit checked bounds before storing sizes in narrow integer fields", 3)
    r.subheader("try_into().unwrap()/expect() (panic on conversion failure)")
    _sub(scan, r, scan.ast_hits(["try_into_unwrap", "try_into_expect"]),
         "rust.casts.try-into-unwrap", 22, "warning", "try_into().unwrap()/expect() present",
         "Handle conversion errors explicitly; panics can be input-dependent", 3)


def cat_23(scan: Scan, r: Renderer) -> None:
    r.header(23); r.category(23)
    r.subheader("parse::<T>().unwrap()/expect()")
    _sub(scan, r, scan.ast_hits(["parse_tf_unwrap", "parse_tf_expect", "parse_unwrap", "parse_expect"]),
         "rust.parsing.parse-unwrap", 23, "warning", "parse::<T>().unwrap()/expect() present",
         "Validate input or propagate errors with context", 3)
    r.subheader("serde/toml deserialization unwrap()/expect()")
    _sub(scan, r, scan.ast_hits([
        "serde_json_from_str_unwrap", "serde_json_from_str_expect",
        "serde_json_from_slice_unwrap", "serde_json_from_slice_expect",
        "serde_json_from_value_unwrap", "serde_json_from_value_expect",
        "serde_yaml_from_str_unwrap", "serde_yaml_from_str_expect",
        "toml_from_str_unwrap", "toml_from_str_expect"]),
        "rust.parsing.serde-unwrap", 23, "warning", "serde/toml deserialization unwrap/expect",
        "Add context, validation, and schema checks; avoid panics on malformed data", 3)
    r.subheader("env::var(...).unwrap()/expect()")
    _sub(scan, r, scan.ast_hits([
        "env_std_var_unwrap", "env_std_var_expect", "env_var_unwrap", "env_var_expect",
        "env_std_var_os_unwrap", "env_std_var_os_expect", "env_var_os_unwrap", "env_var_os_expect"]),
        "rust.parsing.env-var-unwrap", 23, "warning", "env::var(...).unwrap()/expect()",
        "Handle missing/invalid env vars with defaults or clear error propagation", 3)


def cat_24(scan: Scan, r: Renderer) -> None:
    r.header(24); r.category(24)
    r.subheader("Regex::new occurrences and in-loop compilation")
    regex_in_loop = scan.detector_hits("loop_context", "regex_new")
    regex_new = scan.ast_hits(["regex_new_full", "regex_new_bare"])
    if regex_in_loop:
        r.finding("warning", len(regex_in_loop), "Regex::new compiled inside loop",
                  "Precompile regex once (lazy_static/once_cell) to avoid repeated compilation", regex_in_loop[:3], 3)
        scan.emit("rust.perf.regex-in-loop", 24, "warning", len(regex_in_loop),
                  "Regex::new compiled inside loop", regex_in_loop)
    elif regex_new:
        r.finding("info", len(regex_new), "Regex::new present",
                  "Ensure regex is not compiled per request or per iteration", regex_new[:3], 3)
        scan.emit("rust.perf.regex-new", 24, "info", len(regex_new), "Regex::new present", regex_new)
    else:
        r.finding("good", 0, "No regex::Regex::new detected")
    r.subheader("chars().nth(n)/nth_back(n) (O(n))")
    _sub(scan, r, scan.ast_hits(["chars_nth", "chars_nth_back"]), "rust.perf.chars-nth", 24,
         "info", "chars().nth(n)/nth_back(n) used",
         "O(n) indexing; prefer byte indexing where valid or iterators with caching", 3)
    r.subheader("format!/to_string/allocations inside loops (heuristic)")
    _sub(scan, r, scan.detector_hits("loop_context", "string_alloc"), "rust.perf.string-alloc-in-loop", 24,
         "warning", "String allocation inside loop",
         "Consider preallocating buffers, using write!, or restructuring to reduce allocations", 3)


_CAT_FUNCTIONS = {
    1: cat_1, 2: cat_2, 3: cat_3, 4: cat_4, 5: cat_5, 6: cat_6, 7: cat_7,
    8: cat_8, 9: cat_9, 10: cat_10, 11: cat_11, 15: cat_15, 16: cat_16,
    19: cat_19, 20: cat_20, 21: cat_21, 22: cat_22, 23: cat_23, 24: cat_24,
}


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def _read_files_list(path: str) -> list[Path]:
    raw = sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    entries = [e.decode("utf-8", "replace") for e in raw.split(b"\0") if e.strip()]
    if not entries:  # newline-separated fallback
        entries = [e for e in raw.decode("utf-8", "replace").splitlines() if e.strip()]
    return [Path(e) for e in entries]


def _apply_exclude_tests(scan: Scan) -> None:
    """Legacy build_scan_file_list 762-798: drop tests//benches/ files and the
    #[cfg(test)]-only modules from the scan set; keep the dropped set for the
    match-stream boundary filter."""
    from ubs_core.analyzers.cfg_test_only_rust import compute_test_only

    kept: list[Path] = []
    for path in scan.files:
        norm = str(path).replace("\\", "/")
        parts = norm.split("/")
        if any(part in ("tests", "benches") for part in parts[:-1]):
            continue
        kept.append(path)
    try:
        test_only = compute_test_only([str(p) for p in kept])
    except Exception as exc:
        sys.stderr.write(f"[ubs_core.rust_scan] cfg_test_only prefilter failed: {exc}\n")
        test_only = []
    if test_only:
        drop = set(test_only)
        scan.test_only.update(drop)
        kept = [p for p in kept if str(p) not in drop]
    scan.files = kept


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.rust_scan")
    parser.add_argument("--files-from", required=True, help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--ast-rule-dir", default="", help="consolidated ast-grep rule dir")
    parser.add_argument("--text-out", default="", help="render the legacy text report here")
    parser.add_argument("--checks-out", default="",
                        help="legacy findings[] aggregation (severity/count/category/title/description/samples)")
    parser.add_argument("--json-out", default="", help="write the run_lang summary object here")
    parser.add_argument("--project", default="", help="display project dir")
    parser.add_argument("--version", default="2.0.1")
    parser.add_argument("--exclude-tests", action="store_true")
    parser.add_argument("--skip-type-narrowing", action="store_true")
    parser.add_argument("--detail-limit", type=int, default=3)
    parser.add_argument("--files-count", type=int, default=-1,
                        help="authoritative Files-scanned count (base list, pre --exclude-tests)")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--jobs", type=int, default=1, help="parallel worker count for work-stealing file shards")
    args = parser.parse_args(argv)

    files = _read_files_list(args.files_from)
    project_dir = Path(args.project_dir)
    skip = {int(p) for p in args.skip.split(",") if p.strip().isdigit()}
    scan = Scan(files, project_dir, args.exclude_tests, skip, args.detail_limit, jobs=args.jobs)
    if args.exclude_tests:
        _apply_exclude_tests(scan)

    from ubs_core.prefilter import build_prefilter_index, run_prefilter

    from ubs_core.cache import ScanCache

    original_files = list(scan.files)
    cache = ScanCache(
        lang="rust",
        project_dir=project_dir,
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"exclude_tests={args.exclude_tests};skip_narrowing={args.skip_type_narrowing}",
    )
    cached_findings, files_to_scan = cache.partition_files(original_files)

    r = Renderer(scan, quiet=args.quiet)
    if files_to_scan:
        scan.files = list(files_to_scan)
        scan.lines_map = {f: scan.lines_map[f] for f in files_to_scan if f in scan.lines_map}
        scan.texts = {f: scan.texts[f] for f in files_to_scan if f in scan.texts}
        ast_rules_input: list[tuple[str, str]] = []
        if args.ast_rule_dir:
            rule_dir_path = Path(args.ast_rule_dir)
            for rf in rule_dir_path.glob("*.yml"):
                if rf.name.startswith(("sgconfig", "sgbase")):
                    continue
                try:
                    text = rf.read_text(encoding="utf-8", errors="ignore")
                    id_m = re.search(r"id:\s*(\S+)", text)
                    rid = id_m.group(1) if id_m else rf.stem
                    ast_rules_input.append((rid, text))
                except OSError:
                    pass
        from ubs_core.rust_rules import RUN_MODE_RULES
        for slug, pat in RUN_MODE_RULES.items():
            ast_rules_input.append((f"rust.ast.{slug}", f"rule:\n  pattern: {json.dumps(pat)}\n"))

        prefilter_index = build_prefilter_index(
            ast_rules=ast_rules_input,
            patterns=[],
            analyzers=[],
            lang="rust",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        ast_files = prefilter_res.ast_files if not prefilter_res.is_bypass else files_to_scan
        scan.load_ast_matches(Path(args.ast_rule_dir) if args.ast_rule_dir else None, ast_files=ast_files)

        narrowing_skip_note = None
        if args.skip_type_narrowing:
            narrowing_skip_note = "skipped"
        narrowing_hits: list[Hit] = []
        try:
            narrowing_hits = run_narrowing(scan, args.skip_type_narrowing)
        except Exception as exc:  # legacy: helper failure -> info-0 finding
            sys.stderr.write(f"[ubs_core.rust_scan] narrowing failed: {exc}\n")
            narrowing_skip_note = None
            narrowing_failed = str(exc)
        else:
            narrowing_failed = ""

        for category in sorted(_CAT_FUNCTIONS):
            if category in skip:
                continue
            if category == 1:
                cat_1(scan, r, narrowing_hits, narrowing_skip_note)
                if narrowing_failed:
                    r.finding("info", 0, "Rust type narrowing helper failed", narrowing_failed)
            else:
                _CAT_FUNCTIONS[category](scan, r)

        by_file: dict[str, list[dict]] = {}
        for record in scan.records:
            by_file.setdefault(record.get("path", ""), []).append(record)
        cache.store_scanned_files(files_to_scan, by_file)
    else:
        from ubs_core.prefilter import PrefilterResult
        prefilter_res = PrefilterResult(
            files_considered=0,
            files_after_prefilter=0,
            prefilter_ms=0,
            is_bypass=False,
        )

    # Replay cached findings (for both partial and full cache hits)
    cached_records = [rec for recs in cached_findings.values() for rec in recs]
    if cached_records:
        replay_findings(scan, r, cached_records)

    scan.files = original_files

    prefilter_file = os.environ.get("UBS_PREFILTER_FILE")
    if prefilter_file:
        try:
            Path(prefilter_file).write_text(json.dumps(prefilter_res.to_dict()), encoding="utf-8")
        except OSError:
            pass

    # K2 sink
    with open(args.sink, "w", encoding="utf-8") as fh:
        for record in scan.records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    cache_file = os.environ.get("UBS_CACHE_FILE") or (os.path.splitext(args.sink)[0] + ".cache")
    cache.write_stats(cache_file)

    if args.checks_out:
        Path(args.checks_out).write_text(
            json.dumps({"findings": scan.checks}, ensure_ascii=False) + "\n", encoding="utf-8")

    files_n = args.files_count if args.files_count >= 0 else len(scan.files)
    if args.text_out:
        Path(args.text_out).write_text(r.text(), encoding="utf-8")
    if args.json_out:
        profile_data = {
            "files_considered": prefilter_res.files_considered if files_to_scan else len(scan.files),
            "files_after_prefilter": prefilter_res.files_after_prefilter if files_to_scan else 0,
            "prefilter_ms": prefilter_res.prefilter_ms if files_to_scan else 0,
            "cache_hits": cache.stats["hits"],
            "cache_misses": cache.stats["misses"],
            "cache_hit_rate": cache.stats["hit_rate"],
        }
        doc = {
            "language": "rust",
            "status": "ok",
            "project": args.project or str(project_dir),
            "files": files_n,
            "critical": scan.counters["critical"],
            "warning": scan.counters["warning"],
            "info": scan.counters["info"],
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "format": "json",
            "version": args.version,
            "findings": scan.records,
            "extras": {"profile": profile_data},
        }
        if os.environ.get("UBS_PROFILE") == "1":
            doc["profile"] = profile_data
        Path(args.json_out).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")

    exit_code = 0
    if scan.counters["critical"] > 0:
        exit_code = 1
    if args.fail_on_warning and (scan.counters["critical"] + scan.counters["warning"]) > 0:
        exit_code = 1
    sys.stderr.write(json.dumps({
        "counters": dict(scan.counters), "records": len(scan.records),
        "files": len(scan.files),
        "prefilter": prefilter_res.to_dict(),
    }) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
