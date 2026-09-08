"""ubs_core.swift_scan — contract-v2 orchestrator for the Swift module (bead 0xjg.11).

One process replaces the legacy multi-spawn scan in modules/ubs-swift.sh:

  pattern layer   ubs_core.swift_patterns.*  — the rg pipelines (GREP_RN/RNI/RNW
                  + count_lines ladders), including the `grep -A<N>` intent
                  windows reproduced as ordered-stream emulations
  derived checks  cross-count ladders the rg layer cannot express (async vs
                  await, FileHandle open/close imbalance, @MainActor presence,
                  the Process info residual, Package.swift pins, storyboards)
  detectors       ubs_core.swift_detectors.*  — ports of the module's python
                  heredocs (archive extraction, shell execution, security
                  randomness, header injection, outbound URL, plist ATS,
                  entitlements, URLSession task correlation)
  analyzers       the registered swift analyzers (taint_swift_traversal +
                  taint_swift_redirect = the path-traversal / open-redirect
                  heredocs; narrowing_swift = helpers/type_narrowing_swift.py;
                  lifecycle_swift = helpers/resource_lifecycle_swift.py;
                  regex_swift has no legacy counter impact and stays off unless
                  --enable-new-analyzers)
  ast layer       ubs_core.swift_rules.generate + swift_ast.scan_all — the ONE
                  generated pack rule (swift.urlsession.task-no-resume) feeds
                  both run_urlsession_task_correlation and the rule-pack
                  summary findings, exactly like the legacy AG stream.

Output contract (identical to py_scan/ruby_scan): NDJSON findings sink records
{rule, category_id, path, line, col, severity, count, message, suppressed};
legacy text renderer for --text-out; UBS summary JSON for --json-out; totals
recounted from the sink (summing per-record ``count``); exit 1 on criticals
(or --fail-on-warning).
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import pkgutil
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

MARKER = "ubs:ignore"

# Meta-runner category_slug_for swift (ubs 5110-5136).
_CATEGORY_SLUGS = {
    1: "optionals", 2: "concurrency", 3: "closures", 4: "networking",
    5: "error-handling", 6: "security", 7: "crypto", 8: "filesystem",
    9: "threading", 10: "perf", 11: "debug", 12: "regex", 13: "swiftui",
    14: "memory", 15: "code-quality", 16: "resource-lifecycle",
    17: "info-plist", 18: "deprecations", 19: "build", 20: "packaging",
    21: "ui-safety", 22: "tests", 23: "l10n",
}

# Legacy print_header titles + print_category descriptions, in category order.
_SECTION_HEADERS = {
    1: "1. OPTIONALS / FORCE OPERATIONS",
    2: "2. CONCURRENCY / TASK",
    3: "3. CLOSURES / CAPTURE LISTS",
    4: "4. URLSESSION / NETWORKING",
    5: "5. ERROR HANDLING",
    6: "6. SECURITY",
    7: "7. CRYPTO / HASHING",
    8: "8. FILES & I/O",
    9: "9. THREADING / MAIN",
    10: "10. PERFORMANCE",
    11: "11. DEBUG / PRODUCTION",
    12: "12. REGEX",
    13: "13. SWIFTUI / COMBINE",
    14: "14. MEMORY / RETAIN",
    15: "15. CODE QUALITY MARKERS",
    16: "16. RESOURCE LIFECYCLE",
    17: "17. INFO.PLIST / ATS",
    18: "18. DEPRECATED APIs",
    19: "19. BUILD / SIGNING",
    20: "20. PACKAGING / SPM",
    21: "21. UI/UX SAFETY",
    22: "22. TESTS / HYGIENE",
    23: "23. LOCALIZATION / INTERNATIONALIZATION",
}

_CATEGORY_DETECTED = {
    1: ("Detects: force unwrap (!), try!, as!, IUO declarations, URL(string:)!",
        "Avoid crashes by binding optionals and using safe casts/errors."),
    2: ("Detects: Task launches, detached tasks, unsafe continuations, Sendable footguns",
        "Structured concurrency avoids leaks and deadlocks."),
    3: ("Detects: strong self in long-lived closures, unowned self hazards",
        "Use [weak self] where closures outlive self; prefer guard let self."),
    4: ("Detects: URLSession tasks, http literals, Data(contentsOf:), insecure trust handlers, manual URL queries",
        "Networking bugs cause hangs, security issues, and battery drain."),
    5: ("Detects: empty catches, try? discards, fatalError misuse",
        "Handle errors or propagate with throws."),
    6: ("Detects: trust-all URLSession delegate, hardcoded secrets, request path traversal, request-derived open redirects, request-derived response header injection, request-derived outbound URL/SSRF, insecure unarchiving, unsafe archive extraction, Process misuse",
        "Security bugs expose users and violate policies."),
    7: ("Detects: weak algorithms via CommonCrypto & CryptoKit Insecure.*, ECB mode flags, security-sensitive non-crypto randomness",
        "Prefer SHA-256/512 and authenticated encryption."),
    8: ("Detects: FileHandle leaks, blocking reads, path string concat",
        "Use URL and ensure closing handles."),
    9: ("Detects: sleeps/semaphores on main, missing MainActor hints",
        "UI work must happen on the main actor."),
    10: ("Detects: String += in loops, regex compile in loops, formatter churn",
         "Avoid obvious performance anti-patterns."),
    11: ("Detects: print/NSLog, debug flags, assertions",
         "Ensure debug artifacts are stripped from release."),
    12: ("Detects: nested quantifiers (ReDoS), untrusted predicate formats",
         "Regex bugs cause performance issues."),
    13: ("Detects: sink without store, .onReceive patterns, subscription lifetimes",
         "State management must retain subscriptions and avoid cycles."),
    14: ("Detects: retain cycles via Timer/Notification/closures, resource teardown",
         "Break cycles with weak references or invalidation."),
    15: ("Detects: TODO, FIXME, HACK, XXX",
         "Technical debt markers indicate work remaining."),
    16: ("Detects: Timer/URLSessionTask/Notification tokens/FileHandle/Combine/DispatchSource/CADisplayLink/KVO cleanups",
         "Unreleased resources leak memory, file descriptors, or tasks."),
    17: ("Detects: NSAppTransportSecurity exceptions, arbitrary loads",
         "ATS exceptions require justification; avoid blanket disables."),
    18: ("Detects: UIWebView/NSURLConnection, deprecated status bar APIs, keyWindow",
         "Remove deprecated APIs before submission."),
    19: ("Detects: entitlements anomalies, debug signing in release",
         "Ensure secure build settings."),
    20: ("Detects: unpinned SPM deps, branch deps, local paths, unsafeFlags",
         "Pin dependencies for reproducibility."),
    21: ("Detects: IUO IBOutlets, large storyboards",
         "Prefer safe IBOutlets and modular storyboards."),
    22: ("Detects: XCTFail placeholders, sleeps in tests",
         "Stable tests avoid sleeps and assert properly."),
    23: ("Detects: user-facing strings without NSLocalizedString, locale-sensitive formatting risks",
         "Localize strings and use locale-aware formatters."),
}
_CORRELATION_PREFIX = "ubs.correlation.urlsession."
AST_PACK_RULE = "swift.urlsession.task-no-resume"


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class CheckSpec:
    """Static render metadata for one legacy check, in print order."""

    category: int  # 0 = the AST rule-pack section (legacy, outside 1..23)
    rule_id: str
    subheader: str | None = None
    good: str | None = None
    desc: str | None = None
    # render detailed code samples for this bucket (legacy show_detailed_finding)
    samples: bool = False
    # print the good note only when these sibling buckets are absent too
    # (legacy `elif shell_critical -eq 0` style branches)
    good_suppressed_by: tuple[str, ...] = ()
    order: int = 0


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity): the
    first entry whose count > min_count wins. Ladders with DIFFERENT titles
    (force unwrap >30 vs >0, print/NSLog >50/>10/>0, tech debt >20/>10/>0)
    split into sibling patterns sharing a regex; ``max_count`` caps a tier so
    exactly one sibling fires per count, like the legacy if/elif chain.

    exclude_regex expresses legacy `grep -v` post-filters; include_regex
    expresses legacy keep-filters (`grep -E` on the pipeline output);
    swift_only restricts a pattern to *.swift files (the legacy
    `| grep "\\.swift:"` post-filter). ``window``/``after_regex`` reproduce
    the `rg | grep -A<N> -e P | grep ...` intent pipelines: the ordered match
    stream is expanded with <N> lines of trailing context before the
    keep/drop filters apply (see grep_after_emulation). ``always`` emits a
    count-0 aggregate record when nothing matched (legacy print_finding with
    a literal 0, e.g. "Task usages").
    """

    category: int
    rule_id: str
    title: str
    regex: str
    thresholds: tuple[tuple[int, str], ...]
    case_insensitive: bool = False
    exclude_regex: str | None = None  # legacy `grep -v` post-filter
    include_regex: str | None = None  # legacy keep-filter `grep -E`
    swift_only: bool = False
    max_count: int | None = None  # upper tier of a legacy if/elif ladder
    components: tuple[str, ...] = ()  # summed sub-counts (cat 15)
    window: int = 0  # legacy `grep -A<N>` context on the rg output stream
    after_regex: str | None = None  # `grep -A<N> -e P` pattern
    show_samples: bool = False  # legacy show_detailed_finding
    always: bool = False  # print the finding even at count 0
    multiline: bool = False  # ^-anchored pipelines (rg is line-anchored)

    def compiled(self) -> re.Pattern[str]:
        flags = re.IGNORECASE if self.case_insensitive else 0
        if self.multiline:
            flags |= re.MULTILINE
        return re.compile(self.regex, flags)

@dataclass
class ScanContext:
    files: list[Path]
    texts: dict[Path, str] = field(default_factory=dict)
    project_dir: Path = Path(".")
    skip_narrowing: bool = False
    ast_available: bool = False
    ast_records: list[dict] = field(default_factory=list)

    def text_of(self, path: Path) -> str:
        if path not in self.texts:
            try:
                self.texts[path] = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                self.texts[path] = ""
        return self.texts[path]

    def has_swift(self) -> bool:
        return any(p.suffix == ".swift" for p in self.files)


def line_text_of(text: str, pos: int) -> str:
    """The full line containing ``pos`` (used for marker/exclude checks)."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def file_match_entries(pattern: re.Pattern[str], path: Path, text: str) -> list[tuple[Path, int, str, str]]:
    """Ordered rg-style entries [(path, line_no, display, line_text)] for one file.

    ``display`` mirrors the rg output line (path:line:code) so the marker and
    context filters see exactly what the legacy shell pipelines saw.
    """
    entries: list[tuple[Path, int, str, str]] = []
    seen: set[int] = set()
    for match in pattern.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        if line_no in seen:
            continue
        seen.add(line_no)
        line_text = line_text_of(text, match.start())
        code = line_text.strip()
        entries.append((path, line_no, f"{path}:{line_no}:{line_text.strip()}", code[:240] if code else line_text[:240]))
    return entries


def grep_after_emulation(
    stream: list[tuple[Path, int, str, str]],
    window: int,
    after_regex: re.Pattern[str],
    include_regex: re.Pattern[str] | None,
    exclude_regex: re.Pattern[str] | None,
    exclude_ci: bool = False,
) -> list[tuple[Path, int, str, str]]:
    """Reproduce `rg | grep -A<N> -e P | [grep -v Q] | [grep -E R] | count_lines`.

    ``stream`` is the ordered rg output for one file (rg walks files one at a
    time, so cross-file adjacency cannot occur in the trees this parity
    targets). GNU grep prints each stream line at most once, restarts the
    context window at every match, and emits a `--` separator only across
    gaps; every emitted line (match, context, separator) then runs through
    the keep/drop filters and the count_lines marker filter.
    """
    match_positions = [i for i, entry in enumerate(stream) if after_regex.search(entry[3])]
    expanded: list[tuple[Path, int, str, str]] = []
    printed_upto = -1
    for pos in match_positions:
        end = min(pos + window, len(stream) - 1)
        if printed_upto >= 0 and pos > printed_upto + 1:
            expanded.append((Path("--"), 0, "--", "--"))
        for j in range(max(pos, printed_upto + 1), end + 1):
            expanded.append(stream[j])
        printed_upto = max(printed_upto, end)

    out = []
    for entry in expanded:
        _path, _line_no, display, line_text = entry
        if MARKER in display:
            continue
        if include_regex is not None and not include_regex.search(line_text):
            continue
        if exclude_regex is not None:
            hay = line_text.lower() if exclude_ci else line_text
            if exclude_regex.search(hay):
                continue
        out.append(entry)
    return out


def active_tier(pattern: Pattern, count: int) -> str | None:
    """Resolve one legacy if/elif ladder tier: this tier's severity, else None."""
    if pattern.max_count is not None and count > pattern.max_count:
        return None
    for min_count, severity in pattern.thresholds:
        if count > min_count:
            return severity
    return None


def scan_patterns(patterns: Sequence[Pattern], ctx: ScanContext, sink, skip: set[int], prefilter: Any = None) -> None:
    """Run every pattern over the file list, writing sink records.

    Legacy parity semantics: counts are DISTINCT MATCHING LINES across the
    whole file list, severity is resolved ONCE per pattern from that
    project-wide count, and every record of a pattern carries that severity —
    so the sink recount equals the legacy print_finding buckets.
    """
    active = [p for p in patterns if p.category not in skip]
    if not active:
        return
    for pattern in active:
        files = ctx.files
        if pattern.swift_only:
            files = [p for p in files if p.suffix == ".swift"]
        regex = pattern.compiled()
        include = re.compile(pattern.include_regex) if pattern.include_regex else None
        exclude = re.compile(pattern.exclude_regex, re.IGNORECASE if False else 0) if pattern.exclude_regex else None
        exclude_ci = False
        after = re.compile(pattern.after_regex) if pattern.after_regex else None
        hits: list[tuple[Path, int, str, str]] = []
        if pattern.components:
            for component in pattern.components:
                cregex = re.compile(component, re.IGNORECASE)
                for path in files:
                    if prefilter is not None and pattern.rule_id not in prefilter.candidate_rules_for(path):
                        continue
                    for entry in file_match_entries(cregex, path, ctx.text_of(path)):
                        # count_lines drops rg output lines carrying a marker
                        if MARKER in entry[2] or MARKER in entry[3]:
                            continue
                        hits.append(entry)
        else:
            for path in files:
                if prefilter is not None and pattern.rule_id not in prefilter.candidate_rules_for(path):
                    continue
                file_hits = file_match_entries(regex, path, ctx.text_of(path))
                if pattern.window > 0 and after is not None:
                    hits.extend(grep_after_emulation(file_hits, pattern.window, after, include, exclude, exclude_ci))
                else:
                    for entry in file_hits:
                        line_text = entry[3]
                        # count_lines drops rg output lines carrying a marker
                        if MARKER in entry[2] or MARKER in line_text:
                            continue
                        if include is not None and not include.search(line_text):
                            continue
                        if exclude is not None and exclude.search(line_text):
                            continue
                        hits.append(entry)
        count = len(hits)
        if count == 0 and pattern.always:
            # legacy print_finding with a literal 0 (e.g. "Task usages")
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"swift.{slug_for_category(pattern.category)}",
                "path": "", "line": 0, "col": 1,
                "severity": pattern.thresholds[-1][1],
                "count": 0,
                "title": pattern.title,
                "message": pattern.title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
            continue
        severity = active_tier(pattern, count)
        if severity is None:
            continue
        for path, line_no, _display, line_text in hits:
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"swift.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "count": 1,
                "title": pattern.title,
                "message": f"{pattern.title} — {line_text}" if line_text else pattern.title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def load_patterns() -> list[Pattern]:
    """Aggregate PATTERNS from every ubs_core.swift_patterns.* module."""
    from ubs_core import swift_patterns

    patterns: list[Pattern] = []
    for module_info in pkgutil.iter_modules(swift_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.swift_patterns.{module_info.name}")
        except Exception as exc:  # a broken pattern module must not kill the scan
            sys.stderr.write(f"[ubs_core.swift_scan] pattern module {module_info.name} failed: {exc}\n")
            continue
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns


def load_derived() -> list[Callable]:
    """Aggregate DERIVED check callables from every swift_patterns module."""
    from ubs_core import swift_patterns

    derived: list[Callable] = []
    for module_info in pkgutil.iter_modules(swift_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.swift_patterns.{module_info.name}")
        except Exception:
            continue
        derived.extend(getattr(module, "DERIVED", []))
    return derived


def rel_for(path: Path, project_dir: Path) -> str:
    """Legacy rel(): path relative to the scan root, basename when outside.

    The heredoc detectors resolve findings against ``base = root if
    root.is_dir() else root.parent`` and fall back to the bare name for
    external paths.
    """
    base = project_dir if project_dir.is_dir() else project_dir.parent
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except (ValueError, OSError):
        return path.name


def run_derived(ctx: ScanContext, sink, skip: set[int]) -> None:
    """Run the cross-count derived checks contributed by pattern modules."""
    for fn in load_derived():
        try:
            findings = list(fn(ctx))
        except Exception as exc:
            sys.stderr.write(f"[ubs_core.swift_scan] derived check {getattr(fn, '__name__', fn)} failed: {exc}\n")
            continue
        for finding in findings:
            _write_record(sink, finding, skip)


def run_detectors(ctx: ScanContext, sink, skip: set[int]) -> None:
    """Run ubs_core.swift_detectors.* modules (legacy heredoc detector ports).

    Protocol: each module exposes ``scan(ctx) -> Iterable[dict]`` yielding
    final sink-record dicts; the orchestrator validates and writes them.
    """
    from ubs_core import swift_detectors

    for module_info in pkgutil.iter_modules(swift_detectors.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.swift_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.swift_scan] detector module {module_info.name} failed: {exc}\n")
            continue
        scan = getattr(module, "scan", None)
        if scan is None:
            continue
        try:
            findings = list(scan(ctx))
        except Exception as exc:
            sys.stderr.write(f"[ubs_core.swift_scan] detector {module_info.name} failed: {exc}\n")
            continue
        for finding in findings:
            _write_record(sink, finding, skip)


def _write_record(sink, finding: dict, skip: set[int]) -> None:
    category = int(finding.get("category", 0) or 0)
    if category in skip:
        return
    record = {
        "rule": str(finding.get("rule", "swift.detector")),
        "category_id": finding.get("category_id")
        or (f"swift.{slug_for_category(category)}" if category else ""),
        "path": str(finding.get("path", "")),
        "line": int(finding.get("line", 0) or 0),
        "col": int(finding.get("col", 1) or 1),
        "severity": finding.get("severity", "warning"),
        "count": int(finding.get("count", 1) or 0),
        "message": str(finding.get("message", "")),
        "suppressed": False,
    }
    for key in ("title", "description", "samples"):
        if finding.get(key) is not None:
            record[key] = finding[key]
    sink.write(json.dumps(record, ensure_ascii=False) + "\n")


def _analyzer_category(rule: str) -> int | None:
    """Registry analyzers ran inside their legacy categories."""
    if rule.startswith("swift.taint."):
        return 6
    if rule.startswith("swift.narrowing."):
        return 1
    if rule.startswith("swift.lifecycle."):
        return 16
    return None


def run_analyzers(ctx: ScanContext, sink, skip: set[int], enable_new: bool = False, prefilter: Any = None) -> None:
    """Run registered swift analyzers (taint, narrowing, lifecycle).

    ``regex_swift`` (ReDoS deep analysis) has no legacy counter impact — the
    legacy cat-12 checks were pure rg pipelines — so it stays off unless
    ``enable_new`` is set, keeping v2 totals at legacy parity. Analyzer
    record paths are re-expressed relative to the scan root exactly like the
    legacy heredocs' rel() (project-relative, basename fallback).
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import RunContext, analyzers_for_lang

    for analyzer in analyzers_for_lang("swift"):
        if analyzer.layer == "regex" and not enable_new:
            continue
        if analyzer.layer == "narrowing":
            # legacy run_swift_type_narrowing_checks degradation branches
            if ctx.skip_narrowing:
                _write_record(sink, {
                    "rule": "swift.narrowing", "category": 1,
                    "severity": "info", "count": 0,
                    "title": "Swift type narrowing checks skipped",
                    "message": "Swift type narrowing checks skipped",
                    "description": "Set UBS_SKIP_TYPE_NARROWING=0 to re-enable",
                    "degraded": True,
                }, skip)
                continue
            if not ctx.has_swift():
                _write_record(sink, {
                    "rule": "swift.narrowing", "category": 1,
                    "severity": "info", "count": 0,
                    "title": "No Swift sources detected",
                    "message": "No Swift sources detected",
                    "description": "Place .swift files in the project root to enable guard analysis",
                    "degraded": True,
                }, skip)
                continue
        if prefilter is not None:
            target_files = prefilter.filter_files_for_analyzer(analyzer.name, ctx.files)
        else:
            target_files = list(ctx.files)
        if not target_files:
            continue
        run_ctx = RunContext(lang="swift", files=target_files)
        try:
            findings = list(analyzer.run(run_ctx))
        except Exception as exc:
            sys.stderr.write(f"[ubs_core.swift_scan] analyzer {analyzer.name} failed: {exc}\n")
            continue
        for finding in findings:
            rule = str(finding.get("rule", ""))
            category = _analyzer_category(rule)
            if category is None or category in skip:
                continue
            path_raw = str(finding.get("path", "") or "")
            rel = rel_for(Path(path_raw), ctx.project_dir) if path_raw else ""
            _write_record(sink, {
                "rule": rule,
                "category": category,
                "path": rel,
                "line": finding.get("line", 0),
                "col": finding.get("col", 1),
                "severity": finding.get("severity", "warning"),
                "count": 1,
                "message": finding.get("message", ""),
            }, skip)


# ─────────────────────────────────────────────────────────────────────────────
# Static check catalog: the renderer walks these in legacy print order, so the
# v2 text output announces every non-skipped check (subheader + finding bucket
# or good note) exactly like the legacy module — including checks that found
# nothing. Buckets aggregate sink records by rule id.
# ─────────────────────────────────────────────────────────────────────────────
CHECK_SPECS: tuple[CheckSpec, ...] = (
    # 1. OPTIONALS / FORCE OPERATIONS
    CheckSpec(1, "swift.optionals.force-heavy", "Force unwrap (!) occurrences", samples=True, order=10),
    CheckSpec(1, "swift.optionals.force-some", None,
              good="No obvious force unwraps detected by heuristic",
              good_suppressed_by=("swift.optionals.force-heavy",), order=11),
    CheckSpec(1, "swift.optionals.try-bang", "try! and as! occurrences",
              good="No try!", samples=True, order=20),
    CheckSpec(1, "swift.optionals.as-bang", None, good="No as!", samples=True, order=21),
    CheckSpec(1, "swift.optionals.iuo", "Implicitly unwrapped optionals (T!)",
              good="No IUO types", samples=True, order=30),
    CheckSpec(1, "swift.optionals.url-bang", "URL(string:) force unwrap (URL(...)!)",
              good="No URL(string:) force unwraps detected", samples=True, order=40),
    CheckSpec(1, "swift.narrowing", "Swift guard let validation",
              good="Swift guard clauses exit before force unwraps", order=50),
    # 2. CONCURRENCY / TASK
    CheckSpec(2, "swift.concurrency.task-usages", order=10),
    CheckSpec(2, "swift.concurrency.unawaited-async", order=20),
    CheckSpec(2, "swift.concurrency.escape-hatches", "@unchecked Sendable / nonisolated(unsafe)",
              good="No @unchecked Sendable / nonisolated(unsafe) detected",
              desc="Review for thread-safety and actor isolation correctness", order=30),
    CheckSpec(2, "swift.concurrency.async-rules", "Async concurrency coverage (ast-grep)", order=40),
    # 3. CLOSURES / CAPTURE LISTS
    CheckSpec(3, "swift.closures.strong-self", "Long-lived closures without [weak self] (heuristic)",
              # legacy: the rg pattern in this pipeline has an unmatched ")" and
              # never compiles, so the check ALWAYS reports the good note
              good="No obvious long-lived closure sites lacking [weak self] by heuristic",
              order=10),
    CheckSpec(3, "swift.closures.unowned-self", "[unowned self] captures",
              good="No [unowned self] captures detected",
              desc="Unowned capture can crash if self deallocates; prefer weak + guard",
              samples=True, order=20),
    # 4. URLSESSION / NETWORKING
    CheckSpec(4, "swift.networking.task-sites", "URLSession task creation sites (review resume/cancel)",
              good="No URLSession task creation detected", order=10),
    CheckSpec(4, "swift.networking.correlation", "URLSession task correlation (resume/cancel) [AST-guided]", order=20),
    CheckSpec(4, "swift.networking.http-literals", "http:// literals",
              good="No http:// literals", samples=True, order=30),
    CheckSpec(4, "swift.networking.data-contents", "Blocking Data(contentsOf:)",
              good="No Data(contentsOf:) usage detected", samples=True, order=40),
    CheckSpec(4, "swift.networking.manual-query", "Manual query string building (prefer URLComponents)",
              good="No obvious manual query URLs detected", samples=True, order=50),
    # 5. ERROR HANDLING
    CheckSpec(5, "swift.errors.empty-catch", "Empty catch blocks",
              good="No empty catch blocks", samples=True, order=10),
    CheckSpec(5, "swift.errors.try-question", "try? discarding errors",
              good="try? usage not excessive by heuristic", order=20),
    CheckSpec(5, "swift.errors.crash-sites", "fatalError/preconditionFailure presence",
              good="No fatalError/preconditionFailure detected", samples=True, order=30),
    # 6. SECURITY
    CheckSpec(6, "swift.security.trust-all", "Trust-all server trust delegates",
              good="No obvious trust-all delegate patterns", samples=True, order=10),
    CheckSpec(6, "swift.security.secrets", "Hardcoded secrets",
              good="No obvious hardcoded secrets", samples=True, order=20),
    CheckSpec(6, "swift.security.unarchiving", "Insecure unarchiving (NSKeyedUnarchiver)",
              good="No obvious insecure unarchiving", samples=True, order=30),
    CheckSpec(6, "swift.security.archive-extraction", "Archive extraction path traversal",
              good="No unvalidated archive extraction path construction detected",
              desc="Expand/canonicalize archive entry destinations and reject paths outside the extraction root.", order=40),
    CheckSpec(6, "swift.taint.request_path_traversal", "Request-derived filesystem paths",
              good="No request-derived file path sinks detected",
              desc="Reduce request/query/url/upload filenames to a basename or canonicalize and prove the final URL stays under the allowed root.", order=50),
    CheckSpec(6, "swift.taint.request_open_redirect", "Request-derived open redirects",
              good="No request-derived redirect sinks detected",
              desc="Validate redirect targets as local URLs or parse and allow-list their scheme and host before redirects or Location headers.", order=60),
    CheckSpec(6, "swift.taint.header-injection", "Request-derived response headers",
              good="No request-derived response header sinks detected",
              desc="Reject or strip CR/LF before writing request data to response headers; encode Content-Disposition filenames or use a header-safe helper.", order=70),
    CheckSpec(6, "swift.taint.outbound-url", "Request-derived outbound HTTP URLs",
              good="No request-derived outbound HTTP URL sinks detected",
              desc="Validate outbound URLs with URL parsing plus explicit https scheme and host allow-list checks before URLSession, URLRequest, Data(contentsOf:), or HTTP client calls.", order=80),
    CheckSpec(6, "swift.security.shell-exec", "Process/posix shell usage", order=90),
    CheckSpec(6, "swift.security.process-other", None,
              good="No Process/system invocations detected",
              good_suppressed_by=("swift.security.shell-exec",), samples=True, order=91),
    # 7. CRYPTO / HASHING
    CheckSpec(7, "swift.crypto.commoncrypto", "CommonCrypto MD5/SHA1",
              good="No CommonCrypto MD5/SHA1", samples=True, order=10),
    CheckSpec(7, "swift.crypto.insecure", "CryptoKit Insecure.*",
              good="No CryptoKit Insecure algorithms", samples=True, order=20),
    CheckSpec(7, "swift.crypto.ecb", "ECB mode flags (CommonCrypto)",
              good="No ECB mode flags", samples=True, order=30),
    CheckSpec(7, "swift.crypto.weak-randomness", "Security-sensitive non-crypto randomness",
              good="No security-sensitive non-crypto randomness detected",
              desc="Use SecRandomCopyBytes, CryptoKit SymmetricKey/Nonce generation, or a cryptographic helper for tokens, sessions, CSRF nonces, OTPs, salts, API keys, and secrets", order=40),
    # 8. FILES & I/O
    CheckSpec(8, "swift.files.filehandle", "FileHandle open without close in file",
              good="No FileHandle close imbalance by heuristic", order=10),
    CheckSpec(8, "swift.files.string-contents", "String(contentsOf:) usage",
              good="No String(contentsOf:)", samples=True, order=20),
    CheckSpec(8, "swift.files.path-concat", "Path string concatenation",
              good="No significant string path concatenation", order=30),
    # 9. THREADING / MAIN
    CheckSpec(9, "swift.threading.main-actor", "UI frameworks used but no @MainActor annotations found (heuristic)",
              good="MainActor annotation presence not obviously missing", order=10),
    CheckSpec(9, "swift.threading.sleep-main", "sleep/usleep on main queue",
              good="No sleep/usleep on main queue", samples=True, order=20),
    CheckSpec(9, "swift.threading.main-sync", "DispatchQueue.main.sync usage",
              good="No DispatchQueue.main.sync", samples=True, order=30),
    # 10. PERFORMANCE
    CheckSpec(10, "swift.perf.string-loops", "String concatenation in loops (heuristic)",
              good="No obvious string += loop patterns", order=10),
    CheckSpec(10, "swift.perf.regex-loops", "NSRegularExpression init near loops (heuristic)",
              good="No NSRegularExpression-in-loop patterns", order=20),
    CheckSpec(10, "swift.perf.formatter-churn", "DateFormatter/JSONDecoder churn",
              good="No excessive formatter/decoder churn by heuristic", order=30),
    # 11. DEBUG / PRODUCTION
    CheckSpec(11, "swift.debug.print-many", "print/NSLog occurrences", order=10),
    CheckSpec(11, "swift.debug.print-some", None, order=11),
    CheckSpec(11, "swift.debug.print-minimal", None, good="No print/NSLog",
              good_suppressed_by=("swift.debug.print-many", "swift.debug.print-some"), order=12),
    CheckSpec(11, "swift.debug.ifdebug", "#if DEBUG blocks",
              good="No #if DEBUG blocks detected", order=20),
    CheckSpec(11, "swift.debug.failing-asserts", "assert(false) or assertionFailure()",
              good="No always-failing assertions detected", samples=True, order=30),
    # 12. REGEX
    CheckSpec(12, "swift.regex_cat.nested-quantifiers", "Nested quantifiers (potential catastrophic backtracking)",
              good="No obvious nested-quantifier patterns", samples=True, order=10),
    CheckSpec(12, "swift.regex_cat.nspredicate", "NSPredicate(format:) usage",
              good="No NSPredicate(format:) usage detected", samples=True, order=20),
    # 13. SWIFTUI / COMBINE
    CheckSpec(13, "swift.swiftui.sink-unstored", "Combine .sink without obvious .store(in:) nearby (heuristic)",
              good="No obvious unstored sink calls", samples=True, order=10),
    CheckSpec(13, "swift.swiftui.onreceive", "SwiftUI onReceive usage",
              good="No .onReceive usage detected", samples=True, order=20),
    # 14. MEMORY / RETAIN
    CheckSpec(14, "swift.memory.timers", "Timer scheduled (review invalidation & capture lists)",
              good="No Timer.scheduledTimer usage", samples=True, order=10),
    CheckSpec(14, "swift.memory.block-observers", "NotificationCenter block-based observers",
              good="No block-based NotificationCenter observers", samples=True, order=20),
    CheckSpec(14, "swift.memory.cadisplaylink", "CADisplayLink created (ensure invalidate)",
              good="No CADisplayLink usage detected", samples=True, order=30),
    # 15. CODE QUALITY MARKERS (no subheader in legacy)
    CheckSpec(15, "swift.quality.debt-heavy", order=10),
    CheckSpec(15, "swift.quality.debt-moderate", order=11),
    CheckSpec(15, "swift.quality.debt-minimal", good="No technical debt markers",
              good_suppressed_by=("swift.quality.debt-heavy", "swift.quality.debt-moderate"), order=12),
    # 16. RESOURCE LIFECYCLE
    CheckSpec(16, "swift.lifecycle", "Resource lifecycle correlation (Swift)",
              good="All tracked resource acquisitions show matching cleanup or usage", order=10),
    # 17. INFO.PLIST / ATS
    CheckSpec(17, "swift.infoplist.ats-parse", "Info.plist ATS precise parsing",
              good="No problematic ATS settings found via plist parsing", order=10),
    CheckSpec(17, "swift.infoplist.ats-regex", "ATS allows arbitrary loads (regex heuristic)",
              good="No obvious ATS arbitrary-loads strings", order=20),
    CheckSpec(17, "swift.infoplist.web-content", "NSAllowsArbitraryLoadsInWebContent",
              good="No NSAllowsArbitraryLoadsInWebContent=true found", order=30),
    # 18. DEPRECATED APIs
    CheckSpec(18, "swift.deprecations.webview", "UIWebView/NSURLConnection",
              good="No UIWebView/NSURLConnection detected", samples=True, order=10),
    CheckSpec(18, "swift.deprecations.statusbar", "Deprecated status bar APIs / keyWindow",
              good="No obvious deprecated status bar/keyWindow usage", samples=True, order=20),
    # 19. BUILD / SIGNING
    CheckSpec(19, "swift.build.entitlements", "Entitlements parsing (.entitlements)",
              good="No suspicious entitlements detected (heuristic set)", order=10),
    CheckSpec(19, "swift.build.debug-signing", "Debug signing identifiers in Release configs (heuristic)",
              good="No obvious debug signing strings", order=20),
    # 20. PACKAGING / SPM
    CheckSpec(20, "swift.packaging.branch-pins", "Package.swift branch/revision/unsafeFlags",
              good="No branch/revision SPM pins detected",
              good_suppressed_by=("swift.packaging.no-manifest",), order=10),
    CheckSpec(20, "swift.packaging.unsafe-flags", None, good="No SPM unsafeFlags detected",
              good_suppressed_by=("swift.packaging.no-manifest",), order=20),
    CheckSpec(20, "swift.packaging.no-manifest", None, order=30),
    # 21. UI/UX SAFETY
    CheckSpec(21, "swift.uisafety.iboutlet-iuo", "IBOutlet IUO (T!)",
              good="No IUO IBOutlets detected", samples=True, order=10),
    CheckSpec(21, "swift.uisafety.storyboards", "Many storyboards (heuristic)",
              good="Storyboard count not high", order=20),
    # 22. TESTS / HYGIENE
    CheckSpec(22, "swift.tests.xctfail-todo", 'XCTFail("TODO")',
              good='No placeholder XCTFail("TODO")', samples=True, order=10),
    CheckSpec(22, "swift.tests.sleeps", "sleep/usleep in tests",
              good="No sleep/usleep patterns in tests by heuristic", order=20),
    # 23. LOCALIZATION
    CheckSpec(23, "swift.l10n.ui-strings", "Hard-coded user-facing strings (heuristic)",
              good="No obvious unlocalized UI strings", order=10),
    CheckSpec(23, "swift.l10n.string-format", "String(format:) without explicit locale (heuristic)",
              good="No String(format:) without locale found", order=20),
)
_BAR = "━" * 64

_SPEC_BY_RULE = {spec.rule_id: spec for spec in CHECK_SPECS}
_LIFECYCLE_SUMMARY = {
    "timer": "Timer scheduled but never invalidated",
    "urlsession_task": "URLSession task created but not resumed/cancelled",
    "notification_token": "NotificationCenter observer token not removed",
    "file_handle": "FileHandle opened without close()",
    "combine_sink": "Combine sink not stored, may be dropped immediately",
    "dispatch_source": "DispatchSource created but not cancelled/resumed",
    "cadisplaylink": "CADisplayLink created but not invalidated",
    "kvo_observer": "KVO addObserver without removeObserver",
}


class _Renderer:
    def __init__(self, args, records: list[dict]):
        self.args = args
        self.records = records
        self.buckets: dict[str, list[dict]] = {}
        for rec in records:
            self.buckets.setdefault(str(rec.get("rule", "")), []).append(rec)
        self.lines: list[str] = []
        self.detailed = 0
        self._line_cache: dict[str, list[str]] = {}

    # ── legacy print primitives (colors stripped: the meta runner captures
    # module output with NO_COLOR=1 in every manifest/CI context) ──
    def header(self, title: str) -> None:
        self.lines += ["", _BAR, title, _BAR]

    def category(self, cat: int) -> None:
        detects, prefer = _CATEGORY_DETECTED[cat]
        self.lines += ["", f"▓▓▓ {detects}", prefer]

    def subheader(self, text: str) -> None:
        self.lines += ["", f"• {text}"]

    def finding(self, sev: str, count: int, title: str, desc: str | None) -> None:
        label = {"critical": "🔥 CRITICAL", "warning": "⚠ Warning", "good": "✓ OK"}.get(sev, "ℹ Info")
        if sev == "good":
            self.lines.append(f" ✓ OK {title}")
            return
        self.lines.append(f" {label} ({count} found)")
        self.lines.append(f" {title}")
        if desc:
            self.lines.append(f" {desc}")

    def _code(self, path: str, line_no: int) -> str:
        if path not in self._line_cache:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    self._line_cache[path] = fh.readlines()
            except OSError:
                self._line_cache[path] = []
        lines = self._line_cache[path]
        idx = line_no - 1
        return lines[idx].rstrip("\n") if 0 <= idx < len(lines) else ""

    def samples(self, items: list[tuple[str, int]]) -> None:
        for path, line_no in items:
            if self.detailed >= self.args.max_detailed:
                self.lines.append("(max detailed samples reached; increase --max-detailed to see more)")
                return
            self.detailed += 1
            self.lines.append(f" {path}:{line_no}")
            code = self._code(path, line_no)
            if code:
                self.lines.append(f" {code}")

    def embedded_samples(self, recs: list[dict], limit: int = 5) -> None:
        items: list[tuple[str, int]] = []
        for rec in recs:
            for s in rec.get("samples") or []:
                items.append((str(s.get("path", "")), int(s.get("line", 0) or 0)))
        self.samples(items[:limit])

    # ── bucket accessors ──
    def count(self, rule: str) -> int:
        return sum(int(rec.get("count", 1) or 0) for rec in self.buckets.get(rule, []))

    def severity(self, rule: str) -> str:
        recs = self.buckets.get(rule) or [{}]
        return str(recs[0].get("severity", "info"))

    def title(self, rule: str) -> str:
        recs = self.buckets.get(rule) or []
        for rec in recs:
            if rec.get("title"):
                return str(rec["title"])
        if recs and recs[0].get("message"):
            return str(recs[0]["message"])
        return rule

    def desc(self, rule: str, spec: CheckSpec | None) -> str | None:
        for rec in self.buckets.get(rule, []):
            if rec.get("description"):
                return str(rec["description"])
        return spec.desc if spec else None

    def per_line_samples(self, rule: str, limit: int = 5) -> list[tuple[str, int]]:
        return [
            (str(rec.get("path", "")), int(rec.get("line", 0) or 0))
            for rec in self.buckets.get(rule, [])
            if rec.get("path") and int(rec.get("line", 0) or 0) > 0
        ][:limit]

    def render(self, skip: set[int]) -> None:
        for cat in range(1, 24):
            if cat in skip:
                continue
            self.header(_SECTION_HEADERS[cat])
            self.category(cat)
            for spec in sorted([s for s in CHECK_SPECS if s.category == cat], key=lambda s: s.order):
                if spec.subheader:
                    self.subheader(spec.subheader)
                self.render_spec(spec)
        self.render_ast_section()

    def render_spec(self, spec: CheckSpec) -> None:
        if spec.rule_id == "swift.networking.correlation":
            # degradation/good records land under the check's own rule id;
            # per-finding buckets use the legacy ubs.correlation.* ids
            for rec in self.buckets.get("swift.networking.correlation", []):
                self.finding(str(rec.get("severity", "info")), int(rec.get("count", 0) or 0),
                             str(rec.get("title") or rec.get("message", "")), rec.get("description"))
            correlation = [r for r in self.buckets if r.startswith(_CORRELATION_PREFIX)]
            if correlation:
                for rule in correlation:
                    for rec in self.buckets[rule]:
                        self.finding(str(rec.get("severity", "info")), int(rec.get("count", 1) or 0),
                                     str(rec.get("title") or rule), rec.get("description"))
                        self.embedded_samples([rec], limit=3)
            elif not self.buckets.get("swift.networking.correlation") and spec.good:
                self.finding("good", 0, spec.good, None)
            return
        if spec.rule_id == "swift.narrowing":
            recs = [rec for rule, bucket in self.buckets.items()
                    if rule.startswith("swift.narrowing") for rec in bucket]
            findings = [r for r in recs if not r.get("degraded")]
            degraded = [r for r in recs if r.get("degraded")]
            if findings:
                count = sum(int(r.get("count", 1) or 0) for r in findings)
                previews = [
                    f"{r.get('path', '')}:{r.get('line', 0)}:{r.get('col', 1)} → {r.get('message', '')}"
                    for r in findings[:3]
                ]
                desc = f"Examples: {' '.join(previews)}"
                if count > len(previews):
                    desc += f" (and {count - len(previews)} more)"
                self.finding(str(findings[0].get("severity", "warning")), count,
                             "Swift guard let else-block may continue", desc)
            elif degraded:
                for rec in degraded:
                    self.finding(str(rec.get("severity", "info")), int(rec.get("count", 0) or 0),
                                 str(rec.get("title") or rec.get("message", "")), rec.get("description"))
            elif spec.good:
                self.finding("good", 0, spec.good, None)
            return
        rule = spec.rule_id
        if rule in self.buckets:
            count = self.count(rule)
            severity = self.severity(rule)
            self.finding(severity, count, self.title(rule), self.desc(rule, spec))
            if _SPEC_BY_RULE[rule].samples:
                if rule == "swift.security.process-other":
                    self.embedded_samples(self.buckets[rule], limit=5)
                else:
                    self.samples(self.per_line_samples(rule))
            return
        if spec.good and not any(s in self.buckets for s in spec.good_suppressed_by):
            self.finding("good", 0, spec.good, None)

    def render_ast_section(self) -> None:
        self.header("AST-GREP RULE PACK FINDINGS")
        if not self.args.ast_available:
            self.lines.append(" ⚠ ast-grep not available; rule pack skipped.")
            return
        pack = [
            rule for rule in self.buckets
            if rule == AST_PACK_RULE or (
                not self.buckets[rule][0].get("category_id")
                and not rule.startswith(_CORRELATION_PREFIX)
                and rule not in _SPEC_BY_RULE
            )
        ]
        if not pack:
            return
        self.subheader("ast-grep rule-pack summary")
        for rule in sorted(pack):
            for rec in self.buckets[rule]:
                count = int(rec.get("count", 1) or 0)
                if count <= 0:
                    continue
                self.finding(str(rec.get("severity", "info")), count,
                             str(rec.get("title") or f"{rule}: {rec.get('message', '')}"), None)
                self.embedded_samples([rec], limit=self.args.detail_limit)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _skip_set(args) -> set[int]:
    return {int(part) for part in (args.skip or "").split(",") if part.strip().isdigit()}


def _legacy_report(records: list[dict], version: str) -> dict:
    """Legacy issue-64 payload: per-rule aggregated findings with samples."""
    by_rule: dict[str, list[dict]] = {}
    for rec in records:
        by_rule.setdefault(rec.get("rule", ""), []).append(rec)
    findings = []
    for rule, recs in by_rule.items():
        first = recs[0]
        findings.append({
            "severity": first.get("severity", "info"),
            "count": sum(int(rec.get("count", 1) or 0) for rec in recs),
            "title": str(first.get("title") or first.get("message", ""))[:200],
            "description": str(first.get("description", "")),
            "samples": [
                {"path": rec.get("path", ""), "line": int(rec.get("line", 0) or 0)}
                for rec in recs[:3]
            ],
        })
    return {"version": version, "findings": findings}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.swift_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="scan root for rel-path parity")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--ast-rule-dir", default="", help="consolidated ast-grep rule dir")
    parser.add_argument("--ast-available", action="store_true",
                        help="ast-grep was available to the module (degradation parity)")
    parser.add_argument("--skip-type-narrowing", action="store_true",
                        help="UBS_SKIP_TYPE_NARROWING=1 (legacy env escape)")
    parser.add_argument("--text-out", default="", help="write the legacy-format text report here")
    parser.add_argument("--json-out", default="", help="write the UBS summary JSON document here")
    parser.add_argument("--project", default="", help="project path recorded in the json summary")
    parser.add_argument("--version", default="", help="module version recorded in the json summary")
    parser.add_argument("--max-detailed", type=int, default=250)
    parser.add_argument("--detail-limit", type=int, default=3)
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--enable-new-analyzers", action="store_true",
                        help="run analyzers with no legacy counter impact (regex_swift)")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)
    project_dir = Path(args.project_dir) if args.project_dir else Path(".")
    ctx = ScanContext(files=files, project_dir=project_dir,
                      skip_narrowing=args.skip_type_narrowing,
                      ast_available=args.ast_available)
    patterns = load_patterns()

    from ubs_core.cache import CapturingSink, ScanCache

    cache = ScanCache(
        lang="swift",
        project_dir=project_dir,
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"ast_available={args.ast_available};skip_narrowing={args.skip_type_narrowing};new_analyzers={args.enable_new_analyzers}",
    )
    cached_findings, files_to_scan = cache.partition_files(files)

    capturing_sink = None
    if files_to_scan:
        from ubs_core.prefilter import build_prefilter_index, run_prefilter
        from ubs_core.registry import analyzers_for_lang
        from ubs_core.swift_rules import _RULES

        swift_analyzers = [a.name for a in analyzers_for_lang("swift")]
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
            analyzers=swift_analyzers,
            lang="swift",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        scan_ctx = ScanContext(
            files=files_to_scan,
            project_dir=project_dir,
            skip_narrowing=args.skip_type_narrowing,
            ast_available=args.ast_available,
        )
        capturing_sink = CapturingSink()
        scan_patterns(patterns, scan_ctx, capturing_sink, skip, prefilter=prefilter_res)
        if args.ast_rule_dir:
            from ubs_core.swift_ast import scan_all

            ast_files = prefilter_res.ast_files if not prefilter_res.is_bypass else files_to_scan
            scan_all(Path(args.ast_rule_dir), ast_files, scan_ctx, capturing_sink, skip=skip,
                     detail_limit=args.detail_limit)
        if args.ast_available and not scan_ctx.ast_stream_ok:
            _write_record(capturing_sink, {
                "rule": "swift.concurrency.async-rules",
                "category": 2,
                "severity": "info",
                "count": 0,
                "title": "ast-grep stream unavailable",
                "message": "ast-grep stream unavailable",
                "description": "Concurrency summary requires ast-grep JSON stream output",
                "degraded": True,
            }, skip)
        run_detectors(scan_ctx, capturing_sink, skip)
        run_derived(scan_ctx, capturing_sink, skip)
        run_analyzers(scan_ctx, capturing_sink, skip, enable_new=args.enable_new_analyzers, prefilter=prefilter_res)
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

    with open(args.sink, "w", encoding="utf-8") as sink_file:
        for f in files:
            recs = cached_findings.get(f)
            if recs is None and capturing_sink is not None:
                recs = capturing_sink.get_for_file(f, project_dir=args.project_dir or args.project)
            if recs:
                for r in recs:
                    sink_file.write(json.dumps(r, ensure_ascii=False) + "\n")

    cache_file = os.environ.get("UBS_CACHE_FILE") or (os.path.splitext(args.sink)[0] + ".cache")
    cache.write_stats(cache_file)

    # The sink is the single source of truth: recount severities from it so
    # every layer (patterns, derived, detectors, analyzers, ast) is reflected.
    counters = {"critical": 0, "warning": 0, "info": 0}
    for line in Path(args.sink).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        severity = record.get("severity", "info")
        if severity in counters:
            counters[severity] += int(record.get("count", 1) or 0)

    exit_code = 1 if counters["critical"] else 0
    if args.fail_on_warning and (counters["critical"] + counters["warning"]) > 0:
        exit_code = 1

    if args.json_out:
        import datetime

        records = [json.loads(line) for line in Path(args.sink).read_text(encoding="utf-8").splitlines() if line.strip()]
        profile_data = {
            "files_considered": prefilter_res.files_considered if files_to_scan else len(files),
            "files_after_prefilter": prefilter_res.files_after_prefilter if files_to_scan else 0,
            "prefilter_ms": prefilter_res.prefilter_ms if files_to_scan else 0,
            "cache_hits": cache.stats["hits"],
            "cache_misses": cache.stats["misses"],
            "cache_hit_rate": cache.stats["hit_rate"],
        }
        doc = {
            "language": "swift",
            "project": args.project or args.project_dir,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": len(files),
            "critical": counters["critical"],
            "warning": counters["warning"],
            "info": counters["info"],
            "version": args.version,
            "status": "ok",
            "findings": records,
            "report": _legacy_report(records, args.version),
            "extras": {"profile": profile_data},
        }
        if os.environ.get("UBS_PROFILE") == "1":
            doc["profile"] = profile_data
        Path(args.json_out).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.text_out:
        records = [json.loads(line) for line in Path(args.sink).read_text(encoding="utf-8").splitlines() if line.strip()]
        renderer = _Renderer(args, records)
        renderer.render(skip)
        Path(args.text_out).write_text(renderer.text(), encoding="utf-8")

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns),
                                 "prefilter": prefilter_res.to_dict()}) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
