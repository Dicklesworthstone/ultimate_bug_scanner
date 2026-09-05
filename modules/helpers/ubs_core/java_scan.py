"""ubs_core.java_scan — contract-v2 orchestrator for the Java/Kotlin module (bead 0xjg.8).

Replaces the legacy module's ~200-300 process spawns with ONE python process:

    python3 -m ubs_core.java_scan --files-from <nul-list> --sink <ndjson> \
        [--project-dir DIR] [--skip 1,2,3] [--ast-rule-dir DIR]

Layers, in order:
1. Pattern layer — regex categories aggregated from ubs_core.java_patterns.*
   (one Pattern per legacy rg pipeline; flat same-line ubs:ignore exclusion
   preserves the legacy count_lines semantics; the A7 statement-interval
   engine in the meta-runner postprocess adds the richer placements).
2. Analyzer layer — registered ubs_core analyzers: taint_java_traversal +
   taint_java_redirect (category 4; verbatim heredoc ports) and
   narrowing_kotlin (category 1 Kotlin guard probe, run when .kt/.kts files
   are in scope). lifecycle_java does NOT run: with ast-grep available the
   legacy category-19 resource branch uses the ast rule group, and the
   regex helper is only the no-ast-grep fallback.
3. Detector layer — ubs_core.java_detectors.* (verbatim ports of the legacy
   python heredocs and per-file/count-comparison loops).
4. ast-grep layer — the consolidated rule pack (ONE `scan -c` invocation)
   via ubs_core.java_ast.scan_all; only the resource/async/isPresent ids are
   counted, everything else is an informational dump in legacy.

Sink record (one JSON object per line, K2 schema):
    {rule, category_id, path, line, col, severity, message, suppressed}
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.registry import RunContext

MARKER = "ubs:ignore"

_CATEGORY_SLUGS = {
    1: "null-optional", 2: "equality", 3: "concurrency", 4: "security",
    5: "io", 6: "logging", 7: "regex", 8: "collections",
    9: "control-flow", 10: "streams-perf", 11: "serialization", 12: "java21",
    13: "sql", 14: "annotations", 15: "ast-grep", 16: "build",
    17: "inventory", 18: "api-misuse", 19: "resource-lifecycle",
    20: "filesystem", 21: "secrets", 22: "logging-practices",
}

# Legacy print_header titles, in category order (rendered before a section).
_SECTION_HEADERS = {
    1: "1. NULL & OPTIONAL PITFALLS",
    2: "2. EQUALITY & HASHCODE",
    3: "3. CONCURRENCY & THREADING",
    4: "4. SECURITY",
    5: "5. I/O & RESOURCES",
    6: "6. LOGGING & DEBUGGING",
    7: "7. REGEX & STRING PITFALLS",
    8: "8. COLLECTIONS & GENERICS",
    9: "9. SWITCH & CONTROL FLOW",
    10: "10. STREAMS & PERFORMANCE",
    11: "11. SERIALIZATION & COMPATIBILITY",
    12: "12. JAVA 21 FEATURES (INFO)",
    13: "13. SQL CONSTRUCTION (HEURISTICS)",
    14: "14. ANNOTATIONS & NULLNESS (HEURISTICS)",
    15: "15. AST-GREP RULE PACK FINDINGS",
    16: "16. BUILD HEALTH (Maven/Gradle)",
    17: "17. META STATISTICS & INVENTORY",
    18: "18. MISC API MISUSE",
    19: "19. RESOURCE SAFETY & RESOURCE LIFECYCLE CORRELATION",
    20: "20. PATH HANDLING & FILESYSTEM",
    21: "21. HARD-CODED SECRETS (HEURISTICS)",
    22: "22. LOGGING BEST PRACTICES",
}

# Legacy print_subheader texts that manifest cases assert, keyed by the rule
# prefix they announce.
_SUBHEADERS = {
    1: {
        "java.null-optional.optional-get": "Optional.get() usage (potential NoSuchElementException)",
        "kotlin.narrowing.": "Kotlin guard clauses without exit",
    },
    3: {
        "java.async.": "Async error path coverage",
    },
    4: {
        "java.security.insecure-randomness": "Security-sensitive non-crypto randomness",
        "java.taint.path_traversal": "Request-derived filesystem paths",
        "java.security.header-injection": "Request-derived response headers",
        "java.taint.open_redirect": "Request-derived open redirects",
        "java.security.ssrf-outbound-url": "Request-derived outbound HTTP URLs",
        "java.security.archive-extraction": "Archive extraction path traversal",
    },
    19: {
        "java.resource.": "Resource lifecycle correlation",
    },
}

# Legacy print_finding titles for analyzer/ast/detector findings that carry
# their own message; pattern findings carry their pattern title.
_SUMMARY_TITLES: dict[str, str] = {
    "java.taint.path_traversal": "Request-derived path reaches file read/write/serve sink",
    "java.taint.open_redirect": "Unvalidated redirect from request data",
    "kotlin.narrowing.safecall_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.negative_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.positive_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.smart_cast": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.elvis_force": "Kotlin guard without exit before '!!'",
}

# Legacy print_finding "good" notes: rule-id prefix -> note, emitted when the
# category ran but produced no records under that prefix. The Kotlin note
# only applies when .kt/.kts files are in scope (legacy HAS_KOTLIN_FILES).
_GOOD_LINES: tuple[tuple[str, str, int], ...] = (
    ("java.null-optional.optional-get", "No Optional.get() calls", 1),
    ("kotlin.narrowing.", "No Kotlin guard clauses missing exit", 1),
    ("java.equality.string-eq", "No String '==' comparisons detected", 2),
    ("java.taint.path_traversal", "No request-derived filesystem paths detected", 4),
    ("java.security.header-injection", "No request-derived response header values detected", 4),
    ("java.taint.open_redirect", "No request-derived open redirect sinks detected", 4),
    ("java.security.ssrf-outbound-url", "No request-derived outbound HTTP URL sinks detected", 4),
    ("java.security.archive-extraction", "No unvalidated archive extraction path construction detected", 4),
    ("java.security.insecure-randomness", "No security-sensitive non-crypto randomness detected", 4),
    ("java.io.twr", "Closeable resources appear wrapped in try-with-resources", 5),
    ("java.logging.tech-debt", "No technical debt markers", 6),
    ("java.resource.", "All tracked resource acquisitions have matching cleanups", 19),
)


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity): the
    first entry whose count > min_count wins; when none match, the pattern
    reports nothing — mirroring the legacy `warning >N / info >0` ladders.
    require_regex expresses the legacy `| grep -E` post-pipe (a line must
    match BOTH regexes); exclude_regex expresses `grep -v` post-filters.
    """

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...]
    require_regex: re.Pattern[str] | None = None  # legacy `grep -E` post-pipe
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` post-filters
    description: str = ""


def iter_matches(pattern: Pattern, text: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for matches, skipping excluded lines.

    rg is line-oriented: a match never spans a newline, one line is reported
    once per pattern, and count_lines drops ubs:ignore lines. Matching
    per line reproduces exactly that (a whole-text finditer would let
    ``[^)]``-style classes cross newlines and drift from legacy counts).
    """
    for line_no, line_text in enumerate(text.splitlines(), 1):
        if MARKER in line_text:
            continue  # legacy count_lines drops marker lines from counts
        if pattern.exclude_regex is not None and pattern.exclude_regex.search(line_text):
            continue
        if pattern.require_regex is not None and not pattern.require_regex.search(line_text):
            continue
        if pattern.regex.search(line_text):
            yield line_no, line_text.strip()[:240]


def resolve_severity(pattern: Pattern, count: int) -> str | None:
    for min_count, severity in pattern.thresholds:
        if count > min_count:
            return severity
    return None


def scan_patterns(patterns: Sequence[Pattern], files: Sequence[Path], sink, skip: set[int]) -> dict[str, int]:
    """Run every pattern over the file list, writing sink records.

    Legacy parity semantics: counts are DISTINCT MATCHING LINES across the
    whole file list (rg prints each matching line once), and severity is
    resolved ONCE per pattern from that project-wide count — every record of
    a pattern carries the same severity, so summed counters equal the legacy
    print_finding buckets.

    Returns severity counters ({"critical": n, "warning": n, "info": n}).
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
        hits: list[tuple[Path, int, str]] = []
        seen: set[tuple[Path, int]] = set()
        for path, text in texts.items():
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
                "category_id": f"java.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "message": f"{pattern.title} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def load_patterns() -> list[Pattern]:
    """Aggregate PATTERNS from every ubs_core.java_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import java_patterns

    patterns: list[Pattern] = []
    for module_info in pkgutil.iter_modules(java_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"ubs_core.java_patterns.{module_info.name}")
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns


def _record_category(finding: dict) -> int | None:
    """Map a finding's rule id to its legacy category number."""
    rule = str(finding.get("rule", ""))
    category_id = str(finding.get("category_id", ""))
    if rule.startswith("java.taint."):
        return 4
    if rule.startswith("java.resource."):
        return 19
    if rule.startswith("java.async."):
        return 3
    if rule.startswith("java.optional."):
        return 1
    if rule.startswith("kotlin.narrowing."):
        return 1
    # category_id is authoritative for pattern/detector records.
    for num, slug in _CATEGORY_SLUGS.items():
        if category_id == f"java.{slug}":
            return num
    # Legacy `java.<slug>.<name>` ids minted after the meta-runner slug table.
    if rule.startswith("java."):
        rest = rule[5:]
        for num, slug in _CATEGORY_SLUGS.items():
            if rest.startswith(f"{slug}."):
                return num
    return None  # ast-pack rules count in totals only (legacy CURRENT_CATEGORY=0)


def run_analyzers(files: Sequence[Path], sink, skip: set[int] | None = None,
                  project_dir: Path | None = None, enable_new: bool = False) -> None:
    """Run registered analyzers: java taint pair + kotlin narrowing.

    narrowing_kotlin registers under lang="kotlin" while the module's file
    list mixes .java/.kt/.kts, so both registries run over the same list —
    each analyzer filters by suffix itself. Two calibration gates keep v2
    totals at legacy parity:
    - layer=="lifecycle" (lifecycle_java) is the legacy NO-ast-grep fallback
      for the cat-19 resource branch; with ast-grep at the gate the counted
      ast rule group owns those findings.
    - layer=="guards" (guards_java, bead D3) has no legacy java counterpart —
      it stays off unless ``enable_new``.
    Analyzer paths are relativized to the project dir, mirroring the legacy
    heredoc relpath form.
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import analyzers_for_lang

    allowed_layers = {"java": {"taint"}, "kotlin": {"narrowing"}}

    def _rel(path: str) -> str:
        if project_dir is None or not path:
            return path
        try:
            p = Path(path)
            if not p.is_absolute():
                resolved = (Path.cwd() / p).resolve()
                base = Path(project_dir).resolve()
                if resolved != base:
                    return str(resolved.relative_to(base))
                return path
            return str(p.resolve().relative_to(Path(project_dir).resolve()))
        except ValueError:
            return path

    for lang in ("java", "kotlin"):
        ctx = RunContext(lang=lang, files=list(files))
        for analyzer in analyzers_for_lang(lang):
            if analyzer.layer not in allowed_layers[lang]:
                if not (enable_new and analyzer.layer == "guards" and lang == "java"):
                    continue
            for finding in analyzer.run(ctx):
                if skip and _record_category(finding) in skip:
                    continue
                sink.write(json.dumps({
                    "rule": finding.get("rule", ""),
                    "category_id": f"java.{_CATEGORY_SLUGS[_record_category(finding)]}"
                    if _record_category(finding) is not None else finding.get("category_id", "java.security"),
                    "path": _rel(str(finding.get("path", ""))),
                    "line": int(finding.get("line", 0) or 0),
                    "col": int(finding.get("col", 1) or 1),
                    "severity": finding.get("severity", "warning"),
                    "message": finding.get("message", ""),
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")


def run_detectors(files: Sequence[Path], sink, skip: set[int] | None = None) -> None:
    """Run ubs_core.java_detectors.* modules (legacy heredoc detector ports).

    Protocol (single-rule modules): RULE_ID, CATEGORY, TITLE, SEVERITY,
    DESCRIPTION and ``find(files)`` yielding (path, line, col, detail).
    Multi-rule modules expose ``RULES`` — a tuple of
    (rule_id, category, title, severity, description) tuples — and
    ``find(files)`` yielding (rule_id, path, line, col, detail).
    """
    import importlib
    import pkgutil

    from ubs_core import java_detectors

    for module_info in pkgutil.iter_modules(java_detectors.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.java_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.java_scan] detector module {module_info.name} failed: {exc}\n")
            continue
        find = getattr(module, "find", None)
        if find is None:
            continue
        if hasattr(module, "RULES"):
            specs = {
                spec[0]: {"category": int(spec[1]), "title": str(spec[2]),
                          "severity": str(spec[3]), "description": str(spec[4])}
                for spec in module.RULES
            }
        else:
            category = int(getattr(module, "CATEGORY", 4))
            rule_id = str(getattr(module, "RULE_ID", f"java.cat{category}.{module_info.name}"))
            specs = {rule_id: {
                "category": category,
                "title": str(getattr(module, "TITLE", rule_id)),
                "severity": str(getattr(module, "SEVERITY", "warning")),
                "description": str(getattr(module, "DESCRIPTION", "")),
            }}
        if skip:
            specs = {rid: spec for rid, spec in specs.items()
                     if spec["category"] not in skip}
            if not specs:
                continue
        for hit in find(files):
            if len(hit) == 5:
                rule_id, path, line_no, col, detail = hit
            else:
                path, line_no, col, detail = hit  # single-rule convenience
                rule_id = next(iter(specs))
            spec = specs.get(rule_id)
            if spec is None:
                continue
            slug = slug_for_category(spec["category"])
            title = spec["title"]
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"java.{slug}",
                "path": str(path),
                "line": int(line_no),
                "col": int(col),
                "severity": spec["severity"],
                "message": f"{title} — {detail}"[:300] if detail else title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def _finding_title(rec: dict) -> str:
    rule = rec.get("rule", "")
    if rule in _SUMMARY_TITLES:
        return _SUMMARY_TITLES[rule]
    return str(rec.get("message", rule))


def _render_text(args, files: Sequence[Path], counters: dict[str, int], ast_ran: bool) -> None:
    """Render the legacy-format text report from the NDJSON sink."""
    import datetime

    try:
        from ubs_core.java_rules import REMEDIATION_MAP, SUMMARY_MAP
        summary_titles = dict(SUMMARY_MAP)
    except ImportError:
        REMEDIATION_MAP = {}
        summary_titles = {}
    summary_titles.update(_SUMMARY_TITLES)

    records = [
        json.loads(line)
        for line in Path(args.sink).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_rule: dict[str, list[dict]] = {}
    for rec in records:
        by_rule.setdefault(rec["rule"], []).append(rec)

    lines = [
        f"UBS module: java (contract v2) — {args.project or args.project_dir}",
        f"Files scanned: {len(files)}",
    ]
    category_order = {num: i for i, num in enumerate(sorted(_CATEGORY_SLUGS))}
    ordered_rules = sorted(
        by_rule,
        key=lambda rule: (
            category_order.get(_record_category(by_rule[rule][0]) or 99, 99),
            rule,
        ),
    )
    current_section = None
    emitted_subheaders: set[str] = set()
    for rule in ordered_rules:
        recs = by_rule[rule]
        category_num = _record_category(recs[0])
        section = _SECTION_HEADERS.get(category_num) if category_num is not None else None
        subheader = None
        if category_num is not None:
            for prefix, text in _SUBHEADERS.get(category_num, {}).items():
                if rule.startswith(prefix) or str(recs[0].get("category_id", "")).startswith(prefix):
                    subheader = text
        if section is not None and section != current_section:
            lines.append("")
            lines.append(section)
            current_section = section
        if subheader and subheader not in emitted_subheaders:
            lines.append(subheader)
            emitted_subheaders.add(subheader)
        if section is None and current_section != _SECTION_HEADERS[15]:
            # Legacy pack findings count in totals only (CURRENT_CATEGORY=0);
            # category 15 is their printed home (ubs-java.sh 3825-3831).
            lines.append("")
            lines.append(_SECTION_HEADERS[15])
            current_section = _SECTION_HEADERS[15]
        severity = recs[0]["severity"]
        title = summary_titles.get(rule, _finding_title(recs[0]))
        lines.append(f"[{severity}] {title} ({len(recs)} found) — {rule}")
        remediation = REMEDIATION_MAP.get(rule)
        if remediation:
            lines.append(f"    {remediation}")
        cap = 25 if rule.endswith("sql-injection") else 5
        for rec in recs[:cap]:
            lines.append(f"    {rec['path']}:{rec['line']}  {str(rec.get('message', ''))[:180]}")

    # Legacy category-15 staging note (info, count 0).
    if ast_ran and 15 not in _skip_set(args):
        lines.append("")
        lines.append(_SECTION_HEADERS[15])
        lines.append("[info] AST rule pack staged (0 found) — java.ast-grep.staged")
        lines.append("    Use --sarif-out=FILE or --json-out=FILE to save full ast-grep outputs")

    # Legacy "good" notes for subchecks whose category ran but produced no
    # records under that prefix. The Kotlin note only applies when .kt/.kts
    # files are in scope; the resource note only when the ast layer ran
    # (legacy emit_ast_rule_group had no ast-grep fallback here).
    skip = _skip_set(args)
    has_kotlin = any(path.suffix.lower() in {".kt", ".kts"} for path in files)
    for prefix, note, category in _GOOD_LINES:
        if category in skip:
            continue
        if prefix == "kotlin.narrowing." and not has_kotlin:
            continue
        if prefix == "java.resource." and not ast_ran:
            continue
        if any(rule.startswith(prefix) for rule in by_rule):
            continue
        lines.append(f"good: {note}")

    lines += [
        f"Critical issues: {counters['critical']}",
        f"Warning issues: {counters['warning']}",
        f"Info items: {counters['info']}",
        f"Report generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
    ]
    Path(args.text_out).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _skip_set(args) -> set[int]:
    return {int(part) for part in (args.skip or "").split(",") if part.strip().isdigit()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.java_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="base dir for relative sink paths")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--ast-rule-dir", default="", help="consolidated ast-grep rule dir (sgconfig-java.yml + manifest.json)")
    parser.add_argument("--text-out", default="", help="write the legacy-format text report here")
    parser.add_argument("--json-out", default="", help="write the UBS summary JSON document here")
    parser.add_argument("--project", default="", help="project path recorded in the json summary")
    parser.add_argument("--enable-new-analyzers", action="store_true",
                        help="run bead-D3 java guards (no legacy java counterpart)")
    parser.add_argument("--version", default="", help="module version recorded in the json summary")
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)

    patterns = load_patterns()
    ast_ran = False
    with open(args.sink, "w", encoding="utf-8") as sink:
        scan_patterns(patterns, files, sink, skip)
        run_analyzers(files, sink, skip,
                      project_dir=Path(args.project_dir) if args.project_dir else None,
                      enable_new=args.enable_new_analyzers)
        run_detectors(files, sink, skip)
        if args.ast_rule_dir:
            from ubs_core.java_ast import scan_all
            from ubs_core.java_rules import MARKER_SUPPRESSED_IDS, SEVERITY_MAP

            # Legacy calibration: ONLY the resource/async/isPresent ids are
            # counted — the rest of the pack is an informational dump.
            # Severity comes from SEVERITY_MAP (legacy emit-group maps), and
            # only the async ids get the parser's marker check.
            scan_all(
                Path(args.ast_rule_dir), files, sink,
                severity_overrides=dict(SEVERITY_MAP),
                count_only=set(SEVERITY_MAP),
                skip_categories=skip,
                marker_suppressed_ids=MARKER_SUPPRESSED_IDS,
                category_for_rule=lambda rule_id: _record_category({"rule": rule_id}),
            )
            ast_ran = True

    # The sink is the single source of truth: recount severities from it so
    # every layer (patterns, analyzers, detectors, ast) is reflected in totals.
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
        records = [json.loads(line) for line in Path(args.sink).read_text(encoding="utf-8").splitlines() if line.strip()]
        import datetime

        doc = {
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
        Path(args.json_out).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.text_out:
        _render_text(args, files, counters, ast_ran)

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns)}) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
