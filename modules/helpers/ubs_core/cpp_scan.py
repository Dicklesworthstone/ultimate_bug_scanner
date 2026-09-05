"""ubs_core.cpp_scan — contract-v2 orchestrator for the C/C++ module (bead 0xjg.9).

Replaces the legacy module's hundreds of process spawns with ONE python
process:

    python3 -m ubs_core.cpp_scan --files-from <nul-list> --sink <ndjson> \
        [--project-dir DIR] [--skip 1,2,3]

Layers, in order:
1. Pattern layer — regex categories aggregated from ubs_core.cpp_patterns.*
   (one Pattern per legacy rg pipeline; flat same-line ubs:ignore exclusion
   preserves the legacy count_lines semantics; the A7 statement-interval
   engine in the meta-runner postprocess adds the richer placements).
2. Detector layer — ubs_core.cpp_detectors.* ports of the legacy heredoc
   detectors (archive entry, weak randomness, header injection, outbound
   URL, async error coverage, header hygiene, quality markers, perf
   pipelines) and of the count-based CMake checks.
3. Analyzer layer — registered ubs_core analyzers for cpp
   (taint_cpp_traversal, taint_cpp_redirect, lifecycle_cpp).
   ``cpp.narrowing.*`` (bead D4) has no legacy cpp counterpart — it stays
   off unless --enable-new-analyzers, so v2 totals match legacy.
4. No ast-grep layer: the legacy pack's ast_count call sites are dead code
   (run_ast_once runs only in the text-mode tally section, after every
   category block), so legacy totals never include rule-pack hits — and
   neither does v2. See the NOTE in main().

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
    1: "memory-raii", 2: "exceptions", 3: "concurrency", 4: "modernization",
    5: "pointer-lifetime", 6: "numeric", 7: "undefined-behavior", 8: "headers",
    9: "stl", 10: "string-io", 11: "macros", 12: "cmake", 13: "code-quality",
    14: "perf", 15: "debug", 16: "resource-lifecycle",
}

# Legacy print_header titles (rendered before a section). The "N. " prefixes
# are part of the legacy output and manifest assertions key on them.
_SECTION_HEADERS = {
    1: "1. MEMORY & RAII",
    2: "2. EXCEPTIONS & ERROR HANDLING",
    3: "3. CONCURRENCY & ATOMICS",
    4: "4. MODERNIZATION (C++20+)",
    5: "5. POINTER & LIFETIME HAZARDS",
    6: "6. NUMERIC & ARITHMETIC PITFALLS",
    7: "7. UNDEFINED BEHAVIOR RISK ZONE",
    8: "8. HEADER & INCLUDE HYGIENE",
    9: "9. STL & ALGORITHMS",
    10: "10. STRING & I/O SAFETY",
    11: "11. MACROS & PREPROCESSOR TRAPS",
    12: "12. CMAKE & BUILD HYGIENE",
    13: "13. CODE QUALITY MARKERS",
    14: "14. PERFORMANCE & ALLOCATION PRESSURE",
    15: "15. TEST/DEBUG LEFTOVERS",
    16: "16. RESOURCE LIFECYCLE CORRELATION",
}

# Legacy print_subheader texts that manifest cases assert, keyed by the rule
# prefix they announce.
_SUBHEADERS = {
    3: {"cpp.async.": "Async error path coverage"},
    7: {
        "cpp.taint.path_traversal": "Request-derived filesystem paths",
        "cpp.taint.open_redirect": "Request-derived open redirects",
        "cpp.detector.header-injection": "Request-derived response headers",
        "cpp.detector.outbound-url": "Request-derived outbound HTTP URLs",
        "cpp.detector.archive-entry": "Archive extraction path traversal",
        "cpp.detector.weak-random": "Security-sensitive non-crypto randomness",
    },
    16: {"cpp.lifecycle.": "Resource lifecycle correlation"},
}


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity): the
    first entry whose count > min_count wins; when none match, the category
    reports nothing — mirroring the legacy `warning >15` ladders.
    file_regex restricts a pattern to matching file paths (legacy header-only
    rg loops). zero_finding reproduces the legacy `if [ "$count" -eq 0 ]`
    info fallbacks: a synthetic single record (no location) when the
    project-wide count is zero. thresholds=() means the pattern never emits
    per-line records (legacy printed only the zero fallback or a good note).
    """

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...] = ()
    case_insensitive: bool = False
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` post-filters
    file_regex: re.Pattern[str] | None = None  # legacy per-file-scope loops
    zero_finding: tuple[str, int, str] | None = None  # (severity, count, title)


def iter_matches(pattern: Pattern, text: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for matching lines.

    rg is line-scoped: a match can never span a newline, and every match
    attributes to its own line. Python finditer over the whole text would
    let a leading ``[^A-Za-z0-9_]``-style class consume the newline of the
    previous line and misattribute (or marker-suppress) the hit, so match
    line by line — exact count_lines/rg parity.
    """
    for line_no, line_text in enumerate(text.splitlines(), start=1):
        if MARKER in line_text:
            continue  # legacy count_lines drops marker lines from counts
        if pattern.exclude_regex is not None and pattern.exclude_regex.search(line_text):
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
        scoped = {p: t for p, t in texts.items()
                  if pattern.file_regex is None or pattern.file_regex.search(p.name)}
        hits: list[tuple[Path, int, str]] = []
        seen: set[tuple[Path, int]] = set()
        for path, text in scoped.items():
            for line_no, line_text in iter_matches(pattern, text):
                key = (path, line_no)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((path, line_no, line_text))
        if not hits:
            if pattern.zero_finding is not None:
                severity, _count, title = pattern.zero_finding
                counters[severity] = counters.get(severity, 0) + 1
                sink.write(json.dumps({
                    "rule": pattern.rule_id,
                    "category_id": f"cpp.{slug_for_category(pattern.category)}",
                    "path": "",
                    "line": 0,
                    "col": 1,
                    "severity": severity,
                    "message": title,
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")
            continue
        severity = resolve_severity(pattern, len(hits))
        if severity is None:
            continue
        counters[severity] = counters.get(severity, 0) + len(hits)
        for path, line_no, line_text in hits:
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"cpp.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "message": f"{pattern.title} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def load_patterns() -> list[Pattern]:
    """Aggregate PATTERNS from every ubs_core.cpp_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import cpp_patterns

    patterns: list[Pattern] = []
    for module_info in pkgutil.iter_modules(cpp_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"ubs_core.cpp_patterns.{module_info.name}")
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns


def _record_category(finding: dict) -> int | None:
    """Map a finding's rule id to its legacy category number."""
    rule = str(finding.get("rule", ""))
    if rule.startswith("cpp.taint."):
        return 7
    if rule.startswith("cpp.lifecycle."):
        return 16
    for num, slug in _CATEGORY_SLUGS.items():
        if rule.startswith(f"cpp.{slug}."):
            return num
    for prefix in ("cpp.async.", "cpp.detector.", "cpp.headers.",
                   "cpp.quality.", "cpp.perf."):
        if rule.startswith(prefix):
            # Detector families with fixed legacy homes.
            return {"cpp.async.": 3, "cpp.detector.": 7, "cpp.headers.": 8,
                    "cpp.quality.": 13, "cpp.perf.": 14}[prefix]
    return None


def run_detectors(files: Sequence[Path], sink, skip: set[int] | None = None) -> None:
    """Run ubs_core.cpp_detectors.* modules (legacy heredoc detector ports).

    Protocol (matches ubs_core.py_detectors): single-rule modules expose
    RULE_ID/CATEGORY/TITLE/SEVERITY/DESCRIPTION + ``find(files)`` yielding
    (path, line, col, detail); multi-rule modules expose ``RULES`` — tuples
    of (rule_id, category, title, severity, description) — and find(files)
    yielding (rule_id, path, line, col, detail).
    """
    import importlib
    import pkgutil

    from ubs_core import cpp_detectors

    for module_info in pkgutil.iter_modules(cpp_detectors.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.cpp_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.cpp_scan] detector module {module_info.name} failed: {exc}\n")
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
            category = int(getattr(module, "CATEGORY", 7))
            rule_id = str(getattr(module, "RULE_ID", f"cpp.detector.{module_info.name}"))
            specs = {rule_id: {
                "category": category,
                "title": str(getattr(module, "TITLE", rule_id)),
                "severity": str(getattr(module, "SEVERITY", "critical")),
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
                "category_id": f"cpp.{slug}",
                "path": str(path),
                "line": int(line_no),
                "col": int(col),
                "severity": spec["severity"],
                "message": f"{title} — {detail}"[:300] if detail else title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def run_analyzers(files: Sequence[Path], sink, skip: set[int] | None = None,
                  enable_new: bool = False) -> None:
    """Run registered cpp analyzers (taint traversal/redirect, lifecycle).

    ``cpp.narrowing.*`` (bead D4) has no legacy cpp counterpart — it stays
    off unless ``enable_new`` is set, so v2 totals match legacy.
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import analyzers_for_lang

    ctx = RunContext(lang="cpp", files=list(files))
    for analyzer in analyzers_for_lang("cpp"):
        if analyzer.layer == "narrowing" and not enable_new:
            continue
        for finding in analyzer.run(ctx):
            if skip and _record_category(finding) in skip:
                continue
            sink.write(json.dumps({
                "rule": finding.get("rule", ""),
                "category_id": finding.get("category_id", f"cpp.{_CATEGORY_SLUGS.get(_record_category(finding), 'undefined-behavior')}"),
                "path": finding.get("path", ""),
                "line": int(finding.get("line", 0) or 0),
                "col": int(finding.get("col", 1) or 1),
                "severity": finding.get("severity", "warning"),
                "message": finding.get("message", ""),
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def _finding_title(rec: dict) -> str:
    return str(rec.get("message", rec.get("rule", "")))


def _render_text(args, files: Sequence[Path], counters: dict[str, int]) -> None:
    """Render the legacy-format text report from the NDJSON sink."""
    import datetime

    records = [
        json.loads(line)
        for line in Path(args.sink).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_rule: dict[str, list[dict]] = {}
    for rec in records:
        by_rule.setdefault(rec["rule"], []).append(rec)

    lines = [
        f"UBS module: cpp (contract v2) — {args.project or args.project_dir}",
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
        for rec in recs[:5]:
            path = str(rec.get("path", ""))
            line_no = int(rec.get("line", 0) or 0)
            if path and line_no:
                lines.append(f"    {path}:{line_no}  {str(rec.get('message', ''))[:180]}")
            else:
                lines.append(f"    {str(rec.get('message', ''))[:180]}")

    # Legacy "good" notes for emit groups whose category produced no findings.
    categories_with_records = {
        _record_category(rec) for rec in records
    }
    good_notes = {
        2: "No throws in destructors",
        3: "No std::async usage detected",
        7: "No request-derived filesystem paths detected",
        16: "All tracked resource acquisitions have matching cleanups",
    }
    for num, note in good_notes.items():
        if num not in categories_with_records and num not in _skip_set(args):
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
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.cpp_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="base dir for relative sink paths")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--text-out", default="", help="write the legacy-format text report here")
    parser.add_argument("--json-out", default="", help="write the UBS summary JSON document here")
    parser.add_argument("--project", default="", help="project path recorded in the json summary")
    parser.add_argument("--version", default="", help="module version recorded in the json summary")
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--enable-new-analyzers", action="store_true",
                        help="run analyzers with no legacy counterpart (cpp.narrowing)")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)

    patterns = load_patterns()
    with open(args.sink, "w", encoding="utf-8") as sink:
        counters = scan_patterns(patterns, files, sink, skip)
        run_detectors(files, sink, skip)
        run_analyzers(files, sink, skip, enable_new=args.enable_new_analyzers)
        # No ast-grep layer: the legacy pack's ast_count call sites are dead
        # code (see the module docstring) — legacy totals never include
        # rule-pack hits, and neither does v2.

    # The sink is the single source of truth: recount severities from it so
    # every layer (patterns, detectors, analyzers) is reflected in totals.
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
        _render_text(args, files, counters)

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns)}) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
