"""ubs_core.js_scan — contract-v2 orchestrator for the JavaScript/TS module (bead 0xjg.4).

Replaces the legacy module's ~350-400 process spawns with ONE python process:

    python3 -m ubs_core.js_scan --files-from <nul-list> --sink <ndjson> \
        [--project-dir DIR] [--skip 1,2,3] [--ast-rule-dir DIR]

Layers, in order:
1. Pattern layer — regex categories aggregated from ubs_core.js_patterns.*
   (one Pattern per legacy rg pipeline; flat same-line ubs:ignore exclusion
   preserves the legacy count_lines semantics; the A7 statement-interval
   engine in the meta-runner postprocess adds the richer placements).
2. Analyzer layer — registered ubs_core analyzers for javascript
   (taint_js, guards_js, ctcompare_js) via their run(ctx).
3. ast-grep layer — the consolidated rule packs (≤ 3 `scan -c` invocations)
   via ubs_core.js_ast.scan_all; only SEVERITY_MAP ids are counted (the rest
   of the pack is an informational dump in legacy), async rules downgrade to
   info unless --fail-on-warning (GH #93 / ubs-js.sh 293-296).

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
    1: "null-undefined", 2: "equality", 3: "proto-object", 4: "type-coercion",
    5: "async", 6: "error-handling", 7: "security", 8: "function-scope",
    9: "parsing", 10: "control-flow", 11: "debug", 12: "perf",
    13: "vars", 14: "code-quality", 15: "regex", 16: "dom",
    17: "typescript", 18: "node", 19: "resource-lifecycle",
}


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity): the
    first entry whose count > min_count wins; when none match, the category
    reports nothing — mirroring the legacy `warning >15 / info >0` ladders.
    gate_regex expresses legacy project-wide preconditions (e.g. an Express
    import must exist somewhere before req.body patterns count).
    """

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...]
    case_insensitive: bool = False
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` post-filters
    gate_regex: re.Pattern[str] | None = None  # legacy project-wide precondition
    suppress_when_regex: re.Pattern[str] | None = None  # legacy project-wide count-comparison (e.g. parsers present -> silent)


def iter_matches(pattern: Pattern, text: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for matches, skipping excluded lines."""
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
    a category carries the same severity, so summed counters equal the
    legacy print_finding buckets. Patterns with gate_regex stay silent unless
    some file in the list satisfies the gate (legacy project-wide preconditions).

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
        if pattern.gate_regex is not None and not any(
            pattern.gate_regex.search(text) for text in texts.values()
        ):
            continue
        if pattern.suppress_when_regex is not None and any(
            pattern.suppress_when_regex.search(text) for text in texts.values()
        ):
            continue
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
                "category_id": f"js.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "message": f"{pattern.title} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def load_patterns() -> list[Pattern]:
    """Aggregate PATTERNS from every ubs_core.js_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import js_patterns

    patterns: list[Pattern] = []
    for module_info in pkgutil.iter_modules(js_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"ubs_core.js_patterns.{module_info.name}")
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns


def run_analyzers(files: Sequence[Path], sink) -> None:
    """Run registered javascript analyzers (taint, guards, ctcompare)."""
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import analyzers_for_lang

    ctx = RunContext(lang="javascript", files=list(files))
    for analyzer in analyzers_for_lang("javascript"):
        for finding in analyzer.run(ctx):
            sink.write(json.dumps({
                "rule": finding.get("rule", ""),
                "category_id": finding.get("category_id", "js.security"),
                "path": finding.get("path", ""),
                "line": int(finding.get("line", 0) or 0),
                "col": int(finding.get("col", 1) or 1),
                "severity": finding.get("severity", "warning"),
                "message": finding.get("message", ""),
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.js_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="base dir for relative sink paths")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--ast-rule-dir", default="", help="consolidated ast-grep rule dir (sgconfig-*.yml + manifest.json)")
    parser.add_argument("--text-out", default="", help="write the legacy-format text report here")
    parser.add_argument("--json-out", default="", help="write the UBS summary JSON document here")
    parser.add_argument("--project", default="", help="project path recorded in the json summary")
    parser.add_argument("--version", default="", help="module version recorded in the json summary")
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = {int(part) for part in args.skip.split(",") if part.strip().isdigit()}

    patterns = load_patterns()
    with open(args.sink, "w", encoding="utf-8") as sink:
        counters = scan_patterns(patterns, files, sink, skip)
        run_analyzers(files, sink)
        if args.ast_rule_dir:
            from ubs_core.js_ast import scan_all
            from ubs_core.js_rules import SEVERITY_MAP

            # Legacy calibration (emit_ast_rule_group): ONLY the ~19 mapped
            # ids are counted — the rest of the rule pack is an informational
            # dump. The declare -A severity map wins over YAML severity, and
            # every ASYNC_ERROR group rule downgrades to info unless
            # --fail-on-warning (ubs-js.sh 293-296 + 755-763).
            overrides: dict[str, str] = dict(SEVERITY_MAP)
            manifest_path = Path(args.ast_rule_dir) / "manifest.json"
            if manifest_path.is_file():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (ValueError, OSError):
                    pass
            if not args.fail_on_warning:
                for rid, severity in list(overrides.items()):
                    if rid.startswith("js.async."):
                        overrides[rid] = "info"
            ast_counters = scan_all(Path(args.ast_rule_dir), files, sink, overrides, count_only=set(SEVERITY_MAP))
            for key, value in ast_counters.items():
                counters[key] = counters.get(key, 0) + value

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
        import datetime

        try:
            from ubs_core.js_rules import REMEDIATION_MAP, SUMMARY_MAP
        except ImportError:
            SUMMARY_MAP, REMEDIATION_MAP = {}, {}
        SECTION_HEADERS = {7: "Lightweight taint analysis"}

        records = [
            json.loads(line)
            for line in Path(args.sink).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        by_rule: dict[str, list[dict]] = {}
        for rec in records:
            by_rule.setdefault(rec["rule"], []).append(rec)

        lines = [f"UBS module: js (contract v2) — {args.project or args.project_dir}",
                 f"Files scanned: {len(files)}"]
        ordered_rules = sorted(
            by_rule,
            key=lambda rule: (by_rule[rule][0].get("category_id", ""), rule),
        )
        current_section = None
        for rule in ordered_rules:
            recs = by_rule[rule]
            category_id = recs[0].get("category_id", "")
            section = None
            if category_id.startswith("js."):
                tail = category_id.split(".", 1)[1]
                for num, slug in _CATEGORY_SLUGS.items():
                    if tail == slug:
                        section = SECTION_HEADERS.get(num)
                        break
            if section is not None and section != current_section:
                lines.append("")
                lines.append(section)
                current_section = section
            severity = recs[0]["severity"]
            title = SUMMARY_MAP.get(rule, rule)
            lines.append(f"[{severity}] {title} ({len(recs)} found) — {rule}")
            remediation = REMEDIATION_MAP.get(rule)
            if remediation:
                lines.append(f"    {remediation}")
            for rec in recs[:5]:
                lines.append(f"    {rec['path']}:{rec['line']}  {rec['message'][:180]}")
        lines += [
            f"Critical issues: {counters['critical']}",
            f"Warning issues: {counters['warning']}",
            f"Info items: {counters['info']}",
            f"Report generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        ]
        Path(args.text_out).write_text("\n".join(lines) + "\n", encoding="utf-8")

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns)}) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
