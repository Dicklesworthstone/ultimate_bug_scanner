"""ubs_core.js_scan — contract-v2 orchestrator for the JavaScript/TS module (bead 0xjg.4).

Replaces the legacy module's ~350-400 process spawns with ONE python process:

    python3 -m ubs_core js-scan --files-from <nul-list> --sink <ndjson> \
        [--project-dir DIR] [--skip 1,2,3] [--lang js]

Layers, in order:
1. Pattern layer — regex categories aggregated from ubs_core.js_patterns.*
   (one Pattern per legacy rg pipeline; flat same-line ubs:ignore exclusion
   preserves the legacy count_lines semantics; the A7 statement-interval
   engine in the meta-runner postprocess adds the richer placements).
2. Analyzer layer — registered ubs_core analyzers for javascript
   (taint_js, guards_js, ctcompare_js) via their run(ctx).
3. ast-grep layer — the consolidated rule packs (≤ 3 `scan -c` invocations)
   are executed by the shell wrapper and appended to the same sink; this
   module only defines the sink record shape.

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


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds."""

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...]
    case_insensitive: bool = False
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` post-filters


def iter_matches(pattern: Pattern, text: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for matches, skipping marker lines."""
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



def iter_matches(pattern: Pattern, text: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for matches, skipping marker lines."""
    for match in pattern.regex.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.start())
        if line_end == -1:
            line_end = len(text)
        line_text = text[line_start:line_end]
        if MARKER in line_text:
            continue  # legacy count_lines drops marker lines from counts
        yield line_no, line_text.strip()[:240]


def resolve_severity(pattern: Pattern, count: int) -> str | None:
    for min_count, severity in pattern.thresholds:
        if count > min_count:
            return severity
    return None


def scan_patterns(patterns: Sequence[Pattern], files: Sequence[Path], sink, skip: set[int]) -> dict[str, int]:
    """Run every pattern over the file list, writing sink records.

    Returns severity counters ({"critical": n, "warning": n, "info": n}).
    """
    counters = {"critical": 0, "warning": 0, "info": 0}
    active = [p for p in patterns if p.category not in skip]
    if not active:
        return counters
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in active:
            hits = list(iter_matches(pattern, text))
            count = len(hits)
            if not count:
                continue
            severity = resolve_severity(pattern, count)
            if severity is None:
                continue
            counters[severity] = counters.get(severity, 0) + count
            for line_no, line_text in hits:
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


_CATEGORY_SLUGS = {
    1: "null-undefined", 2: "equality", 3: "proto-object", 4: "type-coercion",
    5: "async", 6: "error-handling", 7: "security", 8: "function-scope",
    9: "parsing", 10: "control-flow", 11: "debug", 12: "perf",
    13: "vars", 14: "code-quality", 15: "regex", 16: "dom",
    17: "typescript", 18: "node", 19: "resource-lifecycle",
}


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


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
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core js-scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="base dir for relative sink paths")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
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

    sys.stdout.write(json.dumps({"counters": counters, "patterns": len(patterns)}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
