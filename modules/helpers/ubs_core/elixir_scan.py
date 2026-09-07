r"""ubs_core.elixir_scan — contract-v2 orchestrator for the Elixir module (bead 0xjg.13).

One process replaces the legacy ~200-300 spawn scan in modules/ubs-elixir.sh:

  pattern table   ubs_core.elixir_patterns.*  — the rg pipelines (GREP_RN/RNI +
                  count_lines ladders), line-scoped and marker-filtered the way
                  rg never crosses newlines
  detectors       ubs_core.elixir_detectors.*  — verbatim ports of the module's
                  python heredocs (archive extraction, response header
                  injection, outbound URL SSRF, security randomness, hardcoded
                  secrets) plus the two filesystem checks (config/runtime.exs,
                  mix.lock)
  analyzers       the registered elixir analyzers (taint_elixir_traversal +
                  taint_elixir_redirect = the path-traversal / open-redirect
                  heredocs, bead A2). The guards_generic elixir spec and
                  narrowing_elixir have NO legacy elixir counterpart — both
                  stay off unless --enable-new-analyzers, so v2 totals match
                  legacy.
  ast layer       none: the elixir module has no ast-grep pack (contract.json
                  ships custom rules to "all modules except elixir").

Elixir-specific pattern semantics the shared engine expresses declaratively:
  components          legacy counted SUMS of separate rg pipelines (bare
                      rescue = ``rescue\s*$`` + ``rescue\s+_\s*->``, weak
                      crypto, SQL injection). One record per (component,
                      path, line) so the sink recount equals the legacy sum.
  diff_regexes        legacy NET counts (Task.async minus Task.await, File.open
                      minus close/stream, binary_to_term minus [:safe], unpinned
                      deps, fixed-vs-shell command execution). The record count
                      equals the NET number: the first N main-pattern hits.
  suppress_if         legacy conjunctions (`count > 50 AND guarded < 5`,
                      `async: true > 5 AND no SQL.Sandbox`). The pattern is
                      dropped when the guard regex counts >= cap.
  output filters      legacy `grep -v/-E` ran on rg's OUTPUT LINES (path:line:
                      code), so path-based filters like `test/|_test\.exs` and
                      text filters like `#\s*` are re-applied here against the
                      same `path:line:code` pseudo-line.
  gate                legacy IS_PHOENIX: category-5 patterns run only when a
                      mix.exs in the file list mentions `:phoenix`.
  zero_finding        legacy `if count -eq 0` info fallbacks (force_ssl).

Output contract (identical to py_scan/js_scan/ruby_scan): NDJSON findings sink
records {rule, category_id, path, line, col, severity, message, suppressed};
legacy text renderer for --text-out; UBS summary JSON for --json-out; the sink
is recounted for totals; exit 1 on criticals (or --fail-on-warning).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from ubs_core.registry import RunContext

MARKER = "ubs:ignore"

# Meta-runner category_slug_for elixir (ubs ~5138). All 16 categories have
# slugs; there is no ast-pack passthrough category.
_CATEGORY_SLUGS = {
    1: "pattern-matching", 2: "error-handling", 3: "process-otp",
    4: "security", 5: "phoenix", 6: "ecto", 7: "concurrency", 8: "io",
    9: "debug", 10: "perf", 11: "code-quality", 12: "config", 13: "testing",
    14: "mix", 15: "binary-safety", 16: "analyzers",
}

# Legacy print_header titles, in category order (rendered before a section).
# The record-less header bridge on the module side emits the same titles for
# non-skipped categories that produced no records.
_SECTION_HEADERS = {
    1: "1. PATTERN MATCHING & GUARDS",
    2: "2. ERROR HANDLING & EXCEPTIONS",
    3: "3. PROCESS & OTP LIFECYCLE",
    4: "4. SECURITY VULNERABILITIES",
    5: "5. PHOENIX-SPECIFIC ISSUES",
    6: "6. ECTO & DATABASE",
    7: "7. CONCURRENCY & MESSAGING",
    8: "8. I/O & RESOURCE LIFECYCLE",
    9: "9. DEBUGGING & PRODUCTION CODE",
    10: "10. PERFORMANCE & MEMORY",
    11: "11. CODE QUALITY MARKERS",
    12: "12. CONFIGURATION & ENVIRONMENT",
    13: "13. TESTING PATTERNS",
    14: "14. DEPENDENCY & MIX HYGIENE",
    15: "15. STRING & BINARY SAFETY",
    16: "16. MIX-POWERED EXTRA ANALYZERS",
}

# Rule id -> legacy print_finding title for analyzer findings that carry a
# bare message (pattern findings already embed "title — line").
_SUMMARY_TITLES: dict[str, str] = {
    "elixir.taint.request_path_traversal": "Request-derived path reaches file read/write/serve sink",
    "elixir.taint.open_redirect": "Unvalidated redirect from request data",
}


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity): the
    first entry whose count > min_count wins; when none match, the check
    reports nothing — mirroring the legacy `info >15` / elif ladders.
    Ladders with DIFFERENT titles (spawn >5 vs >0, raw >5 vs >0) split into
    sibling patterns sharing a regex; ``max_count`` caps a tier so exactly
    one sibling fires per count, like the legacy if/elif chain.

    components: legacy SUMS of separate pipelines (bare rescue, weak crypto).
    diff_regexes: legacy NET counts; severity resolves against the NET number
    and exactly NET records (a prefix of the main hits) join the sink.
    suppress_if: (regex, cap) — drop the whole check when that regex counts
    >= cap lines (legacy `guarded < 5` conjunctions).
    output_filter_regex / output_keep_regex: legacy `grep -v/-E` applied to
    the rg OUTPUT line `path:line:code` (path-based test/ filters included).
    file_regex: legacy single-file pipelines (mix.exs hygiene).
    gate: (path_regex, content_regex) — run only when a listed file matching
    path_regex has content matching content_regex (legacy IS_PHOENIX).
    zero_finding: (severity, title) synthetic single record when count == 0.
    """

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...] = ()
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` on line text
    components: tuple[re.Pattern[str], ...] = ()  # summed sub-counts
    diff_regexes: tuple[re.Pattern[str], ...] = ()  # NET-count subtrahends
    suppress_if: tuple[re.Pattern[str], int] | None = None  # (regex, cap)
    output_filter_regex: re.Pattern[str] | None = None  # `grep -v` on output line
    output_keep_regex: re.Pattern[str] | None = None  # `grep -E` keep filter
    file_regex: re.Pattern[str] | None = None  # legacy per-file-scope pipelines
    gate: tuple[re.Pattern[str], re.Pattern[str]] | None = None  # IS_PHOENIX
    zero_finding: tuple[str, str] | None = None  # (severity, title)
    max_count: int | None = None  # upper tier of a legacy if/elif ladder
    description: str = field(default="", compare=False)


def resolve_severity(pattern: Pattern, count: int) -> str | None:
    for min_count, severity in pattern.thresholds:
        if count > min_count:
            return severity
    return None


def active_tier(pattern: Pattern, count: int) -> str | None:
    """Resolve one legacy if/elif ladder tier: this tier's severity, else None."""
    if pattern.max_count is not None and count > pattern.max_count:
        return None
    return resolve_severity(pattern, count)


def output_line(path: Path, line_no: int, line_text: str) -> str:
    """The rg OUTPUT line shape the legacy `grep -v/-E` filters ran against."""
    return f"{path}:{line_no}:{line_text}"


def distinct_lines(regex: re.Pattern[str], texts: dict[Path, str],
                   pattern: Pattern, apply_output_filters: bool) -> list[tuple[Path, int, str]]:
    """Distinct matching lines for one regex, rg/count_lines parity.

    Line-scoped matching (rg never crosses newlines), `ubs:ignore` marker
    lines dropped (legacy count_lines), legacy output-line filters applied
    when requested.
    """
    hits: list[tuple[Path, int, str]] = []
    for path, text in texts.items():
        if pattern.file_regex is not None and not pattern.file_regex.search(str(path)):
            continue
        for line_no, line_text in enumerate(text.splitlines(), start=1):
            if MARKER in line_text:
                continue
            if apply_output_filters:
                out_line = output_line(path, line_no, line_text)
                if pattern.output_filter_regex is not None and pattern.output_filter_regex.search(out_line):
                    continue
                if pattern.output_keep_regex is not None and not pattern.output_keep_regex.search(out_line):
                    continue
            if regex.search(line_text):
                hits.append((path, line_no, line_text.strip()[:240]))
    return hits


def count_regex(regex: re.Pattern[str], texts: dict[Path, str], file_regex) -> int:
    """Project-wide distinct-line count for guard/diff regexes (no filters)."""
    total = 0
    for path, text in texts.items():
        if file_regex is not None and not file_regex.search(str(path)):
            continue
        seen: set[int] = set()
        for line_no, line_text in enumerate(text.splitlines(), start=1):
            if MARKER in line_text or line_no in seen:
                continue
            if regex.search(line_text):
                seen.add(line_no)
        total += len(seen)
    return total


def pattern_hits(pattern: Pattern, texts: dict[Path, str]) -> list[tuple[Path, int, str]]:
    """The main-pattern hit list: components sum, plain patterns dedupe."""
    hits: list[tuple[Path, int, str]] = []
    if pattern.components:
        for component in pattern.components:
            hits.extend(distinct_lines(component, texts, pattern, apply_output_filters=True))
    else:
        hits.extend(distinct_lines(pattern.regex, texts, pattern, apply_output_filters=True))
    return hits


def scan_patterns(patterns: Sequence[Pattern], files: Sequence[Path], sink,
                  skip: set[int], prefilter: Any = None) -> dict[str, int]:
    """Run every pattern over the file list, writing sink records.

    Legacy parity semantics: counts are DISTINCT MATCHING LINES across the
    file list, severity resolves ONCE per pattern from that project-wide
    count, and diff/suppress guards re-run their own pipelines exactly like
    the legacy shell did.
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
        if pattern.gate is not None:
            gate_path_re, gate_content_re = pattern.gate
            if not any(
                gate_path_re.search(str(path)) and gate_content_re.search(text)
                for path, text in texts.items()
            ):
                continue
        if pattern.suppress_if is not None:
            guard_re, cap = pattern.suppress_if
            if count_regex(guard_re, texts, pattern.file_regex) >= cap:
                continue

        target_texts = texts
        if prefilter is not None and not prefilter.is_bypass and pattern.zero_finding is None:
            target_texts = {p: txt for p, txt in texts.items() if pattern.rule_id in prefilter.candidate_rules_for(p)}
            if not target_texts:
                continue

        hits = pattern_hits(pattern, target_texts)
        if not hits:
            if pattern.zero_finding is not None:
                severity, title = pattern.zero_finding
                counters[severity] = counters.get(severity, 0) + 1
                sink.write(json.dumps({
                    "rule": pattern.rule_id,
                    "category_id": f"elixir.{slug_for_category(pattern.category)}",
                    "path": "",
                    "line": 0,
                    "col": 1,
                    "severity": severity,
                    "message": title,
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")
            continue
        count = len(hits)
        if pattern.diff_regexes:
            for diff_re in pattern.diff_regexes:
                count -= count_regex(diff_re, texts, pattern.file_regex)
        severity = active_tier(pattern, count)
        if severity is None:
            continue
        counters[severity] = counters.get(severity, 0) + count
        for path, line_no, line_text in hits[:count]:
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"elixir.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "message": f"{pattern.title} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def load_patterns() -> tuple[list[Pattern], int]:
    """Aggregate PATTERNS from every ubs_core.elixir_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import elixir_patterns

    patterns: list[Pattern] = []
    failures = 0
    for module_info in pkgutil.iter_modules(elixir_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.elixir_patterns.{module_info.name}")
        except Exception as exc:  # a broken pattern module must not kill the scan
            failures += 1
            sys.stderr.write(f"[ubs_core.elixir_scan] pattern module {module_info.name} failed: {exc}\n")
            continue
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns, failures


def _record_category(finding: dict) -> int | None:
    """Map a finding's rule id to its legacy category number."""
    rule = str(finding.get("rule", ""))
    category_id = str(finding.get("category_id", ""))
    # Registry analyzers (A2) — legacy heredocs ran inside category 4.
    if rule.startswith("elixir.taint."):
        return 4
    # category_id is authoritative for pattern/detector records.
    for num, slug in _CATEGORY_SLUGS.items():
        if category_id == f"elixir.{slug}":
            return num
    return None


def run_analyzers(files: Sequence[Path], sink, skip: set[int] | None = None,
                  enable_new: bool = False, prefilter: Any = None) -> None:
    """Run registered elixir analyzers (the two taint heredoc ports).

    ``guards_elixir`` (guards_generic) and ``narrowing_elixir`` have no legacy
    elixir counterpart — they stay off unless ``enable_new`` is set, so v2
    totals match legacy.
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import analyzers_for_lang

    for analyzer in analyzers_for_lang("elixir"):
        if analyzer.layer in ("narrowing", "guards") and not enable_new:
            continue
        target_files = files
        if prefilter is not None and not prefilter.is_bypass:
            target_files = prefilter.filter_files_for_analyzer(analyzer.name, files)
        if not target_files:
            continue
        ctx = RunContext(lang="elixir", files=list(target_files))
        for finding in analyzer.run(ctx):
            rule = finding.get("rule", "")
            if skip and _record_category(finding) in skip:
                continue
            sink.write(json.dumps({
                "rule": rule,
                "category_id": finding.get("category_id", "elixir.security"),
                "path": finding.get("path", ""),
                "line": int(finding.get("line", 0) or 0),
                "col": int(finding.get("col", 1) or 1),
                "severity": finding.get("severity", "warning"),
                "message": finding.get("message", ""),
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def run_detectors(files: Sequence[Path], sink, skip: set[int] | None = None) -> None:
    """Run ubs_core.elixir_detectors.* modules (legacy heredoc detector ports).

    Protocol (single-rule modules): RULE_ID, CATEGORY, TITLE, SEVERITY,
    DESCRIPTION and ``find(files)`` yielding (path, line, col, detail).
    """
    import importlib
    import pkgutil

    from ubs_core import elixir_detectors

    for module_info in pkgutil.iter_modules(elixir_detectors.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.elixir_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.elixir_scan] detector module {module_info.name} failed: {exc}\n")
            continue
        find = getattr(module, "find", None)
        if find is None:
            continue
        category = int(getattr(module, "CATEGORY", 4))
        rule_id = str(getattr(module, "RULE_ID", f"elixir.cat{category}.{module_info.name}"))
        spec = {
            "category": category,
            "title": str(getattr(module, "TITLE", rule_id)),
            "severity": str(getattr(module, "SEVERITY", "critical")),
            "description": str(getattr(module, "DESCRIPTION", "")),
        }
        if skip and spec["category"] in skip:
            continue
        for hit in find(files):
            path, line_no, col, detail = hit[0], hit[1], hit[2], hit[3]
            slug = slug_for_category(spec["category"])
            title = spec["title"]
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"elixir.{slug}",
                "path": str(path),
                "line": int(line_no),
                "col": int(col),
                "severity": spec["severity"],
                "message": f"{title} — {detail}"[:300] if detail else title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def _finding_title(rule: str, count: int, message: str) -> str:
    if rule in _SUMMARY_TITLES:
        return _SUMMARY_TITLES[rule]
    if message:
        return message
    return rule


def _sample_code(path: str, line_no: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh, 1):
                if i == line_no:
                    return line.strip()[:200]
    except OSError:
        pass
    return ""


def _legacy_report(records: list[dict], version: str) -> dict:
    """Legacy --report-json payload shape (#64): per-rule aggregated findings
    with severity/count/title/description and up to 3 code samples."""
    by_rule: dict[str, list[dict]] = {}
    for rec in records:
        by_rule.setdefault(rec.get("rule", ""), []).append(rec)
    findings = []
    for rule, recs in by_rule.items():
        first = recs[0]
        samples = []
        for rec in recs[:3]:
            samples.append({
                "file": rec.get("path", ""),
                "line": int(rec.get("line", 0) or 0),
                "code": _sample_code(rec.get("path", ""), int(rec.get("line", 0) or 0)),
            })
        findings.append({
            "severity": first.get("severity", "info"),
            "count": len(recs),
            "title": _finding_title(rule, len(recs), str(first.get("message", ""))),
            "description": "",
            "samples": samples,
        })
    return {"version": version, "findings": findings}


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
        f"UBS module: elixir (contract v2) — {args.project or args.project_dir}",
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
    for rule in ordered_rules:
        recs = by_rule[rule]
        category_num = _record_category(recs[0])
        section = _SECTION_HEADERS.get(category_num) if category_num is not None else None
        if section is not None and section != current_section:
            lines.append("")
            lines.append(section)
            current_section = section
        severity = recs[0]["severity"]
        title = _finding_title(rule, len(recs), str(recs[0].get("message", "")))
        lines.append(f"[{severity}] {title} ({len(recs)} found) — {rule}")
        for rec in recs[:5]:
            lines.append(f"    {rec['path']}:{rec['line']}  {str(rec.get('message', ''))[:180]}")

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
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.elixir_scan")
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
                        help="run analyzers with no legacy counterpart (guards_elixir, narrowing_elixir)")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)

    patterns, _failures = load_patterns()

    from ubs_core.prefilter import build_prefilter_index, run_prefilter
    from ubs_core.registry import analyzers_for_lang

    elixir_analyzers = [a.name for a in analyzers_for_lang("elixir")]
    prefilter_index = build_prefilter_index(
        ast_rules=[],
        patterns=patterns,
        analyzers=elixir_analyzers,
        lang="elixir",
    )
    prefilter_res = run_prefilter(files, prefilter_index)

    prefilter_file = os.environ.get("UBS_PREFILTER_FILE")
    if prefilter_file:
        try:
            Path(prefilter_file).write_text(json.dumps(prefilter_res.to_dict()), encoding="utf-8")
        except OSError:
            pass

    with open(args.sink, "w", encoding="utf-8") as sink:
        scan_patterns(patterns, files, sink, skip, prefilter=prefilter_res)
        run_detectors(files, sink, skip)
        run_analyzers(files, sink, skip, enable_new=args.enable_new_analyzers, prefilter=prefilter_res)

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
            "language": "elixir",
            "project": args.project or args.project_dir,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": len(files),
            "critical": counters["critical"],
            "warning": counters["warning"],
            "info": counters["info"],
            "version": args.version,
            "status": "ok",
            "findings": records,
            # Legacy issue-64 payload (title + samples) carried inside the
            # module summary so the combined JSON keeps per-finding samples.
            "report": _legacy_report(records, args.version),
        }
        if os.environ.get("UBS_PROFILE") == "1":
            doc["profile"] = {
                "files_considered": len(files),
                "files_after_prefilter": prefilter_res.files_after_prefilter,
            }
        Path(args.json_out).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.text_out:
        _render_text(args, files, counters)

    sys.stderr.write(json.dumps({"counters": counters, "patterns": len(patterns)}) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
