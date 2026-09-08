"""ubs_core.ruby_scan — contract-v2 orchestrator for the Ruby module (bead 0xjg.10).

One process replaces the legacy ~250-400 spawn scan in modules/ubs-ruby.sh:

  pattern table   ubs_core.ruby_patterns.*  — the rg pipelines (GREP_RN/RNI +
                  count_lines ladders), including the grep -A3 intent windows
                  as bounded cross-line regexes (py_patterns.flow precedent)
  detectors       ubs_core.ruby_detectors.*  — ports of the module's python
                  heredocs (archive extraction, open redirect, response header
                  injection, security randomness, JSON.parse/rescue, the
                  frozen_string_literal pragma walk)
  analyzers       the registered ruby analyzers (taint_ruby_traversal +
                  taint_ruby_url = the path-traversal / outbound-URL heredocs;
                  lifecycle_ruby = helpers/resource_lifecycle_ruby.py;
                  guards_ruby = the cat-1 deep-chain guard analysis). The
                  narrowing layer has no legacy ruby counterpart and stays off
                  unless --enable-new-analyzers.
  ast layer       ubs_core.ruby_rules.generate + ruby_ast.scan_all. Legacy
                  ruby NEVER converted rule-pack output into counters (cat 18
                  only wrote --json-out/--sarif-out passthrough files), so
                  exactly ONE pack rule reaches the sink: the category-16
                  async rule that run_async_error_checks ran via its own
                  `scan -r` (CATEGORY_MAP gates it under --skip).

Output contract (identical to py_scan/js_scan): NDJSON findings sink records
{rule, category_id, path, line, col, severity, message, suppressed}; legacy
text renderer for --text-out; UBS summary JSON for --json-out; the sink is
recounted for totals; exit 1 on criticals (or --fail-on-warning).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.registry import RunContext

MARKER = "ubs:ignore"

# Meta-runner category_slug_for ruby (ubs 4883-4904). Category 18 (the
# ast-grep rule pack) has NO slug — its findings never carry a category_id.
_CATEGORY_SLUGS = {
    1: "nil", 2: "numeric", 3: "collections", 4: "comparison",
    5: "exceptions", 6: "security", 7: "shell", 8: "io",
    9: "parsing", 10: "control-flow", 11: "debug", 12: "perf",
    13: "variables", 14: "code-quality", 15: "regex", 16: "concurrency",
    17: "rails", 19: "bundler",
}

# Legacy print_header titles, in category order (rendered before a section).
# Cat 18's header is not numbered in legacy (`print_header "AST-GREP RULE
# PACK FINDINGS"`) and cat 19 rides the module-side bundler bridge, but both
# stay here so the record-less header bridge can emit them in order.
_SECTION_HEADERS = {
    1: "1. NIL / DEFENSIVE PROGRAMMING",
    2: "2. NUMERIC / ARITHMETIC PITFALLS",
    3: "3. COLLECTION SAFETY",
    4: "4. COMPARISON & IDIOMS",
    5: "5. EXCEPTIONS & ERROR HANDLING",
    6: "6. SECURITY VULNERABILITIES",
    7: "7. SHELL / SUBPROCESS SAFETY",
    8: "8. I/O & RESOURCE LIFECYCLE CORRELATION",
    9: "9. PARSING & TYPE CONVERSION BUGS",
    10: "10. CONTROL FLOW GOTCHAS",
    11: "11. DEBUGGING & PRODUCTION CODE",
    12: "12. PERFORMANCE & MEMORY",
    13: "13. VARIABLE & SCOPE",
    14: "14. CODE QUALITY MARKERS",
    15: "15. REGEX & STRING SAFETY",
    16: "16. CONCURRENCY & PARALLELISM",
    17: "17. RUBY/RAILS PRACTICALS",
    18: "AST-GREP RULE PACK FINDINGS",
    19: "19. BUNDLER-POWERED EXTRA ANALYZERS",
}

# Legacy print_subheader texts that manifest cases assert, keyed by the rule
# prefix they announce.
_SUBHEADERS = {
    8: {"ruby.lifecycle.": "Resource lifecycle correlation"},
    16: {"ruby.async.thread-no-rescue": "Async error path coverage"},
}

# Rule id -> legacy print_finding title for analyzer/detector findings that
# carry their own message. Pack findings embed "id: message" in the sink
# record already; pattern findings carry pattern titles.
_SUMMARY_TITLES: dict[str, str] = {
    # RESOURCE_LIFECYCLE_SUMMARY (ubs-ruby.sh 237-241)
    "ruby.lifecycle.file_handle": "File handles opened without close or block",
    "ruby.lifecycle.thread_join": "Ruby threads started without join",
    "ruby.lifecycle.http_session": "Net::HTTP sessions missing finish()",
    # taint_ruby_traversal / taint_ruby_url (verbatim heredoc ports, bead A2)
    "ruby.taint.path_traversal": "Request-derived path reaches file read/write/serve sink",
    "ruby.taint.outbound_url": "Request-derived URL reaches outbound HTTP client",
    # run_async_error_checks (ASYNC_ERROR_SUMMARY)
    "ruby.async.thread-no-rescue": "Thread.new block lacks rescue",
}

# Legacy severity table the shell applied on top of the lifecycle helper's
# records (RESOURCE_LIFECYCLE_SEVERITY, ubs-ruby.sh 225-229); lifecycle_ruby
# itself always yields "warning".
_LIFECYCLE_SEVERITY = {
    "ruby.lifecycle.file_handle": "critical",
    "ruby.lifecycle.thread_join": "warning",
    "ruby.lifecycle.http_session": "warning",
}

# Cat 1 deep-chain ladder: legacy titled the SAME info bucket by size
# ("Fragile deep chaining" >15 chains, else "Some deep chaining detected").
_DEEP_CHAIN_RULE = "ruby.guards.unguarded"


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat{category}")


@dataclass(frozen=True)
class Pattern:
    """One legacy rg pipeline: a category-scoped regex with count thresholds.

    thresholds is a descending list of (min_count_exclusive, severity): the
    first entry whose count > min_count wins; when none match, the category
    reports nothing — mirroring the legacy `warning >25 / info >0` ladders.
    exclude_regex expresses legacy `grep -v` post-filters (applied to the
    matched line's text); gate_regex / suppress_when_regex are legacy
    project-wide preconditions and silencers.

    Multi-tier ladders with DIFFERENT titles (division >25 vs info, puts
    >40 vs >15, globals >10 vs >0, tech debt >20/>10/>0) split into sibling
    patterns sharing a regex; ``max_count`` caps a tier so exactly one
    sibling fires per count, like the legacy if/elif chain.

    ``components`` (category 14): legacy summed FIVE separate rg counts
    (TODO/FIXME/HACK/XXX). A line matching several markers must count once
    per marker, which a single alternation cannot express — with components,
    each sub-regex contributes its own distinct-line count and one record per
    (component, path, line), so the sink recount equals the legacy sum.
    """

    category: int
    rule_id: str
    title: str
    regex: re.Pattern[str]
    thresholds: tuple[tuple[int, str], ...]
    case_insensitive: bool = False
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` post-filters
    gate_regex: re.Pattern[str] | None = None  # legacy project-wide precondition
    suppress_when_regex: re.Pattern[str] | None = None  # legacy project-wide silencer
    max_count: int | None = None  # upper tier of a legacy if/elif ladder
    components: tuple[re.Pattern[str], ...] = ()  # summed sub-counts (cat 14)


def line_text_of(text: str, pos: int) -> str:
    """The full line containing ``pos`` (used for marker/exclude checks)."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


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


def line_text_of(text: str, pos: int) -> str:
    """The full line containing ``pos`` (used for marker/exclude checks)."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def iter_matches(regex: re.Pattern[str], text: str, exclude_regex: re.Pattern[str] | None = None) -> Iterable[tuple[int, str]]:
    """Yield (line_number, line_text) for distinct matching lines.

    Legacy parity: rg prints each matching line once (deduped here per line),
    and count_lines drops any line carrying a `ubs:ignore` marker before the
    awk count; exclude_regex re-applies the legacy `grep -v` post-filters.
    """
    seen: set[int] = set()
    for match in regex.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        if line_no in seen:
            continue
        seen.add(line_no)
        line_text = line_text_of(text, match.start())
        if MARKER in line_text:
            continue
        if exclude_regex is not None and exclude_regex.search(line_text):
            continue
        yield line_no, line_text.strip()[:240]


def resolve_severity(pattern: Pattern, count: int) -> str | None:
    for min_count, severity in pattern.thresholds:
        if count > min_count:
            return severity
    return None


def scan_patterns(
    patterns: Sequence[Pattern],
    files: Sequence[Path],
    sink,
    skip: set[int],
    prefilter: Any = None,
) -> dict[str, int]:
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
        if pattern.gate_regex is not None and not any(
            pattern.gate_regex.search(text) for text in texts.values()
        ):
            continue
        if pattern.suppress_when_regex is not None and any(
            pattern.suppress_when_regex.search(text) for text in texts.values()
        ):
            continue
        hits: list[tuple[Path, int, str]] = []
        if pattern.components:
            # One record per (component, path, line): the sink recount must
            # equal the legacy per-marker COUNT sum, not the distinct-line sum.
            for component in pattern.components:
                for path, text in texts.items():
                    if prefilter is not None and pattern.rule_id not in prefilter.candidate_rules_for(path):
                        continue
                    for line_no, line_text in iter_matches(component, text, pattern.exclude_regex):
                        hits.append((path, line_no, line_text))
        else:
            for path, text in texts.items():
                if prefilter is not None and pattern.rule_id not in prefilter.candidate_rules_for(path):
                    continue
                for line_no, line_text in iter_matches(pattern.regex, text, pattern.exclude_regex):
                    hits.append((path, line_no, line_text))
        if not hits:
            continue
        severity = active_tier(pattern, len(hits))
        if severity is None:
            continue
        counters[severity] = counters.get(severity, 0) + len(hits)
        for path, line_no, line_text in hits:
            sink.write(json.dumps({
                "rule": pattern.rule_id,
                "category_id": f"ruby.{slug_for_category(pattern.category)}",
                "path": str(path),
                "line": line_no,
                "col": 1,
                "severity": severity,
                "message": f"{pattern.title} — {line_text}",
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def load_patterns() -> list[Pattern]:
    """Aggregate PATTERNS from every ubs_core.ruby_patterns.* module."""
    import importlib
    import pkgutil

    from ubs_core import ruby_patterns

    patterns: list[Pattern] = []
    for module_info in pkgutil.iter_modules(ruby_patterns.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.ruby_patterns.{module_info.name}")
        except Exception as exc:  # a broken pattern module must not kill the scan
            sys.stderr.write(f"[ubs_core.ruby_scan] pattern module {module_info.name} failed: {exc}\n")
            continue
        patterns.extend(getattr(module, "PATTERNS", []))
    return patterns


def _record_category(finding: dict) -> int | None:
    """Map a finding's rule id to its legacy category number."""
    rule = str(finding.get("rule", ""))
    category_id = str(finding.get("category_id", ""))
    # Registry analyzers (A2) — legacy heredocs ran inside their categories.
    if rule.startswith("ruby.taint."):
        return 6
    if rule.startswith("ruby.lifecycle."):
        return 8
    if rule.startswith("ruby.guards."):
        return 1
    # category_id is authoritative for pattern/detector records.
    for num, slug in _CATEGORY_SLUGS.items():
        if category_id == f"ruby.{slug}":
            return num
    # The one category-gated pack rule (run_async_error_checks, cat 16).
    if rule == "ruby.async.thread-no-rescue":
        return 16
    return None  # ast-pack rules count in totals only (legacy cat 18 passthrough)


def run_analyzers(
    files: Sequence[Path],
    sink,
    skip: set[int] | None = None,
    enable_new: bool = False,
    prefilter: Any = None,
) -> None:
    """Run registered ruby analyzers (taint, lifecycle, guards).

    ``ruby.narrowing.*`` (bead D4) has no legacy ruby counterpart — it stays
    off unless ``enable_new`` is set, so v2 totals match legacy. Guarded deep
    chains (ruby.guards.guarded) are dropped: legacy's ast-grep path counts
    only unguarded chains and reports guarded ones as a counter-less good
    note, so keeping them would inflate info totals.
    """
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import analyzers_for_lang

    for analyzer in analyzers_for_lang("ruby"):
        if analyzer.layer == "narrowing" and not enable_new:
            continue
        if prefilter is not None:
            target_files = prefilter.filter_files_for_analyzer(analyzer.name, files)
        else:
            target_files = list(files)
        if not target_files:
            continue
        ctx = RunContext(lang="ruby", files=target_files)
        for finding in analyzer.run(ctx):
            rule = finding.get("rule", "")
            if rule == "ruby.guards.guarded":
                continue
            if skip and _record_category(finding) in skip:
                continue
            severity = finding.get("severity", "warning")
            if rule in _LIFECYCLE_SEVERITY:
                severity = _LIFECYCLE_SEVERITY[rule]
            sink.write(json.dumps({
                "rule": rule,
                "category_id": finding.get("category_id", "ruby.security"),
                "path": finding.get("path", ""),
                "line": int(finding.get("line", 0) or 0),
                "col": int(finding.get("col", 1) or 1),
                "severity": severity,
                "message": finding.get("message", ""),
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def run_detectors(files: Sequence[Path], sink, skip: set[int] | None = None) -> None:
    """Run ubs_core.ruby_detectors.* modules (legacy heredoc detector ports).

    Protocol (single-rule modules): RULE_ID, CATEGORY, TITLE, SEVERITY,
    DESCRIPTION and ``find(files)`` yielding (path, line, col, detail).
    """
    import importlib
    import pkgutil

    from ubs_core import ruby_detectors

    for module_info in pkgutil.iter_modules(ruby_detectors.__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"ubs_core.ruby_detectors.{module_info.name}")
        except Exception as exc:  # legacy heredoc failures degraded gracefully too
            sys.stderr.write(f"[ubs_core.ruby_scan] detector module {module_info.name} failed: {exc}\n")
            continue
        find = getattr(module, "find", None)
        if find is None:
            continue
        category = int(getattr(module, "CATEGORY", 6))
        rule_id = str(getattr(module, "RULE_ID", f"ruby.cat{category}.{module_info.name}"))
        spec = {
            "category": category,
            "title": str(getattr(module, "TITLE", rule_id)),
            "severity": str(getattr(module, "SEVERITY", "critical")),
            "description": str(getattr(module, "DESCRIPTION", "")),
        }
        if skip and spec["category"] in skip:
            continue
        for hit in find(files):
            if len(hit) == 4:
                path, line_no, col, detail = hit
            else:
                path, line_no, col, detail = hit[0], hit[1], hit[2], hit[3]
            slug = slug_for_category(spec["category"])
            title = spec["title"]
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"ruby.{slug}",
                "path": str(path),
                "line": int(line_no),
                "col": int(col),
                "severity": spec["severity"],
                "message": f"{title} — {detail}"[:300] if detail else title,
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def _finding_title(rule: str, count: int, message: str) -> str:
    if rule == _DEEP_CHAIN_RULE:
        return "Fragile deep chaining" if count > 15 else "Some deep chaining detected"
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
        f"UBS module: ruby (contract v2) — {args.project or args.project_dir}",
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
        if section is None and current_section != "AST-GREP RULE PACK FINDINGS":
            # Legacy passthrough header; only async pack records are
            # classified (cat 16), so unclassified pack rules would land here.
            lines.append("")
            lines.append("AST-GREP RULE PACK FINDINGS")
            current_section = "AST-GREP RULE PACK FINDINGS"
        severity = recs[0]["severity"]
        title = _finding_title(rule, len(recs), str(recs[0].get("message", "")))
        lines.append(f"[{severity}] {title} ({len(recs)} found) — {rule}")
        for rec in recs[:5]:
            lines.append(f"    {rec['path']}:{rec['line']}  {str(rec.get('message', ''))[:180]}")

    # Legacy "good" notes for groups whose category produced no findings.
    categories_with_records = {
        _record_category(rec) for rec in records
    }
    skip = _skip_set(args)
    good_notes = {
        8: "All tracked resource acquisitions have matching cleanups",
        16: "Thread bodies appear to handle exceptions",
        1: "No nil equality comparisons",
    }
    for num, note in good_notes.items():
        if num not in categories_with_records and num not in skip:
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
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.ruby_scan")
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
    parser.add_argument("--enable-new-analyzers", action="store_true",
                        help="run analyzers with no legacy counterpart (ruby.narrowing)")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]
    skip = _skip_set(args)

    patterns = load_patterns()

    from ubs_core.cache import CapturingSink, ScanCache

    cache = ScanCache(
        lang="ruby",
        project_dir=args.project_dir or args.project or ".",
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"new_analyzers={args.enable_new_analyzers}",
    )
    cached_findings, files_to_scan = cache.partition_files(files)

    capturing_sink = None
    if files_to_scan:
        from ubs_core.ruby_rules import _RULES
        from ubs_core.registry import analyzers_for_lang
        from ubs_core.prefilter import build_prefilter_index, run_prefilter
        from ubs_core import analyzers  # noqa: F401

        rb_analyzers = [a.name for a in analyzers_for_lang("ruby")]
        ast_rules_input = list(_RULES)
        if args.ast_rule_dir:
            rules_dir = Path(args.ast_rule_dir) / "rules"
            if rules_dir.is_dir():
                for rf in rules_dir.glob("*.yml"):
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
            analyzers=rb_analyzers,
            lang="ruby",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        capturing_sink = CapturingSink()
        counters = scan_patterns(patterns, files_to_scan, capturing_sink, skip, prefilter=prefilter_res)
        run_detectors(files_to_scan, capturing_sink, skip)
        run_analyzers(files_to_scan, capturing_sink, skip, enable_new=args.enable_new_analyzers, prefilter=prefilter_res)
        if args.ast_rule_dir:
            from ubs_core.ruby_ast import scan_all
            from ubs_core.ruby_rules import CATEGORY_MAP, SEVERITY_MAP

            overrides: dict[str, str] = dict(SEVERITY_MAP)
            manifest_path = Path(args.ast_rule_dir) / "manifest.json"
            if manifest_path.is_file():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    for rid, meta in manifest.items():
                        if isinstance(meta, dict) and meta.get("severity") and rid not in overrides:
                            overrides[rid] = meta["severity"]
                except (ValueError, OSError):
                    pass
            ast_files = prefilter_res.ast_files if not prefilter_res.is_bypass else files_to_scan
            scan_all(
                Path(args.ast_rule_dir), ast_files, capturing_sink, overrides,
                count_only=set(CATEGORY_MAP), skip_categories=None,
                category_map=CATEGORY_MAP, skip=skip,
            )
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
    # every layer (patterns, detectors, analyzers, ast) is reflected in totals.
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

        profile_data = {
            "files_considered": prefilter_res.files_considered if files_to_scan else len(files),
            "files_after_prefilter": prefilter_res.files_after_prefilter if files_to_scan else 0,
            "prefilter_ms": prefilter_res.prefilter_ms if files_to_scan else 0,
            "cache_hits": cache.stats["hits"],
            "cache_misses": cache.stats["misses"],
            "cache_hit_rate": cache.stats["hit_rate"],
        }
        doc = {
            "language": "ruby",
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
            "extras": {"profile": profile_data},
        }
        if os.environ.get("UBS_PROFILE") == "1":
            doc["profile"] = profile_data
        Path(args.json_out).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.text_out:
        _render_text(args, files, counters)

    sys.stderr.write(json.dumps({
        "counters": counters,
        "patterns": len(patterns),
        "prefilter": prefilter_res.to_dict(),
    }) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
