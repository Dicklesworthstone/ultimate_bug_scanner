"""ubs_core.kotlin_scan — contract-v2 orchestrator for the Kotlin module (bead 7mga.2).

Executes static analysis on Kotlin (.kt, .kts) files across:
1. Pattern layer: ProcessBuilder shell execution
2. Analyzer layer: Kotlin null-guard type narrowing, taint path traversal, taint open redirect
3. Detector layer: archive extraction (zip slip), response header injection,
   SSRF outbound URL, insecure randomness in tokens/secrets
4. ast-grep layer: consolidated rule pack via ubs_core.kotlin_rules

Sink record (one JSON object per line, contract schema):
    {rule, category_id, path, line, col, severity, message, suppressed}
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

MARKER = "ubs:ignore"

_CATEGORY_SLUGS = {
    1: "type-narrowing", 2: "equality", 3: "concurrency", 4: "security",
    5: "io", 6: "logging", 7: "regex", 8: "collections",
    9: "control-flow", 10: "performance", 11: "serialization", 12: "features",
    13: "sql", 14: "annotations", 15: "ast-grep", 16: "build",
    17: "inventory", 18: "api-misuse", 19: "resource-lifecycle",
    20: "filesystem", 21: "secrets", 22: "logging-practices",
}

_SECTION_HEADERS = {
    1: "1. NULL SAFETY & TYPE NARROWING",
    2: "2. EQUALITY & HASHCODE",
    3: "3. CONCURRENCY & THREADING",
    4: "4. SECURITY",
    5: "5. I/O & RESOURCES",
    6: "6. LOGGING & DEBUGGING",
    7: "7. REGEX & STRING PITFALLS",
    8: "8. COLLECTIONS & GENERICS",
    9: "9. SWITCH & CONTROL FLOW",
    10: "10. PERFORMANCE & MEMORY",
    11: "11. SERIALIZATION & COMPATIBILITY",
    12: "12. KOTLIN LANGUAGE FEATURES",
    13: "13. SQL CONSTRUCTION",
    14: "14. ANNOTATIONS & METADATA",
    15: "15. AST-GREP RULE PACK FINDINGS",
    16: "16. BUILD HEALTH (Gradle)",
    17: "17. META STATISTICS & INVENTORY",
    18: "18. MISC API MISUSE",
    19: "19. RESOURCE LIFECYCLE",
    20: "20. PATH HANDLING & FILESYSTEM",
    21: "21. HARD-CODED SECRETS",
    22: "22. LOGGING BEST PRACTICES",
}

_SUBHEADERS = {
    1: {
        "kotlin.narrowing.": "Kotlin guard clauses without exit",
    },
    4: {
        "kotlin.security.insecure-randomness": "Security-sensitive non-crypto randomness",
        "kotlin.taint.path_traversal": "Request-derived filesystem paths",
        "kotlin.security.header-injection": "Request-derived response headers",
        "kotlin.taint.open_redirect": "Request-derived open redirects",
        "kotlin.security.ssrf-outbound-url": "Request-derived outbound HTTP URLs",
        "kotlin.security.archive-extraction": "Archive extraction path traversal",
        "kotlin.security.processbuilder-shell": "Command execution via ProcessBuilder",
    },
}

_SUMMARY_TITLES: dict[str, str] = {
    "kotlin.taint.path_traversal": "Request-derived path reaches file read/write/serve sink",
    "kotlin.taint.open_redirect": "Unvalidated redirect from request data",
    "kotlin.security.header-injection": "Request-controlled value reaches HTTP response header",
    "kotlin.security.ssrf-outbound-url": "Request-derived URL reaches outbound HTTP client",
    "kotlin.security.archive-extraction": "Archive extraction path traversal risk",
    "kotlin.security.insecure-randomness": "Security token generated with non-cryptographic randomness",
    "kotlin.security.processbuilder-shell": "ProcessBuilder shell interpreter invoked",
    "kotlin.narrowing.safecall_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.negative_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.positive_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.smart_cast": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.elvis_force": "Kotlin guard without exit before '!!'",
}

_GOOD_LINES: tuple[tuple[str, str, int], ...] = (
    ("kotlin.narrowing.", "No Kotlin guard clauses missing exit", 1),
    ("kotlin.taint.path_traversal", "No request-derived filesystem paths detected", 4),
    ("kotlin.security.header-injection", "No request-derived response header values detected", 4),
    ("kotlin.taint.open_redirect", "No open redirect vulnerabilities detected", 4),
    ("kotlin.security.ssrf-outbound-url", "No request-derived outbound URLs detected", 4),
    ("kotlin.security.archive-extraction", "No archive extraction path traversal risks detected", 4),
    ("kotlin.security.insecure-randomness", "No insecure randomness in security tokens detected", 4),
    ("kotlin.security.processbuilder-shell", "No shell interpreters invoked via ProcessBuilder", 4),
)


@dataclass(frozen=True)
class Pattern:
    category: int
    rule_id: str
    title: str
    regex: re.Pattern
    severity: str = "critical"
    description: str = ""


_PB_SHELL = (
    r'(new[ \t]+)?ProcessBuilder[ \t]*\([ \t]*"(sh|bash)"[ \t]*,[ \t]*"-?c"'
    r'|(new[ \t]+)?ProcessBuilder[ \t]*\([ \t]*"cmd([.]exe)?"[ \t]*,[ \t]*"/[cC]"'
    r'|(new[ \t]+)?ProcessBuilder[ \t]*\([ \t]*"(powershell|pwsh)([.]exe)?"[ \t]*,[ \t]*"-(Command|EncodedCommand)"'
    r'|ProcessBuilder[ \t]*\([ \t]*(listOf|arrayOf)[ \t]*\([ \t]*"(sh|bash)"[ \t]*,[ \t]*"-?c"'
    r'|ProcessBuilder[ \t]*\([ \t]*(listOf|arrayOf)[ \t]*\([ \t]*"cmd([.]exe)?"[ \t]*,[ \t]*"/[cC]"'
    r'|ProcessBuilder[ \t]*\([ \t]*(listOf|arrayOf)[ \t]*\([ \t]*"(powershell|pwsh)([.]exe)?"[ \t]*,[ \t]*"-(Command|EncodedCommand)"'
)

_PATTERNS: list[Pattern] = [
    Pattern(
        category=4,
        rule_id="kotlin.security.processbuilder-shell",
        title="ProcessBuilder shell interpreter invoked",
        regex=re.compile(_PB_SHELL),
        severity="critical",
        description="Pass arguments directly as argv, or strictly validate and escape every shell fragment",
    ),
]


def _has_suppression(line: str, rule_id: str) -> bool:
    if MARKER in line:
        m = re.search(r"ubs:ignore(?:\[([a-zA-Z0-9_.,-]+)\])?", line)
        if m:
            rules = m.group(1)
            if not rules or rule_id in rules.split(","):
                return True
    return False


def _record_category(rec: dict) -> int | None:
    rule = rec.get("rule", "")
    if rule.startswith("kotlin.narrowing."):
        return 1
    if rule.startswith("kotlin.security.") or rule.startswith("kotlin.taint."):
        return 4
    cat_id = rec.get("category_id", "")
    if cat_id.startswith("kotlin."):
        slug = cat_id.split(".", 1)[1]
        for num, s in _CATEGORY_SLUGS.items():
            if s == slug:
                return num
    return 4


def scan_patterns(patterns: list[Pattern], files: Sequence[Path], sink, skip: set[int], prefilter: Any = None) -> None:
    for path in files:
        active_patterns = patterns
        if prefilter is not None and not prefilter.is_bypass:
            cand = prefilter.candidate_rules_for(path)
            active_patterns = [p for p in patterns if p.rule_id in cand]
            if not active_patterns:
                continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = content.splitlines()
        for pattern in active_patterns:
            if pattern.category in skip:
                continue
            for lineno, line in enumerate(lines, 1):
                if pattern.regex.search(line):
                    if _has_suppression(line, pattern.rule_id):
                        continue
                    detail = pattern.description
                    msg = f"{pattern.title} — {detail}" if detail else pattern.title
                    sink.write(json.dumps({
                        "rule": pattern.rule_id,
                        "category_id": f"kotlin.{_CATEGORY_SLUGS.get(pattern.category, 'security')}",
                        "path": str(path),
                        "line": lineno,
                        "col": 1,
                        "severity": pattern.severity,
                        "message": msg[:300],
                        "suppressed": False,
                    }, ensure_ascii=False) + "\n")


def scan_analyzers(files: Sequence[Path], sink, skip: set[int], project_dir: Path | None = None, prefilter: Any = None) -> None:
    from ubs_core.registry import RunContext

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

    # 1. Type narrowing (category 1)
    if 1 not in skip:
        from ubs_core.analyzers import narrowing_kotlin
        aname = getattr(narrowing_kotlin, "name", "narrowing_kotlin")
        target_files = files
        if prefilter is not None and not prefilter.is_bypass:
            target_files = prefilter.filter_files_for_analyzer(aname, files)
        if target_files:
            ctx = RunContext(lang="kotlin", files=list(target_files))
            for finding in narrowing_kotlin.run(ctx):
                rule_id = finding.get("rule", "")
                sink.write(json.dumps({
                    "rule": rule_id,
                    "category_id": "kotlin.type-narrowing",
                    "path": _rel(str(finding.get("path", ""))),
                    "line": int(finding.get("line", 0) or 0),
                    "col": int(finding.get("col", 1) or 1),
                    "severity": finding.get("severity", "warning"),
                    "message": finding.get("message", ""),
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")

    # 2. Taint path traversal & redirect (category 4)
    if 4 not in skip:
        from ubs_core.analyzers.taint_java_traversal import run as run_traversal
        from ubs_core.analyzers.taint_java_redirect import run as run_redirect

        trav_files = files
        if prefilter is not None and not prefilter.is_bypass:
            trav_files = prefilter.filter_files_for_analyzer("taint_java_traversal", files)
        if trav_files:
            ctx = RunContext(lang="java", files=list(trav_files))
            for finding in run_traversal(ctx):
                sink.write(json.dumps({
                    "rule": "kotlin.taint.path_traversal",
                    "category_id": "kotlin.security",
                    "path": _rel(str(finding.get("path", ""))),
                    "line": int(finding.get("line", 0) or 0),
                    "col": int(finding.get("col", 1) or 1),
                    "severity": "critical",
                    "message": finding.get("message", "Request-derived path reaches file read/write/serve sink"),
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")

        redir_files = files
        if prefilter is not None and not prefilter.is_bypass:
            redir_files = prefilter.filter_files_for_analyzer("taint_java_redirect", files)
        if redir_files:
            ctx = RunContext(lang="java", files=list(redir_files))
            for finding in run_redirect(ctx):
                sink.write(json.dumps({
                    "rule": "kotlin.taint.open_redirect",
                    "category_id": "kotlin.security",
                    "path": _rel(str(finding.get("path", ""))),
                    "line": int(finding.get("line", 0) or 0),
                    "col": int(finding.get("col", 1) or 1),
                    "severity": "critical",
                    "message": finding.get("message", "Unvalidated redirect from request data"),
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")


def scan_detectors(files: Sequence[Path], sink, skip: set[int]) -> None:
    if 4 in skip:
        return

    from ubs_core.java_detectors import (
        archive_extraction,
        header_injection,
        security_randomness,
        ssrf_outbound_url,
    )

    detectors = [
        (archive_extraction, "kotlin.security.archive-extraction", "Archive extraction path traversal risk"),
        (header_injection, "kotlin.security.header-injection", "Request-controlled value reaches HTTP response header"),
        (ssrf_outbound_url, "kotlin.security.ssrf-outbound-url", "Request-derived URL reaches outbound HTTP client"),
        (security_randomness, "kotlin.security.insecure-randomness", "Security token generated with non-cryptographic randomness"),
    ]

    for module, rule_id, title in detectors:
        find = getattr(module, "find", None)
        if not find:
            continue
        for hit in find(files):
            if len(hit) == 5:
                _rid, path, line_no, col, detail = hit
            else:
                path, line_no, col, detail = hit
            msg = f"{title} — {detail}" if detail else title
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": "kotlin.security",
                "path": str(path),
                "line": int(line_no),
                "col": int(col),
                "severity": "critical",
                "message": msg[:300],
                "suppressed": False,
            }, ensure_ascii=False) + "\n")


def _render_text(args, files: Sequence[Path], counters: dict[str, int]) -> None:
    records = [
        json.loads(line)
        for line in Path(args.sink).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_rule: dict[str, list[dict]] = {}
    for rec in records:
        by_rule.setdefault(rec["rule"], []).append(rec)

    lines = [
        f"UBS module: kotlin (contract v2) — {args.project or args.project_dir}",
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
                if rule.startswith(prefix) or prefix.startswith(rule):
                    subheader = text
                    break
        if section and section != current_section:
            current_section = section
            lines.append("")
            lines.append(f"=== {section} ===")
        if subheader and subheader not in emitted_subheaders:
            emitted_subheaders.add(subheader)
            lines.append(f"--- {subheader} ---")

        title = _SUMMARY_TITLES.get(rule, recs[0].get("message", rule))
        sev = recs[0].get("severity", "warning").upper()
        lines.append(f"[{sev}] {title} ({len(recs)} match{'es' if len(recs) != 1 else ''})")
        for r in recs[:5]:
            p = r.get("path", "")
            ln = r.get("line", 0)
            msg = r.get("message", "")
            lines.append(f"  {p}:{ln}: {msg}")

    # Emit "good" lines for empty categories
    skip = {int(p) for p in (args.skip or "").split(",") if p.strip().isdigit()}
    for prefix, note, cat in _GOOD_LINES:
        if cat in skip:
            continue
        if not any(r.startswith(prefix) for r in by_rule):
            lines.append(f"[OK] {note}")

    lines.append("")
    lines += [
        f"Critical issues: {counters['critical']}",
        f"Warning issues: {counters['warning']}",
        f"Info items: {counters['info']}",
        f"Report generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
    ]
    Path(args.text_out).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _render_sarif(records: list[dict], counters: dict[str, int], project_path: str, files: Sequence[Path]) -> dict:
    rules_map: dict[str, dict] = {}
    sarif_results: list[dict] = []
    level_map = {"critical": "error", "warning": "warning", "info": "note"}

    for r in records:
        rid = r.get("rule", "kotlin.finding")
        if rid not in rules_map:
            rules_map[rid] = {
                "id": rid,
                "shortDescription": {"text": _SUMMARY_TITLES.get(rid, rid)},
                "defaultConfiguration": {"level": level_map.get(r.get("severity", "warning"), "warning")},
            }
        p = r.get("path", "")
        ln = int(r.get("line", 1) or 1)
        col = int(r.get("col", 1) or 1)
        sarif_results.append({
            "ruleId": rid,
            "level": level_map.get(r.get("severity", "warning"), "warning"),
            "message": {"text": r.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": p},
                    "region": {
                        "startLine": max(1, ln),
                        "startColumn": max(1, col),
                    },
                },
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ubs-kotlin",
                    "version": "0.1.0",
                    "rules": list(rules_map.values()),
                },
            },
            "results": sarif_results,
        }],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.kotlin_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink path")
    parser.add_argument("--project-dir", default="", help="base dir for relative sink paths")
    parser.add_argument("--skip", default="", help="comma-separated category numbers to skip")
    parser.add_argument("--ast-rule-dir", default="", help="ast-grep rule dir")
    parser.add_argument("--text-out", default="", help="write text report here")
    parser.add_argument("--json-out", default="", help="write JSON summary here")
    parser.add_argument("--project", default="", help="project path recorded in the json summary")
    parser.add_argument("--enable-new-analyzers", action="store_true")
    parser.add_argument("--version", default="0.1.0", help="module version")
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args(argv)

    if args.files_from in ("-", ""):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.files_from).read_bytes()
    entries = data.split(b"\0") if b"\0" in data else data.splitlines()
    files = [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]

    skip = {int(p) for p in (args.skip or "").split(",") if p.strip().isdigit()}

    from ubs_core.prefilter import build_prefilter_index, run_prefilter
    from ubs_core.registry import analyzers_for_lang

    ast_rules_input = []
    if args.ast_rule_dir and Path(args.ast_rule_dir).is_dir():
        for rf in sorted(Path(args.ast_rule_dir).glob("*.yml")) + sorted(Path(args.ast_rule_dir).glob("*.yaml")):
            try:
                text = rf.read_text(encoding="utf-8", errors="ignore")
                id_m = re.search(r"id:\s*(\S+)", text)
                rid = id_m.group(1) if id_m else rf.stem
                ast_rules_input.append((rid, text))
            except OSError:
                pass

    from ubs_core.cache import CapturingSink, ScanCache

    cache = ScanCache(
        lang="kotlin",
        project_dir=args.project_dir or args.project or ".",
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"new_analyzers={args.enable_new_analyzers}",
    )
    cached_findings, files_to_scan = cache.partition_files(files)

    capturing_sink = None
    if files_to_scan:
        kotlin_analyzers = [a.name for a in analyzers_for_lang("kotlin")] + ["taint_java_traversal", "taint_java_redirect"]
        prefilter_index = build_prefilter_index(
            ast_rules=ast_rules_input,
            patterns=_PATTERNS,
            analyzers=kotlin_analyzers,
            lang="kotlin",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        capturing_sink = CapturingSink()
        scan_patterns(_PATTERNS, files_to_scan, capturing_sink, skip, prefilter=prefilter_res)
        scan_analyzers(files_to_scan, capturing_sink, skip, project_dir=Path(args.project_dir) if args.project_dir else None, prefilter=prefilter_res)
        scan_detectors(files_to_scan, capturing_sink, skip)
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

    counters = {"critical": 0, "warning": 0, "info": 0}
    records = []
    for line in Path(args.sink).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            records.append(rec)
            sev = rec.get("severity", "info")
            counters[sev] = counters.get(sev, 0) + 1
        except ValueError:
            continue

    exit_code = 1 if counters["critical"] else 0
    if args.fail_on_warning and (counters["critical"] + counters["warning"]) > 0:
        exit_code = 1

    if args.json_out:
        by_category: dict[str, dict[str, int]] = {}
        for rec in records:
            cat_id = rec.get("category_id", "kotlin.security")
            by_category.setdefault(cat_id, {"critical": 0, "warning": 0, "info": 0})
            sev = rec.get("severity", "info")
            by_category[cat_id][sev] = by_category[cat_id].get(sev, 0) + 1

        profile_data = {
            "files_considered": prefilter_res.files_considered if files_to_scan else len(files),
            "files_after_prefilter": prefilter_res.files_after_prefilter if files_to_scan else 0,
            "prefilter_ms": prefilter_res.prefilter_ms if files_to_scan else 0,
            "cache_hits": cache.stats["hits"],
            "cache_misses": cache.stats["misses"],
            "cache_hit_rate": cache.stats["hit_rate"],
        }
        summary = {
            "language": "kotlin",
            "project": args.project or args.project_dir or ".",
            "files": len(files),
            "critical": counters["critical"],
            "warning": counters["warning"],
            "info": counters["info"],
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "status": "ok",
            "findings": records,
            "categories": by_category,
            "ast_grep_rules": len(records),
            "extras": {"profile": profile_data},
            "uv_tools": [],
        }
        if os.environ.get("UBS_PROFILE") == "1":
            summary["profile"] = profile_data
        Path(args.json_out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if args.text_out:
        _render_text(args, files, counters)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
