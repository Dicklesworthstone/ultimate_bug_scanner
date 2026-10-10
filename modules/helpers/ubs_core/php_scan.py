"""Contract-v2 PHP scanner: bounded native request flow and optional custom rules.

The native engine does not need PHP or ast-grep installed. Findings established
before an unsupported operation or exhausted budget survive in the partial
report; incomplete results are never admitted to the incremental cache.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import sys

from ubs_core.analyzers.taint_php import RULES, policy_limits, scan_file_findings
from ubs_core.cache import CapturingSink, ScanCache
from ubs_core.suppression import SourceSuppressions


def _skip_set(value: str) -> set[int]:
    if not value:
        return set()
    parts = value.split(",")
    if any(not part.strip().isdigit() or int(part) < 1 for part in parts):
        raise argparse.ArgumentTypeError("category skips must be comma-separated positive integers")
    return {int(part) for part in parts}


def _category_set(value: str) -> set[int]:
    categories = _skip_set(value)
    if not categories or not categories <= set(range(1, 6)):
        raise argparse.ArgumentTypeError("PHP categories must be comma-separated integers from 1 to 5")
    return categories


def _write_json(path: str, document: dict) -> None:
    Path(path).write_text(json.dumps(document, ensure_ascii=False) + "\n", encoding="utf-8")


def _render_text(args: argparse.Namespace, summary: dict, errors: list[str]) -> str:
    lines = [f"UBS module: PHP (contract v2) v{args.version} — {summary['project']}"]
    if errors:
        lines.append("Partial: [ANALYZER_ERROR] " + summary["message"])
    if not args.quiet:
        for record in summary["findings"]:
            lines.append(f"[{record['severity'].upper()}] {record['rule']}: {record['message']}")
            lines.append(f"  {record['path']}:{record['line']}:{record['col']}")
            if args.verbose and record.get("extras"):
                lines.append("  " + json.dumps(record["extras"], ensure_ascii=False))
    lines.extend([
        "", "Summary Statistics:", f"Files scanned: {summary['files']}",
        f"Critical issues: {summary['critical']}", f"Warning issues: {summary['warning']}",
        f"Info items: {summary['info']}",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.php_scan")
    parser.add_argument("--files-from", default="-", help="NUL-separated source paths")
    parser.add_argument("--sink", required=True, help="NDJSON findings sink")
    parser.add_argument("--completion-out", default="")
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--project", default="")
    # The runner forwards global category numbers to every active module.
    # A number belonging only to another language is an irrelevant skip here.
    parser.add_argument("--skip", type=_skip_set, default=set())
    parser.add_argument("--only", type=_category_set, default=None)
    parser.add_argument("--custom-rules", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--sarif-out", default="")
    parser.add_argument("--text-out", default="")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args(argv)

    raw = sys.stdin.buffer.read() if args.files_from == "-" else Path(args.files_from).read_bytes()
    entries = raw.split(b"\0") if b"\0" in raw else raw.splitlines()
    # Stable deduplication preserves the caller's spelling, including embedded
    # newlines and spaces. Cache association uses canonical source identities.
    files = list(dict.fromkeys(Path(os.fsdecode(entry)).resolve() for entry in entries if entry))
    selected = set(range(1, 6)) if args.only is None else args.only
    enabled = frozenset(rule for rule, (_slug, category, _title) in RULES.items()
                        if category in selected and category not in args.skip)
    cache = ScanCache(
        lang="php", project_dir=args.project_dir, custom_rules=args.custom_rules,
        skip=",".join(str(value) for value in sorted(set(range(1, 6)) - selected | args.skip)),
        extra=json.dumps({"limits": policy_limits(), "enabled": sorted(enabled)}, sort_keys=True),
    )
    cached, pending = cache.partition_files(files)
    sink = CapturingSink()
    errors: list[str] = []
    suppressions = SourceSuppressions("php")
    for path in pending:
        try:
            # Iterate, rather than list(), so a later failure cannot discard
            # the definite findings already produced for this source file.
            for finding in scan_file_findings(path, enabled_rules=enabled):
                rule = finding["rule"]
                if rule not in enabled:
                    continue
                line = int(finding.get("line", 0) or 0)
                if suppressions.is_suppressed(path, line, rule):
                    continue
                slug, _category, title = RULES[rule]
                record = {
                    **finding, "rule": rule, "category_id": slug,
                    "path": str(path), "line": line,
                    "col": int(finding.get("col", 1) or 1),
                    "severity": "critical", "message": finding.get("message") or title,
                    "suppressed": False,
                }
                sink.write(json.dumps(record, ensure_ascii=False) + "\n")
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            errors.append(f"{path}: {exc}")
    # External policy results remain invocation-local: changing ast-grep or
    # losing the tool must be observable even when all native files are warm.
    custom_sink = CapturingSink()
    if args.custom_rules:
        from ubs_core.external_tools import scan_custom_rules
        scan_custom_rules(args.custom_rules, files, custom_sink, "php", errors)
    if not errors:
        cache.store_scanned_files(pending, sink.by_file)

    records = []
    for path in files:
        records.extend(cached[path] if path in cached else sink.get_for_file(path))
        records.extend(custom_sink.get_for_file(path))
    with open(args.sink, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
    cache.write_stats(os.environ.get("UBS_CACHE_FILE") or str(Path(args.sink).with_suffix(".cache")))

    counters = {"critical": 0, "warning": 0, "info": 0}
    categories: dict[str, dict[str, int]] = {}
    for record in records:
        severity = record["severity"]
        counters[severity] += 1
        category = categories.setdefault(record["category_id"], dict.fromkeys(counters, 0))
        category[severity] += 1
    profile = {
        "files_considered": len(files), "files_after_prefilter": len(pending), "prefilter_ms": 0,
        "cache_hits": cache.stats["hits"], "cache_misses": cache.stats["misses"],
        "cache_hit_rate": cache.stats["hit_rate"],
    }
    summary = {
        "language": "php", "version": args.version, "project": args.project or args.project_dir,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": len(files), **counters, "status": "partial" if errors else "ok",
        "findings": records, "categories": categories, "ast_grep_rules": 0,
        "extras": {"profile": profile}, "uv_tools": [],
    }
    if errors:
        summary["module_error"] = "ANALYZER_ERROR"
        summary["message"] = ("PHP analysis did not complete: " + "; ".join(errors[:5]))[:1000]
        summary["errors"] = errors
    if os.environ.get("UBS_PROFILE") == "1":
        summary["profile"] = profile
    if args.json_out:
        _write_json(args.json_out, summary)
    if args.sarif_out:
        from ubs_core.findings_merge import to_sarif
        report = to_sarif(summary)
        report["runs"][0]["invocations"] = [{
            "executionSuccessful": not errors,
            "exitCode": 2 if errors else int(bool(counters["critical"] or (args.fail_on_warning and counters["warning"]))),
        }]
        if errors:
            report["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [{
                "level": "error", "descriptor": {"id": "ANALYZER_ERROR"},
                "message": {"text": summary["message"]},
            }]
        _write_json(args.sarif_out, report)
    if args.text_out:
        Path(args.text_out).write_text(_render_text(args, summary, errors), encoding="utf-8")
    for error in errors:
        sys.stderr.write(f"ubs-php: analysis incomplete: {error}\n")
    code = 2 if errors else int(bool(counters["critical"] or (args.fail_on_warning and counters["warning"])))
    if args.completion_out:
        _write_json(args.completion_out, {"language": "php", "status": summary["status"],
                                         "files": len(files), "exit_code": code, **counters})
    return code


if __name__ == "__main__":
    raise SystemExit(main())
