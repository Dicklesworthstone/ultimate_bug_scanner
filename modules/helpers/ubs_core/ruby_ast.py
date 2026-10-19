"""ubs_core.ruby_ast — consolidated ast-grep rule-pack scanning (bead 0xjg.10).

Runs the single sgconfig produced by `ubs_core.ruby_rules.generate` (one
`ast-grep scan -c <config> --json=stream` invocation per path batch), parses
the stream once, and appends normalized records to the same NDJSON findings
sink the pattern/detector layers use. Mirrors the legacy consolidated
`run_ast_rules` scan plus run_async_error_checks' per-rule `scan -r` (which
is the only rule whose findings ever joined the legacy counters — every
other pack rule was a cat-18 --json-out/--sarif-out passthrough). Keep all
AST records in the internal cache sink, marking report-only records so the
caller can preserve SARIF evidence without changing the counted findings.

Suppression: invocation-local source indexes apply the shared lexical and
statement-interval policy to the exact diagnostic rule before counting.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ubs_core.external_tools import ast_rule_configs, scan_ast_config
from ubs_core.suppression import SourceSuppressions

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    counted_rules: set[str] | None = None,
    category_map: dict[str, int] | None = None,
    skip: set[int] | None = None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run one sgconfig over the path list; write sink records; return counters.

    Failure reporting has two modes (#111). Without ``errors`` every failure
    raises, which is what a direct caller (the rule-quality harness) wants: a
    broken rule pack must not look like a pack that matched nothing. With
    ``errors`` the failure is appended as a bounded description and the scan
    carries on, so the records already parsed survive and the caller can report
    an incomplete scan (``status: partial`` / exit 2) instead of losing every
    other analysis layer to an exception.
    """
    counters = {"critical": 0, "warning": 0, "info": 0}
    path_list = [Path(p) for p in paths]
    suppressions = SourceSuppressions("ruby")
    for match in scan_ast_config(config, path_list, errors,
                                 ast_grep_bin=ast_grep_bin, batch_size=_BATCH):
        rule_id, file_str = match["ruleId"], match["file"]
        counted = counted_rules is None or rule_id in counted_rules
        category = (category_map or {}).get(rule_id, 18)
        if skip and category in skip:
            continue  # --skip applies to counted and report-only rules.
        rng = match["range"]["start"]
        path = Path(file_str)
        line_no = rng["line"] + 1
        raw_severity = match["severity"]
        if raw_severity == "off":
            continue
        if raw_severity in ("critical", "error", "fatal"):
            default_severity = "critical"
        elif raw_severity in ("warning", "warn"):
            default_severity = "warning"
        else:
            default_severity = "info"
        severity = (severity_overrides or {}).get(rule_id) or default_severity
        if severity not in counters:
            severity = "warning"
        if suppressions.is_suppressed(path, line_no, rule_id):
            continue
        if counted:
            counters[severity] = counters.get(severity, 0) + 1
        message = match.get("message", "").strip() or rule_id
        sink.write(json.dumps({
            "rule": rule_id,
            "category_id": rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id,
            "path": file_str,
            "line": line_no,
            "col": rng["column"] + 1,
            "severity": severity,
            "message": f"{rule_id}: {message}"[:300],
            "suppressed": False,
            "_ast_pack": True,
            "_report_only": not counted,
        }, ensure_ascii=False) + "\n")
    return counters


def scan_all(
    rule_dir: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    counted_rules: set[str] | None = None,
    category_map: dict[str, int] | None = None,
    skip: set[int] | None = None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run every sgconfig-*.yml in rule_dir; aggregate counters.

    ``errors`` collects any scan that could not complete, so the caller can
    report a partial run rather than a clean one (#111)."""
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in ast_rule_configs(rule_dir, paths, errors):
        counters = scan_config(
            config, paths, sink, severity_overrides, ast_grep_bin,
            counted_rules, category_map, skip, errors,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
