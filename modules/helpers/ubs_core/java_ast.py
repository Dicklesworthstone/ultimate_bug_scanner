"""ubs_core.java_ast — consolidated ast-grep rule-pack scanning (bead 0xjg.8).

Runs the sgconfig produced by `ubs_core.java_rules.generate` (ONE
`ast-grep scan -c <config> --json=stream` invocation per 400-path batch,
replacing the legacy per-rule `scan -r` spawns), parses the stream once, and
appends normalized records to the same NDJSON findings sink the pattern layer
uses.

Counting: only the ids in `counted_rules` affect totals. Other pack records
are retained for SARIF, with internal flags to survive cache replay without
changing the counted sink. Severity comes from java_rules.SEVERITY_MAP
overrides for counted rules and the rule configuration for other records.

Suppression uses the source statement interval and exact public rule ID before
counting or emitting either counted or report-only AST records.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.external_tools import ast_rule_configs, scan_ast_config

_ASTGREP_BIN = "ast-grep"

# rule-id family -> legacy category number (for --skip filtering).
_FAMILY_CATEGORY = {
    "java.async": 3,
    "java.resource": 19,
}
_BATCH = 400  # paths per scan invocation (argv length safety)


def _family_category(rule_id: str) -> int | None:
    family = rule_id.rsplit(".", 1)[0]
    if family in _FAMILY_CATEGORY:
        return _FAMILY_CATEGORY[family]
    return None


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    lang: str,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    counted_rules: set[str] | None = None,
    skip_categories: set[int] | None = None,
    category_for_rule=None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run one sgconfig over the path list; write sink records; return counters.

    Records already parsed from a failed batch are kept — a partial result is
    still evidence — but the failure itself is appended to ``errors`` so the
    caller can report the scan as incomplete. Issue #111 (the same shape #103
    fixed for Python): this layer used to swallow launch failures, timeouts and
    non-zero exits, so a rule pack that never ran was indistinguishable from
    one that ran and found nothing.
    """
    counters = {"critical": 0, "warning": 0, "info": 0}
    path_list = [Path(p) for p in paths]
    suppressions = SourceSuppressions("kotlin" if lang == "kotlin" else "java")
    for match in scan_ast_config(config, path_list, errors,
                                 ast_grep_bin=ast_grep_bin, batch_size=_BATCH):
        rule_id, file_str = match["ruleId"], match["file"]
        counted = counted_rules is None or rule_id in counted_rules
        if skip_categories:
            category = _family_category(rule_id) if counted else 15
            if category is None and category_for_rule is not None:
                category = category_for_rule(rule_id)
            if category is not None and category in skip_categories:
                continue
        rng = match["range"]["start"]
        path = Path(file_str)
        line_no = rng["line"] + 1
        raw_severity = match["severity"]
        if raw_severity == "off":
            continue
        default_severity = {"error": "critical", "fatal": "critical", "warn": "warning",
                            "note": "info", "hint": "info"}.get(raw_severity, raw_severity)
        severity = (severity_overrides or {}).get(rule_id) or default_severity
        if severity not in counters:
            severity = "warning"
        if suppressions.is_suppressed(path, line_no, rule_id):
            continue
        if counted:
            counters[severity] = counters.get(severity, 0) + 1
        message = match.get("message", "").strip() or match.get("text", "")[:240]
        if category_for_rule is not None:
            category_id = category_for_rule(rule_id)
        else:
            category_id = rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id
        sink.write(json.dumps({
            "rule": rule_id,
            "category_id": category_id,
            "path": file_str,
            "line": line_no,
            "col": rng["column"] + 1,
            "severity": severity,
            "message": message[:240],
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
    skip_categories: set[int] | None = None,
    category_for_rule=None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run every sgbase-*.yml in rule_dir; aggregate counters.

    ``errors`` collects any scan that could not complete, so the caller can
    report a partial run rather than a clean one (#111).
    """
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in ast_rule_configs(rule_dir, paths, errors, prefix="sgbase-"):
        lang = config.stem.removeprefix("sgbase-")
        counters = scan_config(
            config, paths, sink, lang, severity_overrides, ast_grep_bin,
            counted_rules, skip_categories, category_for_rule, errors,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
