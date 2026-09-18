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
import subprocess
from pathlib import Path
from typing import Sequence

from ubs_core.suppression import SourceSuppressions

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
    if not path_list or not config.is_file():
        return counters
    suppressions = SourceSuppressions("kotlin" if lang == "kotlin" else "java")
    for start in range(0, len(path_list), _BATCH):
        batch = [str(p) for p in path_list[start : start + _BATCH]]
        try:
            proc = subprocess.run(
                [ast_grep_bin, "scan", "-c", str(config), "--json=stream", *batch],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            if errors is not None:
                errors.append(f"ast-grep unavailable ({ast_grep_bin})")
            continue
        except OSError as exc:
            if errors is not None:
                errors.append(f"ast-grep could not be launched: {exc}")
            continue
        except subprocess.TimeoutExpired:
            if errors is not None:
                errors.append(f"ast-grep timed out on {config.name}")
            continue
        # ast-grep exits 0 with no error-level diagnostics and 1 when it found
        # some; anything else (bad config, unreadable path, internal error) is
        # a failed invocation, not a clean one.
        if proc.returncode not in (0, 1) and errors is not None:
            detail = (proc.stderr or "").strip().splitlines()
            errors.append(
                f"ast-grep exited {proc.returncode} on {config.name}"
                + (f": {detail[0][:160]}" if detail else "")
            )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                match = json.loads(line)
            except ValueError:
                continue
            rule_id = str(match.get("ruleId", "") or match.get("rule_id", ""))
            file_str = str(match.get("file", "") or match.get("path", ""))
            if not rule_id or not file_str:
                continue
            counted = counted_rules is None or rule_id in counted_rules
            if skip_categories:
                category = _family_category(rule_id) if counted else 15
                if category is None and category_for_rule is not None:
                    category = category_for_rule(rule_id)
                if category is not None and category in skip_categories:
                    continue  # --skip: the category is disabled
            rng = match.get("range", {}).get("start", {})
            path = Path(file_str)
            line_no = int(rng.get("line", 0)) + 1  # ast-grep rows are 0-based
            raw_severity = str(match.get("severity", "warning")).lower()
            default_severity = {"error": "critical", "warn": "warning", "note": "info"}.get(raw_severity, raw_severity)
            severity = (severity_overrides or {}).get(rule_id) or default_severity
            if severity not in counters:
                severity = "warning"
            if suppressions.is_suppressed(path, line_no, rule_id):
                continue
            if counted:
                counters[severity] = counters.get(severity, 0) + 1
            message = str(match.get("message", "")).strip() or str(match.get("text", ""))[:240]
            if category_for_rule is not None:
                category_id = category_for_rule(rule_id)
            else:
                category_id = rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": category_id,
                "path": file_str,
                "line": line_no,
                "col": int(rng.get("column", 0)) + 1,
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
    for config in sorted(rule_dir.glob("sgbase-*.yml")):
        lang = config.stem.removeprefix("sgbase-")
        counters = scan_config(
            config, paths, sink, lang, severity_overrides, ast_grep_bin,
            counted_rules, skip_categories, category_for_rule, errors,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
