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

Suppression: per-id, mirroring the two legacy parsers —
- java.async.* ids: current + previous-line `ubs:ignore` check
  (run_async_error_checks parser, ubs-java.sh 2462-2475);
- java.resource.* ids and java.optional-isPresent-then-get: NO marker check
  (emit_ast_rule_group's PYRULE parser and the cat-1 ast_search probe never
  checked markers — the A7 statement-interval engine in the meta-runner
  postprocess layers the richer placements on top).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from ubs_core.java_scan import MARKER

_ASTGREP_BIN = "ast-grep"

# rule-id family -> legacy category number (for --skip filtering).
_FAMILY_CATEGORY = {
    "java.async": 3,
    "java.resource": 19,
}
_BATCH = 400  # paths per scan invocation (argv length safety)


def _file_lines(path: Path, cache: dict[Path, list[str]]) -> list[str]:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    return cache[path]


def _has_marker(path: Path, line_no: int, cache: dict[Path, list[str]]) -> bool:
    lines = _file_lines(path, cache)
    idx = line_no - 1
    return any(0 <= i < len(lines) and MARKER in lines[i].lower() for i in (idx, idx - 1))


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
    marker_suppressed_ids: frozenset[str] | None = None,
    category_for_rule=None,
) -> dict[str, int]:
    """Run one sgconfig over the path list; write sink records; return counters."""
    counters = {"critical": 0, "warning": 0, "info": 0}
    path_list = [Path(p) for p in paths]
    if not path_list or not config.is_file():
        return counters
    cache: dict[Path, list[str]] = {}
    suppressed_ids = marker_suppressed_ids or frozenset()
    for start in range(0, len(path_list), _BATCH):
        batch = [str(p) for p in path_list[start : start + _BATCH]]
        try:
            proc = subprocess.run(
                [ast_grep_bin, "scan", "-c", str(config), "--json=stream", *batch],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired):
            return counters
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
            if rule_id in suppressed_ids and _has_marker(path, line_no, cache):
                continue  # legacy async parser marker check only
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
    marker_suppressed_ids: frozenset[str] | None = None,
    category_for_rule=None,
) -> dict[str, int]:
    """Run every sgbase-*.yml in rule_dir; aggregate counters."""
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in sorted(rule_dir.glob("sgbase-*.yml")):
        lang = config.stem.removeprefix("sgbase-")
        counters = scan_config(
            config, paths, sink, lang, severity_overrides, ast_grep_bin,
            counted_rules, skip_categories, marker_suppressed_ids, category_for_rule,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
