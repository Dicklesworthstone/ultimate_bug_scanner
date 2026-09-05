"""ubs_core.py_ast — consolidated ast-grep rule-pack scanning (bead 0xjg.5).

Runs the single sgconfig produced by `ubs_core.py_rules.generate` (one
`ast-grep scan -c <config> --json=stream` invocation per path batch), parses
the stream once, and appends normalized records to the same NDJSON findings
sink the pattern/detector layers use. Replaces the legacy 51-per-rule `scan
-r` loops (text + sarif + summary histogram ≈ 156 spawns).

Suppression: flat same-line + previous-line `ubs:ignore` checks (the legacy
run_ast_rules parser semantics, ubs-python.sh 10085-10098); `py.assert-used`
stays suppressed in test/conftest files (10111); the A7 statement-interval
engine in the meta-runner postprocess layers the richer placements on top.

Counting: legacy counts EVERY rule bucket in totals (the pack ran outside the
category loop, CURRENT_CATEGORY=0); only `py.async.task-no-await` is
category-gated (it ran inside category 5 via run_async_error_checks) — that
mapping comes in through ``category_map``.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from ubs_core.py_scan import MARKER

_ASTGREP_BIN = "ast-grep"
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


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    count_only: set[str] | None = None,
    category_map: dict[str, int] | None = None,
    skip: set[int] | None = None,
) -> dict[str, int]:
    """Run one sgconfig over the path list; write sink records; return counters."""
    counters = {"critical": 0, "warning": 0, "info": 0}
    path_list = [Path(p) for p in paths]
    if not path_list or not config.is_file():
        return counters
    cache: dict[Path, list[str]] = {}
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
            continue  # legacy: `|| true` per rule-file invocation
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
            if count_only is not None and rule_id not in count_only:
                continue
            if skip and category_map:
                category = category_map.get(rule_id)
                if category is not None and category in skip:
                    continue  # --skip: the rule's category is disabled
            rng = match.get("range", {}).get("start", {})
            path = Path(file_str)
            line_no = int(rng.get("line", 0)) + 1  # ast-grep rows are 0-based
            # Legacy parser severity: YAML tier mapped at parse time; the
            # manifest/SEVERITY_MAP override wins (ubs-python.sh 10102-10108).
            raw_severity = str(match.get("severity", "info")).lower().strip()
            if raw_severity in ("critical", "error", "fatal"):
                default_severity = "critical"
            elif raw_severity in ("warning", "warn"):
                default_severity = "warning"
            else:
                default_severity = "info"
            severity = (severity_overrides or {}).get(rule_id) or default_severity
            if severity not in counters:
                severity = "warning"
            # Suppress asserts in test files (10111).
            if rule_id == "py.assert-used" and (
                "test" in file_str.lower() or "conftest" in file_str.lower()
            ):
                continue
            if _has_marker(path, line_no, cache):
                continue  # legacy line + previous-line marker check
            counters[severity] = counters.get(severity, 0) + 1
            message = str(match.get("message", "")).strip() or rule_id
            # Legacy pack text title: "__FINDING__  <rid>  <message>".
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id,
                "path": file_str,
                "line": line_no,
                "col": int(rng.get("column", 0)) + 1,
                "severity": severity,
                "message": f"{rule_id}: {message}"[:300],
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def scan_all(
    rule_dir: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    count_only: set[str] | None = None,
    skip_categories: set[int] | None = None,
    category_map: dict[str, int] | None = None,
    skip: set[int] | None = None,
) -> dict[str, int]:
    """Run every sgconfig-*.yml in rule_dir; aggregate counters."""
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in sorted(rule_dir.glob("sgconfig-*.yml")):
        counters = scan_config(
            config, paths, sink, severity_overrides, ast_grep_bin,
            count_only, category_map, skip,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
