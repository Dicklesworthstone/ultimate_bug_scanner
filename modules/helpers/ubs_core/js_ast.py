"""ubs_core.js_ast — consolidated ast-grep rule-pack scanning (bead 0xjg.4).

Runs the ≤ 3 sgconfigs produced by `ubs_core.js_rules.generate` (one
`ast-grep scan -c <config> --json=stream` invocation per grammar group),
parses the stream once, and appends normalized records to the same NDJSON
findings sink the pattern layer uses.

Suppression: flat same-line + previous-line `ubs:ignore` checks (the legacy
emit_ast_rule_group semantics, ubs-js.sh 572-577); the A7 statement-interval
engine in the meta-runner postprocess layers the richer placements on top.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from ubs_core.js_scan import MARKER

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)


def _has_marker(path: Path, line_no: int, cache: dict[Path, list[str]]) -> bool:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path]
    idx = line_no - 1
    return any(0 <= i < len(lines) and MARKER in lines[i].lower() for i in (idx, idx - 1))


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    lang: str,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
) -> dict[str, int]:
    """Run one sgconfig over the path list; write sink records; return counters."""
    counters = {"critical": 0, "warning": 0, "info": 0}
    path_list = [Path(p) for p in paths]
    if not path_list or not config.is_file():
        return counters
    cache: dict[Path, list[str]] = {}
    for start in range(0, len(path_list), _BATCH):
        batch = [str(p) for p in path_list[start : start + _BATCH]]
        proc = subprocess.run(
            [ast_grep_bin, "scan", "-c", str(config), "--json=stream", *batch],
            capture_output=True,
            text=True,
            timeout=600,
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
            rng = match.get("range", {}).get("start", {})
            line_no = int(rng.get("line", 0)) + 1  # ast-grep rows are 0-based
            path = Path(file_str)
            severity = (severity_overrides or {}).get(rule_id) or str(match.get("severity", "warning"))
            if severity not in counters:
                severity = "warning"
            if _has_marker(path, line_no, cache):
                continue  # legacy line + previous-line marker check
            counters[severity] = counters.get(severity, 0) + 1
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id,
                "path": file_str,
                "line": line_no,
                "col": int(rng.get("column", 0)) + 1,
                "severity": severity,
                "message": str(match.get("text", ""))[:240],
                "suppressed": False,
            }, ensure_ascii=False) + "\n")
    return counters


def scan_all(
    rule_dir: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
) -> dict[str, int]:
    """Run every sgconfig-<lang>.yml in rule_dir; aggregate counters."""
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in sorted(rule_dir.glob("sgconfig-*.yml")):
        lang = config.stem.removeprefix("sgconfig-")
        counters = scan_config(config, paths, sink, lang, severity_overrides, ast_grep_bin)
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
