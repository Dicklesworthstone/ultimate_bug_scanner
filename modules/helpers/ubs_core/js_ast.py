"""ubs_core.js_ast — consolidated ast-grep rule-pack scanning (bead 0xjg.4).

Runs the ≤ 3 sgconfigs produced by `ubs_core.js_rules.generate` (one
`ast-grep scan -c <config> --json=stream` invocation per grammar group),
parses the stream once, and appends normalized records to the same NDJSON
findings sink the pattern layer uses.

Suppression: flat same-line + previous-line `ubs:ignore` checks (the legacy
emit_ast_rule_group semantics, ubs-js.sh 572-577); the A7 statement-interval
engine in the meta-runner postprocess layers the richer placements on top.

Counting: when `count_only` is provided, only those rule ids are counted and
emitted — legacy counts just the mapped emit_ast_rule_group ids and dumps
the rest of the pack informationally (bead A4-js calibration).

Emit conditions: js.resource.listener-no-remove carries the legacy rg-delta
condition (ubs-js.sh 670-710) — it fires only when a file's addEventListener
count exceeds its removeEventListener count.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Sequence

from ubs_core.js_scan import MARKER

_ASTGREP_BIN = "ast-grep"

# rule-id family -> legacy category number (for --skip filtering).
_FAMILY_CATEGORY = {
    "js.async": 5,
    "js.hooks": 5,
    "react": 5,
    "js.error": 6,
    "js.resource": 19,
    "js.taint": 7,
    "javascript.guards": 1,
    "js.security": 7,
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


def _listener_imbalance(path: Path, cache: dict[Path, list[str]]) -> bool:
    """Legacy rg-delta (ubs-js.sh 670-710): addEventListener count must exceed
    removeEventListener count in the same file for the finding to fire."""
    lines = _file_lines(path, cache)
    adds = sum(line.count("addEventListener") for line in lines)
    removes = sum(line.count("removeEventListener") for line in lines)
    return adds > removes


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    lang: str,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    count_only: set[str] | None = None,
    skip_categories: set[int] | None = None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run one sgconfig over the path list; write sink records; return counters.

    A batch that could not run appends to ``errors`` instead of contributing a
    silent zero, and the records already parsed from a failed batch are kept —
    a partial result is still evidence (#111).
    """
    counters = {"critical": 0, "warning": 0, "info": 0}
    path_list = [Path(p) for p in paths]
    if not path_list or not config.is_file():
        return counters
    cache: dict[Path, list[str]] = {}
    for start in range(0, len(path_list), _BATCH):
        batch = [str(p) for p in path_list[start : start + _BATCH]]
        try:
            proc = subprocess.run(
                [os.environ.get("UBS_AST_GREP_BIN") or ast_grep_bin,
                 "scan", "-c", str(config), "--json=stream", *batch],
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
        # some; anything else is a failed invocation, which used to degrade to
        # zero AST findings.
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
            if count_only is not None and rule_id not in count_only:
                continue  # informational dump in legacy — not counted
            if skip_categories:
                family = rule_id.rsplit(".", 1)[0]
                category = _FAMILY_CATEGORY.get(family)
                if category is not None and category in skip_categories:
                    continue  # --skip: the category is disabled
            rng = match.get("range", {}).get("start", {})
            path = Path(file_str)
            line_no = int(rng.get("line", 0)) + 1  # ast-grep rows are 0-based
            severity = (severity_overrides or {}).get(rule_id) or str(match.get("severity", "warning"))
            severity = {"error": "critical", "hint": "info"}.get(severity, severity)
            if severity == "off":
                continue
            if severity not in counters:
                severity = "warning"
            if rule_id == "js.resource.listener-no-remove" and not _listener_imbalance(path, cache):
                continue  # legacy rg-delta: adds <= removes means balanced
            if _has_marker(path, line_no, cache):
                continue  # legacy line + previous-line marker check
            counters[severity] = counters.get(severity, 0) + 1
            message = str(match.get("message", "")).strip() or str(match.get("text", ""))[:240]
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id,
                "path": file_str,
                "line": line_no,
                "col": int(rng.get("column", 0)) + 1,
                "severity": severity,
                "message": message[:240],
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
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run the grammar configs and the isolated custom policy config once.

    Custom policies retain their authored severity and every reported ID:
    built-in counting/calibration must not silently weaken project policies.
    Rules whose category is skipped (--skip) are not emitted.

    ``errors`` collects any scan that could not complete, so the caller can
    report a partial run rather than a clean one (#111)."""
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in sorted(rule_dir.glob("sgconfig-*.yml")):
        lang = config.stem.removeprefix("sgconfig-")
        custom = lang == "custom"
        counters = scan_config(config, paths, sink, lang,
                               None if custom else severity_overrides, ast_grep_bin,
                               None if custom else count_only, skip_categories, errors)
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
