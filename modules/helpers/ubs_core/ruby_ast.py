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

Suppression: same-line + previous-line `ubs:ignore` checks (the legacy
run_async_error_checks parser semantics, ubs-ruby.sh 3377-3391); the A7
statement-interval engine in the meta-runner postprocess layers the richer
placements on top.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from ubs_core.ruby_scan import MARKER

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


def _lines_for(path: Path, cache: dict[Path, list[str]]) -> list[str]:
    return _file_lines(path, cache)


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
    if not path_list:
        return counters
    if not config.is_file():
        if errors is not None:
            errors.append(f"Ruby AST configuration is missing: {config}")
            return counters
        raise RuntimeError(f"Ruby AST configuration is missing: {config}")
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
        except (OSError, subprocess.TimeoutExpired) as exc:
            if errors is not None:
                errors.append(f"Ruby AST scan could not run with {config.name}: {exc}")
                continue
            raise RuntimeError(f"Ruby AST scan could not run with {config}: {exc}") from exc
        # `ast-grep scan` exits 0 with no error-level diagnostics and 1 when it
        # found some; anything else is a failed invocation.
        if proc.returncode not in (0, 1):
            detail = (proc.stderr or "").strip()
            if errors is not None:
                errors.append(
                    f"Ruby AST scan failed with {config.name} (exit {proc.returncode})"
                    + (f": {detail.splitlines()[0][:160]}" if detail else "")
                )
            else:
                raise RuntimeError(
                    f"Ruby AST scan failed with {config} (exit {proc.returncode}): {detail}"
                )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                match = json.loads(line)
            except json.JSONDecodeError as exc:
                if errors is not None:
                    errors.append(f"Ruby AST scan returned invalid JSON with {config.name}: {exc}")
                    continue
                raise RuntimeError(f"Ruby AST scan returned invalid JSON with {config}: {exc}") from exc
            if not isinstance(match, dict):
                if errors is not None:
                    errors.append(f"Ruby AST scan returned a non-object finding with {config.name}")
                    continue
                raise RuntimeError(f"Ruby AST scan returned a non-object finding with {config}")
            rule_id = str(match.get("ruleId", "") or match.get("rule_id", ""))
            file_str = str(match.get("file", "") or match.get("path", ""))
            if not rule_id or not file_str:
                continue
            counted = counted_rules is None or rule_id in counted_rules
            category = (category_map or {}).get(rule_id, 18)
            if skip and category in skip:
                continue  # --skip applies to counted and report-only rules.
            rng = match.get("range", {}).get("start", {})
            path = Path(file_str)
            line_no = int(rng.get("line", 0)) + 1  # ast-grep rows are 0-based
            # Legacy parser severity: YAML tier mapped at parse time; the
            # SEVERITY_MAP override wins (ubs-ruby.sh 3366-3369 defaults).
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
            if _has_marker(path, line_no, cache):
                continue  # legacy line + previous-line marker check
            if counted:
                counters[severity] = counters.get(severity, 0) + 1
            message = str(match.get("message", "")).strip() or rule_id
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": rule_id.rsplit(".", 1)[0] if "." in rule_id else rule_id,
                "path": file_str,
                "line": line_no,
                "col": int(rng.get("column", 0)) + 1,
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
    for config in sorted(rule_dir.glob("sgconfig-*.yml")):
        counters = scan_config(
            config, paths, sink, severity_overrides, ast_grep_bin,
            counted_rules, category_map, skip, errors,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
