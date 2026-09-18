"""ubs_core.elixir_ast — consolidated ast-grep rule-pack scanning (bead 1b9j.5)."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable, Sequence

MARKER = "ubs:ignore"
_ASTGREP_BIN = "ast-grep"
_BATCH = 400


def _map_severity(raw: str) -> str:
    raw = (raw or "").lower().strip()
    if raw in ("critical", "error", "fatal"):
        return "critical"
    if raw in ("info", "note", "hint"):
        return "info"
    return "warning"


def _file_lines(path: Path, cache: dict[Path, list[str]]) -> list[str]:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            cache[path] = []
    return cache[path]


def _has_marker(path: Path, line_no: int, cache: dict[Path, list[str]]) -> bool:
    lines = _file_lines(path, cache)
    idx = line_no - 1
    return (0 <= idx < len(lines) and MARKER in lines[idx]) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    count_only: set[str] | None = None,
    skip: set[int] | None = None,
    rule_category: dict[str, int] | None = None,
    slug_for_rule: Callable[[int], str] | None = None,
    base_dir: Path | None = None,
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
    cache: dict[Path, list[str]] = {}
    seen: set[tuple[str, str, int, int]] = set()
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
            rng = match.get("range", {}).get("start", {})
            path = Path(file_str)
            line_no = int(rng.get("line", 0)) + 1
            col_no = int(rng.get("column", 0)) + 1
            source_path = str(path.resolve())
            key = (rule_id, source_path, line_no, col_no)
            if key in seen:
                continue
            seen.add(key)
            if count_only is not None and rule_id not in count_only:
                continue
            category = rule_category.get(rule_id) if rule_category else None
            if skip and category is not None and category in skip:
                continue
            if _has_marker(path, line_no, cache):
                continue
            raw_severity = str(match.get("severity", "")).lower().strip()
            default_severity = _map_severity(raw_severity)
            severity = (severity_overrides or {}).get(rule_id) or default_severity
            if severity not in counters:
                severity = "warning"
            counters[severity] = counters.get(severity, 0) + 1
            category_slug = slug_for_rule(category) if slug_for_rule and category else None
            message = str(match.get("message", "")).strip() or rule_id
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"elixir.{category_slug}" if category_slug else rule_id,
                "path": source_path,
                "line": line_no,
                "col": col_no,
                "severity": severity,
                "message": message[:300],
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
    skip: set[int] | None = None,
    rule_category: dict[str, int] | None = None,
    slug_for_rule: Callable[[int], str] | None = None,
    base_dir: Path | None = None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run every sgconfig-*.yml in rule_dir; aggregate counters.

    ``errors`` collects any scan that could not complete, so the caller can
    report a partial run rather than a clean one (#111).
    """
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in sorted(rule_dir.glob("sgconfig-*.yml")):
        counters = scan_config(
            config, paths, sink, severity_overrides, ast_grep_bin,
            count_only, skip, rule_category, slug_for_rule, base_dir, errors,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
