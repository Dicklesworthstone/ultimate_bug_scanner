"""ubs_core.csharp_ast — consolidated ast-grep rule-pack scanning (bead 0xjg.12).

Runs the single sgconfig produced by `ubs_core.csharp_rules.generate` (one
`ast-grep scan -c <config> --json=stream` invocation per path batch), parses
the stream once, and appends normalized records to the same NDJSON findings
sink the pattern/detector layers use. Mirrors the legacy cat-17 ingestion
(category_17_ast_grep_pack + ast_scan_json_to_tsv, ubs-csharp.sh 615-717,
3244-3322):

- dedup by (rule_id, display path, line, col) — the legacy parser's ``seen``
  set, applied across the whole scan (all batches);
- exact public rule suppression at the source statement interval;
- severity from the module's AST_RULE_SEVERITY table (passed as
  ``severity_overrides``) normalized through the legacy tier map;
- every pack rule counted (no ``count_only`` gate — legacy cat 17 ingested
  the whole scan).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.external_tools import ast_rule_configs, scan_ast_config

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)


def _map_severity(raw: str) -> str:
    """Legacy parser severity map (normalize_ast_severity, 606-613)."""
    raw = (raw or "").lower().strip()
    if raw in ("critical", "error", "fatal"):
        return "critical"
    if raw in ("info", "note", "hint"):
        return "info"
    return "warning"


def scan_config(
    config: Path,
    paths: Sequence[Path],
    sink,
    severity_overrides: dict[str, str] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    count_only: set[str] | None = None,
    skip: set[int] | None = None,
    rule_category: dict[str, int] | None = None,
    slug_for_rule: Callable[[str], str] | None = None,
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
    suppressions = SourceSuppressions("csharp")
    seen: set[tuple[str, str, int, int]] = set()
    for match in scan_ast_config(config, path_list, errors,
                                 ast_grep_bin=ast_grep_bin, batch_size=_BATCH):
        rule_id, file_str = match["ruleId"], match["file"]
        rng = match["range"]["start"]
        path = Path(file_str)
        line_no, col_no = rng["line"] + 1, rng["column"] + 1
        # Distinct files can have the same project-relative display path.
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
        if suppressions.is_suppressed(path, line_no, rule_id):
            continue
        if match["severity"] == "off":
            continue
        severity = (severity_overrides or {}).get(rule_id) or _map_severity(match["severity"])
        if severity not in counters:
            severity = "warning"
        counters[severity] = counters.get(severity, 0) + 1
        category_slug = slug_for_rule(category) if slug_for_rule and category else None
        message = match.get("message", "").strip() or rule_id
        sink.write(json.dumps({
            "rule": rule_id,
            "category_id": f"csharp.{category_slug}" if category_slug else rule_id,
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
    slug_for_rule: Callable[[str], str] | None = None,
    base_dir: Path | None = None,
    errors: list[str] | None = None,
) -> dict[str, int]:
    """Run every sgconfig-*.yml in rule_dir; aggregate counters.

    ``errors`` collects any scan that could not complete, so the caller can
    report a partial run rather than a clean one (#111).
    """
    total = {"critical": 0, "warning": 0, "info": 0}
    for config in ast_rule_configs(rule_dir, paths, errors):
        counters = scan_config(
            config, paths, sink, severity_overrides, ast_grep_bin,
            count_only, skip, rule_category, slug_for_rule, base_dir, errors,
        )
        for key, value in counters.items():
            total[key] = total.get(key, 0) + value
    return total
