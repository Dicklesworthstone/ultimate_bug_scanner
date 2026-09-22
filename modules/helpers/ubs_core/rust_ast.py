"""Consolidated Rust ast-grep scanning with complete, structured evidence.

The rule pack runs once per path batch. Three patterns use ``run --pattern``
so nested occurrences remain visible; they use the same validated NDJSON
boundary rather than parsing human-oriented colon-separated output. Callers
retain the legacy rule consumption, source selection and suppression logic.
"""
from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Sequence

from ubs_core.external_tools import parse_ast_diagnostics, run_command, scan_ast_config

_ASTGREP_BIN = "ast-grep"
_BATCH = 400


def _normalize_match(match: dict) -> dict:
    start = match["range"]["start"]
    return {
        "rule": match["ruleId"], "path": match["file"],
        "line": start["line"] + 1, "col": start["column"] + 1,
        "text": match.get("text", "").strip(),
    }


def _parse_stream(text: str, errors: list[str] | None = None) -> list[dict]:
    return [_normalize_match(match) for match in parse_ast_diagnostics(text, errors)
            if match["severity"] != "off"]


def _parse_run_output(text: str, rule_id: str, errors: list[str] | None = None) -> list[dict]:
    return [_normalize_match(match) for match in parse_ast_diagnostics(
        text, errors, context=f"ast-grep ({rule_id})", run_rule_id=rule_id,
    )]


def _run_spawn_patterns(path_list: list[str], ast_grep_bin: str, batch: int,
                        errors: list[str] | None = None) -> tuple[Counter, dict[str, list[dict]]]:
    """Run nested-match patterns, retaining valid output even on failure."""
    from ubs_core.rust_rules import RUN_MODE_RULES

    counts: Counter = Counter()
    matches: dict[str, list[dict]] = {}
    failures = errors if errors is not None else []
    if type(batch) is not int or batch <= 0:
        raise ValueError("AST batch size must be a positive integer")
    executable = os.environ.get("UBS_AST_GREP_BIN") or ast_grep_bin
    for slug, pattern in RUN_MODE_RULES.items():
        rule_id = f"rust.ast.{slug}"
        seen: set[tuple] = set()
        for start in range(0, len(path_list), batch):
            output = run_command(
                "ast-grep", [executable, "run", "--pattern", pattern, "-l", "rust",
                             "--json=stream", "--", *path_list[start:start + batch]],
                Path.cwd(), 600, failures, strict_utf8=True,
            )
            if output is None:
                continue
            # run: 0 = matches, 1 = no matches; scan has different severity
            # semantics, but both reject exit statuses outside this pair.
            if output.returncode not in (0, 1):
                detail = output.stderr.strip().splitlines()
                failures.append(
                    f"ast-grep exited {output.returncode} on pattern {rule_id}"
                    + (f": {detail[0][:160]}" if detail else "")
                )
            for match in _parse_run_output(output.stdout, rule_id, failures):
                # Nested expressions may start at the very same column.
                # Their different matched spans are independent evidence.
                key = (match["path"], match["line"], match["col"], match["text"])
                if key in seen:
                    continue
                seen.add(key)
                counts[rule_id] += 1
                matches.setdefault(rule_id, []).append(match)
    if errors is None and failures:
        raise RuntimeError("; ".join(failures))
    return counts, matches


def scan_all(rule_dir: Path, paths: Sequence[Path], ast_grep_bin: str = _ASTGREP_BIN,
             batch: int = _BATCH,
             errors: list[str] | None = None) -> tuple[Counter, dict[str, list[dict]]]:
    """Return rule tallies and matches; incomplete coverage never becomes clean."""
    counts: Counter = Counter()
    matches: dict[str, list[dict]] = {}
    path_list = [Path(p) for p in paths]
    for diagnostic in scan_ast_config(Path(rule_dir) / "sgconfig-rust.yml", path_list, errors,
                                      ast_grep_bin=ast_grep_bin, batch_size=batch):
        if diagnostic["severity"] == "off":
            continue
        match = _normalize_match(diagnostic)
        counts[match["rule"]] += 1
        matches.setdefault(match["rule"], []).append(match)
    # RUN_MODE_RULES are defined in code, not in manifest.json. Losing an
    # optional reporting manifest must not silently disable these checks.
    if path_list:
        spawn_counts, spawn_matches = _run_spawn_patterns(
            [str(p) for p in path_list], ast_grep_bin, batch, errors,
        )
        counts.update(spawn_counts)
        for rule_id, entries in spawn_matches.items():
            matches.setdefault(rule_id, []).extend(entries)
    return counts, matches
