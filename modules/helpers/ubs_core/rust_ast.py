"""ubs_core.rust_ast — consolidated ast-grep scanning for Rust (bead 0xjg.7).

Runs the sgconfig produced by `ubs_core.rust_rules.generate` (one
`ast-grep scan -c … --json=stream` invocation per 400-path batch — the
PortGolang bridge precedent) and returns the per-rule match lists. Unlike the
legacy module's ~140 ad-hoc ``ast-grep run --pattern`` spawns, nothing is
emitted from here: the caller (ubs_core.rust_scan) consumes the matches in
legacy check order, applies the legacy ast_match_should_skip suppression
(source-line ``ubs:ignore``, authoritative file set, --exclude-tests
boundaries) and derives the legacy per-check counts.

Counting parity note: legacy ``count_ast_pattern_matches`` deduplicated
matches per pattern on (file, line, col) — the same key this module reports.
"""
from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Sequence

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)


def _parse_stream(text: str) -> list[dict]:
    matches: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            match = json.loads(line)
        except ValueError:
            continue
        rule_id = str(match.get("ruleId", "") or match.get("rule_id", "") or match.get("id", ""))
        file_str = str(match.get("file", "") or match.get("path", ""))
        if not rule_id or not file_str:
            continue
        rng = match.get("range", {}).get("start", {})
        matches.append({
            "rule": rule_id,
            "path": file_str,
            "line": int(rng.get("line", 0)) + 1,  # ast-grep rows are 0-based
            "col": int(rng.get("column", 0)) + 1,
            "text": str(match.get("text", "") or "").strip(),
        })
    return matches


def scan_all(rule_dir: Path, paths: Sequence[Path], ast_grep_bin: str = _ASTGREP_BIN,
             batch: int = _BATCH) -> tuple[Counter, dict[str, list[dict]]]:
    """Run sgconfig-rust.yml over the path list in batches.

    Returns (rule-id match tally, rule-id -> match list). A failed scan
    degrades to zero matches, exactly like the legacy ``run --pattern``
    spawns whose failures left every count at 0.
    """
    counts: Counter = Counter()
    matches: dict[str, list[dict]] = {}
    config = Path(rule_dir) / "sgconfig-rust.yml"
    path_list = [Path(p) for p in paths]
    if not path_list or not config.is_file():
        return counts, matches
    for start in range(0, len(path_list), batch):
        batch_paths = [str(p) for p in path_list[start : start + batch]]
        try:
            proc = subprocess.run(
                [ast_grep_bin, "scan", "-c", str(config), "--json=stream", *batch_paths],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue  # legacy: scan failures degraded to zero AST matches
        for match in _parse_stream(proc.stdout):
            counts[match["rule"]] += 1
            matches.setdefault(match["rule"], []).append(match)
    return counts, matches
