"""ubs_core.rust_ast — consolidated ast-grep scanning for Rust (bead 0xjg.7).

Runs the sgconfig produced by `ubs_core.rust_rules.generate` (one
`ast-grep scan -c … --json=stream` invocation per 400-path batch — the
PortGolang bridge precedent) and returns the per-rule match lists. Unlike the
legacy module's ~140 ad-hoc ``ast-grep run --pattern`` spawns, nothing is
emitted from here: the caller (ubs_core.rust_scan) consumes the matches in
legacy check order, applies the legacy ast_match_should_skip suppression
(source-line ``ubs:ignore``, authoritative file set, --exclude-tests
boundaries) and derives the legacy per-check counts.

Counting parity notes:
- legacy ``count_ast_pattern_matches`` deduplicated matches per pattern on
  (file, line, col) — the same key this module reports;
- three patterns behave differently under ``scan`` rules than under the
  legacy ``run --pattern`` spawns (scan suppresses matches nested inside an
  already-reported match of the same rule) — those stay on real spawns, see
  ``ubs_core.rust_rules.RUN_MODE_RULES``.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Sequence

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)

# file:line:col:code first, then file:line:code (legacy parse_ast_match_line);
# continuation lines of multi-line matches do not parse and are skipped.
_BOTH_RE = re.compile(r"^([^:\n]+):(\d+):(\d+):(.*)$")
_PLAIN_RE = re.compile(r"^([^:\n]+):(\d+):(.*)$")


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


def _parse_run_output(text: str, rule_id: str) -> list[dict]:
    matches: list[dict] = []
    for line in text.splitlines():
        m = _BOTH_RE.match(line) or _PLAIN_RE.match(line)
        if not m:
            continue
        groups = m.groups()
        if len(groups) == 4:
            path, line_no, col, code = groups
        else:
            path, line_no, code = groups
            col = "0"
        matches.append({
            "rule": rule_id,
            "path": path,
            "line": int(line_no),
            "col": int(col) + 1,
            "text": code,
        })
    return matches


def _run_spawn_patterns(path_list: list[str], rule_manifest: dict,
                        ast_grep_bin: str, batch: int) -> tuple[Counter, dict[str, list[dict]]]:
    """Legacy `ast-grep run --pattern` spawns for the run-mode-only rules."""
    from ubs_core.rust_rules import RUN_MODE_RULES

    counts: Counter = Counter()
    matches: dict[str, list[dict]] = {}
    for slug, pattern in RUN_MODE_RULES.items():
        rule_id = f"rust.ast.{slug}"
        rule_manifest.pop(rule_id, None)
        seen: set[tuple] = set()
        for start in range(0, len(path_list), batch):
            batch_paths = path_list[start : start + batch]
            try:
                proc = subprocess.run(
                    [ast_grep_bin, "run", "--pattern", pattern, "-l", "rust", *batch_paths],
                    capture_output=True, text=True, timeout=600,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue  # legacy: failing pattern spawn contributed 0
            for match in _parse_run_output(proc.stdout, rule_id):
                key = (match["path"], match["line"], match["col"])
                if key in seen:
                    continue  # legacy per-pattern (file,line,col) dedup
                seen.add(key)
                counts[rule_id] += 1
                matches.setdefault(rule_id, []).append(match)
    return counts, matches


def scan_all(rule_dir: Path, paths: Sequence[Path], ast_grep_bin: str = _ASTGREP_BIN,
             batch: int = _BATCH) -> tuple[Counter, dict[str, list[dict]]]:
    """Run sgconfig-rust.yml (plus the run-mode spawns) over the path list.

    Returns (rule-id match tally, rule-id -> match list). A failed scan
    degrades to zero matches, exactly like the legacy ``run --pattern``
    spawns whose failures left every count at 0.
    """
    counts: Counter = Counter()
    matches: dict[str, list[dict]] = {}
    config = Path(rule_dir) / "sgconfig-rust.yml"
    path_list = [str(p) for p in paths]
    if not path_list:
        return counts, matches
    if config.is_file():
        for start in range(0, len(path_list), batch):
            batch_paths = path_list[start : start + batch]
            try:
                proc = subprocess.run(
                    [ast_grep_bin, "scan", "-c", str(config), "--json=stream", *batch_paths],
                    capture_output=True, text=True, timeout=600,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue  # legacy: scan failures degraded to zero AST matches
            for match in _parse_stream(proc.stdout):
                counts[match["rule"]] += 1
                matches.setdefault(match["rule"], []).append(match)
    manifest_path = Path(rule_dir) / "manifest.json"
    rule_manifest: dict = {}
    if manifest_path.is_file():
        try:
            rule_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except ValueError:
            rule_manifest = {}
    if rule_manifest:
        spawn_counts, spawn_matches = _run_spawn_patterns(path_list, rule_manifest, ast_grep_bin, batch)
        counts.update(spawn_counts)
        for rule_id, entries in spawn_matches.items():
            matches.setdefault(rule_id, []).extend(entries)
    return counts, matches
