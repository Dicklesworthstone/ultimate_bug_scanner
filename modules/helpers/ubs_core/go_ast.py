"""ubs_core.go_ast — consolidated ast-grep rule-pack scanning for Go (bead 0xjg.6).

Runs the sgconfigs produced by `ubs_core.go_rules.generate` (one
`ast-grep scan -c <config> --json=stream` invocation per path batch per
config — the main pack plus the single-rule async pack), parses each stream
once, and feeds the same NDJSON findings sink the pattern/detector/analyzers
layers use. Replaces the legacy single `ast-grep scan -c … --json` cache
(`ensure_ast_scan_json`, ubs-golang.sh 2878-2907) whose per-rule counts were
re-derived by the `ast_count` python walk (2910-2946).

Suppression parity: the legacy `ast_count` walk has NO ubs:ignore awareness
and neither does this layer — marker suppression for Go happens inside the
python detectors and the rg `count_lines` filter, and the A7 statement-
interval engine in the meta-runner postprocess strips annotated lines from
the rendered text (documented legacy invariant, ubs-golang.sh 7538-7539).

Counting parity: legacy text severities are hardcoded per callsite, so the
consumption table below (rule id -> [(category, severity, title), …]) drives
emission. Rules consumed in several categories (go.sql.begin-without-defer-
rollback in 5+21; the three defer-before-err rules in 4/5+20) emit one record
per match per consumption entry, matching the legacy double counting. Rules
handled by go_scan computed checks (AST-count-gated fallbacks: tls-insecure-
skip, exec-sh-c, time-after-in-loop, http-response-body-not-closed,
sql-rows-not-closed) are NOT emitted here; their matches are returned to the
caller. Orphan rules (generated but never printed by any category) surface
only in the category-16 tally, also returned to the caller.
"""
from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Sequence

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)

# Rules whose records are emitted by go_scan computed checks instead of here.
COMPUTED_RULES = frozenset({
    "go.tls-insecure-skip",
    "go.exec-sh-c",
    "go.time-after-in-loop",
    "go.http-response-body-not-closed",
    "go.sql.rows-not-closed",
})


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
            "text": str(match.get("text", "") or match.get("snippet", "")).strip(),
        })
    return matches


def scan_config(
    config: Path,
    paths: Sequence[Path],
    consumption: dict[str, list[tuple[int, str, str]]],
    sink,
    skip: set[int] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    slug_for_category=None,
) -> tuple[Counter, dict[str, list[dict]]]:
    """Run one sgconfig over the path list.

    Returns (rule-id match tally, rule-id -> match list). Records for rules
    in ``consumption`` are appended to the sink (one record per match per
    consumption entry), unless the entry's category is in ``skip``. Tally and
    matches cover every rule the config reports regardless of skip — they
    feed the category-16 inventory tally and the computed checks, exactly as
    the legacy AST_JSON cache did.
    """
    counts: Counter = Counter()
    matches: dict[str, list[dict]] = {}
    path_list = [Path(p) for p in paths]
    if not path_list or not config.is_file():
        return counts, matches
    slug = slug_for_category or (lambda category: f"cat{category}")
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
            continue  # legacy: scan failures degraded to "AST rules disabled"
        for match in _parse_stream(proc.stdout):
            rule_id = match["rule"]
            counts[rule_id] += 1
            matches.setdefault(rule_id, []).append(match)
            for entry in consumption.get(rule_id, []):
                category, severity, title = entry
                if skip and category in skip:
                    continue
                sink.write(json.dumps({
                    "rule": rule_id,
                    "category_id": f"golang.{slug(category)}",
                    "path": match["path"],
                    "line": match["line"],
                    "col": match["col"],
                    "severity": severity,
                    "message": f"{title}: {match['text']}"[:300] if match["text"] else title,
                    "suppressed": False,
                }, ensure_ascii=False) + "\n")
    return counts, matches


def scan_all(
    rule_dir: Path,
    paths: Sequence[Path],
    consumption: dict[str, list[tuple[int, str, str]]],
    sink,
    skip: set[int] | None = None,
    ast_grep_bin: str = _ASTGREP_BIN,
    slug_for_category=None,
) -> tuple[Counter, dict[str, list[dict]]]:
    """Run every sgconfig-*.yml in rule_dir; aggregate tally and matches.

    The category-16 inventory tally covers only the main pack
    (sgconfig-go.yml); the async single-rule config contributes matches and
    records but no tally entries, mirroring the legacy split between
    ensure_ast_scan_json (whole-pack cache) and run_async_error_checks (its
    own `scan --rule` spawn, ubs-golang.sh 632).
    """
    total: Counter = Counter()
    all_matches: dict[str, list[dict]] = {}
    for config in sorted(rule_dir.glob("sgconfig-*.yml")):
        counts, matches = scan_config(
            config, paths, consumption, sink, skip, ast_grep_bin,
            slug_for_category,
        )
        if config.name == "sgconfig-go.yml":
            total.update(counts)
        for rule_id, hits in matches.items():
            all_matches.setdefault(rule_id, []).extend(hits)
    return total, all_matches
