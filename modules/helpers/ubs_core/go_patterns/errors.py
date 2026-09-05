r"""ubs_core.go_patterns.errors — category 6 regex checks (bead 0xjg.6).

Faithful ports of the legacy rg pipelines in modules/ubs-golang.sh 5234-5305:
- blank-identifier discards (5240).
- fmt.Errorf without %w when wrapping err (5284-5291): the legacy pipeline is
  `rg "fmt\.Errorf\(" | grep -v "%w" | grep -E "err[),]" | count_lines` — the
  exclusion and requirement are per-line post-filters, expressed here as
  exclude_regex/require_regex.
"""
from __future__ import annotations

import re

from ubs_core.go_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=6,
        rule_id="go.error-handling.blank-discards",
        title="Assignments discarding secondary return values (could be error)",
        # legacy grep_count_scoped ",[[:space:]]*_[[:space:]]*:=" (5240)
        regex=re.compile(r",[ \t]*_[ \t]*:="),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=6,
        rule_id="go.error-handling.errorf-no-wrap",
        title="Consider using %w when wrapping errors",
        # legacy pipeline at 5284-5291
        regex=re.compile(r"fmt\.Errorf\("),
        exclude_regex=re.compile(r"%w"),
        require_regex=re.compile(r"err[),]"),
        thresholds=((0, "info"),),
    ),
]
