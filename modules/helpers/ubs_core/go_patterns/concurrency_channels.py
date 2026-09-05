"""ubs_core.go_patterns.concurrency_channels — categories 1-2 (bead 0xjg.6).

Faithful ports of the legacy rg pipelines in modules/ubs-golang.sh:
- CATEGORY 1 (4942-4996): goroutine launch census (4951).
- CATEGORY 2 (5001-5031): select census (5007). The time.After-in-loop check
  is an AST-count-gated regex window — computed_checks in go_scan.
"""
from __future__ import annotations

import re

from ubs_core.go_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=1,
        rule_id="go.concurrency.goroutine-launches",
        title="goroutine launches found",
        # legacy grep_count_scoped "^[[:space:]]*go[[:space:]]+" (4951)
        regex=re.compile(r"(?m)^[ \t]*go[ \t]+"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=2,
        rule_id="go.channels.select-statements",
        title="select statements present",
        # legacy grep_count_scoped "^[[:space:]]*select[[:space:]]*\{" (5007)
        regex=re.compile(r"(?m)^[ \t]*select[ \t]*\{"),
        thresholds=((0, "info"),),
    ),
]
