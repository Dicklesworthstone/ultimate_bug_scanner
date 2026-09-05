"""ubs_core.go_patterns.json_fs — categories 7-8 regex checks (bead 0xjg.6).

Faithful ports of the legacy rg pipelines in modules/ubs-golang.sh:
- CATEGORY 7 (5506-5525): json.Unmarshal census (5520). The other two checks
  are ast-grep rules.
- CATEGORY 8 (5527-5553): io.ReadAll census with the >10 threshold (5537).
  The os.Open/Close ratio is a computed check in go_scan.
"""
from __future__ import annotations

import re

from ubs_core.go_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=7,
        rule_id="go.json-encoding.unmarshal-census",
        title="json.Unmarshal found - ensure errors handled and input validated",
        # legacy grep_count_scoped "json\.Unmarshal\(" (5520)
        regex=re.compile(r"json\.Unmarshal\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=8,
        rule_id="go.filesystem.readall-census",
        title="Many ReadAll calls - ensure bounded inputs",
        # legacy grep_count_scoped "io\.ReadAll\(" with >10 info (5537)
        regex=re.compile(r"io\.ReadAll\("),
        thresholds=((10, "info"),),
    ),
]
