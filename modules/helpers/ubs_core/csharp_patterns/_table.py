"""ubs_core.csharp_patterns._table — shared Pattern row helper (bead 0xjg.12).

The orchestrator (ubs_core.csharp_scan) owns the frozen Pattern dataclass;
pattern modules build rows with this lightweight record so importing the
orchestrator from a pattern module would be circular.
"""
from __future__ import annotations

import re
from typing import NamedTuple


class P(NamedTuple):
    category: int
    rule_id: str
    seq: int
    label: str
    text: str  # legacy summary line, "{n}" = hit count
    regex: re.Pattern[str]
    severity: str
    exclude_regex: re.Pattern[str] | None = None  # legacy `grep -v` post-filter
    gate_regex: re.Pattern[str] | None = None  # legacy project-wide precondition
    needs_no_ast: bool = False  # legacy skips when the ast-grep pack ran (cat 20)
