r"""ubs_core.py_patterns.io_files — category 16 I/O & RESOURCE SAFETY (bead 0xjg.5).

Faithful ports of the single-regex legacy rg pipelines in modules/ubs-python.sh:
- CATEGORY 16 (11658-11663): open() without explicit encoding — `open\([^)]*\)`
  minus a `grep -v "encoding[[:space:]]*="` post-filter, info when >0.
- CATEGORY 16 (11665-11669): shutil.rmtree(ignore_errors=True), info when >0.

The open()-vs-with-open ratio check (11648-11656) needs two project-wide
counts and therefore lives in ubs_core.py_detectors.io_open_checks.
"""
from __future__ import annotations

import re

from ubs_core.py_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 16: I/O & RESOURCE SAFETY ──────────────────────────────────
    Pattern(
        category=16,
        rule_id="py.io.open-no-encoding",
        title="open() missing encoding",
        # legacy post-filter: `grep -v "encoding[[:space:]]*="`.
        regex=re.compile(r"open\([^)]*\)"),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r"encoding[ \t]*="),
    ),
    Pattern(
        category=16,
        rule_id="py.io.rmtree-ignore-errors",
        title="rmtree(ignore_errors=True) hides failures",
        regex=re.compile(r"shutil\.rmtree\([^)]*ignore_errors\s*=\s*True"),
        thresholds=((0, "info"),),
    ),
]
