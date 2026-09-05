"""ubs_core.cpp_patterns.numeric — category 6 (bead 0xjg.9).

Faithful ports of the CATEGORY 6 NUMERIC & ARITHMETIC pipelines
(modules/ubs-cpp.sh 3229-3242).
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=6,
        rule_id="cpp.numeric.division-by-variable",
        title="Division by variable - add guards",
        # legacy: `/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*` minus lines matching
        # `/[[:space:]]*(2|10|100|1000)\b|//|/\*`, warning >15
        regex=re.compile(r"/[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((15, "warning"),),
        exclude_regex=re.compile(r"/[ \t]*(2|10|100|1000)\b|//|/\*"),
    ),
    Pattern(
        category=6,
        rule_id="cpp.numeric.float-equality",
        title="Floating-point equality - prefer epsilon comparison",
        # legacy: `==[[:space:]]*[0-9]+\.[0-9]+`, info >3
        regex=re.compile(r"==[ \t]*[0-9]+\.[0-9]+"),
        thresholds=((3, "info"),),
    ),
    Pattern(
        category=6,
        rule_id="cpp.numeric.modulo-by-variable",
        title="Modulo by variable - ensure non-zero",
        # legacy: `%[[:space:]]*[A-Za-z_][A-Za-z0-9_]*`, info >10
        regex=re.compile(r"%[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((10, "info"),),
    ),
]
