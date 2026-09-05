"""ubs_core.cpp_patterns.debug — category 15 (bead 0xjg.9).

Faithful ports of the CATEGORY 15 TEST/DEBUG LEFTOVERS pipelines
(modules/ubs-cpp.sh 3481-3486).
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=15,
        rule_id="cpp.debug.assert-abort",
        title="Many asserts/abort calls - ensure controlled by NDEBUG",
        # legacy: `\bassert\s*\(|\babort\s*\(`, warning >50
        regex=re.compile(r"\bassert\s*\(|\babort\s*\("),
        thresholds=((50, "warning"),),
    ),
    Pattern(
        category=15,
        rule_id="cpp.debug.cout-cerr",
        title="Many std::cout/cerr statements - consider a logging library",
        # legacy: `std::cout|std::cerr`, info >50
        regex=re.compile(r"std::cout|std::cerr"),
        thresholds=((50, "info"),),
    ),
]
