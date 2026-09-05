"""ubs_core.cpp_patterns.memory_raii — category 1 rg-pipeline subset (bead 0xjg.9).

Faithful ports of the CATEGORY 1 rg pipelines (modules/ubs-cpp.sh 3087-3108).
The ast-grep halves of the category (cpp.raw-new, cpp.raw-new-array,
cpp.c-style-cast) run through the consolidated rule pack in
ubs_core.cpp_rules / ubs_core.js_ast.scan_all.
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=1,
        rule_id="cpp.memory-raii.manual-delete",
        title="Manual delete/delete[] present",
        # legacy: `(^|[^A-Za-z0-9_])delete[[:space:]]*(\[\])?`, critical >0
        regex=re.compile(r"(?m)(^|[^A-Za-z0-9_])[ \t]*delete[ \t]*(\[\])?"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=1,
        rule_id="cpp.memory-raii.dangerous-casts",
        title="Dangerous casts present",
        # legacy: `const_cast<|reinterpret_cast<`, warning >0
        regex=re.compile(r"const_cast<|reinterpret_cast<"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=1,
        rule_id="cpp.memory-raii.null-macro",
        title="Use nullptr in C++ code",
        # legacy: `\bNULL\b`, info >0
        regex=re.compile(r"\bNULL\b"),
        thresholds=((0, "info"),),
    ),
]
