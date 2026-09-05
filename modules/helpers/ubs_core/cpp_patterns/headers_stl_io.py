"""ubs_core.cpp_patterns.headers_stl_io — categories 8-10 rg subset (bead 0xjg.9).

Faithful ports of the simple rg pipelines in CATEGORY 8 (C headers,
modules/ubs-cpp.sh 3308-3309), CATEGORY 9 (STL, 3332-3337) and CATEGORY 10
(printf family, 3349-3352). The header-guard loop, the header-scoped
using-namespace check and std::endl (ast-grep cpp.std-endl) live in
ubs_core.cpp_detectors.header_hygiene and the rule pack respectively.
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 8: HEADER & INCLUDE HYGIENE ────────────────────────────────
    Pattern(
        category=8,
        rule_id="cpp.headers.c-std-headers",
        title="Prefer <cstdio>/<cstdlib>/<cstring>/<cmath>",
        # legacy: `#include[[:space:]]*<(stdio|stdlib|string|math)\.h>`, info >0
        regex=re.compile(r"#include[ \t]*<(stdio|stdlib|string|math)\.h>"),
        thresholds=((0, "info"),),
    ),
    # ── Category 9: STL & ALGORITHMS ────────────────────────────────────────
    Pattern(
        category=9,
        rule_id="cpp.stl.erase-iteration",
        title="Verify loop structure when erasing from containers",
        # legacy:
        # `\.erase\([[:space:]]*[A-Za-z_]|\.erase\([[:space:]]*begin|\.erase\([[:space:]]*end`,
        # info >0
        regex=re.compile(
            r"\.erase\([ \t]*[A-Za-z_]|\.erase\([ \t]*begin|\.erase\([ \t]*end"
        ),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=9,
        rule_id="cpp.stl.manual-loops",
        title="Consider ranges/algorithms instead of index loops",
        # legacy: `for[[:space:]]*\([^)]+;[^)^:]*;[^\)]+\)`, info >20
        regex=re.compile(r"for[ \t]*\([^)]+;[^)^:]*;[^\)]+\)"),
        thresholds=((20, "info"),),
    ),
    # ── Category 10: STRING & I/O SAFETY ────────────────────────────────────
    Pattern(
        category=10,
        rule_id="cpp.string-io.c-format-apis",
        title="C-format APIs in C++",
        # legacy: `\b(printf|fprintf|sprintf|snprintf|scanf|sscanf)\s*\(`, info >0
        regex=re.compile(r"\b(printf|fprintf|sprintf|snprintf|scanf|sscanf)\s*\("),
        thresholds=((0, "info"),),
    ),
]
