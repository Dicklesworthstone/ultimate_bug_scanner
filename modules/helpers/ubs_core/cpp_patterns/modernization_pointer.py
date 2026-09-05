"""ubs_core.cpp_patterns.modernization_pointer — categories 4-5 (bead 0xjg.9).

Faithful ports of the CATEGORY 4 MODERNIZATION rg pipelines
(modules/ubs-cpp.sh 3180-3197) and the CATEGORY 5 POINTER & LIFETIME
heuristics (3208-3218).
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 4: MODERNIZATION (C++20+) ──────────────────────────────────
    Pattern(
        category=4,
        rule_id="cpp.modernization.using-namespace-std",
        title="using namespace std found",
        # legacy: `using[[:space:]]+namespace[[:space:]]+std`, warning >0
        regex=re.compile(r"using[ \t]+namespace[ \t]+std"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=4,
        rule_id="cpp.modernization.auto-ptr",
        title="std::auto_ptr used (removed)",
        # legacy: `std::auto_ptr<`, critical >0
        regex=re.compile(r"std::auto_ptr<"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=4,
        rule_id="cpp.modernization.std-bind",
        title="std::bind present - lambdas are clearer",
        # legacy: `std::bind[[:space:]]*\(`, info >0
        regex=re.compile(r"std::bind[ \t]*\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=4,
        rule_id="cpp.modernization.cpp-modules",
        title="C++20 Modules in use - verify partition & BMI strategy",
        # legacy: `^[[:space:]]*module;|^[[:space:]]*export[[:space:]]+module`, info >0
        regex=re.compile(r"(?m)^[ \t]*(?:module;|export[ \t]+module)"),
        thresholds=((0, "info"),),
    ),
    # ── Category 5: POINTER & LIFETIME HAZARDS ──────────────────────────────
    Pattern(
        category=5,
        rule_id="cpp.pointer-lifetime.string-view-temporary",
        title="Potential dangling string_view (heuristic)",
        # legacy: `std::string_view[[:space:]]*\(` + `grep -v "&"`, warning >0
        regex=re.compile(r"std::string_view[ \t]*\("),
        thresholds=((0, "warning"),),
        exclude_regex=re.compile(r"&"),
    ),
    Pattern(
        category=5,
        rule_id="cpp.pointer-lifetime.return-reference",
        title="Return by reference - verify lifetime",
        # legacy: `return[[:space:]]*&[[:space:]]*[A-Za-z_]`, warning >0
        regex=re.compile(r"return[ \t]*&[ \t]*[A-Za-z_]"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=5,
        rule_id="cpp.pointer-lifetime.move-const",
        title="std::move(const T) is a copy, not a move",
        # legacy: `std::move[[:space:]]*\([^)]*\bconst\b`, warning >0
        regex=re.compile(r"std::move[ \t]*\([^)]*\bconst\b"),
        thresholds=((0, "warning"),),
    ),
]
