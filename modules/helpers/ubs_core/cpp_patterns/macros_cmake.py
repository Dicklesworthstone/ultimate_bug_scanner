"""ubs_core.cpp_patterns.macros_cmake — categories 11-12 (bead 0xjg.9).

Faithful ports of CATEGORY 11 (macros, modules/ubs-cpp.sh 3369-3374) and the
CATEGORY 12 CMake checks (3386-3409). Legacy quirk preserved: the CMake
checks ran through the same rg include-globs as every other category, so
CMakeLists.txt was never actually searched and the `count == 0` info
fallbacks always fired — the ``zero_finding`` synthetic records reproduce
that exactly (including the legacy 5-info floor on every project).
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 11: MACROS & PREPROCESSOR TRAPS ────────────────────────────
    Pattern(
        category=11,
        rule_id="cpp.macros.min-max",
        title="min/max macros detected - conflict with std::min/std::max",
        # legacy: `#[[:space:]]*define[[:space:]]+min\(|#[[:space:]]*define[[:space:]]+max\(`,
        # warning >0
        regex=re.compile(r"#[ \t]*define[ \t]+min\(|#[ \t]*define[ \t]+max\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=11,
        rule_id="cpp.macros.debug-toggles",
        title="Debug macros enabled",
        # legacy: `#[[:space:]]*define[[:space:]]+(DEBUG|TRACE|VERBOSE)`, info >0
        regex=re.compile(r"#[ \t]*define[ \t]+(DEBUG|TRACE|VERBOSE)"),
        thresholds=((0, "info"),),
    ),
    # ── Category 12: CMAKE & BUILD HYGIENE ──────────────────────────────────
    Pattern(
        category=12,
        rule_id="cpp.cmake.cxx-standard",
        title="C++ standard declarations present",
        # legacy: count >0 -> info count "C++ standard declarations present";
        # count == 0 -> info 1 "CMake lacks explicit C++ standard settings".
        regex=re.compile(r"CMAKE_CXX_STANDARD|target_compile_features"),
        thresholds=((0, "info"),),
        zero_finding=("info", 1, "CMake lacks explicit C++ standard settings"),
    ),
    Pattern(
        category=12,
        rule_id="cpp.cmake.warnings",
        title="Common warnings appear enabled",
        # legacy: count == 0 -> info 1 "No common warnings in CMake found";
        # otherwise a good note (no records, no totals).
        regex=re.compile(r"(-Wall|-Wextra|-Wpedantic)"),
        thresholds=(),
        zero_finding=("info", 1, "No common warnings in CMake found"),
    ),
    Pattern(
        category=12,
        rule_id="cpp.cmake.sanitizers",
        title="Sanitizers appear configured",
        # legacy: count == 0 -> info 1 "No sanitizers detected in CMake";
        # otherwise a good note (no records, no totals).
        regex=re.compile(r"fsanitize=(address|undefined)"),
        thresholds=(),
        zero_finding=("info", 1, "No sanitizers detected in CMake"),
    ),
    Pattern(
        category=12,
        rule_id="cpp.cmake.exceptions-flags",
        title="fno-exceptions/RTTI used - verify library requirements",
        # legacy: `fno-exceptions|fno-rtti`, info >0
        regex=re.compile(r"fno-exceptions|fno-rtti"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="cpp.cmake.pic",
        title="PIC not detected (fine for static, check for shared libs)",
        # legacy: count == 0 -> info 1 (silent when present).
        regex=re.compile(r"POSITION_INDEPENDENT_CODE|-fPIC"),
        thresholds=(),
        zero_finding=("info", 1, "PIC not detected (fine for static, check for shared libs)"),
    ),
    Pattern(
        category=12,
        rule_id="cpp.cmake.lto",
        title="LTO not detected (optional)",
        # legacy: count == 0 -> info 1 (silent when present).
        regex=re.compile(r"INTERPROCEDURAL_OPTIMIZATION|flto"),
        thresholds=(),
        zero_finding=("info", 1, "LTO not detected (optional)"),
    ),
]
