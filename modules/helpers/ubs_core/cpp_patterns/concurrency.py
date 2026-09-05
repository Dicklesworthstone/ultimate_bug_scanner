"""ubs_core.cpp_patterns.concurrency — category 3 rg-pipeline subset (bead 0xjg.9).

Faithful ports of the CATEGORY 3 rg pipelines (modules/ubs-cpp.sh 3154-3167).
run_async_error_checks lives in ubs_core.cpp_detectors.async_errors.
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=3,
        rule_id="cpp.concurrency.manual-lock",
        title="Manual lock/unlock usage",
        # legacy: `\.lock\(|\.unlock\(`, warning >0
        regex=re.compile(r"\.lock\(|\.unlock\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="cpp.concurrency.async-no-policy",
        title="Async without policy (behavior may vary)",
        # legacy: `std::async[[:space:]]*\(` + `grep -v "std::launch::"`, info >0
        regex=re.compile(r"std::async[ \t]*\("),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r"std::launch::"),
    ),
    Pattern(
        category=3,
        rule_id="cpp.concurrency.weak-memory-order",
        title="Weak memory order in atomics - verify correctness",
        # legacy: `memory_order_relaxed|memory_order_consume`, info >0
        regex=re.compile(r"memory_order_relaxed|memory_order_consume"),
        thresholds=((0, "info"),),
    ),
]
