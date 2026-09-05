"""ubs_core.cpp_patterns.ub_zone — category 7 rg-pipeline subset (bead 0xjg.9).

Faithful ports of the simple rg pipelines in CATEGORY 7 (modules/ubs-cpp.sh
3253-3281). The heredoc detectors of the same category live in
ubs_core.cpp_detectors (archive entry, weak randomness, header injection,
outbound URL); the taint analyzers (traversal, redirect) come from the
registered ubs_core cpp analyzers.
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=7,
        rule_id="cpp.undefined-behavior.unsafe-c-apis",
        title="Unsafe C APIs present",
        # legacy: `\b(gets|strcpy|strcat|sprintf|scanf)\s*\(`, critical >0
        regex=re.compile(r"\b(gets|strcpy|strcat|sprintf|scanf)\s*\("),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=7,
        rule_id="cpp.undefined-behavior.shell-exec",
        title="Shell command execution API used",
        # legacy: `\b(std::)?system\s*\(|\bpopen\s*\(|\bShellExecute(A|W)?\s*\(`,
        # critical >0
        regex=re.compile(r"\b(std::)?system\s*\(|\bpopen\s*\(|\bShellExecute(A|W)?\s*\("),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=7,
        rule_id="cpp.undefined-behavior.low-level-casts",
        title="Many low-level casts - scrutinize for UB",
        # legacy: `reinterpret_cast<|const_cast<`, warning >5
        regex=re.compile(r"reinterpret_cast<|const_cast<"),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="cpp.undefined-behavior.delete-mismatch",
        title="Verify delete/delete[] matches allocation form",
        # legacy: `(^|[^A-Za-z0-9_])delete[[:space:]]*(\[\])?[[:space:]]*[A-Za-z_][A-Za-z0-9_]*`,
        # info >2
        regex=re.compile(r"(?m)(^|[^A-Za-z0-9_])[ \t]*delete[ \t]*(\[\])?[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((2, "info"),),
    ),
]
