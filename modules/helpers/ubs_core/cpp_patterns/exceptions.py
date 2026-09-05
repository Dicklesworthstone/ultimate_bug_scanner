"""ubs_core.cpp_patterns.exceptions — category 2 rg-pipeline subset (bead 0xjg.9).

Faithful ports of the CATEGORY 2 rg pipelines (modules/ubs-cpp.sh 3128-3137).
The ast-grep halves (cpp.throw-in-destructor, cpp.throw-raw-value,
cpp.throw-string) run through the consolidated rule pack.
"""
from __future__ import annotations

import re

from ubs_core.cpp_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=2,
        rule_id="cpp.exceptions.catch-by-value",
        title="Catching exceptions by value",
        # legacy: rg catch(...) shape + `grep -v "&"` post-filter
        regex=re.compile(
            r"catch[ \t]*\([ \t]*[A-Za-z_:][A-Za-z0-9_:<>]*[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\)"
        ),
        thresholds=((0, "warning"),),
        exclude_regex=re.compile(r"&"),
    ),
    Pattern(
        category=2,
        rule_id="cpp.exceptions.dynamic-exception-spec",
        title="Deprecated 'throw(...)' found",
        # legacy: `throw[[:space:]]*\([[:space:]]*[^)]`, warning >0
        regex=re.compile(r"throw[ \t]*\([ \t]*[^)]"),
        thresholds=((0, "warning"),),
    ),
]
