"""ubs_core.java_patterns.resource_lifecycle — category 19 rg pipelines (bead 0xjg.8).

The cat-19 I/O constructor census (modules/ubs-java.sh 3930-3936). The
executor-shutdown subcheck and the ast rule group live in java_detectors
.resource_leaks and the counted ast layer respectively.
"""
from __future__ import annotations

import re

from ubs_core.java_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=19,
        rule_id="java.resource-lifecycle.io-ctors",
        title="I/O constructors present - ensure try-with-resources",
        regex=re.compile(
            r"new[ \t]+(File(Input|Output)Stream|FileReader|FileWriter"
            r"|Buffered(Input|Output)Stream|Buffered(Reader|Writer)"
            r"|InputStreamReader|OutputStreamWriter|PrintWriter|Scanner)[ \t]*\("
        ),
        thresholds=((0, "info"),),
    ),
]
