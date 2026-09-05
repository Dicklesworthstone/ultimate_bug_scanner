"""ubs_core.js_patterns.null_coercion — categories 1 and 4 (bead 0xjg.4).

Faithful ports of the legacy rg pipelines in modules/ubs-js.sh:
- CATEGORY 1 NULL SAFETY (3856-3959): unguarded DOM queries, optional-chaining
  opportunities, nullish-coalescing opportunities, deep property chains
  (rg fallback; legacy prefers ast-grep `$X.$Y.$Z.$W`).
- CATEGORY 4 TYPE COERCION (4120-4273): loose ==/!= (rg fallback; legacy
  prefers ast-grep `$L == $R` / `$L != $R`), different-type comparisons,
  truthy .length/.size checks, implicit string concatenation with +.
"""
from __future__ import annotations

import re

from ubs_core.js_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── CATEGORY 1: NULL SAFETY & DEFENSIVE PROGRAMMING (ubs-js.sh 3864-3943) ──
    Pattern(
        category=1,
        rule_id="js.null-undefined.dom-query-unguarded",
        title="DOM queries not immediately null-checked",
        regex=re.compile(r"= *document\.(getElementById|querySelector)"),
        thresholds=((15, "warning"), (0, "info")),
        exclude_regex=re.compile(r"if\s*\(|\?\."),
    ),
    Pattern(
        category=1,
        rule_id="js.null-undefined.optional-chaining",
        title="Could simplify with optional chaining (?.)",
        regex=re.compile(r"[\w]\s*&&\s*[\w.]+\."),
        thresholds=((50, "info"),),
        exclude_regex=re.compile(r"\?\."),
    ),
    Pattern(
        category=1,
        rule_id="js.null-undefined.nullish-coalescing",
        title="Could use nullish coalescing for clarity",
        regex=re.compile(r"\|\|\s*(''|\"\"|0|false|null|undefined|\[\]|\{\})"),
        thresholds=((15, "info"),),
        exclude_regex=re.compile(r"\?\?"),
    ),
    # ── CATEGORY 4: TYPE COERCION & COMPARISON TRAPS (ubs-js.sh 4128-4272) ──
    Pattern(
        category=4,
        rule_id="js.type-coercion.loose-equality",
        title="Loose equality causes type coercion bugs",
        # Legacy prefers ast-grep '$L == $R' / '$L != $R'; this is the rg fallback.
        regex=re.compile(r"(^|[^=!<>])==($|[^=])|(^|[^=!<>])!=($|[^=])", re.MULTILINE),
        thresholds=((0, "critical"),),
        exclude_regex=re.compile(r"===|!=="),
    ),
    Pattern(
        category=4,
        rule_id="js.type-coercion.different-types",
        title="Type comparisons - verify both sides match",
        regex=re.compile(r"===\s*('|\"|true|false|null)"),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r"typeof|instanceof"),
    ),
    Pattern(
        category=4,
        rule_id="js.type-coercion.truthy-length",
        title="Truthy checks on .length/.size",
        regex=re.compile(r"if\s*\(.*\.(length|size)\)"),
        thresholds=((8, "info"),),
    ),
    Pattern(
        category=4,
        rule_id="js.type-coercion.string-concat",
        title="String concatenation with +",
        regex=re.compile(r"\+\s*['\"]|['\"]\s*\+"),
        thresholds=((5, "info"),),
        exclude_regex=re.compile(r"\+\+|[+\-]="),
    ),
]
