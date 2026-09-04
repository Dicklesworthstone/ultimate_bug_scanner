"""ubs_core.js_patterns.eq_regex_dom — categories 2, 15, 16 (bead 0xjg.4 wave 1).

Faithful ports of the legacy rg pipelines in modules/ubs-js.sh:
- CATEGORY 2 MATH & ARITHMETIC (3961-4070, rg/rg-fallback parts only):
  global isNaN (4036-4043), floating-point equality (4045-4050),
  modulo by variable (4052-4060; rg FALLBACK of the ast-grep-primary
  `$L % $R` search), bitwise operations (4062-4069). The division-by-zero
  and direct-NaN-comparison sub-findings are ast-grep-primary with their own
  pipelines and are intentionally not pattern ports.
- CATEGORY 15 REGEX & STRING SAFETY (10661-10695): nested quantifiers /
  ReDoS (10669-10674), dynamic RegExp (10676-10680), missing escaping in
  replace() (10682-10687), case-sensitive match() (10689-10694).
- CATEGORY 16 DOM MANIPULATION (10697-10729): DOM queries (10705-10707),
  uncached DOM queries in loops (10709-10715), direct style manipulation
  (10717-10721), listeners added in loops (10723-10728).

Equivalence notes:
- All sources are GREP_RN (case-sensitive ERE), so no case_insensitive flags.
- "Uncached DOM queries in loops": the legacy pipeline
  `rg 'for|while' | grep -A5E 'querySelector|getElementById' | grep -E '...'`
  counts exactly the lines that contain BOTH a loop keyword and a DOM query:
  every for/while line carrying a query is already a direct match of the
  middle grep, and the -A5 context lines the final filter keeps are those
  same input lines. Ported as a MULTILINE-anchored composite so one line
  yields exactly one match (legacy count_lines counts lines, not hits).
- "Adding listeners in loops": legacy is
  `rg 'addEventListener' | grep -E 'forEach|map'` — the same
  line-contains-both composite.
- Bitwise: legacy excludes lines matching `//|&&|\\|\\||/\\*` via a post
  grep -v; that becomes exclude_regex. Legacy counter is plain `wc -l`
  (no ubs:ignore strip) while the engine always skips marker lines — a
  divergence only on marker-annotated bitwise lines.
- DOM queries: legacy prints its info finding unconditionally (even at 0);
  the engine is silent when a pattern has no matches.
"""
from __future__ import annotations

import re

from ubs_core.js_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 2: Math & Arithmetic Pitfalls (rg parts) ──
    Pattern(
        category=2,
        rule_id="js.equality.isnan-global",
        title="Using global isNaN() - use Number.isNaN()",
        regex=re.compile(r"(^|[^.])isNaN\("),
        thresholds=((0, "warning"),),
        exclude_regex=re.compile(r"Number\.isNaN"),
    ),
    Pattern(
        category=2,
        rule_id="js.equality.float-equality",
        title="Floating-point equality comparison",
        regex=re.compile(r"(===|==)\s*[0-9]+\.[0-9]+"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="js.equality.modulo-variable",
        title="Modulo operations - verify divisor is non-zero",
        # rg FALLBACK variant; upstream is ast-grep-primary ($L % $R).
        regex=re.compile(r"%\s*[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((10, "info"),),
    ),
    Pattern(
        category=2,
        rule_id="js.equality.bitwise-ops",
        title="Bitwise operations detected - ensure integer inputs",
        regex=re.compile(r"(^|[^<])<<([^<]|$)|(^|[^>])>>([^>]|$)|\&|\^"),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r"//|&&|\|\||/\*"),
    ),
    # ── Category 15: Regex & String Safety ──
    Pattern(
        category=15,
        rule_id="js.regex.nested-quantifiers",
        title="Nested quantifiers - ReDoS risk",
        regex=re.compile(r"\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+"),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=15,
        rule_id="js.regex.dynamic-regexp",
        title="Dynamic RegExp construction",
        regex=re.compile(r"new RegExp\("),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=15,
        rule_id="js.regex.replace-escaping",
        title="Special chars in replace - verify escaping",
        regex=re.compile(r"replace\(.*[\\*+?\[\](){}^$|]"),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r"\\"),  # legacy `grep -v '\\'`: any backslash drops the line
    ),
    Pattern(
        category=15,
        rule_id="js.regex.case-sensitive-match",
        title="Case-sensitive matching - intentional?",
        regex=re.compile(r"match\("),
        thresholds=((5, "info"),),
        exclude_regex=re.compile(r"/i|toUpperCase|toLowerCase"),
    ),
    # ── Category 16: DOM Manipulation Safety ──
    Pattern(
        category=16,
        rule_id="js.dom.queries",
        title="DOM queries found",
        regex=re.compile(r"querySelector|getElementById"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=16,
        rule_id="js.dom.queries-in-loops",
        title="DOM queries inside loops",
        # Line contains (for|while) AND (querySelector|getElementById);
        # MULTILINE anchor keeps the count per line, like legacy count_lines.
        regex=re.compile(r"^(?=.*(?:for|while))(?=.*(?:querySelector|getElementById))", re.MULTILINE),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=16,
        rule_id="js.dom.style-manipulation",
        title="Direct style manipulation",
        regex=re.compile(r"\.style\.[A-Za-z]*\s*="),
        thresholds=((30, "info"),),
    ),
    Pattern(
        category=16,
        rule_id="js.dom.listeners-in-loops",
        title="Adding listeners in loops",
        # Line contains addEventListener AND (forEach|map).
        regex=re.compile(r"^(?=.*addEventListener)(?=.*(?:forEach|map))", re.MULTILINE),
        thresholds=((3, "info"),),
    ),
]
