"""ubs_core.py_patterns.foundations — categories 1, 2, 3, 4 rg-pipeline ports (bead 0xjg.5).

Faithful ports of the legacy rg pipelines in modules/ubs-python.sh:
- CATEGORY 1 NONE / DEFENSIVE PROGRAMMING (10604-10611, 10670-10675):
  `== None` / `!= None` and `dict.get("k")` immediately dereferenced. The
  deep attribute-chain ladder is NOT ported here — it is replaced by the
  guards_py analyzer (GH #90).
- CATEGORY 2 NUMERIC / ARITHMETIC PITFALLS (10763-10774): float equality,
  modulo by variable. Division is an ast walker port:
  ubs_core.py_detectors.division.
- CATEGORY 3 COLLECTION SAFETY (10785-10792, 10855-10859): index arithmetic
  `arr[i±k]` and len(x) comparisons. Mutation-during-iteration is a heredoc
  detector port: ubs_core.py_detectors.mutation_during_iteration.
- CATEGORY 4 COMPARISON & TYPE CHECKING TRAPS (10874-10879): type(x) ==/is T.
  The `is <literal>` heredoc already lives in ubs_core.py_detectors.is_literal.

POSIX `[[:space:]]` translates to `[ \\t]` — rg matched line-by-line, so the
line regexes never see newlines; negated classes that could span a newline
(`[^)]`) exclude `\\n` to preserve that line-based behavior.
"""
from __future__ import annotations

import re

from ubs_core.py_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 1: NONE / DEFENSIVE PROGRAMMING ────────────────────────────
    Pattern(
        category=1,
        rule_id="py.none.equality",
        title="Equality to None",
        # legacy: warning >0 "Equality to None" (10605-10607).
        regex=re.compile(r"==[ \t]*None|!=[ \t]*None"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=1,
        rule_id="py.none.dict-get-deref",
        title="dict.get(...) used without default then dereferenced",
        # legacy: warning >10 (10671-10673).
        regex=re.compile(r"\.get\([ \t]*['\"][^'\"]+['\"][ \t]*\)[ \t]*(\.|\[)"),
        thresholds=((10, "warning"),),
    ),
    # ── Category 2: NUMERIC / ARITHMETIC PITFALLS ───────────────────────────
    Pattern(
        category=2,
        rule_id="py.numeric.float-equality",
        title="Float equality comparison",
        # legacy: warning >3 "Float equality comparison" (10764-10766).
        regex=re.compile(r"==[ \t]*[0-9]+\.[0-9]+"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="py.numeric.modulo",
        title="Modulo operations - verify divisor non-zero",
        # legacy: info >10 "Modulo operations - verify divisor non-zero"
        # (10771-10773; the subheader said "Modulo by variable").
        regex=re.compile(r"%[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((10, "info"),),
    ),
    # ── Category 3: COLLECTION SAFETY ───────────────────────────────────────
    Pattern(
        category=3,
        rule_id="py.collections.index-arithmetic",
        title="Array index arithmetic - verify bounds",
        # legacy ladder (10786-10791): warning >12 "Array index arithmetic -
        # verify bounds", else info >0 "Index arithmetic present - review".
        # One pattern carries one title; it follows the dominant (warning)
        # tier while the threshold ladder keeps first-match-wins severity.
        regex=re.compile(r"\[[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[+\-][ \t]*[0-9]+[ \t]*\]"),
        thresholds=((12, "warning"), (0, "info")),
    ),
    Pattern(
        category=3,
        rule_id="py.collections.len-zero",
        title="len(x) == 0 checks",
        # legacy: info >8 "len(x) == 0 checks" (10856-10858).
        regex=re.compile(r"len\([^\n)]+\)[ \t]*(==|!=|<|>|<=|>=)[ \t]*0"),
        thresholds=((8, "info"),),
    ),
    # ── Category 4: COMPARISON & TYPE CHECKING TRAPS ────────────────────────
    Pattern(
        category=4,
        rule_id="py.comparison.type-equality",
        title="type equality used",
        # legacy: warning >0 "type equality used" (10875-10877).
        regex=re.compile(r"type\([^\n)]+\)[ \t]*(==|is)[ \t]*[A-Za-z_][A-Za-z0-9_.]*"),
        thresholds=((0, "warning"),),
    ),
]
