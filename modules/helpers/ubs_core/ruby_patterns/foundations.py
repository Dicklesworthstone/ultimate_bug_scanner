"""ubs_core.ruby_patterns.foundations — categories 1 and 2 (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 1 NIL / DEFENSIVE PROGRAMMING (2701-2776): nil equality, nested
  [] access. (The deep-chain guard analysis is NOT a pattern — the registered
  guards_ruby analyzer replaces analyze_rb_chain_guards.)
- CATEGORY 2 NUMERIC / ARITHMETIC PITFALLS (2778-2809): division by variable,
  float equality, modulo by variable.
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 1: NIL / DEFENSIVE PROGRAMMING ─────────────────────────────
    Pattern(
        category=1,
        rule_id="ruby.nil.eq-nil",
        title="Equality to nil",
        # legacy 2713: `==[[:space:]]*nil|!=[[:space:]]*nil`, warning >0,
        # good "No nil equality comparisons".
        regex=re.compile(r"==[ \t]*nil|!=[ \t]*nil"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=1,
        rule_id="ruby.nil.nested-brackets",
        title="Nested [] access",
        # legacy 2770: `\[[^\]]+\]\[[^\]]+\]`, info >8, "Consider Hash#dig".
        regex=re.compile(r"\[[^\]\n]+\]\[[^\]\n]+\]"),
        thresholds=((8, "info"),),
    ),
    # ── Category 2: NUMERIC / ARITHMETIC PITFALLS ───────────────────────────
    Pattern(
        category=2,
        rule_id="ruby.numeric.division-by-variable",
        title="Division by variable - verify non-zero",
        # legacy 2790-2793: `/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*` with
        # `grep -E -v "/[[:space:]]*(255|2|10|100|1000)\b|//|/\*"`; warning
        # >25, else the info tier below.
        regex=re.compile(r"/[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        exclude_regex=re.compile(r"/[ \t]*(?:255|2|10|100|1000)\b|//|/\*"),
        thresholds=((25, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="ruby.numeric.division-operations",
        title="Division operations found - check divisors",
        # legacy 2796: same pipeline, info tier (count 1..25).
        regex=re.compile(r"/[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        exclude_regex=re.compile(r"/[ \t]*(?:255|2|10|100|1000)\b|//|/\*"),
        thresholds=((0, "info"),),
        max_count=25,
    ),
    Pattern(
        category=2,
        rule_id="ruby.numeric.float-equality",
        title="Float equality comparison",
        # legacy 2801: `==[[:space:]]*[0-9]+\.[0-9]+`, warning >3.
        regex=re.compile(r"==[ \t]*[0-9]+\.[0-9]+"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="ruby.numeric.modulo-by-variable",
        title="Modulo operations - verify divisor non-zero",
        # legacy 2806: `%[[:space:]]*[A-Za-z_][A-Za-z0-9_]*`, info >10.
        regex=re.compile(r"%[ \t]*[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((10, "info"),),
    ),
]
