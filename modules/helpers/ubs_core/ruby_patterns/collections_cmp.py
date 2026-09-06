"""ubs_core.ruby_patterns.collections_cmp — categories 3 and 4 (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 3 COLLECTION SAFETY (2811-2842): index arithmetic, mutation during
  iteration, length/size zero checks.
- CATEGORY 4 COMPARISON & IDIOMS (2844-2864): and/or precedence, case
  equality outside case/when.
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

# legacy 2827-2830: iterator headers `rg "\.(each|map|select|reject)\b"` plus
# `grep -E -A3 "(push|<<|insert|delete|...)"` and a final count — the stated
# intent being "a mutating call on the header line or within the 3 lines
# after it". Encoded as one bounded cross-line regex (py_patterns.flow
# precedent); several headers reaching one mutation line each produce their
# own record, mirroring the legacy per-header context groups.
_ITERATOR = r"\.(?:each|map|select|reject)\b"
_MUTATION = r"(?:push|<<|insert|delete|delete_if|pop|shift|unshift|clear)"

PATTERNS: list[Pattern] = [
    # ── Category 3: COLLECTION SAFETY ───────────────────────────────────────
    Pattern(
        category=3,
        rule_id="ruby.collections.index-arithmetic",
        title="Array index arithmetic - verify bounds",
        # legacy 2821: `\[[[:space:]]*ident[[:space:]]*[+\-][[:space:]]*[0-9]+[[:space:]]*\]`,
        # warning >12, else the info tier below.
        regex=re.compile(r"\[[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[+\-][ \t]*[0-9]+[ \t]*\]"),
        thresholds=((12, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="ruby.collections.index-arithmetic-info",
        title="Index arithmetic present - review bounds",
        # legacy 2824: same pipeline, info tier (count 1..12).
        regex=re.compile(r"\[[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[+\-][ \t]*[0-9]+[ \t]*\]"),
        thresholds=((0, "info"),),
        max_count=12,
    ),
    Pattern(
        category=3,
        rule_id="ruby.collections.mutation-during-iteration",
        title="Possible mutation during iteration",
        # legacy 2827-2834, warning >5. See _ITERATOR/_MUTATION above.
        regex=re.compile(
            _ITERATOR + r"[^\n]*(?:"
            + _MUTATION
            + r"|\n(?:[^\n]*\n){0,2}?[^\n]*"
            + _MUTATION
            + r")"
        ),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="ruby.collections.length-zero-check",
        title="length/size == 0 checks",
        # legacy 2837: `\.(length|size)[[:space:]]*(==|!=|<|>|<=|>=)[[:space:]]*0`,
        # info >8, "Prefer empty?/any?".
        regex=re.compile(r"\.(?:length|size)[ \t]*(?:==|!=|<|>|<=|>=)[ \t]*0"),
        thresholds=((8, "info"),),
    ),
    # ── Category 4: COMPARISON & IDIOMS ─────────────────────────────────────
    Pattern(
        category=4,
        rule_id="ruby.comparison.and-or",
        title="and/or used; precedence differs from &&/||",
        # legacy 2851: `[^&] and [^&]|[^|] or [^|]`, info >3.
        regex=re.compile(r"[^&\n] and [^&\n]|[^|\n] or [^|\n]"),
        thresholds=((3, "info"),),
    ),
    Pattern(
        category=4,
        rule_id="ruby.comparison.case-equality",
        title="=== used directly",
        # legacy 2857: `===[[:space:]]*[A-Za-z_]` with `grep -E -v "when[[:space:]]"`,
        # info >0, "Ensure intent; === can be surprising".
        regex=re.compile(r"===[ \t]*[A-Za-z_]"),
        exclude_regex=re.compile(r"when[ \t]"),
        thresholds=((0, "info"),),
    ),
]
