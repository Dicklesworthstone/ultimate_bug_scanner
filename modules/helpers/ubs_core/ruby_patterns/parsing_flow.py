"""ubs_core.ruby_patterns.parsing_flow — categories 9 and 10 rg subset (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 9 PARSING & TYPE CONVERSION (3099-3124 rg part): to_i fallback,
  Time.parse. (The JSON.parse-without-rescue subtraction check is a detector:
  ubs_core.ruby_detectors.json_parse_no_rescue.)
- CATEGORY 10 CONTROL FLOW GOTCHAS (3127-3154): control transfer in ensure,
  nested ternary, retry.
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 9: PARSING & TYPE CONVERSION ───────────────────────────────
    Pattern(
        category=9,
        rule_id="ruby.parsing.to-i-fallback",
        title="Frequent to_i usage",
        # legacy 3114: `\.to_i(\)|\([[:space:]]*base:` — i.e. `.to_i)` or
        # `(base:`; info >20, "Consider Integer(str, 10) for strictness".
        regex=re.compile(r"\.to_i\)|\([ \t]*base:"),
        thresholds=((20, "info"),),
    ),
    Pattern(
        category=9,
        rule_id="ruby.parsing.time-parse",
        title="Time.parse used",
        # legacy 3119: `Time\.parse\(`, info >5, "Validate inputs; prefer
        # iso8601".
        regex=re.compile(r"Time\.parse\("),
        thresholds=((5, "info"),),
    ),
    # ── Category 10: CONTROL FLOW GOTCHAS ───────────────────────────────────
    Pattern(
        category=10,
        rule_id="ruby.control-flow.ensure-transfer",
        title="Control transfer in ensure",
        # legacy 3137-3139: `ensure[[:space:]]*$` plus `grep -E -A3
        # "return|break|next"` — the stated intent being a return/break/next
        # within the 3 lines after an ensure line (rg streams matching lines
        # only, so the literal pipeline degenerated; the intent encoding is
        # the py_patterns.flow precedent). warning >0, "May swallow
        # exceptions".
        regex=re.compile(
            r"(?m)^[ \t]*ensure[ \t]*$"
            r"(?:[^\n]*\b(?:return|break|next)\b"
            r"|\n(?:[^\n]*\n){0,2}?[^\n]*\b(?:return|break|next)\b)"
        ),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=10,
        rule_id="ruby.control-flow.nested-ternary",
        title="Nested ternary expressions",
        # legacy 3144: `\?.*:[^;]*\?.*:`, info >3, "Prefer if/elsif".
        regex=re.compile(r"\?[^\n]*:[^;\n]*\?[^\n]*:"),
        thresholds=((3, "info"),),
    ),
    Pattern(
        category=10,
        rule_id="ruby.control-flow.retry",
        title="retry used",
        # legacy 3150: `^[[:space:]]*retry[[:space:]]*$`, info >2, "Ensure
        # bounded retries with backoff".
        regex=re.compile(r"(?m)^[ \t]*retry[ \t]*$"),
        thresholds=((2, "info"),),
    ),
]
