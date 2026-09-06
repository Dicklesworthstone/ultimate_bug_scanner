"""ubs_core.ruby_patterns.debug_perf — categories 11 and 12 (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 11 DEBUGGING & PRODUCTION CODE (3157-3189): puts/p/pp ladder,
  debugger calls, sensitive log data.
- CATEGORY 12 PERFORMANCE & MEMORY (3192-3221): string concat / regex
  compile / gsub inside loops (grep -A3 intent windows, py_patterns.flow
  precedent).
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

# legacy 3213/3220 loop headers: `for[[:space:]]|each[[:space:]]+do|\bwhile[[:space:]]`
_LOOP = r"(?:for[ \t]|each[ \t]+do|\bwhile[ \t])"

PATTERNS: list[Pattern] = [
    # ── Category 11: DEBUGGING & PRODUCTION CODE ────────────────────────────
    Pattern(
        category=11,
        rule_id="ruby.debug.puts-statements",
        title="Many puts/p/pp statements",
        # legacy 3166: `^[[:space:]]*(puts|p|pp)\(`, warning >40, else the
        # info tier below, else good "Minimal direct printing".
        regex=re.compile(r"(?m)^[ \t]*(?:puts|p|pp)\("),
        thresholds=((40, "warning"),),
    ),
    Pattern(
        category=11,
        rule_id="ruby.debug.puts-statements-info",
        title="puts/p/pp statements found",
        # legacy 3169: same pipeline, info tier (count 16..40).
        regex=re.compile(r"(?m)^[ \t]*(?:puts|p|pp)\("),
        thresholds=((15, "info"),),
        max_count=40,
    ),
    Pattern(
        category=11,
        rule_id="ruby.debug.debugger-calls",
        title="Debugger calls present",
        # legacy 3176: `binding\.pry|binding\.irb|byebug|debugger`,
        # critical >0, good "No debugger calls", "Remove before commit".
        regex=re.compile(r"binding\.pry|binding\.irb|byebug|debugger"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=11,
        rule_id="ruby.debug.sensitive-logs",
        title="Sensitive data in logs",
        # legacy 3183 (GREP_RNI): `logger\.(debug|info|warn|error|fatal)\(.*
        # (password|token|secret|Bearer|Authorization)`, critical >0, "Mask
        # or remove secrets".
        regex=re.compile(
            r"logger\.(?:debug|info|warn|error|fatal)\([^\n]*(?:password|token|secret|Bearer|Authorization)"
        ),
        case_insensitive=True,
        thresholds=((0, "critical"),),
    ),
    # ── Category 12: PERFORMANCE & MEMORY ───────────────────────────────────
    Pattern(
        category=12,
        rule_id="ruby.perf.concat-in-loop",
        title="String concat in loops",
        # legacy 3213-3216: loop headers plus `grep -A3 "<<|\+=\"" — a `<<`
        # or `+=` on the header line or within the 3 lines after it; info >5,
        # "Use String#<< with capacity or Array#join".
        regex=re.compile(
            _LOOP + r"[^\n]*(?:<<|\+=(?!=)|\n(?:[^\n]*\n){0,2}?[^\n]*(?:<<|\+=(?!=)))"
        ),
        thresholds=((5, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="ruby.perf.regex-in-loop",
        title="Regex compiled in loop",
        # legacy 3220-3223: loop headers plus `Regexp\.new\(|%r\{` within the
        # 3 lines after; info >0, "Precompile outside loop".
        regex=re.compile(
            _LOOP
            + r"[^\n]*(?:Regexp\.new\(|%r\{|\n(?:[^\n]*\n){0,2}?[^\n]*(?:Regexp\.new\(|%r\{))"
        ),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="ruby.perf.gsub-in-loop",
        title="gsub in loops",
        # legacy 3227-3230: loop headers plus `\.gsub\(` within the 3 lines
        # after; info >3, "Consider bulk operations".
        regex=re.compile(
            _LOOP + r"[^\n]*(?:\.gsub\(|\n(?:[^\n]*\n){0,2}?[^\n]*\.gsub\()"
        ),
        thresholds=((3, "info"),),
    ),
]
