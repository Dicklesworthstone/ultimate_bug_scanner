"""ubs_core.elixir_patterns.perf_misc — categories 10, 12, 13, 15 (bead 0xjg.13).

Faithful ports of the legacy rg pipelines in modules/ubs-elixir.sh 2779-2807,
2855-2877, 2883-2909 and 2948-2972. Category 12's filesystem check
(config/runtime.exs) and category 13's async/Sandbox conjunction keep their
legacy shapes here; the mix.exs-scoped category-14 pipelines live in
mix_deps.py and the two filesystem checks (runtime.exs, mix.lock) in
elixir_detectors.
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 10: PERFORMANCE & MEMORY ───────────────────────────────────
    Pattern(
        category=10,
        rule_id="ex.perf.string-concat-loops",
        title="String concatenation in loops",
        # legacy 2785: `Enum\.(reduce|map).*<>`, warning >3.
        regex=re.compile(r"Enum\.(reduce|map).*<>"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=10,
        rule_id="ex.perf.enum-count-compare",
        title="Enum.count for size comparisons",
        # legacy 2792: `Enum\.count\(.*[=!><]`, info >5.
        regex=re.compile(r"Enum\.count\(.*[=!><]"),
        thresholds=((5, "info"),),
    ),
    Pattern(
        category=10,
        rule_id="ex.perf.recursive-functions",
        title="Recursive function calls detected",
        # legacy 2798: `def\s+(\w+).*\1\(` (PCRE2 backreference), info >10.
        regex=re.compile(r"def[ \t]+(\w+).*\1\("),
        thresholds=((10, "info"),),
    ),
    Pattern(
        category=10,
        rule_id="ex.perf.large-binaries",
        title="Large binary literals in source",
        # legacy 2804: `<<[^>]{500,}>>` — line-scoped, so the negated class
        # must not cross newlines.
        regex=re.compile(r"<<[^>\n]{500,}>>"),
        thresholds=((0, "info"),),
    ),
    # ── Category 12: CONFIGURATION & ENVIRONMENT ────────────────────────────
    Pattern(
        category=12,
        rule_id="ex.config.app-env-attr",
        title="Application.get_env in module attribute (compile-time read)",
        # legacy 2861: `^[^#]*@\w+\s+Application\.get_env\b` — `[^#]` is
        # line-scoped in rg, so it must not span newlines here either.
        regex=re.compile(r"^[^#\n]*@\w+[ \t]+Application\.get_env\b"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=12,
        rule_id="ex.config.system-env-attr",
        title="System.get_env in module attribute (compile-time read)",
        # legacy 2868: `^[^#]*@\w+\s+System\.get_env\b`, warning >0.
        regex=re.compile(r"^[^#\n]*@\w+[ \t]+System\.get_env\b"),
        thresholds=((0, "warning"),),
    ),
    # ── Category 13: TESTING PATTERNS ───────────────────────────────────────
    Pattern(
        category=13,
        rule_id="ex.testing.test-blocks",
        title="Test blocks found",
        # legacy 2889: `test\s+".*"\s+do\s*$`, info >0.
        regex=re.compile(r'test[ \t]+".*"[ \t]+do[ \t]*$'),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=13,
        rule_id="ex.testing.sleep-in-tests",
        title="Sleep calls in tests (flaky)",
        # legacy 2895: `:timer\.sleep\b|Process\.sleep\b` with
        # `grep -E "test/|_test\.exs"` (a KEEP filter on the rg output
        # line), warning >3.
        regex=re.compile(r":timer\.sleep\b|Process\.sleep\b"),
        output_keep_regex=re.compile(r"test/|_test\.exs"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=13,
        rule_id="ex.testing.async-no-sandbox",
        title="Async tests without Ecto.Adapters.SQL.Sandbox",
        # legacy 2903-2907: async: true > 5 AND the SQL.Sandbox pipeline
        # count == 0, warning with the async count.
        regex=re.compile(r"async:[ \t]*true"),
        suppress_if=(re.compile(r"Ecto\.Adapters\.SQL\.Sandbox"), 1),
        thresholds=((5, "warning"),),
    ),
    # ── Category 15: STRING & BINARY SAFETY ─────────────────────────────────
    Pattern(
        category=15,
        rule_id="ex.binary.regex-udos",
        title="Regex with interpolated input (ReDoS risk)",
        # legacy 2954-2956: SUM of Regex.compile/run and ~r interpolation
        # pipelines, warning >0.
        regex=re.compile(r"Regex\.(compile|run)\b.*#\{"),
        components=(re.compile(r"Regex\.(compile|run)\b.*#\{"),
                    re.compile(r"~r/.*#\{")),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=15,
        rule_id="ex.binary.byte-size",
        title="byte_size/1 usage (returns bytes, not characters)",
        # legacy 2963: `\bbyte_size\b`, info >5.
        regex=re.compile(r"\bbyte_size\b"),
        thresholds=((5, "info"),),
    ),
    Pattern(
        category=15,
        rule_id="ex.binary.string-to-integer",
        title="String.to_integer/1 (raises on invalid input)",
        # legacy 2969: `String\.to_integer\b`, info >3.
        regex=re.compile(r"String\.to_integer\b"),
        thresholds=((3, "info"),),
    ),
]
