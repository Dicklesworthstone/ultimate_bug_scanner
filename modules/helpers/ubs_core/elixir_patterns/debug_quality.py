r"""ubs_core.elixir_patterns.debug_quality — categories 9 and 11 (bead 0xjg.13).

Faithful ports of the legacy rg pipelines in modules/ubs-elixir.sh 2732-2773
and 2813-2849: the debug-artifact checks (IO.inspect, IEx.pry, dbg(),
IO.puts) carry the legacy `grep -v -E` filters that ran on rg OUTPUT lines
(``path:line:code`` — note the bare ``\#\s*`` filter drops any IO.inspect
line whose code contains a hash), and the code-quality ladders (nested
control structures, @moduledoc/@doc false, the @spec coverage conjunction
def > 20 AND @spec < 5).
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 9: DEBUGGING & PRODUCTION CODE ─────────────────────────────
    Pattern(
        category=9,
        rule_id="ex.debug.io-inspect",
        title="IO.inspect calls in non-test code",
        # legacy 2738: `IO\.inspect\b` with
        # `grep -v -E "test/|_test\.exs|#\s*"` on the rg output line, info >0.
        regex=re.compile(r"IO\.inspect\b"),
        output_filter_regex=re.compile(r"test/|_test\.exs|#\s*"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=9,
        rule_id="ex.debug.iex-pry",
        title="IEx.pry breakpoints in non-test code",
        # legacy 2746: `IEx\.pry\b` with test-path output filter, warning >0.
        regex=re.compile(r"IEx\.pry\b"),
        output_filter_regex=re.compile(r"test/|_test\.exs"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=9,
        rule_id="ex.debug.dbg-macro",
        title="dbg() calls in non-test code",
        # legacy 2754: `\bdbg\(\b` with test-path output filter, info >0.
        regex=re.compile(r"\bdbg\(\b"),
        output_filter_regex=re.compile(r"test/|_test\.exs"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=9,
        rule_id="ex.debug.io-puts-logging",
        title="IO.puts used instead of Logger",
        # legacy 2762: `IO\.puts\b` with
        # `grep -v -E "test/|_test\.exs|mix\.exs"`, info >5.
        regex=re.compile(r"IO\.puts\b"),
        output_filter_regex=re.compile(r"test/|_test\.exs|mix\.exs"),
        thresholds=((5, "info"),),
    ),
    Pattern(
        category=9,
        rule_id="ex.debug.todo-markers",
        title="TODO/FIXME/HACK/XXX markers in code",
        # legacy 2769: GREP_RNI `\b(TODO|FIXME|HACK|XXX)\b`, info >0.
        regex=re.compile(r"\b(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE),
        thresholds=((0, "info"),),
    ),
    # ── Category 11: CODE QUALITY MARKERS ───────────────────────────────────
    Pattern(
        category=11,
        rule_id="ex.quality.compiler-warnings",
        title="Compiler warnings about unused variables",
        # legacy 2819: `warning:.*variable.*is unused`, info >0.
        regex=re.compile(r"warning:.*variable.*is unused"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=11,
        rule_id="ex.quality.nested-control",
        title="Deeply nested control structures",
        # legacy 2825: `^\s{8,}(case|cond|with)\s`, info >10.
        regex=re.compile(r"^[ \t]{8,}(case|cond|with)[ \t]"),
        thresholds=((10, "info"),),
    ),
    Pattern(
        category=11,
        rule_id="ex.quality.moduledoc-false",
        title="Modules with @moduledoc false",
        # legacy 2832: `@moduledoc\s+false`, info >10.
        regex=re.compile(r"@moduledoc[ \t]+false"),
        thresholds=((10, "info"),),
    ),
    Pattern(
        category=11,
        rule_id="ex.quality.doc-false",
        title="Functions with @doc false",
        # legacy 2838: `@doc\s+false`, info >15.
        regex=re.compile(r"@doc[ \t]+false"),
        thresholds=((15, "info"),),
    ),
    Pattern(
        category=11,
        rule_id="ex.quality.missing-spec",
        title="Public functions mostly lack @spec annotations",
        # legacy 2844-2848: def pipeline (test paths filtered from the rg
        # output line) > 20 AND the @spec pipeline count < 5, info with the
        # def count.
        regex=re.compile(r"^[ \t]*def[ \t]+\w+\("),
        output_filter_regex=re.compile(r"test/|_test\.exs"),
        suppress_if=(re.compile(r"@spec[ \t]+"), 5),
        thresholds=((20, "info"),),
    ),
]
