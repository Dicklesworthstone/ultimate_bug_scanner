"""ubs_core.elixir_patterns.ecto_concurrency — categories 6-8 (bead 0xjg.13).

Faithful ports of the legacy rg pipelines in modules/ubs-elixir.sh 2621-2727:
- CATEGORY 6 ECTO & DATABASE: N+1 loops, bang Repo ops (test paths filtered
  from the rg OUTPUT line), transactions without Ecto.Multi.
- CATEGORY 7 CONCURRENCY & MESSAGING: self-send mailbox risk, GenServer.call
  default timeout, ETS read_concurrency NET count, heavy Agent usage.
- CATEGORY 8 I/O & RESOURCE LIFECYCLE: File.open NET of close/stream, Port
  open/close NET, large File.read! counts.
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 6: ECTO & DATABASE ─────────────────────────────────────────
    Pattern(
        category=6,
        rule_id="ex.ecto.n1-queries",
        title="Possible N+1 queries (association traversal in loops)",
        # legacy 2627: `Enum\.(map|each|reduce)\(.*\.\w+\.\w+`, warning >5.
        regex=re.compile(r"Enum\.(map|each|reduce)\(.*\.\w+\.\w+"),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="ex.ecto.bang-repo",
        title="Bang Repo operations outside tests",
        # legacy 2634: `Repo\.(insert|update|delete)!\b` with
        # `grep -v -E "test/|_test\.exs"` on the rg output line, warning >5.
        regex=re.compile(r"Repo\.(insert|update|delete)!\b"),
        output_filter_regex=re.compile(r"test/|_test\.exs"),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="ex.ecto.transaction-no-multi",
        title="Repo.transaction without Ecto.Multi",
        # legacy 2649-2652: Repo.transaction > 5 AND the Ecto.Multi pipeline
        # count == 0, info with the transaction count.
        regex=re.compile(r"Repo\.transaction\b"),
        suppress_if=(re.compile(r"Ecto\.Multi\b|Multi\.new\b"), 1),
        thresholds=((5, "info"),),
    ),
    # ── Category 7: CONCURRENCY & MESSAGING ─────────────────────────────────
    Pattern(
        category=7,
        rule_id="ex.concurrency.mailbox-overflow",
        title="send(self(), ...) patterns",
        # legacy 2665: `\bsend\(\s*self\(\)`, warning >5.
        regex=re.compile(r"\bsend\([ \t]*self\(\)"),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="ex.concurrency.genserver-call-timeout",
        title="GenServer.call without explicit timeout",
        # legacy 2672: `GenServer\.call\([^,)]+\)\s*$`, info >10.
        regex=re.compile(r"GenServer\.call\([^,)]+\)[ \t]*$"),
        thresholds=((10, "info"),),
    ),
    Pattern(
        category=7,
        rule_id="ex.concurrency.ets-read-concurrency",
        title="ETS tables without read_concurrency optimization",
        # legacy 2678-2683: NET count :ets.new - :ets.new...read_concurrency,
        # info when positive (legacy gate optimized < count).
        regex=re.compile(r":ets\.new\b"),
        diff_regexes=(re.compile(r":ets\.new.*read_concurrency"),),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=7,
        rule_id="ex.concurrency.heavy-agent",
        title="Heavy Agent usage",
        # legacy 2688: `Agent\.(start|start_link|get|update|get_and_update)\b`,
        # info >20.
        regex=re.compile(r"Agent\.(start|start_link|get|update|get_and_update)\b"),
        thresholds=((20, "info"),),
    ),
    # ── Category 8: I/O & RESOURCE LIFECYCLE ────────────────────────────────
    Pattern(
        category=8,
        rule_id="ex.io.file-open-unmatched",
        title="File.open without matching File.close or stream",
        # legacy 2703-2710: NET count File.open - File.close -
        # (File.stream! | File.open...fn ), warning when the diff > 2
        # (legacy gate open > 0 is implied by diff > 2).
        regex=re.compile(r"File\.open\b"),
        diff_regexes=(re.compile(r"File\.close\b"),
                      re.compile(r"File\.stream!\b|File\.open.*fn[ \t]")),
        thresholds=((2, "warning"),),
    ),
    Pattern(
        category=8,
        rule_id="ex.io.port-open-unmatched",
        title="Port.open without matching Port.close",
        # legacy 2715-2719: NET count Port.open - Port.close, warning when
        # positive (legacy gate open > 0 AND close < open).
        regex=re.compile(r"Port\.open\b"),
        diff_regexes=(re.compile(r"Port\.close\b"),),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=8,
        rule_id="ex.io.large-file-reads",
        title="File.read! calls (loads entire file into memory)",
        # legacy 2723: `File\.read!\b`, info >10.
        regex=re.compile(r"File\.read!\b"),
        thresholds=((10, "info"),),
    ),
]
