"""ubs_core.elixir_patterns.foundations — categories 1-3 (bead 0xjg.13).

Faithful ports of the legacy rg pipelines in modules/ubs-elixir.sh 2363-2484:
- CATEGORY 1 PATTERN MATCHING & GUARDS: catch-all clauses, error-tuple
  discards, the unguarded-function-heads conjunction (count > 50 AND
  guarded < 5).
- CATEGORY 2 ERROR HANDLING & EXCEPTIONS: bare rescue (SUM of two pipelines),
  raise without message, bang GenServer callbacks, try/rescue blocks.
- CATEGORY 3 PROCESS & OTP LIFECYCLE: spawn/spawn_link ladder, Process.exit
  :kill, init/1 return filter, Task.async/await NET count, hardcoded PIDs.
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 1: PATTERN MATCHING & GUARDS ───────────────────────────────
    Pattern(
        category=1,
        rule_id="ex.match.catch-all",
        title="Catch-all _ -> clauses",
        # legacy 2369: `^\s*_\s*->`, info >15, else a counter-less good note.
        regex=re.compile(r"^[ \t]*_[ \t]*->"),
        thresholds=((15, "info"),),
    ),
    Pattern(
        category=1,
        rule_id="ex.match.error-tuple-discard",
        title="Error tuples matched with {:error, _} - reason discarded",
        # legacy 2378: `\{:error,\s*_\}`, warning >0.
        regex=re.compile(r"\{:error,[ \t]*_\}"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=1,
        rule_id="ex.match.unguarded-heads",
        title="Function definitions mostly lack when guards",
        # legacy 2387-2391: def-pipeline count > 50 AND the guarded pipeline
        # (`def\s+\w+\(.*\)\s+when\s+`) count < 5 → info with the def count.
        regex=re.compile(r"def[ \t]+\w+\(.*\)[ \t]*do"),
        suppress_if=(re.compile(r"def[ \t]+\w+\(.*\)[ \t]+when[ \t]+"), 5),
        thresholds=((50, "info"),),
    ),
    # ── Category 2: ERROR HANDLING & EXCEPTIONS ─────────────────────────────
    Pattern(
        category=2,
        rule_id="ex.error.bare-rescue",
        title="Bare rescue (catches all exceptions broadly)",
        # legacy 2403-2405: SUM of `rescue\s*$` and `rescue\s+_\s*->`,
        # warning >0.
        regex=re.compile(r"rescue[ \t]*$"),
        components=(re.compile(r"rescue[ \t]*$"), re.compile(r"rescue[ \t]+_[ \t]*->")),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="ex.error.raise-no-message",
        title="raise without error message or exception module",
        # legacy 2414: `raise\s*$`, warning >0.
        regex=re.compile(r"raise[ \t]*$"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="ex.error.bang-genserver",
        title="Bang functions in GenServer callbacks",
        # legacy 2421: `def\s+handle_(call|cast|info).*!`, warning >0.
        regex=re.compile(r"def[ \t]+handle_(call|cast|info).*!"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=2,
        rule_id="ex.error.try-blocks",
        title="try/rescue blocks found",
        # legacy 2428: `^\s*try\s+do`, info >10.
        regex=re.compile(r"^[ \t]*try[ \t]+do"),
        thresholds=((10, "info"),),
    ),
    # ── Category 3: PROCESS & OTP LIFECYCLE ─────────────────────────────────
    Pattern(
        category=3,
        rule_id="ex.otp.unsupervised-spawn",
        title="Unsupervised spawn/spawn_link calls",
        # legacy 2443-2447: SUM of `\bspawn\s*\(` and `\bspawn_link\s*\(`,
        # warning >5.
        regex=re.compile(r"\bspawn[ \t]*\("),
        components=(re.compile(r"\bspawn[ \t]*\("), re.compile(r"\bspawn_link[ \t]*\(")),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="ex.otp.spawn-usage",
        title="spawn/spawn_link usage found - verify supervision",
        # legacy 2449-2450: same SUM, info tier (count 1..5).
        regex=re.compile(r"\bspawn[ \t]*\("),
        components=(re.compile(r"\bspawn[ \t]*\("), re.compile(r"\bspawn_link[ \t]*\(")),
        thresholds=((0, "info"),),
        max_count=5,
    ),
    Pattern(
        category=3,
        rule_id="ex.otp.process-exit-kill",
        title="Process.exit with :kill (untrappable signal)",
        # legacy 2454: `Process\.exit\(.*:kill`, warning >0.
        regex=re.compile(r"Process\.exit\(.*:kill"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="ex.otp.init-return",
        title="init/1 callbacks may not return {:ok, state}",
        # legacy 2461-2466: `def\s+init\(` pipeline filtered by
        # `grep -v -E "\{:ok,|:ignore|\{:stop,"` (run on the rg OUTPUT line),
        # info >0 — the outer count>0 gate is implied (no init lines, no
        # filtered hits).
        regex=re.compile(r"def[ \t]+init\("),
        output_filter_regex=re.compile(r"\{:ok,|:ignore|\{:stop,"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=3,
        rule_id="ex.otp.task-async-unawaited",
        title="Task.async calls may lack matching Task.await",
        # legacy 2471-2475: NET count Task.async - Task.await, warning when
        # the diff > 0 (legacy condition async > 0 AND await < async).
        regex=re.compile(r"Task\.async\b"),
        diff_regexes=(re.compile(r"Task\.await\b"),),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="ex.otp.send-pid",
        title="Sending messages to hardcoded PIDs",
        # legacy 2479: `\bsend\(\s*#PID`, warning >0.
        regex=re.compile(r"\bsend\([ \t]*#PID"),
        thresholds=((0, "warning"),),
    ),
]
