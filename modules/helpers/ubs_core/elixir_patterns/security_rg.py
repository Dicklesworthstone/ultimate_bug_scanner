"""ubs_core.elixir_patterns.security_rg — category 4 rg pipelines (bead 0xjg.13).

Faithful ports of the legacy rg pipelines in modules/ubs-elixir.sh 2489-2569
(the seven python-heredoc detectors of category 4 live in elixir_detectors/ and
the registered taint analyzers):
- Code.eval_* dynamic evaluation (critical)
- the three-tier command-execution check (critical shell-backed / warning
  variable executable / NET info "fixed execution" remainder)
- SQL injection via interpolated fragments (critical, SUM of two pipelines)
- weak hash algorithms (warning, SUM of two pipelines)
- String.to_atom (warning), binary_to_term without [:safe] (critical, NET)
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

# legacy 2502-2504 verbatim (\s → [ \t], [^]] → [^]\n] to stay line-scoped).
SHELL_CRITICAL_RE = re.compile(
    r':os\.cmd\b|System\.shell\b|Port\.open\([ \t]*\{:spawn,|'
    r'System\.cmd[ \t]*\([ \t]*"(((/usr)?/bin/)?(sh|bash|zsh)|cmd(\.exe)?|powershell|pwsh)"'
    r'[ \t]*,[ \t]*\[[^]\n]*("-c"|"/C"|"-Command")|'
    r'System\.cmd[ \t]*\([ \t]*"/usr/bin/env"[ \t]*,[ \t]*\[[^]\n]*"(sh|bash|zsh)"[^]\n]*("-c")'
)
SHELL_VARIABLE_RE = re.compile(r"System\.cmd[ \t]*\([ \t]*[A-Za-z_][A-Za-z0-9_?!]*[ \t]*,")
SHELL_ALL_RE = re.compile(r"System\.cmd\b|System\.shell\b|:os\.cmd\b|Port\.open\([ \t]*\{:spawn,")

PATTERNS: list[Pattern] = [
    Pattern(
        category=4,
        rule_id="ex.security.code-eval",
        title="Dynamic code evaluation (Code.eval_*)",
        # legacy 2495: `Code\.eval_(string|quoted|file)\b`, critical >0.
        regex=re.compile(r"Code\.eval_(string|quoted|file)\b"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.shell-exec-critical",
        title="Shell-backed command execution",
        # legacy 2505-2508: critical shell-backed pipeline, critical >0.
        regex=SHELL_CRITICAL_RE,
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.shell-exec-variable",
        title="System.cmd executable comes from a variable",
        # legacy 2510-2513: variable-executable pipeline, warning >0.
        regex=SHELL_VARIABLE_RE,
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.shell-exec-review",
        title="Fixed System.cmd/Port command execution present - validate argv boundaries",
        # legacy 2515-2520: NET count all - critical - variable (floored at
        # 0), info when positive.
        regex=SHELL_ALL_RE,
        diff_regexes=(SHELL_CRITICAL_RE, SHELL_VARIABLE_RE),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.sql-interpolation",
        title="Possible SQL injection via string interpolation in Ecto fragments/queries",
        # legacy 2532-2534: SUM of fragment and Ecto.Adapters.SQL.query
        # interpolation pipelines, critical >0.
        regex=re.compile(r'fragment\(".*#\{'),
        components=(re.compile(r'fragment\(".*#\{'),
                    re.compile(r'Ecto\.Adapters\.SQL\.query.*".*#\{')),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.weak-hash",
        title="Weak hash algorithm (:md5 or :sha)",
        # legacy 2543-2545: SUM of :crypto hash/hmac and bare :md5 pipelines,
        # warning >0.
        regex=re.compile(r":crypto\.(hash|hmac)\(:(md5|sha)\b"),
        components=(re.compile(r":crypto\.(hash|hmac)\(:(md5|sha)\b"),
                    re.compile(r":md5\b")),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.string-to-atom",
        title="String.to_atom/1 (atom table is finite, never GC'd)",
        # legacy 2554: `String\.to_atom\b`, warning >0.
        regex=re.compile(r"String\.to_atom\b"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=4,
        rule_id="ex.security.binary-to-term-unsafe",
        title="binary_to_term without [:safe] option",
        # legacy 2561-2567: NET count binary_to_term minus the [:safe]
        # pipeline, critical when the diff > 0.
        regex=re.compile(r":erlang\.binary_to_term\b"),
        diff_regexes=(re.compile(r":erlang\.binary_to_term\(.*\[:safe\]"),),
        thresholds=((0, "critical"),),
    ),
]
