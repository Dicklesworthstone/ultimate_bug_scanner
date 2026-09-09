"""ubs_core.py_patterns.debug_typing — categories 11, 13, 17, 18 (bead 0xjg.5 exemplar).

Faithful ports of the legacy rg pipelines in modules/ubs-python.sh:
- CATEGORY 11 DEBUGGING (11211-11241): print(), breakpoint/pdb, sensitive logs.
- CATEGORY 13 VARIABLE & SCOPE (11284-11292): global/nonlocal, wildcard imports.
- CATEGORY 17 TYPING STRICTNESS (11391-11403): `Any` usage, type: ignore.
- CATEGORY 18 PYTHON I/O & MODULE USAGE (11414-11420): os.system, dynamic imports.
"""
from __future__ import annotations

import re

from ubs_core.py_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 11: DEBUGGING & PRODUCTION CODE ────────────────────────────
    Pattern(
        category=11,
        rule_id="py.debug.print",
        title="print() statements",
        # legacy ladder: warning >50 "Many print() statements - prefer logging",
        # info >20 "print() statements found", else good "Minimal print usage".
        # The two titles merge into the v2 record stream; the ladder tiers do.
        regex=re.compile(r"(?m)^[ \t]*print\("),
        thresholds=((50, "warning"), (20, "info")),
        # A bare `print(` is not evidence of leftover debug code: in a command
        # line entry point, stdout IS the product. Legacy counted the whole
        # project, so any CLI with >50 prints failed a --fail-on-warning gate
        # for doing its job. Modules that declare a CLI role — a shebang, a
        # `__main__` guard, an argument parser, or sys.argv — are exempt; a
        # library module that prints instead of logging still reports.
        exclude_file_regex=re.compile(
            r"(?m)^#!.*\bpython"
            r"|^[ \t]*if[ \t]+__name__[ \t]*==[ \t]*[\"\']__main__[\"\']"
            r"|^[ \t]*(?:import|from)[ \t]+(?:argparse|click|typer)\b"
            r"|(?<![A-Za-z0-9_.])sys\.argv(?![A-Za-z0-9_])"
        ),
    ),
    Pattern(
        category=11,
        rule_id="py.debug.debugger",
        title="Debugger calls present",
        regex=re.compile(r"breakpoint\(|pdb\.set_trace\("),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=11,
        rule_id="py.debug.sensitive-log",
        title="Sensitive data in logs",
        regex=re.compile(
            r"logging\.(debug|info|warning|error|exception)\(.*(password|token|secret|Bearer|Authorization)"
        ),
        thresholds=((0, "critical"),),
        case_insensitive=True,
        scan_strings=True,  # the secret-ish word is inside the logged literal
    ),
    # ── Category 13: VARIABLE & SCOPE ───────────────────────────────────────
    Pattern(
        category=13,
        rule_id="py.variables.global-nonlocal",
        title="Frequent global/nonlocal usage",
        regex=re.compile(r"(?m)^[ \t]*(global|nonlocal)[ \t]+[A-Za-z_]"),
        thresholds=((5, "info"),),
    ),
    Pattern(
        category=13,
        rule_id="py.variables.wildcard-import",
        title="Wildcard imports deter tooling",
        regex=re.compile(r"from[ \t]+[A-Za-z0-9_.]+[ \t]+import[ \t]+\*"),
        thresholds=((0, "warning"),),
    ),
    # ── Category 17: TYPING STRICTNESS ──────────────────────────────────────
    Pattern(
        category=17,
        rule_id="py.typing.any-usage",
        title="Frequent 'Any' usage",
        # legacy ladder: info >10 "Frequent 'Any' usage" / info >0
        # "Some 'Any' usage present" — both info, one merged tier.
        regex=re.compile(r"(:|->)[ \t]*Any\b|typing\.Any\b"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=17,
        rule_id="py.typing.type-ignore",
        title="Many 'type: ignore' pragmas",
        regex=re.compile(r"#[ \t]*type:[ \t]*ignore"),
        thresholds=((5, "info"),),
    ),
    # ── Category 18: PYTHON I/O & MODULE USAGE ──────────────────────────────
    Pattern(
        category=18,
        rule_id="py.modules.os-system",
        title="os.system used (shell)",
        regex=re.compile(r"os\.system\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=18,
        rule_id="py.modules.dynamic-import",
        title="Dynamic imports present",
        regex=re.compile(r"__import__\(|importlib\.import_module\("),
        thresholds=((0, "info"),),
    ),
]
