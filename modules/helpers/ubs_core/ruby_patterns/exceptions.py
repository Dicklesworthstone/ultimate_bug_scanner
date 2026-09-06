"""ubs_core.ruby_patterns.exceptions — category 5 (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh 2866-2904:
bare rescue, rescue Exception, rescue => e with `raise e`, rescue nil.
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=5,
        rule_id="ruby.exceptions.bare-rescue",
        title="Bare rescue without class",
        # legacy 2874: `^[[:space:]]*rescue[[:space:]]*($|#)`, warning >0,
        # good "No bare rescue blocks".
        regex=re.compile(r"(?m)^[ \t]*rescue[ \t]*(?:$|#)"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=5,
        rule_id="ruby.exceptions.rescue-exception",
        title="Rescuing Exception",
        # legacy 2883: `rescue[[:space:]]+Exception\b`, critical >0,
        # "Rescue StandardError or specific subclasses".
        regex=re.compile(r"rescue[ \t]+Exception\b"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=5,
        rule_id="ruby.exceptions.raise-name",
        title="Use 'raise' not 'raise e' to keep traceback",
        # legacy 2892-2894: `rescue[[:space:]]+[^=]+=>[[:space:]]*ident`
        # headers plus `grep -E -A2 "raise[[:space:]]+ident[[:space:]]*$"` —
        # a bare-name re-raise on the header line itself or within the 2
        # lines after it (bounded cross-line encoding; py_patterns.flow
        # precedent).
        regex=re.compile(
            r"rescue[ \t]+[^=\n]+=>[ \t]*[A-Za-z_][A-Za-z0-9_]*[^\n]*?"
            r"(?:raise[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*(?=\n|\Z)"
            r"|\n(?:[^\n]*\n){0,1}?[^\n]*raise[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*(?=\n|\Z))"
        ),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=5,
        rule_id="ruby.exceptions.rescue-nil",
        title="Silencing errors with 'rescue nil'",
        # legacy 2899: `rescue[[:space:]]+nil`, warning >2,
        # "Log or handle specifically".
        regex=re.compile(r"rescue[ \t]+nil"),
        thresholds=((2, "warning"),),
    ),
]
