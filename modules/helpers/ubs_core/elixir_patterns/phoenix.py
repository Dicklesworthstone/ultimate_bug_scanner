"""ubs_core.elixir_patterns.phoenix — category 5, IS_PHOENIX-gated (bead 0xjg.13).

Legacy ubs-elixir.sh 2575-2616 runs these checks only when
check_phoenix detected a mix.exs containing `:phoenix`; otherwise the whole
category degrades to a counter-less "Not a Phoenix project" note. The gate
tuple (path regex, content regex) reproduces exactly that: some listed file
matching mix.exs must mention :phoenix, so single-file targets and plain
Elixir projects keep the category silent like legacy.
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

_MIX_EXS_PATH = re.compile(r"(^|/)mix\.exs$")
_PHOENIX_DEP = re.compile(r":phoenix")

PATTERNS: list[Pattern] = [
    Pattern(
        category=5,
        rule_id="ex.phoenix.csrf-disabled",
        title="CSRF protection may be disabled",
        # legacy 2583-2588: SUM of the protect_from_forgery/delete_csrf_token
        # and Plug.CSRFProtection pipelines, warning >0.
        regex=re.compile(r"plug[ \t]+:protect_from_forgery.*false|delete_csrf_token"),
        components=(re.compile(r"plug[ \t]+:protect_from_forgery.*false|delete_csrf_token"),
                    re.compile(r"Plug\.CSRFProtection.*false")),
        thresholds=((0, "warning"),),
        gate=(_MIX_EXS_PATH, _PHOENIX_DEP),
    ),
    Pattern(
        category=5,
        rule_id="ex.phoenix.raw-usage",
        title="raw/2 usage in templates (bypasses HTML escaping)",
        # legacy 2592-2594: `\braw\s*\(`, warning >5.
        regex=re.compile(r"\braw[ \t]*\("),
        thresholds=((5, "warning"),),
        gate=(_MIX_EXS_PATH, _PHOENIX_DEP),
    ),
    Pattern(
        category=5,
        rule_id="ex.phoenix.raw-usage-info",
        title="raw/2 found - verify content is sanitized",
        # legacy 2596-2597: same pipeline, info tier (count 1..5).
        regex=re.compile(r"\braw[ \t]*\("),
        thresholds=((0, "info"),),
        max_count=5,
        gate=(_MIX_EXS_PATH, _PHOENIX_DEP),
    ),
    Pattern(
        category=5,
        rule_id="ex.phoenix.no-force-ssl",
        title="No force_ssl configuration detected",
        # legacy 2601-2603: GREP_RNI count == 0 → info "1" fallback.
        regex=re.compile(r"force_ssl|Plug\.SSL", re.IGNORECASE),
        thresholds=(),
        zero_finding=("info", "No force_ssl configuration detected"),
        gate=(_MIX_EXS_PATH, _PHOENIX_DEP),
    ),
    Pattern(
        category=5,
        rule_id="ex.phoenix.controllers-no-auth",
        title="Controller actions found but no auth plugs detected",
        # legacy 2607-2610: controller-action pipeline > 10 AND the
        # case-insensitive auth-plug pipeline count == 0, warning with the
        # action count.
        regex=re.compile(r"def[ \t]+(index|show|create|update|delete)[ \t]*\("),
        suppress_if=(re.compile(r"plug[ \t]+:.*auth|plug[ \t]+.*Auth", re.IGNORECASE), 1),
        thresholds=((10, "warning"),),
        gate=(_MIX_EXS_PATH, _PHOENIX_DEP),
    ),
]
