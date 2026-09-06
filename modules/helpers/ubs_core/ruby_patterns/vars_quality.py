"""ubs_core.ruby_patterns.vars_quality — categories 13 and 14 (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 13 VARIABLE & SCOPE (3224-3248): global variables ladder, class
  variables, core-class reopening.
- CATEGORY 14 CODE QUALITY MARKERS (3251-3281): the TODO/FIXME/HACK/XXX
  count sum (NOTE is counted for the text breakdown only and never joins
  total_markers — legacy behavior preserved). The per-marker counts are
  Pattern.components so a line carrying two markers counts twice, exactly
  like the legacy five-rg sum; the ladder splits across max_count tiers.
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

# legacy 3267-3271, GREP_RNI sub-counts summed into total_markers. NOTE is
# intentionally absent (legacy computed note_count but never added it).
_MARKERS = (
    re.compile(r"TODO"),
    re.compile(r"FIXME"),
    re.compile(r"HACK"),
    re.compile(r"XXX"),
)

PATTERNS: list[Pattern] = [
    # ── Category 13: VARIABLE & SCOPE ───────────────────────────────────────
    Pattern(
        category=13,
        rule_id="ruby.variables.globals",
        title="Use of global variables",
        # legacy 3231: `[$][A-Za-z_][A-Za-z0-9_]*`, warning >10, else the
        # info tier below, "Prefer dependency injection or constants".
        regex=re.compile(r"[$][A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((10, "warning"),),
    ),
    Pattern(
        category=13,
        rule_id="ruby.variables.globals-info",
        title="Some globals present",
        # legacy 3234: same pipeline, info tier (count 1..10).
        regex=re.compile(r"[$][A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((0, "info"),),
        max_count=10,
    ),
    Pattern(
        category=13,
        rule_id="ruby.variables.class-vars",
        title="Class variables used",
        # legacy 3239: `@@[A-Za-z_][A-Za-z0-9_]*`, info >5, "Prefer class
        # instance variables".
        regex=re.compile(r"@@[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((5, "info"),),
    ),
    Pattern(
        category=13,
        rule_id="ruby.variables.monkey-patch",
        title="Monkey patching core classes",
        # legacy 3244: `^[[:space:]]*class[[:space:]]+(String|Array|Hash|
        # Numeric|Integer|Float|Symbol|Object|Kernel)\b`, warning >0.
        regex=re.compile(
            r"(?m)^[ \t]*class[ \t]+(?:String|Array|Hash|Numeric|Integer|Float|Symbol|Object|Kernel)\b"
        ),
        thresholds=((0, "warning"),),
    ),
    # ── Category 14: CODE QUALITY MARKERS ───────────────────────────────────
    Pattern(
        category=14,
        rule_id="ruby.quality.tech-debt-significant",
        title="Significant technical debt",
        # legacy 3273: marker sum >20, "Create tracking tickets".
        regex=_MARKERS[0],
        components=_MARKERS,
        thresholds=((20, "warning"),),
    ),
    Pattern(
        category=14,
        rule_id="ruby.quality.tech-debt-moderate",
        title="Moderate technical debt",
        # legacy 3276: marker sum 11..20, info.
        regex=_MARKERS[0],
        components=_MARKERS,
        thresholds=((10, "info"),),
        max_count=20,
    ),
    Pattern(
        category=14,
        rule_id="ruby.quality.tech-debt-minimal",
        title="Minimal technical debt",
        # legacy 3279: marker sum 1..10, info; else good "No technical debt
        # markers".
        regex=_MARKERS[0],
        components=_MARKERS,
        thresholds=((0, "info"),),
        max_count=10,
    ),
]
