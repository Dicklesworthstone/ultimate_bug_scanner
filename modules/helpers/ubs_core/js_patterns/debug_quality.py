"""ubs_core.js_patterns.debug_quality — categories 11, 14, 17 (bead 0xjg.4 wave 1).

Faithful ports of the legacy rg pipelines in modules/ubs-js.sh:
- CATEGORY 11 DEBUGGING (10206-10254): console.*, debugger, blocking dialogs,
  sensitive data in console logs.
- CATEGORY 14 CODE QUALITY MARKERS (10627-10660): TODO/FIXME/HACK/XXX counts
  (NOTE appears in the legacy breakdown only, never in the total).
- CATEGORY 17 TYPESCRIPT STRICTNESS (10731-10747): explicit any, non-null
  assertions (legacy post-filter drops lines containing != or !==).
"""
from __future__ import annotations

import re

from ubs_core.js_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=11,
        rule_id="js.debug.console",
        title="console.* statements",
        regex=re.compile(r"console\."),
        thresholds=((50, "warning"), (20, "info")),
    ),
    Pattern(
        category=11,
        rule_id="js.debug.debugger",
        title="debugger statements in code",
        regex=re.compile(r"\bdebugger\b"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=11,
        rule_id="js.debug.blocking-dialog",
        title="Blocking dialogs - poor UX",
        regex=re.compile(r"\balert\(|\bconfirm\(|\bprompt\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=11,
        rule_id="js.debug.sensitive-log",
        title="Logging sensitive data",
        regex=re.compile(r"console\.(log|dir).*?(password|token|secret|Bearer|Authorization)"),
        thresholds=((0, "critical"),),
        case_insensitive=True,
    ),
    Pattern(
        category=14,
        rule_id="js.markers.todo-family",
        title="Technical debt markers",
        regex=re.compile(r"TODO|FIXME|HACK|XXX"),
        thresholds=((20, "warning"), (10, "info"), (0, "info")),
        case_insensitive=True,
    ),
    Pattern(
        category=17,
        rule_id="js.typescript.explicit-any",
        title="Explicit any types present",
        regex=re.compile(r":\s*any(\W|$)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=17,
        rule_id="js.typescript.non-null-assertion",
        title="Non-null assertions used",
        regex=re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*!"),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r"!=|!=="),
    ),
]
