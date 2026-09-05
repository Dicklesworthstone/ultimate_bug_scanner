"""ubs_core.java_patterns.quality — categories 6, 7, 8, 10, 11, 18, 22 (bead 0xjg.8).

Regex-halves of the legacy logging/regex/collections/streams/serialization/
api-misuse/logging-practices pipelines. The multi-count technical-debt ladder,
the foreach-mutation window and the string '+=' loop window live in
ubs_core.java_detectors (project-wide counts / cross-line windows).
"""
from __future__ import annotations

import re

from ubs_core.java_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 6: LOGGING & DEBUGGING ─────────────────────────────────────
    Pattern(
        category=6,
        rule_id="java.logging.system-println",
        title="System.out/err.println present - prefer logger",
        regex=re.compile(r"System\.(out|err)\.println\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=6,
        rule_id="java.logging.printstacktrace",
        title="printStackTrace leaks details",
        regex=re.compile(r"\.printStackTrace\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="java.logging.concat",
        title="Logging concatenation - prefer parameterized logging",
        regex=re.compile(r"(logger|LOG|log)\.(trace|debug|info|warn|error)[ \t]*\([^)]*\+[^)]*\)"),
        thresholds=((0, "info"),),
    ),
    # ── Category 7: REGEX & STRING PITFALLS ─────────────────────────────────
    Pattern(
        category=7,
        rule_id="java.regex.redos",
        title="Regex contains nested quantifiers - potential ReDoS",
        regex=re.compile(r"\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="java.regex.dynamic-compile",
        title="Dynamic Pattern.compile detected - sanitize/escape user input",
        regex=re.compile(r"Pattern\.compile\([ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=7,
        rule_id="java.regex.case-compare",
        title="Prefer equalsIgnoreCase or use Locale",
        regex=re.compile(r"\.to(Lower|Upper)Case\(\)\.equals\("),
        thresholds=((0, "info"),),
    ),
    # ── Category 8: COLLECTIONS & GENERICS ──────────────────────────────────
    Pattern(
        category=8,
        rule_id="java.collections.raw-types",
        title="Raw generic types used",
        # legacy post-filter: `grep -v '<'`.
        regex=re.compile(r"\b(List|Map|Set)[ \t]+[a-zA-Z_][a-zA-Z0-9_]*[ \t]*(=|;)"),
        exclude_regex=re.compile(r"<"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=8,
        rule_id="java.collections.legacy",
        title="Vector/Hashtable detected",
        regex=re.compile(r"new[ \t]+(Vector|Hashtable)\("),
        thresholds=((0, "info"),),
    ),
    # ── Category 10: STREAMS & PERFORMANCE ──────────────────────────────────
    Pattern(
        category=10,
        rule_id="java.streams-perf.parallel-foreach",
        title="parallel forEach detected - ensure thread-safe side effects",
        regex=re.compile(r"\.parallel\(\)\.forEach\("),
        thresholds=((0, "info"),),
    ),
    # ── Category 11: SERIALIZATION & COMPATIBILITY ──────────────────────────
    Pattern(
        category=11,
        rule_id="java.serialization.implements",
        title="Classes implement Serializable - audit necessity",
        regex=re.compile(r"implements[ \t]+Serializable\b"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=11,
        rule_id="java.serialization.custom-hooks",
        title="Custom serialization hooks present - validate invariants",
        regex=re.compile(r"void[ \t]+readObject[ \t]*\(|void[ \t]+writeObject[ \t]*\("),
        thresholds=((0, "info"),),
    ),
    # ── Category 18: MISC API MISUSE ────────────────────────────────────────
    Pattern(
        category=18,
        rule_id="java.api-misuse.finalizers",
        title="System.runFinalizersOnExit used - do not use",
        regex=re.compile(r"System\.runFinalizersOnExit\("),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=18,
        rule_id="java.api-misuse.thread-stop",
        title="Thread.stop/suspend/resume used - unsafe",
        regex=re.compile(r"Thread\.stop\(|Thread\.suspend\(|Thread\.resume\("),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=18,
        rule_id="java.api-misuse.set-accessible",
        title="setAccessible(true) used - restrict usage",
        regex=re.compile(r"\.setAccessible\([ \t]*true[ \t]*\)"),
        thresholds=((0, "info"),),
    ),
    # ── Category 22: LOGGING BEST PRACTICES ─────────────────────────────────
    Pattern(
        category=22,
        rule_id="java.logging-practices.concat",
        title="Concatenation in log calls - use placeholders",
        regex=re.compile(r"\.(trace|debug|info|warn|error)[ \t]*\([^)]*\+[^)]*\)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=22,
        rule_id="java.logging-practices.throwable-position",
        title="Throwable not last in logger call",
        regex=re.compile(r"\.(trace|debug|info|warn|error)[ \t]*\(.*Throwable[ \t]*,[ \t]*[^)]*\)"),
        thresholds=((0, "info"),),
    ),
]
