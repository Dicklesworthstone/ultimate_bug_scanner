"""ubs_core.java_patterns.concurrency_io — categories 3, 5, 12 (bead 0xjg.8).

Regex halves of the legacy concurrency checks (the `ast_search` conjuncts are
subsumed by the counted ast layer where legacy counted them; on the manifest
fixtures the ad-hoc `-p` probes contribute nothing) plus the cat-5 I/O
charset/try-with-resources pipelines and the cat-12 Java 21 inventory.
"""
from __future__ import annotations

import re

from ubs_core.java_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 3: CONCURRENCY & THREADING ─────────────────────────────────
    Pattern(
        category=3,
        rule_id="java.concurrency.synchronized-this",
        title="synchronized(this) used - prefer private lock objects",
        regex=re.compile(r"synchronized[ \t]*\([ \t]*this[ \t]*\)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=3,
        rule_id="java.concurrency.thread-start",
        title="Manual thread creation detected",
        regex=re.compile(r"new[ \t]+Thread[ \t]*\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=3,
        rule_id="java.concurrency.cached-pool",
        title="newCachedThreadPool unbounded threads",
        regex=re.compile(r"Executors\.newCachedThreadPool\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="java.concurrency.sleep-sync",
        title="Thread.sleep within synchronized block",
        regex=re.compile(r"synchronized[ \t]*\([^)]+\)[ \t]*\{[^}]*Thread\.sleep\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=3,
        rule_id="java.concurrency.notify",
        title="notify() calls detected - ensure correct semantics",
        regex=re.compile(r"\.notify\(\)"),
        thresholds=((0, "info"),),
    ),
    # ── Category 5: I/O & RESOURCES ─────────────────────────────────────────
    Pattern(
        category=5,
        rule_id="java.io.inputstreamreader-charset",
        title="InputStreamReader without charset",
        regex=re.compile(r"new[ \t]+InputStreamReader\([^)]+\)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=5,
        rule_id="java.io.string-no-charset",
        title="Charset not specified in String/bytes conversion",
        regex=re.compile(r"new[ \t]+String\([ \t]*[A-Za-z0-9_]+[ \t]*\)|\.getBytes\([ \t]*\)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=5,
        rule_id="java.io.twr",
        title="Closeable created outside try-with-resources",
        regex=re.compile(
            r"new[ \t]+(File(Input|Output)Stream|Buffered(Reader|Writer)|Scanner"
            r"|FileReader|FileWriter|Connection|PreparedStatement)\("
        ),
        exclude_regex=re.compile(r"try[ \t]*\("),
        thresholds=((0, "warning"),),
        description="Wrap AutoCloseable objects in try-with-resources or close them in finally blocks",
    ),
    # ── Category 12: JAVA 21 FEATURES (INFO) ────────────────────────────────
    Pattern(
        category=12,
        rule_id="java.java21.virtual-threads",
        title="Virtual threads in use - ensure blocking operations are appropriate",
        regex=re.compile(r"Thread\.ofVirtual\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="java.java21.structured-task-scope",
        title="StructuredTaskScope in use - validate proper join/shutdown handling",
        regex=re.compile(r"StructuredTaskScope"),
        thresholds=((0, "info"),),
    ),
]
