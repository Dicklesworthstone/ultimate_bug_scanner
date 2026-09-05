"""ubs_core.java_patterns.foundations — categories 1, 2, 13, 14, 20, 21 (bead 0xjg.8).

Faithful ports of the single-regex legacy rg pipelines:
- cat 1  (3443): null equality checks, info when >0.
- cat 2  (3466-3490): String '==' comparisons (warning), BigDecimal.equals
  (info; legacy piped `grep BigDecimal` through `grep -E '\\.equals\\('` — a
  line must match both, expressed as require_regex), boxed '==' (info).
- cat 13 (3780): string-concatenated SQL, warning when >0.
- cat 14 (3814-3818): @Nullable / @Deprecated annotations, info.
- cat 20 (3964-3969): Paths.get with '+' and unchecked File.delete().
- cat 21 (3982): secret-like identifier assignments, warning (case-insensitive
  GREP_RNI). The legacy `ast_search 'String $K = $V;'` conjunct only ever
  matched .java files with the java grammar; on every manifest fixture it
  contributes 0, so the v2 keeps the rg half (documented divergence).
"""
from __future__ import annotations

import re

from ubs_core.java_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 1: NULL & OPTIONAL PITFALLS ────────────────────────────────
    Pattern(
        category=1,
        rule_id="java.null-optional.null-equality",
        title="Null equality checks present - consider Objects.isNull/nonNull where expressive",
        regex=re.compile(r"==[ \t]*null|null[ \t]*=="),
        thresholds=((0, "info"),),
    ),
    # ── Category 2: EQUALITY & HASHCODE ─────────────────────────────────────
    Pattern(
        category=2,
        rule_id="java.equality.string-eq",
        title="String compared with '=='",
        regex=re.compile(r'==[ \t]*"|"[ \t]*=='),
        thresholds=((0, "warning"),),
        description="Use equals() or Objects.equals(a,b)",
    ),
    Pattern(
        category=2,
        rule_id="java.equality.bigdecimal-equals",
        title="BigDecimal.equals usage - consider compareTo()==0",
        regex=re.compile(r"BigDecimal"),
        require_regex=re.compile(r"\.equals\("),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=2,
        rule_id="java.equality.boxed-eq",
        title="Boxed primitives using '==' - consider equals()/Objects.equals()",
        regex=re.compile(r"\b(Integer|Long|Short|Byte|Boolean|Double|Float)\b[^;\n]*==[^;\n]*"),
        thresholds=((0, "info"),),
    ),
    # ── Category 13: SQL CONSTRUCTION (HEURISTICS) ──────────────────────────
    Pattern(
        category=13,
        rule_id="java.sql.concat",
        title="SQL built via concatenation - prefer parameters",
        regex=re.compile(r'"(SELECT|INSERT|UPDATE|DELETE)[^"]*"[ \t]*\+[ \t]*[A-Za-z0-9_]'),
        thresholds=((0, "warning"),),
        description="Prefer PreparedStatement parameters over string concatenation",
    ),
    # ── Category 14: ANNOTATIONS & NULLNESS (HEURISTICS) ────────────────────
    Pattern(
        category=14,
        rule_id="java.annotations.nullable",
        title="@Nullable present - ensure null checks at use sites",
        regex=re.compile(r"@Nullable"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=14,
        rule_id="java.annotations.deprecated",
        title="Deprecated annotations present - verify migration plans",
        regex=re.compile(r"@Deprecated|@deprecated"),
        thresholds=((0, "info"),),
    ),
    # ── Category 20: PATH HANDLING & FILESYSTEM ─────────────────────────────
    Pattern(
        category=20,
        rule_id="java.filesystem.paths-plus",
        title="Paths.get with '+' - prefer resolve()/varargs",
        regex=re.compile(r"Paths\.get\([^)]*\+[^)]*\)"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=20,
        rule_id="java.filesystem.delete-unchecked",
        title="File.delete() return value not checked",
        regex=re.compile(r"\.delete\(\)[ \t]*;"),
        exclude_regex=re.compile(r"if[ \t]*\(|assert|check|ensure|\?:"),
        thresholds=((0, "info"),),
    ),
    # ── Category 13 (cont.): execute* with '+' — legacy primary layer ───────
    Pattern(
        category=13,
        rule_id="java.sql.exec-concat",
        title="execute* called with concatenated query string",
        # legacy post-pipe: `grep "\\+"` — the line must also contain a '+'.
        regex=re.compile(r"execute(Query|Update)[ \t]*\("),
        require_regex=re.compile(r"\+"),
        thresholds=((0, "warning"),),
    ),
    # ── Category 21: HARD-CODED SECRETS (HEURISTICS) ────────────────────────
    Pattern(
        category=21,
        rule_id="java.secrets.hardcoded",
        title="Potential hard-coded secrets found",
        # legacy GREP_RNI — case-insensitive.
        regex=re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key|auth|credential)[ \t]*=", re.IGNORECASE),
        thresholds=((0, "warning"),),
    ),
]
