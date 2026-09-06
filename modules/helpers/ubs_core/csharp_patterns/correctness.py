"""ubs_core.csharp_patterns.correctness — cats 4/5/6/7/10.

Legacy: category_4_numeric_fp (1311-1335), category_5_collections_linq
(1337-1361), category_6_strings_alloc (1363-1378), category_7_io_process
(1380-1404), category_10_api_misuse (2959-2983).
"""
from __future__ import annotations

import re

from ubs_core.csharp_patterns._table import P

PATTERNS = [
    # ── cat 4 ──
    P(
        category=4, rule_id="cs.pattern.fp-equality", seq=210,
        label="FP equality",
        text="Floating/decimal equality comparisons ({n}) - review tolerance/precision",
        regex=re.compile(r'\b(float|double|decimal)\b.*(==|!=)'),
        severity="info",
    ),
    P(
        category=4, rule_id="cs.pattern.int-cast", seq=220,
        label="(int) cast",
        text="Casts to int ({n}) - possible truncation/overflow",
        regex=re.compile(r'\(\s*int\s*\)\s*[A-Za-z_][A-Za-z0-9_]*'),
        severity="info",
    ),
    # ── cat 5 ──
    P(
        category=5, rule_id="cs.pattern.linq-first", seq=230,
        label=".First(",
        text=".First(...) usages ({n}) - may throw on empty sequences; consider FirstOrDefault + null check",
        regex=re.compile(r'\.First\s*\('),
        severity="warning",
    ),
    P(
        category=5, rule_id="cs.pattern.count-gt-zero", seq=240,
        label=".Count() > 0",
        text=".Count() > 0 ({n}) - prefer .Any() for IEnumerable to avoid full enumeration",
        regex=re.compile(r'\.Count\s*\(\s*\)\s*>\s*0'),
        severity="info",
    ),
    # ── cat 6 ──
    P(
        category=6, rule_id="cs.pattern.string-plus-eq", seq=250,
        label="String +=",
        text="String '+=' concatenation ({n}) - in loops consider StringBuilder",
        regex=re.compile(r'\+\=\s*"[^"]*"'),
        severity="info",
    ),
    # ── cat 7 ──
    P(
        category=7, rule_id="cs.pattern.process-start", seq=260,
        label="Process.Start",
        text="Process.Start(...) ({n}) - ensure inputs are validated/escaped",
        regex=re.compile(r'\bProcess\.Start\s*\('),
        severity="warning",
    ),
    P(
        category=7, rule_id="cs.pattern.path-combine-input", seq=270,
        label="Path.Combine(user input)",
        text="Path.Combine with user-ish input ({n}) - review for path traversal",
        regex=re.compile(r'\bPath\.Combine\s*\([^)]*(request|query|input|user|param|args)\b'),
        severity="info",
    ),
    # ── cat 10 ──
    P(
        category=10, rule_id="cs.pattern.datetime-now", seq=280,
        label="DateTime.Now",
        text="DateTime.Now ({n}) - consider DateTime.UtcNow or TimeProvider for testability",
        regex=re.compile(r'\bDateTime\.Now\b'),
        severity="info",
    ),
    P(
        category=10, rule_id="cs.pattern.gc-collect", seq=290,
        label="GC.Collect",
        text="GC.Collect() ({n}) - usually indicates perf issues or misconception",
        regex=re.compile(r'\bGC\.Collect\s*\('),
        severity="warning",
    ),
]
