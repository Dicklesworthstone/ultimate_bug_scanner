"""swift_patterns.foundations — categories 1-2 (optionals, concurrency).

Verbatim ports of the legacy rg pipelines in modules/ubs-swift.sh category
blocks 1 and 2 (GREP_RN/GREP_RNW + count_lines ladders). The un-awaited-async
check needs two project-wide counts, so it rides the DERIVED hook.
"""
from __future__ import annotations

import re

from ubs_core.swift_scan import Pattern

FORCE_UNWRAP = r"!(\s|\.|\(|\)|\[|\]|\{|\}|,|;|:|\?|$)"

PATTERNS = [
    # 1. OPTIONALS / FORCE OPERATIONS — force unwrap >30 warns, else info
    Pattern(1, "swift.optionals.force-heavy", "Heavy use of force unwrap",
            FORCE_UNWRAP, ((30, "warning"),), swift_only=True, show_samples=True),
    Pattern(1, "swift.optionals.force-some", "Some force unwraps present",
            FORCE_UNWRAP, ((0, "info"),), swift_only=True, max_count=30, show_samples=True),
    Pattern(1, "swift.optionals.try-bang", "try! used",
            r"\btry!", ((0, "warning"),), show_samples=True),
    Pattern(1, "swift.optionals.as-bang", "as! used",
            r"\bas!\s", ((0, "warning"),), show_samples=True),
    Pattern(1, "swift.optionals.iuo", "Implicitly unwrapped optionals",
            r"(:|->)\s*[A-Za-z_][A-Za-z0-9_<>?:\.\[\] ]*!\b",
            ((0, "warning"),), show_samples=True),
    Pattern(1, "swift.optionals.url-bang", "URL(string:) force-unwrapped",
            r"URL\(string:[^\)]*\)!\b", ((0, "warning"),), show_samples=True),
    # 2. CONCURRENCY / TASK — "Task usages" prints even at zero
    Pattern(2, "swift.concurrency.task-usages", "Task usages",
            r"\bTask\b", ((-1, "info"),), always=True),
    Pattern(2, "swift.concurrency.escape-hatches", "Concurrency escape hatches used",
            r"@unchecked\s+Sendable|nonisolated\(unsafe\)",
            ((0, "warning"),), show_samples=True),
]


def _count_lines(ctx, regex: re.Pattern[str]) -> int:
    total = 0
    for path in ctx.files:
        text = ctx.text_of(path)
        seen = set()
        for match in regex.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            if line_no in seen:
                continue
            seen.add(line_no)
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            if line_end == -1:
                line_end = len(text)
            if "ubs:ignore" in text[line_start:line_end]:
                continue
            total += 1
    return total


def _unawaited_async(ctx):
    """Legacy: async count vs await count, info on the positive difference."""
    async_count = _count_lines(ctx, re.compile(r"\basync\s+"))
    await_count = _count_lines(ctx, re.compile(r"\bawait\b"))
    if async_count <= await_count:
        return
    diff = async_count - await_count
    yield {
        "rule": "swift.concurrency.unawaited-async",
        "category": 2,
        "path": "", "line": 0,
        "severity": "info",
        "count": diff,
        "title": "Possible un-awaited async paths",
        "message": "Possible un-awaited async paths",
    }


DERIVED = [_unawaited_async]
