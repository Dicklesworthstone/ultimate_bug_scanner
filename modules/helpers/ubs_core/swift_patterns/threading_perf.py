"""swift_patterns.threading_perf — categories 8-10 (files, threading, perf).

Category 8's FileHandle open/close imbalance and category 9's @MainActor
presence check are cross-count ladders; they ride the DERIVED hook. The
loop-adjacent perf checks reproduce `rg | grep -A<N> | grep -E | count_lines`.
"""
from __future__ import annotations

import re

from ubs_core.swift_scan import Pattern

LOOP_REGEX = r"for\s+.+\s+in\s+.+\{"

PATTERNS = [
    # 8. FILES & I/O
    Pattern(8, "swift.files.string-contents", "String(contentsOf:) may block",
            r"String\(contentsOf:", ((0, "warning"),), show_samples=True),
    Pattern(8, "swift.files.path-concat", "String path join - use URL(fileURLWithPath:) or appendingPathComponent",
            r"\"/\"\s*\+", ((10, "info"),)),
    # 9. THREADING / MAIN — rg lines cannot span newlines in ripgrep, so the
    #    {0,250} lookahead window is bounded to one line, matching rg semantics
    Pattern(9, "swift.threading.sleep-main", "sleep on main queue",
            r"DispatchQueue\.main\.(async|sync)\s*\{[^\n]{0,250}(sleep\(|usleep\()",
            ((0, "warning"),), show_samples=True),
    Pattern(9, "swift.threading.main-sync", "DispatchQueue.main.sync (deadlock risk)",
            r"DispatchQueue\.main\.sync\s*\{", ((0, "warning"),), show_samples=True),
    # 10. PERFORMANCE
    Pattern(10, "swift.perf.string-loops", "String += in loops - consider join/builders",
            LOOP_REGEX, ((5, "info"),),
            window=6, after_regex=r"\+=", include_regex=r"\+="),
    Pattern(10, "swift.perf.regex-loops", "Regex compiled inside/near loop",
            LOOP_REGEX, ((0, "info"),),
            window=10, after_regex=r"NSRegularExpression\(",
            include_regex=r"NSRegularExpression\("),
    Pattern(10, "swift.perf.formatter-churn", "Many formatter/encoder/decoder constructions",
            r"DateFormatter\(\)|JSONDecoder\(\)|JSONEncoder\(\)|NumberFormatter\(\)",
            ((50, "info"),)),
]


def _distinct_line_count(ctx, regex: re.Pattern[str]) -> int:
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


def _filehandle_imbalance(ctx):
    """Legacy cat 8: FileHandle opens vs .close() calls, warning on the diff."""
    opens = _distinct_line_count(
        ctx, re.compile(r"FileHandle\s*\(\s*for(Reading|Writing|Updating)(From|To|AtPath)\s*:"))
    closes = _distinct_line_count(ctx, re.compile(r"\.close\s*\(\)"))
    if opens <= 0 or closes >= opens:
        return
    yield {
        "rule": "swift.files.filehandle",
        "category": 8,
        "path": "", "line": 0,
        "severity": "warning",
        "count": opens - closes,
        "title": "FileHandle open without matching close",
        "message": "FileHandle open without matching close",
    }


def _main_actor_presence(ctx):
    """Legacy cat 9: UI frameworks but zero @MainActor annotations."""
    ui_files = []
    for path in ctx.files:
        text = ctx.text_of(path)
        if re.search(r"UIKit|AppKit|SwiftUI", text):
            ui_files.append(path)
    mainactor = _distinct_line_count(ctx, re.compile(r"@MainActor"))
    if ui_files and mainactor == 0:
        yield {
            "rule": "swift.threading.main-actor",
            "category": 9,
            "path": "", "line": 0,
            "severity": "info",
            "count": len(ui_files),
            "title": "UI frameworks used but no @MainActor annotations found",
            "message": "UI frameworks used but no @MainActor annotations found",
        }


DERIVED = [_filehandle_imbalance, _main_actor_presence]
