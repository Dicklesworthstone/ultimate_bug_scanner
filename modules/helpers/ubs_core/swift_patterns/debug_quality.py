"""swift_patterns.debug_quality — categories 11-14 (debug, regex, SwiftUI, memory).

The print/NSLog ladder (>50 warn / >10 info / >0 info) splits into three
sibling patterns sharing one regex; only one tier fires per count.
"""
from __future__ import annotations

from ubs_core.swift_scan import Pattern

PRINT_NSLOG = r"^[ \t]*print\s*\(|\bNSLog\s*\("

PATTERNS = [
    # 11. DEBUG / PRODUCTION
    Pattern(11, "swift.debug.print-many", "Many print/NSLog calls",
            PRINT_NSLOG, ((50, "warning"),), multiline=True),
    Pattern(11, "swift.debug.print-some", "print/NSLog present",
            PRINT_NSLOG, ((10, "info"),), max_count=50, multiline=True),
    Pattern(11, "swift.debug.print-minimal", "Minimal print/NSLog",
            PRINT_NSLOG, ((0, "info"),), max_count=10, multiline=True),
    Pattern(11, "swift.debug.ifdebug", "#if DEBUG present",
            r"#if\s+DEBUG", ((0, "info"),)),
    Pattern(11, "swift.debug.failing-asserts", "Assertions that always fail",
            r"assert\(false\)|assertionFailure\(", ((0, "warning"),), show_samples=True),
    # 12. REGEX
    Pattern(12, "swift.regex_cat.nested-quantifiers", "Potential catastrophic regex",
            r"NSRegularExpression\(pattern:[^\)]*(\+\+|\*\+|\+\*|\*\*)[^\)]*\)",
            ((1, "warning"),), show_samples=True),
    Pattern(12, "swift.regex_cat.nspredicate", "NSPredicate(format:) used",
            r"NSPredicate\(format:", ((0, "info"),), show_samples=True),
    # 13. SWIFTUI / COMBINE
    Pattern(13, "swift.swiftui.sink-unstored", "Combine sinks not stored",
            r"\.sink\(", ((0, "warning"),),
            exclude_regex=r"\.store\(in:", show_samples=True),
    Pattern(13, "swift.swiftui.onreceive", "SwiftUI .onReceive present",
            r"\.onReceive\(", ((0, "info"),), show_samples=True),
    # 14. MEMORY / RETAIN
    Pattern(14, "swift.memory.timers", "Timers scheduled",
            r"Timer\.scheduledTimer", ((0, "warning"),), show_samples=True),
    Pattern(14, "swift.memory.block-observers", "Block-based observer sites",
            r"addObserver\(forName:", ((0, "warning"),), show_samples=True),
    Pattern(14, "swift.memory.cadisplaylink", "CADisplayLink created",
            r"CADisplayLink\s*\(", ((0, "warning"),), show_samples=True),
]
