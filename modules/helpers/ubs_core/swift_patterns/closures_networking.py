"""swift_patterns.closures_networking — categories 3-4 (closures, URLSession).

The strong-self capture check is the legacy `rg | grep -A3 -E '\\{...' |
grep -vi '\\[weak self\\]' | count_lines` intent pipeline, reproduced with the
ordered-stream window emulation.
"""
from __future__ import annotations

from ubs_core.swift_scan import Pattern

PATTERNS = [
    # 3. CLOSURES / CAPTURE LISTS — the strong-self pipeline pattern is kept
    # only as documentation: its legacy rg regex has an unmatched ")" (ubs
    # GREP_RN -e "(...\.onReceive\\()))") and never compiles, so the check is
    # always the good note. No Pattern is emitted for it.
    Pattern(3, "swift.closures.unowned-self", "[unowned self] in closures",
            r"\[[^\]]*unowned\s+self[^\]]*\]", ((0, "warning"),), show_samples=True),
    # 4. URLSESSION / NETWORKING
    Pattern(4, "swift.networking.task-sites", "URLSession tasks created",
            r"\.(dataTask|uploadTask|downloadTask)\s*\(", ((0, "info"),)),
    Pattern(4, "swift.networking.http-literals", "http:// URLs",
            r"\"http://[^\"]+\"", ((0, "warning"),),
            exclude_regex=r"http://www\.apple\.com/DTDs", show_samples=True),
    Pattern(4, "swift.networking.data-contents", "Data(contentsOf:) usage may block",
            r"Data\(contentsOf:", ((0, "warning"),), show_samples=True),
    Pattern(4, "swift.networking.manual-query", "Manual URL query strings",
            r"URL\(string:\s*\"https?://[^\"\?]+\?[^\"\)]*\"\)",
            ((0, "info"),), show_samples=True),
]
