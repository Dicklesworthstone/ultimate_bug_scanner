"""swift_patterns.closures_networking — categories 3-4 (closures, URLSession).

The strong-self capture check is the legacy `rg | grep -A3 -E '\\{...' |
grep -vi '\\[weak self\\]' | count_lines` intent pipeline, reproduced with the
ordered-stream window emulation.
"""
from __future__ import annotations

from ubs_core.swift_scan import Pattern

STRONG_SELF_TRIGGER = (
    r"(URLSession\.|DispatchQueue\.(global|main)|Timer\.scheduledTimer|"
    r"NotificationCenter\.default\.addObserver|UIView\.animate|"
    r"NSAnimationContext\.runAnimationGroup|\.sink\(|\.onReceive\()"
)

PATTERNS = [
    # 3. CLOSURES / CAPTURE LISTS
    Pattern(3, "swift.closures.strong-self", "Potential strong self captures in long-lived closures",
            STRONG_SELF_TRIGGER, ((0, "warning"),),
            window=3, after_regex=r"\{\s*(\[[^\]]*\])?",
            exclude_regex=r"\[weak self\]", show_samples=True),
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
