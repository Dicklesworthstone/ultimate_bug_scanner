"""swift_patterns.misc_cats — categories 15, 17-23 (quality, plist, deprecations,
build, packaging, UI safety, tests, l10n).

Category 15 sums four case-insensitive marker counts (TODO/FIXME/HACK/XXX) via
Pattern.components — a line matching several markers counts once per marker,
like the legacy four-pipeline sum. Category 20 (Package.swift) and the
storyboard count are filesystem-gated derived checks.
"""
from __future__ import annotations

import os
from pathlib import Path

from ubs_core.swift_scan import Pattern

PATTERNS = [
    # 15. CODE QUALITY MARKERS — legacy TODO/FIXME/HACK/XXX RNI sum
    Pattern(15, "swift.quality.debt-heavy", "Significant technical debt",
            "", ((20, "warning"),),
            components=(r"TODO", r"FIXME", r"HACK", r"XXX")),
    Pattern(15, "swift.quality.debt-moderate", "Moderate technical debt",
            "", ((10, "info"),), max_count=20,
            components=(r"TODO", r"FIXME", r"HACK", r"XXX")),
    Pattern(15, "swift.quality.debt-minimal", "Minimal technical debt",
            "", ((0, "info"),), max_count=10,
            components=(r"TODO", r"FIXME", r"HACK", r"XXX")),
    # 17. INFO.PLIST / ATS — regex heuristics (precise parse = detector)
    Pattern(17, "swift.infoplist.ats-regex", "ATS arbitrary loads enabled",
            r"NSAppTransportSecurity|NSAllowsArbitraryLoads", ((0, "warning"),),
            include_regex=r"true|YES"),
    Pattern(17, "swift.infoplist.web-content", "Arbitrary loads in web content enabled",
            r"NSAllowsArbitraryLoadsInWebContent", ((0, "info"),),
            include_regex=r"true|YES"),
    # 18. DEPRECATED APIs
    Pattern(18, "swift.deprecations.webview", "Deprecated networking/webview APIs",
            r"UIWebView|NSURLConnection", ((0, "warning"),), show_samples=True),
    Pattern(18, "swift.deprecations.statusbar", "Deprecated UIKit status bar/keyWindow APIs",
            r"statusBarFrame|setStatusBarHidden|UIApplication\.shared\.keyWindow",
            ((0, "info"),), show_samples=True),
    # 19. BUILD / SIGNING — regex heuristic (precise parse = detector)
    Pattern(19, "swift.build.debug-signing", "Debug-like signing strings detected",
            r"PROVISIONING_PROFILE_SPECIFIER|CODE_SIGN_IDENTITY", ((0, "info"),),
            include_regex=r"(?i)debug"),
    # 21. UI/UX SAFETY
    Pattern(21, "swift.uisafety.iboutlet-iuo", "IBOutlet implicitly unwrapped",
            r"@IBOutlet\s+weak\s+var\s+[A-Za-z_][A-Za-z0-9_]*:[^!]*!",
            ((0, "info"),), show_samples=True),
    # 22. TESTS / HYGIENE
    Pattern(22, "swift.tests.xctfail-todo", "Placeholder XCTFail",
            r"XCTFail\(\"TODO", ((0, "info"),), show_samples=True),
    Pattern(22, "swift.tests.sleeps", "Sleep in tests - use expectations",
            r"XCTestCase|XCT", ((0, "info"),),
            window=4, after_regex=r"sleep\(|usleep\(", include_regex=r"sleep\(|usleep\("),
    # 23. LOCALIZATION
    Pattern(23, "swift.l10n.ui-strings", "Possible user-facing strings without localization",
            r"UILabel\(|setTitle\(|Text\(\"", ((0, "info"),),
            exclude_regex=r"NSLocalizedString"),
    Pattern(23, "swift.l10n.string-format", "String(format:) without explicit locale",
            r"String\(format:", ((0, "info"),),
            exclude_regex=r"locale:"),
]


def _packaging(ctx):
    """Legacy cat 20: Package.swift branch/revision + unsafeFlags checks."""
    manifest = next((p for p in ctx.files if p.name == "Package.swift"
                     and p.parent == (ctx.project_dir if ctx.project_dir.is_dir()
                                      else ctx.project_dir)), None)
    if manifest is None:
        # legacy: a Package.swift directly under the scan root
        direct = ctx.project_dir / "Package.swift"
        if not direct.is_file():
            yield {
                "rule": "swift.packaging.no-manifest",
                "category": 20,
                "path": "", "line": 0,
                "severity": "info",
                "count": 0,
                "title": "Package.swift not found",
                "message": "Package.swift not found",
                "description": "Skipping SPM checks",
            }
            return
        manifest = direct
    import re

    def _count(regex: str) -> int:
        total = 0
        text = ctx.text_of(manifest)
        seen = set()
        for match in re.compile(regex).finditer(text):
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

    branch = _count(r"\.branch\(|\.revision\(")
    if branch:
        yield {
            "rule": "swift.packaging.branch-pins",
            "category": 20,
            "path": str(manifest), "line": 0,
            "severity": "info",
            "count": branch,
            "title": "Branch/revision-based SPM dependencies",
            "message": "Branch/revision-based SPM dependencies",
        }
    unsafe = _count(r"\.unsafeFlags\(")
    if unsafe:
        yield {
            "rule": "swift.packaging.unsafe-flags",
            "category": 20,
            "path": str(manifest), "line": 0,
            "severity": "warning",
            "count": unsafe,
            "title": "SPM unsafeFlags used",
            "message": "SPM unsafeFlags used",
        }


def _storyboards(ctx):
    """Legacy cat 21: raw find for *.storyboard under the scan root."""
    root = ctx.project_dir
    count = 0
    if root.is_dir():
        for dp, _dn, fn in os.walk(root):
            for name in fn:
                if name.endswith(".storyboard"):
                    count += 1
    elif root.is_file() and root.suffix == ".storyboard":
        count = 1
    if count > 5:
        yield {
            "rule": "swift.uisafety.storyboards",
            "category": 21,
            "path": "", "line": 0,
            "severity": "info",
            "count": count,
            "title": "Many storyboards - consider modularization",
            "message": "Many storyboards - consider modularization",
        }


DERIVED = [_packaging, _storyboards]
