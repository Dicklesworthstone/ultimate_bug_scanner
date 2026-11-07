"""swift_detectors.outbound_url — cat 6 "Request-derived outbound HTTP URLs" (SSRF).

The shared scoped frontend follows selected helpers, value overwrites and
dominating scheme/host checks. File-URL readers keep their separate path
obligation. Unknown HTTP receivers remain explicitly incomplete.
"""
from __future__ import annotations

from pathlib import Path

from ubs_core.analyzers.taint_swift_traversal import flow_findings
from ubs_core.swift_detectors._common import (
    SKIP_DIRS, should_skip, source_line,
)

RULE_ID = "swift.taint.outbound-url"
CATEGORY = 6
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"


def scan(ctx):
    project = ctx.project_dir
    root = project.resolve()
    base = root if root.is_dir() else root.parent
    for candidate in ctx.files:
        path = Path(candidate).resolve()
        if path.suffix != '.swift':
            continue
        if path != root and should_skip(path, base, SKIP_DIRS):
            continue
        text = path.read_text(encoding='utf-8')
        lines = text.splitlines()
        for finding in flow_findings(path, text, 'outbound'):
            line_no = finding['line']
            yield {
                **finding,
                "category": CATEGORY,
                "count": 1,
                "title": TITLE,
                "description": "Validate the selected URL's HTTPS scheme and exact host before an outbound HTTP operation.",
                "samples": [{"path": str(path), "line": line_no, "code": source_line(lines, line_no)}],
            }
