"""Swift response-header values on the bounded shared dataflow frontend.

Selected bindings, local helper summaries and dominating String checks carry
CR/LF proofs to the actual header value. Unsupported dispatch remains explicit
incomplete analysis, and Location values retain the separate redirect policy.
"""
from __future__ import annotations

from pathlib import Path

from ubs_core.swift_detectors._common import SKIP_DIRS, should_skip, source_line

RULE_ID = "swift.taint.header-injection"
CATEGORY = 6
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"


def scan(ctx):
    from ubs_core.analyzers.taint_swift_traversal import flow_findings

    project = ctx.project_dir
    root = project.resolve()
    base = root if root.is_dir() else root.parent
    for candidate in ctx.files:
        path = Path(candidate).resolve()
        if path.suffix != '.swift':
            continue
        if path != root and should_skip(path, base, SKIP_DIRS):
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        lines = text.splitlines()
        for finding in flow_findings(path, text, 'header'):
            line_no = finding['line']
            yield {
                **finding,
                "category": CATEGORY,
                "count": 1,
                "title": TITLE,
                "description": "Reject both CR and LF, strip both characters, or percent-encode with a proven safe character set before writing response headers.",
                "samples": [{"path": str(path), "line": line_no, "code": source_line(lines, line_no)}],
            }
