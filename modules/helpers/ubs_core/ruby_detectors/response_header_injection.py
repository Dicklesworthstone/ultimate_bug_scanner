"""Scoped Ruby response-header injection with exact value validation.

The shared Ruby frontend resolves local values, helpers, aliases and branches.
Only actual CR/LF removal, URL-component encoding, or dominating rejection
checks establish safety. Location values belong to the open-redirect policy.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.ruby_detectors._common import (
    EXTS,
    read_lines,
    ruby_files,
)

RULE_ID = "ruby.header-injection.response"
CATEGORY = 6
TITLE = "Request-derived value reaches response header"
SEVERITY = "critical"
DESCRIPTION = (
    "Reject or strip CR/LF before writing request data to response headers; "
    "use encoded filenames or a header-safe helper for Content-Disposition values"
)

def findings(path_str, text):
    if not (re.search(r'\b(?:params|request|req|rack_request|env|Rack::Request|cookies)\b', text)
            and re.search(r'\b(?:headers|response|send_data|send_file)\b', text)):
        return
    from ubs_core.analyzers.taint_ruby_traversal import HEADER_RULE, flow_findings_from_text

    for rule, line_no, code, extras in flow_findings_from_text(Path(path_str), text, 'header') or ():
        if rule == HEADER_RULE:
            yield path_str, line_no, 1, code, extras


def analyze(lines, issues, path_str):
    issues.extend(findings(path_str, "\n".join(lines)))


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        yield from findings(str(path), "\n".join(lines))
