"""ubs_core.py_detectors.path_traversal — category 7 security (bead 0xjg.5).

Port of run_path_traversal_checks (modules/ubs-python.sh 6208-6466): an
ast.NodeVisitor that taints names assigned from request data
(request.args/values/form/headers/META/GET/POST/query_params/path_params/
match_info/cookies/files/FILES) plus upload-file variables (request.files
handles and their propagations), then flags file sinks whose path argument is
request-derived: open/io.open/send_file/FileResponse positional or
file/filename/path keywords, Path method sinks (open/read_text/read_bytes/
write_text/write_bytes — the receiver is the argument), and .save() on
upload handles (positional or dst/destination/file/filename/path keywords).
FileResponse(open(...)) is skipped so only the inner open is reported.
safe_join/secure_filename/basename/commonpath/... in the expression, or a
validator or hand-rolled traversal guard (quote-in check, startswith,
normpath/realpath/resolve) mentioning the tainted name within the preceding
12 lines, suppresses the hit.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.path-traversal"
CATEGORY = 7
TITLE = "Request-derived path reaches file read/download/write sink"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate paths with safe_join, secure_filename, or a resolved-base "
    "containment check before opening, sending, or saving files"
)

REQUEST_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:args|values|form|headers|META|GET|POST|query_params|path_params|match_info|cookies|files|FILES)\b'
    r'|\b(?:self\.)?request\.(?:GET|POST|query_params|path_params|match_info|headers|META|FILES)\b',
    re.IGNORECASE,
)
UPLOAD_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:files|FILES)\b'
    r'|\b(?:self\.)?request\.FILES\b',
    re.IGNORECASE,
)
SAFE_VALIDATOR_RE = re.compile(
    r'\b(?:safe_join|secure_filename|validate_path|validate_file|validate_filename|'
    r'safe_path|safe_filename|sanitize_path|sanitize_filename|allowed_path|allowed_file|'
    r'is_safe_path|is_safe_file|commonpath|relative_to|is_relative_to|basename)\b',
    re.IGNORECASE,
)
# Hand-rolled traversal guards that reject '..', '/' or '\' in the value, or
# check containment/prefixes explicitly. A handler that already rejects
# traversal sequences right before the sink is not an open path sink (#64).
MANUAL_GUARD_RE = re.compile(
    r'["\'](?:\.\.|/|\\\\)["\']\s*(?:not\s+)?in\b'
    r'|\bstartswith\s*\('
    r'|\bnormpath\s*\('
    r'|\brealpath\s*\('
    r'|\.resolve\s*\('
)
PATH_METHODS = {'open', 'read_text', 'read_bytes', 'write_text', 'write_bytes'}
PATH_FUNCTION_SINKS = {
    'open',
    'io.open',
    'send_file',
    'flask.send_file',
    'FileResponse',
    'django.http.FileResponse',
    'starlette.responses.FileResponse',
    'fastapi.responses.FileResponse',
}
FILE_RESPONSE_SINKS = {'FileResponse', 'django.http.FileResponse', 'starlette.responses.FileResponse', 'fastapi.responses.FileResponse'}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


class _PathTraversalAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted = {}
        self.upload_file_vars = set()
        self.issues = []

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def is_request_source(self, node):
        return bool(REQUEST_SOURCE_RE.search(self.segment(node)))

    def is_upload_source(self, node):
        return bool(UPLOAD_SOURCE_RE.search(self.segment(node)))

    def has_safe_expression(self, node):
        return bool(SAFE_VALIDATOR_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def tainted_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.tainted)

    def upload_file_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.upload_file_vars)

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def safe_validation_context(self, names, line_no):
        if not names:
            return False
        start = max(0, line_no - 12)
        context = '\n'.join(self.lines[start:line_no])
        if not (SAFE_VALIDATOR_RE.search(context) or MANUAL_GUARD_RE.search(context)):
            return False
        return any(re.search(rf'\b{re.escape(name)}\b', context) for name in names)

    def mark_assignment(self, names, value):
        if self.has_safe_expression(value):
            for name in names:
                self.tainted.pop(name, None)
                self.upload_file_vars.discard(name)
            return
        if self.is_request_source(value):
            for name in names:
                self.tainted[name] = 'request'
                if self.is_upload_source(value):
                    self.upload_file_vars.add(name)
            return
        upload_refs = self.upload_file_names_in(value)
        if upload_refs:
            for name in names:
                self.tainted[name] = upload_refs[0]
                self.upload_file_vars.add(name)
            return
        refs = self.tainted_names_in(value)
        if refs:
            for name in names:
                self.tainted[name] = refs[0]
            return
        for name in names:
            self.tainted.pop(name, None)
            self.upload_file_vars.discard(name)

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.generic_visit(node)

    def sink_argument(self, node):
        name = _call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        if name in PATH_FUNCTION_SINKS or short_name in PATH_FUNCTION_SINKS:
            for keyword in node.keywords:
                if keyword.arg in {'file', 'filename', 'path'}:
                    return keyword.value
            if node.args:
                if (name in FILE_RESPONSE_SINKS or short_name in FILE_RESPONSE_SINKS) and self.call_is_open(node.args[0]):
                    return None
                return node.args[0]
        if isinstance(node.func, ast.Attribute) and short_name in PATH_METHODS:
            return node.func.value
        if isinstance(node.func, ast.Attribute) and short_name == 'save' and node.args:
            owner = node.func.value
            if self.is_upload_source(owner) or self.upload_file_names_in(owner):
                return node.args[0]
        if isinstance(node.func, ast.Attribute) and short_name == 'save':
            owner = node.func.value
            if self.is_upload_source(owner) or self.upload_file_names_in(owner):
                for keyword in node.keywords:
                    if keyword.arg in {'dst', 'destination', 'file', 'filename', 'path'}:
                        return keyword.value
        return None

    def call_is_open(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = _call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        return name in {'open', 'io.open'} or short_name == 'open'

    def visit_Call(self, node):
        if _has_ignore(self.lines, node.lineno):
            self.generic_visit(node)
            return
        arg = self.sink_argument(node)
        if arg is not None:
            direct = self.is_request_source(arg)
            refs = self.tainted_names_in(arg)
            if (direct or refs) and not self.has_safe_expression(arg) and not self.safe_validation_context(refs, node.lineno):
                self.issues.append((self.path, node.lineno, _source_line(self.lines, node.lineno)))
        self.generic_visit(node)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        analyzer = _PathTraversalAnalyzer(path, text, lines)
        analyzer.visit(tree)
        for _, line_no, code in analyzer.issues:
            yield path, line_no, 1, code.strip()[:240]
