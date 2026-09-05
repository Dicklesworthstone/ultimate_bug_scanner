"""ubs_core.py_detectors.open_redirect — category 7 security (bead 0xjg.5).

Port of run_open_redirect_checks (modules/ubs-python.sh 5407-5609):
an ast.NodeVisitor that taints names assigned from request data
(request.args/form/GET/POST/query_params/cookies/...) and flags redirect
sinks (flask.redirect, django HttpResponseRedirect, starlette/fastapi
RedirectResponse, ...) whose first positional or url/location/redirect_to
argument is request-derived. An assignment whose value contains a safe
validator (url_has_allowed_host_and_scheme, is_safe_url, url_for, reverse,
.netloc/.scheme, ...) clears the taint; a redirect argument or the preceding
10 lines mentioning a validator suppresses the hit.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.open-redirect"
CATEGORY = 7
TITLE = "Unvalidated redirect from request data"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate redirect targets with an allow-list or same-origin check "
    "before redirecting"
)

REQUEST_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:args|values|form|GET|POST|query_params|cookies|url|full_path)\b'
    r'|\b(?:self\.)?request\.(?:GET|POST|query_params|cookies)\b',
    re.IGNORECASE,
)
SAFE_VALIDATOR_RE = re.compile(
    r'\b(?:url_has_allowed_host_and_scheme|is_safe_url|is_safe_redirect|validate_redirect|'
    r'validate_next|safe_redirect_target|safe_next_url|same_origin|allowed_redirect|'
    r'sanitize_redirect|url_for|reverse)\b'
    r'|\.netloc\b|\.scheme\b',
    re.IGNORECASE,
)
REDIRECT_SINKS = {
    'redirect',
    'flask.redirect',
    'django.shortcuts.redirect',
    'HttpResponseRedirect',
    'HttpResponsePermanentRedirect',
    'RedirectResponse',
    'starlette.responses.RedirectResponse',
    'fastapi.responses.RedirectResponse',
}


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


class _RedirectAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted = {}
        self.issues = []

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def is_request_source(self, node):
        return bool(REQUEST_SOURCE_RE.search(self.segment(node)))

    def has_safe_expression(self, node):
        return bool(SAFE_VALIDATOR_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def tainted_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.tainted)

    def safe_validation_context(self, names, line_no):
        start = max(0, line_no - 10)
        context = '\n'.join(self.lines[start:line_no])
        if not SAFE_VALIDATOR_RE.search(context):
            return False
        if not names:
            return True
        return any(re.search(rf'\b{re.escape(name)}\b', context) for name in names)

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def redirect_argument(self, node):
        if node.args:
            return node.args[0]
        for keyword in node.keywords:
            if keyword.arg in {'url', 'location', 'redirect_to'}:
                return keyword.value
        return None

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            value = node.value
            if self.has_safe_expression(value):
                for name in names:
                    self.tainted.pop(name, None)
            elif self.is_request_source(value):
                for name in names:
                    self.tainted[name] = 'request'
            else:
                refs = self.tainted_names_in(value)
                if refs:
                    for name in names:
                        self.tainted[name] = refs[0]
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            if self.has_safe_expression(node.value):
                self.tainted.pop(node.target.id, None)
            elif self.is_request_source(node.value):
                self.tainted[node.target.id] = 'request'
            else:
                refs = self.tainted_names_in(node.value)
                if refs:
                    self.tainted[node.target.id] = refs[0]
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        if name in REDIRECT_SINKS or short_name in REDIRECT_SINKS:
            arg = self.redirect_argument(node)
            if arg is not None and not _has_ignore(self.lines, node.lineno):
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
        analyzer = _RedirectAnalyzer(path, text, lines)
        analyzer.visit(tree)
        for _, line_no, code in analyzer.issues:
            yield path, line_no, 1, code.strip()[:240]
