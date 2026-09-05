"""ubs_core.py_detectors.host_header_poisoning — category 7 security (bead 0xjg.5).

Port of run_host_header_poisoning_checks (modules/ubs-python.sh 5611-5917):
an ast.NodeVisitor tracking two per-scope name sets (host-tainted vs
config-safe). Host sources are request.get_host()/build_absolute_uri(),
request.host/host_url/url_root/base_url/url attributes, and Host /
HTTP_HOST / X-Forwarded-Host lookups on request/headers/META/environ.
Flagged: urlish-named assignments that carry host taint, implicit-host calls
(request.build_absolute_uri(), url_for(..., _external=True) without safe
config), and host-sensitive sinks (send_mail, templates, jsonify, redirect,
...) receiving tainted values. urljoin/urlunsplit/urlunparse over safe
config, SAFE_HOST_FUNCS validators, and configured canonical names
(SITE_URL, PUBLIC_BASE_URL, settings.*, os.environ[...], ...) count as safe.

Line-deduped per file; same-file and previous-line ``ubs:ignore`` markers
suppress a hit.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.host-header-poisoning"
CATEGORY = 7
TITLE = "Request Host header used to build absolute URL"
SEVERITY = "critical"
DESCRIPTION = (
    "Use a configured canonical base URL or validate the host against an "
    "allow-list before generating password reset, email, redirect, or "
    "callback links"
)

REQUEST_NAMES = {'request'}
URLISH_NAMES = {
    'url', 'uri', 'link', 'callback', 'redirect', 'next', 'return_to',
    'reset', 'confirm', 'verify', 'invite', 'activation', 'absolute',
}
HOST_SINKS = {
    'send_mail', 'django.core.mail.send_mail',
    'EmailMessage', 'django.core.mail.EmailMessage',
    'EmailMultiAlternatives', 'django.core.mail.EmailMultiAlternatives',
    'Message', 'flask_mail.Message',
    'render', 'django.shortcuts.render',
    'render_template', 'flask.render_template',
    'render_template_string', 'flask.render_template_string',
    'jsonify', 'flask.jsonify',
    'JsonResponse', 'django.http.JsonResponse',
    'Response', 'flask.Response',
    'redirect', 'flask.redirect',
    'HttpResponseRedirect', 'django.http.HttpResponseRedirect',
    'HttpResponsePermanentRedirect', 'django.http.HttpResponsePermanentRedirect',
    'RedirectResponse', 'starlette.responses.RedirectResponse',
}
SAFE_HOST_FUNCS = {
    'validate_host', 'validate_allowed_host', 'allowed_host', 'allowlisted_host',
    'trusted_host', 'is_allowed_host', 'is_trusted_host', 'get_canonical_host',
    'canonical_host', 'canonical_base_url', 'public_base_url', 'site_base_url',
    'absolute_url_from_settings', 'build_absolute_url_from_settings',
    'url_has_allowed_host_and_scheme',
}
SAFE_CONFIG_NAMES = {
    'SITE_URL', 'PUBLIC_BASE_URL', 'BASE_URL', 'CANONICAL_URL',
    'CANONICAL_BASE_URL', 'CANONICAL_HOST', 'SERVER_NAME',
    'settings.SITE_URL', 'settings.PUBLIC_BASE_URL', 'settings.BASE_URL',
    'settings.CANONICAL_URL', 'settings.CANONICAL_BASE_URL',
    'settings.CANONICAL_HOST', 'settings.SERVER_NAME',
}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ''


def _const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


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


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return _rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return _rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return _rooted_at_request(node.value)
    return False


def _subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return _const_string(node.slice)


def _keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _truthy_constant(node):
    return isinstance(node, ast.Constant) and bool(node.value) is True


def _name_is_urlish(name):
    lowered = name.lower()
    return any(token in lowered for token in URLISH_NAMES)


class _HostHeaderPoisoningAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.host_tainted = set()
        self.safe_values = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.path, line_no, _source_line(self.lines, line_no)))

    def expr_uses_safe_config(self, node):
        for child in ast.walk(node):
            name = _call_name(child)
            if name in SAFE_CONFIG_NAMES:
                return True
            if isinstance(child, ast.Subscript):
                owner = _call_name(child.value)
                key = _subscript_key(child)
                if owner.endswith('.config') and key in SAFE_CONFIG_NAMES:
                    return True
                if owner in {'os.environ', 'environ'} and key in SAFE_CONFIG_NAMES:
                    return True
        return False

    def expr_is_safe(self, node):
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if self.expr_uses_safe_config(node):
            return True
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_HOST_FUNCS or short in SAFE_HOST_FUNCS:
                return True
            if short in {'urljoin', 'urlunsplit', 'urlunparse'} and self.expr_uses_safe_config(node):
                return True
        return False

    def expr_is_host_source(self, node):
        name = _call_name(node)
        if isinstance(node, ast.Call) and _rooted_at_request(node.func):
            short = name.rsplit('.', 1)[-1]
            return short in {'get_host', 'build_absolute_uri'}
        if isinstance(node, ast.Attribute) and _rooted_at_request(node.value):
            return node.attr in {'host', 'host_url', 'url_root', 'base_url', 'url'}
        if isinstance(node, ast.Subscript):
            key = _subscript_key(node)
            owner = _call_name(node.value)
            if key and key.lower() in {'host', 'http_host', 'x-forwarded-host', 'x_host'}:
                return _rooted_at_request(node.value) or owner.endswith('.headers') or owner.endswith('.META') or owner.endswith('.environ')
        return False

    def expr_contains_host_taint(self, node):
        if self.expr_is_safe(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.host_tainted
        if self.expr_is_host_source(node):
            return True
        return any(self.expr_contains_host_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value, line_no):
        is_safe = self.expr_is_safe(value)
        is_tainted = (not is_safe) and self.expr_contains_host_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
                self.host_tainted.discard(name)
            elif is_tainted:
                self.host_tainted.add(name)
                self.safe_values.discard(name)
                if _name_is_urlish(name):
                    self.remember_issue(line_no)
            else:
                self.host_tainted.discard(name)
                self.safe_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.host_tainted)
        self.safe_values.clear()
        self.host_tainted.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.host_tainted = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in _target_names(target)]
        if names:
            self.mark_assignment(names, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = _target_names(node.target)
            if names:
                self.mark_assignment(names, node.value, node.lineno)
        self.generic_visit(node)

    def call_uses_implicit_host(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short == 'build_absolute_uri' and _rooted_at_request(node.func):
            return True
        if short == 'url_for' and _truthy_constant(_keyword_value(node, '_external')):
            return not self.expr_uses_safe_config(node)
        return False

    def call_is_host_sensitive_sink(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        return name in HOST_SINKS or short in HOST_SINKS

    def visit_Call(self, node):
        if self.call_uses_implicit_host(node):
            self.remember_issue(node.lineno)
        elif self.call_is_host_sensitive_sink(node):
            values = list(node.args) + [keyword.value for keyword in node.keywords]
            if any(self.expr_contains_host_taint(value) for value in values):
                self.remember_issue(node.lineno)
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
        analyzer = _HostHeaderPoisoningAnalyzer(path, text, lines)
        analyzer.visit(tree)
        for _, line_no, code in analyzer.issues:
            yield path, line_no, 1, code.strip()[:240]
