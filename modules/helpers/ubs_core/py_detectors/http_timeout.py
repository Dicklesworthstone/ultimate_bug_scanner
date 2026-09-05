"""ubs_core.py_detectors.http_timeout — outbound HTTP without a timeout.

Port of run_http_timeout_checks (modules/ubs-python.sh 4947-5195): an
ast.NodeVisitor flagging requests/httpx module-level verbs, urllib
``urlopen``, urllib3 ``PoolManager``/``ProxyManager`` constructors,
aiohttp ``ClientSession``, httpx ``Client``/``AsyncClient``, and method
calls on variables bound to those clients, when no bounded ``timeout=``
is in play (``timeout=None``/``False`` counts as unbounded). Variables
bound to a constructor WITH a timeout mark client vars as safe.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit, and hits
are line-deduped per file (legacy ``seen_lines``).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.http-timeout"
CATEGORY = 7
TITLE = "Outbound HTTP call has no explicit timeout"
SEVERITY = "warning"
DESCRIPTION = "Pass timeout=... or configure the HTTP client with a bounded timeout"

HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'send'}
URLLIB3_METHODS = {'request', 'request_encode_url', 'request_encode_body', 'urlopen'}


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def timeout_value_is_bounded(node):
    if node is None:
        return False
    if isinstance(node, ast.Constant) and node.value in {None, False}:
        return False
    return True


def has_bounded_timeout(call):
    return timeout_value_is_bounded(keyword_value(call, 'timeout'))


def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []


class HttpTimeoutAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.issues = []
        self.seen_lines = set()
        self.requests_modules = {'requests'}
        self.httpx_modules = {'httpx'}
        self.urllib_request_modules = {'urllib.request'}
        self.urllib3_modules = {'urllib3'}
        self.aiohttp_modules = {'aiohttp'}
        self.direct_calls = {}
        self.http_client_vars = {}

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'requests':
                self.requests_modules.add(local)
            elif alias.name == 'httpx':
                self.httpx_modules.add(local)
            elif alias.name == 'urllib.request':
                self.urllib_request_modules.add(local)
            elif alias.name == 'urllib3':
                self.urllib3_modules.add(local)
            elif alias.name == 'aiohttp':
                self.aiohttp_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'requests', 'httpx'} and alias.name in HTTP_METHODS:
                self.direct_calls[local] = module
            elif module == 'urllib.request' and alias.name == 'urlopen':
                self.direct_calls[local] = 'urllib.request'
            elif module == 'urllib3' and alias.name in {'PoolManager', 'ProxyManager'}:
                self.direct_calls[local] = f'urllib3.{alias.name}'
            elif module == 'aiohttp' and alias.name == 'ClientSession':
                self.direct_calls[local] = 'aiohttp.ClientSession'
        self.generic_visit(node)

    def is_requests_or_httpx_module_call(self, name, short):
        if self.direct_calls.get(name) in {'requests', 'httpx'}:
            return True
        return short in HTTP_METHODS and (
            any(name == f'{module}.{short}' for module in self.requests_modules)
            or any(name == f'{module}.{short}' for module in self.httpx_modules)
        )

    def is_urlopen_call(self, name):
        return (
            self.direct_calls.get(name) == 'urllib.request'
            or any(name == f'{module}.urlopen' for module in self.urllib_request_modules)
        )

    def is_http_client_constructor(self, name):
        if self.direct_calls.get(name) in {'aiohttp.ClientSession', 'urllib3.PoolManager', 'urllib3.ProxyManager'}:
            return True
        return (
            any(name in {f'{module}.Client', f'{module}.AsyncClient'} for module in self.httpx_modules)
            or any(name == f'{module}.ClientSession' for module in self.aiohttp_modules)
            or any(name in {f'{module}.PoolManager', f'{module}.ProxyManager'} for module in self.urllib3_modules)
        )

    def client_var_has_timeout(self, owner):
        return self.http_client_vars.get(owner, False)

    def call_missing_timeout(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        if self.is_http_client_constructor(name):
            return not has_bounded_timeout(node)
        if self.is_requests_or_httpx_module_call(name, short):
            return not has_bounded_timeout(node)
        if self.is_urlopen_call(name):
            return not has_bounded_timeout(node)
        if owner in self.http_client_vars and short in (HTTP_METHODS | URLLIB3_METHODS):
            return not (has_bounded_timeout(node) or self.client_var_has_timeout(owner))
        return False

    def remember_client_assignments(self, targets, value):
        if not isinstance(value, ast.Call):
            return
        if self.is_http_client_constructor(call_name(value.func)):
            safe = has_bounded_timeout(value)
            for target in targets:
                for name in target_names(target):
                    self.http_client_vars[name] = safe

    def visit_Assign(self, node):
        self.remember_client_assignments(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.remember_client_assignments([node.target], node.value)
        self.generic_visit(node)

    def visit_With(self, node):
        self.visit_with_like(node)

    def visit_AsyncWith(self, node):
        self.visit_with_like(node)

    def visit_with_like(self, node):
        old_clients = dict(self.http_client_vars)
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and item.optional_vars is not None:
                self.remember_client_assignments([item.optional_vars], item.context_expr)
        for item in node.items:
            self.visit(item.context_expr)
        for stmt in node.body:
            self.visit(stmt)
        self.http_client_vars = old_clients

    def visit_Call(self, node):
        if self.call_missing_timeout(node):
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
        analyzer = HttpTimeoutAnalyzer(text.splitlines())
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
