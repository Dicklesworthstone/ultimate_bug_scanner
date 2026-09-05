"""ubs_core.py_detectors.ssrf — category 7 security (bead 0xjg.5).

Port of run_ssrf_checks (modules/ubs-python.sh 5919-6206): an ast.NodeVisitor
that taints names assigned from request data (request.args/GET/POST/
query_params/json/body, Lambda event queryStringParameters/body, ...) and
flags outbound HTTP calls whose URL argument is request-derived: module-level
requests/httpx get/post/.../request/stream, urllib urlopen/Request,
from-imported helpers, and methods on tracked client instances
(requests.Session, httpx.Client/AsyncClient, aiohttp.ClientSession,
urllib3.PoolManager — including their text heuristic for inline owners).
A safe validator (is_safe_url, validate_outbound_url, allowlisted_*,
ipaddress., .hostname/.netloc/.scheme, ...) in the expression or mentioning
the tainted name within the preceding 12 lines suppresses the hit.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.ssrf"
CATEGORY = 7
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate outbound URLs with an allow-list and block private/link-local "
    "hosts before fetching"
)

REQUEST_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:args|values|form|GET|POST|query_params|cookies|json|get_json|data|body|url|full_path)\b'
    r'|\b(?:self\.)?request\.(?:GET|POST|query_params|cookies|json|data|body)\b'
    r"|event\.get\(['\"]queryStringParameters['\"]\)"
    r"|event\[['\"](?:queryStringParameters|body)['\"]\]",
    re.IGNORECASE,
)
SAFE_VALIDATOR_RE = re.compile(
    r'\b(?:is_allowed_url|is_safe_url|is_trusted_url|validate_url|validate_outbound_url|'
    r'validate_fetch_url|safe_fetch_url|safe_outbound_url|allowlisted_url|allowed_url|'
    r'allowed_host|allowlisted_host|deny_private|reject_private|block_private|'
    r'is_private_address|is_public_host|same_origin)\b'
    r'|\.hostname\b|\.netloc\b|\.scheme\b|ipaddress\.',
    re.IGNORECASE,
)
HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
REQUEST_METHODS = {'request', 'stream'}


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


class _SSRFAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted = {}
        self.http_clients = set()
        self.modules = {
            'requests': {'requests'},
            'httpx': {'httpx'},
            'urllib_request': {'urllib.request'},
        }
        self.direct_http_calls = {}
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
        if not SAFE_VALIDATOR_RE.search(context):
            return False
        return any(re.search(rf'\b{re.escape(name)}\b', context) for name in names)

    def remember_import(self, module, alias):
        if module == 'requests':
            self.modules['requests'].add(alias)
        elif module == 'httpx':
            self.modules['httpx'].add(alias)
        elif module == 'urllib.request':
            self.modules['urllib_request'].add(alias)

    def visit_Import(self, node):
        for alias in node.names:
            self.remember_import(alias.name, alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'requests', 'httpx'}:
                if alias.name in HTTP_METHODS:
                    self.direct_http_calls[local] = 0
                elif alias.name in REQUEST_METHODS:
                    self.direct_http_calls[local] = 1
                elif alias.name in {'Session', 'Client', 'AsyncClient'}:
                    self.direct_http_calls[local] = 'client_ctor'
            elif module == 'urllib.request' and alias.name in {'urlopen', 'Request'}:
                self.direct_http_calls[local] = 0
        self.generic_visit(node)

    def call_creates_http_client(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = _call_name(node.func)
        if self.direct_http_calls.get(name) == 'client_ctor':
            return True
        for module in self.modules['requests']:
            if name == f'{module}.Session':
                return True
        for module in self.modules['httpx']:
            if name in {f'{module}.Client', f'{module}.AsyncClient'}:
                return True
        return 'aiohttp.ClientSession' in name or 'urllib3.PoolManager' in name

    def mark_assignment(self, target_names, value):
        if self.call_creates_http_client(value):
            self.http_clients.update(target_names)
            return
        if self.has_safe_expression(value):
            for name in target_names:
                self.tainted.pop(name, None)
            return
        if self.is_request_source(value):
            for name in target_names:
                self.tainted[name] = 'request'
            return
        refs = self.tainted_names_in(value)
        if refs:
            for name in target_names:
                self.tainted[name] = refs[0]

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.generic_visit(node)

    def visit_With(self, node):
        self.mark_context_clients(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node):
        self.mark_context_clients(node)
        self.generic_visit(node)

    def mark_context_clients(self, node):
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name) and self.call_creates_http_client(item.context_expr):
                self.http_clients.add(item.optional_vars.id)

    def url_argument(self, node):
        name = _call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        for keyword in node.keywords:
            if keyword.arg in {'url', 'href'}:
                return keyword.value

        if short_name in self.direct_http_calls:
            index = self.direct_http_calls[short_name]
            if isinstance(index, int) and len(node.args) > index:
                return node.args[index]

        for module in self.modules['requests'] | self.modules['httpx']:
            if short_name in HTTP_METHODS and name == f'{module}.{short_name}' and node.args:
                return node.args[0]
            if short_name in REQUEST_METHODS and name == f'{module}.{short_name}' and len(node.args) > 1:
                return node.args[1]

        for module in self.modules['urllib_request']:
            if name in {f'{module}.urlopen', f'{module}.Request'} and node.args:
                return node.args[0]

        if isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id in self.http_clients:
                if short_name in HTTP_METHODS and node.args:
                    return node.args[0]
                if short_name in REQUEST_METHODS and len(node.args) > 1:
                    return node.args[1]
            owner_text = self.segment(owner)
            if ('ClientSession(' in owner_text or 'Session(' in owner_text or 'PoolManager(' in owner_text):
                if short_name in HTTP_METHODS and node.args:
                    return node.args[0]
                if short_name in REQUEST_METHODS and len(node.args) > 1:
                    return node.args[1]
        return None

    def visit_Call(self, node):
        if _has_ignore(self.lines, node.lineno):
            self.generic_visit(node)
            return
        arg = self.url_argument(node)
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
        analyzer = _SSRFAnalyzer(path, text, lines)
        analyzer.visit(tree)
        for _, line_no, code in analyzer.issues:
            yield path, line_no, 1, code.strip()[:240]
