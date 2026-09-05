"""ubs_core.py_detectors.tls_verification — category 7 TLS verification (bead 0xjg.5).

Port of run_tls_verification_checks (modules/ubs-python.sh 8749-9035): an
ast.NodeVisitor flagging disabled certificate verification across httpx/
requests (verify=False, incl. `from httpx import get` direct imports),
aiohttp (TCPConnector(ssl=False), ClientSession(connector=...) with an
unsafe connector, session-variable `.get(..., ssl=False)`), urllib3
(PoolManager cert_reqs=CERT_NONE / assert_hostname=False), ssl
(_create_unverified_context, CERT_NONE verify_mode, check_hostname=False,
`ssl._create_default_https_context = ssl._create_unverified_context`).

Same-file and previous-line `ubs:ignore` markers suppress a hit, with
per-file line dedupe, exactly like the heredoc.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.tls-verification"
CATEGORY = 7
TITLE = "HTTP/TLS client disables certificate verification"
SEVERITY = "critical"
DESCRIPTION = "Keep certificate and hostname verification enabled; use explicit CA bundles for private trust roots"

HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'stream'}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def _const_value(node):
    return node.value if isinstance(node, ast.Constant) else None


def _is_false(node):
    value = _const_value(node)
    return value is False or value == 0 or (isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'})


def _is_cert_none(node, cert_none_names, ssl_aliases):
    value = _const_value(node)
    if isinstance(value, str) and value.strip().upper() in {'CERT_NONE', 'NONE'}:
        return True
    name = _call_name(node)
    if name in cert_none_names:
        return True
    return any(name == f'{alias}.CERT_NONE' for alias in ssl_aliases)


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


class _TLSVerificationAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.ssl_aliases = {'ssl'}
        self.httpx_aliases = {'httpx'}
        self.requests_aliases = {'requests'}
        self.aiohttp_aliases = {'aiohttp'}
        self.urllib3_aliases = {'urllib3'}
        self.httpx_direct = set()
        self.requests_direct = set()
        self.aiohttp_connector_names = set()
        self.aiohttp_session_names = set()
        self.urllib3_pool_names = set()
        self.unverified_context_names = set()
        self.cert_none_names = set()
        self.client_vars = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == 'ssl':
                self.ssl_aliases.add(local)
            elif alias.name == 'httpx':
                self.httpx_aliases.add(local)
            elif alias.name == 'requests':
                self.requests_aliases.add(local)
            elif alias.name == 'aiohttp':
                self.aiohttp_aliases.add(local)
            elif alias.name == 'urllib3':
                self.urllib3_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'ssl':
                if alias.name == '_create_unverified_context':
                    self.unverified_context_names.add(local)
                elif alias.name == 'CERT_NONE':
                    self.cert_none_names.add(local)
            elif module == 'httpx' and alias.name in HTTP_METHODS | {'Client', 'AsyncClient'}:
                self.httpx_direct.add(local)
            elif module == 'requests' and alias.name in HTTP_METHODS | {'Session'}:
                self.requests_direct.add(local)
            elif module == 'aiohttp':
                if alias.name == 'TCPConnector':
                    self.aiohttp_connector_names.add(local)
                elif alias.name == 'ClientSession':
                    self.aiohttp_session_names.add(local)
            elif module == 'urllib3' and alias.name in {'PoolManager', 'ProxyManager'}:
                self.urllib3_pool_names.add(local)
        self.generic_visit(node)

    def keyword(self, call, key):
        for keyword in call.keywords:
            if keyword.arg == key:
                return keyword.value
        return None

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
        return names

    def is_ssl_unverified_context(self, node):
        name = _call_name(node)
        return name in self.unverified_context_names or any(name == f'{alias}._create_unverified_context' for alias in self.ssl_aliases)

    def is_httpx_or_requests_call(self, name):
        if name in self.httpx_direct or name in self.requests_direct:
            return True
        if '.' not in name:
            return False
        prefix, short = name.rsplit('.', 1)
        first = prefix.split('.', 1)[0]
        return short in HTTP_METHODS | {'Client', 'AsyncClient', 'Session'} and (first in self.httpx_aliases or first in self.requests_aliases)

    def is_aiohttp_connector_call(self, name):
        if name in self.aiohttp_connector_names:
            return True
        return any(name == f'{alias}.TCPConnector' for alias in self.aiohttp_aliases)

    def is_aiohttp_session_call(self, name):
        if name in self.aiohttp_session_names:
            return True
        return any(name == f'{alias}.ClientSession' for alias in self.aiohttp_aliases)

    def is_urllib3_pool_call(self, name):
        if name in self.urllib3_pool_names:
            return True
        return any(name in {f'{alias}.PoolManager', f'{alias}.ProxyManager'} for alias in self.urllib3_aliases)

    def has_unsafe_connector(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self.is_aiohttp_connector_call(_call_name(child.func)):
                ssl_value = self.keyword(child, 'ssl')
                if ssl_value is not None and _is_false(ssl_value):
                    return True
        return False

    def call_disables_tls(self, node):
        name = _call_name(node.func)
        if self.is_ssl_unverified_context(node.func):
            return True
        verify = self.keyword(node, 'verify')
        if verify is not None and _is_false(verify) and self.is_httpx_or_requests_call(name):
            return True
        if self.is_aiohttp_connector_call(name):
            ssl_value = self.keyword(node, 'ssl')
            if ssl_value is not None and _is_false(ssl_value):
                return True
        if self.is_aiohttp_session_call(name):
            connector = self.keyword(node, 'connector')
            if connector is not None and self.has_unsafe_connector(connector):
                return True
        if self.is_urllib3_pool_call(name):
            cert_reqs = self.keyword(node, 'cert_reqs')
            assert_hostname = self.keyword(node, 'assert_hostname')
            if cert_reqs is not None and _is_cert_none(cert_reqs, self.cert_none_names, self.ssl_aliases):
                return True
            if assert_hostname is not None and _is_false(assert_hostname):
                return True
        if '.' in name:
            prefix, short = name.rsplit('.', 1)
            first = prefix.split('.', 1)[0]
            ssl_value = self.keyword(node, 'ssl')
            if short in HTTP_METHODS and ssl_value is not None and _is_false(ssl_value):
                return first in self.aiohttp_aliases or first in self.client_vars or 'aiohttp' in prefix
        return False

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            name = _call_name(node.value.func)
            if self.is_httpx_or_requests_call(name) or self.is_aiohttp_session_call(name) or self.is_urllib3_pool_call(name):
                self.client_vars.update(self.target_names(node.targets))
            if self.call_disables_tls(node.value):
                self.remember_issue(node.lineno)
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                attr = target.attr
                target_owner = _call_name(target.value)
                if attr == 'verify_mode' and _is_cert_none(node.value, self.cert_none_names, self.ssl_aliases):
                    self.remember_issue(node.lineno)
                elif attr == 'check_hostname' and _is_false(node.value):
                    self.remember_issue(node.lineno)
                elif attr == 'verify' and target_owner in self.client_vars and _is_false(node.value):
                    self.remember_issue(node.lineno)
                elif attr == '_create_default_https_context' and target_owner in self.ssl_aliases and self.is_ssl_unverified_context(node.value):
                    self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.call_disables_tls(node):
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
        analyzer = _TLSVerificationAnalyzer(path, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
