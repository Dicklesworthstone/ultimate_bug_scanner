"""ubs_core.py_detectors.cors_misconfig — category 7 credentialed wildcard CORS (bead 0xjg.5).

Port of run_cors_misconfig_checks (modules/ubs-python.sh 6638-6898): an
ast.NodeVisitor flagging flask-cors ``CORS``/``cross_origin`` calls, Starlette/
FastAPI ``CORSMiddleware`` (direct or via ``add_middleware``), and Django
``CORS_*`` settings where credentials are allowed together with a wildcard
origin (or with no origin configured at all).

Same-file and previous-line ``ubs:ignore`` markers suppress a hit (6710-6716).
Django settings are paired per-file: a wildcard-origin setting only fires when
a credentials setting also exists (finalize, 6874-6876).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.cors-misconfig"
CATEGORY = 7
TITLE = "CORS allows credentials with wildcard origins"
SEVERITY = "critical"
DESCRIPTION = "Use an explicit origin allow-list whenever cookies or Authorization headers are allowed"

ORIGIN_KEYS = {'origins', 'allow_origins'}
CREDENTIAL_KEYS = {'supports_credentials', 'allow_credentials'}
DJANGO_WILDCARD_SETTINGS = {'CORS_ALLOW_ALL_ORIGINS', 'CORS_ORIGIN_ALLOW_ALL'}
DJANGO_ORIGIN_LIST_SETTINGS = {'CORS_ALLOWED_ORIGINS', 'CORS_ORIGIN_WHITELIST'}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def _const_value(node: ast.AST):
    return node.value if isinstance(node, ast.Constant) else None


def _is_true(node: ast.AST) -> bool:
    return _const_value(node) is True


def _key_name(node: ast.AST):
    value = _const_value(node)
    return value if isinstance(value, str) else None


def _source_line(lines: list[str], line_no: int) -> str:
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _has_ignore(lines: list[str], line_no: int) -> bool:
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def _contains_wildcard_origin(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip() == '*'
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_contains_wildcard_origin(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return any(_contains_wildcard_origin(value) for value in node.values)
    return False


def _dict_has_unsafe_cors_pair(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    saw_origin_key = False
    has_wildcard = False
    has_credentials = False
    for key, value in zip(node.keys, node.values):
        name = _key_name(key)
        if name in ORIGIN_KEYS:
            saw_origin_key = True
            if _contains_wildcard_origin(value):
                has_wildcard = True
        elif name in CREDENTIAL_KEYS and _is_true(value):
            has_credentials = True
        elif _dict_has_unsafe_cors_pair(value):
            return True
    return has_credentials and (has_wildcard or not saw_origin_key)


def _keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _has_wildcard_origin_kw(call):
    return any(
        _keyword_value(call, key) is not None and _contains_wildcard_origin(_keyword_value(call, key))
        for key in ORIGIN_KEYS
    )


def _has_credentials_kw(call):
    return any(
        _keyword_value(call, key) is not None and _is_true(_keyword_value(call, key))
        for key in CREDENTIAL_KEYS
    )


def _has_send_wildcard_kw(call):
    value = _keyword_value(call, 'send_wildcard')
    return value is not None and _is_true(value)


def _resources_are_unsafe(call):
    resources = _keyword_value(call, 'resources')
    return resources is not None and _dict_has_unsafe_cors_pair(resources)


def _positional_resources(call):
    return call.args[1] if len(call.args) > 1 else None


def _flask_cors_is_unsafe(call):
    if _resources_are_unsafe(call):
        return True
    positional = _positional_resources(call)
    if positional is not None and _dict_has_unsafe_cors_pair(positional):
        return True
    if not _has_credentials_kw(call):
        return False
    resources = _keyword_value(call, 'resources')
    if resources is not None and _contains_wildcard_origin(resources):
        return True
    if _has_wildcard_origin_kw(call) or _has_send_wildcard_kw(call):
        return True
    if positional is not None and _contains_wildcard_origin(positional):
        return True
    return _keyword_value(call, 'origins') is None and _keyword_value(call, 'resources') is None and positional is None


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []


class _CORSAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.cors_calls = {'CORS', 'cross_origin', 'flask_cors.CORS', 'flask_cors.cross_origin'}
        self.middleware_calls = {'CORSMiddleware', 'starlette.middleware.cors.CORSMiddleware', 'fastapi.middleware.cors.CORSMiddleware'}
        self.django_wildcard_origin_lines = []
        self.django_credential_lines = []
        self.issues = []

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no):
            return
        self.issues.append((line_no, _source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'flask_cors':
                self.cors_calls.add(f'{local}.CORS')
                self.cors_calls.add(f'{local}.cross_origin')
            elif alias.name in {'starlette.middleware.cors', 'fastapi.middleware.cors'}:
                self.middleware_calls.add(f'{local}.CORSMiddleware')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'flask_cors' and alias.name in {'CORS', 'cross_origin'}:
                self.cors_calls.add(local)
            elif module in {'starlette.middleware.cors', 'fastapi.middleware.cors'} and alias.name == 'CORSMiddleware':
                self.middleware_calls.add(local)
        self.generic_visit(node)

    def remember_django_setting(self, name, value, line_no):
        if name in DJANGO_WILDCARD_SETTINGS and _is_true(value):
            self.django_wildcard_origin_lines.append(line_no)
        elif name in DJANGO_ORIGIN_LIST_SETTINGS and _contains_wildcard_origin(value):
            self.django_wildcard_origin_lines.append(line_no)
        elif name == 'CORS_ALLOW_CREDENTIALS' and _is_true(value):
            self.django_credential_lines.append(line_no)

    def visit_Assign(self, node):
        for target in node.targets:
            for name in _target_names(target):
                self.remember_django_setting(name, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        for name in _target_names(node.target):
            if node.value is not None:
                self.remember_django_setting(name, node.value, node.lineno)
        self.generic_visit(node)

    def call_is_unsafe(self, node):
        name = _call_name(node.func)
        if name in self.cors_calls or name.rsplit('.', 1)[-1] in {'CORS', 'cross_origin'}:
            return _flask_cors_is_unsafe(node)
        if name in self.middleware_calls or name.rsplit('.', 1)[-1] == 'CORSMiddleware':
            return _has_wildcard_origin_kw(node) and _has_credentials_kw(node)
        if name.endswith('.add_middleware') and node.args:
            middleware_name = _call_name(node.args[0])
            if middleware_name in self.middleware_calls or middleware_name.rsplit('.', 1)[-1] == 'CORSMiddleware':
                return _has_wildcard_origin_kw(node) and _has_credentials_kw(node)
        return False

    def visit_Call(self, node):
        if self.call_is_unsafe(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

    def finalize(self):
        if self.django_wildcard_origin_lines and self.django_credential_lines:
            self.remember_issue(self.django_credential_lines[0])


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            warnings.simplefilter('ignore', SyntaxWarning)
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        analyzer = _CORSAnalyzer(lines)
        analyzer.visit(tree)
        analyzer.finalize()
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
