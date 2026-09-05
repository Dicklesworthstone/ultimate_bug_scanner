"""ubs_core.py_detectors.jwt_verification — category 7 JWT verification bypass (bead 0xjg.5).

Port of run_jwt_verification_checks (modules/ubs-python.sh 6468-6636): an
ast.NodeVisitor flagging jwt / jose.jwt decode calls that weaken verification —
``verify=False``, an ``options`` dict (or 4th positional argument) disabling
verify_signature/verify_exp/verify_aud/verify_iss/verify_iat/verify_nbf, or an
``algorithms`` argument (or 3rd positional argument) containing ``"none"``.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit (6527-6533).
Every unsafe call yields its own record (legacy counted without dedupe).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.jwt-verification"
CATEGORY = 7
TITLE = "JWT decode disables signature or claim verification"
SEVERITY = "critical"
DESCRIPTION = "Require explicit algorithms and keep signature/expiration/audience/issuer verification enabled"

VERIFY_OPTION_KEYS = {'verify_signature', 'verify_exp', 'verify_aud', 'verify_iss', 'verify_iat', 'verify_nbf'}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


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


def _const_value(node: ast.AST):
    return node.value if isinstance(node, ast.Constant) else None


def _key_name(node: ast.AST):
    value = _const_value(node)
    return value if isinstance(value, str) else None


def _is_false(node: ast.AST) -> bool:
    return _const_value(node) is False


def _contains_none_algorithm(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower() == 'none'
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_contains_none_algorithm(elt) for elt in node.elts)
    return False


def _disables_verify_option(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values):
        name = _key_name(key)
        if name in VERIFY_OPTION_KEYS and _is_false(value):
            return True
    return False


class _JWTAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.jwt_modules = {'jwt'}
        self.decode_names: set[str] = set()
        self.issues = []

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name in {'jwt', 'jose.jwt'}:
                self.jwt_modules.add(local)
                self.jwt_modules.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'jwt', 'jose.jwt'} and alias.name == 'decode':
                self.decode_names.add(local)
            elif module == 'jose' and alias.name == 'jwt':
                self.jwt_modules.add(local)
        self.generic_visit(node)

    def is_jwt_decode(self, node):
        name = _call_name(node.func)
        if isinstance(node.func, ast.Name):
            return node.func.id in self.decode_names
        return any(name == f'{module}.decode' for module in self.jwt_modules) or name in {'jwt.decode', 'jose.jwt.decode'}

    def call_is_unsafe(self, node):
        for keyword in node.keywords:
            if keyword.arg == 'verify' and _is_false(keyword.value):
                return True
            if keyword.arg == 'options' and _disables_verify_option(keyword.value):
                return True
            if keyword.arg == 'algorithms' and _contains_none_algorithm(keyword.value):
                return True
        if len(node.args) > 2 and _contains_none_algorithm(node.args[2]):
            return True
        if len(node.args) > 3 and _disables_verify_option(node.args[3]):
            return True
        return False

    def visit_Call(self, node):
        if not _has_ignore(self.lines, node.lineno) and self.is_jwt_decode(node) and self.call_is_unsafe(node):
            self.issues.append((node.lineno, _source_line(self.lines, node.lineno)))
        self.generic_visit(node)


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
        analyzer = _JWTAnalyzer(lines)
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
