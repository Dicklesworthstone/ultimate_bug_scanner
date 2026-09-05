"""ubs_core.py_detectors.cookie_security — category 7 insecure cookie/session flags (bead 0xjg.5).

Port of run_cookie_security_checks (modules/ubs-python.sh 6900-7099): an
ast.NodeVisitor flagging Django/Flask session/CSRF cookie settings set to
unsafe values (``SESSION_COOKIE_SECURE = False`` and friends, SameSite=None
without Secure), ``config.update``/``config.from_mapping`` keyword forms, and
``set_cookie``/``set_signed_cookie`` calls with ``secure=False``,
``httponly=False``, or ``samesite=None`` without ``secure=True``.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit (6979-6985).
SameSite settings are deferred to finalize (7073-7077) so a matching
``*_COOKIE_SECURE = True`` elsewhere in the file clears them; a single
set_cookie call can emit multiple records (legacy did not dedupe).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.cookie-security"
CATEGORY = 7
TITLE = "Insecure web cookie/session configuration"
SEVERITY = "critical"
DESCRIPTION = "Set Secure and HttpOnly on session/CSRF cookies and avoid SameSite=None without Secure"

FALSE_IS_BAD = {'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'CSRF_COOKIE_HTTPONLY'}
SAMESITE_SETTINGS = {'SESSION_COOKIE_SAMESITE', 'CSRF_COOKIE_SAMESITE'}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def _const_value(node: ast.AST):
    return node.value if isinstance(node, ast.Constant) else None


def _is_false(node: ast.AST) -> bool:
    return _const_value(node) is False


def _is_true(node: ast.AST) -> bool:
    return _const_value(node) is True


def _is_samesite_none(node: ast.AST) -> bool:
    value = _const_value(node)
    if value is None or value is False:
        return True
    return isinstance(value, str) and value.lower() == 'none'


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


def _keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _subscript_key(node: ast.AST):
    if not isinstance(node, ast.Subscript):
        return None
    return _key_name(node.slice)


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []


class _CookieSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.secure_true_settings: set[str] = set()
        self.samesite_candidates = []
        self.issues = []

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no):
            return
        self.issues.append((line_no, _source_line(self.lines, line_no)))

    def check_setting_value(self, name, value, line_no):
        if name in FALSE_IS_BAD and _is_false(value):
            self.remember_issue(line_no)
        elif name in {'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE'} and _is_true(value):
            self.secure_true_settings.add(name)
        elif name in SAMESITE_SETTINGS and _is_samesite_none(value):
            self.samesite_candidates.append((name, line_no))

    def visit_Assign(self, node):
        for target in node.targets:
            for name in _target_names(target):
                self.check_setting_value(name, node.value, node.lineno)
            key = _subscript_key(target)
            if key is not None:
                self.check_setting_value(key, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            for name in _target_names(node.target):
                self.check_setting_value(name, node.value, node.lineno)
            key = _subscript_key(node.target)
            if key is not None:
                self.check_setting_value(key, node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        if name.endswith('.config.update') or name.endswith('.config.from_mapping') or name in {'config.update', 'config.from_mapping'}:
            secure_true = any(keyword.arg == 'SESSION_COOKIE_SECURE' and _is_true(keyword.value) for keyword in node.keywords)
            for keyword in node.keywords:
                if keyword.arg is None:
                    continue
                if keyword.arg in FALSE_IS_BAD:
                    self.check_setting_value(keyword.arg, keyword.value, node.lineno)
                elif keyword.arg in SAMESITE_SETTINGS and _is_samesite_none(keyword.value) and not secure_true:
                    self.remember_issue(node.lineno)

        short_name = name.rsplit('.', 1)[-1]
        if short_name in {'set_cookie', 'set_signed_cookie'}:
            secure = _keyword_value(node, 'secure')
            httponly = _keyword_value(node, 'httponly')
            samesite = _keyword_value(node, 'samesite')
            if secure is not None and _is_false(secure):
                self.remember_issue(node.lineno)
            if httponly is not None and _is_false(httponly):
                self.remember_issue(node.lineno)
            if samesite is not None and _is_samesite_none(samesite) and not (secure is not None and _is_true(secure)):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def finalize(self):
        for name, line_no in self.samesite_candidates:
            secure_key = 'CSRF_COOKIE_SECURE' if name.startswith('CSRF_') else 'SESSION_COOKIE_SECURE'
            if secure_key not in self.secure_true_settings:
                self.remember_issue(line_no)


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
        analyzer = _CookieSecurityAnalyzer(lines)
        analyzer.visit(tree)
        analyzer.finalize()
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
