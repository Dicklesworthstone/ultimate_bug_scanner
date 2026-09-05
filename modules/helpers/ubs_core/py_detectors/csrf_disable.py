"""ubs_core.py_detectors.csrf_disable — category 7 explicit CSRF disables (bead 0xjg.5).

Port of run_csrf_disable_checks (modules/ubs-python.sh 7101-7343): an
ast.NodeVisitor flagging ``csrf_exempt`` decorators/calls (Django import or
any ``<csrf-owner>.exempt``), CSRF config values switched off —
``WTF_CSRF_ENABLED = False`` and friends, with loose 0/"off"/"no" coercions —
``config.update``/``config.from_mapping`` keyword or dict forms, and
CSRFProtect/CsrfProtect/SeaSurf objects constructed with ``enabled=False``
(tracked so ``@csrf.exempt`` on the instance also fires).

Same-file and previous-line ``ubs:ignore`` markers suppress a hit, and the
per-file ``seen_lines`` set dedupes repeat reports on one line (7225-7233).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.csrf-disable"
CATEGORY = 7
TITLE = "CSRF protection explicitly disabled"
SEVERITY = "critical"
DESCRIPTION = "Remove CSRF exemptions or require request signatures / same-site tokens on state-changing routes"

FALSE_DISABLE_KEYS = {'WTF_CSRF_ENABLED', 'WTF_CSRF_CHECK_DEFAULT', 'CSRF_ENABLED', 'CSRF_CHECK_DEFAULT'}
TRUE_DISABLE_KEYS = {'CSRF_EXEMPT'}


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
    value = _const_value(node)
    return value is False or value == 0 or (isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'})


def _is_true(node: ast.AST) -> bool:
    value = _const_value(node)
    return value is True or value == 1 or (isinstance(value, str) and value.strip().lower() in {'1', 'true', 'yes', 'on'})


def _key_name(node: ast.AST):
    value = _const_value(node)
    return value if isinstance(value, str) else None


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


def _csrf_owner(name: str) -> bool:
    return 'csrf' in name.lower() or 'xsrf' in name.lower()


def _config_value_disables_csrf(name, value) -> bool:
    if not name:
        return False
    key = name.upper()
    return (key in FALSE_DISABLE_KEYS and _is_false(value)) or (key in TRUE_DISABLE_KEYS and _is_true(value))


def _dict_disables_csrf(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    return any(_config_value_disables_csrf(_key_name(key), value) for key, value in zip(node.keys, node.values))


class _CSRFDisableAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.csrf_exempt_names = {'csrf_exempt'}
        self.csrf_objects: set[str] = set()
        self.issues = []
        self.seen_lines: set[int] = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, _source_line(self.lines, line_no)))

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'django.views.decorators.csrf' and alias.name == 'csrf_exempt':
                self.csrf_exempt_names.add(local)
        self.generic_visit(node)

    def check_config_value(self, name, value, line_no):
        if _config_value_disables_csrf(name, value):
            self.remember_issue(line_no)

    def call_creates_csrf_object(self, node):
        if not isinstance(node, ast.Call):
            return False
        return _call_name(node.func).rsplit('.', 1)[-1] in {'CSRFProtect', 'CsrfProtect', 'SeaSurf'}

    def decorator_disables_csrf(self, decorator):
        expr = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _call_name(expr)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        return (
            name in self.csrf_exempt_names
            or short == 'csrf_exempt'
            or (short == 'exempt' and (_csrf_owner(owner) or owner in self.csrf_objects))
        )

    def call_disables_csrf(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        if name in self.csrf_exempt_names or short == 'csrf_exempt':
            return True
        if short == 'exempt' and (_csrf_owner(owner) or owner in self.csrf_objects):
            return True
        enabled = _keyword_value(node, 'enabled')
        if enabled is not None and _is_false(enabled) and _call_name(node.func).rsplit('.', 1)[-1] in {'CSRFProtect', 'CsrfProtect', 'SeaSurf'}:
            return True
        if name.endswith('.config.update') or name.endswith('.config.from_mapping') or name in {'config.update', 'config.from_mapping'}:
            return any(keyword.arg is not None and self.keyword_disables_csrf(keyword) for keyword in node.keywords) or any(_dict_disables_csrf(arg) for arg in node.args)
        return False

    def keyword_disables_csrf(self, keyword):
        if keyword.arg is None:
            return False
        return _config_value_disables_csrf(keyword.arg, keyword.value)

    def visit_Assign(self, node):
        for target in node.targets:
            for name in _target_names(target):
                if self.call_creates_csrf_object(node.value):
                    self.csrf_objects.add(name)
                self.check_config_value(name, node.value, node.lineno)
            key = _subscript_key(target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(target, ast.Attribute):
                self.check_config_value(target.attr, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            for name in _target_names(node.target):
                self.check_config_value(name, node.value, node.lineno)
            key = _subscript_key(node.target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(node.target, ast.Attribute):
                self.check_config_value(node.target.attr, node.value, node.lineno)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if self.decorator_disables_csrf(decorator):
                self.remember_issue(getattr(decorator, 'lineno', node.lineno))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        for decorator in node.decorator_list:
            if self.decorator_disables_csrf(decorator):
                self.remember_issue(getattr(decorator, 'lineno', node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.call_disables_csrf(node):
            self.remember_issue(node.lineno)
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
        analyzer = _CSRFDisableAnalyzer(lines)
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
