"""ubs_core.py_detectors.template_autoescape — category 7 autoescape disables (bead 0xjg.5).

Port of run_template_autoescape_checks (modules/ubs-python.sh 7345-7582): an
ast.NodeVisitor flagging Jinja2 environments built with autoescape off —
``Environment``/``Template``/``SandboxedEnvironment`` (aliased or via
``jinja2.*``) called with ``autoescape=False`` or a false-returning lambda,
``select_autoescape(default=False)``/``default_for_string=False``, and
``*.jinja_options.update``/``*.jinja_env.options.update`` disabling it, plus
``autoescape``-keyed assignments in a jinja-ish context (subscripts,
attributes, plain ``autoescape = ...``).

Same-file and previous-line ``ubs:ignore`` markers suppress a hit, and the
per-file ``seen_lines`` set dedupes repeat reports on one line (7468-7476).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.template-autoescape"
CATEGORY = 7
TITLE = "Template autoescape explicitly disabled"
SEVERITY = "critical"
DESCRIPTION = "Keep template autoescape enabled for HTML/XML templates; mark only audited trusted fragments safe"

ENV_FACTORY_NAMES = {'Environment', 'Template', 'SandboxedEnvironment'}


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


def _returns_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Lambda):
        return _is_false(node.body)
    return False


def _disables_autoescape_value(node: ast.AST) -> bool:
    return _is_false(node) or _returns_false(node)


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


def _dict_has_autoescape_false(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    return any(_key_name(key) == 'autoescape' and _disables_autoescape_value(value) for key, value in zip(node.keys, node.values))


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [_call_name(target)]
    return []


def _subscript_key(node: ast.AST):
    if not isinstance(node, ast.Subscript):
        return None
    return _key_name(node.slice)


def _has_jinja_context(name: str) -> bool:
    lowered = name.lower()
    return 'jinja' in lowered or 'template' in lowered or lowered.endswith('autoescape')


class _TemplateAutoescapeAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.jinja_modules = {'jinja2'}
        self.env_factories = set(ENV_FACTORY_NAMES)
        self.select_autoescape_names = {'select_autoescape'}
        self.issues = []
        self.seen_lines: set[int] = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, _source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == 'jinja2':
                self.jinja_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'jinja2', 'jinja2.environment', 'jinja2.sandbox'}:
                if alias.name in ENV_FACTORY_NAMES:
                    self.env_factories.add(local)
                elif alias.name == 'select_autoescape':
                    self.select_autoescape_names.add(local)
        self.generic_visit(node)

    def is_env_factory_call(self, name):
        short = name.rsplit('.', 1)[-1]
        if name in self.env_factories or short in self.env_factories:
            return True
        if '.' not in name:
            return False
        first = name.split('.', 1)[0]
        return first in self.jinja_modules and short in ENV_FACTORY_NAMES

    def is_select_autoescape_call(self, name):
        short = name.rsplit('.', 1)[-1]
        if name in self.select_autoescape_names or short in self.select_autoescape_names:
            return True
        if '.' not in name:
            return False
        first = name.split('.', 1)[0]
        return first in self.jinja_modules and short == 'select_autoescape'

    def call_disables_autoescape(self, node):
        name = _call_name(node.func)
        autoescape = _keyword_value(node, 'autoescape')
        if autoescape is not None and _disables_autoescape_value(autoescape) and self.is_env_factory_call(name):
            return True
        if self.is_select_autoescape_call(name):
            default = _keyword_value(node, 'default')
            default_for_string = _keyword_value(node, 'default_for_string')
            if default is not None and _is_false(default):
                return True
            if default_for_string is not None and _is_false(default_for_string):
                return True
        if name.endswith('.jinja_options.update') or name.endswith('.jinja_env.options.update'):
            return any(keyword.arg == 'autoescape' and _disables_autoescape_value(keyword.value) for keyword in node.keywords) or any(_dict_has_autoescape_false(arg) for arg in node.args)
        return False

    def visit_Assign(self, node):
        for target in node.targets:
            key = _subscript_key(target)
            target_name = _call_name(target)
            if key == 'autoescape' and _has_jinja_context(target_name) and _disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(target, ast.Attribute) and target.attr == 'autoescape' and _has_jinja_context(_call_name(target.value)) and _disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif any(_has_jinja_context(name) for name in _target_names(target)) and _dict_has_autoescape_false(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(target, ast.Name) and target.id == 'autoescape' and _disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            key = _subscript_key(node.target)
            target_name = _call_name(node.target)
            if key == 'autoescape' and _has_jinja_context(target_name) and _disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(node.target, ast.Attribute) and node.target.attr == 'autoescape' and _has_jinja_context(_call_name(node.target.value)) and _disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif any(_has_jinja_context(name) for name in _target_names(node.target)) and _dict_has_autoescape_false(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(node.target, ast.Name) and node.target.id == 'autoescape' and _disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.call_disables_autoescape(node):
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
        analyzer = _TemplateAutoescapeAnalyzer(lines)
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
