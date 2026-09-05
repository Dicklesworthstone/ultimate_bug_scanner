"""ubs_core.py_detectors.security_assert — asserts guarding security checks.

Port of run_security_assert_checks (modules/ubs-python.sh 4556-4737): an
ast.NodeVisitor flagging ``assert`` statements whose test expression (or
enclosing class/function name) looks security-sensitive (auth, permission,
token, csrf, ...). Under ``python -O`` such asserts vanish, silently
disabling the check.

Test code uses assert as its primary idiom (pytest) and never runs under
``python -O`` in a way that weakens production security, so test dirs/files
are excluded from this rule by default (#64): any path with a ``tests``/
``test`` directory component, or named ``test_*``/``*_test.py``/
``conftest.py``, is skipped. Unlike the sibling detectors there is NO
per-file line dedupe in the legacy heredoc — every sensitive assert is
reported.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.security-assert"
CATEGORY = 7
TITLE = "Security-sensitive assert stripped by -O"
SEVERITY = "critical"
DESCRIPTION = ("Use explicit if/raise checks for authorization, ownership, CSRF, token, "
               "and permission validation")

TEST_DIR_NAMES = {'tests', 'test'}
SECURITY_RE = re.compile(
    r'(auth|authori[sz]e|permission|perm|privilege|role|admin|staff|superuser|owner|tenant|account|session|csrf|xsrf|token|secret|api_?key|signature|password|passwd|jwt|bearer|credential|scope|acl|access|login|authenticated|has_?perm|can_)',
    re.IGNORECASE,
)


def is_test_path(path: Path) -> bool:
    parts = [part.lower() for part in path.parts[:-1]]
    if any(part in TEST_DIR_NAMES for part in parts):
        return True
    name = path.name.lower()
    return name.startswith('test_') or name.endswith('_test.py') or name == 'conftest.py'


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''


def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


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


def name_is_security_sensitive(name):
    return bool(name and SECURITY_RE.search(name))


def expr_is_security_sensitive(node):
    if isinstance(node, ast.Name):
        return name_is_security_sensitive(node.id)
    if isinstance(node, ast.Attribute):
        return name_is_security_sensitive(node.attr) or name_is_security_sensitive(call_name(node))
    if isinstance(node, ast.Subscript):
        key = const_string(node.slice)
        return name_is_security_sensitive(key or '') or expr_is_security_sensitive(node.value)
    if isinstance(node, ast.Call):
        return (
            name_is_security_sensitive(call_name(node.func))
            or any(expr_is_security_sensitive(arg) for arg in node.args)
            or any(name_is_security_sensitive(keyword.arg or '') or expr_is_security_sensitive(keyword.value) for keyword in node.keywords)
        )
    if isinstance(node, ast.Compare):
        return expr_is_security_sensitive(node.left) or any(expr_is_security_sensitive(value) for value in node.comparators)
    if isinstance(node, ast.BoolOp):
        return any(expr_is_security_sensitive(value) for value in node.values)
    if isinstance(node, ast.UnaryOp):
        return expr_is_security_sensitive(node.operand)
    if isinstance(node, ast.BinOp):
        return expr_is_security_sensitive(node.left) or expr_is_security_sensitive(node.right)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return name_is_security_sensitive(node.value)
    return False


class SecurityAssertAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.context_names = []
        self.issues = []

    def context_is_security_sensitive(self):
        return any(name_is_security_sensitive(name) for name in self.context_names)

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        self.issues.append((line_no, source_line(self.lines, line_no)))

    def visit_ClassDef(self, node):
        self.context_names.append(node.name)
        self.generic_visit(node)
        self.context_names.pop()

    def visit_FunctionDef(self, node):
        self.context_names.append(node.name)
        self.generic_visit(node)
        self.context_names.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assert(self, node):
        if expr_is_security_sensitive(node.test) or self.context_is_security_sensitive():
            self.remember_issue(node.lineno)
        self.generic_visit(node)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        # Legacy iter_files skipped test paths relative to the walk root; the
        # orchestrator's file list is already project-relative, so apply the
        # same predicate to the path as given (#64).
        if is_test_path(path):
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        analyzer = SecurityAssertAnalyzer(text.splitlines())
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
