"""ubs_core.py_detectors.subprocess_timeout — subprocess calls without timeouts (bead 0xjg.5).

Port of run_subprocess_timeout_checks (modules/ubs-python.sh 3430-3585): an
ast.NodeVisitor tracking `import subprocess` / `from subprocess import ...`
aliases and flagging subprocess.run/call/check_call/check_output calls
without a bounded `timeout=` keyword (timeout=None/False counts as
unbounded) plus the inherently unbounded getoutput/getstatusoutput calls.

Same-file and previous-line `ubs:ignore` markers suppress a hit; hits dedupe
per line within a file (legacy `seen_lines`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.subprocess-timeout"
CATEGORY = 7
TITLE = "Subprocess call has no bounded timeout"
SEVERITY = "warning"
DESCRIPTION = ("Pass timeout=... to subprocess.run/call/check_* or wrap long-running "
               "process execution with an explicit deadline")

TIMEOUT_CAPABLE_CALLS = {'run', 'call', 'check_call', 'check_output'}
NO_TIMEOUT_API_CALLS = {'getoutput', 'getstatusoutput'}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
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


def _keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _timeout_value_is_bounded(node):
    if node is None:
        return False
    if isinstance(node, ast.Constant) and node.value in {None, False}:
        return False
    return True


class _SubprocessTimeoutAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.subprocess_modules = {'subprocess'}
        self.direct_calls = {}
        self.issue_lines = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issue_lines.append(line_no)

    def canonical_call(self, node):
        name = _call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for module in self.subprocess_modules:
            for func in TIMEOUT_CAPABLE_CALLS | NO_TIMEOUT_API_CALLS:
                if name == f'{module}.{func}':
                    return f'subprocess.{func}'
        return ''

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == 'subprocess':
                self.subprocess_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        if module == 'subprocess':
            for alias in node.names:
                if alias.name in (TIMEOUT_CAPABLE_CALLS | NO_TIMEOUT_API_CALLS):
                    self.direct_calls[alias.asname or alias.name] = f'subprocess.{alias.name}'
        self.generic_visit(node)

    def visit_Call(self, node):
        canonical = self.canonical_call(node)
        if canonical:
            func = canonical.rsplit('.', 1)[-1]
            if func in NO_TIMEOUT_API_CALLS or not _timeout_value_is_bounded(_keyword_value(node, 'timeout')):
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
        analyzer = _SubprocessTimeoutAnalyzer(lines)
        analyzer.visit(tree)
        for line_no in analyzer.issue_lines:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
