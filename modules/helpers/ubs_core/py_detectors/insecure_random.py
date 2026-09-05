"""ubs_core.py_detectors.insecure_random — category 7 insecure random (bead 0xjg.5).

Port of run_insecure_random_security_checks (modules/ubs-python.sh
8527-8747): an ast.NodeVisitor flagging `random`-module calls (random,
randint, choice, shuffle, ...) on security-sensitive surfaces — assignments
to security-named targets (token/secret/session/csrf/nonce/otp/...),
returns from security-named functions, and calls whose name, source line,
or keyword names look security-relevant. `random.SystemRandom` instances
and `from random import SystemRandom` are treated as safe.

Same-file and previous-line `ubs:ignore` markers suppress a hit, with
per-file line dedupe, exactly like the heredoc.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.insecure-random"
CATEGORY = 7
TITLE = "Security token generated with non-cryptographic random"
SEVERITY = "critical"
DESCRIPTION = ("Use secrets.token_urlsafe/token_hex/randbelow or "
               "random.SystemRandom for tokens, sessions, OTPs, salts, and keys")

RANDOM_FUNCS = {'random', 'randint', 'randrange', 'choice', 'choices', 'sample',
                'shuffle', 'getrandbits', 'randbytes', 'uniform'}
SECURITY_NAME_RE = re.compile(r'(token|secret|session|csrf|nonce|otp|password|passwd|api_?key|auth|salt|reset|invite|verification|cookie|credential|signing|hmac|jwt|key)', re.IGNORECASE)


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
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


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _expr_has_security_name(*parts):
    return any(SECURITY_NAME_RE.search(part or '') for part in parts)


class _SecurityRandomAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.random_aliases = {'random'}
        self.random_functions = set()
        self.random_instances = set()
        self.safe_instances = set()
        self.function_stack = []
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no):
            return
        if line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == 'random':
                self.random_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'random' and alias.name in RANDOM_FUNCS:
                self.random_functions.add(local)
            elif module == 'random' and alias.name == 'Random':
                self.random_functions.add(local)
            elif module == 'random' and alias.name == 'SystemRandom':
                self.safe_instances.add(local)
        self.generic_visit(node)

    def is_random_constructor(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = _call_name(node.func)
        if name in self.random_functions and name.endswith('Random') and name not in self.safe_instances:
            return True
        return any(name == f'{alias}.Random' for alias in self.random_aliases)

    def is_insecure_random_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short not in RANDOM_FUNCS:
            return False
        if name in self.random_functions:
            return True
        if '.' in name:
            prefix = name.rsplit('.', 1)[0]
            if 'SystemRandom' in prefix.split('.'):
                return False
            first = prefix.split('.', 1)[0]
            return first in self.random_aliases or first in self.random_instances
        return False

    def expr_uses_insecure_random(self, node):
        return any(isinstance(child, ast.Call) and self.is_insecure_random_call(child) for child in ast.walk(node))

    def visit_FunctionDef(self, node):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Assign(self, node):
        names = []
        for target in node.targets:
            names.extend(_target_names(target))
        if self.is_random_constructor(node.value):
            self.random_instances.update(names)
        elif names and _expr_has_security_name(*names) and self.expr_uses_insecure_random(node.value):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        names = _target_names(node.target)
        if node.value is not None:
            if self.is_random_constructor(node.value):
                self.random_instances.update(names)
            elif names and _expr_has_security_name(*names) and self.expr_uses_insecure_random(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Return(self, node):
        current = self.function_stack[-1] if self.function_stack else ''
        if node.value is not None and _expr_has_security_name(current) and self.expr_uses_insecure_random(node.value):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.expr_uses_insecure_random(node):
            name = _call_name(node.func)
            keyword_names = [keyword.arg or '' for keyword in node.keywords]
            line = _source_line(self.lines, node.lineno)
            if _expr_has_security_name(name, line, *keyword_names):
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
        analyzer = _SecurityRandomAnalyzer(path, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
