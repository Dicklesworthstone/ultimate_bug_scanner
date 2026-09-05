"""ubs_core.py_detectors.unsafe_deserialization — unsafe deserialization loaders (bead 0xjg.5).

Port of run_unsafe_deserialization_checks (modules/ubs-python.sh 3587-3796):
an ast.NodeVisitor tracking module imports (incl. aliases and
sklearn.externals.joblib spellings) and flagging pickle-compatible loader
calls — marshal/dill/cloudpickle load*, joblib.load, jsonpickle.decode/
loads, shelve.open, pandas.read_pickle, yaml.unsafe_load[_all] — plus
numpy.load with allow_pickle=True and torch.load without weights_only=True.

Same-file and previous-line `ubs:ignore` markers suppress a hit; hits dedupe
per line within a file (legacy `seen_lines`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.unsafe-deserialization"
CATEGORY = 7
TITLE = "Unsafe Python deserialization loader"
SEVERITY = "critical"
DESCRIPTION = ("Avoid pickle-compatible loaders for untrusted data; use JSON/schema formats "
               "or explicitly safe artifact loading")

MODULE_CALLS = {
    'marshal': {'load', 'loads'},
    'dill': {'load', 'loads'},
    'cloudpickle': {'load', 'loads'},
    'joblib': {'load'},
    'jsonpickle': {'decode', 'loads'},
    'shelve': {'open'},
    'pandas': {'read_pickle'},
    'yaml': {'unsafe_load', 'unsafe_load_all'},
}
SPECIAL_CALLS = {
    'numpy': {'load'},
    'torch': {'load'},
}
MODULE_ALIASES = {
    'marshal': {'marshal'},
    'dill': {'dill'},
    'cloudpickle': {'cloudpickle'},
    'joblib': {'joblib', 'sklearn.externals.joblib'},
    'jsonpickle': {'jsonpickle'},
    'shelve': {'shelve'},
    'pandas': {'pandas'},
    'yaml': {'yaml'},
    'numpy': {'numpy'},
    'torch': {'torch'},
}
FROM_MODULES = {
    'marshal': 'marshal',
    'dill': 'dill',
    'cloudpickle': 'cloudpickle',
    'joblib': 'joblib',
    'sklearn.externals.joblib': 'joblib',
    'jsonpickle': 'jsonpickle',
    'shelve': 'shelve',
    'pandas': 'pandas',
    'yaml': 'yaml',
    'numpy': 'numpy',
    'torch': 'torch',
}


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


def _is_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def _keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


class _UnsafeDeserializerAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.modules = {key: set(value) for key, value in MODULE_ALIASES.items()}
        self.direct_calls = {}
        self.issue_lines = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issue_lines.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            canonical = FROM_MODULES.get(alias.name)
            if canonical:
                self.modules[canonical].add(alias.asname or alias.name)
            elif alias.name.endswith('.joblib'):
                self.modules['joblib'].add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        if module == 'sklearn.externals':
            for alias in node.names:
                if alias.name == 'joblib':
                    self.modules['joblib'].add(alias.asname or alias.name)
            self.generic_visit(node)
            return
        canonical = FROM_MODULES.get(module)
        if canonical:
            allowed = MODULE_CALLS.get(canonical, set()) | SPECIAL_CALLS.get(canonical, set())
            for alias in node.names:
                if alias.name in allowed:
                    self.direct_calls[alias.asname or alias.name] = f'{canonical}.{alias.name}'
        self.generic_visit(node)

    def canonical_call(self, node):
        name = _call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for canonical, funcs in {**MODULE_CALLS, **SPECIAL_CALLS}.items():
            for alias in self.modules.get(canonical, set()):
                for func in funcs:
                    if name == f'{alias}.{func}':
                        return f'{canonical}.{func}'
        if name.endswith('.joblib.load'):
            return 'joblib.load'
        return ''

    def is_unsafe_call(self, node):
        canonical = self.canonical_call(node)
        if not canonical:
            return False
        module, func = canonical.rsplit('.', 1)
        if module == 'numpy' and func == 'load':
            return _is_true(_keyword_value(node, 'allow_pickle'))
        if module == 'torch' and func == 'load':
            return not _is_true(_keyword_value(node, 'weights_only'))
        return True

    def visit_Call(self, node):
        if self.is_unsafe_call(node):
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
        analyzer = _UnsafeDeserializerAnalyzer(lines)
        analyzer.visit(tree)
        for line_no in analyzer.issue_lines:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
