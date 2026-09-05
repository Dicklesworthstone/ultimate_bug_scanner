"""ubs_core.py_detectors.debug_host_config — category 7 debug/host config (bead 0xjg.5).

Port of run_debug_host_config_checks (modules/ubs-python.sh 8064-8257): an
ast.NodeVisitor flagging enabled DEBUG-style settings (name, subscript key,
or attribute targets, plus `run(debug=True)`/`use_debugger=True` calls) and
wildcard ALLOWED_HOSTS values ('*', '*.*', '*.host', '.domain') in plain,
annnotated, `config.update()`/`config.from_mapping()`, and attribute
assignments.

Same-file and previous-line `ubs:ignore` markers suppress a hit; the
heredoc keeps NO line dedupe here, so a line can carry several records —
preserved verbatim.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.debug-host-config"
CATEGORY = 7
TITLE = "Production debug mode or wildcard host allow-list"
SEVERITY = "critical"
DESCRIPTION = "Disable debug mode and replace wildcard ALLOWED_HOSTS with explicit production hostnames"


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def _const_value(node):
    return node.value if isinstance(node, ast.Constant) else None


def _is_enabled(node):
    value = _const_value(node)
    if value is True:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 1:
        return True
    if isinstance(value, str) and value.strip().lower() in {'1', 'true', 'yes', 'on'}:
        return True
    return False


def _is_debug_name(name):
    return name in {'DEBUG', 'FLASK_DEBUG'} or name.endswith('_DEBUG')


def _key_name(node):
    value = _const_value(node)
    return value if isinstance(value, str) else None


def _contains_wildcard_host(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        host = node.value.strip()
        return host in {'*', '*.*'} or host.startswith('*.') or (host.startswith('.') and len(host) > 1)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_contains_wildcard_host(elt) for elt in node.elts)
    return False


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


def _keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return _key_name(node.slice)


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []


class _DebugHostAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.issues = []

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no):
            return
        self.issues.append(line_no)

    def check_config_value(self, name, value, line_no):
        if _is_debug_name(name) and _is_enabled(value):
            self.remember_issue(line_no)
        elif name == 'ALLOWED_HOSTS' and _contains_wildcard_host(value):
            self.remember_issue(line_no)

    def visit_Assign(self, node):
        for target in node.targets:
            for name in _target_names(target):
                self.check_config_value(name, node.value, node.lineno)
            key = _subscript_key(target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(target, ast.Attribute):
                self.check_config_value(target.attr, node.value, node.lineno)
                if target.attr == 'debug' and _is_enabled(node.value):
                    self.remember_issue(node.lineno)
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
                if node.target.attr == 'debug' and _is_enabled(node.value):
                    self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        if name.endswith('.config.update') or name.endswith('.config.from_mapping') or name in {'config.update', 'config.from_mapping'}:
            for keyword in node.keywords:
                if keyword.arg is not None:
                    self.check_config_value(keyword.arg, keyword.value, node.lineno)
        if name.endswith('.run') or name in {'run', 'uvicorn.run', 'hypercorn.run'}:
            debug = _keyword_value(node, 'debug')
            if debug is not None and _is_enabled(debug):
                self.remember_issue(node.lineno)
            use_debugger = _keyword_value(node, 'use_debugger')
            if use_debugger is not None and _is_enabled(use_debugger):
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
        analyzer = _DebugHostAnalyzer(path, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
