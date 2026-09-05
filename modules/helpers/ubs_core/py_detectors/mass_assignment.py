"""ubs_core.py_detectors.mass_assignment — category 7 mass assignment (bead 0xjg.5).

Port of run_mass_assignment_checks (modules/ubs-python.sh 7853-8062): an
ast.NodeVisitor flagging model constructors and create/update/from_dict/
model_validate/setattr/populate_obj calls that spread request-derived data
(`request.json`/`.form`/`.args`/... or names tainted from them, including
loop targets) via `**kwargs`, `data=`/`defaults=`/`values=`, or a first
positional argument.

Same-file and previous-line `ubs:ignore` markers suppress a hit, with
per-file line dedupe, exactly like the heredoc.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.mass-assignment"
CATEGORY = 7
TITLE = "Request data mass-assigned into model/object"
SEVERITY = "critical"
DESCRIPTION = "Map allowed fields explicitly before constructing or updating domain objects"

MODELISH_OWNER_RE = ('user', 'account', 'profile', 'model', 'object', 'obj',
                     'entity', 'record', 'instance', 'customer', 'member',
                     'admin', 'role', 'permission')


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


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []


def _is_request_attr_name(name):
    lowered = name.lower()
    return (
        lowered.startswith('request.')
        or '.request.' in lowered
        or lowered.startswith('flask.request.')
        or lowered.startswith('self.request.')
    ) and any(part in lowered for part in ('.json', '.form', '.values', '.args', '.data', '.post', '.get', '.files', '.body'))


def _is_request_source_expr(node, tainted):
    if isinstance(node, ast.Name):
        return node.id in tainted
    name = _call_name(node)
    if name and _is_request_attr_name(name):
        return True
    if isinstance(node, ast.Call):
        func_name = _call_name(node.func)
        if _is_request_attr_name(func_name):
            return True
        if func_name.rsplit('.', 1)[-1] in {'dict', 'to_dict', 'copy'} and _is_request_source_expr(node.func, tainted):
            return True
    if isinstance(node, ast.Subscript):
        return _is_request_source_expr(node.value, tainted)
    return any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(node))


def _looks_like_model_constructor(name):
    short = name.rsplit('.', 1)[-1]
    return bool(short) and short[0].isupper() and short not in {'dict', 'list', 'set', 'tuple', 'Response', 'JsonResponse'}


def _looks_like_model_create(name):
    lowered = name.lower()
    short = name.rsplit('.', 1)[-1]
    return (
        short in {'create', 'update', 'bulk_create', 'bulk_update', 'from_dict', 'from_json'}
        or lowered.endswith('.objects.create')
        or lowered.endswith('.query.update')
        or lowered.endswith('.model_validate')
        or lowered.endswith('.parse_obj')
    )


def _owner_looks_modelish(owner):
    lowered = owner.lower()
    return any(token in lowered for token in MODELISH_OWNER_RE)


class _MassAssignmentAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.tainted = set()
        self.loop_tainted = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def expr_is_request_source(self, node):
        return _is_request_source_expr(node, self.tainted | self.loop_tainted)

    def mark_targets_from_source(self, targets, value):
        if self.expr_is_request_source(value):
            for target in targets:
                self.tainted.update(_target_names(target))

    def call_is_mass_assignment(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        for keyword in node.keywords:
            if keyword.arg is None and self.expr_is_request_source(keyword.value):
                if _looks_like_model_constructor(name) or _looks_like_model_create(name):
                    return True
            elif keyword.arg in {'data', 'defaults', 'values'} and self.expr_is_request_source(keyword.value) and _looks_like_model_create(name):
                return True
        if short in {'update', 'from_dict', 'from_json'} and node.args and self.expr_is_request_source(node.args[0]):
            return _owner_looks_modelish(owner) or _looks_like_model_create(name)
        if short in {'create', 'bulk_create', 'bulk_update'} and node.args and self.expr_is_request_source(node.args[0]):
            return True
        if short in {'model_validate', 'parse_obj'} and node.args and self.expr_is_request_source(node.args[0]):
            return True
        if name == 'setattr' and len(node.args) >= 3:
            return self.expr_is_request_source(node.args[1])
        if short == 'populate_obj' and node.args:
            return _owner_looks_modelish(_call_name(node.args[0]))
        return False

    def visit_Assign(self, node):
        self.mark_targets_from_source(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.mark_targets_from_source([node.target], node.value)
        self.generic_visit(node)

    def visit_For(self, node):
        old_loop = set(self.loop_tainted)
        if self.expr_is_request_source(node.iter):
            self.loop_tainted.update(_target_names(node.target))
        self.generic_visit(node)
        self.loop_tainted = old_loop

    def visit_Call(self, node):
        if self.call_is_mass_assignment(node):
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
        analyzer = _MassAssignmentAnalyzer(path, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
