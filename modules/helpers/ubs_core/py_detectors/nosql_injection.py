"""ubs_core.py_detectors.nosql_injection — category 7 NoSQL query injection (bead 0xjg.5).

Port of run_nosql_injection_checks (modules/ubs-python.sh 1388-1667): an
ast.NodeVisitor that tracks request-derived objects (request.args/json/body/...,
get_json()/dict()/copy() of them) and unsafe filter dicts (operator keys such as
$where/$function/$accumulator, dangerous operators fed request data, or plain
keys with untrusted values) and flags Mongo/PyMongo sinks — find/find_one/
find_raw_batches/delete_one/delete_many/count_documents filters, update/replace/
find_one_and_* first two args, aggregate/watch pipelines, and run.command —
whose filter/query/pipeline/command/spec/where/update argument is unsafe.

Same-file and previous-line `ubs:ignore` markers suppress a hit; a per-file
`seen` line set dedupes repeats (legacy remember_issue).
"""
from __future__ import annotations

import ast
from typing import Iterable, Sequence

RULE_ID = "py.security.nosql-injection"
CATEGORY = 7
TITLE = "Request-controlled NoSQL filter reaches database sink"
SEVERITY = "critical"
DESCRIPTION = ("Build Mongo/PyMongo filters from explicit allow-listed fields and "
               "reject operator keys such as $where, $ne, $regex, $or, and $expr")

FILTER_METHODS = {
    'find', 'find_one', 'find_raw_batches', 'delete_one', 'delete_many',
    'count_documents',
}
UPDATE_METHODS = {
    'update_one', 'update_many', 'replace_one', 'find_one_and_update',
    'find_one_and_replace', 'find_one_and_delete',
}
PIPELINE_METHODS = {'aggregate', 'watch'}
COMMAND_METHODS = {'command'}
DANGEROUS_OPERATORS = {
    '$where', '$regex', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
    '$or', '$and', '$nor', '$expr', '$function', '$accumulator',
}
REQUEST_NAMES = {'request'}
UNTRUSTED_ATTRS = {'args', 'form', 'values', 'json', 'data', 'body', 'GET', 'POST'}
UNTRUSTED_CALLS = {'get_json', 'json', 'dict', 'to_dict'}


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''


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


def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []


def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False


class NoSQLInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, text, lines):
        self.text = text
        self.lines = lines
        self.untrusted_objects = set()
        self.unsafe_queries = set()
        self.request_values = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def expr_is_untrusted_object(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.untrusted_objects or node.id in self.unsafe_queries
        if isinstance(node, ast.Attribute):
            return rooted_at_request(node) and node.attr in UNTRUSTED_ATTRS
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if rooted_at_request(node.func) and short in UNTRUSTED_CALLS:
                return True
            if short == 'dict' and any(self.expr_is_untrusted_object(arg) for arg in node.args):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'copy', 'dict'}:
                return self.expr_is_untrusted_object(node.func.value)
        if isinstance(node, ast.Subscript):
            root = call_name(node.value)
            return root in {'request.json', 'request.data', 'request.body'} or (
                isinstance(node.value, ast.Name) and node.value.id in self.untrusted_objects
            )
        return False

    def expr_has_request_source(self, node):
        if rooted_at_request(node):
            return True
        return any(self.expr_has_request_source(child) for child in ast.iter_child_nodes(node))

    def expr_contains_request_data(self, node):
        if isinstance(node, ast.Name) and node.id in self.request_values:
            return True
        if self.expr_is_untrusted_object(node):
            return True
        if rooted_at_request(node):
            return True
        return any(self.expr_contains_request_data(child) for child in ast.iter_child_nodes(node))

    def value_contains_untrusted_object(self, node):
        if self.expr_is_untrusted_object(node):
            return True
        return any(self.value_contains_untrusted_object(child) for child in ast.iter_child_nodes(node))

    def dict_expr_is_unsafe(self, node):
        for key, value in zip(node.keys, node.values):
            if key is None:
                if self.expr_contains_request_data(value):
                    return True
                continue
            key_text = const_string(key)
            if key_text is None:
                if self.expr_contains_request_data(key) or self.expr_contains_request_data(value):
                    return True
                continue
            if key_text.startswith('$'):
                if key_text in {'$where', '$function', '$accumulator'}:
                    return True
                if key_text in DANGEROUS_OPERATORS and self.expr_contains_request_data(value):
                    return True
                if self.value_contains_untrusted_object(value):
                    return True
            elif self.value_contains_untrusted_object(value):
                return True
        return False

    def query_expr_is_unsafe(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.untrusted_objects or node.id in self.unsafe_queries
        if isinstance(node, ast.Dict):
            return self.dict_expr_is_unsafe(node)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self.query_expr_is_unsafe(elt) for elt in node.elts)
        if isinstance(node, ast.Call) and call_name(node.func).rsplit('.', 1)[-1] == 'dict':
            return any(self.query_expr_is_unsafe(arg) for arg in node.args)
        return self.expr_is_untrusted_object(node)

    def mark_assignment(self, names, value):
        is_untrusted = self.expr_is_untrusted_object(value)
        is_unsafe_query = self.query_expr_is_unsafe(value)
        has_request_value = self.expr_has_request_source(value)
        for name in names:
            if is_untrusted:
                self.untrusted_objects.add(name)
            else:
                self.untrusted_objects.discard(name)
            if is_unsafe_query:
                self.unsafe_queries.add(name)
            else:
                self.unsafe_queries.discard(name)
            if has_request_value:
                self.request_values.add(name)
            else:
                self.request_values.discard(name)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def sink_args(self, node, short):
        args = []
        if short in FILTER_METHODS:
            if node.args:
                args.append(node.args[0])
        elif short in UPDATE_METHODS:
            args.extend(node.args[:2])
        elif short in PIPELINE_METHODS:
            if node.args:
                args.append(node.args[0])
        elif short in COMMAND_METHODS:
            args.extend(node.args)
        for keyword in node.keywords:
            if keyword.arg in {'filter', 'query', 'pipeline', 'command', 'spec', 'where', 'update'}:
                args.append(keyword.value)
        return args

    def visit_Call(self, node):
        short = call_name(node.func).rsplit('.', 1)[-1]
        if short in (FILTER_METHODS | UPDATE_METHODS | PIPELINE_METHODS | COMMAND_METHODS):
            if any(self.query_expr_is_unsafe(arg) for arg in self.sink_args(node, short)):
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
        analyzer = NoSQLInjectionAnalyzer(text, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, source_line(lines, line_no)[:240]
