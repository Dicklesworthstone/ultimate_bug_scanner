"""ubs_core.py_detectors.ldap_injection — LDAP filter/DN injection (bead 0xjg.5).

Port of run_ldap_injection_checks (modules/ubs-python.sh 2833-3106): a
taint-style ast.NodeVisitor flagging request-controlled values that reach
directory sinks — LDAP search methods (filter as 2nd arg for search/
paged_search, 3rd for the *_s/_ext variants, `search_filter`/`filterstr`/
`ldap_filter` keywords, LDAPSearch constructor filter arg) and DN methods
(add/delete/modify/rename/bind families, `dn`/`user`/`*_dn` keywords). A
value is tainted when it roots at `request` (or `*_request`), comes from
input()/sys.stdin, or indexes sys.argv/os.environ, unless it passes through
a SAFE_LDAP_FUNCS sanitizer or a `.format()` over safe parts. Function
scopes reset the taint/safe tracking, exactly like the legacy analyzer.

Comment directives use shared statement ownership and rule scopes; hits
dedupe per line within a file (legacy `seen_lines`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions

RULE_ID = "py.security.ldap-injection"
CATEGORY = 7
TITLE = "Request-controlled LDAP filter or DN reaches directory sink"
SEVERITY = "critical"
DESCRIPTION = ("Escape LDAP filter values with escape_filter_chars(), escape DN fragments "
               "with escape_dn_chars(), or use fixed allow-lists before LDAP operations")

REQUEST_NAMES = {'request'}
LDAP_SEARCH_METHODS = {
    'search', 'search_s', 'search_st', 'search_ext', 'search_ext_s',
    'paged_search', 'paged_search_s', 'paged_search_ext_s',
}
LDAP_SECOND_ARG_FILTER_METHODS = {'search', 'paged_search'}
LDAP_DN_METHODS = {
    'add', 'add_s', 'delete', 'delete_s', 'modify', 'modify_s',
    'modify_dn', 'modify_dn_s', 'rename', 'rename_s', 'compare_s',
    'simple_bind_s', 'bind_s', 'rebind', 'rebind_s',
}
LDAP_CONSTRUCTORS = {'LDAPSearch', 'django_auth_ldap.config.LDAPSearch'}
FILTER_KEYWORDS = {'search_filter', 'filterstr', 'ldap_filter'}
DN_KEYWORDS = {'dn', 'user', 'user_dn', 'bind_dn', 'base_dn'}
SAFE_LDAP_FUNCS = {
    'escape_filter_chars', 'ldap.filter.escape_filter_chars',
    'escape_dn_chars', 'ldap.dn.escape_dn_chars',
    'validate_ldap_filter_value', 'validate_ldap_dn_value',
    'sanitize_ldap_filter_value', 'sanitize_ldap_dn_value',
    'allowlisted_ldap_value', 'allowlisted_ldap_dn',
}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ''


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return _rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return _rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return _rooted_at_request(node.value)
    return False


def _direct_untrusted_source(node):
    name = _call_name(node)
    if _rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and _call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False


def _keyword_values(node, names):
    return [keyword.value for keyword in getattr(node, 'keywords', []) if keyword.arg in names]


class _LDAPInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, lines, tree, suppressions):
        self.lines = lines
        self.suppressions = suppressions
        self.tainted_values = set()
        self.safe_values = set()
        self.issue_lines = []
        self.seen_lines = set()
        self.set_receivers = set()
        nodes = tuple(ast.walk(tree))
        self.external_names = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal))
                               for name in node.names}
        self.dynamic_names = any(
            isinstance(node, ast.Name) and node.id in {
                'globals', 'locals', 'vars', 'exec', 'eval', '__builtins__', 'currentframe', '_getframe'}
            or isinstance(node, ast.Attribute) and node.attr in {
                'f_locals', 'f_globals', '__dict__', '__globals__', '__closure__',
                'cell_contents', 'currentframe', '_getframe'}
            or isinstance(node, ast.ImportFrom) and any(
                alias.name in {'currentframe', '_getframe'} for alias in node.names)
            for node in nodes)
        self.builtin_set = not self.dynamic_names and 'set' not in self.external_names
        for node in nodes:
            if (isinstance(node, ast.Name) and node.id == 'set' and isinstance(node.ctx, (ast.Store, ast.Del))
                    or isinstance(node, ast.arg) and node.arg == 'set'
                    or isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name == 'set'
                    or isinstance(node, ast.MatchMapping) and node.rest == 'set'
                    or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == 'set'
                    or isinstance(node, ast.Attribute) and node.attr == 'set' and isinstance(node.ctx, (ast.Store, ast.Del))
                    or isinstance(node, ast.Call) and _call_name(node.func).rsplit('.', 1)[-1] in {
                        'setattr', 'delattr', '__setattr__', '__delattr__'}):
                self.builtin_set = False
            if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                    (alias.asname or alias.name.split('.')[0]) == 'set' or alias.name == '*'
                    for alias in node.names):
                self.builtin_set = False

    def local_set_receivers(self, function):
        """Prove builtin set identity, never infer LDAP safety from a name.

        A single function-local binding cannot change type through an alias.
        Rebindings, parameters, deferred nonlocal writes and frame reflection
        invalidate that proof. Constructor shadowing affects set(), while a
        set display intrinsically constructs the builtin type.
        """
        if self.dynamic_names:
            return set()
        arguments = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        arguments += [arg for arg in (function.args.vararg, function.args.kwarg) if arg is not None]
        counts = {argument.arg: 1 for argument in arguments}
        candidates, pending = set(), list(function.body)
        while pending:
            node = pending.pop()
            names = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                counts[node.name] = counts.get(node.name, 0) + 1
                if isinstance(node, ast.ClassDef):
                    pending.extend([*node.decorator_list, *node.bases, *node.keywords])
                else:
                    pending.extend([*node.decorator_list, *node.args.defaults,
                                    *(value for value in node.args.kw_defaults if value is not None)])
                    pending.extend(argument.annotation for argument in
                                   [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                                    *(arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None)]
                                   if argument.annotation is not None)
                    if node.returns is not None:
                        pending.append(node.returns)
                continue
            if isinstance(node, ast.Lambda):
                pending.extend([*node.args.defaults, *(value for value in node.args.kw_defaults if value is not None)])
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.append(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names.extend(alias.asname or alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                names.append(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                names.append(node.rest)
            for name in names:
                counts[name] = counts.get(name, 0) + 1
            target = node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else (
                node.target if isinstance(node, ast.AnnAssign) else None)
            if isinstance(target, ast.Name):
                value = node.value
                if (isinstance(value, (ast.Set, ast.SetComp))
                        or self.builtin_set and isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name) and value.func.id == 'set'):
                    candidates.add(target.id)
            pending.extend(ast.iter_child_nodes(node))
        return {name for name in candidates if counts.get(name) == 1 and name not in self.external_names}

    def remember_issue(self, line_no):
        if self.suppressions.is_suppressed(line_no, RULE_ID) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issue_lines.append(line_no)

    def expr_is_safe_ldap(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_LDAP_FUNCS or short in SAFE_LDAP_FUNCS:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return self.expr_is_safe_ldap(node.func.value) and all(
                    self.expr_is_safe_ldap(arg) for arg in node.args
                ) and all(self.expr_is_safe_ldap(keyword.value) for keyword in node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_ldap(node.left) and self.expr_is_safe_ldap(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_safe_ldap(value.value):
                    continue
                return False
            return True
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_safe_ldap(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if _direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_ldap(value)
        is_tainted = (not is_safe) and self.expr_contains_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
            else:
                self.safe_values.discard(name)
            if is_tainted:
                self.tainted_values.add(name)
            else:
                self.tainted_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.tainted_values)
        old_sets, self.set_receivers = self.set_receivers, self.local_set_receivers(node)
        self.safe_values.clear()
        self.tainted_values.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.tainted_values = old_tainted
        self.set_receivers = old_sets

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in _target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = _target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def search_filter_args(self, node, short):
        args = []
        if short in LDAP_SECOND_ARG_FILTER_METHODS:
            if len(node.args) >= 2:
                args.append(node.args[1])
        elif short in LDAP_SEARCH_METHODS:
            if len(node.args) >= 3:
                args.append(node.args[2])
        if short in LDAP_CONSTRUCTORS:
            if len(node.args) >= 3:
                args.append(node.args[2])
        args.extend(_keyword_values(node, FILTER_KEYWORDS))
        return args

    def dn_args(self, node, short):
        args = []
        if short in LDAP_DN_METHODS and node.args:
            args.append(node.args[0])
        args.extend(_keyword_values(node, DN_KEYWORDS))
        return args

    def visit_Call(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        values = []
        if short in LDAP_SEARCH_METHODS or short in LDAP_CONSTRUCTORS or name in LDAP_CONSTRUCTORS:
            values.extend(self.search_filter_args(node, short))
        builtin_add = (short == 'add' and isinstance(node.func, ast.Attribute)
                       and isinstance(node.func.value, ast.Name) and node.func.value.id in self.set_receivers)
        if short in LDAP_DN_METHODS and not builtin_add:
            values.extend(self.dn_args(node, short))
        if values and any(self.expr_contains_taint(value) for value in values):
            self.remember_issue(node.lineno)
        self.generic_visit(node)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions('python')
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        analyzer = _LDAPInjectionAnalyzer(lines, tree, suppressions.index(path, text))
        analyzer.visit(tree)
        for line_no in analyzer.issue_lines:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
