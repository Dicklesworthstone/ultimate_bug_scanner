"""ubs_core.py_detectors.command_injection — category 7 command-injection dataflow (bead 0xjg.5).

Port of run_command_injection_checks (modules/ubs-python.sh 3108-3428):
an ast.NodeVisitor that tracks request-derived taint (request.args/form/json,
sys.argv, os.environ, input(), ...) through assignments and flags subprocess
and os execution sinks whose command or executable is a dynamic string
(f-string / format / % / concatenation), a tainted name, a `sh -c` payload, or
shell=True input. shlex.quote / pipes.quote sanitize a segment.

Same-file and previous-line `ubs:ignore` markers suppress a hit; a per-file
`seen` line set dedupes repeats (legacy remember_issue).
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.io import python_source_segment

RULE_ID = "py.security.command-injection"
CATEGORY = 7
TITLE = "User-controlled command reaches shell or executable selection"
SEVERITY = "critical"
DESCRIPTION = ("Use a fixed executable with argv arrays, validate command allow-lists "
               "before dispatch, and avoid shell=True or shell -c")

SUBPROCESS_CALLS = {'run', 'call', 'check_call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput'}
OS_COMMAND_CALLS = {'system', 'popen'}
OS_EXEC_CALLS = {'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execle', 'execlp', 'execlpe'}
OS_SPAWN_CALLS = {'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe'}
SHELL_NAMES = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'cmd', 'powershell', 'pwsh'}
SHELL_FLAGS = {'-c', '-lc', '/c', '-command', '-encodedcommand'}
SOURCE_RE = re.compile(
    r"(?:request\.(?:args|form|values|json|data|body|GET|POST|get_json)|"
    r"flask\.request|django\.http\.request|sys\.argv|os\.environ|"
    r"event\s*\[|params\s*\[|input\s*\(|raw_input\s*\()",
    re.IGNORECASE,
)
SANITIZER_CALLS = {'shlex.quote', 'pipes.quote'}


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


def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
        if keyword.arg is None and isinstance(keyword.value, ast.Dict):
            values = literal_keywords(keyword.value)
            if name in values:
                return values[name]
    return None


def literal_keywords(node):
    """Read syntactic ** mappings without evaluating scanned code."""
    values = {}
    for key, value in zip(node.keys, node.values):
        if key is None and isinstance(value, ast.Dict):
            values.update(literal_keywords(value))
        elif isinstance(key, ast.Constant) and isinstance(key.value, str):
            values[key.value] = value
    return values


def positional_values(nodes):
    for node in nodes:
        if isinstance(node, ast.Starred) and isinstance(node.value, (ast.List, ast.Tuple)):
            yield from positional_values(node.value.elts)
        else:
            yield node


def argument_value(call, index, name):
    value = keyword_value(call, name)
    if value is not None:
        return value
    for position, value in enumerate(positional_values(call.args)):
        if isinstance(value, ast.Starred):
            # An unknown expansion has no reliable positional shape.
            return None
        if position == index:
            return value
    return None


def may_enable_shell(node):
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return bool(node.value)
    # A supplied dynamic flag can enable shell interpretation. Do not treat
    # shell=1 or shell=configuration as the default shell=False.
    return True


def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def all_static_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return all_static_strings(node.left) and all_static_strings(node.right)
    return False


def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []


def shell_name(value):
    if not value:
        return ''
    # The scanned program's platform need not match the scanner's platform.
    name = os.path.basename(value.replace('\\', '/')).lower()
    return name[:-4] if name.endswith('.exe') else name


class CommandAnalysisLimit(ValueError):
    """A bounded analysis must fail visibly instead of reporting a clean file."""


class LocalBindings(ast.NodeVisitor):
    """Names owned by a Python scope, excluding child scopes' local bindings."""
    def __init__(self):
        self.names = set()
        self.external = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)

    def visit_ImportFrom(self, node):
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_Global(self, node):
        self.external.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.names.add(node.name)
        for expr in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expr is not None:
                self.visit(expr)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.names.add(node.name)
        for expr in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expr)

    def visit_Lambda(self, node):
        for expr in [*node.args.defaults, *node.args.kw_defaults]:
            if expr is not None:
                self.visit(expr)

    def visit_comprehension(self, node):
        # Comprehension targets are local; a walrus in their expressions is not.
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)


class CommandInjectionAnalyzer(ast.NodeVisitor):
    _SET_FIELDS = ('tainted_names', 'raw_tainted_names', 'shell_command_vars',
                   'executable_vars', 'argv_names', 'subprocess_modules', 'os_modules',
                   'unsafe_shell_argv_names', 'unsafe_posix_payload_names',
                   'unsafe_windows_payload_names')

    def __init__(self, text, lines, *, max_steps=100_000):
        self.text = text
        self.lines = lines
        self.subprocess_modules = {'subprocess'}
        self.os_modules = {'os'}
        self.direct_calls = {}
        self.tainted_names = set()
        # Quoting protects a shell argument, not executable selection. Keep
        # the unescaped provenance as a separate domain through assignments.
        self.raw_tainted_names = set()
        self.shell_command_vars = set()
        self.executable_vars = set()
        self.argv_names = set()
        self.unsafe_shell_argv_names = set()
        self.unsafe_posix_payload_names = set()
        self.unsafe_windows_payload_names = set()
        self.issues = []
        self.seen_lines = set()
        self.remaining_steps = max_steps
        self.exception_states = []
        self.class_enclosing = []

    def state(self):
        return tuple(frozenset(getattr(self, name)) for name in self._SET_FIELDS) + (
            frozenset((name, call) for name, calls in self.direct_calls.items() for call in calls),)

    def restore(self, state):
        for name, value in zip(self._SET_FIELDS, state):
            setattr(self, name, set(value))
        self.direct_calls = {}
        for name, call in state[-1]:
            self.direct_calls.setdefault(name, set()).add(call)

    @staticmethod
    def merge(*states):
        states = [state for state in states if state is not None]
        if not states:
            return None
        # Taint and sink bindings are may facts. In contrast, argv is a must
        # fact: one scalar alternative must not inherit another branch's
        # exemption for a fixed executable followed by untrusted arguments.
        return tuple(frozenset.intersection(*(state[index] for state in states))
                     if index == 4 else frozenset.union(*(state[index] for state in states))
                     for index in range(len(states[0])))

    def merge_exits(self, *flows):
        result = {}
        for flow in flows:
            for kind, state in flow.items():
                result[kind] = self.merge(result.get(kind), state)
        return result

    def forget(self, names):
        for field in self._SET_FIELDS:
            getattr(self, field).difference_update(names)
        for name in names:
            self.direct_calls.pop(name, None)

    def observe(self, state):
        for index, previous in enumerate(self.exception_states):
            self.exception_states[index] = self.merge(previous, state)

    def suite(self, statements, initial):
        flow = {'normal': initial}
        for statement in statements:
            current = flow.pop('normal', None)
            if current is None:
                break
            self.remaining_steps -= 1
            if self.remaining_steps < 0:
                raise CommandAnalysisLimit('command-injection control-flow budget exceeded')
            self.restore(current)
            self.observe(current)
            exits = self.statement(statement)
            for state in exits.values():
                self.observe(state)
            flow = self.merge_exits(flow, exits)
        return flow

    def statement(self, node):
        if isinstance(node, ast.If):
            self.visit(node.test)
            entry = self.state()
            if isinstance(node.test, ast.Constant):
                return self.suite(node.body if node.test.value else node.orelse, entry)
            return self.merge_exits(self.suite(node.body, entry), self.suite(node.orelse, entry))
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self.loop(node)
        if isinstance(node, (ast.Try, getattr(ast, 'TryStar', ast.Try))):
            return self.try_statement(node)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.visit(item.context_expr)
                if item.optional_vars is not None:
                    self.mark_assignment(target_names(item.optional_vars), item.context_expr)
            flow = self.suite(node.body, self.state())
            if 'raise' in flow:
                # A context manager may suppress an exception; do not assume
                # a raising path is dead after an unknown __exit__ method.
                flow['normal'] = self.merge(flow.get('normal'), flow['raise'])
            return flow
        if isinstance(node, getattr(ast, 'Match', ())):
            self.visit(node.subject)
            entry = self.state()
            flow = {}
            exhaustive = False
            for case in node.cases:
                self.restore(entry)
                bindings = LocalBindings()
                bindings.visit(case.pattern)
                self.mark_assignment(bindings.names, node.subject)
                self.argv_names.difference_update(bindings.names)
                if case.guard is not None:
                    self.visit(case.guard)
                flow = self.merge_exits(flow, self.suite(case.body, self.state()))
                if case.guard is None and isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                    exhaustive = True
            if not exhaustive:
                flow = self.merge_exits(flow, {'normal': entry})
            return flow
        if isinstance(node, ast.Return):
            if node.value is not None:
                self.visit(node.value)
            return {'return': self.state()}
        if isinstance(node, ast.Raise):
            for expr in (node.exc, node.cause):
                if expr is not None:
                    self.visit(expr)
            return {'raise': self.state()}
        if isinstance(node, (ast.Break, ast.Continue)):
            return {'break' if isinstance(node, ast.Break) else 'continue': self.state()}
        self.visit(node)
        return {'normal': self.state()}

    def loop(self, node):
        is_for = isinstance(node, (ast.For, ast.AsyncFor))
        if is_for:
            self.visit(node.iter)
        entry = self.state()
        header = entry
        while True:
            self.restore(header)
            if is_for:
                self.mark_assignment(target_names(node.target), node.iter)
                self.argv_names.difference_update(target_names(node.target))
                exhausted = header
            else:
                self.visit(node.test)
                exhausted = self.state()
                if isinstance(node.test, ast.Constant) and not node.test.value:
                    return self.suite(node.orelse, exhausted)
            body = self.suite(node.body, self.state())
            updated = self.merge(entry, body.get('normal'), body.get('continue'))
            if updated == header:
                break
            header = updated
        result = {kind: state for kind, state in body.items() if kind in ('return', 'raise')}
        if is_for or not (isinstance(node.test, ast.Constant) and node.test.value):
            result = self.merge_exits(result, self.suite(node.orelse, exhausted))
        if 'break' in body:
            result = self.merge_exits(result, {'normal': body['break']})
        return result

    def try_statement(self, node):
        entry = self.state()
        self.exception_states.append(entry)
        body = self.suite(node.body, entry)
        exceptional = self.exception_states.pop()
        normal = body.pop('normal', None)
        result = self.merge_exits(body, {'raise': exceptional})
        if normal is not None:
            result = self.merge_exits(result, self.suite(node.orelse, normal))
        for handler in node.handlers:
            self.restore(exceptional)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self.forget([handler.name])
            flow = self.suite(handler.body, self.state())
            if handler.name:
                for kind, state in flow.items():
                    self.restore(state)
                    self.forget([handler.name])
                    flow[kind] = self.state()
            result = self.merge_exits(result, flow)
        if node.finalbody:
            finalized = {}
            for pending, state in result.items():
                flow = self.suite(node.finalbody, state)
                normal = flow.pop('normal', None)
                if normal is not None:
                    flow = self.merge_exits(flow, {pending: normal})
                finalized = self.merge_exits(finalized, flow)
            result = finalized
        return result

    def visit_Module(self, node):
        entry = self.state()
        flow = self.suite(node.body, entry)
        self.restore(flow.get('normal', entry))

    def visit_FunctionDef(self, node):
        for expr in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expr is not None:
                self.visit(expr)
        self.forget([node.name])
        outer = self.state()
        inherited = self.class_enclosing[-1] if self.class_enclosing else outer
        self.restore(inherited)
        bindings = LocalBindings()
        for statement in node.body:
            bindings.visit(statement)
        parameters = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
        parameters.extend(arg.arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None)
        self.forget((bindings.names - bindings.external) | set(parameters))
        exceptions, classes = self.exception_states, self.class_enclosing
        self.exception_states, self.class_enclosing = [], []
        try:
            self.suite(node.body, self.state())
        finally:
            self.restore(outer)
            self.exception_states, self.class_enclosing = exceptions, classes

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expr in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expr)
        self.forget([node.name])
        outer = self.state()
        self.class_enclosing.append(self.class_enclosing[-1] if self.class_enclosing else outer)
        try:
            self.suite(node.body, outer)
        finally:
            self.class_enclosing.pop()
            self.restore(outer)

    def visit_Lambda(self, node):
        for expr in [*node.args.defaults, *node.args.kw_defaults]:
            if expr is not None:
                self.visit(expr)
        outer = self.state()
        parameters = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
        parameters.extend(arg.arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None)
        self.forget(parameters)
        try:
            self.visit(node.body)
        finally:
            self.restore(outer)

    def visit_IfExp(self, node):
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            self.visit(node.body if node.test.value else node.orelse)
            return
        entry = self.state()
        self.visit(node.body)
        left = self.state()
        self.restore(entry)
        self.visit(node.orelse)
        self.restore(self.merge(left, self.state()))

    def visit_BoolOp(self, node):
        result = None
        for value in node.values:
            self.visit(value)
            result = self.merge(result, self.state())
            if isinstance(value, ast.Constant) and (
                    (isinstance(node.op, ast.And) and not value.value) or
                    (isinstance(node.op, ast.Or) and value.value)):
                break
        self.restore(result)

    def visit_ListComp(self, node):
        # Only the first iterable is evaluated in the enclosing scope. The
        # remaining iterables, filters and values run in the comprehension's
        # private scope, possibly zero times. Reuse the ordinary loop solver
        # so backedges and filters do not become unconditional assignments.
        first = node.generators[0]
        self.visit(first.iter)
        outer = self.state()
        temporary = '\0comprehension_iterable'
        self.mark_assignment([temporary], first.iter)
        local_names = {name for generator in node.generators
                       for name in target_names(generator.target)}
        self.forget(local_names)
        values = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        body = [ast.Expr(value=value) for value in values]
        for index in range(len(node.generators) - 1, -1, -1):
            generator = node.generators[index]
            for condition in reversed(generator.ifs):
                body = [ast.If(test=condition, body=body, orelse=[])]
            iterable = ast.Name(id=temporary, ctx=ast.Load()) if index == 0 else generator.iter
            body = [ast.For(target=generator.target, iter=iterable, body=body, orelse=[])]
        # Assignment expressions may escape; iteration targets never do.
        escaped = LocalBindings()
        escaped.visit(node)
        names = escaped.names - local_names
        observers = self.exception_states
        self.exception_states = [self.state()]
        try:
            flow = self.suite(body, self.state())
            observed = self.exception_states[0]
            changed = self.merge(outer, *flow.values())
        finally:
            self.exception_states = observers
            self.restore(outer)

        def export(state):
            fields = [frozenset((before - names) | (after & names))
                      for before, after in zip(outer[:-1], state[:-1])]
            aliases = frozenset((name, call) for name, call in outer[-1] if name not in names)
            aliases |= frozenset((name, call) for name, call in state[-1] if name in names)
            return (*fields, aliases)

        self.observe(export(self.merge(outer, observed)))
        self.restore(export(changed))

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    # A generator can be consumed later. Retain possible escaping effects,
    # but never assume that its body executes just because it was created.
    visit_GeneratorExp = visit_ListComp

    def visit_Delete(self, node):
        self.generic_visit(node)
        self.forget([name for target in node.targets for name in target_names(target)])

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.mark_assignment(target_names(node.target), node.value)

    def safe_argv_extension(self, node):
        """A literal tail with no dynamic or untrusted values cannot change argv[0].

        Keep this narrower than general list concatenation: an unknown tail
        may supply a shell flag or payload and must retain the conservative
        fallback until vector mutation has a complete positional model.
        """
        if isinstance(node, ast.IfExp):
            return self.safe_argv_extension(node.body) and self.safe_argv_extension(node.orelse)
        return isinstance(node, (ast.List, ast.Tuple)) and all(
            not isinstance(value, ast.Starred)
            and not self.expr_is_dynamic_string(value)
            and not self.expr_is_tainted(value, shell=False)
            for value in node.elts
        )

    def visit_AugAssign(self, node):
        self.visit(node.value)
        if (isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name)
                and node.target.id in self.argv_names
                and self.safe_argv_extension(node.value)):
            # Preserve the existing executable/payload provenance, including
            # dangerous prefixes. Adding safe options is not string building.
            return
        value = ast.BinOp(left=node.target, op=node.op, right=node.value)
        self.mark_assignment(target_names(node.target), value)

    def segment(self, node):
        return python_source_segment(self.text, node) or ''

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def expr_is_sanitized(self, node):
        # Only this call's returned value is escaped. A quoted sibling, an
        # unused call, or sanitizer-looking string must not clean a parent.
        return isinstance(node, ast.Call) and call_name(node.func) in SANITIZER_CALLS

    def expr_has_source(self, node):
        if isinstance(node, ast.Call):
            return bool(SOURCE_RE.search(call_name(node.func) + '('))
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = call_name(node)
            return bool(SOURCE_RE.search(name)) or (
                isinstance(node, ast.Subscript) and name in {'event', 'params'}
            )
        return False

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def expr_is_tainted(self, node, *, shell=True):
        if node is None or isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.NamedExpr):
            return self.expr_is_tainted(node.value, shell=shell)
        if isinstance(node, ast.IfExp) and isinstance(node.test, ast.Constant):
            return self.expr_is_tainted(node.body if node.test.value else node.orelse, shell=shell)
        if shell and self.expr_is_sanitized(node):
            return False
        names = self.tainted_names if shell else self.raw_tainted_names
        if isinstance(node, ast.Name) and node.id in names:
            return True
        return self.expr_has_source(node) or any(
            self.expr_is_tainted(child, shell=shell) for child in ast.iter_child_nodes(node)
        )

    def expr_is_dynamic_string(self, node):
        if self.expr_is_tainted(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self.expr_is_dynamic_string(node.value)
        if isinstance(node, ast.IfExp):
            if isinstance(node.test, ast.Constant):
                return self.expr_is_dynamic_string(node.body if node.test.value else node.orelse)
            return self.expr_is_dynamic_string(node.body) or self.expr_is_dynamic_string(node.orelse)
        if isinstance(node, ast.BoolOp):
            return any(self.expr_is_dynamic_string(value) for value in node.values)
        if isinstance(node, ast.Name):
            return node.id in self.shell_command_vars
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(part, ast.FormattedValue) for part in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not all_static_strings(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return True
        return False

    def arg_is_shell_command(self, node):
        if isinstance(node, ast.Name) and node.id in self.shell_command_vars:
            return True
        return self.expr_is_dynamic_string(node)

    def executable_is_dynamic(self, node):
        if self.expr_is_tainted(node, shell=False):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.executable_vars or node.id in self.shell_command_vars
        return self.expr_is_dynamic_string(node)

    def shell_flag_payload(self, node):
        if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) < 3:
            return None
        flag = const_string(node.elts[1])
        if flag and flag.lower() in SHELL_FLAGS:
            return node.elts[2]
        return None

    def shell_c_payload(self, node, executable=None):
        payload = self.shell_flag_payload(node)
        if payload is None:
            return None
        executable = const_string(executable if executable is not None else node.elts[0])
        return payload if shell_name(executable) in SHELL_NAMES else None

    def argv_shell_is_unsafe(self, node, executable=None):
        if isinstance(node, ast.IfExp):
            if isinstance(node.test, ast.Constant):
                return self.argv_shell_is_unsafe(node.body if node.test.value else node.orelse, executable)
            return self.argv_shell_is_unsafe(node.body, executable) or self.argv_shell_is_unsafe(node.orelse, executable)
        program = shell_name(const_string(executable)) if executable is not None else ''
        if isinstance(node, ast.Name):
            if executable is None:
                return node.id in self.unsafe_shell_argv_names
            if program not in SHELL_NAMES:
                return False
            names = self.unsafe_windows_payload_names if program in {'cmd', 'powershell', 'pwsh'} else self.unsafe_posix_payload_names
            return node.id in names
        payload = self.shell_c_payload(node, executable)
        if payload is None:
            return False
        if executable is None:
            program = shell_name(const_string(node.elts[0]))
        # shlex.quote escapes POSIX tokens, not cmd/PowerShell programs. Keep
        # their raw provenance even when the POSIX shell domain is clean.
        return self.arg_is_shell_command(payload) or (
            program in {'cmd', 'powershell', 'pwsh'} and self.expr_is_tainted(payload, shell=False)
        )

    def argv_payload_is_unsafe(self, node, *, windows=False):
        if isinstance(node, ast.IfExp):
            if isinstance(node.test, ast.Constant):
                return self.argv_payload_is_unsafe(node.body if node.test.value else node.orelse, windows=windows)
            return self.argv_payload_is_unsafe(node.body, windows=windows) or self.argv_payload_is_unsafe(node.orelse, windows=windows)
        if isinstance(node, ast.Name):
            names = self.unsafe_windows_payload_names if windows else self.unsafe_posix_payload_names
            return node.id in names
        payload = self.shell_flag_payload(node)
        return payload is not None and (self.arg_is_shell_command(payload) or (
            windows and self.expr_is_tainted(payload, shell=False)))

    def expr_is_argv(self, node):
        if isinstance(node, ast.IfExp):
            if isinstance(node.test, ast.Constant):
                return self.expr_is_argv(node.body if node.test.value else node.orelse)
            return self.expr_is_argv(node.body) and self.expr_is_argv(node.orelse)
        return isinstance(node, (ast.List, ast.Tuple)) or (
            isinstance(node, ast.Name) and node.id in self.argv_names)

    def list_executable_is_dynamic(self, node):
        if isinstance(node, ast.IfExp):
            if isinstance(node.test, ast.Constant):
                return self.list_executable_is_dynamic(node.body if node.test.value else node.orelse)
            return self.list_executable_is_dynamic(node.body) or self.list_executable_is_dynamic(node.orelse)
        if isinstance(node, ast.Name):
            return node.id in self.executable_vars
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            return self.executable_is_dynamic(node.elts[0])
        return False

    def canonical_calls(self, node):
        name = call_name(node.func)
        if name in self.direct_calls:
            return sorted(self.direct_calls[name])
        for module in self.subprocess_modules:
            for func in SUBPROCESS_CALLS:
                if name == f'{module}.{func}':
                    return [f'subprocess.{func}']
        for module in self.os_modules:
            for func in OS_COMMAND_CALLS | OS_EXEC_CALLS | OS_SPAWN_CALLS:
                if name == f'{module}.{func}':
                    return [f'os.{func}']
        return []

    def canonical_call(self, node):
        calls = self.canonical_calls(node)
        return calls[0] if calls else ''

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            self.forget([local])
            if alias.name == 'subprocess':
                self.subprocess_modules.add(local)
            elif alias.name == 'os':
                self.os_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            self.forget([local])
            if module == 'subprocess' and alias.name in SUBPROCESS_CALLS:
                self.direct_calls[local] = {f'subprocess.{alias.name}'}
            elif module == 'os' and alias.name in (OS_EXEC_CALLS | OS_SPAWN_CALLS | OS_COMMAND_CALLS):
                self.direct_calls[local] = {f'os.{alias.name}'}
        self.generic_visit(node)

    def mark_assignment(self, names, value):
        tainted = self.expr_is_tainted(value)
        raw_tainted = self.expr_is_tainted(value, shell=False)
        shell_command = self.expr_is_dynamic_string(value)
        dynamic_executable = self.list_executable_is_dynamic(value)
        is_argv = self.expr_is_argv(value)
        unsafe_posix = self.argv_payload_is_unsafe(value)
        unsafe_windows = self.argv_payload_is_unsafe(value, windows=True)
        unsafe_shell = self.argv_shell_is_unsafe(value)
        for name in names:
            self.subprocess_modules.discard(name)
            self.os_modules.discard(name)
            self.direct_calls.pop(name, None)
            if is_argv:
                self.argv_names.add(name)
            else:
                self.argv_names.discard(name)
            if raw_tainted:
                self.raw_tainted_names.add(name)
            else:
                self.raw_tainted_names.discard(name)
            if tainted:
                self.tainted_names.add(name)
            else:
                self.tainted_names.discard(name)
            if shell_command:
                self.shell_command_vars.add(name)
            else:
                self.shell_command_vars.discard(name)
            if dynamic_executable:
                self.executable_vars.add(name)
            else:
                self.executable_vars.discard(name)
            for field, unsafe in (
                    ('unsafe_shell_argv_names', unsafe_shell),
                    ('unsafe_posix_payload_names', unsafe_posix),
                    ('unsafe_windows_payload_names', unsafe_windows)):
                if unsafe:
                    getattr(self, field).add(name)
                else:
                    getattr(self, field).discard(name)

    def visit_Assign(self, node):
        self.visit(node.value)
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.visit(node.target)

    def subprocess_arg_is_unsafe(self, node):
        command = argument_value(node, 0, 'args')
        if command is None:
            return False
        # The wrappers forward Popen's positional and keyword arguments.
        executable = argument_value(node, 2, 'executable')
        if isinstance(executable, ast.Constant) and executable.value is None:
            executable = None
        if executable is not None and self.executable_is_dynamic(executable):
            return True
        if may_enable_shell(argument_value(node, 8, 'shell')):
            return self.arg_is_shell_command(command)
        if self.argv_shell_is_unsafe(command, executable):
            return True
        if executable is not None:
            # With an explicit fixed program, argv[0] is data, not the
            # executable selector. A fixed shell override was checked above.
            return False
        if self.expr_is_argv(command):
            return self.list_executable_is_dynamic(command)
        # A scalar args value chooses the executable even without a shell;
        # shell quoting does not authorize that program.
        return self.executable_is_dynamic(command)

    def os_exec_arg_is_unsafe(self, node, func):
        if func in OS_SPAWN_CALLS:
            executable_index = 1
        else:
            executable_index = 0
        executable = argument_value(node, executable_index, 'file')
        if executable is None:
            executable = argument_value(node, executable_index, 'path')
        if executable is None:
            return False
        if self.executable_is_dynamic(executable):
            return True
        if func.startswith(('execv', 'spawnv')):
            argv = argument_value(node, executable_index + 1, 'args')
        else:
            arguments = list(positional_values(node.args))
            # The last argument of the l*e variants is an environment mapping,
            # not a command argument. argv[0] is still the program's display name.
            argv = ast.List(elts=arguments[executable_index + 1:-1 if func.endswith('e') else None], ctx=ast.Load())
        return self.argv_shell_is_unsafe(argv, executable)

    def visit_Call(self, node):
        for canonical in self.canonical_calls(node):
            module, func = canonical.rsplit('.', 1)
            unsafe = False
            if module == 'subprocess':
                if func in {'getoutput', 'getstatusoutput'}:
                    unsafe = self.arg_is_shell_command(argument_value(node, 0, 'cmd'))
                else:
                    unsafe = self.subprocess_arg_is_unsafe(node)
            elif module == 'os' and func in OS_COMMAND_CALLS:
                command = argument_value(node, 0, 'cmd' if func == 'popen' else 'command')
                unsafe = command is not None and self.arg_is_shell_command(command)
            elif module == 'os' and func in (OS_EXEC_CALLS | OS_SPAWN_CALLS):
                unsafe = self.os_exec_arg_is_unsafe(node, func)
            if unsafe:
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
        analyzer = CommandInjectionAnalyzer(text, lines)
        analyzer.visit(tree)
        for line_no in sorted(analyzer.issues):
            yield path, line_no, 1, source_line(lines, line_no)[:240]
