"""Outbound HTTP timeout policy for selected Python client bindings.

An omitted request option inherits the client's policy; an explicit option
replaces it. HTTPX and aiohttp have finite native defaults, unlike requests
and urllib3. Resolve imports, aliases and lexical bindings before borrowing
those contracts. Unknown external configuration is not proof of a missing
timeout. This is a bounded configuration check, not whole-program deadline
or cancellation analysis.

Shared lexical statement ownership and exact rule scopes suppress annotated
hits; hits are line-deduped per file (legacy ``seen_lines``).
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions

RULE_ID = "py.security.http-timeout"
CATEGORY = 7
TITLE = "Outbound HTTP call has no bounded timeout"
SEVERITY = "warning"
DESCRIPTION = "Pass timeout=... or configure the HTTP client with a bounded timeout"

HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'send'}
URLLIB3_METHODS = {'request', 'request_encode_url', 'request_encode_body', 'urlopen'}
CLIENT_CONSTRUCTORS = {
    'requests.Session': 'requests', 'requests.session': 'requests',
    'requests.sessions.Session': 'requests',
    'httpx.Client': 'httpx', 'httpx.AsyncClient': 'httpx',
    'aiohttp.ClientSession': 'aiohttp',
    'urllib3.PoolManager': 'urllib3', 'urllib3.ProxyManager': 'urllib3',
}
TIMEOUT_CONSTRUCTORS = {
    'httpx.Timeout': 'httpx', 'aiohttp.ClientTimeout': 'aiohttp',
    'urllib3.Timeout': 'urllib3', 'urllib3.util.Timeout': 'urllib3',
    'urllib3.util.timeout.Timeout': 'urllib3',
}


@dataclass(frozen=True)
class _Value:
    kind: str
    name: str = ''
    data: object = None


UNKNOWN = frozenset({_Value('unknown')})
MISSING = frozenset({_Value('missing')})


def _join_policy(policies):
    """A known unbounded alternative is actionable; unknown is not bounded."""
    policies = tuple(policies)
    if False in policies:
        return False
    if not policies or None in policies:
        return None
    return True


class _LocalNames(ast.NodeVisitor):
    """Collect Python function locals without borrowing nested scopes."""
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

    def visit_FunctionDef(self, node):
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_Global(self, node):
        self.external.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        # Comprehension targets belong to their own implicit function scope.
        self.visit(node.generators[0].iter)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


class HttpTimeoutAnalyzer(ast.NodeVisitor):
    def __init__(self, lines, suppression):
        self.lines = lines
        self.suppression = suppression
        self.issues = []
        self.seen_lines = set()
        self.bindings = {}
        self.client_policies = {}
        self.member_overrides = {}
        self.call_results = {}
        self.call_inputs = {}
        self.class_enclosing = None

    def remember_issue(self, line_no):
        if self.suppression.is_suppressed(line_no, RULE_ID) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            canonical = alias.name if alias.asname else local
            self.bindings[local] = frozenset({_Value('native', canonical)})

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            self.bindings[local] = (UNKNOWN if node.level or alias.name == '*'
                                    else frozenset({_Value('native', f'{node.module}.{alias.name}')}))

    def values(self, node):
        if node is None:
            return UNKNOWN
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, UNKNOWN)
        if isinstance(node, ast.Constant):
            return frozenset({_Value('literal', data=node.value)})
        if isinstance(node, (ast.Tuple, ast.List)):
            return frozenset({_Value('sequence', data=tuple(self.values(item) for item in node.elts))})
        if isinstance(node, ast.Dict) and all(isinstance(key, ast.Constant) and isinstance(key.value, str)
                                              for key in node.keys):
            items = {key.value: self.values(value) for key, value in zip(node.keys, node.values)}
            return frozenset({_Value('mapping', data=tuple(items.items()))})
        if isinstance(node, (ast.IfExp, ast.BoolOp)):
            return self.call_results.get(id(node), UNKNOWN)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            result = set()
            for value in self.values(node.operand):
                if value.kind == 'literal' and isinstance(value.data, (int, float)):
                    result.add(_Value('literal', data=-value.data if isinstance(node.op, ast.USub) else value.data))
                else:
                    result.update(UNKNOWN)
            return frozenset(result)
        if isinstance(node, ast.Attribute):
            result = set()
            for owner in self.values(node.value):
                if owner.kind == 'native':
                    name = f'{owner.name}.{node.attr}'
                    result.update(self.member_overrides.get(name, frozenset({_Value('native', name)})))
                elif owner.kind == 'client' and node.attr in HTTP_METHODS | URLLIB3_METHODS:
                    key = (owner, node.attr)
                    result.update(self.member_overrides.get(key, self.member_default(key)))
                else:
                    result.update(UNKNOWN)
            return frozenset(result)
        if isinstance(node, ast.Call):
            return self.call_results.get(id(node), UNKNOWN)
        if isinstance(node, ast.NamedExpr):
            return self.values(node.value)
        return UNKNOWN

    def argument_values(self, call, expression):
        return self.call_inputs.get(id(call), {}).get(id(expression), self.values(expression))

    def option(self, call, name):
        """Return (present, values), retaining opaque **kwargs as uncertainty."""
        present = False
        result = MISSING
        for keyword in call.keywords:
            if keyword.arg == name:
                present, result = True, self.argument_values(call, keyword.value)
            elif keyword.arg is None:
                alternatives = []
                for value in self.argument_values(call, keyword.value):
                    if value.kind != 'mapping':
                        alternatives.append(UNKNOWN)
                    else:
                        alternatives.append(dict(value.data).get(name, result))
                result = frozenset().union(*alternatives) or UNKNOWN
                present = result != MISSING
        return present, result

    def option_policy(self, values, family, inherited):
        return _join_policy(inherited if value.kind == 'missing'
                            else self.bounded(frozenset({value}), family)
                            for value in values)

    def bounded(self, values, family):
        policies = []
        for value in values:
            if value.kind == 'timeout' and value.name == family:
                policies.append(value.data)
            elif value.kind == 'literal':
                if value.data is None:
                    policies.append(False)
                elif isinstance(value.data, (int, float)):
                    # HTTPX zero is an immediate timeout; aiohttp zero/negative
                    # values disable that timer. requests/urllib3 reject zero.
                    policies.append(value.data > 0 if family == 'aiohttp' else True)
                else:
                    policies.append(None)
            elif value.kind == 'sequence' and family == 'requests' and len(value.data) == 2:
                policies.append(_join_policy(self.bounded(item, family) for item in value.data))
            else:
                policies.append(None)
        return _join_policy(policies)

    def timeout_object(self, call, family):
        name = 'timeout' if family == 'httpx' else 'total'
        supplied, default = self.option(call, name)
        if not supplied and call.args:
            supplied, default = True, self.argument_values(call, call.args[0])
        default_policy = self.bounded(default, family) if supplied else False
        if family != 'httpx' and default_policy is True:
            return True
        fields = ('connect', 'read', 'write', 'pool') if family == 'httpx' else (
            ('connect', 'sock_read') if family == 'aiohttp' else ('connect', 'read'))
        if family == 'httpx' and not supplied and not all(self.option(call, field)[0] for field in fields):
            # HTTPX rejects an omitted default unless all four phases are
            # configured. An invalid constructor does not create a client
            # whose requests can be proved to have an unbounded timeout.
            return None
        policies = []
        for field in fields:
            present, values = self.option(call, field)
            policies.append(self.option_policy(values, family, default_policy) if present else default_policy)
        return _join_policy(policies)

    def policy(self, call, family, inherited, *, constructor=False):
        present, values = self.option(call, 'timeout')
        if not present and family == 'urllib.request' and (len(call.args) >= 3
                or any(isinstance(arg, ast.Starred) for arg in call.args)):
            present = True
            values = (UNKNOWN if any(isinstance(arg, ast.Starred) for arg in call.args[:3])
                      else self.argument_values(call, call.args[2]))
        if not present:
            return inherited
        if constructor and family == 'aiohttp':
            # ClientSession(None) uses DEFAULT_TIMEOUT. A request with None
            # instead creates ClientTimeout(total=None) and disables it.
            values = frozenset(_Value('timeout', family, True)
                               if value.kind == 'literal' and value.data is None
                               else value if value.kind in {'timeout', 'missing'} else _Value('unknown')
                               for value in values)
        return self.option_policy(values, family, inherited)

    def call_result(self, node, callees):
        results = set()
        for callee in callees:
            if callee.kind == 'method':
                client = callee.data
                methods = URLLIB3_METHODS if client.name == 'urllib3' else HTTP_METHODS
                if callee.name in methods:
                    inherited = self.client_policies.get(client, None)
                    if self.policy(node, client.name, inherited) is False:
                        self.remember_issue(node.lineno)
                results.update(UNKNOWN)
                continue
            name = callee.name if callee.kind == 'native' else ''
            if name in TIMEOUT_CONSTRUCTORS:
                family = TIMEOUT_CONSTRUCTORS[name]
                results.add(_Value('timeout', family, self.timeout_object(node, family)))
            elif name in CLIENT_CONSTRUCTORS:
                family = CLIENT_CONSTRUCTORS[name]
                policy = self.policy(node, family, family in {'httpx', 'aiohttp'}, constructor=True)
                client = _Value('client', family, (node.lineno, node.col_offset))
                self.client_policies[client] = policy
                results.add(client)
                if policy is False and family != 'requests':
                    self.remember_issue(node.lineno)
            else:
                owner, _, method = name.rpartition('.')
                family = None
                if owner in {'requests', 'requests.api', 'httpx'} and method in HTTP_METHODS | {'stream'}:
                    family = 'requests' if owner.startswith('requests') else 'httpx'
                elif name == 'urllib.request.urlopen':
                    family = 'urllib.request'
                elif name in {'urllib3.request', 'aiohttp.request'}:
                    family = owner
                if family and self.policy(node, family, family in {'httpx', 'aiohttp'}) is False:
                    self.remember_issue(node.lineno)
                results.update(UNKNOWN)
        return frozenset(results) or UNKNOWN

    def bind(self, target, values):
        if isinstance(target, ast.Name):
            self.bindings[target.id] = values
        elif isinstance(target, (ast.Tuple, ast.List)):
            sequence = next(iter(values)) if len(values) == 1 else None
            elements = (sequence.data if sequence and sequence.kind == 'sequence'
                        and len(sequence.data) == len(target.elts) else (UNKNOWN,) * len(target.elts))
            for child, item in zip(target.elts, elements):
                self.bind(child, item)
        elif isinstance(target, ast.Attribute):
            owners = self.values(target.value)
            for owner in owners:
                if owner.kind == 'client' and target.attr == 'timeout' and owner.name == 'httpx':
                    policy = self.bounded(values, owner.name)
                    self.client_policies[owner] = (policy if len(owners) == 1 else
                                                   _join_policy((self.client_policies.get(owner), policy)))
                elif owner.kind == 'client' and target.attr in HTTP_METHODS | URLLIB3_METHODS:
                    key = (owner, target.attr)
                    previous = self.member_overrides.get(key, self.member_default(key))
                    self.member_overrides[key] = values if len(owners) == 1 else previous | values
                elif owner.kind == 'native':
                    key = f'{owner.name}.{target.attr}'
                    previous = self.member_overrides.get(key, self.member_default(key))
                    self.member_overrides[key] = values if len(owners) == 1 else previous | values

    @staticmethod
    def member_default(key):
        return frozenset({_Value('method', key[1], key[0]) if isinstance(key, tuple)
                          else _Value('native', key)})

    def visit_target(self, target):
        if isinstance(target, ast.Attribute):
            self.visit(target.value)
        elif isinstance(target, ast.Subscript):
            self.visit(target.value)
            self.visit(target.slice)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.visit_target(child)

    def visit_Assign(self, node):
        self.visit(node.value)
        value = self.values(node.value)
        for target in node.targets:
            self.visit_target(target)
            self.bind(target, value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.visit_target(node.target)
            self.bind(node.target, self.values(node.value))

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.bind(node.target, self.values(node.value))

    def visit_AugAssign(self, node):
        self.visit_target(node.target)
        self.visit(node.value)
        self.bind(node.target, UNKNOWN)

    def visit_Delete(self, node):
        for target in node.targets:
            self.visit_target(target)
            self.bind(target, UNKNOWN)

    def snapshot(self):
        return self.bindings.copy(), self.client_policies.copy(), self.member_overrides.copy()

    def restore(self, state):
        self.bindings, self.client_policies, self.member_overrides = (part.copy() for part in state)

    def merge(self, left, right):
        self.bindings = {name: left[0].get(name, UNKNOWN) | right[0].get(name, UNKNOWN)
                         for name in left[0].keys() | right[0].keys()}
        self.client_policies = {client: _join_policy((left[1].get(client), right[1].get(client)))
                                for client in left[1].keys() | right[1].keys()}
        self.member_overrides = {name: left[2].get(name, self.member_default(name))
                                      | right[2].get(name, self.member_default(name))
                                 for name in left[2].keys() | right[2].keys()}

    def visit_If(self, node):
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            for statement in node.body if node.test.value else node.orelse:
                self.visit(statement)
            return
        before = self.snapshot()
        for statement in node.body:
            self.visit(statement)
        left = self.snapshot()
        self.restore(before)
        for statement in node.orelse:
            self.visit(statement)
        self.merge(left, self.snapshot())

    def visit_IfExp(self, node):
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            selected = node.body if node.test.value else node.orelse
            self.visit(selected)
            self.call_results[id(node)] = self.values(selected)
            return
        before = self.snapshot()
        self.visit(node.body)
        left_values = self.values(node.body)
        left = self.snapshot()
        self.restore(before)
        self.visit(node.orelse)
        self.call_results[id(node)] = left_values | self.values(node.orelse)
        self.merge(left, self.snapshot())

    def visit_BoolOp(self, node):
        # A later operand may not execute. Its rebinding must not erase the
        # possible earlier client policy at a following request.
        self.visit(node.values[0])
        pending = self.values(node.values[0])
        completed = frozenset()
        for expression in node.values[1:]:
            stopped, continuing = set(), set()
            for value in pending:
                truth = bool(value.data) if value.kind in {'literal', 'sequence', 'mapping'} else None
                stop = (not truth if isinstance(node.op, ast.And) else truth) if truth is not None else None
                if stop is not False:
                    stopped.add(value)
                if stop is not True:
                    continuing.add(value)
            completed |= frozenset(stopped)
            if not continuing:
                pending = frozenset()
                break
            before = self.snapshot()
            self.visit(expression)
            pending = self.values(expression)
            if stopped:
                self.merge(before, self.snapshot())
        self.call_results[id(node)] = completed | pending

    def visit_Try(self, node):
        exceptional = self.snapshot()
        for statement in node.body:
            self.visit(statement)
            after = self.snapshot()
            self.merge(exceptional, after)
            exceptional = self.snapshot()
            self.restore(after)
        for statement in node.orelse:
            self.visit(statement)
        completed = self.snapshot()
        for handler in node.handlers:
            self.restore(exceptional)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self.bindings[handler.name] = UNKNOWN
            for statement in handler.body:
                self.visit(statement)
            if handler.name:
                self.bindings[handler.name] = UNKNOWN
            self.merge(completed, self.snapshot())
            completed = self.snapshot()
        self.restore(completed)
        for statement in node.finalbody:
            self.visit(statement)

    visit_TryStar = visit_Try

    def visit_For(self, node):
        self.visit(node.iter)
        before = self.snapshot()
        self.bind(node.target, UNKNOWN)
        for statement in node.body:
            self.visit(statement)
        self.merge(before, self.snapshot())
        for statement in node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        before = self.snapshot()
        for statement in node.body:
            self.visit(statement)
        self.merge(before, self.snapshot())
        for statement in node.orelse:
            self.visit(statement)

    def visit_FunctionDef(self, node):
        for expression in (*node.decorator_list, *node.args.defaults,
                           *(value for value in node.args.kw_defaults if value is not None)):
            self.visit(expression)
        self.bindings[node.name] = UNKNOWN
        outer = self.snapshot()
        enclosing = self.class_enclosing
        if enclosing is not None:
            self.restore(enclosing)
        self.class_enclosing = None
        locals_ = _LocalNames()
        for statement in node.body:
            locals_.visit(statement)
        for name in locals_.names - locals_.external:
            self.bindings[name] = UNKNOWN
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                     *((node.args.vararg,) if node.args.vararg else ()),
                     *((node.args.kwarg,) if node.args.kwarg else ()))
        for argument in arguments:
            self.bindings[argument.arg] = UNKNOWN
        for statement in node.body:
            self.visit(statement)
        self.restore(outer)
        self.class_enclosing = enclosing

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expression in (*node.decorator_list, *node.bases, *(keyword.value for keyword in node.keywords)):
            self.visit(expression)
        self.bindings[node.name] = UNKNOWN
        outer, enclosing = self.snapshot(), self.class_enclosing
        self.class_enclosing = enclosing if enclosing is not None else outer
        for statement in node.body:
            self.visit(statement)
        self.restore(outer)
        self.class_enclosing = enclosing

    def visit_Lambda(self, node):
        outer = self.snapshot()
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.bindings[argument.arg] = UNKNOWN
        self.visit(node.body)
        self.restore(outer)

    def visit_ListComp(self, node):
        outer = self.snapshot()
        for generator in node.generators:
            self.visit(generator.iter)
            self.bind(generator.target, UNKNOWN)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.restore(outer)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_With(self, node):
        self.visit_with_like(node)

    def visit_AsyncWith(self, node):
        self.visit_with_like(node)

    def visit_with_like(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.bind(item.optional_vars, self.values(item.context_expr))
        for stmt in node.body:
            self.visit(stmt)

    def visit_Call(self, node):
        self.visit(node.func)
        callees = self.values(node.func)
        captured = {}
        for argument in node.args:
            self.visit(argument)
            captured[id(argument)] = self.values(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)
            captured[id(keyword.value)] = self.values(keyword.value)
        self.call_inputs[id(node)] = captured
        self.call_results[id(node)] = self.call_result(node, callees)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions("python")
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        analyzer = HttpTimeoutAnalyzer(text.splitlines(), suppressions.index(path, text))
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
