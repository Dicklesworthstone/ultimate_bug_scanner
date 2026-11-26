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
        self.loop_depth = 0
        self.loop_clients = set()
        self.repeated_loop_clients = set()

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
            shape = 'tuple' if isinstance(node, ast.Tuple) else 'list'
            if any(isinstance(item, ast.Starred) for item in node.elts):
                shape = 'expanded'
            return frozenset({_Value('sequence', shape, tuple(self.values(item) for item in node.elts))})
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
                client = self.native_client(node, family)
                if (client in self.repeated_loop_clients and client in self.client_policies
                        and self.client_policies[client] != policy):
                    raise ValueError('Python HTTP configuration loop analysis is incomplete: '
                                     'repeated client allocation has distinct timeout policies')
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

    def native_client(self, node, family):
        client = _Value('client', family, (node.lineno, node.col_offset))
        if self.loop_depth:
            if client in self.loop_clients:
                self.repeated_loop_clients.add(client)
            self.loop_clients.add(client)
        if client in self.repeated_loop_clients and any(
                isinstance(key, tuple) and key[0] == client for key in self.member_overrides):
            raise ValueError('Python HTTP configuration loop analysis is incomplete: '
                             'repeated client allocation has distinct method bindings')
        return client

    def bind(self, target, values):
        if isinstance(target, ast.Name):
            self.bindings[target.id] = values
        elif isinstance(target, (ast.Tuple, ast.List)):
            elements = tuple(frozenset().union(*(
                value.data[index] if value.kind == 'sequence' and value.name != 'expanded'
                and len(value.data) == len(target.elts) else UNKNOWN for value in values)) or UNKNOWN
                for index in range(len(target.elts)))
            for child, item in zip(target.elts, elements):
                self.bind(child, item)
        elif isinstance(target, ast.Attribute):
            owners = self.values(target.value)
            for owner in owners:
                if (owner in self.repeated_loop_clients
                        and target.attr in HTTP_METHODS | URLLIB3_METHODS | {'timeout'}):
                    raise ValueError('Python HTTP configuration loop analysis is incomplete: '
                                     'mutation of a repeated client allocation')
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
        outcomes = self.loop(node)
        self.restore(self.join_states(outcomes.values()))

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        outcomes = self.loop(node)
        self.restore(self.join_states(outcomes.values()))

    def join_states(self, states):
        states = iter(states)
        result = next(states, None)
        if result is None:
            return self.snapshot()
        for state in states:
            self.merge(result, state)
            result = self.snapshot()
        return result

    def join_outcomes(self, *branches):
        result = {}
        for branch in branches:
            for route, state in branch.items():
                result[route] = self.join_states((result[route], state)) if route in result else state
        return result

    def loop_block(self, statements, exceptional=None):
        """Keep abrupt paths separate so they cannot become loop backedges."""
        outcomes = {'normal': self.snapshot()}
        for statement in statements:
            state = outcomes.pop('normal', None)
            if state is None:
                break
            self.restore(state)
            if exceptional is not None:
                exceptional.append(state)
            step = self.loop_statement(statement)
            if exceptional is not None:
                exceptional.extend(step.values())
            outcomes = self.join_outcomes(outcomes, step)
        return outcomes

    def loop_statement(self, node):
        if isinstance(node, ast.If):
            self.visit(node.test)
            if isinstance(node.test, ast.Constant):
                return self.loop_block(node.body if node.test.value else node.orelse)
            before = self.snapshot()
            left = self.loop_block(node.body)
            self.restore(before)
            return self.join_outcomes(left, self.loop_block(node.orelse))
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self.loop(node)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.visit(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, self.values(item.context_expr))
            outcomes = self.loop_block(node.body)
            if 'raise' in outcomes:
                # __exit__/__aexit__ may suppress an exception. Preserve
                # both possibilities; other abrupt routes stay abrupt.
                outcomes = self.join_outcomes(outcomes, {'normal': outcomes['raise']})
            return outcomes
        if isinstance(node, (ast.Try, ast.TryStar)):
            exceptional = [self.snapshot()]
            outcomes = self.loop_block(node.body, exceptional)
            completed = outcomes.pop('normal', None)
            if completed is not None:
                self.restore(completed)
                outcomes = self.join_outcomes(outcomes, self.loop_block(node.orelse))
            for handler in node.handlers:
                self.restore(self.join_states(exceptional))
                if handler.type is not None:
                    self.visit(handler.type)
                if handler.name:
                    self.bindings[handler.name] = UNKNOWN
                branch = self.loop_block(handler.body)
                if handler.name:
                    for state in branch.values():
                        state[0][handler.name] = UNKNOWN
                outcomes = self.join_outcomes(outcomes, branch)
            if not node.finalbody:
                return outcomes
            finalized = {}
            for route, state in outcomes.items():
                self.restore(state)
                final = self.loop_block(node.finalbody)
                normal = final.pop('normal', None)
                if normal is not None:
                    final = self.join_outcomes(final, {route: normal})
                finalized = self.join_outcomes(finalized, final)
            return finalized
        for kind, route in ((ast.Break, 'break'), (ast.Continue, 'continue'),
                            (ast.Return, 'return'), (ast.Raise, 'raise')):
            if isinstance(node, kind):
                self.generic_visit(node)
                return {route: self.snapshot()}
        self.visit(node)
        return {'normal': self.snapshot()}

    @staticmethod
    def native_loop_state(state):
        # Most project loops have no native HTTP facts. Their unrelated
        # container construction must not pay for a configuration fixpoint.
        pending = [value for values in state[0].values() for value in values]
        pending.extend(value for values in state[2].values() for value in values)
        seen = set()
        while pending:
            value = pending.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            if value.kind in {'client', 'method', 'timeout'}:
                return True
            if value.kind == 'native' and value.name.split('.')[0] in {
                    'requests', 'httpx', 'aiohttp', 'urllib3', 'urllib', 'ssl'}:
                return True
            if value.kind == 'sequence':
                pending.extend(item for values in value.data for item in values)
            elif value.kind == 'mapping':
                pending.extend(item for _, values in value.data for item in values)
        return bool(state[1])

    @staticmethod
    def check_loop_state(state):
        # Recursive containers and synthesized attribute chains have no
        # finite native identity proof. Refuse explicitly, never truncate
        # them and certify the remaining configuration as clean.
        pending = [(value, 0) for values in state[0].values() for value in values]
        pending.extend((value, 0) for values in state[2].values() for value in values)
        seen = {}
        while pending:
            value, depth = pending.pop()
            if depth > 12 or len(seen) > 4096:
                raise ValueError('Python HTTP configuration loop analysis is incomplete: value growth')
            if seen.get(id(value), -1) >= depth:
                continue
            seen[id(value)] = depth
            if value.kind == 'sequence':
                pending.extend((item, depth + 1) for values in value.data for item in values)
            elif value.kind == 'mapping':
                pending.extend((item, depth + 1) for _, values in value.data for item in values)

    def loop(self, node):
        self.loop_depth += 1
        try:
            return self.loop_transfer(node)
        finally:
            self.loop_depth -= 1

    def loop_transfer(self, node):
        is_for = isinstance(node, (ast.For, ast.AsyncFor))
        count = None
        elements = None
        if is_for:
            self.visit(node.iter)
            values = self.values(node.iter)
            sequence = next(iter(values)) if len(values) == 1 else None
            if (sequence is not None and sequence.kind == 'sequence'
                    and (sequence.name == 'tuple'
                         or sequence.name == 'list' and isinstance(node.iter, ast.List))):
                # Tuple length is immutable. A direct list literal has no
                # published alias; an aliased list may grow during iteration.
                elements, count = sequence.data, len(sequence.data)
            elif (isinstance(node.iter, ast.Call) and not node.iter.keywords
                  and isinstance(node.iter.func, ast.Name) and node.iter.func.id == 'range'
                  and 'range' not in self.bindings and 1 <= len(node.iter.args) <= 3
                  and all(isinstance(arg, ast.Constant) and isinstance(arg.value, int)
                          for arg in node.iter.args)):
                try:
                    count = len(range(*(arg.value for arg in node.iter.args)))
                except (ValueError, OverflowError):
                    pass
        before = self.snapshot()
        head = before
        exits, exhausted, terminated = [], [], {}
        iteration = 0
        while True:
            self.restore(head)
            if is_for:
                if count is not None and iteration >= count:
                    exhausted.append(head)
                    break
                if count is None:
                    exhausted.append(head)
                self.bind(node.target, elements[iteration] if elements is not None else UNKNOWN)
            else:
                self.visit(node.test)
                truth = bool(node.test.value) if isinstance(node.test, ast.Constant) else None
                if truth is not True:
                    exhausted.append(self.snapshot())
                if truth is False:
                    break
            outcomes = self.loop_block(node.body)
            if 'break' in outcomes:
                exits.append(outcomes.pop('break'))
            backs = [outcomes.pop(route) for route in ('normal', 'continue') if route in outcomes]
            terminated = self.join_outcomes(terminated, outcomes)
            if not backs:
                break
            back = self.join_states(backs)
            iteration += 1
            # Exact short sequences keep order and do not invent a second
            # execution for singleton loops. A stable transfer can skip the
            # remaining iterations of a range without unrolling its size.
            next_head = back if count is not None else self.join_states((head, back))
            native = self.native_loop_state(head) or self.native_loop_state(back)
            if native:
                self.check_loop_state(next_head)
            stable = next_head == head
            if (count is None and stable) or (count is not None and elements is None and stable):
                if is_for:
                    exhausted.append(next_head)
                break
            if not native:
                exhausted.append(self.join_states((before, back)))
                break
            if iteration >= 64:
                raise ValueError('Python HTTP configuration loop analysis is incomplete: fixpoint limit')
            head = next_head
        if exhausted:
            self.restore(self.join_states(exhausted))
            terminated = self.join_outcomes(terminated, self.loop_block(node.orelse))
        if exits:
            terminated = self.join_outcomes(terminated, {'normal': self.join_states(exits)})
        return terminated

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
