"""Bounded Elixir resource obligations for actual bindings and exits.

The request-flow frontend already owns Elixir tokens, immutable values,
matching, lexical scopes, local callbacks and selected same-module calls. This
analyzer reuses those semantics, adding try/after syntax and a resource state
carried alongside each path. A cleanup consumes only the object passed to it.
Unknown ownership transfers and exhausted analysis remain explicit errors.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

from ubs_core.analyzers.taint_elixir_traversal import (
    ElixirEngine, ElixirSyntaxError, Expr, FlowState, Parser, Value,
)
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit, Budget


RESOURCE_RULES = {
    'file': ('ex.io.file-open-unmatched', 'elixir.io',
             'File handle is not closed on every exit'),
    'port': ('ex.io.port-open-unmatched', 'elixir.io',
             'Port is not closed on every exit'),
    'task': ('ex.otp.task-async-unawaited', 'elixir.process-otp',
             'Task result or monitor is not handled on every exit'),
}
REPLACED_RULES = frozenset(spec[0] for spec in RESOURCE_RULES.values())
_RESOURCE = 'lifecycle.resource'
_EXIT = ('lifecycle.exit',)


class LifecycleParser(Parser):
    """Add selected try/after to the shared callback grammar."""

    def expression(self, minimum=0, bare=True):
        self.newlines()
        if self.current.text != 'try':
            return super().expression(minimum, bare)
        self.depth += 1
        if self.depth > 120:
            raise AnalysisLimit('Elixir lifecycle syntax nesting limit exceeded; analysis is incomplete')
        token = self.take()
        try:
            self.require('do')
            body = self.block(frozenset({'after', 'rescue', 'catch', 'else', 'end'}))
            if self.current.text in {'rescue', 'catch', 'else'}:
                raise ElixirSyntaxError(
                    f'Elixir try/{self.current.text} needs additional lifecycle semantics at line '
                    f'{self.current.line}; analysis is incomplete')
            finalizer = self.block(frozenset({'end'})) if self.accept('after') else Expr('block', token)
            self.require('end')
            return Expr('try', token, args=(body, finalizer))
        finally:
            self.depth -= 1


@dataclass(frozen=True)
class Acquisition:
    family: str
    line: int
    col: int
    call: str


class ElixirLifecycleEngine(ElixirEngine):
    """Finite per-path ownership; immutable aliases retain allocation identity."""

    def __init__(self, path: Path, text: str, budget: Budget | None = None,
                 families=frozenset(RESOURCE_RULES)):
        super().__init__(path, text, 'lifecycle', budget)
        self.families = families
        self.acquisitions: dict[tuple, Acquisition] = {}
        self.binding_names: dict[tuple, str] = {}
        self.leaks: dict[tuple, dict] = {}
        self.sequence_depth = 0
        self.worker_depth = 0

    @staticmethod
    def resource_key(identity):
        return (_RESOURCE, *identity)

    @staticmethod
    def terminated(state):
        return bool(state.checks.get(_EXIT))

    @staticmethod
    def exception(state):
        return next(iter(state.checks.get(_EXIT, ())), ('raise', Value()))

    def terminate(self, state, kind='raise', value=None):
        result = state.copy()
        result.checks[_EXIT] = frozenset({(kind, value or Value())})
        return result, Value('exception', kind)

    def opened(self, state):
        return {key[1:] for key, status in state.checks.items()
                if key and key[0] == _RESOURCE and 'open' in status}

    def acquire(self, expr, state, family, call):
        if family not in self.families:
            return state, Value('parameter', identity=self.identity(expr))
        identity = self.identity(expr)
        if identity in self.opened(state):
            raise AnalysisLimit('Repeated Elixir resource allocation requires additional ownership states; '
                                'analysis is incomplete')
        self.acquisitions[identity] = Acquisition(family, expr.token.line, expr.token.col, call)
        after = state.copy()
        after.checks[self.resource_key(identity)] = frozenset({'open'})
        return after, Value('resource', family, identity=identity)

    def close(self, state, value, family):
        after = state.copy()
        if value.kind == 'resource' and value.literal == family:
            after.checks[self.resource_key(value.identity)] = frozenset({'closed'})
        return after

    def references(self, value):
        """Find owned handles inside selected immutable values, without escaping them."""
        if value.kind == 'resource':
            return {value.identity}
        if value.kind == 'callback':
            closure = self.closures.get(value.identity)
            return set().union(*(self.references(item) for _, item in closure[1])) if closure else set()
        if value.kind == 'map':
            return set().union(*(self.references(item) for _, item in value.items))
        if value.kind in {'tuple', 'list', 'pair', 'map_pair', 'set'}:
            return set().union(*(self.references(item) for item in value.items))
        return set()

    def transferred(self, value, state):
        if value.kind == 'resource':
            return {value.identity}
        if value.kind == 'tuple':
            return set().union(*(self.transferred(item, state) for item in value.items))
        if self.references(value) & self.opened(state):
            raise ElixirSyntaxError('Elixir callback or collection ownership transfer needs additional '
                                    'lifecycle semantics; analysis is incomplete')
        return set()

    def observe(self, state, value, inherited=frozenset(), transfer=True):
        returned = self.transferred(value, state) if transfer and not self.terminated(state) else set()
        for identity in sorted(self.opened(state) - set(inherited) - returned, key=repr):
            allocation = self.acquisitions[identity]
            if self.worker_depth and allocation.family in {'file', 'port'}:
                # Ordinary file server processes and ports terminate with the
                # Task process which opened them. A helper return is not a
                # process exit, but the enclosing selected worker will exit.
                continue
            rule, category, message = RESOURCE_RULES[allocation.family]
            binding = self.binding_names.get(identity, 'unbound result')
            key = rule, allocation.line, allocation.col
            self.leaks[key] = {
                'rule': rule, 'category_id': category, 'path': self.path,
                'line': allocation.line, 'col': allocation.col,
                'severity': 'warning', 'suppressed': False,
                'message': f'{message}: {binding} ({allocation.call})',
                'extras': {'resource': allocation.family, 'binding': binding,
                           'exit': self.exception(state)[0] if self.terminated(state) else 'return'},
            }

    def sequence(self, block, initial):
        # The inherited worklist only has normal expressions. Keep terminated
        # states until the enclosing try/after or function exit consumes them.
        top_level = self.sequence_depth == 0 and not self.call_stack and not self.callback_depth
        self.sequence_depth += 1
        pending = deque([(0, initial, Value('nil'))])
        outputs, visited = [], set()
        try:
            while pending:
                self.budget.spend()
                index, state, value = pending.popleft()
                key = (index, tuple(sorted(state.bindings.items())), frozenset(state.checks.items()), value)
                if key in visited:
                    continue
                visited.add(key)
                if self.terminated(state) or index == len(block.args):
                    outputs.append((state, value))
                    continue
                for successor, returned in self.evaluate(block.args[index], state):
                    pending.append((index + 1, successor, returned))
                if len(pending) > 512:
                    raise AnalysisLimit('Elixir lifecycle worklist limit exceeded; analysis is incomplete')
            results = self.outcomes(outputs)
            if top_level:
                for after, value in results:
                    self.observe(after, value, transfer=False)
            return results
        finally:
            self.sequence_depth -= 1

    def seed(self, pattern):
        # A function argument is borrowed, not a new locally acquired resource.
        return Value('parameter', identity=(self.owner, 'parameter', pattern.token.offset))

    def entry_arguments(self, function):
        return tuple(self.seed(pattern) for pattern in function.parameters)

    def analyze(self):
        pending, names = [self.tokens], set()
        while pending:
            for token in pending.pop():
                if token.kind == 'id':
                    names.add(token.text)
                pending.extend(token.interpolations)
        modules = {'File' if family == 'file' else 'Port' for family in self.families & {'file', 'port'}}
        relevant = {'open', 'open!'} if names & modules else set()
        if 'task' in self.families and 'Task' in names:
            relevant |= {'async', 'async_nolink', 'start', 'start_link', 'start_child'}
        if not names & relevant:
            return self.leaks
        program = LifecycleParser(self.tokens, self.budget).block()
        self.register_block(program)
        for key, clauses in tuple(self.functions.items()):
            if not any(function.public for function in clauses):
                continue
            self.owner, self.context = key[0], ('entry', key[1], key[2])
            for function in clauses:
                if function.public and key[2] == len(function.parameters):
                    self.invoke(key, self.entry_arguments(function), FlowState(),
                                Expr('name', function.token, function.name))
        return self.leaks

    def invoke(self, key, args, state, expr):
        inherited = self.opened(state)
        results = super().invoke(key, args, state, expr)
        for after, value in results:
            self.observe(after, value, inherited)
        return results

    def match(self, pattern, value, state, bound=None):
        if pattern.kind == 'name' and pattern.value != '_' and value.kind == 'resource':
            self.binding_names.setdefault(value.identity, pattern.value)
        return super().match(pattern, value, state, bound)

    def select_clauses(self, clauses, value, state):
        pending, results = [state], []
        for pattern, body in clauses:
            following = []
            for candidate in pending:
                matches, can_fail = self.match(pattern, value, candidate)
                for selected in matches:
                    results.extend(self.sequence(body, selected))
                if can_fail:
                    following.append(candidate)
            pending = following
        results.extend(self.terminate(candidate) for candidate in pending)
        return self.outcomes(results)

    def binary(self, expr, state):
        if expr.value != '=':
            return super().binary(expr, state)
        results = []
        for after, value in self.evaluate(expr.args[1], state):
            if self.terminated(after):
                results.append((after, value))
                continue
            matches, can_fail = self.match(expr.args[0], value, after)
            results.extend((matched, value) for matched in matches)
            if can_fail:
                results.append(self.terminate(after))
        return self.outcomes(results)

    def _refine(self, predicate, state, truth):
        if predicate.kind in {'resource', 'callback', 'module'}:
            return [state.copy()] if truth else []
        if predicate.kind == 'test' and predicate.test[0] in {'==', '==='}:
            first, second = predicate.test[1:]
            definite = {'nil', 'bool', 'string', 'atom', 'number', 'resource',
                        'callback', 'module', 'tuple', 'list', 'map'}
            if first.kind in definite and second.kind in definite and first.kind != second.kind:
                return [] if truth else [state.copy()]
            if first.kind == second.kind == 'nil':
                return [state.copy()] if truth else []
            if first.kind == second.kind == 'resource':
                return [state.copy()] if (first.identity == second.identity) == truth else []
        return super()._refine(predicate, state, truth)

    def evaluate(self, expr, state):
        if self.terminated(state):
            return [(state, Value('exception', self.exception(state)[0]))]
        if expr.kind == 'try':
            outputs = []
            body, finalizer = expr.args
            for after, value in self.sequence(body, state.copy()):
                saved_exit = after.checks.get(_EXIT)
                final_state = FlowState(dict(state.bindings), dict(after.checks))
                final_state.checks.pop(_EXIT, None)
                for final, _ in self.sequence(finalizer, final_state):
                    if not self.terminated(final) and saved_exit:
                        final.checks[_EXIT] = saved_exit
                    outputs.append((FlowState(dict(state.bindings), final.checks), value))
            return self.outcomes(outputs)
        if expr.kind == 'cond':
            pending, outputs = [state], []
            for condition, body in expr.args:
                following = []
                for candidate in pending:
                    for after, value in self.evaluate(condition, candidate):
                        for selected in self.refine(value, after, True):
                            for final, result in self.sequence(body, selected):
                                outputs.append((FlowState(dict(state.bindings), final.checks), result))
                        following.extend(self.refine(value, after, False))
                pending = following
            outputs.extend(self.terminate(candidate) for candidate in pending)
            return self.outcomes(outputs)
        return super().evaluate(expr, state)

    def callback_unmatched(self, state):
        return [self.terminate(state)]

    def invoke_callback(self, expr, callback, args, state):
        inherited = self.opened(state)
        results = super().invoke_callback(expr, callback, args, state)
        for after, value in results:
            self.observe(after, value, inherited)
        return results

    def task_body(self, expr, module, args, state):
        """The worker's resources do not become caller cleanup effects."""
        self.worker_depth += 1
        try:
            return self._task_body(expr, module, args, state)
        finally:
            self.worker_depth -= 1

    def _task_body(self, expr, module, args, state):
        body_args = args[1:] if module == 'Task.Supervisor' else args
        callback = body_args[0] if body_args else Value()
        if callback.kind != 'callback':
            if len(body_args) in {3, 4} and body_args[0].kind == 'module' and body_args[1].kind == 'atom' and body_args[2].kind == 'list':
                if any(self.references(item) & self.opened(state) for item in body_args[2].items):
                    raise ElixirSyntaxError(f'Elixir resource transfer into a task at line '
                                            f'{expr.token.line}; analysis is incomplete')
                key = (str(body_args[0].literal), str(body_args[1].literal), len(body_args[2].items))
                if key in self.functions:
                    for after, result in self.invoke(key, body_args[2].items, FlowState(), expr):
                        if self.references(result) & self.opened(after):
                            raise ElixirSyntaxError(f'Elixir resource returned across a task process at line '
                                                    f'{expr.token.line}; analysis is incomplete')
                return
            raise ElixirSyntaxError(f'Unresolved Elixir task function at line '
                                    f'{expr.token.line}; analysis is incomplete')
        if self.references(callback) & self.opened(state):
            raise ElixirSyntaxError(f'Elixir resource captured across a task process at line '
                                    f'{expr.token.line}; analysis is incomplete')
        for after, result in self.invoke_callback(expr, callback, (), FlowState()):
            if self.references(result) & self.opened(after):
                raise ElixirSyntaxError(f'Elixir resource returned across a task process at line '
                                        f'{expr.token.line}; analysis is incomplete')

    def task_call(self, expr, canonical, args, state):
        name = canonical.rsplit('.', 1)[-1]
        if name in {'async', 'async_nolink', 'start', 'start_link', 'start_child'}:
            module = canonical.rsplit('.', 1)[0]
            allowed = {2, 3, 4, 5} if module == 'Task.Supervisor' else {1, 3}
            if len(args) not in allowed:
                raise ElixirSyntaxError(f'Unsupported {canonical} arity at line '
                                        f'{expr.token.line}; analysis is incomplete')
            self.task_body(expr, module, args, state)
            if name in {'async', 'async_nolink'}:
                return [self.acquire(expr, state, 'task', canonical)]
            return [(state, Value('tuple', items=(Value('atom', 'ok'), Value('parameter'))))]
        allowed = {1} if name == 'ignore' else {1, 2}
        if len(args) not in allowed:
            raise ElixirSyntaxError(f'Unsupported {canonical} arity at line '
                                    f'{expr.token.line}; analysis is incomplete')
        handle = args[0]
        if handle.kind != 'resource' and self.references(handle) & self.opened(state):
            raise ElixirSyntaxError(f'{canonical} receives an unresolved task container at line '
                                    f'{expr.token.line}; analysis is incomplete')
        handled = self.close(state, handle, 'task')
        if name == 'await':
            return [(handled, Value(identity=self.identity(expr)))]
        success = Value('tuple', items=(Value('atom', 'ok'), Value(identity=self.identity(expr))))
        stopped = Value('tuple', items=(Value('atom', 'exit'), Value()))
        if name == 'ignore':
            return [(handled, success), (handled.copy(), stopped), (handled.copy(), Value('nil'))]
        # yield returning nil leaves the reply and monitor outstanding. Only
        # its completed outcomes, or a shutdown fallback, discharge the task.
        outcomes = [(handled, success), (handled.copy(), stopped)]
        if name != 'yield' or len(args) == 1 or args[1].kind != 'atom' or args[1].literal != 'infinity':
            timeout = state.copy() if name == 'yield' else handled.copy()
            outcomes.append((timeout, Value('nil')))
        return outcomes

    def file_modes(self, expr, args, callback):
        modes = args[1] if len(args) > 1 and (len(args) > 2 or callback is None) else Value('list')
        if modes.kind != 'list':
            raise ElixirSyntaxError(f'Unresolved Elixir file modes at line '
                                    f'{expr.token.line}; analysis is incomplete')
        atoms = {'append', 'binary', 'charlist', 'compressed', 'exclusive', 'raw',
                 'read', 'read_ahead', 'sync', 'utf8', 'write', 'ram'}
        for mode in modes.items:
            if mode.kind == 'atom':
                name, allowed = mode.literal, atoms
            elif mode.kind == 'pair':
                name, allowed = mode.literal, {'encoding', 'read_ahead'}
            elif mode.kind == 'tuple' and mode.items and mode.items[0].kind == 'atom':
                name, allowed = mode.items[0].literal, {'encoding', 'read_ahead'}
            else:
                raise ElixirSyntaxError(f'Unresolved Elixir file mode at line '
                                        f'{expr.token.line}; analysis is incomplete')
            if name == 'delayed_write':
                raise ElixirSyntaxError(f'Elixir delayed-write close retry semantics at line '
                                        f'{expr.token.line}; analysis is incomplete')
            if name not in allowed or (self.worker_depth and name in {'raw', 'ram'}):
                raise ElixirSyntaxError(f'Elixir file mode {name!r} needs additional lifecycle semantics '
                                        f'at line {expr.token.line}; analysis is incomplete')

    def builtin(self, expr, module, name, args, state, qualified):
        if self.terminated(state):
            return [(state, Value('exception', self.exception(state)[0]))]
        canonical = f'{module}.{name}' if qualified else name
        if canonical in {'raise', 'throw', 'exit', 'Kernel.raise', 'Kernel.throw', 'Kernel.exit'}:
            return [self.terminate(state, name, args[0] if args else Value())]
        if canonical in {'Task.async', 'Task.Supervisor.async', 'Task.Supervisor.async_nolink',
                         'Task.start', 'Task.start_link', 'Task.Supervisor.start_child',
                         'Task.await', 'Task.yield', 'Task.shutdown', 'Task.ignore'}:
            return self.task_call(expr, canonical, args, state)
        if canonical in {'File.open', 'File.open!'}:
            if not 1 <= len(args) <= 3:
                raise ElixirSyntaxError(f'Unsupported {canonical} arity at line '
                                        f'{expr.token.line}; analysis is incomplete')
            callback = args[-1] if len(args) >= 2 and args[-1].kind == 'callback' else None
            if (len(args) == 3 and callback is None) or (len(args) == 2 and callback is None and args[1].kind != 'list'):
                raise ElixirSyntaxError(f'Unresolved {canonical} modes or callback at line '
                                        f'{expr.token.line}; analysis is incomplete')
            self.file_modes(expr, args, callback)
            after, handle = self.acquire(expr, state, 'file', canonical)
            outcomes = [(after, handle)]
            if callback is not None:
                outcomes = [(self.close(final, handle, 'file'), value)
                            for final, value in self.invoke_callback(expr, callback, (handle,), after)]
            if name == 'open':
                success = [(final, value if self.terminated(final) else
                            Value('tuple', items=(Value('atom', 'ok'), value)))
                           for final, value in outcomes]
                return [*success, (state.copy(), Value('tuple', items=(Value('atom', 'error'), Value())))]
            return outcomes
        if canonical == 'Port.open':
            if len(args) != 2:
                raise ElixirSyntaxError(f'Unsupported Port.open arity at line '
                                        f'{expr.token.line}; analysis is incomplete')
            return [self.acquire(expr, state, 'port', canonical)]
        if canonical in {'File.close', 'Port.close'}:
            if len(args) != 1:
                raise ElixirSyntaxError(f'Unsupported {canonical} arity at line '
                                        f'{expr.token.line}; analysis is incomplete')
            family = 'file' if module == 'File' else 'port'
            if args[0].kind != 'resource' and self.references(args[0]) & self.opened(state):
                raise ElixirSyntaxError(f'{canonical} receives an unresolved resource container at line '
                                        f'{expr.token.line}; analysis is incomplete')
            handled = self.close(state, args[0], family)
            if family == 'port':
                return [(handled, Value('bool', True))]
            return [(handled, Value('atom', 'ok')),
                    (handled.copy(), Value('tuple', items=(Value('atom', 'error'), Value())))]
        if canonical == 'IO.inspect' and args:
            return [(state, args[0])]
        if module == 'IO' and qualified and name in {'read', 'binread', 'write', 'binwrite', 'gets', 'puts'}:
            return [(state, Value(identity=self.identity(expr)))]
        if canonical in {'File.stream!', 'File.read', 'File.read!', 'File.write', 'File.write!',
                         'File.stat', 'File.stat!', 'Port.command', 'Port.info', 'Port.connect'}:
            if canonical == 'Port.connect' and any(self.references(arg) for arg in args):
                raise ElixirSyntaxError(f'Elixir port process-ownership transfer at line '
                                        f'{expr.token.line}; analysis is incomplete')
            return [(state, Value(identity=self.identity(expr)))]
        if canonical in {'Map.get', 'Map.fetch', 'Map.fetch!', 'Keyword.get', 'Keyword.fetch',
                         'Keyword.fetch!', 'List.first', 'hd', 'Kernel.hd', 'elem', 'Kernel.elem',
                         'get_in', 'is_binary', 'is_map', 'is_list', 'is_atom', 'is_integer',
                         'is_nil', 'is_tuple', 'Enum.each', 'Enum.map'}:
            return super().builtin(expr, module, name, args, state, qualified)
        if any(self.references(arg) & self.opened(state) for arg in args):
            raise ElixirSyntaxError(f'Unresolved Elixir resource or callback call {canonical} at line '
                                    f'{expr.token.line}; analysis is incomplete')
        return super().builtin(expr, module, name, args, state, qualified)


def scan_file_findings(path: Path, budget: Budget | None = None,
                       families=frozenset(RESOURCE_RULES)):
    text = path.read_text(encoding='utf-8')
    engine = ElixirLifecycleEngine(path, text, budget, families)
    suppressions = build_index(text, lang='elixir')
    incomplete = None
    try:
        findings = engine.analyze()
    except ValueError as exc:
        findings, incomplete = engine.leaks, exc
    for key, finding in sorted(findings.items()):
        rule, line, _ = key
        if not suppressions.is_suppressed(line, rule):
            yield finding
    if incomplete is not None:
        raise incomplete
