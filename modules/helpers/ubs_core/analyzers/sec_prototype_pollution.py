"""Request-derived object merges and property writes.

Use the shared JavaScript lexical/statement parser for bounded local flow.
Safety belongs to the actual receiver or validated key binding, never to a
helper's spelling or a nearby statement. Local key-validator summaries cover
an explicit string/type and complete forbidden-key guard followed by return;
arbitrary sanitizers, dynamic dispatch and deep-merge sanitization are not
certified. Diagnostics retain the existing public rule and suppression policy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.lexer import javascript_lexical_views
from ubs_core.taint_flow import AnalysisLimit, Budget
from ubs_core.analyzers.taint_js import (
    _Parser, _binding_names, _chunks, _declaration_entries, _function_scopes, _pairs, expression_end,
)

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts'}

RULE = "js.security.prototype-pollution"
CATEGORY_ID = "js.security"
SEVERITY = "critical"
MESSAGE = "Request-derived object merge may allow prototype pollution"

SOURCE_RE = re.compile(
    r'\b(?:req|request|ctx|context|event)\.(?:body|query|params|headers|cookies)\b'
    r'|\b(?:req|request)\.json\s*\('
    r'|\b(?:req|request|ctx|context)\.(?:get|header|param|query)\s*\('
    r'|\bsearchParams\.(?:get|getAll|entries)\s*\('
    r'|\bJSON\.parse\s*\(\s*(?:req|request|event)\.body\b',
    re.IGNORECASE,
)
MERGE_SINK_RE = re.compile(
    r'\b(?:Object\.assign|(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|extend)|'
    r'deepmerge|merge|mergeWith|defaultsDeep|extend)\s*\('
)
IDENTIFIER = r'[A-Za-z_$][\w$]*'
CALL_RE = re.compile(r'(?<![\w$])(' + IDENTIFIER + r'(?:\s*\.\s*' + IDENTIFIER + r')*)\s*\(')
BAD_KEYS = frozenset({'__proto__', 'constructor', 'prototype'})


@dataclass(frozen=True)
class _Value:
    tainted: bool = False
    safe_key: bool = False
    ref: int | None = None
    validator: int | None = None
    object_builtin: bool = False


UNKNOWN = _Value()


@dataclass
class _State:
    bindings: dict = field(default_factory=dict)
    constants: set = field(default_factory=set)
    null_refs: set = field(default_factory=set)
    contents: set = field(default_factory=set)
    safe_keys: set = field(default_factory=set)
    object_methods: set = field(default_factory=lambda: {'create', 'assign'})
    allocated_refs: set = field(default_factory=set)

    def copy(self):
        return _State(dict(self.bindings), set(self.constants), set(self.null_refs), set(self.contents),
                      set(self.safe_keys), set(self.object_methods), set(self.allocated_refs))

    def tainted(self, value):
        return value.tainted or value.ref is not None and value.ref in self.contents

    def shallow_tainted(self, value):
        # Nested values do not become property names in a shallow copy. This
        # exemption requires every write to the exact allocation to be safe.
        return self.tainted(value) and value.ref not in self.safe_keys

    def builtin(self, method):
        return 'Object' not in self.bindings and method in self.object_methods

    def invalidate(self):
        # Calls may mutate escaped allocations or captured mutable bindings.
        self.null_refs.clear()
        self.safe_keys.clear()
        for name, value in self.bindings.items():
            if name not in self.constants:
                self.bindings[name] = replace(value, safe_key=False, validator=None)

    def restore(self, saved):
        for name, (old, constant) in saved.items():
            if old is None:
                self.bindings.pop(name, None)
            else:
                self.bindings[name] = old
            self.constants.discard(name)
            if constant:
                self.constants.add(name)


def _join(*branches):
    live = []
    names = set()
    for state in branches:
        if state is not None:
            live.append(state)
            names.update(state.bindings)
    if not live:
        return None
    result = live[0].copy()
    for name in names:
        first = live[0].bindings.get(name, UNKNOWN)
        ref, validator = first.ref, first.validator
        tainted, safe_key, object_builtin = False, True, False
        for state in live:
            value = state.bindings.get(name, UNKNOWN)
            tainted = tainted or state.tainted(value)
            safe_key = safe_key and value.safe_key
            object_builtin = object_builtin or value.object_builtin
            if value.ref != first.ref:
                ref = None
            if value.validator != first.validator:
                validator = None
        result.bindings[name] = _Value(tainted, safe_key, ref, validator, object_builtin)
    for state in live:
        result.constants.intersection_update(state.constants)
        result.null_refs.intersection_update(state.null_refs)
        result.contents.update(state.contents)
        result.safe_keys.intersection_update(state.safe_keys)
        result.object_methods.intersection_update(state.object_methods)
        result.allocated_refs.update(state.allocated_refs)
    return result


def _trim(code, start, end, pairs, text):
    while start < end:
        while start < end and text[start].isspace():
            start += 1
        while start < end and text[end - 1].isspace():
            end -= 1
        if code[start:start + 1] == '(' and pairs.get(start) == end - 1:
            start, end = start + 1, end - 1
        else:
            break
    return start, end


def _literal(raw):
    raw = raw.strip()
    if re.fullmatch(r"'[^'\\\r\n]*'|\"[^\"\\\r\n]*\"", raw):
        return raw[1:-1]
    return None


class _PrototypeFlow:
    def __init__(self, text, code):
        self.text, self.code = text, code
        self.root, self.scopes = _function_scopes(text, code)
        self.budget = Budget()
        self.findings, self.captures, self.exits, self.throws = set(), {}, {}, {}
        self.exceptional_prefixes = []
        for scope in [self.root, *self.scopes]:
            scope.statements = _Parser(scope).sequence(scope.body_start, scope.body_end)
        self.validators = {scope.start for scope in self.scopes if self.is_validator(scope)}

    def guard(self, scope, start, end, truth):
        """A conjunction of required facts, or the false side of their OR.

        Requiring a string prevents user-defined ToPropertyKey conversion from
        returning a forbidden name after strict-equality checks have passed.
        """
        code, pairs = scope.code, _pairs(scope.code, start, end)
        start, end = _trim(code, start, end, pairs, self.text)
        operator = '&&' if truth else '||'
        atoms, cursor, left = [], start, start
        while cursor < end:
            if code[cursor] in '([{' and cursor in pairs:
                cursor = pairs[cursor] + 1
            elif code[cursor:cursor + 2] == operator:
                atoms.append((left, cursor))
                left = cursor = cursor + 2
            else:
                cursor += 1
        atoms.append((left, end))
        names, excluded, string = set(), set(), False
        for left, right in atoms:
            left, right = _trim(code, left, right, pairs, self.text)
            raw = self.text[left:right].strip()
            type_test = re.fullmatch(r'typeof\s+(' + IDENTIFIER + r')\s*(===|!==)\s*([\'\"])string\3', raw)
            if type_test and type_test.group(2) == ('===' if truth else '!=='):
                names.add(type_test.group(1))
                string = True
                continue
            test = re.fullmatch(r'(' + IDENTIFIER + r')\s*(===|!==)\s*([\'\"])([^\'\"\\]*)\3', raw)
            if not test or test.group(2) != ('!==' if truth else '===') or test.group(4) not in BAD_KEYS:
                return None
            names.add(test.group(1))
            excluded.add(test.group(4))
        return next(iter(names)) if len(names) == 1 and string and excluded == BAD_KEYS else None

    def is_validator(self, scope):
        if scope.asynchronous or scope.generator or scope.children or len(scope.params) != 1:
            return False
        names, rest, default, _span = scope.params[0]
        if len(names) != 1 or rest or default is not None or len(scope.statements) != 2:
            return False
        guard, returned = scope.statements
        body = guard.body
        while len(body) == 1 and body[0].kind == 'block':
            body = body[0].body
        return (guard.kind == 'if' and not guard.alternate and len(body) == 1
                and body[0].kind == 'throw'
                and self.guard(scope, guard.start, guard.end, False) == names[0]
                and returned.kind == 'return'
                and self.text[returned.start:returned.end].strip() == names[0])

    def value(self, scope, start, end, state):
        self.budget.spend()
        code, pairs = scope.code, _pairs(scope.code, start, end)
        # Child bodies are masked in the enclosing scope; retain their exact
        # identity rather than treating a reassuring declaration name as proof.
        for child in scope.children:
            if start <= child.start and child.end <= end and not (
                code[start:child.start].strip() or code[child.end:end].strip()
            ):
                return _Value(validator=child.start if child.start in self.validators else None)
        start, end = _trim(code, start, end, pairs, self.text)
        while code[end - 1:end] == '!':
            start, end = _trim(code, start, end - 1, pairs, self.text)
        visible, raw = code[start:end], self.text[start:end].strip()
        if re.fullmatch(IDENTIFIER, visible):
            return state.bindings.get(visible, _Value(object_builtin=visible == 'Object'))
        if re.sub(r'\s+', '', visible) in {'globalThis.Object', 'global.Object', 'window.Object'}:
            return _Value(object_builtin=visible.split('.')[0].strip() not in state.bindings)
        literal = _literal(raw)
        if literal is not None:
            return _Value(safe_key=literal not in BAD_KEYS)
        if re.fullmatch(r'(?:\d+(?:\.\d+)?|true|false|null|undefined)', raw):
            return _Value(safe_key=True)
        call = CALL_RE.match(visible)
        if call and pairs.get(start + call.end() - 1) == end - 1:
            name = re.sub(r'\s+', '', call.group(1))
            arguments = list(_chunks(code, start + call.end(), end - 1))
            if name == 'Object.create' and state.builtin('create') and len(arguments) == 1 and self.text[arguments[0][0]:arguments[0][1]].strip() == 'null':
                # Expression values may be queried again after a surrounding
                # merge mutated the allocation. Reading its identity must not
                # reestablish a discarded receiver/key-shape guarantee.
                if start not in state.allocated_refs:
                    state.allocated_refs.add(start)
                    state.null_refs.add(start)
                    state.safe_keys.add(start)
                return _Value(ref=start)
            facts = [self.value(scope, left, right, state) for left, right in arguments]
            tainted = False
            for fact in facts:
                tainted = tainted or state.tainted(fact)
            if state.bindings.get(name, UNKNOWN).validator in self.validators:
                return _Value(tainted=tainted, safe_key=True)
            if name == 'Object.assign' and state.builtin('assign') and facts:
                return replace(facts[0], tainted=tainted)
        references = [state.bindings.get(match.group(), _Value(object_builtin=match.group() == 'Object'))
                      for match in re.finditer(r'(?<![\w$.])' + IDENTIFIER, visible)]
        tainted, object_builtin = bool(SOURCE_RE.search(visible)), False
        for reference in references:
            tainted = tainted or state.tainted(reference)
            object_builtin = object_builtin or reference.object_builtin
        return _Value(tainted=tainted, object_builtin=object_builtin)

    def receiver_start(self, code, pairs, end):
        cursor = end - 1
        while cursor >= 0 and (code[cursor].isspace() or code[cursor] == '!'):
            cursor -= 1
        if cursor < 0:
            return None
        if code[cursor] in ')]' and cursor in pairs:
            opening = pairs[cursor]
            previous = self.receiver_start(code, pairs, opening)
            return previous if previous is not None else opening
        right = cursor + 1
        while cursor >= 0 and (code[cursor].isalnum() or code[cursor] in '_$'):
            cursor -= 1
        start = cursor + 1
        if start == right or not (code[start].isascii() and (code[start].isalpha() or code[start] in '_$')):
            return None
        while cursor >= 0 and code[cursor].isspace():
            cursor -= 1
        if code[cursor:cursor + 1] == '.':
            return self.receiver_start(code, pairs, cursor)
        if code[start:right] in {'const', 'let', 'var', 'return', 'yield', 'throw'}:
            return None
        return start

    def object_writes(self, scope, start, end, pairs, state):
        """Explicit writes through Object or an alias revoke intrinsic proof."""
        code = scope.code
        for assigned in re.finditer(r'(?<![=!<>])=(?!=|>)', code[start:end]):
            stop = start + assigned.start()
            while stop > start and (code[stop - 1].isspace() or code[stop - 1] in '+-*/%&|^?'):
                stop -= 1
            left = self.receiver_start(code, pairs, stop)
            if left is None or left < start:
                continue
            raw = code[left:stop].strip()
            if re.sub(r'\s+', '', raw) in {'globalThis.Object', 'global.Object', 'window.Object'}:
                if raw.split('.')[0].strip() not in state.bindings:
                    state.object_methods.clear()
                continue
            if code[stop - 1:stop] == ']' and stop - 1 in pairs:
                opening = pairs[stop - 1]
                owner = self.value(scope, left, opening, state)
                member = _literal(self.text[opening + 1:stop - 1])
            else:
                member_match = re.search(r'\.\s*(' + IDENTIFIER + r')$', raw)
                if member_match is None:
                    continue
                owner = self.value(scope, left, left + member_match.start(), state)
                member = member_match.group(1)
            if owner.object_builtin:
                if member is None:
                    state.object_methods.clear()
                else:
                    state.object_methods.discard(member)

    def expression(self, scope, start, end, state):
        self.budget.spend()
        code = scope.code
        start, end = _trim(code, start, end, _pairs(code, start, end), self.text)
        for child in scope.children:
            if start <= child.start < end:
                self.captures[child.start] = _join(self.captures.get(child.start), state)
        declarations = _declaration_entries(self.text, code, start, end)
        if declarations:
            for kind, names, _left, rhs, right in declarations:
                if rhs is not None:
                    self.expression(scope, rhs, right, state)
                value = self.value(scope, rhs, right, state) if rhs is not None else UNKNOWN
                if self.text[_left:right].lstrip().startswith(('[', '{')):
                    value = _Value(tainted=state.tainted(value))
                for name in names:
                    state.bindings[name] = value
                    state.constants.discard(name)
                    if kind == 'const':
                        state.constants.add(name)
            return
        pieces = list(_chunks(code, start, end))
        if len(pieces) > 1:
            for left, right in pieces:
                self.expression(scope, left, right, state)
            return
        left, equals = next(_chunks(code, start, end, '='))
        target = code[left:equals].strip()
        if equals < end and (re.fullmatch(IDENTIFIER, target) or target.startswith(('[', '{'))):
            self.expression(scope, equals + 1, end, state)
            value = self.value(scope, equals + 1, end, state)
            if target.startswith(('[', '{')):
                value = _Value(tainted=state.tainted(value))
            for name in _binding_names(self.text[left:equals]):
                state.bindings[name] = value
            return
        # A nested assignment can execute conditionally (&&, ?:, arguments).
        # Join it with the incoming binding; it cannot leave a stale proof.
        for assigned in re.finditer(r'(?<![\w$.])(' + IDENTIFIER + r')\s*=(?!=|>)', code[start:end]):
            name = assigned.group(1)
            rhs = start + assigned.end()
            right = min(expression_end(code, rhs), end)
            before = state.copy()
            state.bindings[name] = self.value(scope, rhs, right, state)
            state.bindings[name] = _join(before, state).bindings[name]
        pairs = _pairs(code, start, end)
        self.object_writes(scope, start, end, pairs, state)
        events = []
        for match in CALL_RE.finditer(code, start, end):
            opening = match.end() - 1
            closing = pairs.get(opening)
            if closing is not None:
                events.append((closing, 'call', match))
        for opening, closing in pairs.items():
            if opening < closing and code[opening] == '[' and re.match(r'\s*=(?!=|>)', code[closing + 1:end]):
                receiver = self.receiver_start(code, pairs, opening)
                if receiver is not None and receiver >= start:
                    events.append((end, 'write', (receiver, opening, closing)))
        for closing, kind, event in sorted(events, key=lambda event: event[0]):
            if kind == 'call':
                name = re.sub(r'\s+', '', event.group(1))
                facts = [self.value(scope, left, right, state)
                         for left, right in _chunks(code, event.end(), closing)]
                if MERGE_SINK_RE.fullmatch(name + '('):
                    sources = facts if name == 'deepmerge' or len(facts) < 2 else facts[1:]
                    shallow = name == 'Object.assign' and state.builtin('assign')
                    safe_target = (shallow
                                   and facts and facts[0].ref in state.null_refs)
                    risky_source, tainted_source, unproved_keys = False, False, False
                    for source in sources:
                        risky_source = risky_source or (state.shallow_tainted(source) if shallow else state.tainted(source))
                        tainted_source = tainted_source or state.tainted(source)
                        unproved_keys = unproved_keys or source.ref not in state.safe_keys
                    if risky_source:
                        if not safe_target:
                            self.findings.add(event.start())
                    if tainted_source:
                        if facts and facts[0].ref is not None:
                            state.contents.add(facts[0].ref)
                    if facts and unproved_keys:
                        state.safe_keys.discard(facts[0].ref)
                    if facts and facts[0].object_builtin:
                        state.object_methods.clear()
                    if not shallow:
                        state.invalidate()
                elif name == 'Object.create' and state.builtin('create'):
                    pass
                elif state.bindings.get(name, UNKNOWN).validator not in self.validators:
                    for fact in facts:
                        if fact.object_builtin:
                            state.object_methods.clear()
                            break
                    state.invalidate()
                if self.exceptional_prefixes:
                    self.budget.spend(len(state.bindings))
                    exceptional = state.copy()
                    exceptional.invalidate()
                    self.exceptional_prefixes[-1].append(exceptional)
            else:
                receiver, opening, closing = event
                key = self.value(scope, opening + 1, closing, state)
                destination = self.value(scope, receiver, opening, state)
                rhs = self.value(scope, closing + 1, end, state)
                risky = (state.tainted(key) or state.tainted(rhs)) and not key.safe_key
                # A safe root does not certify traversal through nested values.
                for before, after in pairs.items():
                    if receiver <= before < after < opening and code[before] == '[':
                        parent_key = self.value(scope, before + 1, after, state)
                        risky |= state.tainted(parent_key) and not parent_key.safe_key
                if risky and destination.ref not in state.null_refs:
                    self.findings.add(receiver)
                if destination.ref is not None and (state.tainted(key) or state.tainted(rhs)):
                    state.contents.add(destination.ref)
                if not key.safe_key:
                    state.safe_keys.discard(destination.ref)

    def sequence(self, scope, statements, state, start, end, *, scoped=True):
        saved, declared = {}, set()
        exit_start = len(self.exits.get(scope.start, ()))
        prefix_starts = [(frame, len(frame)) for frame in self.exceptional_prefixes]
        for stmt in statements:
            if stmt.kind == 'expression':
                for kind, names, *_ in _declaration_entries(self.text, scope.code, stmt.start, stmt.end):
                    if kind != 'var':
                        declared.update(names)
        pairs = _pairs(scope.code, start, end)
        functions = []
        for child in scope.children:
            if not child.declaration or not start <= child.start < end:
                continue
            nested = False
            for left, right in pairs.items():
                if left < right and scope.code[left] == '{' and left < child.start < right:
                    nested = True
                    break
            if not nested:
                functions.append(child)
        for child in functions:
            if child.name:
                declared.add(child.name)
        for name in declared:
            saved[name] = (state.bindings.get(name), name in state.constants)
            state.bindings[name] = UNKNOWN
            state.constants.discard(name)
        for child in functions:
            state.bindings[child.name] = _Value(validator=child.start if child.start in self.validators else None)
        for stmt in statements:
            self.budget.spend()
            if stmt.kind == 'block':
                state = self.sequence(scope, stmt.body, state, stmt.start + 1, stmt.end - 1)
            elif stmt.kind == 'if':
                self.expression(scope, stmt.start, stmt.end, state)
                yes, no = state.copy(), state.copy()
                for branch, truth in ((yes, True), (no, False)):
                    name = self.guard(scope, stmt.start, stmt.end, truth)
                    if name is not None:
                        branch.bindings[name] = replace(branch.bindings.get(name, UNKNOWN), safe_key=True)
                yes = self.sequence(scope, stmt.body, yes, stmt.end, stmt.body[0].end)
                if stmt.alternate:
                    no = self.sequence(scope, stmt.alternate, no, stmt.end, stmt.alternate[-1].end)
                state = _join(yes, no)
            elif stmt.kind == 'switch':
                self.expression(scope, stmt.start, stmt.end, state)
                state.invalidate()
                incoming, fallthrough, outcomes = state.copy(), None, [state]
                for arm in stmt.body:
                    before_exit = len(self.exits.get(scope.start, ()))
                    fallthrough = self.sequence(scope, arm.body, _join(incoming, fallthrough), arm.start, arm.end)
                    # A terminating arm cannot prevent another label from
                    # matching. Retain pre-exit stores conservatively as well.
                    outcomes.extend((fallthrough, *self.exits.get(scope.start, ())[before_exit:]))
                state = _join(*outcomes)
            elif stmt.kind in {'while', 'for', 'do', 'try'}:
                # Unsupported control alternatives never establish safety. Keep
                # request facts and inspect loop-carried values to a fixed point.
                incoming = state.copy()
                state.invalidate()
                if stmt.kind != 'try':
                    self.expression(scope, stmt.start, stmt.end, state)
                loop_names, iteration_names, iteration_const = (), (), False
                exceptional = []
                if stmt.kind == 'try':
                    self.exceptional_prefixes.append(exceptional)
                if stmt.kind == 'for':
                    binding = re.match(r'\s*(?:(const|let|var)\s+)?(' + IDENTIFIER
                                       + r'|\{[^;]*\}|\[[^;]*\])\s+(?:of|in)\s+',
                                       scope.code[stmt.start:stmt.end])
                    if binding:
                        rhs = stmt.start + binding.end()
                        self.expression(scope, rhs, stmt.end, state)
                        value = _Value(tainted=state.tainted(self.value(scope, rhs, stmt.end, state)))
                        names = _binding_names(self.text[stmt.start + binding.start(2):stmt.start + binding.end(2)])
                        for name in names:
                            state.bindings[name] = value
                            state.constants.discard(name)
                            if binding.group(1) == 'const':
                                state.constants.add(name)
                        if binding.group(1) in {'const', 'let'}:
                            loop_names = names
                        iteration_names, iteration_const = names, binding.group(1) == 'const'
                while True:
                    for name in iteration_names:
                        state.constants.discard(name)
                        if iteration_const:
                            state.constants.add(name)
                    before = state.copy()
                    thrown_before = len(self.throws.get(scope.start, ()))
                    completed_before = len(self.exits.get(scope.start, ()))
                    body = self.sequence(scope, stmt.body, state.copy(), stmt.start, stmt.end)
                    completed = self.exits.get(scope.start, ())[completed_before:] if stmt.kind == 'try' else ()
                    caught = _join(before, *completed, *exceptional)
                    catch_saved = {name: (caught.bindings.get(name), name in caught.constants)
                                   for name in stmt.catch_names}
                    for name in stmt.catch_names:
                        caught.bindings[name] = _Value(tainted=any(self.throws.get(scope.start, ())[thrown_before:]))
                        caught.constants.discard(name)
                    catch_exit = len(self.exits.get(scope.start, ()))
                    catch_prefix = len(exceptional)
                    alternate = self.sequence(scope, stmt.alternate, caught, stmt.start, stmt.end) if stmt.alternate else None
                    stores = ([alternate] if alternate is not None else [])
                    stores.extend(self.exits.get(scope.start, ())[catch_exit:])
                    stores.extend(exceptional[catch_prefix:])
                    for store in stores:
                        store.restore(catch_saved)
                    completed = self.exits.get(scope.start, ())[completed_before:] if stmt.kind == 'try' else ()
                    state = _join(incoming, before, body, alternate, *completed, *exceptional)
                    for name in iteration_names:
                        state.constants.discard(name)
                        if iteration_const:
                            state.constants.add(name)
                    if state == before or stmt.kind == 'try':
                        break
                for name in loop_names:
                    if name in incoming.bindings:
                        state.bindings[name] = incoming.bindings[name]
                    else:
                        state.bindings.pop(name, None)
                    state.constants.discard(name)
                    if name in incoming.constants:
                        state.constants.add(name)
                if stmt.kind == 'try':
                    self.exceptional_prefixes.pop()
                    if self.exceptional_prefixes:
                        self.exceptional_prefixes[-1].extend(exceptional)
                    if stmt.extra:
                        state = self.sequence(scope, stmt.extra, state, stmt.start, stmt.end)
            elif stmt.kind == 'case':
                state = self.sequence(scope, stmt.body, state, stmt.start, stmt.end)
            else:
                self.expression(scope, stmt.start, stmt.end, state)
                if stmt.kind in {'return', 'throw'}:
                    if stmt.kind == 'throw':
                        self.throws.setdefault(scope.start, []).append(state.tainted(self.value(scope, stmt.start, stmt.end, state)))
                    self.budget.spend(len(state.bindings))
                    self.exits.setdefault(scope.start, []).append(state.copy())
                    state = None
                if stmt.kind in {'break', 'continue'}:
                    break
            if state is None:
                break
        if scoped:
            stores = ([state] if state is not None else []) + list(self.exits.get(scope.start, ())[exit_start:])
            for frame, before in prefix_starts:
                stores.extend(frame[before:])
            for store in stores:
                store.restore(saved)
        return state

    def analyze(self):
        pending = [(self.root, _State())]
        while pending:
            scope, state = pending.pop()
            for names, *_ in scope.params:
                for name in names:
                    state.bindings[name] = UNKNOWN
                    state.constants.discard(name)
            incoming = state.copy()
            final = self.sequence(scope, scope.statements, state, scope.body_start, scope.body_end, scoped=False)
            for child in scope.children:
                captured = self.captures.get(child.start, final if final is not None
                                             else _join(*self.exits.get(scope.start, ())) or incoming)
                pending.append((child, captured.copy()))
        return self.findings


def scan_file_findings(path: Path) -> Iterator[int]:
    """Yield exact 1-based sink lines, once each, after lexical suppression."""
    try:
        source_text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    text, code = javascript_lexical_views(source_text)
    if not SOURCE_RE.search(code):
        return
    suppressions = SourceSuppressions('javascript').index(path, source_text)
    flow, incomplete = _PrototypeFlow(text, code), None
    try:
        flow.analyze()
    except AnalysisLimit as exc:
        incomplete = exc
    lines = {source_text.count('\n', 0, offset) + 1 for offset in flow.findings}
    for line in sorted(lines):
        if not suppressions.is_suppressed(line, RULE):
            yield line
    if incomplete is not None:
        raise incomplete


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        rel = path.resolve()
        for line in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_merge_sink_flagged(tmp_prefix: str = "ubs_core_sec_prototype_pollution_") -> None:
    import tempfile

    src = "\n".join([
        "export function assignBody(req) {",
        "  const payload = req.body;",
        "  return Object.assign({}, payload);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "merge.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [3], findings


def _selftest_dynamic_write_flagged(tmp_prefix: str = "ubs_core_sec_prototype_pollution_dyn_") -> None:
    import tempfile

    src = "\n".join([
        "export function write(req) {",
        "  const key = req.query.field;",
        "  const target = {};",
        "  target[key] = req.params.value;",
        "  return target;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "write.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        # Same spanning-statement rule flags the signature line as well.
        assert findings == [4], findings


def _selftest_safe_helpers_clean(tmp_prefix: str = "ubs_core_sec_prototype_pollution_safe_") -> None:
    import tempfile

    src = "\n".join([
        "function validatePrototypeKeys(key) {",
        "  if (typeof key !== 'string' || key === '__proto__' || key === 'constructor' || key === 'prototype') {",
        "    throw new Error('unsafe object key');",
        "  }",
        "  return key;",
        "}",
        "export function assignSanitized(req) {",
        "  const target = Object.create(null);",
        "  return Object.assign(target, req.body);",
        "}",
        "export function safeMergeBody(req) {",
        "  return Object.assign(Object.create(null), req.body);",
        "}",
        "export function write(req) {",
        "  const key = validatePrototypeKeys(req.query.field);",
        "  const target = Object.create(null);",
        "  target[key] = req.params.value;",
        "  return target;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_prototype_pollution_ign_") -> None:
    import tempfile

    # Source annotations preserve taint at later unannotated sinks. An owned
    # sink marker still suppresses its diagnostic at the actual sink location.
    above = "// ubs:ignore\nconst payload = req.body;\nconst out = Object.assign({}, payload);\n"
    same = "const merged = Object.assign({}, req.body); // ubs:ignore\n"
    in_stmt = "\n".join([
        "export function mergePatch(req) {",
        "  const patch = await request.json(); // ubs:ignore",
        "  return merge({ enabled: true }, patch);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "above.ts"
        target.write_text(above, encoding="utf-8")
        assert list(scan_file_findings(target)) == [3], "source marker must preserve the later sink"
        target = Path(tmp) / "same.ts"
        target.write_text(same, encoding="utf-8")
        assert list(scan_file_findings(target)) == [], "same-line marker must suppress"
        target = Path(tmp) / "stmt.ts"
        target.write_text(in_stmt, encoding="utf-8")
        assert list(scan_file_findings(target)) == [3], "source marker preserves the later sink"
def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_prototype_pollution_run_") -> None:
    import tempfile
    src = "const payload = req.body;\nconst out = Object.assign({}, payload);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "merge.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "critical", rec
        assert rec["line"] == 2 and rec["col"] == 1, rec
        assert "Request-derived object merge may allow prototype pollution" in rec["message"], rec


def _selftest_destructuring_and_computed_receivers() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_prototype_receivers_") as tmp:
        target = Path(tmp) / "receivers.ts"
        for binding in ('const [key, value]', 'let [key, value]',
                        'var [key, value]', '[key, value]',
                        'const /* bindings */ [key, value]'):
            target.write_text(f'{binding} = request.body;\n', encoding='utf-8')
            assert list(scan_file_findings(target)) == [], binding
        for receiver in ('target', 'object.target', 'object.const',
                         'getTarget()', 'targets[0]', 'target!', 'target!!',
                         'target /* mutable destination */ ',
                         'target! /* mutable destination */ ',
                         'target /* mutable destination */ !',
                         'target /* receiver */ ! /* assertion */ '):
            target.write_text(
                'const key = req.query.field;\n'
                f'{receiver}[key] = req.body;\n', encoding='utf-8'
            )
            assert list(scan_file_findings(target)) == [2], receiver
        target.write_text(
            'const key = req.query.field;\n'
            'target[key] /* assigned value */ = req.body;\n', encoding='utf-8'
        )
        assert list(scan_file_findings(target)) == [2]
        target.write_text(
            'const [key, value] = request.body;\n'
            'target[req.query.field] = value;\n', encoding='utf-8'
        )
        assert list(scan_file_findings(target)) == [2]


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("destructuring-and-computed-receivers", _selftest_destructuring_and_computed_receivers),
    ("merge-sink-flagged", _selftest_merge_sink_flagged),
    ("dynamic-write-flagged", _selftest_dynamic_write_flagged),
    ("safe-helpers-clean", _selftest_safe_helpers_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_prototype_pollution", run=run, selftests=SELF_TESTS))
