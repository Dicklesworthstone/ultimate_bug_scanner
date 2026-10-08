"""Selected Ruby handle ownership with scoped references and exit paths.

Files, HTTP sessions and threads are obligations of an acquisition, not a
variable spelling. The bounded Ruby frontend is shared with request-flow
analysis; this interpreter owns separate resource and collection identities.
It follows local aliases, block parameters, branch alternatives, explicit
exits and ensure. Unknown dispatch never proves release. Dynamic syntax or
exhausted analysis raises an error for the driver to report as partial.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path
from typing import Iterable

from ubs_core.io import format_location, line_col
from ubs_core.lexer import strip_comments_and_strings as core_strip
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit, Budget

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "vendor",
    "node_modules",
    "tmp",
    "log",
    "coverage",
    ".bundle",
}

RUBY_SUFFIXES = frozenset({".rb", ".rake", ".ru", ".gemspec"})

IDENT = re.compile(r"(?:@@?|\$)?[A-Za-z_]\w*[!?]?")
FACTORIES = {"File.open": "file_handle", "Net::HTTP.start": "http_session",
             "Thread.new": "thread_join", "Thread.start": "thread_join",
             "Thread.fork": "thread_join"}
ACQUISITION = re.compile(r"\b(?:File\s*\.\s*open|Net\s*::\s*HTTP\s*\.\s*start|Thread\s*\.\s*(?:new|start|fork))\b")


def is_ignored(path: Path, root: Path) -> bool:
    base = root if root.is_dir() else root.parent
    try:
        rel = path.relative_to(base)
    except ValueError:
        rel = path
    return any(part in SKIP_DIRS for part in rel.parts[:-1])


def iter_ruby_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in RUBY_SUFFIXES and not is_ignored(root, root):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in RUBY_SUFFIXES:
            continue
        if is_ignored(path, root):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    return core_strip(text, lang="ruby")


@dataclass(frozen=True)
class Value:
    kind: str = "unknown"
    key: int | str = ""


UNKNOWN = Value()


@dataclass
class State:
    bindings: dict[str, Value] = field(default_factory=dict)
    members: dict[int, tuple[Value, ...]] = field(default_factory=dict)
    live: set[int] = field(default_factory=set)
    closed: set[int] = field(default_factory=set)
    flow: str = "normal"
    result: Value = UNKNOWN

    def copy(self):
        return State(dict(self.bindings), dict(self.members), set(self.live), set(self.closed), self.flow, self.result)


class Ownership:
    """Bounded alternatives retain the binding/obligation correlation.

An unknown branch has both outcomes. Known arrays and bounded Integer#times
counts execute exactly. Unknown loops retain zero and every reachable
ownership state until a fixed point; residual multiplicity or path growth
is an explicit incomplete-analysis error, never a truncated clean result.
"""

    def __init__(self, text):
        from ubs_core.analyzers.taint_ruby_traversal import (
            RubyParser, closing_token, split_tokens, token_text, ungroup,
        )
        self.parser = RubyParser(text)
        self.source = text
        self.closing, self.split = closing_token, split_tokens
        self.text, self.ungroup = token_text, ungroup
        self.budget = Budget()
        self.resources: dict[int, tuple[int, str, str]] = {}
        self.issues: dict[tuple[int, str], str] = {}
        self.serial = 0

    def identity(self):
        self.budget.spend()
        self.serial += 1
        return self.serial

    def acquire(self, name, token, state, label="", position=None):
        identity = self.identity()
        self.resources[identity] = (token.start if position is None else position, FACTORIES[name], label)
        state.live.add(identity)
        return Value("resource", identity)

    def array(self, members, state):
        identity = self.identity()
        state.members[identity] = tuple(members)
        return Value("array", identity)

    def release(self, value, state, method, arguments=(), position=None):
        if value.kind != "resource":
            return
        kind = self.resources[value.key][1]
        observed = (kind == "file_handle" and method == "close" and not arguments
                    or kind == "http_session" and method == "finish" and not arguments
                    or kind == "thread_join" and (method == "value" and not arguments
                        or method == "join" and (not arguments or arguments == (Value("keyword", "nil"),))))
        if observed:
            # Ruby IO#close and Thread#join are idempotent observations.
            # Net::HTTP#finish raises when the same session is not started.
            if kind == "http_session" and value.key in state.closed and position is not None:
                acquired, _, name = self.resources[value.key]
                line, _ = line_col(self.source, acquired)
                self.issues[position, kind] = f"Net::HTTP session finished more than once (opened on line {line}" + (f", {name})" if name else ")")
                state.flow = "raise"
            state.live.discard(value.key)
            state.closed.add(value.key)

    def transfer(self, value, state):
        pending, seen = [value], set()
        while pending:
            self.budget.spend()
            item = pending.pop()
            if item in seen:
                continue
            seen.add(item)
            if item.kind == "resource":
                state.live.discard(item.key)
            elif item.kind == "array":
                pending.extend(state.members.get(item.key, ()))

    def finish(self, states, returns=False):
        for state in states:
            if returns and state.flow in {"normal", "return"}:
                self.transfer(state.result, state)
            for identity in state.live:
                position, kind, name = self.resources[identity]
                description = {"file_handle": "File handle may leave scope without close",
                               "thread_join": "Thread may leave scope without join/value",
                               "http_session": "Net::HTTP session may leave scope without finish"}[kind]
                self.issues[position, kind] = description + (f" ({name})" if name else "")

    def bounded(self, states):
        unique = {}
        for state in states:
            self.budget.spend()
            unique.setdefault(self.state_key(state), state)
        if len(unique) > 256:
            raise AnalysisLimit("Ruby lifecycle path limit exceeded; analysis is incomplete")
        return list(unique.values())

    @staticmethod
    def state_key(state):
        return (tuple(sorted(state.bindings.items())), tuple(sorted(state.members.items())),
                frozenset(state.live), frozenset(state.closed), state.flow, state.result)

    def discard_unreachable_closed_values(self, state):
        """Closed block-local allocations do not prevent loop convergence."""
        pending = [*state.bindings.values(), state.result]
        resources, arrays = set(), set()
        while pending:
            self.budget.spend()
            value = pending.pop()
            if value.kind == "resource":
                resources.add(value.key)
            elif value.kind == "array" and value.key not in arrays:
                arrays.add(value.key)
                pending.extend(state.members.get(value.key, ()))
        state.closed.intersection_update(resources)
        state.members = {key: members for key, members in state.members.items() if key in arrays}

    def arguments(self, tokens, state, depth):
        values = []
        for part in self.split(tokens, {","}):
            if part:
                if len(part) == 3 and self.text(part[:2]) == "&:":
                    values.append(Value("symbol", part[2].value))
                else:
                    values.append(self.expression(part, state, depth + 1))
        return tuple(values)

    def relevant(self, tokens, state):
        return ACQUISITION.search(self.text(tokens)) or any(
            token.kind == "code" and state.bindings.get(token.value, UNKNOWN).kind in {"resource", "array"}
            for token in tokens)

    def inline_block(self, header, tokens):
        from ubs_core.analyzers.taint_ruby_traversal import RubyParser, RubyStatement

        parser = RubyParser("")
        parser.tokens = list(tokens)
        names = []
        explicit = parser.value() in {"|", "||"}
        if parser.value() == "|":
            parser.position += 1
            while parser.value() and parser.value() != "|":
                if parser.value() != ",":
                    names.append(parser.value())
                parser.position += 1
            if parser.value() != "|":
                raise ValueError("Unterminated Ruby block parameters; analysis is incomplete")
            parser.position += 1
        elif parser.value() == "||":
            parser.position += 1
        body = parser.block((), ())
        if len(parser.functions) != 1:
            raise ValueError("Ruby embedded definitions need scope analysis; analysis is incomplete")
        statement = RubyStatement("iterate", tuple(header), body, names=tuple(names), explicit_parameters=explicit)
        parser.functions[-1].body = (statement,)
        parser.bind_numbered_parameters()
        return statement

    def call(self, name, receiver, arguments, token, state, label="", position=None):
        if state.flow != "normal":
            return UNKNOWN
        root = name.split(".", 1)[0]
        constants = root.split("::")
        shadowed = any("::".join(constants[:index]) in state.bindings for index in range(1, len(constants) + 1))
        if name in FACTORIES and not shadowed:
            return self.acquire(name, token, state, label, position)
        method = name.rsplit(".", 1)[-1]
        self.release(receiver, state, method, arguments, token.start)
        if receiver.kind == "resource":
            kind = self.resources[receiver.key][1]
            if kind == "file_handle" and method == "closed?" and not arguments:
                return Value("keyword", "true" if receiver.key in state.closed else "false")
            if kind == "http_session" and method == "started?" and not arguments:
                return Value("keyword", "false" if receiver.key in state.closed else "true")
            if kind == "http_session" and method == "start":
                raise ValueError("Ruby HTTP session restart needs lifetime binding; analysis is incomplete")
            if method == "freeze" or kind == "thread_join" and (
                    method in {"kill", "terminate", "exit"} or method == "join" and receiver.key in state.closed):
                return receiver
            if method in {"close", "finish"} and receiver.key in state.closed:
                return Value("keyword", "nil")
            return UNKNOWN
        if receiver.kind == "array":
            members = state.members.get(receiver.key, ())
            if method in {"each", "map", "collect", "each_with_index"} and len(arguments) == 1 and arguments[0].kind == "symbol":
                for member in members:
                    self.release(member, state, str(arguments[0].key), position=token.start)
                    if state.flow != "normal":
                        break
                return receiver if method == "each" else UNKNOWN
            if method in {"push", "append", "unshift", "prepend"}:
                state.members[receiver.key] = (arguments + members if method in {"unshift", "prepend"} else members + arguments)
                return receiver
            if method == "concat" and all(value.kind == "array" for value in arguments):
                state.members[receiver.key] = members + tuple(item for value in arguments for item in state.members.get(value.key, ()))
                return receiver
            if method == "clear" and not arguments:
                state.members[receiver.key] = ()
                return receiver
            if method in {"pop", "shift"} and not arguments:
                state.members[receiver.key] = members[:-1] if method == "pop" else members[1:]
                return (members[-1] if method == "pop" else members[0]) if members else UNKNOWN
            if method in {"first", "last"} and not arguments:
                return (members[0] if method == "first" else members[-1]) if members else UNKNOWN
            if method in {"[]", "at", "fetch"} and len(arguments) == 1 and arguments[0].kind == "number":
                try:
                    return members[int(arguments[0].key)]
                except (IndexError, ValueError):
                    return UNKNOWN
            if method in {"dup", "clone"} and not arguments:
                return self.array(members, state)
            if method in {"to_a", "freeze"} and not arguments:
                return receiver
            if method in {"replace", "delete", "delete_at", "delete_if", "reject!", "select!", "compact!", "flatten!", "map!", "collect!", "slice!", "insert"}:
                # Unmodeled mutation invalidates membership proof, never the
                # independent obligations of the former members.
                state.members[receiver.key] = ()
        return UNKNOWN

    def expression(self, tokens, state, depth=0, label="", position=None):
        self.budget.spend()
        if state.flow != "normal":
            return UNKNOWN
        if depth > 64:
            raise AnalysisLimit("Ruby lifecycle expression limit exceeded; analysis is incomplete")
        tokens = self.ungroup(tokens)
        if not tokens:
            return UNKNOWN
        if len(tokens) == 2 and tokens[0].value == "-" and tokens[1].kind == "number":
            return Value("number", "-" + tokens[1].value)
        shifted = self.split(tokens, {"<<"})
        if len(shifted) > 1:
            value = self.expression(shifted[0], state, depth + 1)
            for part in shifted[1:]:
                item = self.expression(part, state, depth + 1)
                if value.kind == "array":
                    state.members[value.key] = (*state.members.get(value.key, ()), item)
            return value
        for operators in ({"||", "&&", "or", "and", "?"}, {"==", "!=", "<", ">", "<=", ">="}, {"+", "-", "*", "/", ".."}):
            parts = self.split(tokens, operators)
            if len(parts) > 1:
                if operators & {"||", "&&", "or", "and", "?"} and self.relevant(tokens, state):
                    raise ValueError("Ruby lifecycle short-circuit expression needs branch binding; analysis is incomplete")
                for part in parts:
                    self.expression(part, state, depth + 1)
                return UNKNOWN
        result, cursor = UNKNOWN, 0
        while cursor < len(tokens):
            self.budget.spend()
            token = tokens[cursor]
            name = ""
            if token.kind != "code":
                for part in token.parts:
                    self.expression(part, state, depth + 1)
                result = Value(token.kind, token.value)
                cursor += 1
            elif token.value in {"nil", "false", "true"}:
                result, cursor = Value("keyword", token.value), cursor + 1
            elif token.value == ":" and cursor + 1 < len(tokens):
                result, cursor = Value("symbol", tokens[cursor + 1].value), cursor + 2
            elif token.value in {"(", "[", "{"}:
                end = self.closing(tokens, cursor)
                items = self.arguments(tokens[cursor + 1:end], state, depth + 1)
                result = self.array(items, state) if token.value == "[" else (items[-1] if items else UNKNOWN)
                cursor = end + 1
            elif IDENT.fullmatch(token.value):
                name, cursor = token.value, cursor + 1
                while cursor + 1 < len(tokens) and tokens[cursor].value == "::":
                    name += "::" + tokens[cursor + 1].value
                    cursor += 2
                result = state.bindings.get(name, UNKNOWN)
                if cursor < len(tokens) and tokens[cursor].value == "(":
                    end = self.closing(tokens, cursor)
                    args = self.arguments(tokens[cursor + 1:end], state, depth + 1)
                    result = self.call(name, UNKNOWN, args, token, state, label, position)
                    cursor = end + 1
                elif cursor < len(tokens) and tokens[cursor].value not in {".", "&.", "[", "{", ",", ")", "]", "}"}:
                    args = self.arguments(tokens[cursor:], state, depth + 1)
                    result = self.call(name, UNKNOWN, args, token, state, label, position)
                    cursor = len(tokens)
            else:
                cursor += 1
                continue
            while cursor < len(tokens) and state.flow == "normal":
                if tokens[cursor].value == "[":
                    end = self.closing(tokens, cursor)
                    args = self.arguments(tokens[cursor + 1:end], state, depth + 1)
                    result = self.call(name + ".[]", result, args, token, state)
                    cursor = end + 1
                elif tokens[cursor].value in {".", "&."} and cursor + 1 < len(tokens):
                    member = tokens[cursor + 1]
                    name = name + "." + member.value if name else member.value
                    cursor += 2
                    args = ()
                    if cursor < len(tokens) and tokens[cursor].value == "(":
                        end = self.closing(tokens, cursor)
                        args = self.arguments(tokens[cursor + 1:end], state, depth + 1)
                        cursor = end + 1
                    elif cursor < len(tokens) and tokens[cursor].value not in {".", "&.", "[", "{", ",", ")", "]", "}"}:
                        args = self.arguments(tokens[cursor:], state, depth + 1)
                        cursor = len(tokens)
                    result = self.call(name, result, args, token, state, label, position)
                elif tokens[cursor].value == "{" and result.kind == "resource":
                    # Thread.new {...}.join attaches a block before evaluating
                    # the suffix. The block cannot release creator bindings.
                    if self.resources[result.key][1] != "thread_join":
                        raise ValueError("Ruby nested resource block needs expression binding; analysis is incomplete")
                    end = self.closing(tokens, cursor)
                    child = state.copy()
                    child.live.clear()
                    block = self.inline_block((), tokens[cursor + 1:end])
                    self.finish(self.scoped_block(block, child, ()))
                    cursor = end + 1
                else:
                    break
        return result

    def assign(self, groups, value, state):
        for group in reversed(groups):
            if len(group) == 1 and group[0].kind == "code" and IDENT.fullmatch(group[0].value):
                state.bindings[group[0].value] = value
            elif group and (value.kind in {"resource", "array"} or self.relevant(group, state)):
                raise ValueError("Ruby lifecycle assignment target needs binding analysis; analysis is incomplete")
        state.result = value

    def simple(self, tokens, state):
        if not tokens:
            return state
        if tokens[0].value in {"return", "raise", "fail", "break", "next"}:
            state.result = self.expression(tokens[1:], state)
            state.flow = "raise" if tokens[0].value in {"raise", "fail"} else tokens[0].value
            return state
        groups = self.split(tokens, {"="})
        if len(self.split(tokens, {"||=", "&&=", "+=", "-="})) > 1:
            if self.relevant(tokens, state):
                raise ValueError("Ruby lifecycle compound assignment needs binding analysis; analysis is incomplete")
            return state
        target = groups[0] if len(groups) > 1 else ()
        label = target[0].value if len(target) == 1 else ""
        value = self.expression(groups[-1], state, label=label, position=target[0].start if target else None)
        self.assign(groups[:-1], value, state)
        return state

    def scoped_block(self, statement, state, values):
        names = statement.names
        if any(not IDENT.fullmatch(name) for name in names):
            raise ValueError("Ruby lifecycle block destructuring needs binding analysis; analysis is incomplete")
        previous = {name: state.bindings.get(name) for name in names}
        original = set(state.bindings)
        for index, name in enumerate(names):
            state.bindings[name] = values[index] if index < len(values) else UNKNOWN
        outputs = self.sequence(statement.body, [state])
        for output in outputs:
            for name in set(output.bindings) - original:
                output.bindings.pop(name, None)
            for name, value in previous.items():
                if value is None:
                    output.bindings.pop(name, None)
                else:
                    output.bindings[name] = value
        return outputs

    def iterate(self, statement, state):
        groups = self.split(statement.tokens, {"="})
        expression = groups[-1]
        call_expression = self.ungroup(self.split(expression, {"<<"})[-1])
        factory_parts = self.split(call_expression, {".", "&."})
        factory = (self.text(factory_parts[0]) + "." + factory_parts[1][0].value
                   if len(factory_parts) == 2 and factory_parts[1] else "")
        if factory in {"Thread.new", "Thread.start", "Thread.fork"}:
            self.simple(statement.tokens, state)
            child = state.copy()
            child.live.clear()
            child.result = UNKNOWN
            self.finish(self.scoped_block(statement, child, ()))
            return [state]
        if factory in {"File.open", "Net::HTTP.start"}:
            value = self.expression(expression, state)
            if value.kind == "resource" and self.resources[value.key][1] == FACTORIES[factory]:
                outputs = self.scoped_block(statement, state, (value,))
                for output in outputs:
                    self.release(value, output, "close" if factory.startswith("File.") else "finish")
                    if output.flow == "normal":
                        self.assign(groups[:-1], output.result, output)
                return outputs
        parts = self.split(expression, {".", "&."})
        method = parts[-1][0].value if len(parts) > 1 and parts[-1] else ""
        receiver_tokens = expression[:len(expression) - len(parts[-1]) - 1] if method else ()
        receiver = self.expression(receiver_tokens, state) if receiver_tokens else UNKNOWN
        if method in {"each", "map", "collect"} and receiver.kind == "array":
            members = state.members.get(receiver.key, ())
            mapped = self.array((), state) if method != "each" else UNKNOWN
            outputs = [state]
            for member in members:
                following = []
                for output in outputs:
                    if output.flow != "normal":
                        following.append(output)
                        continue
                    for current in self.scoped_block(statement, output, (member,)):
                        if current.members.get(receiver.key, ()) != members:
                            raise ValueError("Ruby collection mutation during iteration needs loop analysis; analysis is incomplete")
                        if current.flow == "next":
                            current.flow = "normal"
                        following.append(current)
                        if mapped.kind == "array":
                            current.members[mapped.key] = (*current.members.get(mapped.key, ()), current.result)
                outputs = self.bounded(following)
            for output in outputs:
                if output.flow == "break":
                    output.flow = "normal"
                    self.assign(groups[:-1], output.result, output)
                elif output.flow == "normal":
                    self.assign(groups[:-1], receiver if method == "each" else mapped, output)
            return outputs
        repetitions, optional = 64, True
        if method == "times" and receiver.kind == "number" and str(receiver.key).isdigit():
            digits = str(receiver.key)
            if len(digits) > 4 or int(digits) > 1024:
                raise AnalysisLimit("Ruby lifecycle iteration count limit exceeded; analysis is incomplete")
            repetitions, optional = int(digits), False
        outputs = self.loop(statement, state, repetitions, optional)
        for output in outputs:
            if output.flow == "normal":
                self.assign(groups[:-1], UNKNOWN, output)
        return outputs

    def loop(self, statement, state, repetitions=64, optional=True):
        outputs = [state.copy()] if optional else []
        current = [state]
        seen = {self.state_key(state)} if optional else set()
        for _ in range(repetitions):
            following = []
            for item in current:
                if item.flow != "normal":
                    outputs.append(item)
                    continue
                if statement.kind == "iterate":
                    repeated = self.scoped_block(statement, item, ())
                else:
                    for name in statement.names:
                        item.bindings[name] = UNKNOWN
                    repeated = self.sequence(statement.body, [item])
                for result in repeated:
                    if result.flow == "break":
                        result.flow = "normal"
                        outputs.append(result)
                    elif result.flow in {"normal", "next"}:
                        result.flow = "normal"
                        following.append(result)
                    else:
                        outputs.append(result)
            current = self.bounded(following)
            if optional:
                unseen = []
                for item in current:
                    # A loop body's normal value is not the loop's result.
                    item.result = UNKNOWN
                    self.discard_unreachable_closed_values(item)
                    key = self.state_key(item)
                    if key not in seen:
                        seen.add(key)
                        unseen.append(item)
                        outputs.append(item.copy())
                current = unseen
                if not current:
                    return self.bounded(outputs)
        if optional and current:
            raise AnalysisLimit("Ruby lifecycle loop ownership did not stabilize; analysis is incomplete")
        outputs.extend(current)
        return self.bounded(outputs)

    def statement(self, statement, state):
        kind = statement.kind
        if kind == "simple":
            # The shared parser leaves a chained outer brace block embedded
            # when its receiver itself contains a block, such as
            # [Thread.new {...}].each {...}. Recover only the outer block.
            tokens, depth = statement.tokens, 0
            for index, token in enumerate(tokens):
                if token.kind != "code":
                    continue
                if token.value == "{" and depth == 0 and index > 0 and tokens[index - 1].value not in {"=", "=>", ":", ",", "("}:
                    end = self.closing(tokens, index)
                    if end == len(tokens) - 1 and tokens[0].value not in {"return", "raise", "fail", "break", "next"}:
                        return self.iterate(self.inline_block(tokens[:index], tokens[index + 1:end]), state)
                if token.value in {"(", "[", "{"}:
                    depth += 1
                elif token.value in {")", "]", "}"}:
                    depth -= 1
            return [self.simple(statement.tokens, state)]
        if kind == "block":
            return self.sequence(statement.body, [state])
        if kind in {"if", "unless"}:
            condition = self.expression(statement.tokens, state)
            truth = None
            if condition.kind == "keyword":
                truth = condition.key not in {"nil", "false"}
            elif condition.kind in {"literal", "number", "resource", "array", "symbol"}:
                truth = True
            if kind == "unless" and truth is not None:
                truth = not truth
            outputs = []
            if truth is not False:
                outputs.extend(self.sequence(statement.body, [state.copy()]))
            if truth is not True:
                alternate = state.copy()
                alternate.result = UNKNOWN
                outputs.extend(self.sequence(statement.alternate, [alternate]))
            return outputs
        if kind in {"while", "until", "for"}:
            condition = self.expression(statement.tokens, state)
            if kind != "for" and condition.kind == "keyword":
                truth = condition.key not in {"nil", "false"}
                if (kind == "while" and not truth) or (kind == "until" and truth):
                    state.result = UNKNOWN
                    return [state]
            return self.loop(statement, state)
        if kind == "iterate":
            return self.iterate(statement, state)
        if kind == "rescue":
            outputs = []
            for item in self.sequence(statement.body, [state]):
                if item.flow == "normal":
                    outputs.extend(self.sequence(statement.alternate, [item]))
                elif item.flow == "raise" and statement.handlers:
                    # The selected slice does not infer typed rescue dispatch.
                    # Retain an escaping alternative instead of proving close.
                    if any(handler.tokens for handler in statement.handlers):
                        outputs.append(item.copy())
                    for handler in statement.handlers:
                        caught = item.copy()
                        caught.flow, caught.result = "normal", UNKNOWN
                        for name in handler.names:
                            caught.bindings[name] = UNKNOWN
                        outputs.extend(self.sequence(handler.body, [caught]))
                else:
                    outputs.append(item)
            finalized = []
            for item in outputs:
                flow, result = item.flow, item.result
                item.flow = "normal"
                for output in self.sequence(statement.finalizer, [item]):
                    if output.flow == "normal":
                        output.flow, output.result = flow, result
                    finalized.append(output)
            return finalized
        raise ValueError(f"Unsupported Ruby lifecycle statement {kind}; analysis is incomplete")

    def sequence(self, statements, states):
        for statement in statements:
            outputs = []
            for state in states:
                self.budget.spend()
                outputs.extend(self.statement(statement, state) if state.flow == "normal" else [state])
            states = self.bounded(outputs)
        return states

    def run(self):
        for function in self.parser.functions.values():
            state = State()
            for index, name in enumerate(function.parameters):
                default = function.defaults[index] if index < len(function.defaults) else ()
                state.bindings[name] = self.expression(default, state) if default else UNKNOWN
            self.finish(self.sequence(function.body, [state]), returns=not function.scope)
        return [(position, kind, message) for (position, kind), message in sorted(self.issues.items())]


def scan_file(path: Path, text: str) -> list[tuple[int, str, str]]:
    """Return acquisition-site findings, or fail explicitly when incomplete."""
    if not ACQUISITION.search(text):
        return []
    from ubs_core.analyzers.taint_ruby_traversal import RubyLexer
    pending = [RubyLexer(text).scan()]
    relevant = False
    while pending:
        tokens = pending.pop()
        relevant |= bool(ACQUISITION.search(" ".join(token.value if token.kind == "code" else " " for token in tokens)))
        pending.extend(part for token in tokens for part in token.parts)
    if not relevant:
        return []
    issues = Ownership(text).run()
    suppressions = build_index(text, lang="ruby")
    return [(position, kind, message) for position, kind, message in issues
            if not suppressions.is_suppressed(line_col(text, position)[0], f"ruby.lifecycle.{kind}")]


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_ruby_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pos, kind, message in scan_file(path, text):
            issues.append((format_location(base, path, pos, text), kind, message))

    return issues


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_ruby.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in RUBY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for pos, kind, message in scan_file(path, text):
            line, col = line_col(text, pos)
            yield {
                "rule": f"ruby.lifecycle.{kind}",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "ruby",
                "severity": "warning",
                "message": message,
            }


def _selftest_file_handle_detected() -> None:
    code = 'log = File.open("app.log", "w")\nlog.puts "line"\n'
    issues = scan_file(Path("fixture.rb"), code)
    assert [(pos, kind) for pos, kind, _ in issues] == [(0, "file_handle")], issues


def _selftest_close_suppression() -> None:
    code = 'log = File.open("app.log", "w")\nlog.puts "line"\nlog.close\n'
    issues = scan_file(Path("fixture.rb"), code)
    assert not issues, issues


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_ruby_") -> None:
    import tempfile

    code = 'handle = File.open("data.txt")\nhandle.read\n'
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "ruby.lifecycle.file_handle"
    assert findings[0]["line"] == 1
    assert findings[0]["col"] == 1


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("file_handle_detected", _selftest_file_handle_detected),
    ("close_suppression", _selftest_close_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="ruby", name="lifecycle_ruby", run=run, selftests=SELF_TESTS))
