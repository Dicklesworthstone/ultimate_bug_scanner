"""Function-scoped C# request-path dataflow and local helper summaries (D6).

A bounded lexical frontend lowers structured branches/loops to a CFG. The
shared finite-lattice solver handles strong updates and cyclic control flow;
method summaries carry parameter-to-return, ref/out write and file-sink flows.
By-reference alias partitions are separate finite summary contexts; writes are
observed at normal exits after finally cleanup, never at a premature return.
Only explicitly selected source is read. This is not a C# compiler or a heap /
virtual-dispatch model. Unknown calls conservatively propagate their arguments.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
import re
import sys
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import (AnalysisLimit, Budget, CLEAN, Fact, State, Step,
                                 Trace, advance, join, retag, solve, substitute)

RULE = "csharp.taint.request_traversal"
MESSAGE = "Request-derived path reaches file read/write/serve sink"
CANONICAL = frozenset({"canonical-path"})
NAME = re.compile(r"@?[A-Za-z_][\w]*(?:(?:\s*\.|::)\s*@?[A-Za-z_][\w]*)*")
SOURCE = re.compile(
    r"\b(?:Request|request|req)\s*\.\s*(?:Query|Form|RouteValues|Headers|Cookies|Path|PathBase|RawTarget|QueryString)\b"
    r"|\b[A-Za-z_]\w*\s*\.\s*FileName\b", re.IGNORECASE)
MODIFIERS = {"public", "private", "protected", "internal", "static", "async", "virtual",
             "override", "sealed", "new", "unsafe", "extern", "partial", "readonly"}
CONTROL = {"if", "while", "for", "foreach", "switch", "catch", "using", "lock", "fixed"}


def masked_source(text: str, depth: int = 0) -> str:
    """Keep C# executable interpolation holes; mask inert text at exact offsets."""
    if depth > 64:
        raise AnalysisLimit("C# literal nesting limit exceeded")
    out = list(text)

    def blank(start, end):
        for index in range(start, end):
            if text[index] not in "\r\n":
                out[index] = " "

    def literal(start):
        match = re.match(r'(\$+@?|@\$?)?("{3,}|"|\')', text[start:])
        if not match:
            return None
        prefix, delimiter = match.group(1) or "", match.group(2)
        if delimiter == "'" and prefix:
            return None
        raw, verbatim = len(delimiter) >= 3, "@" in prefix
        dollars = prefix.count("$")
        width = dollars if raw else 1
        position = start + match.end()
        holes = []
        while position < len(text):
            if text.startswith(delimiter, position):
                if verbatim and not raw and text.startswith('""', position):
                    position += 2
                    continue
                return position + len(delimiter), holes
            if not raw and not verbatim and text[position] == "\\":
                position += 2
                continue
            if dollars and text.startswith("{" * width, position):
                if not raw and text.startswith("{{", position):
                    position += 2
                    continue
                beginning = position + width
                cursor, braces = beginning, 0
                while cursor < len(text):
                    nested = literal(cursor) if text[cursor] in "@$\"'" else None
                    if nested:
                        cursor = nested[0]
                        continue
                    if text.startswith("//", cursor):
                        end = text.find("\n", cursor + 2)
                        cursor = len(text) if end < 0 else end
                        continue
                    if text.startswith("/*", cursor):
                        end = text.find("*/", cursor + 2)
                        cursor = len(text) if end < 0 else end + 2
                        continue
                    if braces == 0 and text.startswith("}" * width, cursor):
                        break
                    if text[cursor] == "{":
                        braces += 1
                    elif text[cursor] == "}":
                        braces -= 1
                    cursor += 1
                if cursor >= len(text):
                    raise ValueError("Unterminated C# interpolation; analysis is incomplete")
                holes.append((beginning, cursor))
                position = cursor + width
                continue
            position += 1
        raise ValueError("Unterminated C# literal; analysis is incomplete")

    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            blank(index, end)
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("Unterminated C# comment; analysis is incomplete")
            blank(index, end + 2)
            index = end + 2
        elif text[index] in "@$\"'" and (value := literal(index)):
            end, holes = value
            blank(index, end)
            out[index] = "0"  # Retain an inert expression, not empty syntax.
            for start, stop in holes:
                out[start:stop] = masked_source(text[start:stop], depth + 1)
                out[start - 1], out[stop] = "(", ")"
            index = end
        elif text[index] == "#" and not text[text.rfind("\n", 0, index) + 1:index].strip():
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            # Branching compilation cannot be modeled as a sequential kill.
            if re.match(r"#\s*(if|elif|else|endif)\b", text[index:end]):
                raise ValueError("Conditional C# compilation requires a configured source view; analysis is incomplete")
            blank(index, end)
            index = end
        else:
            index += 1
    return "".join(out)


def pairs(code: str) -> dict[int, int]:
    stack, result = [], {}
    for index, char in enumerate(code):
        if char in "([{":
            stack.append((char, index))
        elif char in ")]}":
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[char]:
                raise ValueError("Unbalanced C# source; analysis is incomplete")
            _, opening = stack.pop()
            result[opening] = index
    if stack:
        raise ValueError("Unbalanced C# source; analysis is incomplete")
    return result


def parts(code: str, start: int, end: int, separator: str = ",", *, generics=False):
    stack, beginning = [], start
    index = start
    while index < end:
        char = code[index]
        if char == "<" and not generics:
            match = re.match(r"<[\w@.,<>\[\]?\s:]+>\s*(?=[(.])", code[index:end])
            if match:
                index += match.end()
                continue
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if stack:
                stack.pop()
        elif generics and char == "<":
            stack.append(char)
        elif generics and char == ">" and stack and stack[-1] == "<":
            stack.pop()
        elif char == separator and not stack:
            yield beginning, index
            beginning = index + 1
        index += 1
    if code[beginning:end].strip() or beginning != start:
        yield beginning, end


@dataclass(frozen=True)
class Statement:
    start: int
    end: int
    kind: str = "simple"
    body: tuple = ()
    otherwise: tuple = ()
    header: tuple[int, int] = (0, 0)


@dataclass
class Function:
    key: int
    name: str
    owner: tuple[str, ...]
    declaration: int
    start: int
    end: int
    parameters: tuple[str, ...]
    defaults: int = 0
    expression: bool = False
    parent: int | None = None
    request_parameters: frozenset[str] = frozenset()
    parameter_modes: tuple[str, ...] = ()
    parameter_types: tuple[str, ...] = ()
    body: tuple = ()


class Parser:
    def __init__(self, text: str, code: str):
        self.text, self.code = text, code
        self.pairs = pairs(code)
        self.functions: dict[int, Function] = {}
        self.declarations: dict[int, Function] = {}
        self.types = []
        for match in re.finditer(r"\b(namespace|class|struct|record)\s+([A-Za-z_][\w.]*)[^;{}]*([;{])", code):
            opening = match.end() - 1
            if match.group(3) == "{":
                self.types.append((match.start(), self.pairs[opening], match.group(2)))
            elif match.group(1) == "namespace":
                self.types.append((match.end(), len(code), match.group(2)))
        self.find_functions()

    def skip(self, position: int, end: int) -> int:
        while position < end and (self.code[position].isspace() or self.code[position] == ";"):
            position += 1
        return position

    def boundary(self, position: int) -> int:
        return max(self.code.rfind(char, 0, position) for char in ";{}") + 1

    def find_functions(self):
        for match in re.finditer(r"\b(@?[A-Za-z_]\w*)(?:\s*<[^();{}]+>)?\s*\(", self.code):
            name = match.group(1).lstrip("@")
            opening = match.end() - 1
            close = self.pairs.get(opening)
            if close is None or name in CONTROL:
                continue
            following = self.skip(close + 1, len(self.code))
            expression = self.code.startswith("=>", following)
            if following >= len(self.code) or not (self.code[following] == "{" or expression):
                continue
            beginning = self.boundary(match.start())
            prefix = self.code[beginning:match.start()].strip()
            # Attributes are metadata, not calls or return types.
            prefix = re.sub(r"\[[^\]]*\]", " ", prefix).strip()
            words = prefix.split()
            if (not words or words[-1] in MODIFIERS or any(char in prefix for char in "=()!+\"'")
                    or words[0] in {"return", "throw", "new", "else", "case"}):
                continue
            parameters, request_parameters, parameter_modes, parameter_types, defaults = [], set(), [], [], 0
            for start, end in parts(self.code, opening + 1, close, generics=True):
                declaration = self.code[start:end].split("=", 1)
                ids = re.findall(r"@?[A-Za-z_]\w*", declaration[0])
                if len(ids) < 2:
                    break
                parameter = ids[-1].lstrip("@")
                parameters.append(parameter)
                mode = "out" if "out" in ids[:-1] else "in" if "in" in ids[:-1] or (
                    "ref" in ids[:-1] and "readonly" in ids[:-1]) else "ref" if "ref" in ids[:-1] else "value"
                parameter_modes.append(mode)
                variable = list(re.finditer(r"@?[A-Za-z_]\w*", declaration[0]))[-1]
                spelling = declaration[0][:variable.start()]
                spelling = re.sub(r"\[[^\]]*\]", " ", spelling)
                spelling = re.sub(r"\b(?:this|ref|out|in|readonly|params)\b", " ", spelling)
                parameter_types.append(re.sub(r"\s+", "", spelling))
                if any(word in {"HttpRequest", "HttpRequestBase", "HttpContext"} for word in ids[:-1]):
                    request_parameters.add(parameter)
                defaults += len(declaration) == 2
            else:
                if expression:
                    start = following + 2
                    end = self.end_statement(start, len(self.code))
                    finish = min(end + 1, len(self.code))
                else:
                    start, end = following + 1, self.pairs[following]
                    finish = end + 1
                owner = tuple(name for low, high, name in self.types if low < match.start() < high)
                beginning = self.skip(beginning, match.start())
                function = Function(match.start(), name, owner, beginning, start, end,
                                    tuple(parameters), defaults, expression,
                                    request_parameters=frozenset(request_parameters),
                                    parameter_modes=tuple(parameter_modes),
                                    parameter_types=tuple(parameter_types))
                self.functions[function.key] = function
                self.declarations[beginning] = function
        for function in self.functions.values():
            parents = [other for other in self.functions.values()
                       if other.start <= function.key < other.end and other.key != function.key]
            if parents:
                function.parent = min(parents, key=lambda item: item.end - item.start).key
        for function in self.functions.values():
            function.body = ((Statement(function.start, function.end, "return"),) if function.expression
                             else self.block(function.start, function.end))

    def end_statement(self, start, end):
        while start < end:
            char = self.code[start]
            if char == ";":
                return start
            if char in "([{":
                start = self.pairs[start]
            start += 1
        return end

    def block(self, start, end):
        statements = []
        while (start := self.skip(start, end)) < end:
            statement, following = self.statement(start, end)
            statements.append(statement)
            if following <= start:
                raise ValueError("C# statement parser made no progress")
            start = following
        return tuple(statements)

    def statement(self, start, end):
        function = self.declarations.get(start)
        if function is not None:
            finish = min(function.end + 1, end)
            return Statement(start, finish, "definition"), finish
        if self.code[start] == "{" and start in self.pairs:
            finish = self.pairs[start]
            return Statement(start, finish + 1, "block", self.block(start + 1, finish)), finish + 1
        control = re.match(r"(if|while|for|foreach|switch|using|lock|fixed)\s*\(", self.code[start:end])
        if control:
            opening = start + control.end() - 1
            close = self.pairs[opening]
            body_start = self.skip(close + 1, end)
            body, following = self.statement(body_start, end)
            body_items = body.body if body.kind == "block" else (body,)
            kind, otherwise = control.group(1), ()
            alternate = self.skip(following, end)
            if kind == "if" and re.match(r"else\b", self.code[alternate:end]):
                other, following = self.statement(self.skip(alternate + 4, end), end)
                otherwise = other.body if other.kind == "block" else (other,)
            if kind == "switch":
                # A case arm is its own flow path; do not sequentially kill facts.
                raw_start = body_start + 1 if body.kind == "block" else body_start
                raw_end = self.pairs.get(body_start, body.end)
                matches = list(re.finditer(r"\b(?:case\s+[^:;{}]+|default)\s*:", self.code[raw_start:raw_end]))
                arms = []
                for index, match in enumerate(matches):
                    stop = raw_start + matches[index + 1].start() if index + 1 < len(matches) else raw_end
                    arms.append(Statement(raw_start + match.end(), stop, "block",
                                          self.block(raw_start + match.end(), stop)))
                body_items = tuple(arms)
            return Statement(start, following, kind, body_items, otherwise, (opening + 1, close)), following
        if re.match(r"do\b", self.code[start:end]):
            body, following = self.statement(self.skip(start + 2, end), end)
            tail = self.skip(following, end)
            match = re.match(r"while\s*\(", self.code[tail:end])
            if match:
                opening = tail + match.end() - 1
                close = self.pairs[opening]
                items = body.body if body.kind == "block" else (body,)
                return Statement(start, close + 1, "do", items, header=(opening + 1, close)), close + 1
        if re.match(r"try\b", self.code[start:end]):
            body, following = self.statement(self.skip(start + 3, end), end)
            catches, final = [], ()
            while True:
                tail = self.skip(following, end)
                match = re.match(r"(catch|finally)\b", self.code[tail:end])
                if not match:
                    break
                position = self.skip(tail + match.end(), end)
                if self.code[position:position + 1] == "(":
                    position = self.skip(self.pairs[position] + 1, end)
                if self.code.startswith("when", position):
                    guard = self.code.find("(", position)
                    position = self.skip(self.pairs[guard] + 1, end)
                handler, following = self.statement(position, end)
                if match.group(1) == "finally":
                    final = handler.body if handler.kind == "block" else (handler,)
                else:
                    catches.append(handler)
            return Statement(start, following, "try", (body, *catches), final), following
        if re.match(r"(?:(?:public|private|protected|internal|static|abstract|sealed|partial|readonly|ref|file|unsafe)\s+)*"
                    r"(?:class|struct|namespace|record|interface)\b", self.code[start:end]):
            opening = self.code.find("{", start, end)
            semi = self.code.find(";", start, end)
            if semi >= 0 and (opening < 0 or semi < opening):
                return Statement(start, semi, "definition"), semi + 1
            if opening >= 0:
                finish = self.pairs[opening] + 1
                return Statement(start, finish, "definition"), finish
        finish = self.end_statement(start, end)
        match = re.match(r"(return|throw|break|continue|goto)\b", self.code[start:finish])
        kind = match.group(1) if match else "simple"
        if kind == "goto":
            raise ValueError("C# goto requires an explicit control-flow target; analysis is incomplete")
        if kind == "simple":
            declaration = re.match(r"\s*(?:(?:using|await|const)\s+)*(?:var|[\w.@]+(?:\s*<[^;=]+>)?(?:\[\])?\??)\s+(@?\w+)\s*=", self.code[start:finish])
            if declaration:
                spans = list(parts(self.code, start + declaration.start(1), finish))
                if len(spans) > 1:
                    children = (Statement(start, spans[0][1]),
                                *(Statement(low, high, "declarator") for low, high in spans[1:]))
                    return Statement(start, finish, "declarations", children), min(finish + 1, end)
        return Statement(start, finish, kind), min(finish + 1, end)


@dataclass
class Scope:
    bindings: dict[str, str] = field(default_factory=dict)

    def child(self):
        return Scope(dict(self.bindings))


@dataclass
class Action:
    kind: str
    span: tuple[int, int]
    bindings: dict[str, str]
    guard: tuple[str, str] | None = None


@dataclass
class Summary:
    returned: Fact = CLEAN
    effects: dict[tuple[int, str], Fact] = field(default_factory=dict)
    outputs: dict[int, Fact] = field(default_factory=dict)

    def merged(self, other):
        effects = dict(self.effects)
        for key, value in other.effects.items():
            effects[key] = join(effects.get(key, CLEAN), value)
        outputs = dict(self.outputs)
        for key, value in other.outputs.items():
            outputs[key] = join(outputs.get(key, CLEAN), value)
        return Summary(join(self.returned, other.returned), effects, outputs)


class CSharpFlow:
    rule = RULE
    message = MESSAGE
    source_pattern = SOURCE
    request_members = r"\.(?:Request\.)?(?:Query|Form|RouteValues|Headers|Cookies|Path|PathBase|RawTarget|QueryString)\b"

    def __init__(self, path: Path, text: str):
        self.path, self.text = path, text
        self.code = masked_source(text)
        self.parser = Parser(text, self.code)
        self.lines = [0, *(match.end() for match in re.finditer("\n", text))]
        self.budget = Budget()
        self.summaries = {(key, tuple(range(len(function.parameters)))): Summary()
                          for key, function in self.parser.functions.items()}
        self.dependencies = defaultdict(set)
        self.graphs = {}
        self.function = None
        self.context = None
        self.effects = {}
        self.outputs = {}
        self.returned = CLEAN
        self.aliases = {m.group(1): re.sub(r"\s", "", m.group(2)) for m in re.finditer(
            r"\busing\s+([A-Za-z_]\w*)\s*=\s*([\w.:]+)\s*;", self.code)}
        top = Function(-1, "<top-level>", (), 0, 0, len(self.code), ())
        top.body = self.parser.block(0, len(self.code))
        self.parser.functions[-1] = top
        self.summaries[(-1, ())] = Summary()
        self.pending = deque()
        self.queued = set()

    def step(self, offset, kind, label):
        line = bisect_right(self.lines, offset)
        return Step(str(self.path), line, offset - self.lines[line - 1] + 1, kind, label[:160])

    def declare(self, scope, span, *, declarator=False):
        start, end = span
        code = self.code[start:end]
        if re.fullmatch(r"\s*(?:global\s+)?using\s+@?\w+\s*=\s*[\w.:]+\s*", code):
            # Namespace/type aliases do not allocate local runtime storage.
            return
        declaration = re.match(r"\s*(@?\w+)\s*=", code) if declarator else re.match(r"\s*(?:(?:using|await|const)\s+)*(?:var|[\w.@]+(?:\s*<[^;=]+>)?(?:\[\])?\??)\s+(@?\w+)\s*(?:=|;|$)", code)
        if declaration:
            name = declaration.group(1).lstrip("@")
            scope.bindings[name] = f"{name}@{start + declaration.start(1)}"
        for match in re.finditer(r"\bout\s+(?:var|[\w.<>?\[\]]+)\s+(@?\w+)", code):
            name = match.group(1).lstrip("@")
            scope.bindings[name] = f"{name}@{start + match.start(1)}"

    def graph(self, function, aliases):
        actions, edges = {}, {}
        counter = 0
        scope = Scope({name: f"param:{aliases[index]}" for index, name in enumerate(function.parameters)})

        def node(kind, span, current, successors=(), guard=None):
            nonlocal counter
            self.budget.spend()
            result, counter = counter, counter + 1
            actions[result] = Action(kind, span, dict(current.bindings), guard)
            edges[result] = tuple(successors)
            return result

        exit_node = node("exit", (function.end, function.end), scope)

        def block(statements, following, current, break_to=None, continue_to=None, unwind=()):
            snapshots = []
            for statement in statements:
                if statement.kind in {"simple", "declarator"}:
                    self.declare(current, (statement.start, statement.end), declarator=statement.kind == "declarator")
                elif statement.kind == "declarations":
                    for item in statement.body:
                        self.declare(current, (item.start, item.end), declarator=item.kind == "declarator")
                elif statement.kind == "if":
                    self.declare(current, statement.header)
                snapshots.append(current.child())
            entry = following
            for statement, local in reversed(list(zip(statements, snapshots))):
                kind = statement.kind
                span = (statement.start, statement.end)
                successors = () if entry is None else (entry,)
                if kind == "definition":
                    continue
                if kind == "declarations":
                    # All declarations share the surrounding lexical scope.
                    for item in reversed(statement.body):
                        entry = node("simple", (item.start, item.end), local,
                                     () if entry is None else (entry,))
                    continue
                if kind == "block":
                    entry = block(statement.body, entry, local.child(), break_to, continue_to, unwind)
                elif kind == "if":
                    yes = block(statement.body, entry, local.child(), break_to, continue_to, unwind)
                    no = block(statement.otherwise, entry, local.child(), break_to, continue_to, unwind)
                    guard = self.path_guard(statement.header, local.bindings)
                    if guard:
                        variable, base, truth = guard
                        safe = yes if truth else no
                        refined = node("guard", statement.header, local, () if safe is None else (safe,), (variable, base))
                        if truth:
                            yes = refined
                        else:
                            no = refined
                    condition = self.code[slice(*statement.header)].strip()
                    targets = (yes,) if condition == "true" else (no,) if condition == "false" else (yes, no)
                    entry = node("eval", statement.header, local, tuple(target for target in targets if target is not None))
                elif kind in {"while", "for", "foreach", "do"}:
                    loop_scope = local.child()
                    header = statement.header
                    initial, update, condition = None, None, header
                    if kind == "for":
                        segments = list(parts(self.code, *header, separator=";"))
                        if len(segments) != 3:
                            raise ValueError("Invalid C# for header")
                        initial, condition, update = segments
                        self.declare(loop_scope, initial)
                    if kind == "foreach":
                        match = re.match(r"\s*(?:var|[\w.<>?\[\]]+)\s+(@?\w+)\s+in\b", self.code[slice(*header)])
                        if match:
                            name = match.group(1).lstrip("@")
                            loop_scope.bindings[name] = f"{name}@{header[0]}"
                            condition = (header[0] + match.end(), header[1])
                    test = node("eval", condition, loop_scope)
                    step = node("simple", update, loop_scope, (test,)) if update else test
                    body = block(statement.body, step, loop_scope.child(), (entry, len(unwind)),
                                 (step, len(unwind)), unwind)
                    if kind == "foreach" and match:
                        body = node("foreach", condition, loop_scope, (body,), (name, ""))
                    condition_text = self.code[slice(*condition)].strip()
                    exits = () if condition_text in {"true", ""} and kind != "foreach" else successors
                    edges[test] = tuple(target for target in (body, *exits) if target is not None)
                    if condition_text == "false":
                        edges[test] = successors
                    entry = body if kind == "do" else test
                    if initial:
                        entry = node("simple", initial, loop_scope, (entry,))
                elif kind == "switch":
                    branches = [block(arm.body, entry, local.child(), (entry, len(unwind)), continue_to, unwind)
                                for arm in statement.body]
                    entry = node("eval", statement.header, local,
                                 tuple(target for target in (*branches, entry) if target is not None))
                elif kind == "try":
                    after = block(statement.otherwise, entry, local.child(), break_to, continue_to, unwind)
                    cleanup = (*unwind, (statement.otherwise, local.child())) if statement.otherwise else unwind
                    before_ids = set(actions)
                    body = block((statement.body[0],), after, local.child(), break_to, continue_to, cleanup)
                    body_ids = set(actions) - before_ids
                    catches = tuple(target for arm in statement.body[1:]
                                    if (target := block((arm,), after, local.child(), break_to, continue_to, cleanup)) is not None)
                    # Exceptional transfers can happen after any partial body.
                    # Conservatively connect body operations to each handler.
                    for action_id in body_ids:
                        if actions[action_id].kind not in {"return", "break", "continue"}:
                            edges[action_id] = tuple(dict.fromkeys((*edges[action_id], *catches)))
                    entry = node("eval", (statement.start, statement.start), local,
                                 tuple(target for target in (body, *catches) if target is not None))
                elif kind in {"using", "lock", "fixed"}:
                    self.declare(local, statement.header)
                    body = block(statement.body, entry, local.child(), break_to, continue_to, unwind)
                    entry = node("simple", statement.header, local, () if body is None else (body,))
                else:
                    target, depth = entry, len(unwind)
                    if kind in {"break", "continue"}:
                        target, depth = (break_to if kind == "break" else continue_to) or (None, 0)
                    elif kind in {"return", "throw"}:
                        target, depth = exit_node if kind == "return" else None, 0
                    # Abrupt completion still executes enclosing finally
                    # blocks. A loop's own break/continue stays inside the try.
                    for index in range(depth, len(unwind)):
                        cleanup_statements, cleanup_scope = unwind[index]
                        target = block(cleanup_statements, target, cleanup_scope.child(),
                                       break_to, continue_to, unwind[:index])
                    entry = node(kind, span, local, () if target is None else (target,))
            return entry

        entry = block(function.body, exit_node, scope)
        return entry, actions, edges

    def call_context(self, callee, args, values, bindings, state):
        """Bind actual storage separately from values, preserving ref aliasing.

        The finite context key is the equivalence partition of by-reference
        parameters, not names or taint contents. Different calls can therefore
        reuse one summary without mixing their mutable caller state.
        """
        actuals = {}
        cells = {}
        for index, ((keyword, low, high), fact) in enumerate(zip(args, values)):
            slot = callee.parameters.index(keyword) if keyword in callee.parameters else index
            if slot >= len(callee.parameters):
                continue
            mode = callee.parameter_modes[slot]
            variable = re.fullmatch(r"\s*(?:(?:ref|out|in)\s+)?(?:(?:var|[\w.?<>\[\]]+)\s+)?(@?\w+)\s*", self.code[low:high])
            cell = bindings.get(variable.group(1).lstrip("@")) if variable else None
            if mode != "value" and cell is not None:
                cells[slot] = cell
                # Later argument evaluation may have changed this storage.
                fact = CLEAN if mode == "out" else state.get(cell, CLEAN)
            elif mode == "out":
                fact = CLEAN
            actuals[(callee.key, slot)] = fact
        representatives = {}
        aliases = []
        for slot in range(len(callee.parameters)):
            cell = cells.get(slot)
            aliases.append(representatives.setdefault(cell, slot) if cell is not None else slot)
        context = (callee.key, tuple(aliases))
        if context not in self.summaries:
            self.summaries[context] = Summary()
            self.pending.append(context)
            self.queued.add(context)
        self.dependencies[context].add(self.context)
        return self.summaries[context], actuals, cells

    def path_guard(self, span, bindings=None):
        """Recognize a root-bound prefix predicate, not a nearby magic name."""
        start, end = span
        condition = self.code[start:end].strip()
        match = re.fullmatch(
            r"!?\s*([A-Za-z_]\w*)\s*\.\s*StartsWith\s*\(\s*([A-Za-z_]\w*)\s*\+\s*Path\.DirectorySeparatorChar\s*,\s*StringComparison\.Ordinal\s*\)(.*)",
            condition, re.DOTALL)
        if not match:
            return None
        target, root, tail = match.groups()
        negative = condition.startswith("!")
        if tail.strip():
            equal = re.fullmatch(
                rf"\s*&&\s*!\s*string\.Equals\s*\(\s*{re.escape(target)}\s*,\s*{re.escape(root)}\s*,\s*StringComparison\.Ordinal\s*\)\s*",
                tail)
            if not negative or not equal:
                return None
        return target, root, not negative

    def source_fact(self, offset, label):
        step = self.step(offset, "source", label)
        return frozenset({Trace("source", (str(self.path), offset), evidence=(step,))})

    def is_source(self, name):
        root = name.split(".")[0]
        return bool(self.source_pattern.search(name) or (
            root in self.function.request_parameters and re.search(self.request_members, name)))

    def external_value(self, name, values, receiver):
        """Sink-specific transformations of an unresolved external call."""
        all_values = join(receiver, *values)
        if name in {"Path.GetFileName", "Path.GetFileNameWithoutExtension",
                    "System.IO.Path.GetFileName", "System.IO.Path.GetFileNameWithoutExtension"}:
            return CLEAN
        if name in {"Path.GetFullPath", "System.IO.Path.GetFullPath"}:
            return retag(all_values, add=CANONICAL)
        if name.endswith((".ToString", ".ConfigureAwait")):
            return receiver
        return retag(all_values, remove=CANONICAL)

    def apply_guard(self, action, state):
        variable, root = action.guard
        cell, base = action.bindings.get(variable), action.bindings.get(root)
        base_origins = {(trace.kind, trace.key) for trace in state.get(base, CLEAN)}
        if cell:
            # A user-controlled root remains unsafe; only facts confined
            # below that root are discharged by the canonical-path guard.
            retained = frozenset(trace for trace in state.get(cell, CLEAN)
                                 if not CANONICAL <= trace.tags or (trace.kind, trace.key) in base_origins)
            state[cell] = join(retained, state.get(base, CLEAN))
        return state

    def arguments(self, start, end):
        result = []
        for low, high in parts(self.code, start, end):
            named = re.match(r"\s*(@?\w+)\s*:(?!:)", self.code[low:high])
            result.append((named.group(1).lstrip("@") if named else None,
                           low + named.end() if named else low, high))
        return result

    def resolve(self, name, count):
        name = re.sub(r"\s|@", "", name).replace("global::", "")
        pieces = name.split(".")
        if pieces[0] in self.aliases:
            pieces = (self.aliases[pieces[0]] + "." + ".".join(pieces[1:])).rstrip(".").split(".")
        short, qualifier = pieces[-1], tuple(pieces[:-1])
        candidates = []
        function = self.function
        for other in self.parser.functions.values():
            if other.name != short or not len(other.parameters) - other.defaults <= count <= len(other.parameters):
                continue
            if other.parent is not None:
                if not qualifier and other.parent == function.key:
                    candidates.append(other)
                continue
            if (not qualifier or qualifier == ("this",)) and other.owner == function.owner:
                candidates.append(other)
            elif qualifier and (qualifier == other.owner or qualifier == other.owner[-1:]):
                candidates.append(other)
        return candidates

    def sink_arguments(self, name, args):
        short = name.replace("global::", "")
        constructor = short.split(".")[-1]
        method = short.split(".")[-1]
        owner = short.rsplit(".", 1)[0] if "." in short else ""
        if owner in {"File", "System.IO.File"}:
            if method in {"Move", "Copy"}:
                names = ("sourceFileName", "destFileName")
            elif method == "Replace":
                names = ("sourceFileName", "destinationFileName", "destinationBackupFileName")
            elif re.fullmatch(r"(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|OpenRead|OpenWrite|Open|Create|CreateText|WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|AppendAllLines|AppendText|Delete|Exists)(?:Async)?", method):
                names = ("path",)
            else:
                return []
        elif owner in {"Directory", "System.IO.Directory"}:
            if method == "Move":
                names = ("sourceDirName", "destDirName")
            elif method in {"CreateDirectory", "Delete", "EnumerateFiles", "GetFiles", "EnumerateFileSystemEntries", "GetFileSystemEntries", "Exists"}:
                names = ("path",)
            else:
                return []
        elif constructor in {"FileStream", "StreamReader", "StreamWriter"} and (owner in {"", "System.IO"}):
            names = ("path",)
        elif short in {"PhysicalFile", "this.PhysicalFile", "Results.PhysicalFile", "VirtualFile", "this.VirtualFile"} or method == "SendFileAsync":
            names = ("fileName", "physicalPath", "virtualPath")
            return [index for index, (keyword, _, _) in enumerate(args) if (keyword is None and index == 0) or keyword in names]
        else:
            return []
        return [index for index, (keyword, _, _) in enumerate(args)
                if (keyword is None and index < len(names)) or keyword in names]

    def parameter_fact(self, function, index):
        return frozenset({Trace("parameter", (function.key, index), evidence=(
            self.step(function.key, "parameter", function.parameters[index]),))})

    def name_value(self, name, position, state, bindings):
        if self.is_source(name):
            return self.source_fact(position, name)
        return state.get(bindings.get(name.split(".")[0], ""), CLEAN)

    def call_candidates(self, name, args, values, state, bindings, position):
        root = name.split(".")[0]
        return self.resolve(name, len(args)) if root not in bindings or root == "this" else []

    def intrinsic_value(self, name, args, state, bindings, position):
        return CLEAN

    def call_value(self, name, canonical_name, args, values, receiver, state,
                   bindings, position, opening, name_end):
        return self.external_value(canonical_name, values, receiver)

    def call_sink_facts(self, name, canonical_name, args, values, receiver, state,
                        bindings, position, opening, name_end):
        return [(index, values[index]) for index in self.sink_arguments(canonical_name, args)]

    def evaluate(self, start, end, state, bindings, depth=0):
        self.budget.spend()
        if depth > 96:
            raise AnalysisLimit("C# expression nesting limit exceeded")
        cursor, question, nesting = start, None, 0
        while cursor < end:
            char = self.code[cursor]
            if char in "([{":
                cursor = self.parser.pairs[cursor] + 1
                continue
            if char == "?" and self.code[cursor:cursor + 2] not in {"??", "?.", "?["} and self.code[cursor - 1:cursor] != "?":
                if question is None:
                    question = cursor
                nesting += 1
            elif char == ":" and question is not None and self.code[cursor:cursor + 2] != "::":
                nesting -= 1
                if not nesting:
                    self.evaluate(start, question, state, bindings, depth + 1)
                    return join(self.evaluate(question + 1, cursor, state, bindings, depth + 1),
                                self.evaluate(cursor + 1, end, state, bindings, depth + 1))
            cursor += 1
        result = CLEAN
        position = start
        while position < end:
            self.budget.spend()
            match = NAME.match(self.code, position)
            if match is not None:
                name = re.sub(r"\s|@", "", match.group()).replace("global::", "")
                stop = match.end()
                following = self.parser.skip(stop, end)
                if following < end and self.code[following] == "<":
                    cursor, nesting = following + 1, 1
                    while cursor < end and nesting and self.code[cursor] not in ";={}()":
                        nesting += (self.code[cursor] == "<") - (self.code[cursor] == ">")
                        cursor += 1
                    after = self.parser.skip(cursor, end)
                    if nesting == 0 and after < end and self.code[after] == "(":
                        following = after
                if following < end and self.code[following] == "(" and following in self.parser.pairs:
                    close = self.parser.pairs[following]
                    args = self.arguments(following + 1, close)
                    if name in {"nameof", "typeof", "sizeof"}:
                        value = self.intrinsic_value(name, args, state, bindings, position)
                    else:
                        values = [self.evaluate(low, high, state, bindings, depth + 1) for _, low, high in args]
                        root_name = name.split(".")[0]
                        candidates = self.call_candidates(name, args, values, state, bindings, position)
                        value = CLEAN
                        if candidates:
                            outputs = {}
                            for callee in candidates:
                                summary, arguments, cells = self.call_context(callee, args, values, bindings, state)
                                call = self.step(position, "call", callee.name)
                                value = join(value, substitute(summary.returned, arguments, call))
                                for key, fact in summary.effects.items():
                                    self.effects[key] = join(self.effects.get(key, CLEAN), substitute(fact, arguments, call))
                                for slot, cell in cells.items():
                                    if callee.parameter_modes[slot] in {"ref", "out"}:
                                        fact = substitute(summary.outputs.get(slot, CLEAN), arguments, call)
                                        fact = advance(fact, self.step(position, "output", callee.parameters[slot]))
                                        outputs[cell] = join(outputs.get(cell, CLEAN), fact)
                            for cell, fact in outputs.items():
                                if fact:
                                    state[cell] = fact
                                else:
                                    state.pop(cell, None)
                        else:
                            canonical_name = name
                            root_name = name.split(".")[0]
                            if root_name in self.aliases:
                                canonical_name = self.aliases[root_name] + name[len(root_name):]
                            receiver = state.get(bindings.get(root_name, ""), CLEAN)
                            all_values = join(receiver, *values)
                            if root_name in bindings:
                                # A local named File or Path is not a proof of
                                # System.IO type identity.
                                canonical_name = "<instance>." + canonical_name
                            value = self.call_value(name, canonical_name, args, values, receiver,
                                                    state, bindings, position, following, stop)
                            if self.is_source(name):
                                value = join(value, self.source_fact(position, name))
                            if name.endswith(".TryGetValue") and self.is_source(name):
                                for _, low, high in args:
                                    output = re.fullmatch(r"\s*out\s+(?:(?:var|[\w.?<>\[\]]+)\s+)?(@?\w+)\s*", self.code[low:high])
                                    if output:
                                        cell = bindings.get(output.group(1).lstrip("@"))
                                        if cell:
                                            state[cell] = self.source_fact(position, name)
                                value = CLEAN
                            elif any(re.match(r"\s*(?:ref|out)\b", self.code[low:high]) for _, low, high in args):
                                # An unresolved helper may copy any of its
                                # inputs into ref/out storage; it cannot prove
                                # that an already tainted ref becomes safe.
                                for _, low, high in args:
                                    output = re.fullmatch(r"\s*(?:ref|out)\s+(?:(?:var|[\w.?<>\[\]]+)\s+)?(@?\w+)\s*", self.code[low:high])
                                    cell = bindings.get(output.group(1).lstrip("@")) if output else None
                                    if cell:
                                        state[cell] = join(state.get(cell, CLEAN), retag(all_values, remove=CANONICAL))
                            for index, source in self.call_sink_facts(name, canonical_name, args, values,
                                                                      receiver, state, bindings, position,
                                                                      following, stop):
                                fact = advance(source, self.step(position, "sink", canonical_name))
                                if fact:
                                    key = (position, canonical_name)
                                    self.effects[key] = join(self.effects.get(key, CLEAN), fact)
                    result = join(result, value)
                    position = close + 1
                    continue
                root_name = name.split(".")[0]
                result = join(result, self.name_value(name, position, state, bindings))
                position = stop
                continue
            if self.code[position] in "([{":
                close = self.parser.pairs[position]
                result = join(result, self.evaluate(position + 1, close, state, bindings, depth + 1))
                position = close + 1
                continue
            position += 1
        # Concatenation/arithmetic is no longer a proven canonical path.
        cursor = start
        while cursor < end:
            if self.code[cursor] in "([{":
                cursor = self.parser.pairs[cursor] + 1
                continue
            if self.code[cursor] in "+-*/%":
                result = retag(result, remove=CANONICAL)
                break
            cursor += 1
        return result

    def transfer(self, action, state):
        start, end = action.span
        code = self.code[start:end]
        if action.kind == "exit":
            for slot, name in enumerate(self.function.parameters):
                if self.function.parameter_modes[slot] in {"ref", "out"}:
                    fact = state.get(action.bindings[name], CLEAN)
                    self.outputs[slot] = join(self.outputs.get(slot, CLEAN), fact)
            return state
        if action.kind == "guard":
            return self.apply_guard(action, state)
        if action.kind == "foreach":
            cell = action.bindings[action.guard[0]]
            state[cell] = self.evaluate(start, end, state, action.bindings)
            return state
        if action.kind in {"break", "continue"}:
            return state
        if action.kind == "return":
            offset = re.match(r"\s*return\b", code)
            value = self.evaluate(start + offset.end() if offset else start, end, state, action.bindings)
            self.returned = join(self.returned, advance(value, self.step(start, "return", self.function.name)))
            return state
        assignment = re.match(
            r"\s*(?:(?:(?:using|await|const)\s+)*(?:var|[\w.@]+(?:\s*<[^;=]+>)?(?:\[\])?\??)\s+)?"
            r"(@?\w+)\s*(\+=|=(?!=|>))\s*", code)
        if assignment:
            name = assignment.group(1).lstrip("@")
            value = self.evaluate(start + assignment.end(), end, state, action.bindings)
            cell = action.bindings.get(name)
            if cell:
                if assignment.group(2) == "+=":
                    value = retag(join(state.get(cell, CLEAN), value), remove=CANONICAL)
                state[cell] = advance(value, self.step(start, "assignment", name))
                if not state[cell]:
                    state.pop(cell, None)
        else:
            self.evaluate(start, end, state, action.bindings)
        return state

    def analyze_function(self, function, context):
        self.function = function
        self.context = context
        self.effects, self.returned, self.outputs = {}, CLEAN, {}
        aliases = context[1]
        if context not in self.graphs:
            self.graphs[context] = self.graph(function, aliases)
        entry, actions, edges = self.graphs[context]
        if entry is not None:
            initial = {}
            for index, name in enumerate(function.parameters):
                if function.parameter_modes[index] == "out":
                    continue
                cell = f"param:{aliases[index]}"
                fact = self.parameter_fact(function, index)
                initial[cell] = join(initial.get(cell, CLEAN), fact)
            solve(entry, initial, edges, lambda key, state: self.transfer(actions[key], state), self.budget)
        return Summary(self.returned, dict(self.effects), dict(self.outputs))

    def analyze(self):
        self.pending = deque(sorted(self.summaries))
        self.queued = set(self.pending)
        while self.pending:
            self.budget.spend()
            key = self.pending.popleft()
            self.queued.remove(key)
            summary = self.summaries[key].merged(self.analyze_function(self.parser.functions[key[0]], key))
            if summary != self.summaries[key]:
                self.summaries[key] = summary
                for caller in sorted(self.dependencies[key]):
                    if caller not in self.queued:
                        self.pending.append(caller)
                        self.queued.add(caller)
        effects = {}
        for summary in self.summaries.values():
            for key, fact in summary.effects.items():
                concrete = frozenset(trace for trace in fact if trace.kind == "source")
                if concrete:
                    effects[key] = join(effects.get(key, CLEAN), concrete)
        for (offset, sink), fact in sorted(effects.items()):
            location = self.step(offset, "sink", sink)
            witnesses = sorted(fact, key=lambda trace: (len(trace.evidence), trace.evidence, trace.key))
            yield {"rule": self.rule, "path": str(self.path), "line": location.line,
                   "col": location.column, "severity": "critical", "message": self.message,
                   "extras": {"taint_path": [step.record() for step in witnesses[0].evidence],
                              "source_count": len({trace.key for trace in fact})}}


def run(ctx: RunContext) -> Iterable[dict]:
    if not ctx.rule_enabled(RULE):
        return
    suppressions = SourceSuppressions("csharp")
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        text = path.read_text(encoding="utf-8-sig")
        # The filter is only an optimization; no cross-file claims in phase 1.
        if not re.search(r"\b(?:Request|request|req|FileName|HttpRequest|HttpContext)\b", text):
            continue
        flow = CSharpFlow(path, text)
        for finding in flow.analyze():
            if not suppressions.is_suppressed(path, finding["line"], RULE):
                yield finding


def analyze(path: Path, issues):
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    for finding in run(RunContext(lang="csharp", files=[path])):
        try:
            display = str(path.resolve().relative_to(Path.cwd()))
        except ValueError:
            display = str(path)
        trace = " -> ".join(step["label"] for step in finding["extras"]["taint_path"])
        issues.append((display, finding["line"], f"{lines[finding['line'] - 1].strip()}  [{trace}]"))


def main(argv=None) -> int:
    argv = sys.argv if argv is None else list(argv)
    if len(argv) < 3:
        raise ValueError("Expected project directory and NUL-separated file list")
    paths = [Path(raw.decode("utf-8", "surrogateescape")) for raw in Path(argv[2]).read_bytes().split(b"\0") if raw]
    issues = []
    for path in paths:
        analyze(path, issues)
    for path, line, code in issues:
        print(f"{path}:{line}:{code}")
    return 0


def _selftest_direct_source_to_sink():
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ubs-csharp-flow-") as tmp:
        path = Path(tmp) / "test.cs"
        path.write_text('var p = Request.Query["path"];\nSystem.IO.File.ReadAllText(p);\n')
        findings = list(run(RunContext(lang="csharp", files=[path])))
        assert len(findings) == 1 and findings[0]["line"] == 2, findings


def _selftest_ubs_ignore_suppression():
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ubs-csharp-flow-") as tmp:
        path = Path(tmp) / "test.cs"
        path.write_text('var p = Request.Query["path"];\nFile.ReadAllText(p); // ubs:ignore\n')
        assert not list(run(RunContext(lang="csharp", files=[path])))


def _selftest_containment_guard_suppression():
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ubs-csharp-flow-") as tmp:
        path = Path(tmp) / "test.cs"
        path.write_text('var p = Request.Query["path"];\nvar root = "/srv/uploads";\n'
                        'var full = Path.GetFullPath(root + p);\n'
                        'if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { return; }\n'
                        'File.ReadAllText(full);\n')
        assert not list(run(RunContext(lang="csharp", files=[path])))


SELF_TESTS = (("direct_source_to_sink", _selftest_direct_source_to_sink),
              ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
              ("containment_guard_suppression", _selftest_containment_guard_suppression))
register(Analyzer(layer="taint", lang="csharp", name="taint_csharp_request", run=run, selftests=SELF_TESTS))
