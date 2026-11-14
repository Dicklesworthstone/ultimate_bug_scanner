"""ubs_core.analyzers.narrowing_go — Go error/nil-guard narrowing analysis (bead 1b9j.4).

Detects partial guards whose block falls through, leaving the guarded value
unusable on the continuation path:

1. `if err != nil { log/... }` whose block does not exit (no return/continue/
   break/goto, panic, os.Exit, log.Fatal*, or runtime.Goexit) followed by use
   of the guarded error or of the companion value from the `x, err := ...`
   assignment that produced it — the companion may be a zero value whenever
   the guard fell through (rule go.narrowing.partial_err_guard).
2. `if p == nil { log/... }` whose block does not exit followed by a
   `p.field` / `p[index]` dereference — p may still be nil on the fallthrough
   path.

Scanning runs on comment/string-stripped text with offsets preserved. Only
exact single conditions narrow (`||`/`&&` tails change the contract and are
left alone). Three guards count as handled and are not scanned: an exiting
block (narrowing holds on the fallthrough path), a re-check
`if name ==/!= nil` guard between the partial guard and a candidate use (the
re-check is the narrowing point), and an init-scoped guard
(`if err := f(); err != nil {` — the names are invisible past the chain in
valid Go). A non-exiting guard whose error branch reassigns the companion
likewise re-establishes the value for the fallthrough path. Also exposes a
structured `run(ctx)` for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Callable, Iterable

from ubs_core.io import extract_statement_region, find_block_end, line_col, skip_ws
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", ".hg", ".svn", "vendor", "node_modules", "dist", "build", "bin", ".venv"}

_RULE = "go.narrowing.partial_err_guard"

NIL_RULE = "go.narrowing.nil_dereference"
RULE_METADATA = {
    NIL_RULE: {
        "language": "go", "category_id": "golang.defer-nil", "severity": "warning",
        "confidence": "unknown", "family": "type_narrowing", "status": "active",
        "message": "A proven nil pointer path reaches a dereference",
        "remediation": "Return on the nil path or assign a non-nil pointer before dereferencing it.",
    },
}


class NilFlowLimit(ValueError):
    """A selected nil-pointer flow could not be completed."""


class _NilPointers:
    """Bounded local pointer facts, separate from the legacy guard heuristics.

    A nullable type alone is not evidence. Only zero initialization, an explicit
    nil assignment, or an executed nil branch introduces a reportable nil path.
    Fields require a declared struct member; pointer receiver methods and maps
    are not implicit dereferences. Escaping a pointer *cell* invalidates it at
    opaque calls, without invalidating independent copies of its pointer value.
    """

    NIL, NONNIL, UNKNOWN, TRUE, FALSE = 1, 2, 4, 8, 16
    CONTROL = "\0unresolved-control"
    IDENT = r"[A-Za-z_]\w*"

    def __init__(self, text: str, max_steps: int = 20_000):
        from ubs_core.analyzers.taint_go import _Parser, _Scope, _functions, _masked_source, _parts

        self.text = text
        self.code = _masked_source(text)
        self.parser = _Parser(self.code)
        self.scope_type, self.parts = _Scope, _parts
        self.remaining = max_steps
        self.findings: dict[int, str] = {}
        self.escaped: set[str] = set()
        stack = []
        for position, char in enumerate(self.code):
            if char in "([{":
                stack.append(char)
            elif char in ")]}":
                if not stack or stack.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                    raise NilFlowLimit("Go nil-pointer syntax is unbalanced; analysis is incomplete")
        if stack:
            raise NilFlowLimit("Go nil-pointer syntax is unbalanced; analysis is incomplete")
        self.functions = _functions(self.code, self.parser)
        self.function_names = {function.name for function in self.functions}
        self.package_names = set(self.function_names)
        for node in self.parser.block(0, len(self.code)):
            declarations = node.body if node.kind == "declarations" else (node,)
            for declaration in declarations:
                source = self.code[declaration.start:declaration.end]
                if declaration.kind in {"var", "const", "type"}:
                    source = declaration.kind + " " + source
                names = re.match(r"(?:var|const|type)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)", source)
                if names:
                    self.package_names.update(name.strip() for name in names.group(1).split(","))
        self.fields: dict[str, set[str]] = {}
        self.array_fields: dict[str, set[str]] = {}
        repeated = set()
        for match in re.finditer(r"\btype\s+(\w+)\s+struct\s*\{", self.code):
            name = match.group(1)
            if name in self.fields:
                repeated.add(name)
            close = self.parser.pairs[match.end() - 1]
            fields, arrays = set(), set()
            for node in self.parser.block(match.end(), close):
                field = re.match(r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+(\S.*)",
                                 self.code[node.start:node.end], re.DOTALL)
                if field:
                    names = {part.strip() for part in field.group(1).split(",")}
                    fields.update(names)
                    if re.match(r"\[\s*(?!\])[^]]+\]", field.group(2)):
                        arrays.update(names)
            self.fields[name] = fields
            self.array_fields[name] = arrays
        for name in repeated:
            self.fields.pop(name, None)
            self.array_fields.pop(name, None)
        # unsafe's size/alignment operations do not evaluate their operands.
        # Read actual import declarations, never matching text in a literal.
        self.unsafe_imports = set()
        self.unsafe_dot = False
        self.imports = {}
        self.dot_imports = {}
        source = _masked_source(text, strings=False)
        for match in re.finditer(r"\bimport\b", self.code):
            start = self.parser.skip(match.end(), len(self.code))
            if start < len(self.code) and self.code[start] == "(":
                close = self.parser.pairs[start]
                specs = [(node.start, node.end) for node in self.parser.block(start + 1, close)]
            else:
                specs = [(start, self.parser.statement_end(start, len(self.code)))]
            for left, right in specs:
                spec = re.fullmatch(r'\s*(?:([A-Za-z_]\w*|\.)\s*)?["`]([^"`]+)["`]\s*', source[left:right])
                if spec:
                    alias, package = spec.group(1), spec.group(2)
                    if alias == ".":
                        for member in {"os": ("Exit",), "runtime": ("Goexit",),
                                       "log": ("Fatal", "Fatalf", "Fatalln"),
                                       "unsafe": ("Sizeof", "Alignof", "Offsetof")}.get(package, ()):
                            self.dot_imports[member] = package
                    elif alias != "_":
                        self.imports[alias or package.rsplit("/", 1)[-1]] = package
                    if package != "unsafe":
                        continue
                    if spec.group(1) == ".":
                        self.unsafe_dot = True
                    elif spec.group(1) != "_":
                        self.unsafe_imports.add(spec.group(1) or "unsafe")

    def predeclared(self, name, scope):
        return name not in scope.bindings and name not in self.package_names

    def native_package(self, root, member, scope):
        if not self.predeclared(root, scope):
            return None
        return self.imports.get(root) if member else self.dot_imports.get(root)

    def step(self):
        self.remaining -= 1
        if self.remaining < 0:
            raise NilFlowLimit("Go nil-pointer work limit exceeded; analysis is incomplete")

    @staticmethod
    def join(*states):
        present = [state for state in states if state is not None]
        if not present:
            return None
        joined = {}
        for key in set().union(*(state.keys() for state in present)):
            values = [state[key] for state in present if key in state]
            kinds = {value[0] for value in values}
            mask = 0
            for _, flags in values:
                mask |= flags
            joined[key] = (next(iter(kinds)) if len(kinds) == 1 else "", mask)
        return joined

    def fact(self, name, state, scope):
        return state.get(scope.bindings.get(name), ("", self.UNKNOWN))

    def parameters(self, text, scope, state, offset, *, zero=False):
        kind = ""
        for start, end in reversed(self.parts(text)):
            part = text[start:end].strip()
            match = re.fullmatch(r"([A-Za-z_]\w*)\s+(.+)", part, re.DOTALL)
            if match:
                name, kind = match.groups()
            elif kind and re.fullmatch(self.IDENT, part):
                name = part
            else:
                kind = ""
                continue
            key = scope.declare(name, offset + start)
            typename = re.sub(r"\s+", "", kind)
            state[key] = (typename, self.NIL if zero and typename.startswith("*") else self.UNKNOWN)

    def analyze(self):
        for function in self.functions:
            # Local pointer facts require a pointer type or address expression.
            # Include the full header so receiver/parameter/result types keep
            # their coverage; literals and comments are already masked here.
            source = self.code[function.start:function.end]
            if "*" not in source and "&" not in source:
                continue
            self.step()
            scope, state = self.scope_type(), {}
            self.escaped = set()
            header = re.match(r"func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*(?:\[[^]]*\]\s*)?\(",
                              self.code[function.start:function.end])
            if header is None:
                continue
            opening = function.start + header.end() - 1
            close = self.parser.pairs[opening]
            self.parameters(self.code[opening + 1:close], scope, state, opening + 1)
            receiver = re.match(r"func\s*\(([^)]*)\)", self.code[function.start:opening])
            if receiver:
                self.parameters(receiver.group(1), scope, state, function.start + receiver.start(1))
            result = self.parser.skip(close + 1, function.end)
            if result < function.end and self.code[result] == "(":
                finish = self.parser.pairs[result]
                self.parameters(self.code[result + 1:finish], scope, state, result + 1, zero=True)
            self.block(function.body, state, scope)

    def logical_split(self, start, end, operator):
        position = start
        while position < end:
            if self.code[position] in "([{":
                position = self.parser.pairs[position] + 1
                continue
            if self.code.startswith(operator, position):
                return position
            position += 1
        return None

    def trim(self, start, end):
        while start < end and self.code[start].isspace():
            start += 1
        while end > start and self.code[end - 1].isspace():
            end -= 1
        while start < end and self.code[start] == "(" and self.parser.pairs.get(start) == end - 1:
            start, end = self.trim(start + 1, end - 1)
        return start, end

    def condition(self, start, end, state, scope):
        if state is None:
            return None, None
        self.step()
        start, end = self.trim(start, end)
        for operator in ("||", "&&"):
            split = self.logical_split(start, end, operator)
            if split is not None:
                yes, no = self.condition(start, split, state, scope)
                right_yes, right_no = self.condition(split + 2, end, no if operator == "||" else yes, scope)
                return (self.join(yes, right_yes), right_no) if operator == "||" else (
                    right_yes, self.join(no, right_no))
        expression = self.code[start:end]
        if expression in {"true", "false"} and self.predeclared(expression, scope):
            return (state, None) if expression == "true" else (None, state)
        if re.fullmatch(self.IDENT, expression):
            kind, flags = self.fact(expression, state, scope)
            if kind == "bool" and flags in {self.TRUE, self.FALSE}:
                return (state, None) if flags == self.TRUE else (None, state)
        if expression.startswith("!") and not expression.startswith("!="):
            yes, no = self.condition(start + 1, end, state, scope)
            return no, yes
        match = re.fullmatch(r"(?:(\w+)\s*(==|!=)\s*nil|nil\s*(==|!=)\s*(\w+))", expression)
        if match and self.predeclared("nil", scope):
            name, operator = (match.group(1), match.group(2)) if match.group(1) else (match.group(4), match.group(3))
            kind, mask = self.fact(name, state, scope)
            if kind.startswith("*"):
                key = scope.bindings[name]
                nil, present = state.copy(), state.copy()
                nil[key], present[key] = (kind, self.NIL), (kind, self.NONNIL)
                if mask == self.NONNIL:
                    nil = None
                if mask == self.NIL:
                    present = None
                return (nil, present) if operator == "==" else (present, nil)
        state = self.expression(start, end, state, scope, boolean=False)
        return state, state

    def expression(self, start, end, state, scope, *, boolean=True):
        if state is None:
            return None
        self.step()
        start, end = self.trim(start, end)
        if boolean and any(self.logical_split(start, end, op) is not None for op in ("||", "&&")):
            return self.join(*self.condition(start, end, state, scope))
        state = state.copy()
        tokens = list(re.finditer(r"[A-Za-z_]\w*|\d+|&&|\|\||!=|==|:=|\S", self.code[start:end]))
        index, previous = 0, ""
        while index < len(tokens):
            self.step()
            token = tokens[index]
            word, position = token.group(), start + token.start()
            following = tokens[index + 1].group() if index + 1 < len(tokens) else ""
            if word == "func":
                opening = self.parser.body_open(position + 4, end)
                if opening is not None and opening in self.parser.pairs:
                    close = self.parser.pairs[opening]
                    captures = set(re.findall(self.IDENT, self.code[opening + 1:close]))
                    self.escaped.update(scope.bindings[name] for name in captures
                                        if self.fact(name, state, scope)[0].startswith("*"))
                    while index + 1 < len(tokens) and start + tokens[index + 1].start() <= close:
                        index += 1
                    previous = "}"
                    index += 1
                    continue
            # Native unsafe operands are unevaluated, including *p and p.F.
            unsafe = (self.unsafe_dot and word in {"Sizeof", "Alignof", "Offsetof"}
                      and self.predeclared(word, scope))
            call_index = index + 1
            if (word in self.unsafe_imports and self.predeclared(word, scope) and following == "."
                    and index + 3 < len(tokens)
                    and tokens[index + 2].group() in {"Sizeof", "Alignof", "Offsetof"}):
                unsafe, call_index = True, index + 3
            if unsafe and call_index < len(tokens) and tokens[call_index].group() == "(":
                close = self.parser.pairs[start + tokens[call_index].start()]
                while index + 1 < len(tokens) and start + tokens[index + 1].start() <= close:
                    index += 1
                previous = ")"
                index += 1
                continue
            if word in {"len", "cap"} and self.predeclared(word, scope) and following == "(":
                opening = start + tokens[index + 1].start()
                close = self.parser.pairs[opening]
                left, right = self.trim(opening + 1, close)
                argument = self.code[left:right]
                operand = re.fullmatch(r"\*\s*([A-Za-z_]\w*)", argument)
                field = re.fullmatch(r"([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)", argument)
                array = (operand is not None and re.match(
                    r"\*\[(?!\])[^]]+\]", self.fact(operand.group(1), state, scope)[0]))
                if field:
                    kind = self.fact(field.group(1), state, scope)[0]
                    array = kind.startswith("*") and field.group(2) in self.array_fields.get(kind[1:], ())
                if array:
                    # The length/capacity of this fixed array is constant;
                    # Go does not evaluate the otherwise unsafe *p operand.
                    while index + 1 < len(tokens) and start + tokens[index + 1].start() <= close:
                        index += 1
                    previous = ")"
                    index += 1
                    continue
            if word == "&" and re.fullmatch(self.IDENT, following):
                after = tokens[index + 2].group() if index + 2 < len(tokens) else ""
                if after not in {".", "["} and following in scope.bindings:
                    self.escaped.add(scope.bindings[following])
            name, location = None, position
            if (word == "*" and re.fullmatch(self.IDENT, following)
                    and previous not in {")", "]"}
                    and (not previous or not re.fullmatch(r"[A-Za-z_]\w*|\d+", previous)
                         or previous in {"return", "case"})):
                name = following
            elif (re.fullmatch(self.IDENT, word) and following == "." and index + 2 < len(tokens)):
                kind, _ = self.fact(word, state, scope)
                if kind.startswith("*") and tokens[index + 2].group() in self.fields.get(kind[1:], ()):
                    name = word
            if name:
                kind, mask = self.fact(name, state, scope)
                if kind.startswith("*") and mask & self.NIL:
                    if self.CONTROL in state:
                        raise NilFlowLimit("Go nil-pointer control flow is unresolved; analysis is incomplete")
                    self.findings[location] = name
                    remaining = mask & ~self.NIL
                    if not remaining:
                        return None
                    state[scope.bindings[name]] = (kind, remaining)
            if word in {"(", "[", "{"}:
                close = self.parser.pairs[position]
                call = (word == "(" and previous
                        and (re.fullmatch(self.IDENT, previous) or previous in {")", "]", "}"}))
                for left, right in self.parts(self.code[position + 1:close]):
                    left, right = position + 1 + left, position + 1 + right
                    if word == "{":
                        colon = self.logical_split(left, right, ":")
                        if colon is not None:
                            left = colon + 1
                    state = self.expression(left, right, state, scope)
                    if state is None:
                        return None
                if call:
                    for key in self.escaped.intersection(state):
                        state[key] = (state[key][0], self.UNKNOWN)
                while index + 1 < len(tokens) and start + tokens[index + 1].start() <= close:
                    index += 1
                previous = self.code[close]
                index += 1
                continue
            previous = word
            index += 1
        return state

    def value(self, start, end, state, scope, kind=""):
        start, end = self.trim(start, end)
        expression = self.code[start:end]
        if expression == "nil" and self.predeclared("nil", scope):
            return kind, self.NIL
        if expression in {"true", "false"} and self.predeclared(expression, scope):
            return kind or "bool", self.TRUE if expression == "true" else self.FALSE
        if re.fullmatch(self.IDENT, expression):
            incoming = self.fact(expression, state, scope)
            return kind or incoming[0], incoming[1]
        if expression.startswith("&") and not expression.startswith("&*"):
            constructor = re.match(r"&\s*([A-Za-z_]\w*)\s*\{", expression)
            return kind or ("*" + constructor.group(1) if constructor else "*"), self.NONNIL
        cast = re.fullmatch(r"\(\s*(\*+[A-Za-z_]\w*)\s*\)\s*\(\s*nil\s*\)", expression)
        if cast and self.predeclared("nil", scope):
            return kind or cast.group(1), self.NIL
        return kind, self.UNKNOWN

    def simple(self, node, state, scope):
        start, end = node.start, node.end
        text = self.code[start:end].strip()
        declaration = re.match(r"(var|const)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)(.*)", text, re.DOTALL)
        if node.kind in {"var", "const"}:
            declaration = re.match(r"(var|const)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)(.*)",
                                   node.kind + " " + text, re.DOTALL)
        assignment = re.match(r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(:=|=(?!=))", text)
        if declaration or assignment:
            kind = ""
            if declaration:
                names = [name.strip() for name in declaration.group(2).split(",")]
                tail = declaration.group(3)
                kind = re.sub(r"\s+", "", tail.split("=", 1)[0])
                equal = self.code.find("=", start, end)
                if equal < 0:
                    state = state.copy()
                    for name in names:
                        state[scope.declare(name, start)] = (kind, self.NIL if kind.startswith("*") else self.UNKNOWN)
                    return state
                right = equal + 1
            else:
                names = [name.strip() for name in assignment.group(1).split(",")]
                right = start + self.code[start:end].index(assignment.group()) + assignment.end()
            values = []
            for left, finish in self.parts(self.code[right:end]):
                state = self.expression(right + left, right + finish, state, scope)
                if state is None:
                    return None
                values.append(self.value(right + left, right + finish, state, scope, kind))
            state = state.copy()
            for index, name in enumerate(names):
                if name == "_":
                    continue
                declare = declaration is not None or assignment.group(2) == ":="
                key = scope.declare(name, start) if declare else scope.bindings.get(name)
                if key is None:
                    continue
                typename = kind or state.get(key, ("", self.UNKNOWN))[0]
                value = values[index] if len(values) == len(names) else (typename, self.UNKNOWN)
                state[key] = (typename or value[0], value[1])
            return state
        if text.startswith("type "):
            return state
        returning = re.match(r"return\b", self.code[start:end])
        if returning:
            right = start + returning.end()
            for left, finish in self.parts(self.code[right:end]):
                state = self.expression(right + left, right + finish, state, scope)
            return None
        state = self.expression(start, end, state, scope)
        if re.match(r"panic\s*\(", text) and self.predeclared("panic", scope):
            return None
        call = re.match(r"([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?\s*\(", text)
        if call:
            root, member = call.groups()
            package = self.native_package(root, member, scope)
            operation = member or root
            if operation in {"os": {"Exit"}, "runtime": {"Goexit"},
                              "log": {"Fatal", "Fatalf", "Fatalln"}}.get(package, ()):
                return None
        return state

    def block(self, nodes, state, scope):
        for node in nodes:
            if state is None:
                break
            self.step()
            if node.kind == "if":
                inner = scope.child()
                header = self.code[node.start + 2:node.end]
                parts = self.parts(header, ";")
                if len(parts) > 1:
                    from ubs_core.analyzers.taint_go import _Statement
                    left, end = parts[0]
                    state = self.simple(_Statement(node.start + 2 + left, node.start + 2 + end), state, inner)
                left, end = parts[-1]
                yes, no = self.condition(node.start + 2 + left, node.start + 2 + end, state, inner)
                state = self.join(self.block(node.body, yes, inner.child()),
                                  self.block(node.otherwise, no, inner.child()))
            elif node.kind == "block":
                state = self.block(node.body, state, scope.child())
            elif node.kind == "declarations":
                state = self.block(node.body, state, scope)
            elif node.kind in {"for", "switch", "select"}:
                # Do not make an unrelated loop a failed nil-pointer scan.
                # Unsupported control is remembered, and only a demanded nil
                # dereference makes the result incomplete. Traverse its body
                # speculatively so local nil proofs cannot become clean hits.
                uncertain = {key: (kind, self.UNKNOWN | (flags & self.NIL))
                             for key, (kind, flags) in state.items()}
                uncertain[self.CONTROL] = ("", self.UNKNOWN)
                inner = scope.child()
                body = self.block(node.body, uncertain.copy(), inner)
                state = self.join(uncertain, body)
            elif node.kind in {"case", "default"}:
                state = self.join(state, self.block(node.body, state.copy(), scope.child()))
            elif re.match(r"(?:goto|break|continue)\b", self.code[node.start:node.end]):
                state = state.copy()
                state[self.CONTROL] = ("", self.UNKNOWN)
            else:
                state = self.simple(node, state, scope)
        return state


def run_nil_dereferences(ctx: RunContext) -> Iterable[dict]:
    """Only the independently qualified pointer family runs by default."""
    if os.environ.get("UBS_SKIP_TYPE_NARROWING") == "1" or not ctx.rule_enabled(NIL_RULE):
        return
    for path in ctx.files:
        if path.suffix.lower() != ".go":
            continue
        analysis = _NilPointers(path.read_text(encoding="utf-8"))
        failure = None
        try:
            analysis.analyze()
        except (NilFlowLimit, RecursionError) as exc:
            failure = exc
        for offset, name in sorted(analysis.findings.items()):
            line, col = line_col(analysis.text, offset)
            yield {"rule": NIL_RULE, "path": str(path), "line": line, "col": col,
                   "layer": "narrowing", "lang": "go", "category_id": "golang.defer-nil",
                   "severity": "warning", "message": f"{name} is dereferenced on a proven nil path"}
        if failure is not None:
            raise failure

# `if err != nil {` / `if p == nil {`, optionally behind an init statement
# (`if v, err := f(); err != nil {`). The lookahead keeps match.end() on the
# `{` so extract_statement_region sees the guard body directly.
ERR_GUARD_PATTERN = re.compile(
    r"\bif\b(?:[^;{}]*;)?\s*\(?\s*([A-Za-z_]\w*)\s*!=\s*nil\s*\)?(?=\{)", re.MULTILINE
)
NIL_GUARD_PATTERN = re.compile(
    r"\bif\b(?:[^;{}]*;)?\s*\(?\s*([A-Za-z_]\w*)\s*==\s*nil\s*\)?(?=\{)", re.MULTILINE
)
RECHECK_PATTERN = re.compile(
    r"\bif\b(?:[^;{}]*;)?\s*\(?\s*([A-Za-z_]\w*)\s*(?:==|!=)\s*nil\s*\)?(?=\{)", re.MULTILINE
)
# `x, err := ...` / `x, err = ...` (longer tuples allowed, `err` must be last).
PAIR_ASSIGN_PATTERN = re.compile(
    r"\b([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*?)\s*,\s*([A-Za-z_]\w*)\s*:?=(?!=)"
)
ELSE_PATTERN = re.compile(r"\belse\b")
EXIT_PATTERN = re.compile(
    r"\b(?:return|continue|break|goto)\b"
    r"|\bpanic\s*\("
    r"|\bos\.Exit\s*\("
    r"|\blog\.(?:Fatal|Fatalf|Fatalln)\s*\("
    r"|\bruntime\.Goexit\s*\("
)
ASSIGN_TEMPLATE = r"\b{name}\s*:?=(?!=)"
REF_TEMPLATE = r"\b{name}\b"
MEMBER_TEMPLATE = r"\b{name}\s*\."
INDEX_TEMPLATE = r"\b{name}\s*\["

_ERR_MESSAGE = "{name} used after non-exiting err guard"
_NIL_MESSAGE = "{name} dereferenced after non-exiting nil guard"


def iter_go_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() == ".go" and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for path in root.rglob("*.go"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def contains_exit(block_text: str) -> bool:
    return bool(EXIT_PATTERN.search(block_text))


def skip_optional_else(text: str, idx: int) -> int:
    """Step over an `else` / `else if` branch following a guard block."""
    idx = skip_ws(text, idx)
    match = ELSE_PATTERN.match(text, idx)
    if not match:
        return idx
    idx = skip_ws(text, match.end())
    if idx < len(text) and text[idx] == "{":
        return find_block_end(text, idx) + 1
    brace = text.find("{", idx)
    if brace == -1:
        _, end = extract_statement_region(text, idx)
        return end
    return find_block_end(text, brace) + 1


def companions_for(text: str, match: re.Match[str], name: str) -> list[str]:
    """Return companion names bound alongside `name` by the nearest pair assignment.

    The init statement of the guard itself (`if data, err := f(); err != nil {`)
    takes precedence over earlier assignments elsewhere in the file.
    """
    regions = (text[match.start() : match.start(1)], text[: match.start()])
    for region in regions:
        found: list[str] = []
        for pair in PAIR_ASSIGN_PATTERN.finditer(region):
            if pair.group(2) == name:
                found = [part.strip() for part in pair.group(1).split(",")]
        if found:
            return found
    return []


def guard_is_scoped(text: str, match: re.Match[str]) -> bool:
    """True when the guarded name is scoped to the if statement's init clause.

    `if err := f(); err != nil { ... }` makes the names invisible past the
    if/else chain in valid Go, so nothing after the guard can use them.
    """
    return ";" in text[match.start() : match.start(1)]


_ASSIGN_CACHE: dict[str, re.Pattern[str]] = {}


def _assign_pattern(name: str) -> re.Pattern[str]:
    rx = _ASSIGN_CACHE.get(name)
    if rx is None:
        rx = _ASSIGN_CACHE[name] = re.compile(ASSIGN_TEMPLATE.format(name=re.escape(name)))
    return rx


def _ref_patterns(name: str) -> tuple[re.Pattern[str], ...]:
    return (re.compile(REF_TEMPLATE.format(name=re.escape(name))),)


def _deref_patterns(name: str) -> tuple[re.Pattern[str], ...]:
    return (
        re.compile(MEMBER_TEMPLATE.format(name=re.escape(name))),
        re.compile(INDEX_TEMPLATE.format(name=re.escape(name))),
    )


def find_unsafe_use(
    text: str,
    start: int,
    watch: tuple[str, ...],
    use_patterns: Callable[[str], tuple[re.Pattern[str], ...]],
) -> tuple[int, int, str] | None:
    """Locate the first offending use of a watched name at/after `start`.

    Returns (line, col, name) or None. The search gives up when a watched name
    is reassigned first (the value was refreshed) or when a re-check
    `if name ==/!= nil` guard appears first (the re-check is the narrowing
    point). An offending use before either wins.
    """
    best: tuple[int, int, str, re.Match[str], str] | None = None
    for name in watch:
        assign = _assign_pattern(name).search(text, start)
        if assign and (best is None or (assign.start(), 0) < best[:2]):
            best = (assign.start(), 0, "assign", assign, name)
        for rx in use_patterns(name):
            use = rx.search(text, start)
            if use and (best is None or (use.start(), 1) < best[:2]):
                best = (use.start(), 1, "use", use, name)
    recheck = RECHECK_PATTERN.search(text, start)
    if recheck and recheck.group(1) in watch and (best is None or recheck.start() < best[0]):
        return None
    if best is None or best[2] == "assign":
        return None
    _, _, _, found, name = best
    line, col = line_col(text, found.start())
    return line, col, name


def collect_err_guard_issues(text: str) -> list[tuple[int, int, str]]:
    """Flag uses of err / its companions after a non-exiting `err != nil` guard."""
    issues: list[tuple[int, int, str]] = []
    for match in ERR_GUARD_PATTERN.finditer(text):
        name = match.group(1)
        block_text, guard_end = extract_statement_region(text, match.end())
        if contains_exit(block_text):
            continue
        watch = (name, *companions_for(text, match, name))
        if guard_is_scoped(text, match):
            continue
        if any(_assign_pattern(c).search(block_text) for c in watch[1:]):
            # The guard's error branch reassigns the companion, re-establishing
            # the value for the fallthrough path in both cases.
            continue
        loc = find_unsafe_use(text, skip_optional_else(text, guard_end), watch, _ref_patterns)
        if not loc:
            continue
        line, col, used = loc
        issues.append((line, col, _ERR_MESSAGE.format(name=used)))
    return issues


def collect_nil_guard_issues(text: str) -> list[tuple[int, int, str]]:
    """Flag dereferences after a non-exiting `p == nil` guard."""
    issues: list[tuple[int, int, str]] = []
    for match in NIL_GUARD_PATTERN.finditer(text):
        name = match.group(1)
        block_text, guard_end = extract_statement_region(text, match.end())
        if contains_exit(block_text):
            continue
        loc = find_unsafe_use(text, skip_optional_else(text, guard_end), (name,), _deref_patterns)
        if not loc:
            continue
        line, col, used = loc
        issues.append((line, col, _NIL_MESSAGE.format(name=used)))
    return issues


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    """Return (kind, line, col, message) findings for one file's text."""
    stripped = strip_comments_and_strings(text, lang="go")
    issues: list[tuple[str, int, int, str]] = []
    for line, col, message in collect_err_guard_issues(stripped):
        issues.append(("err_guard", line, col, message))
    for line, col, message in collect_nil_guard_issues(stripped):
        issues.append(("nil_guard", line, col, message))
    deduped: list[tuple[str, int, int, str]] = []
    seen: set[tuple[int, int, str]] = set()
    for kind, line, col, message in issues:
        key = (line, col, message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((kind, line, col, message))
    return deduped


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [(line, col, message) for _, line, col, message in scan_text(text)]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 -m ubs_core.analyzers.narrowing_go <path>", file=sys.stderr)
        return 2
    for path in iter_go_files(Path(sys.argv[1])):
        for line, col, message in analyze_file(path):
            print(f"{path}:{line}:{col} - {message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    if os.environ.get("UBS_SKIP_TYPE_NARROWING", "") == "1":
        return []
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() != ".go":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for kind, line, col, message in scan_text(text):
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line,
                "layer": "narrowing",
                "lang": "go",
                "col": col,
                "severity": "warning",
                "message": message,
            }


def _analyze_snippet(code: str) -> list[tuple[int, int, str]]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_narrowing_go_") as tmp:
        target = Path(tmp) / "snippet.go"
        target.write_text(code, encoding="utf-8")
        return analyze_file(target)


def _selftest_detects_partial_err_guard() -> None:
    code = (
        "package main\n"
        "\n"
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 8, (line, col, message)
    assert col == 13, (line, col, message)
    assert message == "data used after non-exiting err guard", message


def _selftest_detects_nil_guard_fallthrough() -> None:
    code = (
        "package main\n"
        "\n"
        "func f(id string) string {\n"
        "    u := lookup(id)\n"
        "    if u == nil {\n"
        "        log.Println(\"no user\")\n"
        "    }\n"
        "    name := u.Name\n"
        "    return name\n"
        "}\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 8, (line, col, message)
    assert col == 13, (line, col, message)
    assert message == "u dereferenced after non-exiting nil guard", message


def _selftest_exiting_guards_are_clean() -> None:
    err_code = (
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        return\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    nil_code = (
        "func f(id string) string {\n"
        "    u := lookup(id)\n"
        "    if u == nil {\n"
        "        return \"\"\n"
        "    }\n"
        "    return u.Name\n"
        "}\n"
    )
    assert _analyze_snippet(err_code) == [], _analyze_snippet(err_code)
    assert _analyze_snippet(nil_code) == [], _analyze_snippet(nil_code)


def _selftest_recheck_rescue_suppresses() -> None:
    # An exiting re-check between the partial guard and the use narrows err to
    # nil, so the companion use on the fallthrough path is safe.
    code = (
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"retrying: %v\", err)\n"
        "    }\n"
        "    if err != nil {\n"
        "        return\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


def _selftest_reassignment_suppresses() -> None:
    # After the companion is reassigned, a later use is not the guard's fault.
    code = (
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"falling back: %v\", err)\n"
        "    }\n"
        "    data = defaultConfig()\n"
        "    process(data)\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


def _selftest_run_and_env_gate(tmp_prefix: str = "ubs_core_narrowing_go_run_") -> None:
    import tempfile

    code = (
        "package main\n"
        "\n"
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.go"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="go", files=[target])))
        assert len(findings) == 1, findings
        finding = findings[0]
        assert finding["rule"] == "go.narrowing.partial_err_guard", finding
        assert finding["line"] == 8, finding
        assert finding["col"] == 13, finding
        assert finding["message"] == "data used after non-exiting err guard", finding

        os.environ["UBS_SKIP_TYPE_NARROWING"] = "1"
        try:
            assert list(run(RunContext(lang="go", files=[target]))) == []
        finally:
            del os.environ["UBS_SKIP_TYPE_NARROWING"]


def _selftest_scoped_guard_out_of_scope() -> None:
    # Init-scoped err is invisible past the if chain, so the guard must not
    # leak its scan into following functions.
    code = (
        "func f(path string) bool {\n"
        "    if _, err := os.Stat(path); err != nil {\n"
        "        log.Printf(\"stat failed: %v\", err)\n"
        "    }\n"
        "    return false\n"
        "}\n"
        "\n"
        "func g(path string) {\n"
        "    _, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    fmt.Println(\"done\")\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


def _selftest_error_branch_reassign_suppresses() -> None:
    # A non-exiting re-check whose error branch reassigns the companion keeps
    # the fallthrough path valid in both cases.
    code = (
        "func f(path string) []byte {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    if err != nil {\n"
        "        data = defaultConfig()\n"
        "    }\n"
        "    return data, err\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


SELF_TESTS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("detects_partial_err_guard", _selftest_detects_partial_err_guard),
    ("detects_nil_guard_fallthrough", _selftest_detects_nil_guard_fallthrough),
    ("exiting_guards_are_clean", _selftest_exiting_guards_are_clean),
    ("recheck_rescue_suppresses", _selftest_recheck_rescue_suppresses),
    ("reassignment_suppresses", _selftest_reassignment_suppresses),
    ("scoped_guard_out_of_scope", _selftest_scoped_guard_out_of_scope),
    ("error_branch_reassign_suppresses", _selftest_error_branch_reassign_suppresses),
    ("run_and_env_gate", _selftest_run_and_env_gate),
)


register(Analyzer(layer="narrowing", lang="go", name="narrowing_go", run=run, selftests=SELF_TESTS))


def _selftest_proven_nil_pointer():
    analysis = _NilPointers("package p\ntype Item struct { Value int }\n"
                            "func f() int { var p *Item; return p.Value }\n")
    analysis.analyze()
    assert [(line_col(analysis.text, offset), name) for offset, name in analysis.findings.items()] == [((3, 36), "p")], analysis.findings


def _selftest_nil_pointer_repair():
    analysis = _NilPointers("package p\ntype Item struct { Value int }\n"
                            "func f() int { var p *Item; if p == nil { p = &Item{} }; return p.Value }\n")
    analysis.analyze()
    assert analysis.findings == {}, analysis.findings


register(Analyzer(layer="narrowing", lang="go", name="nil_dereference_go", run=run_nil_dereferences,
                  selftests=(("proven_nil_pointer", _selftest_proven_nil_pointer),
                             ("nil_pointer_repair", _selftest_nil_pointer_repair))))
