"""Bounded PHP request provenance with receiver- and context-specific sinks.

Facts flow through selected local PHP statements and callable bodies. SQL
statements retain the template captured by their own allocation; value binds
never sanitize that template. Escaping proves only its documented sink context.
Unknown external effects and exhausted bounds are incomplete analyses, while
already established findings remain available to the public module adapter.
"""
from __future__ import annotations

import os
import re
from bisect import bisect_right
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ubs_core.php_frontend import Node, Parser, Token, lex_php, parse_php
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Step, Trace, advance, join, retag


SQL = "php.security.sql-injection"
COMMAND = "php.security.command-injection"
CODE = "php.security.dynamic-code"
INCLUDE = "php.security.dynamic-include"
DESERIALIZE = "php.security.unsafe-deserialization"
XSS = "php.security.xss"
RULES = {
    SQL: ("php.sql", 1, "Request-derived SQL reaches query execution"),
    COMMAND: ("php.execution", 2, "Request-derived input reaches command execution"),
    CODE: ("php.execution", 2, "Request-derived input reaches PHP code execution"),
    INCLUDE: ("php.includes", 3, "Request-derived input selects an included PHP file"),
    DESERIALIZE: ("php.deserialization", 4, "Request-derived input reaches unserialize"),
    XSS: ("php.output", 5, "Request-derived output lacks escaping for its HTML context"),
}
_REMEDIATIONS = {
    SQL: "Keep the SQL template static and bind request values separately at execution. Allowlist identifiers that cannot be bound.",
    COMMAND: "Use a fixed executable and a separate argument array; do not pass request text to an interpreter code argument.",
    CODE: "Replace request-selected PHP code with explicit, allowlisted application operations.",
    INCLUDE: "Map an allowlisted application key to a fixed local include path.",
    DESERIALIZE: "Use a data-only format with schema validation for untrusted input; allowed_classes does not establish input trust.",
    XSS: "Escape for the actual output context. Quoted attributes need quote escaping; URL and script contexts need additional validation or encoding.",
}
RULE_METADATA = {
    rule: {"language": "php", "category": category, "category_id": category,
           "severity": "critical", "message": title, "remediation": _REMEDIATIONS[rule],
           "confidence": "unknown", "manifest_cases": ["php-buggy", "php-clean"]}
    for rule, (category, _number, title) in RULES.items()
}
LIMIT_DEFAULTS = {"UBS_PHP_MAX_TOKENS": 100_000, "UBS_PHP_MAX_NESTING": 128,
                  "UBS_PHP_MAX_STEPS": 500_000}


def policy_limits() -> dict[str, int]:
    result = {}
    for name, maximum in LIMIT_DEFAULTS.items():
        raw = os.environ.get(name, str(maximum))
        if not re.fullmatch(r"[0-9]+", raw) or int(raw) <= 0:
            raise ValueError("%s must be a positive integer; PHP analysis is incomplete" % name)
        result[name] = min(int(raw), maximum)
    return result


class _Unknown:
    pass


UNKNOWN = _Unknown()


@dataclass(frozen=True)
class Part:
    literal: str | None = None
    fact: Fact = CLEAN


@dataclass(frozen=True)
class Value:
    fact: Fact = CLEAN
    literal: Any = UNKNOWN
    items: tuple[tuple[Any, Value], ...] = ()
    fallback: Value | None = None
    array: bool = False
    refs: frozenset[int] = frozenset()
    parts: tuple[Part, ...] = ()


EMPTY = Value()


def scalar(literal: Any) -> Value:
    return Value(literal=literal, parts=(Part(php_string(literal)),))


def php_string(value: Any) -> str:
    if value is None or value is False:
        return ""
    if value is True:
        return "1"
    return str(value)


def array_value(items: dict[Any, Value], fallback: Value | None = None) -> Value:
    return Value(join(*(value.fact for value in items.values()), fallback.fact if fallback else CLEAN),
                 items=tuple(items.items()), fallback=fallback, array=True)


def joined(*values: Value) -> Value:
    if not values:
        return EMPTY
    if all(value == values[0] for value in values):
        return values[0]
    fact = join(*(value.fact for value in values))
    literal = values[0].literal
    if any(value.literal != literal for value in values[1:]):
        literal = UNKNOWN
    refs = frozenset(ref for value in values for ref in value.refs)
    if all(value.array for value in values):
        keys = dict.fromkeys(key for value in values for key, _ in value.items)
        items = {key: joined(*(dict(value.items).get(key, value.fallback or EMPTY) for value in values)) for key in keys}
        fallback = joined(*(value.fallback or EMPTY for value in values))
        return array_value(items, fallback)
    return Value(fact, literal=literal, refs=refs, parts=(Part(None, fact),))


def tagged(value: Value, *tags: str, remove: frozenset[str] = frozenset()) -> Value:
    fact = retag(value.fact, add=frozenset(tags), remove=remove)
    return Value(fact, literal=value.literal, parts=(Part(None, fact),))


def without_proofs(value: Value) -> Value:
    """Keep provenance after a transformation that may undo earlier escaping."""
    tags = frozenset(tag for trace in value.fact for tag in trace.tags)
    fact = retag(value.fact, remove=tags)
    return Value(fact, parts=(Part(None, fact),))


def key_of(value: Any) -> Any:
    """PHP array keys coerce canonical decimal strings, but not leading zeros."""
    if value is UNKNOWN:
        return UNKNOWN
    if value is None:
        return ""
    if isinstance(value, (bool, int, float)):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value):
        integer = int(value)
        if -(2 ** 63) <= integer < 2 ** 63:
            return integer
    return value


@dataclass(frozen=True)
class Object:
    kind: str
    name: str = ""
    fields: tuple[tuple[str, Value], ...] = ()
    query: Value = EMPTY
    connection: frozenset[int] = frozenset()


@dataclass(frozen=True)
class Context:
    namespace: str = ""
    classes: tuple[tuple[str, str], ...] = ()
    functions: tuple[tuple[str, str], ...] = ()
    constants: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Function:
    node: Node
    context: Context
    captures: tuple[tuple[str, Value], ...] = ()


_CONSTANTS = {
    "ENT_NOQUOTES": 0, "ENT_COMPAT": 2, "ENT_QUOTES": 3, "ENT_IGNORE": 4,
    "ENT_SUBSTITUTE": 8, "ENT_HTML401": 0, "ENT_XML1": 16, "ENT_XHTML": 32,
    "ENT_HTML5": 48, "ENT_DISALLOWED": 128,
    "FILTER_DEFAULT": 516, "FILTER_UNSAFE_RAW": 516,
    "FILTER_VALIDATE_INT": 257, "FILTER_VALIDATE_BOOLEAN": 258, "FILTER_VALIDATE_BOOL": 258,
    "FILTER_VALIDATE_FLOAT": 259, "FILTER_SANITIZE_STRING": 513,
    "FILTER_SANITIZE_SPECIAL_CHARS": 515, "FILTER_SANITIZE_FULL_SPECIAL_CHARS": 522,
    "FILTER_SANITIZE_NUMBER_INT": 519, "FILTER_SANITIZE_NUMBER_FLOAT": 520,
    "FILTER_SANITIZE_URL": 518, "FILTER_FLAG_NO_ENCODE_QUOTES": 128,
    "INPUT_GET": 1, "INPUT_POST": 0, "INPUT_COOKIE": 2, "INPUT_SERVER": 5, "INPUT_ENV": 4,
    "JSON_HEX_TAG": 1, "JSON_HEX_AMP": 2, "JSON_HEX_APOS": 4, "JSON_HEX_QUOT": 8,
    "JSON_UNESCAPED_SLASHES": 64, "JSON_UNESCAPED_UNICODE": 256,
    "JSON_THROW_ON_ERROR": 4194304,
}
_HTML_TAGS = frozenset({"html-text", "html-double", "html-single", "html-url", "url-component", "js-literal"})
_REQUEST_CLASSES = frozenset({"illuminate\\http\\request", "symfony\\component\\httpfoundation\\request"})
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"})


class Engine:
    def __init__(self, path: Path, text: str, limits: dict[str, int], enabled: frozenset[str]):
        self.path = str(path)
        self.text = text
        self.lines = text.splitlines()
        self.line_starts = [0] + [match.end() for match in re.finditer("\n", text)]
        self.limits = limits
        self.budget = Budget(limits["UBS_PHP_MAX_STEPS"])
        self.enabled = enabled
        self.issues: set[str] = set()
        self.effects: dict[tuple[str, int], Fact] = {}
        self.env: dict[str, Value] = {}
        self.heap: dict[int, Object] = {}
        self.next_object = 0
        self.functions: dict[str, Function] = {}
        self.classes: dict[str, tuple[Node, Context]] = {}
        self.constants: dict[str, Value] = {}
        self.closures: dict[int, Function] = {}
        self.context = Context()
        self.call_depth = 0
        self.html = ""
        self.declaration_probe = False

    def location(self, token: Token) -> tuple[int, int]:
        line = bisect_right(self.line_starts, token.start)
        return line, token.start - self.line_starts[line - 1] + 1

    def step(self, token: Token, kind: str, label: str) -> Step:
        line, column = self.location(token)
        return Step(self.path, line, column, kind, label)

    def source(self, token: Token, label: str) -> Value:
        fact = frozenset({Trace("request", (self.path, token.start), evidence=(self.step(token, "source", label),))})
        return Value(fact, parts=(Part(None, fact),))

    def issue(self, message: str) -> None:
        self.issues.add(message + "; PHP analysis is incomplete")

    def allocate(self, kind: str, *, name: str = "", query: Value = EMPTY,
                 connection: frozenset[int] = frozenset()) -> Value:
        self.next_object += 1
        ref = self.next_object
        self.heap[ref] = Object(kind, name, query=query, connection=connection)
        return Value(refs=frozenset({ref}))

    def resolve(self, name: str, kind: str, context: Context | None = None) -> str:
        ctx = context or self.context
        if name.startswith("\\"):
            return name[1:]
        aliases = dict(getattr(ctx, {"class": "classes", "function": "functions", "const": "constants"}[kind]))
        head, separator, tail = name.partition("\\")
        alias = aliases.get(head if kind == "const" else head.lower())
        if alias:
            return alias + (separator + tail if separator else "")
        candidate = ctx.namespace + "\\" + name if ctx.namespace else name
        if kind == "function" and "\\" not in name and candidate.lower() not in self.functions:
            return name
        if kind == "const" and candidate in self.constants:
            return candidate
        if kind == "const" and "\\" not in name and name in _CONSTANTS:
            return name
        return candidate

    def updated_context(self, node: Node, context: Context) -> Context:
        if node.kind == "namespace":
            return Context(namespace=node.value)
        kind, names = node.value
        field_name = {"class": "classes", "function": "functions", "const": "constants"}[kind]
        aliases = dict(getattr(context, field_name))
        for name, alias in names:
            aliases[alias if kind == "const" else alias.lower()] = name
        return replace(context, **{field_name: tuple(aliases.items())})

    def collect(self, statements: tuple[Node, ...], context: Context) -> None:
        for node in statements:
            self.budget.spend()
            if node.kind == "namespace":
                next_context = self.updated_context(node, context)
                if node.children:
                    self.collect(node.children[0].children, next_context)
                else:
                    context = next_context
            elif node.kind == "use":
                context = self.updated_context(node, context)
            elif node.kind == "function" and node.value["name"]:
                name = (context.namespace + "\\" if context.namespace else "") + node.value["name"]
                self.functions[name.lower()] = Function(node, context)
            elif node.kind == "class":
                name = (context.namespace + "\\" if context.namespace else "") + node.value["name"]
                self.classes[name.lower()] = (node, context)
            elif node.kind == "block":
                self.collect(node.children, context)

    def analyze(self) -> None:
        parsed = parse_php(self.text, max_tokens=self.limits["UBS_PHP_MAX_TOKENS"],
                           max_nesting=self.limits["UBS_PHP_MAX_NESTING"])
        self.issues.update(parsed.issues)
        self.collect(parsed.statements, self.context)
        self.execute_many(parsed.statements)
        # Public entry points may consume superglobals or typed framework
        # requests even when their caller is in a different file. Ordinary
        # parameter names are unknown values, never invented request sources.
        old_env, old_heap, old_html = self.env, self.heap, self.html
        self.declaration_probe = True
        for function in self.functions.values():
            self.env, self.heap, self.html = {}, {}, ""
            self.invoke(function, (), (), function.node.token)
        for name, (node, context) in self.classes.items():
            for method in node.children:
                if method.kind == "function":
                    self.env, self.heap, self.html = {}, {}, ""
                    receiver = self.allocate("object", name=name)
                    self.invoke(Function(method, context), (), (), method.token, receiver)
        self.declaration_probe = False
        self.env, self.heap, self.html = old_env, old_heap, old_html

    def record(self, rule: str, token: Token, fact: Fact) -> None:
        if fact and rule in self.enabled:
            key = (rule, token.start)
            fact = advance(fact, self.step(token, "sink", RULES[rule][2]))
            self.effects[key] = join(self.effects.get(key, CLEAN), fact)

    def unsafe(self, value: Value, policy: str, *, connections: frozenset[int] = frozenset(),
               context: str = "text") -> Fact:
        result = CLEAN
        sql_quote = ""
        for part in value.parts or (Part(None, value.fact),):
            if part.literal is not None:
                if policy == "sql":
                    i = 0
                    while i < len(part.literal):
                        char = part.literal[i]
                        if char == "\\" and sql_quote:
                            i += 2
                            continue
                        if char in "'\"`":
                            if not sql_quote:
                                sql_quote = char
                            elif sql_quote == char:
                                if i + 1 < len(part.literal) and part.literal[i + 1] == char:
                                    i += 2
                                    continue
                                sql_quote = ""
                        i += 1
                continue
            for trace in part.fact:
                tags = trace.tags
                safe = False
                if policy in ("sql", "shell", "code") and "numeric" in tags:
                    safe = True
                if policy == "sql" and connections:
                    safe = safe or all("sql-quoted:%d" % ref in tags for ref in connections)
                    safe = safe or (sql_quote == "'" and all("sql-escaped:%d" % ref in tags for ref in connections))
                if policy == "shell":
                    safe = safe or "shell-arg" in tags
                if policy == "html":
                    if context == "text":
                        safe = bool(tags & {"numeric", "html-text", "url-component"})
                    elif context in ("double", "single"):
                        safe = "html-" + context in tags or bool(tags & {"numeric", "url-component"})
                    elif context in ("url-double", "url-single", "url-unquoted"):
                        safe = "url-component" in tags or ("html-url" in tags and context != "url-unquoted")
                    elif context == "script":
                        safe = "numeric" in tags or "js-literal" in tags
                    elif context == "unquoted":
                        safe = bool(tags & {"numeric", "url-component"})
                    # Event handlers, style and dynamic tag structure have no
                    # generic htmlspecialchars proof.
                if not safe:
                    result = join(result, frozenset({trace}))
        return result

    def html_context(self) -> str:
        prefix = self.html
        lowered = prefix.lower()
        if lowered.rfind("<!--") > lowered.rfind("-->"):
            return "comment"
        if lowered.rfind("<script") > lowered.rfind("</script") and lowered.rfind(">") > lowered.rfind("<script"):
            body = prefix[prefix.find(">", lowered.rfind("<script")) + 1:]
            quote = ""
            escaped = False
            for char in body:
                if escaped:
                    escaped = False
                elif char == "\\" and quote:
                    escaped = True
                elif quote and char == quote:
                    quote = ""
                elif not quote and char in "'\"`":
                    quote = char
            return "script-string" if quote else "script"
        if lowered.rfind("<style") > lowered.rfind("</style") and lowered.rfind(">") > lowered.rfind("<style"):
            return "style"
        start = prefix.rfind("<")
        if start < 0 or prefix.rfind(">") > start:
            return "text"
        tag = prefix[start:]
        attribute = ""
        quote = ""
        unquoted = False
        match = re.match(r"</?[A-Za-z][A-Za-z0-9:-]*", tag)
        if match is None:
            return "structure"
        i = match.end()
        while i < len(tag):
            while i < len(tag) and tag[i].isspace():
                i += 1
            match = re.match(r"[^\s=/>]+", tag[i:])
            if not match:
                break
            attribute = match.group().lower()
            i += match.end()
            while i < len(tag) and tag[i].isspace():
                i += 1
            if i == len(tag) or tag[i] != "=":
                attribute = ""
                continue
            i += 1
            while i < len(tag) and tag[i].isspace():
                i += 1
            if i < len(tag) and tag[i] in "'\"":
                quote = tag[i]
                i += 1
                end = tag.find(quote, i)
                if end < 0:
                    break
                i = end + 1
                quote = ""
                attribute = ""
            else:
                unquoted = True
                while i < len(tag) and not tag[i].isspace():
                    i += 1
                if i == len(tag):
                    break
                attribute = ""
                unquoted = False
        if not attribute:
            return "structure"
        if attribute.startswith("on") or attribute in ("style", "srcdoc"):
            return "script-attribute" if attribute.startswith("on") else "style"
        context = "double" if quote == '"' else "single" if quote == "'" else "unquoted"
        if attribute in ("href", "src", "action", "formaction", "poster", "data", "xlink:href"):
            return "url-" + context
        return context if quote or unquoted else "structure"

    def output(self, value: Value, token: Token) -> None:
        for part in value.parts or (Part(None, value.fact),):
            if part.literal is not None:
                self.html = (self.html + part.literal)[-8192:]
            else:
                self.record(XSS, token, self.unsafe(Value(part.fact), "html", context=self.html_context()))

    def concat(self, left: Value, right: Value) -> Value:
        parts = (left.parts or (Part(None, left.fact),)) + (right.parts or (Part(None, right.fact),))
        self.budget.spend(len(parts))
        if len(parts) > 2048:
            raise AnalysisLimit("PHP concatenation limit exceeded; analysis is incomplete")
        literal = php_string(left.literal) + php_string(right.literal) if left.literal is not UNKNOWN and right.literal is not UNKNOWN else UNKNOWN
        return Value(join(left.fact, right.fact), literal=literal, parts=parts)

    def read_index(self, value: Value, key: Value) -> Value:
        if not value.array:
            return Value(join(value.fact, key.fact), parts=(Part(None, join(value.fact, key.fact)),))
        normalized = key_of(key.literal)
        if normalized is UNKNOWN:
            return joined(*(item for _key, item in value.items), value.fallback or EMPTY)
        return dict(value.items).get(normalized, value.fallback or EMPTY)

    def assign(self, target: Node, value: Value) -> None:
        self.budget.spend()
        value = replace(value, fact=advance(value.fact, self.step(target.token, "assignment", "PHP local assignment")))
        if target.kind == "var":
            self.env[target.value] = value
        elif target.kind == "index":
            container, key_node = target.children
            base = self.evaluate(container)
            items = dict(base.items)
            if key_node.kind == "append":
                numeric = [key for key in items if isinstance(key, int)]
                key = max(numeric, default=-1) + 1
            else:
                key = key_of(self.evaluate(key_node).literal)
            fallback = base.fallback
            if key is UNKNOWN:
                items = {existing: joined(previous, value) for existing, previous in items.items()}
                fallback = joined(fallback or EMPTY, value)
            else:
                items[key] = value
            self.assign(container, array_value(items, fallback))
        elif target.kind == "member":
            receiver = self.evaluate(target.children[0])
            for ref in receiver.refs:
                obj = self.heap[ref]
                fields = dict(obj.fields)
                fields[target.value[1]] = value
                self.heap[ref] = replace(obj, fields=tuple(fields.items()))
            if not receiver.refs:
                self.issue("Unresolved PHP property write")
        else:
            self.issue("Unsupported PHP assignment target")

    def typed(self, type_name: str, token: Token) -> Value:
        clean = type_name.lstrip("?")
        resolved = self.resolve(clean, "class").lower()
        if resolved in _REQUEST_CLASSES:
            return self.allocate("request", name=resolved)
        if resolved in ("pdo", "mysqli"):
            return self.allocate(resolved)
        if resolved in self.classes:
            return self.allocate("object", name=resolved)
        return EMPTY

    def invoke(self, function: Function, args: tuple[Value, ...], arg_nodes: tuple[Node, ...],
               token: Token, receiver: Value = EMPTY) -> Value:
        if self.call_depth >= min(32, self.limits["UBS_PHP_MAX_NESTING"]):
            raise AnalysisLimit("PHP local-call recursion limit exceeded; analysis is incomplete")
        self.budget.spend()
        previous_env, previous_context = self.env, self.context
        self.env, self.context = dict(function.captures), function.context
        if receiver.refs:
            self.env["$this"] = receiver
        for index, (name, type_name, _byref, default) in enumerate(function.node.value["params"]):
            if index < len(args):
                value = args[index]
            elif default is not None:
                value = self.evaluate(default)
            else:
                value = self.typed(type_name, function.node.token) if type_name else EMPTY
            self.env[name] = value
        self.call_depth += 1
        try:
            _flow, result = self.execute(function.node.children[0])
            effects = dict(self.env)
        finally:
            self.call_depth -= 1
            self.env, self.context = previous_env, previous_context
        for index, (name, _type_name, byref, _default) in enumerate(function.node.value["params"]):
            if byref and index < len(arg_nodes):
                self.assign(arg_nodes[index], effects.get(name, EMPTY))
        return result

    def fork(self, node: Node, env: dict[str, Value], heap: dict[int, Object]) -> tuple[dict[str, Value], dict[int, Object], str, Value]:
        self.env, self.heap = dict(env), dict(heap)
        flow, value = self.execute(node)
        return self.env, self.heap, flow, value

    def merge(self, branches: tuple[tuple[dict[str, Value], dict[int, Object], str, Value], ...]) -> None:
        active = tuple(branch for branch in branches if branch[2] == "normal") or branches
        keys = dict.fromkeys(key for env, _heap, _flow, _value in active for key in env)
        self.env = {key: joined(*(env.get(key, EMPTY) for env, _heap, _flow, _value in active)) for key in keys}
        refs = dict.fromkeys(ref for _env, heap, _flow, _value in active for ref in heap)
        heap = {}
        for ref in refs:
            objects = [branch_heap[ref] for _env, branch_heap, _flow, _value in active if ref in branch_heap]
            first = objects[0]
            fields = dict.fromkeys(key for obj in objects for key, _value in obj.fields)
            heap[ref] = replace(first, query=joined(*(obj.query for obj in objects)),
                                fields=tuple((key, joined(*(dict(obj.fields).get(key, EMPTY) for obj in objects))) for key in fields))
        self.heap = heap

    def truth(self, value: Value) -> bool | None:
        if value.literal is UNKNOWN:
            return None
        return value.literal not in (None, False, 0, 0.0, "", "0")

    def refine(self, condition: Node, truth: bool) -> None:
        if condition.kind == "unary" and condition.value == "!":
            self.refine(condition.children[0], not truth)
        elif condition.kind == "binary" and condition.value in ("===", "!=="):
            left, right = condition.children
            exact = self.evaluate(right)
            if exact.literal is not UNKNOWN and truth == (condition.value == "==="):
                self.assign(left, exact)
        elif condition.kind == "call" and condition.children[0].kind == "name" and truth:
            name = self.resolve(condition.children[0].value, "function").lower()
            if name in ("ctype_digit", "is_numeric", "is_int", "is_integer", "is_float") and len(condition.children) >= 2:
                argument = condition.children[1]
                self.assign(argument, tagged(self.evaluate(argument), "numeric"))
            if name == "in_array" and len(condition.children) >= 4:
                choices = self.evaluate(condition.children[2])
                strict = self.evaluate(condition.children[3])
                if strict.literal is True and choices.array and choices.fallback is None and all(value.literal is not UNKNOWN for _key, value in choices.items):
                    self.assign(condition.children[1], joined(*(value for _key, value in choices.items)))

    def execute_many(self, nodes: tuple[Node, ...]) -> tuple[str, Value]:
        for node in nodes:
            flow, value = self.execute(node)
            if flow != "normal":
                return flow, value
        return "normal", EMPTY

    def execute(self, node: Node) -> tuple[str, Value]:
        self.budget.spend()
        kind = node.kind
        if kind in ("empty", "function", "class", "separator"):
            return "normal", EMPTY
        if kind in ("block", "catch", "finally"):
            return self.execute_many(node.children)
        if kind == "namespace":
            context = self.context
            self.context = self.updated_context(node, context)
            if node.children:
                result = self.execute(node.children[0])
                self.context = context
                return result
            return "normal", EMPTY
        if kind == "use":
            self.context = self.updated_context(node, self.context)
        elif kind == "html":
            self.html = (self.html + node.value)[-8192:]
        elif kind == "expr":
            self.evaluate(node.children[0])
        elif kind == "echo":
            for child in node.children:
                self.output(self.evaluate(child), node.token)
        elif kind == "return":
            return "return", self.evaluate(node.children[0]) if node.children else scalar(None)
        elif kind in ("throw", "break", "continue"):
            for child in node.children:
                self.evaluate(child)
            return kind, EMPTY
        elif kind == "const":
            for declaration in node.children:
                if declaration.kind == "assign" and declaration.value == "=" and declaration.children[0].kind == "name":
                    name = (self.context.namespace + "\\" if self.context.namespace else "") + declaration.children[0].value
                    value = self.evaluate(declaration.children[1])
                    self.constants[name] = value
                    if value.literal is UNKNOWN:
                        self.issue("Unresolved PHP constant declaration")
                else:
                    self.issue("Unsupported PHP constant declaration")
        elif kind in ("global", "static"):
            self.issue("PHP %s storage effects are outside the selected subset" % kind)
        elif kind == "if":
            condition, yes, no = node.children
            truth = self.truth(self.evaluate(condition))
            if truth is not None:
                self.refine(condition, truth)
                return self.execute(yes if truth else no)
            env, heap, html = dict(self.env), dict(self.heap), self.html
            self.refine(condition, True)
            branch_yes = self.fork(yes, self.env, self.heap)
            self.env, self.heap, self.html = dict(env), dict(heap), html
            self.refine(condition, False)
            branch_no = self.fork(no, self.env, self.heap)
            self.merge((branch_yes, branch_no))
            self.html = html
            if branch_yes[2] == branch_no[2] and branch_yes[2] != "normal":
                return branch_yes[2], joined(branch_yes[3], branch_no[3])
        elif kind in ("while", "for", "foreach", "do"):
            self.loop(node)
        elif kind == "try":
            env, heap = dict(self.env), dict(self.heap)
            branches = []
            for child in node.children:
                if child.kind != "finally":
                    branches.append(self.fork(child, env, heap))
            self.merge(tuple(branches))
            for child in node.children:
                if child.kind == "finally":
                    flow, value = self.execute(child)
                    if flow != "normal":
                        return flow, value
        else:
            self.issue("Unsupported PHP statement %s" % kind)
        return "normal", EMPTY

    def loop(self, node: Node) -> None:
        children, body = node.children[:-1], node.children[-1]
        entry_env, entry_heap = dict(self.env), dict(self.heap)
        if node.kind == "foreach":
            if not children:
                return
            iterable = self.evaluate(children[0])
            targets = [child for child in children[1:] if child.kind not in ("as", "arrow")]
            value = joined(*(item for _key, item in iterable.items), iterable.fallback or EMPTY)
            if targets:
                self.assign(targets[-1], value)
            if len(targets) > 1:
                self.assign(targets[0], EMPTY)
        elif node.kind == "for":
            self.issue("PHP for-loop header semantics are outside the selected subset")
            for child in children:
                if child.kind != "separator":
                    self.evaluate(child)
        elif children and self.truth(self.evaluate(children[0])) is False and node.kind != "do":
            return
        for _iteration in range(16):
            old_env, old_heap = dict(self.env), dict(self.heap)
            branch = self.fork(body, old_env, old_heap)
            self.merge(((entry_env, entry_heap, "normal", EMPTY), branch))
            if self.env == old_env and self.heap == old_heap:
                return
            if branch[2] in ("break", "return", "throw"):
                return
        raise AnalysisLimit("PHP loop fixpoint limit exceeded; analysis is incomplete")

    def string(self, node: Node) -> Value:
        token, raw = node.token, node.value
        if token.quote == "'":
            return scalar(raw.replace("\\'", "'").replace("\\\\", "\\"))
        result = scalar("")
        cursor = 0
        pattern = re.compile(r"(?:\{\$[^{}]+\}|\$[A-Za-z_][A-Za-z_0-9]*(?:\[(?:[^\]\r\n]+)\]|->[A-Za-z_][A-Za-z_0-9]*)*)")
        for match in pattern.finditer(raw):
            escaped = match.start() - 1
            while escaped >= 0 and raw[escaped] == "\\":
                escaped -= 1
            if (match.start() - escaped - 1) % 2:
                continue
            result = self.concat(result, scalar(self.decode_literal(raw[cursor:match.start()])))
            expression = match.group()
            if expression.startswith("{"):
                expression = expression[1:-1]
            # PHP interpolated bare array keys are strings, not constants.
            expression = re.sub(r"\[([A-Za-z_][A-Za-z_0-9]*)\]", r"['\1']", expression)
            start = token.start + match.start() + (0 if self.text[token.start:token.start + 3] == "<<<" else 1)
            parser = Parser(lex_php(expression, fragment=True, offset=start), self.limits["UBS_PHP_MAX_NESTING"])
            try:
                value = self.evaluate(parser.expression())
                if parser.current().kind != "eof":
                    self.issue("Unsupported PHP string interpolation")
            except ValueError:
                self.issue("Unsupported PHP string interpolation")
                value = EMPTY
            result = self.concat(result, value)
            cursor = match.end()
        result = self.concat(result, scalar(self.decode_literal(raw[cursor:])))
        return result

    def decode_literal(self, text: str) -> str:
        translations = {"n": "\n", "r": "\r", "t": "\t", "v": "\v", "e": "\x1b", "f": "\f", "\\": "\\", '"': '"', "$": "$"}
        return re.sub(r"\\([nrtvef\\\"$])", lambda match: translations[match.group(1)], text)

    def evaluate(self, node: Node) -> Value:
        self.budget.spend()
        kind = node.kind
        if kind == "var":
            if node.value in self.env:
                return self.env[node.value]
            if node.value in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"):
                return array_value({}, self.source(node.token, node.value))
            if node.value == "$_SERVER":
                return array_value({}, self.source(node.token, "request server metadata"))
            return EMPTY
        if kind == "name":
            name = node.value
            if name.lower() in ("true", "false", "null"):
                return scalar({"true": True, "false": False, "null": None}[name.lower()])
            if name == "__DIR__":
                return scalar(str(Path(self.path).parent))
            if name == "__FILE__":
                return scalar(self.path)
            resolved = self.resolve(name, "const")
            if resolved in self.constants:
                return self.constants[resolved]
            if resolved in _CONSTANTS:
                return scalar(_CONSTANTS[resolved])
            return EMPTY
        if kind == "number":
            raw = node.value.replace("_", "")
            try:
                return scalar(float(raw) if any(char in raw.lower() for char in (".", "e")) and not raw.lower().startswith(("0x", "0b")) else int(raw, 0 if raw.lower().startswith(("0x", "0b", "0o")) else 10))
            except ValueError:
                self.issue("Unsupported PHP numeric literal")
                return EMPTY
        if kind in ("string", "backtick"):
            value = self.string(node)
            if kind == "backtick":
                self.record(COMMAND, node.token, self.unsafe(value, "shell"))
            return value
        if kind == "array":
            items = {}
            index = 0
            fallback = None
            for child in node.children:
                if child.kind == "entry":
                    key = key_of(self.evaluate(child.children[0]).literal)
                    value = self.evaluate(child.children[1])
                elif child.kind == "spread":
                    self.issue("PHP array unpacking is outside the selected subset")
                    value = self.evaluate(child.children[0])
                    fallback = joined(fallback or EMPTY, value)
                    continue
                else:
                    key, value = index, self.evaluate(child)
                if key is UNKNOWN:
                    fallback = joined(fallback or EMPTY, value)
                else:
                    items[key] = value
                    if isinstance(key, int):
                        index = max(index, key + 1)
            return array_value(items, fallback)
        if kind == "index":
            return self.read_index(self.evaluate(node.children[0]), self.evaluate(node.children[1]))
        if kind == "member":
            receiver = self.evaluate(node.children[0])
            member = node.value[1]
            results = []
            for ref in receiver.refs:
                obj = self.heap[ref]
                if obj.kind == "request" and member in ("query", "request", "cookies", "headers", "files", "server"):
                    results.append(self.allocate("requestbag", name=member))
                else:
                    results.append(dict(obj.fields).get(member, EMPTY))
            return joined(*results)
        if kind == "assign":
            left, right = node.children
            value = self.evaluate(right)
            if node.value != "=":
                value = self.binary(node.value[:-1], self.evaluate(left), value, node.token)
            self.assign(left, value)
            return value
        if kind == "binary":
            left = self.evaluate(node.children[0])
            if node.value in ("&&", "and") and self.truth(left) is False:
                return scalar(False)
            if node.value in ("||", "or") and self.truth(left) is True:
                return scalar(True)
            if node.value == "??" and left.literal is not UNKNOWN and left.literal is not None:
                return left
            right = self.evaluate(node.children[1])
            return self.binary(node.value, left, right, node.token)
        if kind in ("unary", "cast", "postfix"):
            value = self.evaluate(node.children[0])
            operation = node.value
            if kind == "cast":
                if operation in ("int", "integer", "float", "double", "real", "bool", "boolean"):
                    return tagged(value, "numeric")
                if operation == "array":
                    return value if value.array else array_value({0: value})
                return value
            if operation in ("include", "include_once", "require", "require_once"):
                self.record(INCLUDE, node.token, value.fact)
                return EMPTY
            if operation == "print":
                self.output(value, node.token)
                return scalar(1)
            if operation == "!":
                truth = self.truth(value)
                return scalar(not truth) if truth is not None else EMPTY
            if operation in ("+", "-"):
                return tagged(value, "numeric")
            if operation in ("++", "--"):
                self.assign(node.children[0], value)
                return value
            if operation == "&":
                self.issue("PHP reference aliasing is outside the selected subset")
            if operation in ("yield", "throw"):
                self.issue("PHP expression control transfer is outside the selected subset")
            return value
        if kind == "ternary":
            condition, yes, no = node.children
            truth = self.truth(self.evaluate(condition))
            if truth is not None:
                return self.evaluate(yes if truth else no)
            env, heap = dict(self.env), dict(self.heap)
            left = self.evaluate(yes)
            branch_left = (dict(self.env), dict(self.heap), "normal", left)
            self.env, self.heap = env, heap
            right = self.evaluate(no)
            self.merge((branch_left, (self.env, self.heap, "normal", right)))
            return joined(left, right)
        if kind == "new":
            args = tuple(self.evaluate(child) for child in node.children)
            return self.construct(self.resolve(node.value, "class").lower(), args, node)
        if kind == "call":
            return self.call(node)
        if kind == "function":
            captures = dict(self.env) if node.value["arrow"] else {name: self.env.get(name, EMPTY) for name, _ref in node.value["captures"]}
            if any(ref for _name, ref in node.value["captures"]):
                self.issue("PHP closure capture by reference is outside the selected subset")
            value = self.allocate("closure")
            self.closures[next(iter(value.refs))] = Function(node, self.context, tuple(captures.items()))
            return value
        if kind == "named":
            self.issue("PHP named argument binding is outside the selected subset")
            return self.evaluate(node.children[0])
        if kind == "spread":
            self.issue("PHP call argument unpacking is outside the selected subset")
            return self.evaluate(node.children[0])
        if kind == "append":
            return EMPTY
        self.issue("Unsupported PHP value %s" % kind)
        return EMPTY

    def binary(self, operation: str, left: Value, right: Value, token: Token) -> Value:
        if operation == ".":
            return self.concat(left, right)
        if operation == "+" and (left.array or right.array):
            self.issue("PHP array union is outside the selected subset")
            # An unsupported operation establishes neither a clean value nor
            # a proven source-to-sink witness. Completeness carries the gap.
            return EMPTY
        if left.literal is not UNKNOWN and right.literal is not UNKNOWN:
            a, b = left.literal, right.literal
            try:
                operations = {"|": lambda: a | b, "&": lambda: a & b, "^": lambda: a ^ b,
                              "+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b,
                              "===": lambda: type(a) is type(b) and a == b,
                              "!==": lambda: type(a) is not type(b) or a != b,
                              "<": lambda: a < b, ">": lambda: a > b,
                              "<=": lambda: a <= b, ">=": lambda: a >= b}
                if operation in operations:
                    return scalar(operations[operation]())
            except (TypeError, ValueError, OverflowError):
                pass
        value = joined(left, right)
        if operation in ("|", "&", "^"):
            # PHP applies these operators bytewise when both operands are
            # strings. The result can contain delimiters absent from either
            # escaped input, so string escaping is no longer a proof.
            return without_proofs(value)
        if operation in ("+", "-", "*", "/", "%", "**", "<<", ">>"):
            return tagged(value, "numeric")
        if operation in ("==", "!=", "===", "!==", "<", ">", "<=", ">=", "<=>", "instanceof", "&&", "||", "and", "or", "xor"):
            return EMPTY
        return value

    def construct(self, name: str, args: tuple[Value, ...], node: Node) -> Value:
        if name in ("pdo", "mysqli"):
            return self.allocate(name)
        if name == "mysqli_stmt":
            connection = args[0].refs if args else frozenset()
            if connection and all(self.heap[ref].kind == "mysqli" for ref in connection):
                return self.allocate("stmt", query=args[1] if len(args) > 1 else EMPTY, connection=connection)
            self.issue("Unresolved mysqli statement connection")
            return EMPTY
        if name in _REQUEST_CLASSES:
            return self.allocate("request", name=name)
        if name in self.classes:
            definition, context = self.classes[name]
            value = self.allocate("object", name=name)
            for member in definition.children:
                if member.kind == "function" and member.value["name"].lower() == "__construct":
                    self.invoke(Function(member, context), args, node.children, node.token, value)
            return value
        self.issue("Unresolved PHP constructor %s" % name)
        return EMPTY

    def call(self, node: Node) -> Value:
        target, arg_nodes = node.children[0], node.children[1:]
        args = tuple(self.evaluate(child) for child in arg_nodes)
        if target.kind == "name":
            name = self.resolve(target.value, "function").lower()
            if name in self.functions:
                return self.invoke(self.functions[name], args, arg_nodes, node.token)
            return self.builtin(name, args, arg_nodes, node.token)
        if target.kind == "member":
            receiver = self.evaluate(target.children[0])
            if target.value[2] != "name":
                self.issue("Dynamic PHP method dispatch")
                return joined(*args)
            name = target.value[1].lower()
            return self.method(receiver, name, args, arg_nodes, node.token)
        receiver = self.evaluate(target)
        if receiver.refs and all(ref in self.closures for ref in receiver.refs):
            return joined(*(self.invoke(self.closures[ref], args, arg_nodes, node.token) for ref in receiver.refs))
        self.issue("Dynamic PHP function dispatch")
        return joined(receiver, *args)

    def method(self, receiver: Value, name: str, args: tuple[Value, ...],
               arg_nodes: tuple[Node, ...], token: Token) -> Value:
        values = []
        if not receiver.refs:
            if not self.declaration_probe or receiver.fact or any(value.fact for value in args):
                self.issue("Unresolved PHP method receiver for %s" % name)
            return joined(*args)
        for ref in receiver.refs:
            obj = self.heap[ref]
            if obj.kind in ("pdo", "mysqli"):
                if name in ("query", "exec", "multi_query", "real_query", "execute_query"):
                    if args:
                        self.record(SQL, token, self.unsafe(args[0], "sql", connections=frozenset({ref})))
                    values.append(EMPTY)
                elif name == "prepare":
                    values.append(self.allocate("stmt", query=args[0] if args else EMPTY, connection=frozenset({ref})))
                elif name in ("quote", "real_escape_string", "escape_string"):
                    if args:
                        values.append(tagged(args[0], "%s:%d" % ("sql-quoted" if name == "quote" else "sql-escaped", ref)))
                elif name == "stmt_init":
                    values.append(self.allocate("stmt", connection=frozenset({ref})))
                elif name in ("setattribute", "getattribute", "set_charset", "begintransaction", "commit", "rollback", "close", "ping", "select_db", "autocommit", "begin_transaction"):
                    values.append(EMPTY)
                else:
                    self.issue("Unsupported PHP database method %s" % name)
            elif obj.kind == "stmt":
                if name in ("execute", "execute_query"):
                    self.record(SQL, token, self.unsafe(obj.query, "sql", connections=obj.connection))
                elif name == "prepare" and args:
                    self.heap[ref] = replace(obj, query=args[0])
                elif name not in ("bindvalue", "bindparam", "bind_param", "bind_result", "close", "closecursor", "store_result", "get_result", "fetch", "fetchall", "fetchcolumn", "rowcount"):
                    self.issue("Unsupported PHP statement method %s" % name)
                values.append(EMPTY)
            elif obj.kind == "request" and name in ("input", "query", "post", "get", "cookie", "header", "all", "only", "except", "getcontent", "getquerystring", "getpathinfo", "getrequesturi", "path", "url", "fullurl"):
                source = self.source(token, "typed PHP request " + name)
                values.append(array_value({}, source) if name in ("all", "only", "except") else source)
            elif obj.kind == "requestbag" and name in ("get", "all", "getalpha", "getalnum", "getdigits", "getint", "getboolean"):
                source = self.source(token, "typed PHP request bag " + name)
                values.append(tagged(source, "numeric") if name in ("getint", "getboolean") else array_value({}, source) if name == "all" else source)
            elif obj.kind == "object" and obj.name in self.classes:
                definition, context = self.classes[obj.name]
                member = next((item for item in definition.children if item.kind == "function" and item.value["name"].lower() == name), None)
                if member is None:
                    self.issue("Unresolved PHP local method %s" % name)
                    values.append(joined(*args))
                else:
                    values.append(self.invoke(Function(member, context), args, arg_nodes, token, Value(refs=frozenset({ref}))))
            else:
                self.issue("Unsupported PHP receiver effect %s" % name)
                values.append(joined(*args))
        return joined(*values)

    def command(self, value: Value, token: Token) -> None:
        if not value.array:
            self.record(COMMAND, token, self.unsafe(value, "shell"))
            return
        items = dict(value.items)
        program = items.get(0, value.fallback or EMPTY)
        self.record(COMMAND, token, program.fact)
        if program.literal is UNKNOWN:
            if not program.fact:
                self.issue("Unresolved PHP process executable")
            return
        executable = str(program.literal).replace("\\", "/").rsplit("/", 1)[-1].lower()
        arguments = [item for key, item in value.items if isinstance(key, int) and key > 0]
        flags = {"-c", "/c", "-command", "-encodedcommand"} if executable in _SHELLS else {"-r"} if executable in ("php", "php.exe") else {"-c"} if executable.startswith("python") else {"-e"} if executable in ("ruby", "perl") else set()
        for index, argument in enumerate(arguments):
            if argument.literal in flags and index + 1 < len(arguments):
                self.record(COMMAND, token, arguments[index + 1].fact)
                # Once -c/-r/-e consumes its code operand, subsequent values
                # are program positional data, not more interpreter options.
                return
            elif flags and argument.literal is UNKNOWN:
                # An unknown interpreter option can select a code-bearing
                # mode. Ordinary fixed executable argument arrays stay safe.
                self.issue("Unresolved PHP interpreter option")

    def format_string(self, args: tuple[Value, ...]) -> Value:
        if not args:
            return EMPTY
        template = args[0]
        if not isinstance(template.literal, str):
            return joined(*args)
        result, position, index = scalar(""), 0, 1
        pattern = re.compile(r"%%|%(?:(\d+)\$)?[-+ 0#]*\d*(?:\.\d+)?([bcdeEfFgGosuxX])")
        for match in pattern.finditer(template.literal):
            result = self.concat(result, scalar(template.literal[position:match.start()]))
            if match.group() == "%%":
                result = self.concat(result, scalar("%"))
            else:
                slot = int(match.group(1)) if match.group(1) else index
                value = args[slot] if slot < len(args) else EMPTY
                if match.group(2) not in ("s", "c"):
                    value = tagged(value, "numeric")
                result = self.concat(result, value)
                index += 1
            position = match.end()
        return self.concat(result, scalar(template.literal[position:]))

    def builtin(self, name: str, args: tuple[Value, ...], arg_nodes: tuple[Node, ...], token: Token) -> Value:
        first = args[0] if args else EMPTY
        if name in ("mysqli_connect", "mysqli_init"):
            return self.allocate("mysqli")
        if name.startswith("mysqli_"):
            method = name[len("mysqli_"):]
            if method in ("query", "real_query", "multi_query", "execute_query", "prepare", "real_escape_string", "escape_string", "stmt_init", "set_charset", "close", "select_db", "autocommit", "begin_transaction", "commit", "rollback"):
                return self.method(first, method, args[1:], arg_nodes[1:], token)
            if method.startswith("stmt_"):
                return self.method(first, method[5:], args[1:], arg_nodes[1:], token)
            if method == "execute":
                return self.method(first, "execute", args[1:], arg_nodes[1:], token)
        if name in ("system", "exec", "shell_exec", "passthru", "popen"):
            self.record(COMMAND, token, self.unsafe(first, "shell"))
            return EMPTY
        if name == "proc_open":
            self.command(first, token)
            return EMPTY
        if name == "pcntl_exec":
            if len(args) > 1 and args[1].array:
                command = {0: first}
                command.update({index + 1: value for index, (_key, value) in enumerate(args[1].items)})
                self.command(array_value(command, args[1].fallback), token)
            else:
                self.record(COMMAND, token, first.fact)
                if len(args) > 1:
                    self.issue("Unresolved PHP pcntl_exec argument array")
            return EMPTY
        if name == "eval":
            self.record(CODE, token, self.unsafe(first, "code"))
            return EMPTY
        if name == "unserialize":
            self.record(DESERIALIZE, token, first.fact)
            return Value(first.fact)
        if name in ("printf", "vprintf"):
            values = args if name == "printf" else (first, *(value for _key, value in args[1].items)) if len(args) > 1 else args
            self.output(self.format_string(values), token)
            return EMPTY
        if name in ("print_r", "var_export", "var_dump"):
            returning = name != "var_dump" and len(args) > 1 and args[1].literal is True
            if not returning:
                self.output(first, token)
            return Value(first.fact, parts=(Part(None, first.fact),)) if returning else EMPTY
        if name in ("htmlspecialchars", "htmlentities"):
            flags = args[1].literal if len(args) > 1 else 11
            if not isinstance(flags, int):
                return first
            tags = ["html-text"]
            if flags & 2:
                tags.append("html-double")
            if flags & 1:
                tags.append("html-single")
            return tagged(first, *tags)
        if name in ("html_entity_decode", "htmlspecialchars_decode", "urldecode", "rawurldecode", "json_decode", "base64_decode", "hex2bin", "stripslashes", "stripcslashes"):
            value = without_proofs(first)
            return array_value({}, value) if name == "json_decode" and len(args) > 1 and args[1].literal is True else value
        if name in ("rawurlencode", "urlencode"):
            return tagged(first, "url-component")
        if name == "escapeshellarg":
            return tagged(first, "shell-arg")
        if name in ("intval", "floatval", "doubleval", "boolval", "abs", "round", "floor", "ceil"):
            return tagged(first, "numeric")
        if name in ("filter_input", "filter_var"):
            if name == "filter_input":
                value = self.source(token, "filter_input request value")
                filter_value = args[2].literal if len(args) > 2 else 516
                options = args[3] if len(args) > 3 else EMPTY
            else:
                value = first
                filter_value = args[1].literal if len(args) > 1 else 516
                options = args[2] if len(args) > 2 else EMPTY
            if filter_value in (257, 258, 259):
                return tagged(value, "numeric")
            if filter_value in (515, 522):
                flags = dict(options.items).get("flags", scalar(0)).literal if options.array else options.literal
                if (name == "filter_input" and len(args) < 4) or (name == "filter_var" and len(args) < 3):
                    flags = 0
                tags = ["html-text"]
                if isinstance(flags, int) and not flags & 128:
                    tags += ["html-double", "html-single"]
                return tagged(value, *tags)
            return value
        if name in ("json_encode", "wp_json_encode"):
            flags = args[1].literal if len(args) > 1 else 0
            return tagged(first, "js-literal") if isinstance(flags, int) and flags & 15 == 15 else Value(first.fact)
        if name in ("sprintf", "vsprintf"):
            values = args if name == "sprintf" else (first, *(value for _key, value in args[1].items)) if len(args) > 1 else args
            return self.format_string(values)
        if name == "implode" or name == "join":
            separator = first if len(args) > 1 else scalar("")
            values = args[1] if len(args) > 1 else first
            result = scalar("")
            for index, (_key, value) in enumerate(values.items):
                if index:
                    result = self.concat(result, separator)
                result = self.concat(result, value)
            if values.fallback:
                result = self.concat(result, values.fallback)
            return result
        if name == "strval":
            return scalar(php_string(first.literal)) if first.literal is not UNKNOWN else first
        if name in ("strtolower", "strtoupper", "ucfirst", "lcfirst"):
            if isinstance(first.literal, str):
                text = first.literal
                converted = text.lower() if name == "strtolower" else text.upper() if name == "strtoupper" else text[:1].upper() + text[1:] if name == "ucfirst" else text[:1].lower() + text[1:]
                return scalar(converted)
            return first
        if name in ("trim", "ltrim", "rtrim") and len(args) == 1:
            if isinstance(first.literal, str):
                return scalar({"trim": str.strip, "ltrim": str.lstrip, "rtrim": str.rstrip}[name](first.literal))
            return first
        if name == "str_replace":
            return without_proofs(joined(args[1], args[2])) if len(args) >= 3 else EMPTY
        if name == "preg_replace_callback":
            self.issue("PHP replacement callback effects are outside the selected subset")
            return EMPTY
        if name in ("trim", "ltrim", "rtrim", "substr", "mb_substr", "strip_tags", "escapeshellcmd", "addslashes", "basename", "dirname", "realpath", "wp_unslash", "sanitize_text_field"):
            return without_proofs(first)
        if name == "preg_replace":
            return without_proofs(joined(args[1], args[2])) if len(args) >= 3 else EMPTY
        if name in ("esc_html", "esc_attr"):
            return tagged(first, "html-text", "html-double", "html-single")
        if name == "esc_url":
            return tagged(first, "html-text", "html-double", "html-single", "html-url")
        if name == "file_get_contents" and first.literal == "php://input":
            return self.source(token, "PHP raw request body")
        if name in ("isset", "empty", "is_null", "is_array", "is_object", "is_string", "is_int", "is_integer", "is_float", "is_numeric", "is_bool", "ctype_digit", "in_array", "array_key_exists", "key_exists", "count", "sizeof", "strlen", "mb_strlen", "strpos", "str_contains", "str_starts_with", "str_ends_with", "preg_match", "preg_match_all", "assert", "getenv", "time", "date", "random_int", "random_bytes", "session_start", "session_write_close", "setcookie", "header", "http_response_code", "error_log", "exit", "die"):
            return EMPTY
        if name == "unset":
            for target in arg_nodes:
                self.assign(target, scalar(None))
            return EMPTY
        if name in ("array_values", "array_keys"):
            return array_value({index: scalar(key) if name == "array_keys" else value for index, (key, value) in enumerate(first.items)}, first.fallback)
        if name in ("array_merge", "array_replace", "array_map", "array_filter", "array_walk"):
            self.issue("PHP array callback/merge effects are outside the selected subset")
            return joined(*args)
        self.issue("Unknown external PHP call %s" % name)
        return EMPTY


def scan_file_findings(path: Path, enabled_rules: frozenset[str] | None = None):
    enabled = frozenset(RULES) if enabled_rules is None else frozenset(enabled_rules) & frozenset(RULES)
    if not enabled:
        return
    text = path.read_text(encoding="utf-8", errors="strict")
    engine = Engine(path, text, policy_limits(), enabled)
    failure = None
    try:
        engine.analyze()
    except (ValueError, RecursionError) as exc:
        failure = str(exc) or "PHP recursion limit exceeded; analysis is incomplete"
    suppression = build_index(text, lang="php")
    for (rule, offset), fact in sorted(engine.effects.items(), key=lambda item: (item[0][1], item[0][0])):
        token = Token("sink", "", offset, offset)
        line, col = engine.location(token)
        if suppression.is_suppressed(line, rule):
            continue
        category, number, title = RULES[rule]
        evidence = min((trace.evidence for trace in fact), key=lambda steps: (len(steps), steps))
        yield {"rule": rule, "category": number, "category_id": category,
               "path": str(path), "line": line, "col": col, "severity": "critical",
               "message": title, "lang": "php", "layer": "taint", "suppressed": False,
               "code": engine.lines[line - 1] if 0 < line <= len(engine.lines) else "",
               "extras": {"taint_path": [step.record() for step in evidence],
                          "source_count": len({trace.key for trace in fact}), "confidence": "unknown"}}
    errors = sorted(engine.issues)
    if failure:
        errors.append(failure)
    if errors:
        raise ValueError("; ".join(errors[:12]))


def _run(context: RunContext):
    enabled = frozenset(rule for rule in RULES if context.rule_enabled(rule))
    for path in context.files:
        yield from scan_file_findings(path, enabled)


register(Analyzer("taint", "php", "php-request-security", _run))
