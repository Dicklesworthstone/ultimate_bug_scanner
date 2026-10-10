"""Bounded structural PHP frontend shared by native security analyses.

This is a deliberately selected PHP 8.1+ subset, not a PHP runtime. The lexer
owns PHP tags, comments and string boundaries, including mixed HTML templates.
Unsupported syntax is recorded rather than silently interpreted as clean code.
Source offsets always refer to the original file, including interpolation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ubs_core.taint_flow import AnalysisLimit


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    start: int
    end: int
    quote: str = ""


@dataclass
class Lexed:
    tokens: list[Token]
    issues: list[str]
    spans: list[tuple[str, int, int]]


_NAME = re.compile(r"[A-Za-z_\x80-\uffff][A-Za-z_0-9\x80-\uffff]*(?:\\[A-Za-z_\x80-\uffff][A-Za-z_0-9\x80-\uffff]*)*")
_NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?)")
_OPERATORS = tuple(sorted(("?->", "??=", "===", "!==", "<=>", "**=", "<<=", ">>=", "...", "->", "::", "=>", ".=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "==", "!=", "<=", ">=", "&&", "||", "??", "++", "--", "**", "<<", ">>"), key=len, reverse=True))


def lex_php(text: str, max_tokens: int = 100_000, *, fragment: bool = False,
            offset: int = 0) -> Lexed:
    """Tokenize PHP islands, retaining original comment/string/HTML spans."""
    tokens: list[Token] = []
    issues: list[str] = []
    spans: list[tuple[str, int, int]] = []
    i, size = 0, len(text)
    php = fragment
    while i < size:
        if len(tokens) >= max_tokens:
            issues.append("PHP token limit exceeded; analysis is incomplete")
            break
        if not php:
            match = re.search(r"<\?(?:php(?=\s|$)|=)", text[i:], re.IGNORECASE)
            end = size if match is None else i + match.start()
            if end > i:
                tokens.append(Token("html", text[i:end], offset + i, offset + end))
                spans.append(("html", offset + i, offset + end))
            if match is None:
                i = size
                break
            start = end
            i += match.end()
            if text[start:i] == "<?=":
                tokens.append(Token("name", "echo", offset + start, offset + i))
            php = True
            continue
        char = text[i]
        if char.isspace():
            i += 1
            continue
        if not fragment and text.startswith("?>", i):
            tokens.append(Token("op", ";", offset + i, offset + i + 2))
            i += 2
            php = False
            continue
        if text.startswith("//", i) or (char == "#" and not text.startswith("#[", i)):
            end = text.find("\n", i)
            end = size if end < 0 else end
            close = text.find("?>", i, end) if not fragment else -1
            if close >= 0:
                end = close
            spans.append(("comment", offset + i, offset + end))
            i = end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                spans.append(("comment", offset + i, offset + size))
                issues.append("Unterminated PHP comment; analysis is incomplete")
                i = size
                break
            spans.append(("comment", offset + i, offset + end + 2))
            i = end + 2
            continue
        if text.startswith("<<<", i):
            head = re.match(r"<<<[ \t]*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\1[^\n]*\n", text[i:])
            if head is None:
                issues.append("Unsupported PHP heredoc header; analysis is incomplete")
                break
            body = i + head.end()
            tail = re.search(r"(?m)^[ \t]*" + re.escape(head.group(2)) + r"(?=[;,\)\]\r\n]|$)", text[body:])
            if tail is None:
                issues.append("Unterminated PHP heredoc; analysis is incomplete")
                spans.append(("string", offset + i, offset + size))
                i = size
                break
            end = body + tail.start()
            finish = body + tail.end()
            # Retain the body offset for embedded variables. Indentation has no
            # security proof meaning; its literal bytes remain conservative.
            tokens.append(Token("string", text[body:end], offset + body, offset + finish,
                                "'" if head.group(1) == "'" else '"'))
            spans.append(("string", offset + i, offset + finish))
            i = finish
            continue
        if char in "'\"`":
            start = i
            i += 1
            body = i
            while i < size:
                if text[i] == "\\":
                    i += 2
                elif text[i] == char:
                    break
                else:
                    i += 1
            if i >= size:
                issues.append("Unterminated PHP string; analysis is incomplete")
                spans.append(("string", offset + start, offset + size))
                i = size
                break
            tokens.append(Token("backtick" if char == "`" else "string", text[body:i],
                                offset + start, offset + i + 1, char))
            spans.append(("string", offset + start, offset + i + 1))
            i += 1
            continue
        if char == "$":
            match = _NAME.match(text, i + 1)
            if match is not None and "\\" not in match.group():
                tokens.append(Token("var", "$" + match.group(), offset + i, offset + match.end()))
                i = match.end()
                continue
        start = i
        if char == "\\":
            match = _NAME.match(text, i + 1)
            if match is not None:
                tokens.append(Token("name", "\\" + match.group(), offset + i, offset + match.end()))
                i = match.end()
                continue
        match = _NAME.match(text, i)
        if match is not None:
            tokens.append(Token("name", match.group(), offset + i, offset + match.end()))
            i = match.end()
            continue
        match = _NUMBER.match(text, i)
        if match is not None:
            tokens.append(Token("number", match.group(), offset + i, offset + match.end()))
            i = match.end()
            continue
        operator = next((op for op in _OPERATORS if text.startswith(op, i)), char)
        i += len(operator)
        tokens.append(Token("op", operator, offset + start, offset + i))
    tokens.append(Token("eof", "", offset + i, offset + i))
    return Lexed(tokens, issues, spans)


def lexical_spans(text: str) -> list[tuple[str, int, int]]:
    """The same lexical ownership used by the parser, for suppression indexes."""
    return lex_php(text, max_tokens=max(100_000, len(text) + 1)).spans


@dataclass(frozen=True)
class Node:
    kind: str
    token: Token
    value: Any = None
    children: tuple[Node, ...] = ()


@dataclass
class Parsed:
    statements: tuple[Node, ...]
    issues: list[str] = field(default_factory=list)


class ParseError(ValueError):
    pass


_PRECEDENCE = {
    "or": 1, "xor": 2, "and": 3,
    "=": 4, ".=": 4, "+=": 4, "-=": 4, "*=": 4, "/=": 4, "%=": 4,
    "&=": 4, "|=": 4, "^=": 4, "??=": 4, "<<=": 4, ">>=": 4, "**=": 4,
    "??": 6, "||": 7, "&&": 8, "|": 9, "^": 10, "&": 11,
    "==": 12, "!=": 12, "===": 12, "!==": 12,
    "<": 13, ">": 13, "<=": 13, ">=": 13, "<=>": 13, "instanceof": 13,
    ".": 14, "<<": 15, ">>": 15, "+": 16, "-": 16,
    "*": 17, "/": 17, "%": 17, "**": 18,
}
_ASSIGN = frozenset(op for op, precedence in _PRECEDENCE.items() if precedence == 4)


class Parser:
    def __init__(self, lexed: Lexed, max_nesting: int = 128):
        self.tokens = lexed.tokens
        self.issues = list(lexed.issues)
        self.pos = 0
        self.depth = 0
        self.max_nesting = max_nesting

    def current(self) -> Token:
        return self.tokens[min(self.pos, len(self.tokens) - 1)]

    def is_(self, value: str) -> bool:
        return self.current().text.lower() == value

    def take(self) -> Token:
        token = self.current()
        if token.kind != "eof":
            self.pos += 1
        return token

    def accept(self, text: str) -> Token | None:
        return self.take() if self.is_(text) else None

    def expect(self, text: str) -> Token:
        if not self.is_(text):
            raise ParseError("Expected %r at PHP offset %d; analysis is incomplete" % (text, self.current().start))
        return self.take()

    def enter(self) -> None:
        self.depth += 1
        if self.depth > self.max_nesting:
            raise AnalysisLimit("PHP nesting limit exceeded; analysis is incomplete")

    def parse(self, stop: str = "") -> Parsed:
        statements = []
        while self.current().kind != "eof" and not (stop and self.is_(stop)):
            before = self.pos
            try:
                statements.append(self.statement())
            except AnalysisLimit as exc:
                self.issues.append(str(exc))
                break
            except ParseError as exc:
                self.issues.append(str(exc))
                self.recover(stop)
            if self.pos == before:
                self.take()
        return Parsed(tuple(statements), self.issues)

    def recover(self, stop: str) -> None:
        depth = 0
        while self.current().kind != "eof":
            token = self.current()
            if depth == 0 and (token.text == ";" or (stop and token.text == stop)):
                if token.text == ";":
                    self.take()
                return
            token = self.take()
            if token.text in ("(", "[", "{"):
                depth += 1
            elif token.text in (")", "]", "}"):
                depth = max(0, depth - 1)

    def end_statement(self) -> None:
        if not self.accept(";") and self.current().kind != "eof" and not self.is_("}"):
            raise ParseError("Missing PHP statement terminator at offset %d; analysis is incomplete" % self.current().start)

    def block(self) -> Node:
        token = self.expect("{")
        self.enter()
        try:
            statements = self.parse("}").statements
            self.expect("}")
            return Node("block", token, children=statements)
        finally:
            self.depth -= 1

    def statement(self) -> Node:
        self.enter()
        try:
            return self._statement()
        finally:
            self.depth -= 1

    def _statement(self) -> Node:
        token = self.current()
        word = token.text.lower()
        if token.kind == "html":
            self.take()
            return Node("html", token, token.text)
        if word == ";":
            return Node("empty", self.take())
        if word == "{":
            return self.block()
        if word == "namespace":
            self.take()
            name = self.take().text if self.current().kind == "name" else ""
            if self.is_("{"):
                return Node("namespace", token, name, (self.block(),))
            self.expect(";")
            return Node("namespace", token, name)
        if word == "use":
            self.take()
            kind = self.take().text.lower() if self.is_("function") or self.is_("const") else "class"
            names = []
            while True:
                name = self.take()
                if name.kind != "name":
                    raise ParseError("Unsupported PHP import; analysis is incomplete")
                alias = name.text.rsplit("\\", 1)[-1]
                if self.accept("as"):
                    alias = self.take().text
                names.append((name.text.lstrip("\\"), alias))
                if not self.accept(","):
                    break
            self.expect(";")
            return Node("use", token, (kind, tuple(names)))
        if word in ("final", "abstract", "readonly"):
            self.take()
            if self.is_("class"):
                return self.class_definition()
            raise ParseError("Unsupported PHP declaration; analysis is incomplete")
        if word in ("class", "interface", "trait", "enum"):
            return self.class_definition()
        if word == "function":
            return self.function_definition(named=True)
        if word in ("if", "elseif"):
            self.take()
            self.expect("(")
            condition = self.expression()
            self.expect(")")
            yes = self.statement()
            if self.is_("elseif"):
                no = self.statement()
            elif self.accept("else"):
                no = self.statement()
            else:
                no = Node("empty", token)
            return Node("if", token, children=(condition, yes, no))
        if word in ("while", "for", "foreach"):
            self.take()
            self.expect("(")
            items = []
            while not self.is_(")") and self.current().kind != "eof":
                if self.accept(";") or self.accept(","):
                    items.append(Node("separator", token))
                elif self.accept("as"):
                    items.append(Node("as", token))
                elif self.accept("=>"):
                    items.append(Node("arrow", token))
                else:
                    items.append(self.expression())
            self.expect(")")
            return Node(word, token, children=(*items, self.statement()))
        if word == "do":
            self.take()
            body = self.statement()
            self.expect("while")
            self.expect("(")
            condition = self.expression()
            self.expect(")")
            self.end_statement()
            return Node("do", token, children=(condition, body))
        if word == "try":
            self.take()
            bodies = [self.block()]
            while self.accept("catch"):
                self.expect("(")
                while not self.is_(")") and self.current().kind != "eof":
                    self.take()
                self.expect(")")
                bodies.append(Node("catch", token, children=(self.block(),)))
            if self.accept("finally"):
                bodies.append(Node("finally", token, children=(self.block(),)))
            return Node("try", token, children=tuple(bodies))
        if word in ("return", "throw", "break", "continue", "global", "static", "echo", "const"):
            self.take()
            expressions = []
            if not self.is_(";") and not self.is_("}") and self.current().kind != "eof":
                while True:
                    expressions.append(self.expression())
                    if not self.accept(","):
                        break
            self.end_statement()
            return Node(word, token, children=tuple(expressions))
        if word == "declare":
            self.take()
            self.expect("(")
            while not self.is_(")") and self.current().kind != "eof":
                self.take()
            self.expect(")")
            self.end_statement()
            return Node("empty", token)
        expression = self.expression()
        self.end_statement()
        return Node("expr", token, children=(expression,))

    def parameters(self) -> tuple[tuple[str, str, bool, Node | None], ...]:
        self.expect("(")
        result = []
        while not self.is_(")") and self.current().kind != "eof":
            type_parts = []
            byref = False
            while self.current().kind not in ("var", "eof"):
                item = self.take().text
                if item == "&":
                    byref = True
                elif item == "...":
                    self.issues.append("PHP variadic parameters are outside the selected subset; analysis is incomplete")
                elif item in (",", ")"):
                    raise ParseError("Malformed PHP parameter; analysis is incomplete")
                else:
                    type_parts.append(item)
            variable = self.take()
            if variable.kind != "var":
                raise ParseError("Missing PHP parameter name; analysis is incomplete")
            default = self.expression(5) if self.accept("=") else None
            result.append((variable.text, "".join(type_parts), byref, default))
            if not self.accept(","):
                break
        self.expect(")")
        return tuple(result)

    def function_definition(self, *, named: bool = False, arrow: bool = False) -> Node:
        token = self.take()
        byref = bool(self.accept("&"))
        name = self.take().text if self.current().kind == "name" and not arrow else ""
        if named and not name:
            raise ParseError("Missing PHP function name; analysis is incomplete")
        params = self.parameters()
        captures = []
        if self.accept("use"):
            self.expect("(")
            while not self.is_(")") and self.current().kind != "eof":
                ref = bool(self.accept("&"))
                captures.append((self.take().text, ref))
                if not self.accept(","):
                    break
            self.expect(")")
        if self.accept(":"):
            while self.current().kind != "eof" and not self.is_("{") and not self.is_("=>") and not self.is_(";"):
                self.take()
        if arrow:
            self.expect("=>")
            body = Node("return", token, children=(self.expression(5),))
        elif self.accept(";"):
            body = Node("empty", token)
        else:
            body = self.block()
        return Node("function", token, {"name": name, "params": params, "captures": tuple(captures),
                                       "arrow": arrow, "byref": byref}, (body,))

    def class_definition(self) -> Node:
        token = self.take()
        name = self.take()
        if name.kind != "name":
            raise ParseError("Anonymous PHP classes are outside the selected subset; analysis is incomplete")
        bases = []
        while not self.is_("{") and self.current().kind != "eof":
            bases.append(self.take().text)
        self.expect("{")
        members = []
        while not self.is_("}") and self.current().kind != "eof":
            while self.current().text.lower() in ("public", "private", "protected", "static", "readonly", "final", "abstract", "var"):
                self.take()
            if self.is_("function"):
                members.append(self.function_definition(named=True))
            else:
                while self.current().kind == "name" and not self.is_("const"):
                    self.take()
                members.append(self.statement())
        self.expect("}")
        if token.text.lower() != "class":
            self.issues.append("PHP %s semantics are outside the selected subset; analysis is incomplete" % token.text)
        return Node("class", token, {"name": name.text, "bases": tuple(bases)}, tuple(members))

    def expression(self, minimum: int = 0) -> Node:
        self.enter()
        try:
            left = self.prefix()
            while True:
                token = self.current()
                op = token.text.lower()
                if op in ("(", "[", "->", "?->", "::", "++", "--"):
                    if op == "(":
                        args = self.arguments()
                        left = Node("call", left.token, children=(left, *args))
                    elif op == "[":
                        self.take()
                        index = Node("append", token) if self.is_("]") else self.expression()
                        self.expect("]")
                        left = Node("index", left.token, children=(left, index))
                    elif op in ("->", "?->", "::"):
                        self.take()
                        member = self.take()
                        if member.kind not in ("name", "var"):
                            raise ParseError("Dynamic PHP member syntax is unsupported; analysis is incomplete")
                        left = Node("member", left.token, (op, member.text, member.kind), (left,))
                    else:
                        self.take()
                        left = Node("postfix", left.token, op, (left,))
                    continue
                if op == "?" and minimum <= 5:
                    self.take()
                    yes = left if self.is_(":") else self.expression()
                    self.expect(":")
                    no = self.expression(5)
                    left = Node("ternary", left.token, children=(left, yes, no))
                    continue
                precedence = _PRECEDENCE.get(op, -1)
                if precedence < minimum:
                    break
                self.take()
                right = self.expression(precedence if op in _ASSIGN or op in ("??", "**") else precedence + 1)
                left = Node("assign" if op in _ASSIGN else "binary", left.token, op, (left, right))
            return left
        finally:
            self.depth -= 1

    def prefix(self) -> Node:
        token = self.current()
        word = token.text.lower()
        if token.kind in ("string", "backtick", "number", "var"):
            self.take()
            return Node(token.kind, token, token.text)
        if word in ("function", "fn"):
            return self.function_definition(arrow=word == "fn")
        if word == "new":
            self.take()
            name = self.take()
            if name.kind != "name":
                raise ParseError("Dynamic PHP allocation is unsupported; analysis is incomplete")
            args = self.arguments() if self.is_("(") else ()
            return Node("new", token, name.text, args)
        if word in ("!", "~", "+", "-", "@", "&", "++", "--"):
            self.take()
            return Node("unary", token, word, (self.expression(18),))
        if word in ("include", "include_once", "require", "require_once", "print", "throw", "yield"):
            self.take()
            return Node("unary", token, word, (self.expression(4),))
        if word == "(":
            self.take()
            if self.current().text.lower() in ("int", "integer", "float", "double", "real", "string", "bool", "boolean", "array", "object", "unset") and self.tokens[min(self.pos + 1, len(self.tokens) - 1)].text == ")":
                cast = self.take().text.lower()
                self.take()
                return Node("cast", token, cast, (self.expression(18),))
            result = self.expression()
            self.expect(")")
            return result
        if word in ("[", "array"):
            self.take()
            closing = "]" if word == "[" else ")"
            if word == "array":
                self.expect("(")
            entries = []
            while not self.is_(closing) and self.current().kind != "eof":
                if self.accept("..."):
                    entries.append(Node("spread", token, children=(self.expression(5),)))
                else:
                    entry = self.expression(5)
                    if self.accept("=>"):
                        entry = Node("entry", entry.token, children=(entry, self.expression(5)))
                    entries.append(entry)
                if not self.accept(","):
                    break
            self.expect(closing)
            return Node("array", token, children=tuple(entries))
        if token.kind == "name":
            self.take()
            return Node("name", token, token.text)
        raise ParseError("Unsupported PHP expression %r at offset %d; analysis is incomplete" % (token.text, token.start))

    def arguments(self) -> tuple[Node, ...]:
        self.expect("(")
        arguments = []
        while not self.is_(")") and self.current().kind != "eof":
            if self.accept("..."):
                arguments.append(Node("spread", self.current(), children=(self.expression(5),)))
            elif self.current().kind == "name" and self.tokens[min(self.pos + 1, len(self.tokens) - 1)].text == ":":
                token = self.take()
                self.take()
                arguments.append(Node("named", token, token.text, (self.expression(5),)))
            else:
                arguments.append(self.expression(5))
            if not self.accept(","):
                break
        self.expect(")")
        return tuple(arguments)


def parse_php(text: str, *, max_tokens: int = 100_000, max_nesting: int = 128) -> Parsed:
    return Parser(lex_php(text, max_tokens), max_nesting).parse()
