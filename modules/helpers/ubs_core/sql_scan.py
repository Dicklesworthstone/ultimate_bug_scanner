"""Bounded PostgreSQL migration checks, without executing SQL or loading a database.

This is a selected-file DDL model, not a catalog or a PL/pgSQL interpreter.
Dollar-quoted bodies are opaque. Function identity includes input argument
types; privilege changes take effect at transaction publication boundaries.
Unknown DDL context is reported explicitly and is never cached as complete.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, field
import datetime
import json
import os
from pathlib import Path
import re
import sys

from ubs_core.suppression import has_suppression_marker

RULES = {
    "sql.security.definer-search-path": ("search-path", 1, "SECURITY DEFINER search path permits object shadowing"),
    "sql.security.definer-public-execute": ("privileges", 2, "SECURITY DEFINER function is executable by PUBLIC"),
}
RULE_METADATA = {
    "sql.security.definer-search-path": {
        "language": "sql", "name": "SECURITY DEFINER search path", "family": "function_privileges",
        "category_id": "sql.search-path", "severity": "warning", "confidence": "unknown",
        "message": "Function-local schema lookup can expose objects used with definer privileges.",
        "remediation": "Set search_path to schemas whose CREATE privileges are restricted to trusted roles, with pg_temp last. Fully qualify references; an empty path does not exclude temporary relations.",
        "manifest_cases": ["sql-definer-buggy", "sql-definer-clean"],
    },
    "sql.security.definer-public-execute": {
        "language": "sql", "name": "SECURITY DEFINER PUBLIC execution", "family": "function_privileges",
        "category_id": "sql.privileges", "severity": "warning", "confidence": "unknown",
        "message": "A selected migration publishes a privileged function with PUBLIC execution access.",
        "remediation": "Create the function, REVOKE EXECUTE or ALL from PUBLIC, and GRANT EXECUTE to intended roles before COMMIT. Match input argument types; revoking only a grant option does not revoke EXECUTE.",
        "manifest_cases": ["sql-definer-buggy", "sql-definer-clean"],
    },
}
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOKENS = 200000
MAX_STATEMENTS = 10000
MAX_FUNCTIONS = 2000
MAX_SAVEPOINTS = 64
WHITESPACE_RE = re.compile(r"\s+")
DOLLAR_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")


class Incomplete(ValueError):
    """Source outside the deliberately bounded PostgreSQL DDL model."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    col: int
    start: int
    end: int

    def is_word(self, value: str) -> bool:
        return self.kind == "word" and self.value == value


def lex(text: str, comments: list[Token]):
    """Yield tokens; literals/comments cannot inject DDL into the outer stream."""
    pos, line, col, count = 0, 1, 1, 0
    size = len(text)
    while pos < size:
        start, start_line, start_col = pos, line, col
        char = text[pos]
        kind, value = "symbol", char
        if char.isspace():
            match = WHITESPACE_RE.match(text, pos)
            end = match.end()
            kind = "space"
        elif text.startswith("--", pos):
            end = text.find("\n", pos)
            if end < 0:
                end = size
            kind, value = "comment", text[pos:end]
        elif text.startswith("/*", pos):
            depth, end = 1, pos + 2
            while depth and end < size:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise Incomplete(f"line {line}: unterminated block comment")
            kind, value = "comment", text[pos:end]
        elif char == "$" and (match := DOLLAR_RE.match(text, pos)):
            delimiter = match.group()
            end = text.find(delimiter, pos + len(delimiter))
            if end < 0:
                raise Incomplete(f"line {line}: unterminated dollar-quoted body")
            value = text[pos + len(delimiter):end]
            end += len(delimiter)
            kind = "body"
        elif char in "'\"" or (char in "eE" and text[pos:pos + 2].lower() == "e'"):
            escape = char in "eE"
            quote = "'" if escape else char
            end = pos + (2 if escape else 1)
            parts = []
            while end < size:
                if text[end] == quote:
                    if end + 1 < size and text[end + 1] == quote:
                        parts.append(quote)
                        end += 2
                        continue
                    end += 1
                    break
                if escape and text[end] == "\\":
                    if end + 1 >= size:
                        raise Incomplete(f"line {line}: unterminated escape string")
                    # Bodies remain opaque; escaped configuration values are
                    # not used as trusted paths by parse_search_path below.
                    parts.append(text[end:end + 2])
                    end += 2
                else:
                    parts.append(text[end])
                    end += 1
            else:
                raise Incomplete(f"line {line}: unterminated quoted literal or identifier")
            kind = "quoted" if quote == '"' else "escape" if escape else "string"
            value = "".join(parts)
        elif char.isalpha() or char == "_":
            end = pos + 1
            while end < size and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            kind, value = "word", text[pos:end].lower()
        elif char.isdigit():
            end = pos + 1
            while end < size and text[end].isdigit():
                end += 1
            kind, value = "number", text[pos:end]
        else:
            end = pos + 1
        consumed = text[pos:end]
        if "\n" in consumed:
            line += consumed.count("\n")
            col = len(consumed.rsplit("\n", 1)[1]) + 1
        else:
            col += end - pos
        pos = end
        token = Token(kind, value, start_line, start_col, start, end)
        if kind == "comment":
            comments.append(token)
        elif kind != "space":
            count += 1
            if count > MAX_TOKENS:
                raise Incomplete("SQL token budget exhausted")
            yield token


def split_top(tokens: list[Token], separator: str = ",") -> list[list[Token]]:
    groups, current, stack = [], [], []
    for token in tokens:
        if token.value in ("(", "[") and token.kind == "symbol":
            stack.append(token.value)
        elif token.value in (")", "]") and token.kind == "symbol":
            if not stack or stack.pop() != {")": "(", "]": "["}[token.value]:
                # Check matching kinds, not only a combined delimiter count.
                raise Incomplete("unbalanced SQL delimiters")
        if token.kind == "symbol" and token.value == separator and not stack:
            groups.append(current)
            current = []
        else:
            current.append(token)
    if stack:
        raise Incomplete("unbalanced SQL delimiters")
    groups.append(current)
    return groups


TYPE_ALIASES = {
    "int": "int4", "integer": "int4", "smallint": "int2", "bigint": "int8",
    "decimal": "numeric", "boolean": "bool", "real": "float4", "double precision": "float8",
    "character varying": "varchar", "character": "bpchar", "char": "bpchar",
    "timestamp without time zone": "timestamp", "timestamp with time zone": "timestamptz",
    "time without time zone": "time", "time with time zone": "timetz",
}
TYPE_STARTS = frozenset({
    *TYPE_ALIASES, *TYPE_ALIASES.values(), "double", "character", "bit", "varying",
    "text", "uuid", "bytea", "json", "jsonb", "date", "interval", "record", "void",
    "int2", "int4", "int8", "float4", "float8", "numeric", "bool", "varchar", "bpchar",
    "timestamp", "time", "timestamptz", "timetz", "oid", "name", "inet", "cidr",
    "anyelement", "anyarray", "anycompatible", "anycompatiblearray",
})


def argument_type(tokens: list[Token], declaration: bool) -> str | None:
    tokens = list(tokens)
    if not tokens:
        raise Incomplete("empty function argument")
    if tokens[0].is_word("out"):
        return None
    if tokens[0].kind == "word" and tokens[0].value in {"in", "inout", "variadic"}:
        tokens = tokens[1:]
    # Default expressions do not participate in overload identity.
    depth = 0
    for index, token in enumerate(tokens):
        if depth == 0 and (token.is_word("default") or token.value == "="):
            tokens = tokens[:index]
            break
        if token.value in {"(", "["}:
            depth += 1
        elif token.value in {")", "]"}:
            depth -= 1
    if not tokens:
        raise Incomplete("missing function argument type")
    if len(tokens) > 1 and tokens[1].kind in {"word", "quoted"}:
        # A parameter may itself be named "name", "date", "time", or
        # "text". Only actual multiword type grammar keeps both words.
        multiword = (sequence(tokens, "double", "precision") or
                     sequence(tokens, "character", "varying") or
                     sequence(tokens, "bit", "varying") or
                     (tokens[0].kind == "word" and tokens[0].value in {"time", "timestamp"}
                      and tokens[1].kind == "word" and tokens[1].value in {"with", "without"}))
        if not multiword:
            tokens = tokens[1:]
    # Typmods are explicitly discarded by PostgreSQL function identity.
    words, depth = [], 0
    quoted_type = any(token.kind == "quoted" for token in tokens)
    for token in tokens:
        if token.kind == "symbol" and token.value == "(":
            depth += 1
        elif token.kind == "symbol" and token.value == ")":
            depth -= 1
        elif depth == 0:
            if token.kind not in {"word", "quoted"} and token.value not in {".", "[", "]"}:
                raise Incomplete("unsupported function argument type")
            # Preserve a quoted single identifier containing punctuation;
            # "app.money" must not become the qualified type app.money.
            value = token.value
            if token.kind == "quoted" and not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9$]*", value):
                value = '"' + value.replace('"', '""') + '"'
            words.append(value)
    if depth or not words:
        raise Incomplete("unresolved function argument type")
    array = ""
    while len(words) >= 2 and words[-2:] == ["[", "]"]:
        array = "[]"  # PostgreSQL ignores the number of declared dimensions.
        words = words[:-2]
    if words[:2] == ["pg_catalog", "."]:
        words = words[2:]
    name = " ".join(words).replace(" . ", ".")
    return (name if quoted_type else TYPE_ALIASES.get(name, name)) + array


def function_identity(tokens: list[Token], start: int, *, declaration: bool = False):
    names = []
    index = start
    while index < len(tokens) and tokens[index].kind in {"word", "quoted"}:
        names.append(tokens[index].value)
        index += 1
        if index >= len(tokens) or tokens[index].value != ".":
            break
        index += 1
    if not names or len(names) > 2 or index >= len(tokens) or tokens[index].value != "(":
        raise Incomplete("function identity requires a literal name and input argument signature")
    opening, depth = index, 1
    index += 1
    while index < len(tokens) and depth:
        if tokens[index].kind == "symbol":
            if tokens[index].value == "(":
                depth += 1
            elif tokens[index].value == ")":
                depth -= 1
        index += 1
    if depth:
        raise Incomplete("unterminated function signature")
    arguments = tokens[opening + 1:index - 1]
    types = []
    if arguments:
        for group in split_top(arguments):
            value = argument_type(group, declaration)
            if value is not None:
                types.append(value)
    return (tuple(names), tuple(types)), index


def sequence(tokens: list[Token], *words: str) -> bool:
    return len(tokens) >= len(words) and all(token.is_word(word) for token, word in zip(tokens, words))


def word_index(tokens: list[Token], word: str, start: int = 0) -> int:
    return next((i for i in range(start, len(tokens)) if tokens[i].is_word(word)), -1)


def parse_search_path(tokens: list[Token]) -> tuple[str, ...]:
    if sequence(tokens, "from", "current"):
        raise Incomplete("search_path FROM CURRENT depends on an unavailable session setting")
    if tokens and (tokens[0].is_word("to") or tokens[0].value == "="):
        tokens = tokens[1:]
    if len(tokens) == 1 and tokens[0].kind == "string":
        if not tokens[0].value.strip():
            return ()
        tokens = list(lex(tokens[0].value, []))
    if not tokens:
        raise Incomplete("missing search_path value")
    names = []
    for group in split_top(tokens):
        if len(group) != 1 or group[0].kind not in {"word", "quoted", "string"}:
            raise Incomplete("search_path is not a literal schema list")
        names.append(group[0].value)
    return tuple(names)


@dataclass
class Function:
    key: tuple
    anchor: Token
    end: int
    definer: bool = False
    search_path: tuple[str, ...] | None = None
    path_unknown: bool = False
    public: bool | None = True
    body: str = ""
    language: str = ""


@dataclass
class State:
    functions: dict[tuple, Function] = field(default_factory=dict)
    schema_public_create: dict[str, bool] = field(default_factory=dict)
    default_public: bool | None = True
    session_path_changed: bool = False


def function_options(function: Function, tokens: list[Token], errors: list[str]) -> None:
    index, depth = 0, 0
    boundaries = {"set", "as", "language", "security", "external", "cost", "rows", "support",
                  "immutable", "stable", "volatile", "strict", "called", "returns", "parallel",
                  "leakproof", "not", "window", "transform", "return", "begin"}
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "symbol" and token.value == "(":
            depth += 1
        elif token.kind == "symbol" and token.value == ")":
            depth -= 1
        if depth or (token.kind == "symbol" and token.value == ")"):
            index += 1
            continue
        if sequence(tokens[index:], "security", "definer"):
            function.definer = True
            index += 2
        elif sequence(tokens[index:], "security", "invoker"):
            function.definer = False
            index += 2
        elif sequence(tokens[index:], "reset", "search_path") or sequence(tokens[index:], "reset", "all"):
            function.search_path, function.path_unknown = None, False
            index += 2
        elif sequence(tokens[index:], "set", "search_path"):
            end = index + 2
            while end < len(tokens) and not (tokens[end].kind == "word" and tokens[end].value in boundaries):
                end += 1
            try:
                function.search_path = parse_search_path(tokens[index + 2:end])
                function.path_unknown = False
            except Incomplete as exc:
                function.path_unknown = True
                errors.append(f"line {token.line}: {exc}")
            index = end
        elif token.is_word("language") and index + 1 < len(tokens):
            function.language = tokens[index + 1].value
            index += 2
        elif token.is_word("as") and index + 1 < len(tokens) and tokens[index + 1].kind in {"body", "string"}:
            function.body = tokens[index + 1].value
            index += 2
        else:
            index += 1


def empty_path_body(function: Function) -> bool:
    """A small explicit proof for empty-path SQL expressions/qualified reads.

    pg_temp is still implicit for relations and types. Accept only a simple
    SELECT expression without casts/subqueries and with fully qualified FROM
    or JOIN operands. Procedural/dynamic bodies require a nonempty safe path.
    """
    if function.language != "sql":
        raise Incomplete("empty search_path requires a checked SQL body or an explicit pg_temp-last path")
    tokens = list(lex(function.body, []))
    if not sequence(tokens, "select"):
        raise Incomplete("empty search_path body is outside the bounded SELECT proof")
    depth = 0
    for index, token in enumerate(tokens):
        if token.kind in {"body", "escape"}:
            raise Incomplete("nested/dynamic body is outside the empty search_path proof")
        if token.kind == "symbol":
            if token.value == ":":
                raise Incomplete("type lookup is outside the empty search_path proof")
            if token.value == ";" and index != len(tokens) - 1:
                raise Incomplete("multiple statements are outside the empty search_path proof")
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
        if token.kind == "word" and token.value in {"with", "cast", "execute", "into"}:
            raise Incomplete("body requires unmodeled relation/type lookup with empty search_path")
        if index and token.is_word("select"):
            raise Incomplete("subquery is outside the empty search_path proof")
        if token.kind == "word" and token.value in {"from", "join"}:
            operand = tokens[index + 1:index + 4]
            if (len(operand) != 3 or operand[0].kind not in {"word", "quoted"}
                    or operand[1].value != "." or operand[2].kind not in {"word", "quoted"}):
                return False
        if depth < 0:
            raise Incomplete("unbalanced function body")
    if depth:
        raise Incomplete("unbalanced function body")
    return True


def analyze_source(text: str, path: str = "<input>") -> tuple[list[dict], list[str]]:
    """Analyze one ordered migration, preserving committed exposure windows."""
    if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
        return [], ["SQL source byte budget exhausted"]
    state = State()
    transaction: State | None = None
    savepoints: list[tuple[str, State]] = []
    comments: list[Token] = []
    findings: dict[tuple, dict] = {}
    finding_spans: dict[tuple, tuple[int, int, int]] = {}
    errors: list[str] = []

    def publish():
        for function in state.functions.values():
            if not function.definer:
                continue
            name = ".".join(function.key[0]) + "(" + ", ".join(function.key[1]) + ")"
            messages = {}
            schemas = function.search_path
            if not function.path_unknown:
                if schemas is None:
                    messages["sql.security.definer-search-path"] = "No function-local search_path is set; caller/session schemas can shadow objects used with definer privileges."
                elif schemas:
                    if "pg_temp" not in schemas:
                        messages["sql.security.definer-search-path"] = "pg_temp is omitted and is implicitly searched first for relations and types. Put it after trusted schemas."
                    elif schemas.index("pg_temp") != len(schemas) - 1:
                        messages["sql.security.definer-search-path"] = "pg_temp precedes another schema; temporary objects can shadow trusted relations or types."
                    elif "$user" in schemas or any(state.schema_public_create.get(schema) is True for schema in schemas):
                        messages["sql.security.definer-search-path"] = "The search_path contains a role-dependent schema or a schema explicitly writable by PUBLIC."
                    else:
                        unknown = [schema for schema in schemas if schema not in {"pg_catalog", "pg_temp"}
                                   and schema not in state.schema_public_create]
                        if unknown:
                            errors.append(f"line {function.anchor.line}: search_path schema CREATE privileges are unknown: {', '.join(unknown)}")
                else:
                    try:
                        if not empty_path_body(function):
                            messages["sql.security.definer-search-path"] = "Empty search_path still searches pg_temp first; the function body uses an unqualified relation."
                    except Incomplete as exc:
                        errors.append(f"line {function.anchor.line}: {exc}")
            if function.public is True:
                messages["sql.security.definer-public-execute"] = "PUBLIC can execute this SECURITY DEFINER function under the selected migration's default or explicit grants. Revoke PUBLIC EXECUTE and grant intended roles in the same transaction."
            elif function.public is None:
                errors.append(f"line {function.anchor.line}: existing/default ACL of {name} is unknown; CREATE OR REPLACE preserves existing privileges")
            for rule, message in messages.items():
                slug, _category, _title = RULES[rule]
                record = {
                    "rule": rule, "path": path, "line": function.anchor.line,
                    "col": function.anchor.col, "severity": "warning", "category_id": slug,
                    "message": name + ": " + message, "suppressed": False,
                    "extras": {"dialect": "postgresql", "function": name,
                               "scope": "selected migration; external schema ownership and ACLs are not proved"},
                }
                identity = (function.key, function.anchor.line, rule)
                findings.setdefault(identity, record)
                finding_spans.setdefault(identity, (function.anchor.start, function.end, function.anchor.line))

    def privilege(statement: list[Token]):
        grant = statement[0].is_word("grant")
        if any(sequence(statement[index:], "granted", "by") for index in range(len(statement))):
            raise Incomplete("GRANTED BY requires grant-chain context")
        if sequence(statement, "revoke", "grant", "option", "for"):
            return  # Delegation is revoked; the underlying privilege remains.
        on = word_index(statement, "on")
        direction = word_index(statement, "to" if grant else "from", max(0, on))
        if on < 0 or direction < 0:
            raise Incomplete("unresolved privilege statement")
        roles = statement[direction + 1:]
        # Quoted "PUBLIC" names a role, not PostgreSQL's PUBLIC pseudo-role.
        public = any(token.is_word("public") for token in roles)
        if not public:
            return
        privileges = statement[1:on]
        if statement[on + 1].is_word("schema"):
            if not any(token.is_word("create") or token.is_word("all") for token in privileges):
                return
            for group in split_top(statement[on + 2:direction]):
                if len(group) != 1 or group[0].kind not in {"word", "quoted"}:
                    raise Incomplete("unresolved schema privilege target")
                state.schema_public_create[group[0].value] = grant
            return
        if not any(token.is_word("execute") or token.is_word("all") for token in privileges):
            return
        if sequence(statement[on + 1:], "all", "functions", "in", "schema"):
            schemas = []
            for group in split_top(statement[on + 5:direction]):
                if len(group) != 1 or group[0].kind not in {"word", "quoted"}:
                    raise Incomplete("unresolved schema-wide function privilege target")
                schemas.append(group[0].value)
            for function in state.functions.values():
                if len(function.key[0]) == 2 and function.key[0][0] in schemas:
                    function.public = grant
            return  # The rule covers selected functions, not unseen catalog rows.
        if statement[on + 1].kind != "word" or statement[on + 1].value not in {"function", "routine"}:
            return
        for group in split_top(statement[on + 2:direction]):
            key, end = function_identity(group, 0)
            if end != len(group) or key not in state.functions:
                raise Incomplete("function privilege target is not resolved in the selected migration")
            state.functions[key].public = grant

    def process(statement: list[Token]):
        nonlocal state, transaction, savepoints
        if not statement:
            return
        first = statement[0]
        split_top(statement)  # Check delimiters even in ordinary DML.
        if first.kind != "word":
            raise Incomplete(f"line {first.line}: unsupported SQL or psql command")
        if first.value in {"delimiter", "pragma", "go"} or sequence(statement, "use"):
            raise Incomplete(f"line {first.line}: non-PostgreSQL dialect syntax")
        if sequence(statement, "begin") or sequence(statement, "start", "transaction"):
            if transaction is not None:
                raise Incomplete("nested transaction start")
            transaction = copy.deepcopy(state)
            savepoints = []
            return
        if sequence(statement, "savepoint"):
            if transaction is None or len(statement) != 2:
                raise Incomplete("unresolved SAVEPOINT")
            if len(savepoints) >= MAX_SAVEPOINTS:
                raise Incomplete("SQL savepoint-state budget exhausted")
            savepoints.append((statement[1].value, copy.deepcopy(state)))
            return
        rollback_tail = statement[1:]
        if rollback_tail and rollback_tail[0].kind == "word" and rollback_tail[0].value in {"work", "transaction"}:
            rollback_tail = rollback_tail[1:]
        if first.is_word("rollback") and sequence(rollback_tail, "to"):
            rest = rollback_tail[1:]
            if sequence(rest, "savepoint"):
                rest = rest[1:]
            if len(rest) != 1 or rest[0].kind not in {"word", "quoted"}:
                raise Incomplete("unresolved ROLLBACK TO target")
            name = statement[-1].value
            match = next((i for i in range(len(savepoints) - 1, -1, -1) if savepoints[i][0] == name), -1)
            if match < 0:
                raise Incomplete("ROLLBACK TO has no selected SAVEPOINT")
            state = copy.deepcopy(savepoints[match][1])
            savepoints = savepoints[:match + 1]
            return
        if first.value in {"rollback", "abort"}:
            if rollback_tail:
                raise Incomplete("unsupported rollback syntax")
            if transaction is None:
                raise Incomplete("ROLLBACK has no selected transaction")
            state, transaction, savepoints = transaction, None, []
            return
        if first.value in {"commit", "end"}:
            if len(statement) > 2 or (len(statement) == 2 and not
                    (statement[1].is_word("work") or statement[1].is_word("transaction"))):
                raise Incomplete("unsupported commit syntax or external prepared transaction")
            publish()
            transaction, savepoints = None, []
            return
        if sequence(statement, "release"):
            name = statement[-1].value
            match = next((i for i in range(len(savepoints) - 1, -1, -1) if savepoints[i][0] == name), -1)
            if match < 0:
                raise Incomplete("RELEASE has no selected SAVEPOINT")
            savepoints = savepoints[:match]
            return
        if sequence(statement, "alter", "default", "privileges"):
            tail = statement[3:]
            if not (sequence(tail, "grant") or sequence(tail, "revoke")):
                state.default_public = None
                raise Incomplete("role/schema-specific default privileges require external context")
            if not any(token.is_word("public") for token in tail):
                return
            if sequence(tail, "revoke", "grant", "option", "for"):
                return
            if any(sequence(tail[index:], "granted", "by") for index in range(len(tail))):
                state.default_public = None
                raise Incomplete("default privilege grantor requires external role context")
            on = word_index(tail, "on")
            if on < 0 or not sequence(tail[on + 1:], "functions"):
                raise Incomplete("unsupported default privilege target")
            if any(token.is_word("all") or token.is_word("execute") for token in tail[1:on]):
                state.default_public = tail[0].is_word("grant")
        elif sequence(statement, "create", "schema"):
            if len(statement) < 3 or statement[2].kind not in {"word", "quoted"} or statement[2].is_word("if"):
                raise Incomplete("unresolved schema creation")
            state.schema_public_create[statement[2].value] = False
        elif sequence(statement, "create", "function") or sequence(statement, "create", "or", "replace", "function"):
            replace = sequence(statement, "create", "or", "replace")
            key, end = function_identity(statement, 4 if replace else 2, declaration=True)
            if len(state.functions) >= MAX_FUNCTIONS and key not in state.functions:
                raise Incomplete("SQL function-state budget exhausted")
            if any(sequence(statement[index:], "begin", "atomic") for index in range(end, len(statement))):
                raise Incomplete("SQL-standard BEGIN ATOMIC function bodies are outside the selected body model")
            if not any(token.is_word("language") for token in statement[end:]):
                raise Incomplete("function declaration lacks a PostgreSQL LANGUAGE clause")
            previous = state.functions.get(key)
            if len(key[0]) == 1 and state.session_path_changed:
                raise Incomplete("unqualified function identity depends on the session search_path")
            public = previous.public if replace and previous else None if replace else state.default_public
            function = Function(key, first, statement[-1].end, public=public)
            function_options(function, statement[end:], errors)
            body_index = word_index(statement, "as", end)
            if (body_index < 0 or body_index + 1 >= len(statement)
                    or statement[body_index + 1].kind not in {"body", "string"}):
                raise Incomplete("function requires a literal PostgreSQL AS body")
            state.functions[key] = function
        elif sequence(statement, "alter", "function"):
            key, end = function_identity(statement, 2)
            if key not in state.functions:
                raise Incomplete("ALTER FUNCTION target is not resolved in the selected migration")
            function = state.functions[key]
            function.anchor, function.end = first, statement[-1].end
            tail = statement[end:]
            if any(token.is_word("rename") or token.is_word("schema") or token.is_word("owner") for token in tail):
                raise Incomplete("ALTER FUNCTION identity/ownership change requires additional catalog context")
            function_options(function, tail, errors)
        elif first.value in {"grant", "revoke"}:
            privilege(statement)
        elif sequence(statement, "drop", "function"):
            tail = statement[2:]
            if sequence(tail, "if", "exists"):
                tail = tail[2:]
            for group in split_top(tail):
                key, _end = function_identity(group, 0)
                state.functions.pop(key, None)
        elif first.value in {"do", "execute", "prepare", "call"}:
            raise Incomplete("dynamic or external SQL execution is outside the selected migration model")
        elif first.is_word("set"):
            tail = statement[1:]
            if tail and tail[0].kind == "word" and tail[0].value in {"local", "session"}:
                tail = tail[1:]
            if sequence(tail, "search_path"):
                parse_search_path(tail[1:])
                state.session_path_changed = True
            elif sequence(tail, "role") or sequence(tail, "authorization"):
                state.default_public = None
                raise Incomplete("role change invalidates selected default privileges")
        elif sequence(statement, "create", "procedure") or sequence(statement, "create", "or", "replace", "procedure") or sequence(statement, "alter", "procedure"):
            raise Incomplete("procedure privilege analysis is outside the function-only model")
        elif first.value not in {"select", "insert", "update", "delete", "create", "alter", "drop",
                                 "comment", "set", "reset", "truncate", "vacuum", "analyze", "explain"}:
            raise Incomplete(f"line {first.line}: unsupported PostgreSQL statement {first.value!r}")
        if transaction is None:
            publish()

    statement: list[Token] = []
    statement_count = 0
    try:
        for token in lex(text, comments):
            if token.kind == "symbol" and token.value == ";":
                statement_count += 1
                if statement_count > MAX_STATEMENTS:
                    raise Incomplete("SQL statement budget exhausted")
                try:
                    process(statement)
                except (Incomplete, IndexError) as exc:
                    errors.append(f"line {statement[0].line if statement else token.line}: {exc or 'incomplete SQL statement'}")
                statement = []
            else:
                statement.append(token)
        if statement:
            try:
                process(statement)
            except (Incomplete, IndexError) as exc:
                errors.append(f"line {statement[0].line}: {exc or 'incomplete SQL statement'}")
    except Incomplete as exc:
        errors.append(str(exc))
    if transaction is not None:
        errors.append("transaction is not committed or rolled back in the selected migration")
    visible = []
    for identity, record in findings.items():
        start, end, line = finding_spans[identity]
        suppressed = False
        # Resolve comments after lexing so a trailing marker after the final
        # semicolon owns that statement. Bodies and SQL strings remain opaque.
        for comment in comments:
            if not has_suppression_marker(comment.value, record["rule"]):
                continue
            preceding = (comment.line == line - 1 and
                         not text[text.rfind("\n", 0, comment.start) + 1:comment.start].strip())
            trailing = (comment.start >= end and "\n" not in text[end:comment.start]
                        and text[end:comment.start].strip() in {"", ";"})
            if preceding or trailing or start <= comment.start <= end:
                suppressed = True
                break
        if not suppressed:
            visible.append(record)
    return visible, list(dict.fromkeys(errors))


def categories(value: str) -> set[int]:
    if not value:
        return set()
    parts = value.split(",")
    if any(not part.strip().isdigit() or int(part) < 1 for part in parts):
        raise argparse.ArgumentTypeError("categories must be comma-separated positive integers")
    return {int(part) for part in parts}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files-from", required=True)
    parser.add_argument("--sink", required=True)
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--project", default="")
    parser.add_argument("--skip", type=categories, default=set())
    parser.add_argument("--only", type=categories, default={1, 2})
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--sarif-out", default="")
    parser.add_argument("--text-out", default="")
    parser.add_argument("--completion-out", required=True)
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args(argv)
    if not args.only or not args.only <= {1, 2}:
        parser.error("SQL categories are 1 (search-path) and 2 (privileges)")
    from ubs_core.cache import CapturingSink, ScanCache
    raw = Path(args.files_from).read_bytes()
    files = list(dict.fromkeys(Path(os.fsdecode(entry)).resolve() for entry in raw.split(b"\0") if entry))
    enabled = {rule for rule, (_slug, category, _title) in RULES.items()
               if category in args.only and category not in args.skip}
    cache = ScanCache(lang="sql", project_dir=args.project_dir,
                      skip=",".join(map(str, sorted(({1, 2} - args.only) | args.skip))),
                      extra="postgresql-ddl-v1")
    cached, pending = cache.partition_files(files)
    sink, errors = CapturingSink(), []
    for path in pending:
        try:
            with path.open("rb") as source:
                data = source.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise Incomplete("SQL source byte budget exhausted")
            records, incomplete = analyze_source(data.decode("utf-8-sig"), str(path))
            errors.extend(f"{path}: {message}" for message in incomplete)
            for record in records:
                if record["rule"] in enabled:
                    sink.write(json.dumps(record, ensure_ascii=False) + "\n")
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            errors.append(f"{path}: {exc}")
    if not errors:
        cache.store_scanned_files(pending, sink.by_file)
    records = []
    for path in files:
        records.extend(cached[path] if path in cached else sink.get_for_file(path))
    with open(args.sink, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
    cache.write_stats(os.environ.get("UBS_CACHE_FILE") or str(Path(args.sink).with_suffix(".cache")))
    counts = {"critical": 0, "warning": len(records), "info": 0}
    category_counts = {}
    for record in records:
        category_counts.setdefault(record["category_id"], dict.fromkeys(counts, 0))["warning"] += 1
    profile = {"files_considered": len(files), "files_after_prefilter": len(pending), "prefilter_ms": 0,
               "cache_hits": cache.stats["hits"], "cache_misses": cache.stats["misses"], "cache_hit_rate": cache.stats["hit_rate"]}
    summary = {"language": "sql", "version": args.version, "project": args.project or args.project_dir,
               "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "files": len(files), **counts, "status": "partial" if errors else "ok", "findings": records,
               "categories": category_counts, "ast_grep_rules": 0, "uv_tools": [],
               "extras": {"profile": profile, "dialect": "postgresql", "scope": "selected-file migration DDL; function bodies and deployed privileges are not evaluated"}}
    if os.environ.get("UBS_PROFILE") == "1":
        summary["profile"] = profile
    if errors:
        summary.update(module_error="ANALYZER_ERROR", errors=errors,
                       message=("SQL analysis incomplete: " + "; ".join(errors[:5]))[:1000])
    code = 2 if errors else int(bool(args.fail_on_warning and records))
    Path(args.json_out).write_text(json.dumps(summary, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.sarif_out:
        from ubs_core.findings_merge import to_sarif
        report = to_sarif(summary)
        invocation = {"executionSuccessful": not errors, "exitCode": code}
        if errors:
            invocation["toolExecutionNotifications"] = [{"level": "error", "descriptor": {"id": "ANALYZER_ERROR"}, "message": {"text": summary["message"]}}]
        report["runs"][0]["invocations"] = [invocation]
        Path(args.sarif_out).write_text(json.dumps(report, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.text_out:
        lines = [f"UBS module: PostgreSQL SQL (contract v2) v{args.version} — {summary['project']}"]
        if errors:
            lines.append("Partial: [ANALYZER_ERROR] " + summary["message"])
        if not args.quiet:
            for record in records:
                lines.extend([f"[WARNING] {record['rule']}: {record['message']}", f"  {record['path']}:{record['line']}:{record['col']}"])
        lines.extend(["", "Summary Statistics:", f"Files scanned: {len(files)}", "Critical issues: 0", f"Warning issues: {len(records)}", "Info items: 0"])
        Path(args.text_out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    for error in errors:
        print(f"ubs-sql: analysis incomplete: {error}", file=sys.stderr)
    Path(args.completion_out).write_text(json.dumps({"language": "sql", "status": summary["status"], "exit_code": code}) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
