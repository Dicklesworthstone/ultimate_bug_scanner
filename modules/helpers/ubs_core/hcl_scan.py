"""Bounded Terraform AWS configuration checks; no plan, state or provider execution.

Selected administrative ingress, public S3 ACLs, unrestricted IAM policy intent,
and disabled AWS provider TLS verification are checked.
Selected .tf and .tf.json files in one directory share locals and resource identities. Input
variables, remote modules, templates and dynamic relevant configuration remain
unknown. A complete result describes these selected checks, never deployed
reachability or comprehensive infrastructure security.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import dataclass
import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys

from ubs_core.suppression import has_suppression_marker

RULES = {
    "hcl.aws.public-admin-ingress": ("network", 1, "AWS security group permits public administrative ingress"),
    "hcl.aws.public-s3-acl": ("storage", 2, "AWS S3 configuration requests a public ACL"),
    "hcl.aws.iam-wildcard-privilege": ("iam", 3, "AWS IAM identity policy allows every action on every resource"),
    "hcl.aws.insecure-provider-tls": ("tls", 4, "AWS provider explicitly disables TLS verification"),
}
REMEDIATION = {
    1: "Restrict SSH/RDP ingress to trusted networks or a private management path.",
    2: "Use a private ACL and explicit bucket ownership/public-access protections.",
    3: "Grant only the actions and resource ARNs needed by the intended identity.",
    4: "Keep provider TLS verification enabled and configure a trusted CA bundle when needed.",
}
RULE_METADATA = {
    rule: {
        "language": "hcl", "name": title, "family": "infrastructure_security",
        "category_id": "hcl." + slug, "severity": "warning", "confidence": "unknown",
        "message": title,
        "remediation": REMEDIATION[category],
        "manifest_cases": ["hcl-aws-buggy", "hcl-aws-clean"],
    } for rule, (slug, category, title) in RULES.items()
}
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_CONTEXT_BYTES = 32 * 1024 * 1024
MAX_TOKENS = 200_000
MAX_NESTING = 64
MAX_EVALUATIONS = 200_000
MAX_POLICY_BYTES = 256 * 1024
MAX_INGRESS_RULES = 4096
MAX_INGRESS_ITEMS = 200_000
NETWORK = "hcl.aws.public-admin-ingress"
STORAGE = "hcl.aws.public-s3-acl"
IAM = "hcl.aws.iam-wildcard-privilege"
TLS = "hcl.aws.insecure-provider-tls"
IAM_RESOURCES = frozenset({"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"})
SECURITY_GROUPS = frozenset({"aws_security_group", "aws_default_security_group"})
AWS_SOURCES = frozenset({"hashicorp/aws", "registry.terraform.io/hashicorp/aws"})
CATEGORIES = frozenset(category for _, category, _ in RULES.values())


class Incomplete(ValueError):
    """A selected configuration cannot be evaluated by this bounded model."""


@dataclass(frozen=True)
class Unknown:
    reason: str
    cyclic: bool = False


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    line: int
    col: int


@dataclass(frozen=True)
class Attribute:
    anchor: Token
    tokens: tuple[Token, ...]
    json_value: JSONValue | None = None


@dataclass
class Block:
    kind: str
    labels: tuple[str, ...]
    anchor: Token
    attributes: dict[str, Attribute]
    children: list[Block]
    path: str
    opening: int


def lex(text: str) -> tuple[list[Token], list[Token]]:
    """Preserve positions and keep comments and HCL templates out of code."""
    tokens, comments = [], []
    pos, line, col = 0, 1, 1
    while pos < len(text):
        start, first_line, first_col = pos, line, col
        char = text[pos]
        kind, value = "symbol", char
        if char in " \t\r":
            pos += 1
            col += 1
            continue
        if char == "\n":
            end, kind = pos + 1, "newline"
        elif char == "#" or text.startswith("//", pos):
            end = text.find("\n", pos)
            end = len(text) if end < 0 else end
            kind, value = "comment", text[pos:end]
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            if end < 0:
                raise Incomplete(f"line {line}: unterminated HCL block comment")
            end += 2
            kind, value = "comment", text[pos:end]
        elif text.startswith("<<", pos):
            header = re.match(r"<<(-?)([A-Za-z_][\w-]*)[^\S\n]*\r?\n", text[pos:])
            if not header:
                raise Incomplete(f"line {line}: unsupported heredoc header")
            body = pos + header.end()
            indent, delimiter = header.groups()
            ending = re.compile((r"^[ \t]*" if indent else "^") + re.escape(delimiter) + r"[ \t]*\r?$", re.M).search(text, body)
            if ending is None:
                raise Incomplete(f"line {line}: unterminated HCL heredoc")
            end = ending.end()
            value, kind = text[body:ending.start()], "string"
            if re.search(r"(?<!\$)\$\{|(?<!%)%\{", value):
                kind = "template"
        elif char == '"':
            end, template_depth = pos + 1, 0
            while end < len(text):
                current = text[end]
                if current == "\\":
                    end += 2
                    continue
                if text.startswith(("$${", "%%{"), end):
                    end += 3
                    continue
                if text.startswith(("${", "%{"), end):
                    template_depth += 1
                    end += 2
                    continue
                if template_depth:
                    if current == '"':
                        inner = end + 1
                        while inner < len(text) and text[inner] != '"':
                            inner += 2 if text[inner] == "\\" else 1
                        if inner >= len(text):
                            raise Incomplete(f"line {line}: unterminated template expression")
                        end = inner + 1
                        continue
                    template_depth += (current == "{") - (current == "}")
                elif current == '"':
                    end += 1
                    break
                elif current == "\n":
                    raise Incomplete(f"line {line}: newline in quoted HCL string")
                end += 1
            else:
                raise Incomplete(f"line {line}: unterminated HCL string")
            raw = text[pos:end]
            if re.search(r"(?<!\$)\$\{|(?<!%)%\{", raw):
                kind, value = "template", raw
            else:
                try:
                    # HCL's eight-digit Unicode escape is absent from JSON.
                    raw = re.sub(r"(?<!\\)\\U([0-9a-fA-F]{8})", lambda m: chr(int(m.group(1), 16)), raw)
                    value = json.loads(raw).replace("$${", "${").replace("%%{", "%{")
                except (ValueError, OverflowError) as exc:
                    raise Incomplete(f"line {line}: invalid HCL string escape") from exc
                kind = "string"
        elif match := re.match(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", text[pos:]):
            end, kind, value = pos + match.end(), "number", match.group()
        elif match := re.match(r"[A-Za-z_][\w-]*", text[pos:]):
            end, kind, value = pos + match.end(), "word", match.group()
        else:
            end = pos + 1
        token = Token(kind, value, start, end, first_line, first_col)
        (comments if kind == "comment" else tokens).append(token)
        segment = text[pos:end]
        if "\n" in segment:
            line += segment.count("\n")
            col = len(segment.rsplit("\n", 1)[-1]) + 1
        else:
            col += end - pos
        pos = end
        if len(tokens) + len(comments) > MAX_TOKENS:
            raise Incomplete("HCL token budget exhausted")
    return tokens, comments


class Parser:
    def __init__(self, text: str, path: str):
        self.text, self.path = text, path
        self.tokens, self.comments = lex(text)
        self.pairs = {}
        stack = []
        for index, token in enumerate(self.tokens):
            if token.kind != "symbol":
                continue
            if token.value in "([{":
                stack.append(index)
                if len(stack) > MAX_NESTING:
                    raise Incomplete("HCL nesting budget exhausted")
            elif token.value in ")]}":
                if not stack or {')': '(', ']': '[', '}': '{'}[token.value] != self.tokens[stack[-1]].value:
                    raise Incomplete(f"line {token.line}: mismatched HCL delimiter")
                self.pairs[stack.pop()] = index
        if stack:
            raise Incomplete(f"line {self.tokens[stack[-1]].line}: unclosed HCL block or expression")

    def body(self, low: int, high: int) -> tuple[dict[str, Attribute], list[Block]]:
        attributes, blocks = {}, []
        cursor = low
        while cursor < high:
            token = self.tokens[cursor]
            if token.kind == "newline":
                cursor += 1
                continue
            if token.kind != "word":
                raise Incomplete(f"line {token.line}: expected a HCL attribute or block")
            cursor += 1
            if cursor < high and self.tokens[cursor].value == "=":
                cursor += 1
                start = cursor
                while cursor < high:
                    current = self.tokens[cursor]
                    if current.kind == "newline":
                        break
                    if cursor in self.pairs:
                        cursor = self.pairs[cursor] + 1
                    else:
                        cursor += 1
                if start == cursor:
                    raise Incomplete(f"line {token.line}: empty attribute expression")
                if token.value in attributes:
                    raise Incomplete(f"line {token.line}: duplicate attribute {token.value}")
                attributes[token.value] = Attribute(token, tuple(self.tokens[start:cursor]))
                continue
            labels = []
            while cursor < high and self.tokens[cursor].kind in {"string", "word"}:
                labels.append(self.tokens[cursor].value)
                cursor += 1
            if cursor >= high or self.tokens[cursor].value != "{":
                raise Incomplete(f"line {token.line}: missing HCL block body")
            closing = self.pairs[cursor]
            values, children = self.body(cursor + 1, closing)
            blocks.append(Block(token.value, tuple(labels), token, values, children, self.path, self.tokens[cursor].end))
            cursor = closing + 1
        return attributes, blocks


@dataclass(frozen=True)
class JSONValue:
    """An ordered JSON value, retaining duplicates and exact source spans."""
    kind: str
    anchor: Token
    end: Token
    items: tuple = ()
    tokens: tuple[Token, ...] = ()


class JSONParser:
    """Lower the selected Terraform JSON schema into the native block model.

    JSON objects represent both bodies and expressions. Preserve their member
    sequence until the schema decides which interpretation applies; ordinary
    json.loads would silently discard valid repeated blocks or invalid keys.
    """
    token_pattern = re.compile(
        r'[ \t\r\n]+|"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
        r'|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?'
        r'|true|false|null|[{}\[\],:]')
    root_labels = {
        "terraform": 0, "locals": 0, "variable": 1, "output": 1,
        "provider": 1, "resource": 2, "data": 2, "module": 1,
        "moved": 0, "removed": 0, "import": 0, "check": 1, "ephemeral": 2,
    }

    def __init__(self, text: str, path: str):
        self.text, self.path, self.comments = text, path, []
        self.tokens, self.cursor, self.expanded_tokens = [], 0, 0
        starts = [0, *(match.end() for match in re.finditer("\n", text))]
        pos = 0
        while pos < len(text):
            match = self.token_pattern.match(text, pos)
            line = bisect_right(starts, pos)
            if match is None:
                raise Incomplete(f"line {line}: invalid Terraform JSON token")
            raw, end = match.group(), match.end()
            if not raw.isspace():
                kind, value = "symbol", raw
                if raw.startswith('"'):
                    kind = "string"
                    try:
                        value = json.loads(raw)
                        value.encode("utf-8")
                    except (ValueError, UnicodeError) as exc:
                        raise Incomplete(f"line {line}: invalid Terraform JSON string") from exc
                elif raw[0] in "-0123456789":
                    kind = "number"
                elif raw in {"true", "false", "null"}:
                    kind = "word"
                self.tokens.append(Token(kind, value, pos, end, line, pos - starts[line - 1] + 1))
                if len(self.tokens) > MAX_TOKENS:
                    raise Incomplete("Terraform JSON token budget exhausted")
            pos = end
        self.root = self.value(0)
        if self.cursor != len(self.tokens):
            raise Incomplete("extra content after Terraform JSON configuration")

    def take(self, expected=None):
        if self.cursor >= len(self.tokens):
            raise Incomplete("unexpected end of Terraform JSON configuration")
        token = self.tokens[self.cursor]
        if expected is not None and (token.kind != "symbol" or token.value != expected):
            raise Incomplete(f"line {token.line}: expected JSON {expected!r}")
        self.cursor += 1
        return token

    def value(self, depth):
        if depth > MAX_NESTING:
            raise Incomplete("Terraform JSON nesting budget exhausted")
        token = self.take()
        if token.kind != "symbol":
            return JSONValue(token.kind, token, token)
        if token.value not in {"{", "["}:
            raise Incomplete(f"line {token.line}: expected a JSON value")
        kind, close = ("object", "}") if token.value == "{" else ("array", "]")
        items = []
        if (self.cursor < len(self.tokens) and self.tokens[self.cursor].kind == "symbol"
                and self.tokens[self.cursor].value == close):
            return JSONValue(kind, token, self.take(close))
        while True:
            if kind == "object":
                key = self.take()
                if key.kind != "string":
                    raise Incomplete(f"line {key.line}: JSON object property must be a string")
                self.take(":")
                items.append((JSONValue("string", key, key), self.value(depth + 1)))
            else:
                items.append(self.value(depth + 1))
            separator = self.take()
            if separator.kind == "symbol" and separator.value == close:
                return JSONValue(kind, token, separator, tuple(items))
            if separator.kind != "symbol" or separator.value != ",":
                raise Incomplete(f"line {separator.line}: expected JSON comma or closing delimiter")

    def objects(self, node):
        values = node.items if node.kind == "array" else (node,)
        for value in values:
            if value.kind != "object":
                raise Incomplete(f"line {value.anchor.line}: Terraform JSON body or labels require objects")
            yield value

    def expression(self, node, *, literal=False):
        if node.kind == "array":
            items = tuple(self.expression(item, literal=literal) for item in node.items)
        elif node.kind == "object":
            items = tuple((self.expression(key, literal=literal), self.expression(value, literal=literal))
                          for key, value in node.items)
        else:
            items = ()
        tokens = (node.anchor,)
        if node.kind == "string":
            anchor, value = node.anchor, node.anchor.value
            if literal:
                tokens = (anchor,)
            elif not re.search(r"(?<!\$)\$\{|(?<!%)%\{", value):
                tokens = (Token("string", value.replace("$${", "${").replace("%%{", "%{"),
                                anchor.start, anchor.end, anchor.line, anchor.col),)
            else:
                tokens = (Token("unknown", "unsupported Terraform JSON string template",
                                anchor.start, anchor.end, anchor.line, anchor.col),)
                if value.startswith("${") and value.endswith("}"):
                    inner = value[2:-1]
                    try:
                        expression = Parser(inner, self.path)
                        if any(comment.end == len(inner) and not comment.value.startswith("/*")
                               for comment in expression.comments):
                            raise Incomplete("line comment hides the interpolation closing delimiter")
                    except Incomplete:
                        pass
                    else:
                        self.expanded_tokens += len(expression.tokens)
                        if len(self.tokens) + self.expanded_tokens > MAX_TOKENS:
                            raise Incomplete("Terraform JSON expression token budget exhausted")
                        tokens = tuple(Token(token.kind, token.value, anchor.start, anchor.end,
                                             anchor.line, anchor.col) for token in expression.tokens)
        return JSONValue(node.kind, node.anchor, node.end, items, tokens)

    @staticmethod
    def child_labels(kind, labels):
        if kind == "terraform":
            return {"required_providers": 0, "backend": 1, "cloud": 0, "provider_meta": 1}
        if kind == "data" and labels[:1] == ("aws_iam_policy_document",):
            return {"statement": 0, "dynamic": 1, "lifecycle": 0}
        if kind == "statement":
            return {"condition": 0, "principals": 0, "not_principals": 0, "dynamic": 1}
        if kind == "resource" and labels[:1] == ("aws_s3_bucket_ownership_controls",):
            return {"rule": 0, "dynamic": 1, "lifecycle": 0}
        if kind in {"resource", "data", "ephemeral"}:
            # Security-group ingress is SchemaConfigModeAttr in the AWS
            # provider: JSON always treats it as an expression, not blocks.
            return {"dynamic": 1, "lifecycle": 0, "provisioner": 1, "connection": 0}
        if kind == "dynamic":
            return {"content": 0}
        return {}

    def blocks(self, kind, node, remaining, anchor, labels=(), *, literal=False):
        if remaining:
            for mapping in self.objects(node):
                for key, value in mapping.items:
                    yield from self.blocks(kind, value, remaining - 1, key.anchor,
                                           (*labels, key.anchor.value), literal=literal)
            return
        for body in self.objects(node):
            attributes, children = self.body(body, kind, labels, literal=literal or kind == "terraform")
            location = body.anchor if node.kind == "array" and len(node.items) > 1 else anchor
            yield Block(kind, labels, location, attributes, children, self.path, body.anchor.end)

    def body(self, node=None, kind="", labels=(), *, literal=False):
        node = self.root if node is None else node
        schema = self.root_labels if not kind else self.child_labels(kind, labels)
        attributes, blocks = {}, []
        for body in self.objects(node):
            for key, value in body.items:
                name, anchor = key.anchor.value, key.anchor
                if name == "//":
                    continue  # Comment properties have meaning only in bodies.
                if name in schema:
                    blocks.extend(self.blocks(name, value, schema[name], anchor, literal=literal))
                    continue
                if not kind:
                    raise Incomplete(f"line {anchor.line}: unsupported Terraform JSON root property {name}")
                if name in attributes:
                    raise Incomplete(f"line {anchor.line}: duplicate attribute {name}")
                static = (literal or kind == "variable"
                          or kind == "provider" and name in {"alias", "version"}
                          or kind == "output" and name in {"description", "sensitive"}
                          or kind == "module" and name in {"source", "version", "providers"}
                          or kind in {"resource", "data", "ephemeral"} and name in {"provider", "depends_on"})
                expression = self.expression(value, literal=static)
                tokens = expression.tokens if value.kind not in {"object", "array"} else (value.anchor, value.end)
                attributes[name] = Attribute(anchor, tokens, expression)
        return attributes, blocks


def split_items(tokens: tuple[Token, ...], *, newlines: bool = False) -> list[tuple[Token, ...]]:
    result, start, depth = [], 0, 0
    for index, token in enumerate(tokens):
        if token.kind == "symbol" and token.value in "([{":
            depth += 1
        elif token.kind == "symbol" and token.value in ")]}":
            depth -= 1
        if depth == 0 and (token.value == "," or (newlines and token.kind == "newline")):
            if any(t.kind != "newline" for t in tokens[start:index]):
                result.append(tokens[start:index])
            start = index + 1
    if any(t.kind != "newline" for t in tokens[start:]):
        result.append(tokens[start:])
    return result


class Values:
    def __init__(self, blocks: list[Block]):
        self.locals = {}
        self.duplicate_locals = set()
        self.memo = {}
        self.policy_memo = {}
        self.resolve_policy = None
        self.encoded_bytes = 0
        self.decoded_bytes = 0
        self.evaluations = 0
        self.evaluation_depth = 0
        self.limits = set()
        for block in blocks:
            if block.kind == "locals" and not block.labels:
                for name, attribute in block.attributes.items():
                    if name in self.locals:
                        self.duplicate_locals.add(name)
                    self.locals[name] = attribute

    def evaluate_attribute(self, attribute: Attribute, visiting=()):
        if attribute.json_value is not None:
            return self.evaluate_json(attribute.json_value, visiting)
        return self.evaluate(attribute.tokens, visiting)

    def limited(self, reason):
        self.limits.add(reason)
        return Unknown(reason)

    @staticmethod
    def number(value):
        # HCL numbers are decimal in both syntaxes. A rounded binary float
        # must not prove an integral port, protocol or resource count.
        try:
            exact = Decimal(value)
            if exact and abs(exact.adjusted()) > 308:
                return Unknown("HCL number is outside the supported range")
            if exact == exact.to_integral_value():
                return int(exact)
            number = float(exact)
            if Decimal(str(number)) == exact:
                return number
        except (InvalidOperation, ValueError, OverflowError):
            pass
        return Unknown("HCL number requires unsupported precision")

    def evaluate_json(self, node: JSONValue, visiting=()):
        self.evaluation_depth += 1
        try:
            if self.evaluation_depth > MAX_NESTING:
                return self.limited("HCL expression nesting budget exhausted")
            return self.json_value(node, visiting)
        finally:
            self.evaluation_depth -= 1

    def json_value(self, node: JSONValue, visiting):
        self.evaluations += 1
        if self.evaluations > MAX_EVALUATIONS:
            return self.limited("HCL expression evaluation budget exhausted")
        if node.kind == "array":
            return [self.evaluate_json(item, visiting) for item in node.items]
        if node.kind == "object":
            result = {}
            for key_node, value_node in node.items:
                key = self.evaluate_json(key_node, visiting)
                if isinstance(key, Unknown):
                    return Unknown("unresolved Terraform JSON object key", cyclic=key.cyclic)
                if type(key) is bool:
                    key = "true" if key else "false"
                elif isinstance(key, int):
                    key = str(key)
                elif isinstance(key, float) and math.isfinite(key):
                    key = format(Decimal(str(key)), "f")
                    if "." in key:
                        key = key.rstrip("0").rstrip(".")
                if not isinstance(key, str):
                    return Unknown("Terraform JSON object key cannot be converted to a string")
                if key in result:
                    return Unknown("duplicate Terraform JSON expression object key")
                result[key] = self.evaluate_json(value_node, visiting)
            return result
        if node.kind == "number":
            return self.number(node.anchor.value)
        return self.evaluate(node.tokens, visiting)

    def evaluate(self, tokens: tuple[Token, ...], visiting: tuple[str, ...] = ()):
        self.evaluation_depth += 1
        try:
            if self.evaluation_depth > MAX_NESTING:
                return self.limited("HCL expression nesting budget exhausted")
            return self.native_value(tokens, visiting)
        finally:
            self.evaluation_depth -= 1

    def native_value(self, tokens: tuple[Token, ...], visiting: tuple[str, ...]):
        self.evaluations += 1
        if self.evaluations > MAX_EVALUATIONS:
            return self.limited("HCL expression evaluation budget exhausted")
        low, high = 0, len(tokens)
        while low < high and tokens[low].kind == "newline":
            low += 1
        while high > low and tokens[high - 1].kind == "newline":
            high -= 1
        original = tokens[low:high]
        tokens = tuple(t for t in tokens if t.kind != "newline")
        if not tokens:
            return Unknown("empty expression")
        if len(visiting) > MAX_NESTING:
            return Unknown("local expression budget exhausted")
        if len(tokens) == 1:
            token = tokens[0]
            if token.kind == "unknown":
                return Unknown(token.value)
            if token.kind == "string":
                return token.value
            if token.kind == "number":
                return self.number(token.value)
            if token.value in {"true", "false", "null"}:
                return {"true": True, "false": False, "null": None}[token.value]
        raw = "".join(t.value for t in tokens)
        if re.fullmatch(r"local\.[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*", raw):
            name, *members = raw.split(".")[1:]
            if name in visiting or name in self.duplicate_locals:
                return Unknown(f"cyclic or duplicate local {name}", cyclic=name in visiting)
            if name not in self.locals:
                return Unknown(f"unresolved local {name}")
            if name not in self.memo:
                value = self.evaluate_attribute(self.locals[name], (*visiting, name))
                # Terraform depends on the entire local expression, even
                # when a caller selects one object member. Cache a cycle
                # before projection; immutable cached values need no rescan.
                self.memo[name] = (Unknown(f"cyclic local expression {name}", cyclic=True)
                                   if unknown(value, cycles_only=True) else value)
            value = self.memo[name]
            if isinstance(value, Unknown):
                return value
            for member in members:
                value = value.get(member, Unknown(f"unresolved local member {member}")) if isinstance(value, dict) else Unknown("unresolved local object")
            return value
        if (len(tokens) == 7 and all(tokens[index].kind == "word" for index in (0, 2, 4, 6))
                and all(tokens[index].kind == "symbol" and tokens[index].value == "." for index in (1, 3, 5))
                and tokens[0].value == "data" and tokens[2].value == "aws_iam_policy_document"
                and tokens[6].value in {"json", "minified_json"}):
            name = tokens[4].value
            identity = "data.aws_iam_policy_document." + name
            if identity in visiting:
                return Unknown("cyclic IAM policy document reference " + identity, cyclic=True)
            if self.resolve_policy is None:
                return Unknown("IAM policy documents cannot determine provider requirements")
            if name not in self.policy_memo:
                self.policy_memo[name] = self.resolve_policy(name, (*visiting, identity))
            return self.policy_memo[name]
        if (len(tokens) >= 3 and tokens[0].kind == "word" and tokens[0].value == "jsonencode"
                and tokens[1].value == "(" and tokens[-1].value == ")"):
            # Only the built-in single-argument function is evaluated. No file
            # reads, provider functions, templates or external code are run.
            opening = next(index for index, token in enumerate(original) if token.value == "(")
            arguments = split_items(original[opening + 1:-1])
            if len(arguments) != 1:
                return Unknown("jsonencode requires one supported argument")
            value = self.evaluate(arguments[0], visiting)
            return self.encode_json(value)
        if tokens[0].value == "[" and tokens[-1].value == "]":
            return [self.evaluate(part, visiting) for part in split_items(original[1:-1])]
        if tokens[0].value == "{" and tokens[-1].value == "}":
            # Preserve newline boundaries in HCL object literals.
            result = {}
            for part in split_items(original[1:-1], newlines=True):
                while part and part[0].kind == "newline":
                    part = part[1:]
                if len(part) < 3 or part[0].kind not in {"word", "string"} or part[1].value not in {"=", ":"}:
                    return Unknown("unsupported object expression")
                if part[0].value in result:
                    return Unknown("duplicate object key")
                result[part[0].value] = self.evaluate(part[2:], visiting)
            return result
        if tokens[0].value == "(" and tokens[-1].value == ")":
            return self.evaluate(original[1:-1], visiting)
        return Unknown("unresolved expression " + raw[:100])

    def attribute(self, block: Block, name: str, default=None, *, visiting: tuple[str, ...] = ()):
        attribute = block.attributes.get(name)
        return self.evaluate_attribute(attribute, visiting) if attribute else default

    def encode_json(self, value):
        if unknown(value):
            return Unknown("JSON policy contains unresolved configuration", cyclic=unknown(value, cycles_only=True))
        # Shared locals can describe exponentially larger output than their
        # source. Bound each document and the total retained/generated JSON,
        # including documents reached through different data-source addresses.
        chunks, size = [], 0
        try:
            for chunk in json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":")).iterencode(value):
                size += len(chunk)
                self.encoded_bytes += len(chunk)
                if size > MAX_POLICY_BYTES:
                    return Unknown("encoded JSON policy byte budget exhausted")
                if self.encoded_bytes > MAX_CONTEXT_BYTES:
                    return Unknown("generated JSON policy context byte budget exhausted")
                chunks.append(chunk)
            return "".join(chunks)
        except (ValueError, TypeError, RecursionError):
            return Unknown("JSON encoding exceeded the supported value or nesting limits")


def unknown(value, *, cycles_only: bool = False) -> bool:
    pending, seen = [value], set()
    while pending:
        item = pending.pop()
        if isinstance(item, Unknown) and (not cycles_only or item.cyclic):
            return True
        if isinstance(item, (dict, list)) and id(item) not in seen:
            seen.add(id(item))
            pending.extend(item.values() if isinstance(item, dict) else item)
    return False


def policy_object(pairs):
    """JSON policy keys are unique; a last-key-wins parse can invent a grant."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise Incomplete("duplicate IAM JSON key " + key)
        result[key] = value
    return result


def policy_constant(value):
    raise Incomplete("invalid IAM JSON constant " + value)


def policy_strings(value, field):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item for item in values):
        raise Incomplete("IAM " + field + " must contain nonempty strings")
    return values


def policy_variables(values, version):
    """Apply the provider's IAM variable escape after the caller bounds input."""
    if version == "2008-10-17" and any("&{" in item for item in values):
        return Unknown("IAM policy variables require document version 2012-10-17")
    return [item.replace("&{", "${") for item in values]


def parse_policy_document(value, *, composition: bool = False) -> dict:
    """Validate the selected JSON shape before classifying or merging grants.

    The provider accepts only statement arrays in composition inputs. Named
    statement uniqueness belongs to the merge phase: sources reject duplicates,
    while later override statements replace earlier statements of the same name.
    """
    if isinstance(value, Unknown):
        raise Incomplete(value.reason)
    if not isinstance(value, str):
        raise Incomplete("IAM policy must resolve to a JSON string")
    try:
        if len(value.encode("utf-8")) > MAX_POLICY_BYTES:
            raise Incomplete("IAM JSON policy byte budget exhausted")
        document = json.loads(value, object_pairs_hook=policy_object, parse_constant=policy_constant)
    except (ValueError, RecursionError) as exc:
        raise Incomplete("invalid or unsupported IAM JSON policy: " + str(exc)) from exc
    if not isinstance(document, dict) or set(document) - {"Version", "Statement"}:
        raise Incomplete("unsupported IAM identity-policy document fields")
    version = document.get("Version", "2008-10-17")
    if not isinstance(version, str) or version not in {"2008-10-17", "2012-10-17"}:
        raise Incomplete("unsupported IAM policy language version")
    statements = document.get("Statement")
    if composition:
        statements = [] if statements is None else statements
        if not isinstance(statements, list):
            raise Incomplete("IAM policy composition requires a Statement array")
    else:
        statements = [statements] if isinstance(statements, dict) else statements
        if not isinstance(statements, list) or not statements:
            raise Incomplete("IAM policy requires a nonempty Statement object or array")
    identifiers = set()
    for statement in statements:
        if not isinstance(statement, dict) or set(statement) - {"Sid", "Effect", "Action", "Resource", "Condition"}:
            raise Incomplete("unsupported IAM statement fields, principal or complement operators")
        if "Sid" in statement:
            sid = statement["Sid"]
            if (not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9]*", sid)
                    or not composition and sid in identifiers):
                raise Incomplete("invalid or duplicate IAM statement identifier")
            identifiers.add(sid)
            if composition and not sid:
                # The provider omits blank SIDs when encoding its merged
                # document. Anonymous statements never replace one another.
                del statement["Sid"]
        effect = statement.get("Effect")
        if not isinstance(effect, str) or effect not in {"Allow", "Deny"}:
            raise Incomplete("IAM statement Effect must be Allow or Deny")
        policy_strings(statement.get("Action"), "Action")
        policy_strings(statement.get("Resource"), "Resource")
        if "Condition" in statement:
            condition = statement["Condition"]
            if not isinstance(condition, dict) or not condition or any(not isinstance(v, dict) or not v for v in condition.values()):
                raise Incomplete("unsupported IAM Condition structure")
            if composition:
                for terms in condition.values():
                    for term in terms.values():
                        if (not isinstance(term, (str, bool)) and
                                (not isinstance(term, list) or not term or any(not isinstance(item, str) for item in term))):
                            raise Incomplete("unsupported IAM Condition value in policy composition")
    return {"Version": version, "Statement": statements}


def wildcard_policy(value) -> bool:
    """Prove only an unconditional all-action/all-resource identity grant.

    Other policy types, complement operators and effective policy evaluation
    are deliberately excluded. A deny can restrict a candidate grant, so it
    requires an incomplete result instead of a guessed permission outcome.
    """
    document = parse_policy_document(value)
    candidate, conditional, denied = False, False, False
    for statement in document["Statement"]:
        effect = statement["Effect"]
        actions = policy_strings(statement["Action"], "Action")
        resources = policy_strings(statement["Resource"], "Resource")
        denied |= effect == "Deny"
        if effect == "Allow" and "*" in actions and "*" in resources:
            conditional |= "Condition" in statement
            candidate |= "Condition" not in statement
    if conditional or candidate and denied:
        raise Incomplete("IAM wildcard grant has conditional or deny constraints outside the selected model")
    return candidate


class Module:
    def __init__(self, sources: dict[str, str], enabled: set[str]):
        self.sources, self.enabled = sources, enabled
        self.parsers, self.blocks, self.errors, self.findings = {}, [], [], []
        self.ingress_items = self.ingress_rules = 0
        self.ingress_rows, self.ingress_lists, self.ingress_cidrs = {}, {}, {}
        for path, text in sources.items():
            try:
                if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
                    raise Incomplete("HCL source byte budget exhausted")
                parser = JSONParser(text, path) if path.endswith(".tf.json") else Parser(text, path)
                attributes, blocks = (parser.body() if isinstance(parser, JSONParser)
                                      else parser.body(0, len(parser.tokens)))
                if attributes:
                    raise Incomplete("Terraform .tf files require top-level blocks, not variable assignments")
                self.parsers[path] = parser
                self.blocks.extend(blocks)
                for block in blocks:
                    if block.kind == "resource" and len(block.labels) != 2:
                        self.errors.append(f"{path}:{block.anchor.line}: Terraform resource requires type and name labels")
            except (Incomplete, RecursionError) as exc:
                self.errors.append(f"{path}: {exc}")
        self.values = Values(self.blocks)
        self.resources = [b for b in self.blocks if b.kind == "resource" and len(b.labels) == 2]
        self.policy_documents = {}
        for block in self.blocks:
            if block.kind == "data" and len(block.labels) == 2 and block.labels[0] == "aws_iam_policy_document":
                self.policy_documents.setdefault(block.labels[1], []).append(block)
        self.required = {}
        for block in self.blocks:
            if block.kind == "terraform":
                for child in block.children:
                    if child.kind == "required_providers":
                        for name, attr in child.attributes.items():
                            self.required[name] = (Unknown("duplicate provider requirement") if name in self.required
                                                   else self.values.evaluate_attribute(attr))
        # Provider identity must be established before a data source can use
        # that provider's semantics. Do not retain provisional local values
        # evaluated while the data-source resolver was intentionally disabled.
        self.values.memo.clear()
        self.values.resolve_policy = self.policy_document

    def error(self, block: Block, message: str, attr: Attribute | None = None):
        self.errors.append(f"{block.path}:{(attr.anchor if attr else block.anchor).line}: {message}")

    def active(self, block: Block) -> bool:
        if "count" in block.attributes:
            count = self.values.attribute(block, "count")
            if type(count) is not int or count < 0:
                self.error(block, "resource count is unresolved or invalid")
                return False
            if count == 0:
                return False
        if "for_each" in block.attributes:
            instances = self.values.attribute(block, "for_each")
            if not isinstance(instances, dict) or unknown(instances):
                self.error(block, "resource for_each is unresolved")
                return False
            if not instances:
                return False
        return True

    def provider(self, block: Block) -> str | None:
        attribute = block.attributes.get("provider")
        name = "".join(t.value for t in attribute.tokens) if attribute else "aws"
        if not re.fullmatch(r"[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)?", name):
            self.error(block, "AWS provider binding is unresolved")
            return None
        root = name.split(".", 1)[0]
        spec = self.required.get(root)
        source = spec.get("source") if isinstance(spec, dict) else None
        if root in self.required and not isinstance(spec, dict):
            self.error(block, "AWS provider requirement is unresolved")
            return None
        if isinstance(spec, dict) and "source" in spec and not isinstance(source, str):
            self.error(block, "AWS provider source is unresolved")
            return None
        if source is not None and source not in AWS_SOURCES:
            self.error(block, "resource does not resolve to the HashiCorp AWS provider")
            return None
        if (root != "aws" and source is None) or isinstance(spec, Unknown):
            self.error(block, "AWS provider source is unresolved")
            return None
        return name

    def emit(self, block: Block, name: str, rule: str, detail: str):
        attribute = block.attributes.get(name)
        anchor = attribute.anchor if attribute else block.anchor
        end = attribute.tokens[-1].end if attribute else block.opening
        parser = self.parsers[block.path]
        for comment in parser.comments:
            if not has_suppression_marker(comment.value, rule):
                continue
            comment_line_start = parser.text.rfind("\n", 0, comment.start) + 1
            standalone = not parser.text[comment_line_start:comment.start].strip()
            preceding = (standalone and comment.line == anchor.line - 1
                         and not parser.text[comment.end:anchor.start].strip())
            end_line = attribute.tokens[-1].line if attribute else anchor.line
            trailing = (comment.line == end_line and comment.start >= end
                        and not parser.text[end:comment.start].strip())
            inside_header = (attribute is None and comment.line == anchor.line + 1
                             and comment.start >= block.opening
                             and not parser.text[block.opening:comment.start].strip())
            if preceding or trailing or inside_header or anchor.start <= comment.start <= end:
                return
        _, category, title = RULES[rule]
        self.findings.append({"rule": rule, "path": block.path, "line": anchor.line, "col": anchor.col,
                              "severity": "warning", "message": title + ": " + detail,
                              "category_id": category, "suppressed": False,
                              "extras": {"scope": "selected Terraform configuration; deployment not evaluated"}})

    def ingress_budget(self, count=1):
        self.ingress_items += count
        if self.ingress_items > MAX_INGRESS_ITEMS:
            self.values.limited("HCL ingress item budget exhausted")
            return False
        return True

    def ingress_rule_budget(self):
        self.ingress_rules += 1
        if self.ingress_rules > MAX_INGRESS_RULES:
            self.values.limited("HCL ingress rule budget exhausted")
            return False
        return True

    def ingress_strings(self, value):
        """Apply the provider's list-of-strings conversion without evaluating unknowns."""
        if value is None:
            return []
        if isinstance(value, Unknown):
            return value
        if not isinstance(value, list):
            return Unknown("expected a list of strings")
        identity = id(value)
        if identity in self.ingress_lists:
            return self.ingress_lists[identity][1]
        if not self.ingress_budget(len(value)):
            return Unknown("HCL ingress item budget exhausted")
        result = []
        for item in value:
            if isinstance(item, (str, Unknown)):
                result.append(item)
            elif isinstance(item, bool):
                result.append("true" if item else "false")
            elif isinstance(item, int) or isinstance(item, float) and math.isfinite(item):
                result.append(str(item))
            else:
                result = Unknown("ingress string collection contains an unsupported value")
                break
        # Retain the immutable input with the result so object IDs cannot be
        # reused, and shared locals are converted only once in this module.
        self.ingress_lists[identity] = (value, result)
        return result

    def ingress_protocol(self, value):
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            return Unknown("ingress protocol is unresolved or invalid")
        if isinstance(value, float):
            if not value.is_integer():
                return Unknown("ingress protocol is not integral")
            value = int(value)
        protocol = str(value).lower()
        if re.fullmatch(r"[+-]?[0-9]+", protocol):
            number = self.values.number(protocol)
            if not isinstance(number, int) or not -1 <= number <= 255:
                return Unknown("ingress protocol number is outside the supported range")
            protocol = str(number)
        return "-1" if protocol == "all" else protocol

    def ingress_port(self, value):
        if isinstance(value, str):
            value = self.values.number(value)
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int) or not -(2 ** 31) <= value < 2 ** 31:
            return Unknown("ingress port is unresolved or not a supported integer")
        return value

    def ingress_row(self, row):
        """Normalize attribute-as-block input using the AWS rule object schema."""
        fields = {"cidr_blocks", "description", "from_port", "ipv6_cidr_blocks",
                  "prefix_list_ids", "protocol", "security_groups", "self", "to_port"}
        if not isinstance(row, dict) or not fields <= row.keys():
            return Unknown("ingress attribute rows require all nine AWS rule fields, including optional nulls")
        # Terraform object conversion discards extra attributes. Unknown
        # descriptive/group metadata cannot remove an explicit CIDR grant;
        # known unconvertible values still make the row invalid.
        description = row["description"]
        if description is not None and not isinstance(description, (str, int, float, Unknown)):
            return Unknown("ingress description is not convertible to a string")
        own_group = row["self"]
        if (own_group is not None and not isinstance(own_group, (bool, Unknown))
                and not (isinstance(own_group, str) and own_group in {"true", "false"})):
            return Unknown("ingress self is not convertible to a Boolean")
        for name in ("security_groups", "prefix_list_ids"):
            value = row[name]
            if not isinstance(value, Unknown) and isinstance(self.ingress_strings(value), Unknown):
                return Unknown("ingress " + name + " is not convertible to a string collection")
        protocol = self.ingress_protocol(row["protocol"])
        if isinstance(protocol, Unknown):
            return protocol
        ports = [self.ingress_port(row[name]) for name in ("from_port", "to_port")]
        if any(isinstance(port, Unknown) for port in ports):
            return Unknown("ingress from_port or to_port is unresolved or not a supported integer")
        return {"protocol": protocol, "from_port": ports[0], "to_port": ports[1],
                "cidr_blocks": self.ingress_strings(row["cidr_blocks"]),
                "ipv6_cidr_blocks": self.ingress_strings(row["ipv6_cidr_blocks"])}

    def attribute_ingress(self, block):
        attribute = block.attributes["ingress"]
        rows = self.values.evaluate_attribute(attribute)
        if rows is None:
            return  # Null omits this optional/computed rule set.
        if not isinstance(rows, list):
            self.error(block, "ingress attribute is not a supported rule collection", attribute)
            return
        exposed = False
        for index, row in enumerate(rows):
            if not self.ingress_rule_budget():
                break
            if not self.ingress_budget():
                break
            identity = id(row)
            if identity not in self.ingress_rows:
                self.ingress_rows[identity] = (row, self.ingress_row(row))
            normalized = self.ingress_rows[identity][1]
            if isinstance(normalized, Unknown):
                self.error(block, f"ingress row {index}: {normalized.reason}", attribute)
                continue
            exposed |= bool(self.ingress(block, configuration=normalized))
        if exposed:
            self.emit(block, "ingress", NETWORK, "an explicit ingress rule permits all addresses to reach SSH/RDP or all IP protocols")

    def public_cidrs(self, entries, version):
        if not isinstance(entries, list):
            return False, True
        identity = (id(entries), version)
        if identity in self.ingress_cidrs:
            return self.ingress_cidrs[identity][1]
        if not self.ingress_budget(len(entries)):
            return False, True
        exposed, invalid = False, False
        for entry in entries:
            try:
                if not isinstance(entry, str) or not re.fullmatch(r"[^/]+/[0-9]{1,3}", entry):
                    raise ValueError("unresolved CIDR")
                network = ipaddress.ip_network(entry, strict=True)
                if network.version != version:
                    raise ValueError("CIDR address family mismatch")
                exposed |= network.prefixlen == 0
            except ValueError:
                invalid = True
        self.ingress_cidrs[identity] = (entries, (exposed, invalid))
        return exposed, invalid

    def ingress(self, block: Block, *, modern: bool = False, configuration=None):
        if not self.ingress_budget() or configuration is None and not self.ingress_rule_budget():
            return False

        def read(name, default=None):
            return (configuration.get(name, default) if configuration is not None
                    else self.values.attribute(block, name, default))

        def problem(message):
            self.error(block, message, block.attributes.get("ingress") if configuration is not None else None)

        protocol = self.ingress_protocol(read("ip_protocol" if modern else "protocol"))
        if isinstance(protocol, Unknown):
            problem(protocol.reason)
            return
        if protocol not in {"tcp", "6", "-1"}:
            if protocol not in {"udp", "icmp", "icmpv6", "ipv6-icmp", "gre", "esp", "ah"} and not re.fullmatch(r"[0-9]{1,3}", protocol):
                problem("unsupported ingress protocol")
            return
        # Inline rules share the provider's rule-object expansion, which
        # requires zero ports for all protocols. Standalone rule resources
        # have distinct schemas; modern all-protocol rules may omit ports.
        if protocol != "-1" or configuration is not None or block.kind == "ingress":
            low = self.ingress_port(read("from_port"))
            high = self.ingress_port(read("to_port"))
            if isinstance(low, Unknown) or isinstance(high, Unknown):
                problem("ingress port range is unresolved")
                return
            if protocol == "-1" and (low, high) != (0, 0):
                problem("all-protocol ingress requires from_port and to_port to be zero")
                return
            if protocol != "-1" and not 0 <= low <= high <= 65535:
                problem("invalid ingress port range")
                return
            if protocol != "-1" and not any(low <= port <= high for port in (22, 3389)):
                return
        public = False
        for name, version in (("cidr_ipv4", 4), ("cidr_ipv6", 6)) if modern else (("cidr_blocks", 4), ("ipv6_cidr_blocks", 6)):
            value = read(name, [] if not modern else None)
            entries = ([value] if value is not None else []) if modern else self.ingress_strings(value)
            exposed, invalid = self.public_cidrs(entries, version)
            if invalid:
                problem(f"{name} contains an unresolved or invalid CIDR")
            public |= exposed
        if public and configuration is None:
            self.emit(block, "", NETWORK, "all addresses can reach SSH/RDP or all IP protocols")
        return public

    def bucket_identity(self, block: Block, provider: str):
        if block.labels[0] == "aws_s3_bucket":
            return (provider, "reference", block.labels[1])
        attribute = block.attributes.get("bucket")
        if attribute is None:
            return None
        raw = "".join(t.value for t in attribute.tokens)
        traversal = (len(attribute.tokens) == 5
                     and all(attribute.tokens[index].kind == "word" for index in (0, 2, 4))
                     and all(attribute.tokens[index].kind == "symbol" and attribute.tokens[index].value == "."
                             for index in (1, 3)))
        match = re.fullmatch(r"aws_s3_bucket\.([A-Za-z_][\w-]*)\.(?:id|bucket)", raw) if traversal else None
        if match:
            return (provider, "reference", match.group(1))
        name = self.values.evaluate_attribute(attribute)
        if isinstance(name, str):
            matches = [resource for resource in self.resources if resource.labels[0] == "aws_s3_bucket"
                       and self.values.attribute(resource, "bucket") == name and self.provider(resource) == provider]
            if len(matches) == 1:
                return (provider, "reference", matches[0].labels[1])
            return (provider, "literal", name)
        return None

    def acl(self, block: Block, provider: str, protections: list[Block]):
        acl = self.values.attribute(block, "acl")
        if acl is None:
            if block.labels[0] == "aws_s3_bucket_acl":
                self.error(block, "non-canned S3 ACL grants are outside the selected model")
            return
        if unknown(acl) or not isinstance(acl, str):
            self.error(block, "S3 ACL is unresolved")
            return
        if acl not in {"public-read", "public-read-write", "authenticated-read"}:
            return
        identity = self.bucket_identity(block, provider)
        if identity is None:
            self.error(block, "public ACL bucket identity is unresolved")
            return
        ignored, conflict, uncertain = False, False, False
        controls = set()
        for protection in protections:
            count = self.values.attribute(protection, "count", 1)
            instances = self.values.attribute(protection, "for_each", {"one": 1})
            if (type(count) is int and count == 0) or instances == {}:
                continue
            other_provider = self.provider(protection)
            other_identity = self.bucket_identity(protection, other_provider) if other_provider else None
            if other_identity is None:
                uncertain = True
                continue
            if other_identity != identity:
                continue
            if not self.active(protection):
                if "count" in protection.attributes or "for_each" in protection.attributes:
                    # A proven empty resource contributes no protection.
                    count = self.values.attribute(protection, "count", 1)
                    instances = self.values.attribute(protection, "for_each", {"one": 1})
                    uncertain |= count != 0 and instances != {}
                continue
            control = protection.labels[0]
            if control in controls:
                uncertain = True
            controls.add(control)
            if protection.labels[0] == "aws_s3_bucket_public_access_block":
                ignore = self.values.attribute(protection, "ignore_public_acls", False)
                blocked = self.values.attribute(protection, "block_public_acls", False)
                if type(ignore) is not bool or type(blocked) is not bool:
                    uncertain = True
                ignored |= ignore is True
                conflict |= blocked is True
            else:
                rules = [child for child in protection.children if child.kind == "rule"]
                if len(rules) != 1:
                    uncertain = True
                else:
                    ownership = self.values.attribute(rules[0], "object_ownership")
                    uncertain |= unknown(ownership) or ownership is None
                    conflict |= ownership == "BucketOwnerEnforced"
        if conflict:
            self.error(block, "public ACL conflicts with explicit ACL blocking or BucketOwnerEnforced ownership")
        elif uncertain:
            self.error(block, "S3 public ACL protection is unresolved")
        elif not ignored:
            self.emit(block, "acl", STORAGE, f"{acl} is configured without a selected effective ACL ignore control")

    def policy_conditions(self, blocks: list[Block], version: str,
                          visiting: tuple[str, ...], string_chars: int):
        """Lower static provider condition blocks without deciding their truth.

        Equal operator/context names collect values into one JSON condition.
        The provider's condition set removes identical input blocks before
        its IAM-variable conversion; distinct blocks retain all their values.
        """
        conditions, seen = {}, set()
        for block in blocks:
            if (block.kind != "condition" or block.labels or block.children
                    or set(block.attributes) != {"test", "variable", "values"}):
                return Unknown("IAM policy conditions require static test, variable and values fields; dynamic blocks and principals are unsupported")
            test = self.values.attribute(block, "test", visiting=visiting)
            variable = self.values.attribute(block, "variable", visiting=visiting)
            values = self.values.attribute(block, "values", visiting=visiting)
            if (not isinstance(test, str) or not test or not isinstance(variable, str) or not variable
                    or not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values)):
                return Unknown("IAM policy condition fields are unresolved or outside the supported string model",
                               cyclic=unknown([test, variable, values], cycles_only=True))
            # Empty condition strings are legal provider input. Include their
            # JSON quotes in the budget so shared lists of empty strings cannot
            # amplify unboundedly before grouping or variable replacement.
            string_chars += len(test) + len(variable) + sum(len(value) + 2 for value in values)
            if string_chars > MAX_POLICY_BYTES:
                return Unknown("IAM policy condition string expansion budget exhausted")
            identity = (test, variable, tuple(values))
            if identity in seen:
                continue
            seen.add(identity)
            replaced = policy_variables(values, version)
            if isinstance(replaced, Unknown):
                return replaced
            conditions.setdefault(test, {}).setdefault(variable, []).extend(replaced)
        for terms in conditions.values():
            for variable, values in terms.items():
                if len(values) == 1:
                    terms[variable] = values[0]
        return conditions, string_chars

    def policy_document(self, name: str, visiting: tuple[str, ...]):
        """Resolve selected static AWS data statements without executing Terraform.

        Generation alone does not grant permissions: only an identity-policy
        resource consuming the JSON is a finding site. Sources, own statements
        and overrides replace whole statements by nonblank SID, in that order.
        Unsupported input never disappears merely because an override exists.
        """
        definitions = self.policy_documents.get(name, [])
        if len(definitions) != 1:
            return Unknown("missing or duplicate IAM policy document data source " + name)
        block = definitions[0]
        if set(block.attributes) - {"provider", "version", "source_policy_documents", "override_policy_documents"}:
            return Unknown("IAM policy document data source has unsupported attributes or replication")
        if self.provider(block) is None:
            return Unknown("IAM policy document data source does not resolve to the HashiCorp AWS provider")
        version = self.values.attribute(block, "version", "2012-10-17", visiting=visiting)
        if version is None:
            version = "2012-10-17"
        if not isinstance(version, str) or version not in {"2008-10-17", "2012-10-17"}:
            return Unknown("IAM policy document version is unresolved or unsupported", cyclic=unknown(version, cycles_only=True))
        statements, string_chars, own_identifiers = [], 0, set()
        for child in block.children:
            if (child.kind != "statement" or child.labels
                    or set(child.attributes) - {"sid", "effect", "actions", "resources"}):
                return Unknown("IAM policy document requires static identity statements without principals or complement operators")
            effect = self.values.attribute(child, "effect", "Allow", visiting=visiting)
            if effect is None:
                effect = "Allow"
            sid = self.values.attribute(child, "sid", "", visiting=visiting)
            if sid is None:
                sid = ""
            if (not isinstance(effect, str) or effect not in {"Allow", "Deny"}
                    or not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9]*", sid)):
                return Unknown("IAM policy document statement effect or identifier is unresolved",
                               cyclic=unknown([effect, sid], cycles_only=True))
            if sid and sid in own_identifiers:
                return Unknown("duplicate IAM policy document statement identifier")
            if sid:
                own_identifiers.add(sid)
            statement = {"Effect": effect}
            # The provider permits repeated blank SIDs; those statements have
            # no identity and cannot override one another. Omit only the blank
            # value so the shared JSON checker still rejects duplicate names.
            if sid:
                statement["Sid"] = sid
                string_chars += len(sid)
            for field, key in (("actions", "Action"), ("resources", "Resource")):
                values = self.values.attribute(child, field, visiting=visiting)
                if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item for item in values):
                    return Unknown("IAM policy document " + field + " must resolve to a nonempty string collection",
                                   cyclic=unknown(values, cycles_only=True))
                # Count shared strings before transforming them: replacing
                # policy variables in repeated references must not allocate
                # an expanded document before the bounded encoder sees it.
                string_chars += sum(len(item) for item in values)
                if string_chars > MAX_POLICY_BYTES:
                    return Unknown("IAM policy document string expansion budget exhausted")
                if field == "resources":
                    values = policy_variables(values, version)
                    if isinstance(values, Unknown):
                        return values
                statement[key] = values
            lowered = self.policy_conditions(child.children, version, visiting, string_chars)
            if isinstance(lowered, Unknown):
                return lowered
            conditions, string_chars = lowered
            if conditions:
                statement["Condition"] = conditions
            statements.append(statement)
        merged = {"Version": version, "Statement": []}
        positions, sizes, source_identifiers = {}, [], set()
        # Bound the retained intermediate result, not just the final encoder:
        # many small source documents can otherwise accumulate a large object.
        merged_bytes = len('{"Version":"2012-10-17","Statement":[]}')

        def merge(incoming, *, source: bool = False):
            nonlocal merged_bytes
            for statement in incoming:
                sid = statement.get("Sid", "")
                if source and sid:
                    if sid in source_identifiers:
                        raise Incomplete("duplicate IAM statement identifier in source policy documents")
                    source_identifiers.add(sid)
                encoded = self.values.encode_json(statement)
                if isinstance(encoded, Unknown):
                    raise Incomplete(encoded.reason)
                position = positions.get(sid) if sid else None
                size = len(encoded)
                projected = merged_bytes + size
                if position is None:
                    projected += bool(merged["Statement"])
                else:
                    projected -= sizes[position]
                if projected > MAX_POLICY_BYTES:
                    raise Incomplete("merged IAM policy document byte budget exhausted")
                merged_bytes = projected
                if position is None:
                    if sid:
                        positions[sid] = len(sizes)
                    sizes.append(size)
                    merged["Statement"].append(statement)
                else:
                    sizes[position] = size
                    merged["Statement"][position] = statement

        def merge_documents(field):
            documents = self.values.attribute(block, field, [], visiting=visiting)
            if documents is None:
                return None  # Null omits an optional collection.
            if not isinstance(documents, list) or unknown(documents):
                return Unknown("IAM " + field + " must resolve to a list of JSON policies",
                               cyclic=unknown(documents, cycles_only=True))
            for document in documents:
                if document is None:
                    continue  # The provider skips null list elements.
                if not isinstance(document, str):
                    return Unknown("IAM " + field + " contains a non-string policy")
                # Charge every parse, including repeated references to a
                # shared string, before allocating its decoded structure.
                if len(document) > MAX_POLICY_BYTES:
                    return Unknown("IAM JSON policy byte budget exhausted")
                self.values.decoded_bytes += len(document.encode("utf-8"))
                if self.values.decoded_bytes > MAX_CONTEXT_BYTES:
                    return Unknown("decoded IAM policy context byte budget exhausted")
                parsed = parse_policy_document(document, composition=True)
                merged["Version"] = max(merged["Version"], parsed["Version"])
                merge(parsed["Statement"], source=field == "source_policy_documents")
            return None

        try:
            unresolved = merge_documents("source_policy_documents")
            if unresolved is not None:
                return unresolved
            merge(statements)
            unresolved = merge_documents("override_policy_documents")
            if unresolved is not None:
                return unresolved
            return self.values.encode_json(merged)
        except (Incomplete, UnicodeError) as exc:
            return Unknown(str(exc))

    def iam(self, block: Block):
        attribute = block.attributes.get("policy")
        if attribute is None:
            self.error(block, "IAM identity policy document is missing")
            return
        try:
            candidate = wildcard_policy(self.values.attribute(block, "policy"))
        except Incomplete as exc:
            self.error(block, str(exc), attribute)
            return
        if candidate:
            self.emit(block, "policy", IAM, "an unconditional Allow selects '*' for both Action and Resource; policy attachment and effective permissions are not evaluated")

    def provider_tls(self):
        """Inspect actual AWS provider configurations, including local aliases."""
        configurations = {}
        for block in self.blocks:
            if block.kind != "provider":
                continue
            if len(block.labels) != 1:
                if "insecure" in block.attributes:
                    self.error(block, "provider configuration requires one local provider name")
                continue
            root = block.labels[0]
            spec = self.required.get(root)
            if root in self.required:
                if not isinstance(spec, dict):
                    if "insecure" in block.attributes:
                        self.error(block, "provider source is unresolved for TLS verification")
                    continue
                source = spec.get("source", "hashicorp/" + root)
                if not isinstance(source, str):
                    if "insecure" in block.attributes:
                        self.error(block, "provider source is unresolved for TLS verification")
                    continue
            else:
                source = "hashicorp/" + root
            if source not in AWS_SOURCES:
                continue
            alias = self.values.attribute(block, "alias", "")
            if (not isinstance(alias, str) or ("alias" in block.attributes and not re.fullmatch(r"[A-Za-z_][\w-]*", alias))
                    or "count" in block.attributes or "for_each" in block.attributes):
                self.error(block, "AWS provider configuration identity is invalid or unresolved")
                continue
            configurations.setdefault((root, alias), []).append(block)
        for blocks in configurations.values():
            if len(blocks) != 1:
                for block in blocks:
                    self.error(block, "duplicate AWS provider configuration identity")
                continue
            block = blocks[0]
            attribute = block.attributes.get("insecure")
            if attribute is None:
                continue  # The documented provider default verifies TLS.
            value = self.values.attribute(block, "insecure")
            if value is None:
                value = False  # Null omits an optional argument and uses its default.
            if isinstance(value, str) and value in {"true", "false"}:
                value = value == "true"  # Terraform's primitive bool conversion.
            if type(value) is not bool:
                self.error(block, "AWS provider TLS verification setting is unresolved", attribute)
            elif value:
                self.emit(block, "insecure", TLS, "insecure=true permits provider HTTPS requests without certificate verification")

    def run(self):
        protections = [b for b in self.resources if b.labels[0] in
                       {"aws_s3_bucket_public_access_block", "aws_s3_bucket_ownership_controls"}]
        seen = set()
        for block in self.resources:
            kind = block.labels[0]
            relevant = (NETWORK in self.enabled and kind in SECURITY_GROUPS | {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
                        or STORAGE in self.enabled and kind in {"aws_s3_bucket", "aws_s3_bucket_acl"}
                        or IAM in self.enabled and kind in IAM_RESOURCES)
            if not relevant:
                continue
            if block.labels in seen:
                self.error(block, "duplicate Terraform resource address")
                continue
            seen.add(block.labels)
            if not self.active(block):
                continue
            provider = self.provider(block)
            if provider is None:
                continue
            if kind in SECURITY_GROUPS:
                if "ingress" in block.attributes:
                    if any(child.kind == "ingress" or child.kind == "dynamic" and child.labels == ("ingress",)
                           for child in block.children):
                        self.error(block, "ingress attributes cannot be mixed with ingress blocks", block.attributes["ingress"])
                        continue
                    self.attribute_ingress(block)
                for child in block.children:
                    if child.kind == "ingress":
                        self.ingress(child)
                    elif child.kind == "dynamic" and child.labels == ("ingress",):
                        self.error(child, "dynamic ingress is unresolved")
            elif kind == "aws_security_group_rule":
                direction = self.values.attribute(block, "type")
                if direction == "ingress":
                    self.ingress(block)
                elif direction != "egress":
                    self.error(block, "security group rule direction is unresolved")
            elif kind == "aws_vpc_security_group_ingress_rule":
                self.ingress(block, modern=True)
            elif kind in IAM_RESOURCES:
                self.iam(block)
            else:
                self.acl(block, provider, protections)
        if TLS in self.enabled:
            self.provider_tls()
        self.errors.extend(sorted(self.values.limits))
        return self.findings, list(dict.fromkeys(self.errors))


def analyze_sources(sources: dict[str, str], enabled_rules=None) -> tuple[list[dict], list[str]]:
    enabled = set(RULES) if enabled_rules is None else set(enabled_rules) & set(RULES)
    if not enabled:
        return [], []
    if sum(len(text.encode("utf-8")) for text in sources.values()) > MAX_CONTEXT_BYTES:
        return [], ["HCL selected context byte budget exhausted"]
    groups = {}
    for path, text in sources.items():
        groups.setdefault(str(Path(path).parent), {})[path] = text
    findings, errors = [], []
    for group in groups.values():
        try:
            records, incomplete = Module(group, enabled).run()
            findings.extend(records)
            errors.extend(incomplete)
        except (ValueError, RecursionError) as exc:
            errors.append(f"HCL analysis incomplete: {exc}")
    return findings, list(dict.fromkeys(errors))


def analyze_source(text: str, path: str = "<input>", enabled_rules=None) -> tuple[list[dict], list[str]]:
    return analyze_sources({path: text}, enabled_rules)


def categories(value: str) -> set[int]:
    if not value:
        return set()
    values = value.split(",")
    if any(not part.strip().isdigit() or int(part) < 1 for part in values):
        raise argparse.ArgumentTypeError("categories must be comma-separated positive integers")
    return {int(part) for part in values}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files-from", required=True)
    parser.add_argument("--sink", required=True)
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--project", default="")
    parser.add_argument("--skip", type=categories, default=set())
    parser.add_argument("--only", type=categories, default=set(CATEGORIES))
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
    if not args.only or not args.only <= CATEGORIES:
        parser.error("HCL categories are 1 (network), 2 (storage), 3 (iam), and 4 (tls)")
    from ubs_core.cache import CapturingSink, ScanCache
    raw = Path(args.files_from).read_bytes()
    files = list(dict.fromkeys(Path(os.fsdecode(entry)).resolve() for entry in raw.split(b"\0") if entry))
    enabled = {rule for rule, (_, category, _) in RULES.items() if category in args.only and category not in args.skip}
    sources, errors = {}, []
    total_bytes = 0
    for path in files:
        try:
            if path.suffix != ".tf" and not path.name.endswith(".tf.json"):
                raise Incomplete("only Terraform .tf and .tf.json configuration is supported; tfvars and generic JSON are not configuration inputs")
            with path.open("rb") as source:
                data = source.read(MAX_SOURCE_BYTES + 1)
            total_bytes += len(data)
            if len(data) > MAX_SOURCE_BYTES or total_bytes > MAX_CONTEXT_BYTES:
                raise Incomplete("HCL source/context byte budget exhausted")
            sources[str(path)] = data.decode("utf-8-sig")
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
    # Locals/protective resources in any selected sibling can change a result.
    # Salt every file entry with the complete selected context, including paths.
    context = hashlib.sha256(json.dumps(sources, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    cache = ScanCache(lang="hcl", project_dir=args.project_dir,
                      skip=",".join(map(str, sorted((CATEGORIES - args.only) | args.skip))),
                      extra="aws-config-v7:" + context)
    cached, pending = cache.partition_files(files)
    sink = CapturingSink()
    if pending:
        records, incomplete = analyze_sources(sources, enabled)
        errors.extend(incomplete)
        for record in records:
            sink.write(json.dumps(record, ensure_ascii=False) + "\n")
        if not errors:
            cache.store_scanned_files(pending, sink.by_file)
    records = []
    for path in files:
        records.extend(cached[path] if path in cached and not errors else sink.get_for_file(path))
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
    summary = {"language": "hcl", "version": args.version, "project": args.project or args.project_dir,
               "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "files": len(files), **counts, "status": "partial" if errors else "ok", "findings": records,
               "categories": category_counts, "ast_grep_rules": 0, "uv_tools": [],
               "extras": {"profile": profile, "scope": "selected Terraform AWS configuration; no plan/state, remote modules or variable inputs"}}
    if os.environ.get("UBS_PROFILE") == "1":
        summary["profile"] = profile
    if errors:
        summary.update(module_error="ANALYZER_ERROR", errors=errors,
                       message=("HCL analysis incomplete: " + "; ".join(errors[:5]))[:1000])
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
        lines = [f"UBS module: Terraform HCL (contract v2) v{args.version} — {summary['project']}"]
        if errors:
            lines.append("Partial: [ANALYZER_ERROR] " + summary["message"])
        if not args.quiet:
            for record in records:
                lines.extend([f"[WARNING] {record['rule']}: {record['message']}", f"  {record['path']}:{record['line']}:{record['col']}"])
        lines.extend(["", "Summary Statistics:", f"Files scanned: {len(files)}", "Critical issues: 0", f"Warning issues: {len(records)}", "Info items: 0"])
        Path(args.text_out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    for error in errors:
        print(f"ubs-hcl: analysis incomplete: {error}", file=sys.stderr)
    Path(args.completion_out).write_text(json.dumps({"language": "hcl", "status": summary["status"], "exit_code": code}) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
