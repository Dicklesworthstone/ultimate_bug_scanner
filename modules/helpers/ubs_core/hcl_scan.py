"""Bounded Terraform AWS configuration checks; no plan, state or provider execution.

Selected administrative ingress, public S3 ACLs, unrestricted IAM policy intent,
and disabled AWS provider TLS verification are checked.
Selected .tf files in one directory share locals and resource identities. Input
variables, remote modules, templates and dynamic relevant configuration remain
unknown. A complete result describes these selected checks, never deployed
reachability or comprehensive infrastructure security.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime
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
NETWORK = "hcl.aws.public-admin-ingress"
STORAGE = "hcl.aws.public-s3-acl"
IAM = "hcl.aws.iam-wildcard-privilege"
TLS = "hcl.aws.insecure-provider-tls"
IAM_RESOURCES = frozenset({"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"})
AWS_SOURCES = frozenset({"hashicorp/aws", "registry.terraform.io/hashicorp/aws"})
CATEGORIES = frozenset(category for _, category, _ in RULES.values())


class Incomplete(ValueError):
    """A selected configuration cannot be evaluated by this bounded model."""


@dataclass(frozen=True)
class Unknown:
    reason: str


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
        self.evaluations = 0
        for block in blocks:
            if block.kind == "locals" and not block.labels:
                for name, attribute in block.attributes.items():
                    if name in self.locals:
                        self.duplicate_locals.add(name)
                    self.locals[name] = attribute

    def evaluate(self, tokens: tuple[Token, ...], visiting: tuple[str, ...] = ()):
        self.evaluations += 1
        if self.evaluations > MAX_EVALUATIONS:
            return Unknown("HCL expression evaluation budget exhausted")
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
            if token.kind == "string":
                return token.value
            if token.kind == "number":
                try:
                    number = float(token.value) if re.search(r"[.eE]", token.value) else int(token.value)
                    return number if not isinstance(number, float) or math.isfinite(number) else Unknown("number is outside the supported range")
                except ValueError:
                    return Unknown("invalid number")
            if token.value in {"true", "false", "null"}:
                return {"true": True, "false": False, "null": None}[token.value]
        raw = "".join(t.value for t in tokens)
        if re.fullmatch(r"local\.[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*", raw):
            name, *members = raw.split(".")[1:]
            if name in visiting or name in self.duplicate_locals:
                return Unknown(f"cyclic or duplicate local {name}")
            if name not in self.locals:
                return Unknown(f"unresolved local {name}")
            if name not in self.memo:
                self.memo[name] = self.evaluate(self.locals[name].tokens, (*visiting, name))
            value = self.memo[name]
            for member in members:
                value = value.get(member, Unknown(f"unresolved local member {member}")) if isinstance(value, dict) else Unknown("unresolved local object")
            return value
        if (len(tokens) >= 3 and tokens[0].kind == "word" and tokens[0].value == "jsonencode"
                and tokens[1].value == "(" and tokens[-1].value == ")"):
            # Only the built-in single-argument function is evaluated. No file
            # reads, provider functions, templates or external code are run.
            opening = next(index for index, token in enumerate(original) if token.value == "(")
            arguments = split_items(original[opening + 1:-1])
            if len(arguments) != 1:
                return Unknown("jsonencode requires one supported argument")
            value = self.evaluate(arguments[0], visiting)
            if unknown(value):
                return Unknown("jsonencode contains unresolved configuration")
            # Local DAGs can describe exponentially larger JSON than their
            # source. Stream into a bounded buffer instead of expanding first.
            chunks, size = [], 0
            try:
                for chunk in json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":")).iterencode(value):
                    size += len(chunk)
                    if size > MAX_POLICY_BYTES:
                        return Unknown("encoded JSON policy byte budget exhausted")
                    chunks.append(chunk)
                return "".join(chunks)
            except (ValueError, TypeError, RecursionError):
                return Unknown("JSON encoding exceeded the supported value or nesting limits")
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

    def attribute(self, block: Block, name: str, default=None):
        attribute = block.attributes.get(name)
        return self.evaluate(attribute.tokens) if attribute else default


def unknown(value) -> bool:
    pending, seen = [value], set()
    while pending:
        item = pending.pop()
        if isinstance(item, Unknown):
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


def wildcard_policy(value) -> bool:
    """Prove only an unconditional all-action/all-resource identity grant.

    Other policy types, complement operators and effective policy evaluation
    are deliberately excluded. A deny can restrict a candidate grant, so it
    requires an incomplete result instead of a guessed permission outcome.
    """
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
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or not statements:
        raise Incomplete("IAM policy requires a nonempty Statement object or array")
    candidate, conditional, denied, identifiers = False, False, False, set()
    for statement in statements:
        if not isinstance(statement, dict) or set(statement) - {"Sid", "Effect", "Action", "Resource", "Condition"}:
            raise Incomplete("unsupported IAM statement fields, principal or complement operators")
        if "Sid" in statement:
            sid = statement["Sid"]
            if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9]*", sid) or sid in identifiers:
                raise Incomplete("invalid or duplicate IAM statement identifier")
            identifiers.add(sid)
        effect = statement.get("Effect")
        if not isinstance(effect, str) or effect not in {"Allow", "Deny"}:
            raise Incomplete("IAM statement Effect must be Allow or Deny")
        actions = policy_strings(statement.get("Action"), "Action")
        resources = policy_strings(statement.get("Resource"), "Resource")
        if "Condition" in statement:
            condition = statement["Condition"]
            if not isinstance(condition, dict) or not condition or any(not isinstance(v, dict) or not v for v in condition.values()):
                raise Incomplete("unsupported IAM Condition structure")
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
        for path, text in sources.items():
            try:
                if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
                    raise Incomplete("HCL source byte budget exhausted")
                parser = Parser(text, path)
                attributes, blocks = parser.body(0, len(parser.tokens))
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
        self.required = {}
        for block in self.blocks:
            if block.kind == "terraform":
                for child in block.children:
                    if child.kind == "required_providers":
                        for name, attr in child.attributes.items():
                            self.required[name] = (Unknown("duplicate provider requirement") if name in self.required
                                                   else self.values.evaluate(attr.tokens))

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

    def ingress(self, block: Block, *, modern: bool = False):
        protocol = self.values.attribute(block, "ip_protocol" if modern else "protocol")
        if unknown(protocol) or protocol is None:
            self.error(block, "ingress protocol is unresolved")
            return
        if isinstance(protocol, bool) or not isinstance(protocol, (str, int, float)):
            self.error(block, "invalid ingress protocol")
            return
        if isinstance(protocol, float):
            if not protocol.is_integer():
                self.error(block, "invalid ingress protocol number")
                return
            protocol = int(protocol)
        protocol = str(protocol).lower()
        if protocol not in {"tcp", "6", "-1", "all"}:
            if protocol not in {"udp", "icmp", "icmpv6", "ipv6-icmp", "gre", "esp", "ah"} and not re.fullmatch(r"[0-9]{1,3}", protocol):
                self.error(block, "unsupported ingress protocol")
            return
        if protocol not in {"-1", "all"}:
            low, high = (self.values.attribute(block, name) for name in ("from_port", "to_port"))
            try:
                if (isinstance(low, bool) or isinstance(high, bool)
                        or not isinstance(low, (str, int, float)) or not isinstance(high, (str, int, float))
                        or float(low) != int(low) or float(high) != int(high)):
                    raise ValueError("non-integral port")
                low, high = int(low), int(high)
            except (ValueError, TypeError, OverflowError):
                self.error(block, "ingress port range is unresolved")
                return
            if not 0 <= low <= high <= 65535:
                self.error(block, "invalid ingress port range")
                return
            if not any(low <= port <= high for port in (22, 3389)):
                return
        public = False
        for name, version in (("cidr_ipv4", 4), ("cidr_ipv6", 6)) if modern else (("cidr_blocks", 4), ("ipv6_cidr_blocks", 6)):
            value = self.values.attribute(block, name, [] if not modern else None)
            entries = ([value] if value is not None else []) if modern else value
            if not isinstance(entries, list):
                self.error(block, f"{name} is unresolved")
                continue
            exposed = False
            for entry in entries:
                try:
                    if not isinstance(entry, str) or not re.fullmatch(r"[^/]+/[0-9]{1,3}", entry):
                        raise ValueError("unresolved CIDR")
                    network = ipaddress.ip_network(entry, strict=True)
                    if network.version != version:
                        raise ValueError("CIDR address family mismatch")
                    exposed |= network.prefixlen == 0
                except ValueError:
                    self.error(block, f"{name} contains an unresolved or invalid CIDR")
            public |= exposed
        if public:
            self.emit(block, "", NETWORK, "all addresses can reach SSH/RDP or all IP protocols")

    def bucket_identity(self, block: Block, provider: str):
        if block.labels[0] == "aws_s3_bucket":
            return (provider, "reference", block.labels[1])
        attribute = block.attributes.get("bucket")
        if attribute is None:
            return None
        raw = "".join(t.value for t in attribute.tokens)
        match = re.fullmatch(r"aws_s3_bucket\.([A-Za-z_][\w-]*)\.(?:id|bucket)", raw)
        if match:
            return (provider, "reference", match.group(1))
        name = self.values.evaluate(attribute.tokens)
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
            relevant = (NETWORK in self.enabled and kind in {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
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
            if kind == "aws_security_group":
                if "ingress" in block.attributes:
                    value = self.values.attribute(block, "ingress")
                    if value != []:
                        self.error(block, "attribute-based ingress is outside the selected block model")
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
            if path.suffix != ".tf":
                raise Incomplete("only native Terraform .tf configuration is supported; tfvars and JSON are not configuration inputs")
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
                      extra="aws-config-v2:" + context)
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
