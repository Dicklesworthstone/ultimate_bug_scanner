"""ubs_core.rust_detectors.jwt_verification — JWT decode/validation bypass (bead 0xjg.7).

Port of rust_jwt_verification_matches (modules/ubs-rust.sh 6388-6763;
counted by count_jwt_verification_matches at 6765): flags lines whose
block-comment-masked, string-masked, comment-stripped statement contains
``dangerous::insecure_decode``/``insecure_decode``/``dangerous_unsafe_decode``
calls, ``.insecure_disable_signature_validation()`` or
``validate_exp=false``/``validate_aud=false`` — or a JWT ``decode(...)`` call
whose enclosing function lacks full issuer/audience binding
(``set_issuer`` + ``set_audience`` + required_spec_claims covering
``iss`` and ``aud``, narrowed to statements touching the decode's
validation argument). Block comments are masked with line structure
preserved; statements accumulate over up to 10 lines and function context
over up to 180; ``ubs:ignore`` on a line, the previous line, or the
assembled statement suppresses it. Findings dedupe per (file, line) and
keep file order.

JWT decoder calls are qualified by the crate name or resolved from scoped
Rust use trees (including aliases and globs). Imports do not escape their
module or block, and local declarations can shadow imported callables.
Unrelated binary decoders and function declarations do not establish JWT
use. This is lexical import resolution, not a Rust type checker or
cross-file re-export analysis.

The legacy UBS_RUST_FILE_LIST branch yielded entries unresolved and
printed them as-is; ``find(files)`` therefore iterates the entries
unchanged (no resolve, no re-walk). The legacy os.walk/skip_dirs fallback
is documentation-only: the orchestrator passes the already-filtered list.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.suppression import has_suppression_marker

RULE_ID = "rust.security.jwt-verification"
CATEGORY = 8
TITLE = "JWT decode/validation bypass risk"
SEVERITY = "critical"
DESCRIPTION = (
    "Use jsonwebtoken::decode with a real DecodingKey and Validation that "
    "keeps signature, expiration, issuer, and audience checks enabled and "
    "required; avoid dangerous::insecure_decode, dangerous_unsafe_decode, "
    "insecure_disable_signature_validation(), validate_exp=false, and "
    "validate_aud=false"
)

# Documentation only: legacy os.walk fallback's skip list. The orchestrator
# passes the already-filtered file list, so this is never applied.
skip_dirs = {".git", "target", ".cargo", "node_modules"}
call_suffix = r"(?:\s*::\s*<[^>\n]+>)?\s*\("

signature_disabled_re = re.compile(r"\.insecure_disable_signature_validation\s*\(")
claim_validation_disabled_re = re.compile(
    r"\bvalidate_(?:exp|aud)\s*(?::|=)\s*false\b"
)
decode_validation_arg_re = re.compile(
    r"\s*[^,]+,\s*[^,]+,\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)"
)
fn_start_re = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:(?:const|async|unsafe)\s+)*"
    r"(?:extern\s+(?:\"[^\"]+\"\s+)?)?"
    r"fn\b"
)
issuer_binding_re = re.compile(r"\.set_issuer\s*\(")
audience_binding_re = re.compile(r"\.set_audience\s*\(")
required_issuer_re = re.compile(
    r"\.set_required_spec_claims\s*\([^)]*[\"']iss[\"']|"
    r"\.required_spec_claims\s*\.\s*insert\s*\(\s*[\"']iss[\"']|"
    r"\.required_spec_claims\s*=.*[\"']iss[\"']",
    re.DOTALL,
)
required_audience_re = re.compile(
    r"\.set_required_spec_claims\s*\([^)]*[\"']aud[\"']|"
    r"\.required_spec_claims\s*\.\s*insert\s*\(\s*[\"']aud[\"']|"
    r"\.required_spec_claims\s*=.*[\"']aud[\"']",
    re.DOTALL,
)
block_comment_re = re.compile(r"/\*.*?\*/", re.DOTALL)


def mask_block_comments_preserve_lines(text: str) -> str:
    chars = list(text)
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if raw_hashes is not None:
            if ch == '"' and text.startswith("#" * raw_hashes, i + 1):
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "r":
            j = i + 1
            while j < len(chars) and chars[j] == "#":
                j += 1
            if j < len(chars) and chars[j] == '"':
                raw_hashes = j - i - 1
                i = j + 1
                continue
        if ch == '"':
            quote = ch
            i += 1
            continue
        if ch == "/" and nxt == "*":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i < len(chars):
                ch = chars[i]
                nxt = chars[i + 1] if i + 1 < len(chars) else ""
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    break
                if ch != "\n":
                    chars[i] = " "
                i += 1
            continue
        i += 1
    return "".join(chars)


def strip_line_comments(line: str) -> str:
    out = []
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if raw_hashes is not None:
            out.append(ch)
            if ch == '"' and line.startswith("#" * raw_hashes, i + 1):
                out.extend("#" * raw_hashes)
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "r":
            j = i + 1
            while j < len(line) and line[j] == "#":
                j += 1
            if j < len(line) and line[j] == '"':
                raw_hashes = j - i - 1
                out.extend(line[i:j + 1])
                i = j + 1
                continue
        if ch == '"':
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def statement_from(lines, line_no, max_lines=10):
    idx = line_no - 1
    parts = []
    balance = 0
    for current_idx in range(idx, min(len(lines), idx + max_lines)):
        current = strip_line_comments(lines[current_idx]).strip()
        if not current:
            if parts:
                break
            continue
        parts.append(current)
        balance += current.count("(") + current.count("{") - current.count(")") - current.count("}")
        if current_idx > idx and balance <= 0:
            break
        if current_idx == idx and balance <= 0 and not current.endswith(("{", "(", ",")):
            break
    return " ".join(parts)


def function_context(lines, line_no, max_lines=180):
    start = line_no - 1
    while start > 0 and not fn_start_re.match(strip_line_comments(lines[start])):
        start -= 1
    if not fn_start_re.match(strip_line_comments(lines[start])):
        return statement_from(lines, line_no, max_lines=24)
    parts = []
    balance = 0
    saw_open = False
    for idx in range(start, min(len(lines), start + max_lines)):
        current = strip_line_comments(lines[idx])
        parts.append(current.strip())
        balance += current.count("{") - current.count("}")
        if "{" in current:
            saw_open = True
        if saw_open and idx > start and balance <= 0:
            break
    return " ".join(part for part in parts if part)


def mask_string_literals(text: str) -> str:
    chars = list(text)
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if raw_hashes is not None:
            if ch == '"' and text.startswith("#" * raw_hashes, i + 1):
                chars[i] = " "
                for j in range(i + 1, i + 1 + raw_hashes):
                    chars[j] = " "
                i += raw_hashes + 1
                raw_hashes = None
                continue
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue
        if ch == "r":
            j = i + 1
            while j < len(chars) and chars[j] == "#":
                j += 1
            if j < len(chars) and chars[j] == '"':
                raw_hashes = j - i - 1
                for k in range(i, j + 1):
                    chars[k] = " "
                i = j + 1
                continue
        if ch == '"':
            quote = ch
            chars[i] = " "
            i += 1
            continue
        i += 1
    return "".join(chars)


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and has_suppression_marker(lines[idx], RULE_ID)
    ) or (
        0 <= idx - 1 < len(lines) and has_suppression_marker(lines[idx - 1], RULE_ID)
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def risky_jwt_statement(statement: str) -> bool:
    code = block_comment_re.sub(" ", mask_string_literals(statement))
    return bool(
        signature_disabled_re.search(code)
        or claim_validation_disabled_re.search(code)
    )


def imported_paths(source: str) -> Iterator[tuple[tuple[str, ...], str]]:
    """Expand use trees without recursing on attacker-controlled brace depth."""
    for statement in re.finditer(r"\buse\s+([^;]+);", source):
        prefixes: list[tuple[str, ...]] = [()]
        path: list[str] = []
        alias: str | None = None
        tokens = iter(re.findall(r"[A-Za-z_][A-Za-z_0-9]*|::|[{},*]", statement[1]) + [","])
        for token in tokens:
            if token == "::":
                if not path and not prefixes[-1]:
                    path.append("")
                continue
            if token == "as":
                alias = next(tokens, None)
            elif token == "{":
                prefixes.append(prefixes[-1] + tuple(path))
                path, alias = [], None
            elif token in {",", "}"}:
                if path:
                    full = prefixes[-1] + tuple(path)
                    if full[-1] == "self":
                        full = full[:-1]
                    if full:
                        yield full, alias or full[-1]
                path, alias = [], None
                if token == "}" and len(prefixes) > 1:
                    prefixes.pop()
            else:
                path.append(token)


_SCOPE_TOKEN_RE = re.compile(
    r"(?P<use>\buse\s+[^;]+;)"
    r"|(?P<extern>\bextern\s+crate\s+(?P<crate>\w+)(?:\s+as\s+(?P<alias>\w+))?\s*;)"
    r"|\b(?P<kind>fn|mod|struct|enum|union|type|const|static)\s+(?P<item>\w+)"
    r"|\blet\s+(?:(?:mut|ref)\s+)*(?P<local>\w+)"
    r"|(?P<brace>[{};])"
)
_CALL_RE = re.compile(
    r"(?<![\w:.])(?P<path>(?:::)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)"
    + call_suffix
)
_JWT_DECODERS = {
    ("jsonwebtoken", "decode"): False,
    ("jsonwebtoken", "dangerous_unsafe_decode"): True,
    ("jsonwebtoken", "dangerous", "insecure_decode"): True,
}


@dataclass
class _Scope:
    start: int
    end: int
    parent: int | None = None
    module: bool = False
    imports: dict[str, tuple[str, ...]] = field(default_factory=dict)
    globs: list[tuple[str, ...]] = field(default_factory=list)
    items: dict[str, int | None] = field(default_factory=dict)
    values: set[str] = field(default_factory=set)
    locals: dict[str, int] = field(default_factory=dict)


class _JwtSymbols:
    """Resolve callable names without letting one scope contaminate another.

    Use items apply throughout their containing scope; let bindings apply only
    after their initializer. Module boundaries stop lexical inheritance, with
    explicit self/super/crate paths handled separately. Unknown local symbols
    shadow imports instead of being treated as JWT evidence.
    """

    def __init__(self, source: str):
        self.source = source
        self.scopes = [_Scope(0, len(source), module=True)]
        current = 0
        pending: tuple[str, str, int] | None = None
        for token in _SCOPE_TOKEN_RE.finditer(source):
            scope = self.scopes[current]
            if token["use"]:
                for path, alias in imported_paths(token["use"]):
                    if alias == "*":
                        scope.globs.append(path[:-1])
                    else:
                        scope.imports[alias] = path
            elif token["extern"]:
                scope.imports[token["alias"] or token["crate"]] = ("", token["crate"])
            elif token["kind"]:
                if token["kind"] in {"mod", "struct", "enum", "union", "type"}:
                    scope.items[token["item"]] = None
                if token["kind"] in {"fn", "struct", "const", "static"}:
                    scope.values.add(token["item"])
                pending = (token["kind"], token["item"], token.end())
            elif token["local"]:
                # Do not hide a real decode in `let decode = decode(...)`.
                depth = 0
                end = token.end()
                for end in range(end, len(source)):
                    char = source[end]
                    if char in "([{":
                        depth += 1
                    elif char in ")]}":
                        if depth == 0:
                            break
                        depth -= 1
                    elif char == ";" and depth == 0:
                        break
                scope.locals.setdefault(token["local"], end + 1)
            elif token["brace"] == "{":
                child = _Scope(token.end(), len(source), current,
                               module=bool(pending and pending[0] == "mod"))
                if pending and pending[0] == "mod":
                    scope.items[pending[1]] = len(self.scopes)
                elif pending and pending[0] == "fn":
                    header = source[pending[2]:token.start()]
                    start = header.find("(")
                    depth = 0
                    end = start
                    for end in range(max(0, start), len(header)):
                        if header[end] == "(":
                            depth += 1
                        elif header[end] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                    parameters = header[start + 1:end] if start >= 0 else ""
                    for name in re.findall(r"(?:^|,)\s*(?:mut\s+)?(\w+)\s*:", parameters):
                        child.locals[name] = child.start
                self.scopes.append(child)
                current = len(self.scopes) - 1
                pending = None
            elif token["brace"] == "}":
                scope.end = token.start()
                current = scope.parent if scope.parent is not None else 0
                pending = None
            elif token["brace"] == ";":
                pending = None
        self.starts = [scope.start for scope in self.scopes]

    def scope_at(self, offset: int) -> int:
        index = bisect_right(self.starts, offset) - 1
        while self.scopes[index].end <= offset and self.scopes[index].parent is not None:
            index = self.scopes[index].parent
        return index

    def _module(self, scope: int) -> int:
        while not self.scopes[scope].module:
            scope = self.scopes[scope].parent or 0
        return scope

    def _lookup(self, name: str, scope: int, offset: int,
                seen: frozenset[tuple[int, str, bool]], *,
                namespace: bool = False) -> tuple[str, ...] | int | None:
        key = (scope, name, namespace)
        if key in seen or len(seen) >= 100:
            return None
        seen = seen | {key}
        local = self.scopes[scope]
        if not namespace and (local.locals.get(name, len(self.source) + 1) <= offset
                              or name in local.values):
            return None
        if namespace and name in local.items:
            return local.items[name]
        if name in local.imports:
            path = local.imports[name]
            if path == ("jsonwebtoken",):
                return path
            return self._resolve(path, scope, offset, seen, namespace=namespace)
        for path in local.globs:
            target = self._resolve(path, scope, offset, seen, namespace=True)
            if isinstance(target, tuple):
                result = target + (name,)
                if result in _JWT_DECODERS or result == ("jsonwebtoken", "dangerous"):
                    return result
            elif isinstance(target, int):
                result = self._lookup(name, target, offset, seen, namespace=namespace)
                if result is not None:
                    return result
        if local.parent is not None and not local.module:
            return self._lookup(name, local.parent, offset, seen, namespace=namespace)
        return ("jsonwebtoken",) if name == "jsonwebtoken" else None

    def _resolve(self, path: tuple[str, ...], scope: int, offset: int,
                 seen: frozenset[tuple[int, str, bool]], *,
                 namespace: bool = False) -> tuple[str, ...] | int | None:
        if not path:
            return None
        if path[0] == "":
            return path[1:] if len(path) > 1 and path[1] == "jsonwebtoken" else None
        if path[0] in {"crate", "self", "super"}:
            scope = 0 if path[0] == "crate" else self._module(scope)
            while path and path[0] in {"crate", "self", "super"}:
                if path[0] == "super":
                    parent = self.scopes[scope].parent
                    if parent is None:
                        return None
                    scope = self._module(parent)
                path = path[1:]
            if not path:
                return scope
        resolved = self._lookup(path[0], scope, offset, seen,
                                namespace=namespace or len(path) > 1)
        for index, name in enumerate(path[1:], start=1):
            if isinstance(resolved, tuple):
                resolved += (name,)
            elif isinstance(resolved, int):
                resolved = self._lookup(name, resolved, offset, seen,
                                        namespace=namespace or index < len(path) - 1)
            else:
                return None
        return resolved

    def calls(self) -> Iterator[tuple[re.Match[str], bool]]:
        for call in _CALL_RE.finditer(self.source):
            if re.search(r"\bfn\s*$", self.source[max(0, call.start() - 8):call.start()]):
                continue
            path = tuple(re.split(r"\s*::\s*", call["path"]))
            resolved = self._resolve(path, self.scope_at(call.start()), call.start(), frozenset())
            if resolved in _JWT_DECODERS:
                yield call, _JWT_DECODERS[resolved]


def jwt_decode_call(code: str, pattern: re.Pattern[str]) -> re.Match[str] | None:
    for match in pattern.finditer(code):
        if not re.search(r"\bfn\s*$", code[:match.start()]):
            return match
    return None


def lacks_claim_binding(context: str) -> bool:
    code = block_comment_re.sub(" ", context)
    return not (
        issuer_binding_re.search(code)
        and audience_binding_re.search(code)
        and required_issuer_re.search(code)
        and required_audience_re.search(code)
    )


def binding_context_for_decode(statement: str, context: str, pattern: re.Pattern[str]) -> str:
    call = jwt_decode_call(mask_string_literals(statement), pattern)
    match = decode_validation_arg_re.match(statement, call.end()) if call else None
    if not match:
        return context
    validation_var = re.escape(match.group(1))
    related_parts = [
        part
        for part in context.split(";")
        if re.search(rf"\b{validation_var}\b", part)
    ]
    return "; ".join(related_parts) if related_parts else context


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy finding, in legacy order."""
    issues: list[tuple[Path, int, int, str]] = []
    for listed in files:
        rust_file = Path(listed)
        if rust_file.suffix != ".rs":
            continue
        try:
            text = rust_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not any(token in text for token in (
            "decode",
            "insecure_decode",
            "dangerous_unsafe_decode",
            "insecure_disable_signature_validation",
            "validate_exp",
            "validate_aud",
            "Validation",
        )):
            continue
        source_lines = text.splitlines()
        scan_lines = mask_block_comments_preserve_lines(text).splitlines()
        masked = strip_comments_and_strings(text, lang="rust")
        line_starts = [0] + [match.end() for match in re.finditer("\n", masked)]
        calls_by_line: dict[int, list[tuple[re.Pattern[str], bool]]] = {}
        for call, insecure in _JwtSymbols(masked).calls():
            line = bisect_right(line_starts, call.start())
            path_pattern = r"\s*::\s*".join(re.escape(part) for part in
                                            re.split(r"\s*::\s*", call["path"]))
            pattern = re.compile(r"(?<![\w:.])" + path_pattern + call_suffix)
            calls_by_line.setdefault(line, []).append((pattern, insecure))
        seen = set()
        for line_no, raw in enumerate(scan_lines, start=1):
            if has_ignore(source_lines, line_no):
                continue
            stripped = strip_line_comments(raw).strip()
            calls = calls_by_line.get(line_no, [])
            if not stripped or not (calls or risky_jwt_statement(stripped)):
                continue
            statement = statement_from(scan_lines, line_no)
            if not statement or has_suppression_marker(statement, RULE_ID):
                continue
            context = function_context(scan_lines, line_no)
            if not (
                risky_jwt_statement(statement)
                or any(insecure or lacks_claim_binding(binding_context_for_decode(
                    statement, context, pattern,
                )) for pattern, insecure in calls)
            ):
                continue
            key = (str(rust_file), line_no)
            if key in seen:
                continue
            seen.add(key)
            issues.append((rust_file, line_no, 1, source_line(source_lines, line_no)))
    yield from issues


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for found_path, line, col, code in find(root_files):
        print(f"{found_path}:{line}:{code}")
