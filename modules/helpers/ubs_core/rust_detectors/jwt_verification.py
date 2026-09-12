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

JWT decode calls are qualified by the crate name or resolved from file-level
Rust use trees (including aliases and globs). Unrelated binary decoders and
function declarations do not establish JWT use. This is lexical import
resolution, not a Rust type checker or cross-file re-export analysis.

The legacy UBS_RUST_FILE_LIST branch yielded entries unresolved and
printed them as-is; ``find(files)`` therefore iterates the entries
unchanged (no resolve, no re-walk). The legacy os.walk/skip_dirs fallback
is documentation-only: the orchestrator passes the already-filtered list.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator, Sequence

MARKER = "ubs:ignore"

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

decode_only_re = re.compile(
    r"\b(?:jsonwebtoken::)?dangerous::insecure_decode\s*"
    + call_suffix
    + r"|(?:^|[^\w:])insecure_decode\s*"
    + call_suffix
    + r"|\bdangerous_unsafe_decode\s*"
    + call_suffix
)
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
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def risky_jwt_statement(statement: str) -> bool:
    code = block_comment_re.sub(" ", mask_string_literals(statement))
    return bool(
        decode_only_re.search(code)
        or signature_disabled_re.search(code)
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


def jwt_decode_pattern(source: str) -> re.Pattern[str]:
    source = mask_string_literals(source)
    namespaces = {"jsonwebtoken"}
    names: set[str] = set()
    imports = list(imported_paths(source))
    for alias in re.findall(r"\bextern\s+crate\s+jsonwebtoken\s+as\s+(\w+)\s*;", source):
        namespaces.add(alias)
    # Imports can refer to a crate alias declared later in the file. Each pass
    # must add a namespace, so resolution is bounded by the number of imports.
    for _ in range(len(imports) + 1):
        before = len(namespaces)
        for path, alias in imports:
            if path[0] not in namespaces:
                continue
            if len(path) == 1:
                namespaces.add(alias)
            elif len(path) == 2 and path[1] == "decode":
                names.add(alias)
            elif len(path) == 2 and path[1] == "*":
                names.add("decode")
        if len(namespaces) == before:
            break
    qualified = "|".join(re.escape(name) for name in sorted(namespaces))
    alternatives = [rf"(?:::)?(?:{qualified})\s*::\s*decode"]
    alternatives.extend(re.escape(name) for name in sorted(names))
    return re.compile(r"(?<![\w:.])(?:" + "|".join(alternatives) + ")" + call_suffix)


def jwt_decode_call(code: str, pattern: re.Pattern[str]) -> re.Match[str] | None:
    for match in pattern.finditer(code):
        if not re.search(r"\bfn\s*$", code[:match.start()]):
            return match
    return None


def line_has_jwt_candidate(line: str, pattern: re.Pattern[str]) -> bool:
    code = block_comment_re.sub(" ", mask_string_literals(line))
    return bool(
        decode_only_re.search(code)
        or signature_disabled_re.search(code)
        or claim_validation_disabled_re.search(code)
        or jwt_decode_call(code, pattern)
    )


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
        decode_pattern = jwt_decode_pattern("\n".join(strip_line_comments(line) for line in scan_lines))
        seen = set()
        for line_no, raw in enumerate(scan_lines, start=1):
            if has_ignore(source_lines, line_no):
                continue
            stripped = strip_line_comments(raw).strip()
            if not stripped or not line_has_jwt_candidate(stripped, decode_pattern):
                continue
            statement = statement_from(scan_lines, line_no)
            if not statement or MARKER in statement:
                continue
            context = function_context(scan_lines, line_no)
            binding_context = binding_context_for_decode(statement, context, decode_pattern)
            code = block_comment_re.sub(" ", mask_string_literals(statement))
            if not (
                risky_jwt_statement(statement)
                or (jwt_decode_call(code, decode_pattern) and lacks_claim_binding(binding_context))
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
