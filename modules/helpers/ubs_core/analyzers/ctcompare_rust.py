"""ubs_core.analyzers.ctcompare_rust — non-constant-time secret comparisons (bead A2).

Track secret evidence and ambiguous signature-map values through scoped aliases.
Known secret comparisons remain critical. A bare sig/signature map key alone
requires review: it may name an authentication value or a public transaction ID.
The native Rust scanner and the standalone analyzer share these classifications.
"""
from __future__ import annotations

from functools import cache
import os
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.io import source_line
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import has_suppression_marker
from ubs_core.rust_detectors.hardcoded_secrets import (
    ENV_CALL_RE, STRING_RE, direct_risky_literal, metadata_literal, unquote_literal,
)

_SUPPRESSION_RULE = "rust.security.constant-time-compare"

skip_dirs = {".git", "target", ".cargo", "node_modules"}

comparison_token_re = re.compile(
    r"(?P<compare>(?<![=!<>])(?:==|!=)(?!=))"
    r"|(?P<boolean>&&|\|\|)|(?P<separator>;|,|=>)"
    r"|(?P<open>[([{])|(?P<close>[)\]}])"
)
assign_re = re.compile(
    r"^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?"
    # A type annotation begins with one colon, not a qualified match-arm
    # path; neither equality nor a match arrow is an assignment operator.
    r"(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::(?!:)[^=;]+)?=(?![=>])\s*(?P<rhs>.+)"
)
identifier_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A `fn` ITEM declaration (`pub async fn verify`), not a function-pointer type
# (`fn(u32) -> u32`) and not the `Fn`/`FnMut` traits.
fn_decl_re = re.compile(r"(?:^|[^A-Za-z0-9_:])fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
safe_compare_re = re.compile(
    r"\b(?:subtle::)?ConstantTimeEq\s*(?P<ufcs>>\s*)?::\s*ct_eq\s*\("
    r"|\.(?:ct_eq|constant_time_eq|timing_safe_eq|timing_safe_compare|safe_eq|safe_compare|secure_compare)\s*\("
    r"|\b(?:constant_time_eq|constant_time_compare|timing_safe_eq|timing_safe_compare|"
    r"safe_eq|safe_compare|secure_compare|crypto_memcmp)\s*\("
    r"|\bring::constant_time::verify_slices_are_equal\s*\(",
    re.IGNORECASE,
)
# GH #85: two-tier vocabulary. Strong terms are security-sensitive on their
# own (unless immediately followed by schema/metadata vocabulary such as
# "signature_format" or "credential_type"). Weak terms (token, key, digest,
# nonce, session, ...) are ordinary parser/domain vocabulary and only become
# sensitive when combined with a security qualifier (auth_token, api_key,
# session_token, webhook_signature, ...). This stops a bare parser `token`
# from tainting comparisons like `candidate == "BR2"`.
strong_terms = {
    "secret", "password", "passwd", "pwd", "bearer", "hmac", "csrf", "xsrf",
    "otp", "totp", "mfa", "signature", "sig", "credential", "credentials",
    "authorization", "jwt",
}
weak_terms = {
    "token", "key", "mac", "digest", "nonce", "session", "auth", "reset",
    "webhook", "invite", "verification", "recovery",
}
qualifier_terms = {
    "api", "auth", "access", "refresh", "session", "reset", "recovery",
    "verification", "invite", "jwt", "csrf", "xsrf", "webhook", "hmac",
    "bearer", "secret", "signing", "signature", "private", "otp", "totp",
    "mfa", "password", "passwd", "pwd", "credential", "credentials",
}
metadata_terms = {
    "field", "format", "kind", "layout", "policy", "schema", "state",
    "status", "type", "mode", "scheme", "parser", "alg", "algorithm",
    "aud", "audience", "claim", "claims", "exp", "expiration", "header",
    "headers", "issuer", "iss", "kid", "name", "label", "id", "index",
    "count", "len", "length", "scope", "scopes",
}
ambiguous_signature_keys = {"sig", "signature"}
verification_terms = {
    "auth", "authenticate", "authentication", "authorize", "authorization",
    "verify", "verification", "validate", "validation", "sign", "signing",
    "hmac", "webhook",
}
call_name_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
nullish_re = re.compile(r'^(?:None|Some\s*\([^)]*\)|Ok\s*\([^)]*\)|Err\s*\([^)]*\)|true|false|0|1|""|b""|\[\])$')
shape_re = re.compile(r"\b(?:len|is_empty|capacity)\s*\(|\.(?:len|is_empty|capacity)\s*\(")
pure_string_literal_re = re.compile(r'^\s*(?:"(?:\\.|[^"\\])*"|r#*"[^"]*"#*|b"(?:\\.|[^"\\])*")\s*$')
key_lookup_re = re.compile(
    r'(?:\.\s*get(?:_mut)?\s*\(\s*|(?:[A-Za-z_][A-Za-z0-9_]*|\)|\])\s*\[\s*)'
    r'(' + STRING_RE.pattern + r')'
)
keywords = {
    "if", "while", "match", "return", "let", "mut", "const", "static", "true",
    "false", "None", "Some", "Ok", "Err", "self", "Self", "crate", "super",
}


def rust_files(path: Path):
    _ubs_listing = os.environ.get("UBS_RUST_FILE_LIST", "")
    if _ubs_listing and os.path.isfile(_ubs_listing):
        # GH #70: consume the module's authoritative filtered file list
        # (--exclude / --strict-gitignore / --exclude-tests) instead of
        # re-walking the tree with a local skip list.
        with open(_ubs_listing, encoding="utf-8") as _ubs_fh:
            for _ubs_line in _ubs_fh:
                _ubs_entry = _ubs_line.rstrip("\n")
                if _ubs_entry.endswith(".rs"):
                    yield Path(_ubs_entry)
        return
    if path.is_file():
        if path.suffix == ".rs":
            yield path
        return
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            candidate = Path(dirpath) / name
            if candidate.suffix == ".rs":
                yield candidate


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


def statement_from(stripped_lines, line_no, max_lines=8):
    idx = line_no - 1
    parts = []
    balance = 0
    for current_idx in range(idx, min(len(stripped_lines), idx + max_lines)):
        current = stripped_lines[current_idx].strip()
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


def split_identifier_terms(text: str) -> str:
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"[_\-.]+", " ", text)
    return text


def is_sensitive_text(text: str, public_metadata=()) -> bool:
    # Qualifiers belong to one identifier, never to an unrelated callee or
    # argument. Literal error codes and labels are not operand identities.
    structural = blank_string_literals(text)
    for match in identifier_re.finditer(structural):
        identifier = match.group(0)
        prefix = structural[:match.start()].rstrip()
        if identifier in public_metadata and not prefix.endswith((".", "::")):
            continue
        terms = re.findall(r"[a-z0-9]+", split_identifier_terms(identifier).lower())
        for idx, term in enumerate(terms):
            if term in strong_terms:
                follower = terms[idx + 1] if idx + 1 < len(terms) else ""
                if follower not in metadata_terms:
                    return True
                continue
            if term in weak_terms and any(
                other_idx != idx and other in qualifier_terms
                for other_idx, other in enumerate(terms)
            ):
                return True
    return False


def lookup_keys(text: str):
    """Yield actual credential-source keys, excluding lookup-shaped literals."""
    structural = blank_string_literals(text)
    for lookup in (ENV_CALL_RE, key_lookup_re):
        for match in lookup.finditer(text):
            # Recognized source calls retain their credential key's meaning.
            # Lookup-shaped text inside a literal is still ordinary text.
            if not structural[match.start():match.start(1)].strip():
                continue
            name = unquote_literal(match.group(1))
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', name):
                yield name, lookup is ENV_CALL_RE


def is_sensitive_lookup(text: str) -> bool:
    return any(is_sensitive_text(name)
               and (environment or name.lower() not in ambiguous_signature_keys)
               for name, environment in lookup_keys(text))


def has_ambiguous_signature_lookup(text: str) -> bool:
    return any(not environment and name.lower() in ambiguous_signature_keys
               for name, environment in lookup_keys(text))


def is_sensitive_operand_text(text: str, public_metadata=()) -> bool:
    stripped = text.strip()
    if pure_string_literal_re.match(stripped):
        return False
    return is_sensitive_lookup(stripped) or is_sensitive_text(stripped, public_metadata)


def operand_identifiers(operand: str):
    return {
        token
        for token in identifier_re.findall(blank_string_literals(operand))
        if token not in keywords
    }


def comparison_operands(statement: str):
    """Yield each real equality's operands, including comparisons inside calls."""
    code = strip_comments_and_strings(statement, "rust")
    tokens = []
    depth = 0
    for token in comparison_token_re.finditer(code):
        tokens.append((token, depth))
        if token.lastgroup == "open":
            depth += 1
        elif token.lastgroup == "close":
            depth -= 1
    for index, (comparison, level) in enumerate(tokens):
        if comparison.lastgroup != "compare":
            continue
        start, end = 0, len(statement)
        for previous_index in range(index - 1, -1, -1):
            previous, previous_level = tokens[previous_index]
            if ((previous.lastgroup in {"separator", "boolean"} and previous_level <= level)
                    or previous.lastgroup == "open" and previous_level < level):
                start = previous.end()
                break
        for following_index in range(index + 1, len(tokens)):
            following, following_level = tokens[following_index]
            if ((following.lastgroup in {"separator", "boolean"} and following_level <= level)
                    or following.lastgroup == "close" and following_level <= level):
                end = following.start()
                break
        left, right = statement[start:comparison.start()], statement[comparison.end():end]
        if left.strip() and right.strip():
            yield comparison.start(), left, right


def call_prefix_start(code: str, call: int) -> int:
    """Bound a call's qualified name or method receiver, retaining other operands."""
    cursor, stack = call - 1, []
    pairs = {")": "(", "]": "[", "}": "{"}
    while cursor >= 0:
        char = code[cursor]
        if char in pairs:
            stack.append(pairs[char])
        elif char in "([{":
            if not stack or stack[-1] != char:
                break
            stack.pop()
        elif not stack and char == ">":
            # A receiver can contain a turbofish, e.g. AsRef::<[u8]>::as_ref().
            # Treat only paired type arguments adjacent to a call/path as
            # receiver syntax; ordinary comparison operators stay boundaries.
            angle, opening = 1, cursor - 1
            while opening >= 0 and angle:
                angle += (code[opening] == ">") - (code[opening] == "<")
                opening -= 1
            opening += 1
            tail = code[cursor + 1:].lstrip()
            if not angle and (tail.startswith("(") or tail.startswith("::")):
                cursor = opening - 1
                continue
            break
        elif not stack and char == "." and (code[cursor:cursor + 2] == ".."
                                            or code[max(0, cursor - 1):cursor + 1] == ".."):
            # A range's lower bound is independent of a call on its upper
            # bound: secret..provided.ct_eq(other) must retain secret.
            break
        elif (not stack and char == "!" and re.match(r"\s*[(\[{]", code[cursor + 1:])
              and re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*$", code[:cursor])):
            # A macro invocation can produce the entire method receiver.
            # This postfix bang is not a separate unary/binary operand.
            cursor -= 1
            continue
        elif not stack and char in "=;,+-*/%&|^!<":
            break
        cursor -= 1
    return cursor + 1


def mask_safe_compare_results(expression: str) -> str:
    """Mask complete timing-safe call results, preserving independent values.

    A comparison result does not carry its secret arguments. Nested unsafe
    equalities are still visited separately by comparison_operands, so calling
    a safe API cannot hide an unsafe operation performed to build its inputs.
    """
    expression = strip_comments_and_strings(expression, "rust", strip_strings=False)
    code = strip_comments_and_strings(expression, "rust")
    spans = []
    for match in safe_compare_re.finditer(code):
        depth, end = 1, match.end()
        while end < len(code) and depth:
            depth += (code[end] == "(") - (code[end] == ")")
            end += 1
        if not depth:
            prefix = match.end("ufcs") if match.group("ufcs") is not None else match.start()
            spans.append((call_prefix_start(code, prefix), end))
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    parts, previous = [], 0
    for start, end in merged:
        # An opaque literal avoids introducing a source variable or treating
        # the other equality operand as an exempt null/shape comparison.
        parts.extend((expression[previous:start], '"comparison result"'))
        previous = end
    parts.append(expression[previous:])
    return "".join(parts)


def assignment_match(statement: str):
    """Keep the raw match only when its assignment operator is outside literals."""
    match = assign_re.match(statement)
    if not match:
        return None
    operator_index = match.start("rhs") - 1
    while operator_index >= 0 and statement[operator_index].isspace():
        operator_index -= 1
    if (
        operator_index < 0
        or statement[operator_index] != "="
        or blank_string_literals(statement)[operator_index] != "="
    ):
        return None
    return match


def clean_operand_text(operand: str) -> str:
    clean = operand.strip()
    clean = re.sub(r"^(?:if|while|match)\s*\(?\s*", "", clean)
    # In `let secret_matches = actual == expected`, the destination is a
    # boolean binding, not part of the equality's left operand. This also
    # keeps a previously tainted discard binding (`let _ = ...`) out of it.
    assignment = assignment_match(clean)
    if assignment:
        clean = assignment.group("rhs").strip()
    clean = re.split(r"\s*(?:&&|\|\||[;{])", clean, maxsplit=1)[0].strip()
    while clean and clean[-1] in ";{}){":
        clean = clean[:-1].strip()
    while clean.startswith(("&", "*")):
        clean = clean[1:].strip()
    return clean


def operand_is_nullish_or_shape_check(operand: str) -> bool:
    clean = clean_operand_text(operand)
    if nullish_re.match(clean):
        return True
    if shape_re.search(clean):
        return True
    if re.match(r"^[0-9]+(?:\.[0-9]+)?(?:u?size|u8|u16|u32|u64|i8|i16|i32|i64)?$", clean):
        return True
    return False


def has_ignore(lines, line_no, rule=None):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and has_suppression_marker(lines[idx], rule)
    ) or (
        0 <= idx - 1 < len(lines) and has_suppression_marker(lines[idx - 1], rule)
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def blank_string_literals(text: str) -> str:
    """Comment-stripped text with string/char literal CONTENT blanked out.

    Used for structural brace, function, identifier and source detection. It
    keeps the original length and every non-literal character in place: a `{`
    inside `"{}"` or `'{'` must not open a scope.
    """
    chars = list(text)
    i = 0
    n = len(chars)
    while i < n:
        ch = chars[i]
        if ch == "r":
            j = i + 1
            while j < n and chars[j] == "#":
                j += 1
            if j < n and chars[j] == '"':
                hashes = j - i - 1
                closer = '"' + "#" * hashes
                end = text.find(closer, j + 1)
                stop = n if end == -1 else end + len(closer)
                for pos in range(i, stop):
                    chars[pos] = " "
                i = stop
                continue
        if ch == '"':
            chars[i] = " "
            i += 1
            escape = False
            while i < n:
                cur = chars[i]
                chars[i] = " "
                i += 1
                if escape:
                    escape = False
                elif cur == "\\":
                    escape = True
                elif cur == '"':
                    break
            continue
        if ch == "'":
            # `'x'` / `'\n'` are char literals; anything else beginning with a
            # quote is a lifetime (`'a`, `'static`) and is left untouched.
            if i + 2 < n and chars[i + 1] == "\\":
                end = i + 2
                while end < n and chars[end] != "'":
                    end += 1
                if end < n:
                    for pos in range(i, end + 1):
                        chars[pos] = " "
                    i = end + 1
                    continue
            elif i + 2 < n and chars[i + 2] == "'":
                for pos in range(i, i + 3):
                    chars[pos] = " "
                i += 3
                continue
        i += 1
    return "".join(chars)


def function_owner_by_line(stripped_lines):
    """Return each line's innermost `fn` body id and the declared body names.

    Id 0 is module scope: everything outside a function body (`static`/`const`
    items, `impl` headers, struct fields). A body that opens and closes on one
    line still gets its own id, so a one-line function is its own taint scope.
    """
    owner = [0] * (len(stripped_lines) + 1)
    depth = 0
    stack = []  # (fn_id, body_depth)
    names = {}
    next_id = 1
    pending_fn = None
    for line_no, stripped in enumerate(stripped_lines, start=1):
        structural = blank_string_literals(stripped)
        declarations = iter(fn_decl_re.finditer(structural))
        declaration = next(declarations, None)
        # The innermost scope active at ANY point on the line owns it, so the
        # body-opening line, the body's closing brace, and a one-line function
        # all resolve to that function rather than to its parent.
        chosen = stack[-1] if stack else None
        for offset, ch in enumerate(structural):
            if declaration is not None and offset >= declaration.start("name"):
                pending_fn = declaration.group("name")
                declaration = next(declarations, None)
            if ch == "{":
                depth += 1
                if pending_fn:
                    stack.append((next_id, depth))
                    names[next_id] = pending_fn
                    next_id += 1
                    pending_fn = None
                    chosen = stack[-1]
            elif ch == "}":
                if stack and stack[-1][1] == depth:
                    stack.pop()
                depth = max(0, depth - 1)
        if pending_fn and ";" in structural and "{" not in structural:
            # A signature-only declaration (trait method, `extern` block).
            pending_fn = None
        owner[line_no] = chosen[0] if chosen else 0
    return owner, names


def verification_context(name, structural_lines, line_numbers):
    """Keep explicit authentication/verification context local to its function."""
    def verification_name(value):
        return bool(set(split_identifier_terms(value).lower().split()) & verification_terms)

    if verification_name(name):
        return True
    # Joining the masked lines recognizes newline-separated call parentheses.
    # Remove declaration names, retaining real calls in a one-line body.
    calls = "\n".join(fn_decl_re.sub("", structural_lines[line_no - 1])
                      for line_no in line_numbers)
    # Type arguments are not callees. Mask a complete turbofish so generic
    # authenticate::<User>(...) retains the same name evidence as a plain
    # call, while build::<AuthContext>() and Vec::<auth::Context>::new() do not.
    masked = list(calls)
    for generic in re.finditer(r"::\s*<", calls):
        if masked[generic.start()] == " ":
            continue
        depth, braces, end = 1, 0, generic.end()
        while end < len(calls) and depth:
            char = calls[end]
            if char == "{":
                braces += 1
            elif char == "}":
                braces = max(0, braces - 1)
            elif not braces and char == "<":
                depth += 1
            elif not braces and char == ">" and calls[end - 1] != "-":
                depth -= 1
            end += 1
        if not depth:
            masked[generic.start():end] = " " * (end - generic.start())
    calls = "".join(masked)
    return any(verification_name(match.group(1)) for match in call_name_re.finditer(calls))


def collect_public_metadata_vars(statement_at, line_numbers, seeded=()):
    public = set(seeded)
    unproven = set()
    for line_no in line_numbers:
        statement = statement_at(line_no, 5)
        if fn_decl_re.search(statement):
            signature = statement.split("{", 1)[0]
            for parameter in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:(?!:)", signature):
                name = parameter.group(1)
                unproven.add(name)
                public.discard(name)
        match = assignment_match(statement)
        if match:
            name = match.group("lhs")
            if metadata_literal(name, direct_risky_literal(match.group("rhs"))):
                public.add(name)
            else:
                # This analysis exempts names for a whole scope. Any
                # unproven write revokes that proof regardless of order;
                # a later locator must never hide an earlier secret.
                unproven.add(name)
                public.discard(name)
    return public - unproven


def collect_sensitive_vars(lines, stripped_lines, statement_at, line_numbers, seeded=(),
                           public_metadata=(), ambiguous_seeded=()):
    """Keep known-secret and ambiguous-map provenance separate in one scope.

    Iterated to a fixpoint so alias chains stay order-independent inside the
    scope, exactly as the previous whole-file pass was. The only change is the
    scope: one function body instead of the entire file. A sensitive
    `let auth_token` in one function must not taint an unrelated
    `token == "BR2"` in another.
    """
    sensitive = set(seeded)
    ambiguous = set(ambiguous_seeded)
    for _ in range(4):
        changed = False
        for line_no in line_numbers:
            if has_ignore(lines, line_no):
                continue
            stripped = source_line(stripped_lines, line_no).strip()
            if not stripped:
                continue
            statement = statement_at(line_no, 5)
            if not statement:
                continue
            match = assignment_match(statement)
            if not match:
                continue
            name = match.group("lhs")
            rhs = mask_safe_compare_results(match.group("rhs"))
            identifiers = operand_identifiers(rhs)
            if name not in sensitive and (
                is_sensitive_text(name, public_metadata)
                or is_sensitive_operand_text(rhs, public_metadata)
                or (identifiers & sensitive)
            ):
                sensitive.add(name)
                changed = True
            if name not in ambiguous and (has_ambiguous_signature_lookup(rhs)
                                          or identifiers & ambiguous):
                ambiguous.add(name)
                changed = True
        if not changed:
            break
    return sensitive, ambiguous


def operand_is_sensitive(operand: str, sensitive_vars, public_metadata=()) -> bool:
    if is_sensitive_operand_text(operand, public_metadata):
        return True
    return bool(operand_identifiers(operand) & sensitive_vars)


def secret_compare_severity(statement: str, sensitive_vars, ambiguous_vars,
                            public_metadata=(), verification=False, comparison_limit=None) -> str | None:
    if has_suppression_marker(statement, _SUPPRESSION_RULE):
        return None
    severity = None
    for offset, raw_left, raw_right in comparison_operands(statement):
        # Lookahead completes multiline operands; a later line's independent
        # comparison must not also be reported at this line's public condition.
        if comparison_limit is not None and offset >= comparison_limit:
            continue
        raw_left = mask_safe_compare_results(raw_left)
        raw_right = mask_safe_compare_results(raw_right)
        left = clean_operand_text(raw_left)
        right = clean_operand_text(raw_right)
        if operand_is_nullish_or_shape_check(left) or operand_is_nullish_or_shape_check(right):
            continue
        # Cleaning removes trailing parentheses; source lookup recognition
        # needs the original call delimiter, including for direct env macros.
        if is_sensitive_lookup(raw_left) or is_sensitive_lookup(raw_right):
            return "critical"
        if operand_is_sensitive(left, sensitive_vars, public_metadata) or operand_is_sensitive(right, sensitive_vars, public_metadata):
            return "critical"
        if (has_ambiguous_signature_lookup(raw_left)
                or has_ambiguous_signature_lookup(raw_right)
                or operand_identifiers(left) & ambiguous_vars
                or operand_identifiers(right) & ambiguous_vars):
            if verification:
                return "critical"
            # Keep inspecting later clauses: a known secret must dominate a
            # merely ambiguous signature comparison on the same source line.
            severity = "warning"
    return severity


def classified_comparisons(text: str) -> list[tuple[int, str, str]]:
    """Return source sites and evidence-based severity for one immutable file."""
    if "==" not in text and "!=" not in text:
        return []
    lines = text.splitlines()
    # These values depend only on this file's immutable text. Reuse them across
    # scope discovery, the four taint passes, and comparison lookahead without
    # retaining file contents between scans. Raw lines still own suppression
    # and displayed source text.
    stripped_lines = [strip_line_comments(line) for line in lines]
    structural_lines = strip_comments_and_strings(text, "rust").splitlines()

    @cache
    def statement_at(line_no, max_lines):
        return statement_from(stripped_lines, line_no, max_lines)

    owner, function_names = function_owner_by_line(structural_lines)
    scopes = {}
    for line_no in range(1, len(lines) + 1):
        scopes.setdefault(owner[line_no], []).append(line_no)
    # Module-scope taint (a `static API_SECRET`, a `const HMAC_KEY`) seeds every
    # function; a function's own locals stay inside it.
    module_public = collect_public_metadata_vars(statement_at, scopes.get(0, ()))
    module_sensitive, module_ambiguous = collect_sensitive_vars(
        lines, stripped_lines, statement_at, scopes.get(0, ()), public_metadata=module_public)
    found: list[tuple[int, str, str]] = []
    seen: set[int] = set()
    for scope_id, scope_lines in scopes.items():
        public_metadata = (module_public if scope_id == 0 else
                           collect_public_metadata_vars(statement_at, scope_lines, module_public))
        sensitive_vars, ambiguous_vars = (
            (module_sensitive, module_ambiguous)
            if scope_id == 0
            else collect_sensitive_vars(lines, stripped_lines, statement_at, scope_lines, module_sensitive,
                                        public_metadata, module_ambiguous)
        )
        verification = bool(scope_id) and verification_context(
            function_names[scope_id], structural_lines, scope_lines)
        for line_no in scope_lines:
            if has_ignore(lines, line_no, _SUPPRESSION_RULE):
                continue
            stripped = source_line(stripped_lines, line_no).strip()
            if not stripped or ("==" not in stripped and "!=" not in stripped):
                continue
            statement = statement_at(line_no, 8)
            declarations = list(fn_decl_re.finditer(structural_lines[line_no - 1]))
            # A line can contain comparisons in multiple function bodies.
            # Its one finding conservatively retains any explicit auth name;
            # this evidence does not carry into unrelated following lines.
            line_verification = verification or (
                len(declarations) > 1 and verification_context(
                    " ".join(declaration.group("name") for declaration in declarations), (), ()))
            severity = secret_compare_severity(statement, sensitive_vars, ambiguous_vars,
                                               public_metadata, line_verification,
                                               comparison_limit=len(stripped.strip())) if statement else None
            if severity is None:
                continue
            if line_no in seen:
                continue
            seen.add(line_no)
            found.append((line_no, source_line(lines, line_no), severity))
    found.sort(key=lambda item: item[0])
    return found


def scan_file(text: str) -> list[tuple[int, str]]:
    """Return source sites for callers that do not render finding severities."""
    return [(line, code) for line, code, _severity in classified_comparisons(text)]


def collect_issues(root: Path) -> list[tuple[Path, int, str]]:
    issues: list[tuple[Path, int, str]] = []
    for rust_file in rust_files(root):
        try:
            text = rust_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, code in scan_file(text):
            issues.append((rust_file, line_no, code))
    return issues


def main() -> int:
    root = Path(sys.argv[1])
    for path, line_no, code in collect_issues(root):
        print(f"{path}:{line_no}:{code}")
    return 0


_RULE = "rust.ctcompare.secret_compare"
_MESSAGE = (
    "Secret, signature, or token compared with ==/!= "
    "(non-constant-time comparison; use subtle::ConstantTimeEq, "
    "ring::constant_time::verify_slices_are_equal, or crypto_memcmp)"
)
_REVIEW_MESSAGE = (
    "Signature map value compared with ==/!=; review whether it authenticates a request. "
    "A bare sig/signature key may also identify a public transaction. "
    "Use constant-time comparison when the value is authentication material."
)


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix != ".rs":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for line_no, _code, severity in classified_comparisons(text):
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line_no,
                "col": 1,
                "layer": "ctcompare",
                "lang": "rust",
                "severity": severity,
                "message": _MESSAGE if severity == "critical" else _REVIEW_MESSAGE,
            }


_POSITIVE = """fn verify(provided: &str) -> bool {
    let server_secret = load_secret();
    server_secret == provided
}
"""

_SAFE = """fn verify(provided: &str) -> bool {
    let server_secret = load_secret();
    server_secret.ct_eq(provided.as_bytes()).into()
}
"""


def _selftest_flags_unsafe_compare() -> None:
    findings = scan_file(_POSITIVE)
    assert findings == [(3, "server_secret == provided")], findings


def _selftest_safe_compare_suppressed() -> None:
    assert scan_file(_SAFE) == [], scan_file(_SAFE)


def _selftest_run(tmp_prefix: str = "ubs_core_ctcompare_rust_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "handler.rs"
        target.write_text(_POSITIVE, encoding="utf-8")
        findings = list(run(RunContext(lang="rust", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "rust.ctcompare.secret_compare"
    assert findings[0]["line"] == 3
    assert findings[0]["severity"] == "critical"


def _selftest_function_scope_untainted() -> None:
    fn_scoped = """
use subtle::ConstantTimeEq;
pub fn verify_reset_link(auth_token: &str, expected: &str) -> bool {
    let issue = auth_token;
    issue.as_bytes().ct_eq(expected.as_bytes()).into()
}
pub fn is_tracked_issue_kind(issue: &str) -> bool {
    issue == "bug"
}
"""
    assert scan_file(fn_scoped) == [], scan_file(fn_scoped)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("flags_unsafe_compare", _selftest_flags_unsafe_compare),
    ("safe_compare_suppressed", _selftest_safe_compare_suppressed),
    ("function_scope_untainted", _selftest_function_scope_untainted),
    ("run_finds_secret_compare", _selftest_run),
)

register(Analyzer(layer="ctcompare", lang="rust", name="ctcompare_rust", run=run, selftests=SELF_TESTS))
