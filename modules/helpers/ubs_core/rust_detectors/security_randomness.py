"""ubs_core.rust_detectors.security_randomness — non-crypto randomness in security context (bead 0xjg.7).

Port of rust_security_randomness_matches (modules/ubs-rust.sh 5540-5857;
counted by count_security_randomness_matches at 5859): flags security-
sensitive generation statements (token/session/cookie/csrf/otp/salt/
password/auth/... names, or a security-flavored enclosing function) that
draw from non-cryptographic sources — ``rand::random``, ``thread_rng()``/
``rng()`` method chains, seeded ``StdRng``/``SmallRng``/``Pcg*``/``XorShiftRng``/
``ChaCha*Rng``/``WyRand`` constructors, ``fastrand``/``nanorand`` — or
predictable seeds (``SystemTime::now``, ``Instant::now``, ``process::id``,
``.finish()``) when the statement is sensitive. ``OsRng``/``getrandom``/
``ring::rand``/``aws_lc_rs``/``openssl::rand``/``Uuid::new_v4`` mark a
variable safe; string literals are masked before matching and ``//``
comments stripped; a statement is accumulated over up to 10 lookahead
lines until parens balance. A line is suppressed when its own line or the
previous line carries ``ubs:ignore``. Findings dedupe per
(file, line, matched source) and keep file order.

The legacy UBS_RUST_FILE_LIST branch yielded entries unresolved and
printed them as-is; ``find(files)`` therefore iterates the entries
unchanged (no resolve, no re-walk). The legacy rglob/skip_dirs fallback
is documentation-only: the orchestrator passes the already-filtered list.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator, Sequence

MARKER = "ubs:ignore"

RULE_ID = "rust.security.non-crypto-random"
CATEGORY = 8
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = (
    "Use OsRng/getrandom/ring::rand/openssl::rand or a framework helper "
    "backed by OS cryptographic randomness for tokens, sessions, CSRF "
    "nonces, OTPs, salts, API keys, and secrets"
)

# Documentation only: legacy rglob fallback's skip list. The orchestrator
# passes the already-filtered file list, so this is never applied.
skip_dirs = {".git", "target", ".cargo", "node_modules"}
rng_methods = (
    "gen", "gen_range", "gen_bool", "gen_ratio", "random", "random_range",
    "random_bool", "fill", "fill_bytes", "next_u32", "next_u64", "sample",
    "sample_iter",
)
security_terms = (
    "apikey", "accesskey", "privatekey", "publickey", "clientsecret",
    "secret", "token", "session", "cookie", "csrf", "xsrf", "otp", "totp",
    "mfa", "nonce", "salt", "password", "passwd", "pwd", "auth", "bearer",
    "credential", "reset", "invite", "verification", "verify", "confirm",
    "confirmation", "magiclink", "recovery", "signature",
)

assign_re = re.compile(
    r"^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?"
    r"(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)"
)
fn_re = re.compile(
    r"^\s*(?:(?:pub|pub\s*\([^)]*\)|async|unsafe|extern\s+\"[^\"]+\")\s+)*"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{}]+>)?\s*\("
)
safe_random_re = re.compile(
    r"\b(?:rand_core::)?OsRng\b"
    r"|\bgetrandom(?:::getrandom|::fill)?\s*\("
    r"|\bring::rand::(?:SystemRandom|generate)\b"
    r"|\baws_lc_rs::rand::(?:SystemRandom|generate)\b"
    r"|\bopenssl::rand::rand_bytes\s*\("
    r"|\b(?:uuid::)?Uuid::new_v4\s*\(",
)
unsafe_rng_init_re = re.compile(
    r"\b(?:rand\s*::\s*)?(?:thread_rng|rng)\s*\("
    r"|\b(?:rand\s*::\s*rngs\s*::\s*)?(?:StdRng|SmallRng)\s*::\s*(?:seed_from_u64|from_seed|from_rng|from_entropy)\s*\("
    r"|\b(?:Pcg[A-Za-z0-9_]*|XorShiftRng|ChaCha[0-9]*Rng|WyRng|WyRand)\s*::\s*(?:seed_from_u64|from_seed|from_rng|new)\s*\(",
)
direct_unsafe_re = re.compile(
    r"\brand\s*::\s*random\s*(?:::<[^>]+>)?\s*\("
    r"|\brandom\s*::<[^>]+>\s*\("
    r"|\b(?:rand\s*::\s*)?(?:thread_rng|rng)\s*\(\s*\)\s*\.\s*(?:"
    + "|".join(rng_methods)
    + r")\s*(?:::<[^>]+>)?\s*\("
    r"|\bfastrand\s*::\s*(?:u8|u16|u32|u64|usize|i8|i16|i32|i64|isize|bool|alphanumeric|bytes|fill|shuffle|choice)\s*\("
    r"|\bnanorand\s*::",
)
predictable_source_re = re.compile(
    r"\b(?:std\s*::\s*time\s*::\s*)?SystemTime\s*::\s*now\s*\("
    r"|\b(?:std\s*::\s*time\s*::\s*)?Instant\s*::\s*now\s*\("
    r"|\b(?:std\s*::\s*)?process\s*::\s*id\s*\("
    r"|\.finish\s*\(\s*\)",
)


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


def without_string_literals(expr: str) -> str:
    chars = list(expr)
    i = 0
    quote = ""
    raw_hashes = None
    escape = False
    while i < len(chars):
        ch = chars[i]
        if raw_hashes is not None:
            chars[i] = " "
            if ch == '"' and expr.startswith("#" * raw_hashes, i + 1):
                for pos in range(i + 1, min(i + 1 + raw_hashes, len(chars))):
                    chars[pos] = " "
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            chars[i] = " "
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
                for pos in range(i, j + 1):
                    chars[pos] = " "
                raw_hashes = j - i - 1
                i = j + 1
                continue
        if ch == '"':
            chars[i] = " "
            quote = ch
        i += 1
    return "".join(chars)


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren = statement.count("(") - statement.count(")")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (paren > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        paren += nxt.count("(") - nxt.count(")")
        has_end = has_end or ";" in nxt or "{" in nxt or "}" in nxt
        lookahead += 1
    return statement


def normalized(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def has_security_context(statement: str, fn_name: str) -> bool:
    visible = without_string_literals(f"{statement} {fn_name or ''}")
    compact = normalized(visible)
    if any(term in compact for term in security_terms):
        return True
    return bool(re.search(r"(?<![A-Za-z0-9_])(?:key|sig)(?![A-Za-z0-9_])", visible, re.IGNORECASE))


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def rng_method_pattern(name: str) -> re.Pattern:
    return re.compile(rf"\b{re.escape(name)}\.(?:{'|'.join(rng_methods)})\s*(?:::<[^>]+>)?\s*\(")


def starts_function(statement: str):
    match = fn_re.match(statement)
    return match.group("name") if match else None


def update_insecure_rng_vars(statement: str, insecure_rng_vars):
    assign = assign_re.match(statement)
    if not assign:
        return
    name = assign.group("lhs")
    rhs = without_string_literals(assign.group("rhs"))
    if safe_random_re.search(rhs):
        insecure_rng_vars.discard(name)
        return
    if unsafe_rng_init_re.search(rhs):
        insecure_rng_vars.add(name)


def unsafe_source(statement: str, insecure_rng_vars, sensitive: bool):
    visible = without_string_literals(statement)
    direct = direct_unsafe_re.search(visible)
    if direct:
        return direct.group(0).strip()
    for name in sorted(insecure_rng_vars):
        match = rng_method_pattern(name).search(visible)
        if match:
            return match.group(0).strip()
    predictable = predictable_source_re.search(visible)
    if predictable and sensitive:
        return predictable.group(0).strip()
    return None


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not any(token in text for token in (
        "rand", "thread_rng", "fastrand", "nanorand", "StdRng", "SmallRng",
        "SystemTime::now", "Instant::now", "process::id", "DefaultHasher",
    )):
        return
    lines = text.splitlines()
    insecure_rng_vars = set()
    function_stack = []
    pending_function = ""
    brace_depth = 0
    seen = set()
    for line_no, raw in enumerate(lines, start=1):
        raw_statement = strip_line_comments(raw).strip()
        visible_line = without_string_literals(raw_statement)
        while function_stack and brace_depth < function_stack[-1][1]:
            function_stack.pop()
        function_name = starts_function(visible_line)
        opens = visible_line.count("{")
        closes = visible_line.count("}")
        if function_name:
            if opens > 0:
                function_stack.append((function_name, brace_depth + opens))
                pending_function = ""
            elif ";" in visible_line:
                pending_function = ""
            else:
                pending_function = function_name
        elif pending_function and opens > 0:
            function_stack.append((pending_function, brace_depth + opens))
            pending_function = ""
        current_function = function_name or (function_stack[-1][0] if function_stack else "")
        if has_ignore(lines, line_no) or not raw_statement:
            brace_depth += opens - closes
            continue
        statement = logical_statement(lines, line_no)
        update_insecure_rng_vars(statement, insecure_rng_vars)
        line_sensitive = has_security_context(statement, "")
        sensitive = line_sensitive or has_security_context("", current_function)
        source = unsafe_source(statement, insecure_rng_vars, sensitive)
        if source and sensitive:
            key = (str(path), line_no, source)
            if key not in seen:
                seen.add(key)
                issues.append((path, line_no, 1, f"{source_line(lines, line_no)}  [{source} in security-sensitive generation context]"))
        brace_depth += opens - closes


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy finding, in legacy order."""
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        entry = Path(path)
        if entry.suffix == ".rs":
            analyze(entry, issues)
    yield from issues


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for found_path, line, col, code in find(root_files):
        print(f"{found_path}:{line}:{code}")
