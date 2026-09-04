"""ubs_core.analyzers.ctcompare_rust — non-constant-time secret comparisons (bead A2).

Logic moved verbatim from the rust_constant_time_compare_matches heredoc in
modules/ubs-rust.sh (python3 - "$PROJECT_DIR" <<'PY', body lines 5902-6200),
which keeps its copy until the rust module's port bead. main() reproduces the
heredoc's `path:line:code` stdout exactly; run(ctx) exposes the same detection
as structured findings for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

skip_dirs = {".git", "target", ".cargo", "node_modules"}

compare_re = re.compile(r"(?<![=!<>])(?P<left>.+?)\s*(?P<op>==|!=)\s*(?!=)\s*(?P<right>.+)")
assign_re = re.compile(
    r"^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?"
    r"(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)"
)
identifier_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
safe_compare_re = re.compile(
    r"\b(?:subtle::)?ConstantTimeEq\b"
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
    "count", "len", "length",
}
nullish_re = re.compile(r'^(?:None|Some\s*\([^)]*\)|Ok\s*\([^)]*\)|Err\s*\([^)]*\)|true|false|0|1|""|b""|\[\])$')
shape_re = re.compile(r"\b(?:len|is_empty|capacity)\s*\(|\.(?:len|is_empty|capacity)\s*\(")
pure_string_literal_re = re.compile(r'^\s*(?:"(?:\\.|[^"\\])*"|r#*"[^"]*"#*|b"(?:\\.|[^"\\])*")\s*$')
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


def statement_from(lines, line_no, max_lines=8):
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


def split_identifier_terms(text: str) -> str:
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"[_\-.]+", " ", text)
    return text


def is_sensitive_text(text: str) -> bool:
    terms = re.findall(r"[a-z0-9]+", split_identifier_terms(text).lower())
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


def is_sensitive_operand_text(text: str) -> bool:
    stripped = text.strip()
    if pure_string_literal_re.match(stripped):
        return False
    return is_sensitive_text(stripped)


def operand_identifiers(operand: str):
    return {
        token
        for token in identifier_re.findall(operand)
        if token not in keywords
    }


def clean_operand_text(operand: str) -> str:
    clean = operand.strip()
    clean = re.sub(r"^(?:if|while|match)\s*\(?\s*", "", clean)
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


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and "ubs:ignore" in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and "ubs:ignore" in lines[idx - 1]
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def collect_sensitive_vars(lines):
    sensitive = set()
    for line_no, raw in enumerate(lines, start=1):
        if has_ignore(lines, line_no):
            continue
        stripped = strip_line_comments(raw).strip()
        if not stripped:
            continue
        statement = statement_from(lines, line_no, max_lines=5)
        if not statement or safe_compare_re.search(statement):
            continue
        match = assign_re.match(statement)
        if not match:
            continue
        name = match.group("lhs")
        rhs = match.group("rhs")
        if is_sensitive_text(name) or is_sensitive_operand_text(rhs) or (operand_identifiers(rhs) & sensitive):
            sensitive.add(name)
    return sensitive


def operand_is_sensitive(operand: str, sensitive_vars) -> bool:
    if is_sensitive_operand_text(operand):
        return True
    return bool(operand_identifiers(operand) & sensitive_vars)


def unsafe_secret_compare(statement: str, sensitive_vars) -> bool:
    if safe_compare_re.search(statement) or "ubs:ignore" in statement:
        return False
    for clause in re.split(r"\s*(?:&&|\|\|)\s*", statement):
        match = compare_re.search(clause)
        if not match:
            continue
        left = clean_operand_text(match.group("left"))
        right = clean_operand_text(match.group("right"))
        if operand_is_nullish_or_shape_check(left) or operand_is_nullish_or_shape_check(right):
            continue
        if operand_is_sensitive(left, sensitive_vars) or operand_is_sensitive(right, sensitive_vars):
            return True
    return False


def scan_file(text: str) -> list[tuple[int, str]]:
    """Return (line_no, source_code) findings for one file's text."""
    if "==" not in text and "!=" not in text:
        return []
    lines = text.splitlines()
    sensitive_vars = collect_sensitive_vars(lines)
    found: list[tuple[int, str]] = []
    seen: set[int] = set()
    for line_no, raw in enumerate(lines, start=1):
        if has_ignore(lines, line_no):
            continue
        stripped = strip_line_comments(raw).strip()
        if not stripped or ("==" not in stripped and "!=" not in stripped):
            continue
        statement = statement_from(lines, line_no)
        if not statement or not unsafe_secret_compare(statement, sensitive_vars):
            continue
        if line_no in seen:
            continue
        seen.add(line_no)
        found.append((line_no, source_line(lines, line_no)))
    return found


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
        for line_no, _code in scan_file(text):
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line_no,
                "col": 1,
                "layer": "ctcompare",
                "lang": "rust",
                "severity": "critical",
                "message": _MESSAGE,
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


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("flags_unsafe_compare", _selftest_flags_unsafe_compare),
    ("safe_compare_suppressed", _selftest_safe_compare_suppressed),
    ("run_finds_secret_compare", _selftest_run),
)

register(Analyzer(layer="ctcompare", lang="rust", name="ctcompare_rust", run=run, selftests=SELF_TESTS))
