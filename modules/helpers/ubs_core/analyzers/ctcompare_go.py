"""ubs_core.analyzers.ctcompare_go — constant-time secret-compare analysis for Go (bead A2).

Logic moved verbatim from the run_constant_time_compare_checks heredoc in
modules/ubs-golang.sh (modules/ubs-golang.sh:~6087), which keeps its own copy
until that module's port bead lands (transitional duplication is sanctioned).
Also exposes a structured `run(ctx)` for the `python3 -m ubs_core` CLI.
`main()` reproduces the heredoc emit dialect exactly: one `__COUNT__\t<n>`
line followed by up to 25 `__SAMPLE__\tpath\tline\tcode` rows.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {'.git', 'vendor', 'node_modules', '.cache', 'bin', 'build', 'dist'}

COMPARE_RE = re.compile(r'(?<![=!<>])(?P<left>.+?)\s*(?P<op>==|!=)\s*(?!=)\s*(?P<right>.+)')
ASSIGN_RE = re.compile(r'^\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>.+)$')
IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
SAFE_COMPARE_RE = re.compile(
    r'\b(?:hmac\.Equal|subtle\.ConstantTimeCompare|subtle\.ConstantTimeEq)\s*\('
    r'|\b(?:constantTimeEqual|constantTimeCompare|timingSafeEqual|timingSafeCompare|'
    r'safeEqual|safeCompare|secureCompare)\s*\(',
    re.IGNORECASE,
)
# GH #85 two-tier vocabulary (same sets as the Rust module). Strong terms are
# security-sensitive on their own unless the very next identifier term is
# schema/metadata vocabulary (signatureFormat, credentialType, jwtHeader).
# Weak terms (token, key, digest, nonce, session, mac, ...) are ordinary
# parser/domain vocabulary and only become sensitive next to a security
# qualifier (authToken, apiKey, sessionToken, webhookSignature), so a bare
# parser `token == "PAGE_BREAK"` is no longer a secret comparison.
STRONG_TERMS = {
    'secret', 'password', 'passwd', 'pwd', 'bearer', 'hmac', 'csrf', 'xsrf',
    'otp', 'totp', 'mfa', 'signature', 'sig', 'credential', 'credentials',
    'authorization', 'jwt',
}
WEAK_TERMS = {
    'token', 'key', 'mac', 'digest', 'nonce', 'session', 'auth', 'reset',
    'webhook', 'invite', 'verification', 'recovery',
}
QUALIFIER_TERMS = {
    'api', 'auth', 'access', 'refresh', 'session', 'reset', 'recovery',
    'verification', 'invite', 'jwt', 'csrf', 'xsrf', 'webhook', 'hmac',
    'bearer', 'secret', 'signing', 'signature', 'private', 'otp', 'totp',
    'mfa', 'password', 'passwd', 'pwd', 'credential', 'credentials',
}
METADATA_TERMS = {
    'field', 'format', 'kind', 'layout', 'policy', 'schema', 'state',
    'status', 'type', 'mode', 'scheme', 'parser', 'alg', 'algorithm',
    'aud', 'audience', 'claim', 'claims', 'exp', 'expiration', 'header',
    'headers', 'issuer', 'iss', 'kid', 'name', 'label', 'id', 'index',
    'count', 'len', 'length',
}
NULLISH_RE = re.compile(r'^(?:nil|true|false|0|1|""|``)$')
SHAPE_RE = re.compile(r'\b(?:len|cap)\s*\(|\.(?:Len|Size)\s*\(')
PURE_STRING_LITERAL_RE = re.compile(r'^\s*(?:"(?:\\.|[^"\\])*"|`[^`]*`)\s*$')
JWT_METHOD_COMPARE_RE = re.compile(
    r'\bSigningMethod[A-Za-z0-9_]*\b.*?(?:\b[A-Za-z_][A-Za-z0-9_]*\.Method\b|\.Alg\s*\()|'
    r'(?:\b[A-Za-z_][A-Za-z0-9_]*\.Method\b|\.Alg\s*\().*?\bSigningMethod[A-Za-z0-9_]*\b'
)
KEYWORDS = {
    'if', 'for', 'switch', 'case', 'return', 'var', 'const', 'func',
    'true', 'false', 'nil', 'range', 'go', 'defer',
}


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() == '.go':
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() == '.go' and not should_skip(path):
                yield path


def relpath(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except ValueError:
        return str(path)


def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    idx = 0
    while idx < len(line):
        ch = line[idx]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            idx += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            idx += 1
            continue
        if ch == '/' and idx + 1 < len(line):
            nxt = line[idx + 1]
            if nxt == '/':
                break
            if nxt == '*':
                end = line.find('*/', idx + 2)
                if end == -1:
                    break
                idx = end + 2
                continue
        out.append(ch)
        idx += 1
    return ''.join(out)


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def statement_from(lines, line_no, max_lines=8):
    idx = line_no - 1
    parts = []
    balance = 0
    for current_idx in range(idx, min(len(lines), idx + max_lines)):
        current = strip_line_comments(lines[current_idx]).strip()
        if not current:
            if parts and balance <= 0:
                break
            continue
        parts.append(current)
        balance += current.count('(') + current.count('{') - current.count(')') - current.count('}')
        if current_idx > idx and balance <= 0:
            break
        if current_idx == idx and balance <= 0 and not current.endswith(('{', '(', ',')):
            break
    return ' '.join(parts)


def split_identifier_terms(text: str) -> str:
    text = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', text)
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', text)
    text = re.sub(r'[_\-.]+', ' ', text)
    return text


def strip_string_contents(text: str) -> str:
    # Blank out the CONTENTS of "..." and `...` string literals while keeping the
    # surrounding quotes, so the expression's structure (identifiers, calls, fields)
    # survives but a sensitive-looking word that lives only inside string data does
    # not contribute to sensitivity. A title/label/UI-text field like
    # `Model{title: "Auth Login Flow"}` must not taint the variable it is assigned to.
    out = []
    idx = 0
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch == '"':
            out.append('"')
            idx += 1
            while idx < n and text[idx] != '"':
                if text[idx] == '\\' and idx + 1 < n:
                    idx += 2
                    continue
                idx += 1
            if idx < n:
                idx += 1
            out.append('"')
        elif ch == '`':
            out.append('`')
            idx += 1
            while idx < n and text[idx] != '`':
                idx += 1
            if idx < n:
                idx += 1
            out.append('`')
        else:
            out.append(ch)
            idx += 1
    return ''.join(out)


def is_sensitive_text(text: str) -> bool:
    terms = re.findall(r'[a-z0-9]+', split_identifier_terms(text).lower())
    for idx, term in enumerate(terms):
        if term in STRONG_TERMS:
            follower = terms[idx + 1] if idx + 1 < len(terms) else ''
            if follower not in METADATA_TERMS:
                return True
            continue
        if term in WEAK_TERMS and any(
            other_idx != idx and other in QUALIFIER_TERMS
            for other_idx, other in enumerate(terms)
        ):
            return True
    return False


def is_sensitive_operand_text(text: str) -> bool:
    stripped = text.strip()
    if PURE_STRING_LITERAL_RE.match(stripped):
        return False
    return is_sensitive_text(stripped)


def lhs_names(lhs: str):
    names = []
    for part in lhs.split(','):
        name = part.strip()
        if name and name != '_' and IDENT_RE.fullmatch(name):
            names.append(name)
    return names


def operand_identifiers(operand: str):
    return {
        token
        for token in IDENT_RE.findall(operand)
        if token not in KEYWORDS
    }


def clean_operand_text(operand: str) -> str:
    clean = operand.strip()
    clean = re.sub(r'^(?:if|for|switch|case)\s*\(?\s*', '', clean)
    clean = re.split(r'\s*(?:&&|\|\||[;{])', clean, maxsplit=1)[0].strip()
    while clean and clean[-1] in ';{}){':
        clean = clean[:-1].strip()
    return clean


def operand_is_nullish_or_shape_check(operand: str) -> bool:
    clean = clean_operand_text(operand)
    if NULLISH_RE.match(clean):
        return True
    if SHAPE_RE.search(clean):
        return True
    if re.match(r'^[0-9]+(?:\.[0-9]+)?$', clean):
        return True
    return False


def is_jwt_signing_method_check(left: str, right: str) -> bool:
    return bool(JWT_METHOD_COMPARE_RE.search(f'{left} {right}'))


def collect_sensitive_vars(lines):
    sensitive = set()
    for idx, raw in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        stripped = strip_line_comments(raw).strip()
        if not stripped:
            continue
        statement = statement_from(lines, idx, max_lines=5)
        if not statement or SAFE_COMPARE_RE.search(statement):
            continue
        match = ASSIGN_RE.match(statement)
        if not match:
            continue
        rhs = match.group('rhs')
        # Only let the RHS taint the assigned variable name when its sensitivity comes
        # from code (identifiers, fields, calls), not from data living inside a string
        # literal. Otherwise a fixture like `Model{title: "Auth Login Flow"}` taints a
        # common local name (e.g. `m`) for the whole file, flagging unrelated ==/!=
        # assertions elsewhere as secret comparisons.
        rhs_code = strip_string_contents(rhs)
        rhs_sensitive = is_sensitive_operand_text(rhs_code) or bool(operand_identifiers(rhs_code) & sensitive)
        for name in lhs_names(match.group('lhs')):
            if is_sensitive_text(name) or rhs_sensitive:
                sensitive.add(name)
    return sensitive


def operand_is_sensitive(operand: str, sensitive_vars) -> bool:
    if is_sensitive_operand_text(operand):
        return True
    return bool(operand_identifiers(operand) & sensitive_vars)


def unsafe_secret_compare(statement: str, sensitive_vars) -> bool:
    if SAFE_COMPARE_RE.search(statement) or 'ubs:ignore' in statement:
        return False
    for clause in re.split(r'\s*(?:&&|\|\|)\s*', statement):
        match = COMPARE_RE.search(clause)
        if not match:
            continue
        left = clean_operand_text(match.group('left'))
        right = clean_operand_text(match.group('right'))
        if is_jwt_signing_method_check(left, right):
            continue
        if operand_is_nullish_or_shape_check(left) or operand_is_nullish_or_shape_check(right):
            continue
        if operand_is_sensitive(left, sensitive_vars) or operand_is_sensitive(right, sensitive_vars):
            return True
    return False


def scan_file(path: Path, base_dir: Path) -> list[tuple[str, int, str]]:
    """Per-file body of the heredoc walk: [(rel_path, line, code_text), ...]."""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    if '==' not in text and '!=' not in text:
        return []
    lines = text.splitlines()
    sensitive_vars = collect_sensitive_vars(lines)
    issues: list[tuple[str, int, str]] = []
    seen = set()
    for idx, raw in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        stripped = strip_line_comments(raw).strip()
        if not stripped or ('==' not in stripped and '!=' not in stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or not unsafe_secret_compare(statement, sensitive_vars):
            continue
        key = (relpath(path, base_dir), idx)
        if key in seen:
            continue
        seen.add(key)
        issues.append((relpath(path, base_dir), idx, source_line(lines, idx)))
    return issues


def collect_issues(root: Path) -> list[tuple[str, int, str]]:
    base_dir = root if root.is_dir() else root.parent
    issues: list[tuple[str, int, str]] = []
    for path in iter_files(root):
        issues.extend(scan_file(path, base_dir))
    return issues


def main() -> int:
    if len(sys.argv) < 2:
        print('usage: ctcompare_go <project_dir>', file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    issues = collect_issues(root)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_KIND = "unsafe_secret_compare"
_MESSAGE = "Secret, signature, or token compared with ==/!= without timing-safe equality"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() != '.go':
            continue
        try:
            issues = scan_file(path, cwd)
        except OSError:
            continue
        for rel, line_no, _code in issues:
            yield {
                "rule": f"go.ctcompare.{_KIND}",
                "path": rel,
                "line": line_no,
                "col": 1,
                "layer": "ctcompare",
                "lang": "go",
                "severity": "critical",
                "message": _MESSAGE,
            }


_POSITIVE_SRC = (
    "package auth\n"
    "\n"
    "func CheckSession(sessionToken string, expected string) bool {\n"
    "\treturn sessionToken == expected\n"
    "}\n"
)


def _selftest_positive() -> None:
    lines = _POSITIVE_SRC.splitlines()
    statement = statement_from(lines, 4)
    assert unsafe_secret_compare(statement, collect_sensitive_vars(lines)), statement


def _selftest_ubs_ignore_suppression() -> None:
    lines = [
        "package auth",
        "",
        "func CheckSession(sessionToken string, expected string) bool {",
        "\treturn sessionToken == expected // ubs:ignore",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_go_") as tmp:
        target = Path(tmp) / "suppressed.go"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_timing_safe_negative() -> None:
    lines = [
        "package auth",
        "",
        "import (",
        '\t"crypto/hmac"',
        '\t"crypto/subtle"',
        ")",
        "",
        "func Equal(a, b []byte) bool {",
        "\treturn subtle.ConstantTimeCompare(a, b) != 0",
        "}",
        "",
        "func TokensMatch(x, y []byte) bool {",
        "\treturn hmac.Equal(x, y)",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_go_") as tmp:
        target = Path(tmp) / "safe.go"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_bare_token_negative() -> None:
    # GH #85: a bare parser/domain `token` without a security qualifier is not
    # a secret, so `token == next` must not be flagged.
    lines = [
        "package parser",
        "",
        "func advance(token string, next string) bool {",
        "\tif token == next {",
        "\t\treturn true",
        "\t}",
        "\treturn false",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_go_") as tmp:
        target = Path(tmp) / "parser.go"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_run(tmp_prefix: str = "ubs_core_ctcompare_go_") -> None:
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.go"
        target.write_text(_POSITIVE_SRC, encoding="utf-8")
        findings = list(run(RunContext(lang="go", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "go.ctcompare.unsafe_secret_compare"
    assert findings[0]["line"] == 4
    assert findings[0]["severity"] == "critical"


def _selftest_main_dialect(tmp_prefix: str = "ubs_core_ctcompare_go_") -> None:
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.go"
        target.write_text(_POSITIVE_SRC, encoding="utf-8")
        buffer = io.StringIO()
        old_argv = sys.argv
        sys.argv = ["ctcompare_go", tmp]
        try:
            with contextlib.redirect_stdout(buffer):
                assert main() == 0
        finally:
            sys.argv = old_argv
    lines_out = buffer.getvalue().splitlines()
    assert lines_out[0] == "__COUNT__\t1", lines_out
    assert lines_out[1].startswith("__SAMPLE__\tleaky.go\t4\t"), lines_out


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("positive_detects_secret_compare", _selftest_positive),
    ("ubs_ignore_suppresses", _selftest_ubs_ignore_suppression),
    ("timing_safe_equal_negative", _selftest_timing_safe_negative),
    ("bare_token_negative", _selftest_bare_token_negative),
    ("run_finds_unsafe_compares", _selftest_run),
    ("main_reproduces_count_dialect", _selftest_main_dialect),
)

register(Analyzer(layer="ctcompare", lang="go", name="ctcompare_go", run=run, selftests=SELF_TESTS))
