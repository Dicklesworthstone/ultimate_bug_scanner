"""ubs_core.analyzers.ctcompare_js — constant-time secret-compare analysis for JS/TS (bead A2).

Logic moved verbatim from the ctcompare heredoc in modules/ubs-js.sh, which keeps
its own copy until that module's port bead lands (transitional duplication is
sanctioned). Also exposes a structured `run(ctx)` for the `python3 -m ubs_core`
CLI. `main(argv)` reproduces the heredoc emit dialect exactly: first stdout line
is the finding count, followed by up to 25 `path\tline\tcode` sample rows.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

exts = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

compare_re = re.compile(r'(?<![=!<>])(?P<left>.+?)\s*(?P<op>===|!==|==|!=)\s*(?P<right>.+)')
assignment_re = re.compile(r'\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<expr>.+)')
loose_assignment_re = re.compile(r'\b(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?!=)(?P<expr>.+)')
identifier_re = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')
safe_compare_re = re.compile(
    r'\b(?:crypto\.)?(?:timingSafeEqual|safeEqual|safeCompare|constantTimeEqual|compareDigest|verifyWebhookSignature)\s*\('
    r'|\b(?:subtle|crypto\.subtle)\s*\.\s*verify\s*\(',
    re.IGNORECASE,
)
# Map each weak sensitive term to a *concept family*.  Synonyms that name the
# same kind of secret share a family, so a real self-comparison like
# `req.headers.authorization === expectedToken` (authorization vs token, both
# bearer-auth credentials) still counts as "same concept on both sides", while
# `doneToken !== sessionNonce` (a bearer token vs an unrelated correlation
# nonce) does not.  See issue #61.
# Two-tier identifier vocabulary (GH #85; identical to the Python and Go
# modules).  A STRONG term names a secret on its own (password, hmac, csrf...)
# unless the very next term is METADATA (tokenType, secretName, keyId).  A WEAK
# term (token, key, session, nonce...) only counts when the SAME identifier also
# carries a QUALIFIER (authToken, api_key, sessionSecret): bare `token`, `key`,
# `id` or `nonce` are everyday parser/DB/cache vocabulary and must not taint.
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
# Concept family of each vocabulary term, used to decide whether two
# name-sensitive operands compare the SAME secret (issue #61).
TERM_FAMILY = {
    'token': 'token', 'bearer': 'token', 'jwt': 'token',
    'authorization': 'token', 'auth': 'token',
    'secret': 'secret', 'password': 'secret', 'passwd': 'secret',
    'pwd': 'secret', 'credential': 'secret', 'credentials': 'secret',
    'key': 'key',
    'signature': 'signature', 'sig': 'signature', 'hmac': 'signature',
    'digest': 'signature', 'mac': 'signature',
    'csrf': 'csrf', 'xsrf': 'csrf',
    'otp': 'otp', 'totp': 'otp', 'mfa': 'otp',
    'session': 'session',
    'nonce': 'nonce',
    'reset': 'reset', 'recovery': 'reset',
    'webhook': 'webhook',
    'invite': 'invite',
    'verification': 'verification',
}
term_word_re = re.compile(r'[a-z][a-z0-9]*')
nullish_re = re.compile(r'^(?:null|undefined|true|false|0|1|NaN|Number\.NaN|""|\'\'|``)$')
length_re = re.compile(r'\b(?:length|byteLength|size)\b')
string_literal_re = re.compile(r'''(["'`])(?:\\.|(?!\1).)*?\1''')
keywords = {
    'if', 'return', 'const', 'let', 'var', 'true', 'false', 'null', 'undefined',
    'await', 'async', 'function', 'typeof', 'instanceof', 'new', 'this',
}


def split_identifier_terms(text):
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', text)
    text = re.sub(r'[_\-.]+', ' ', text)
    return text


def strip_string_literals(text):
    # Replace the *contents* of string/template literals with an empty pair of
    # quotes so a sensitive word that only ever appears inside a literal (e.g.
    # an allow-list like `new Set(["completion_token", ...])`) cannot taint a
    # variable name.  This mirrors the Go fix in #54 for the same flat-taint
    # bug class, and kills the "file-wide name taint via literal contents"
    # false positive described in #61.
    return string_literal_re.sub(lambda m: m.group(1) * 2, text)


def identifier_terms(identifier):
    return term_word_re.findall(split_identifier_terms(identifier).lower())


def identifier_is_sensitive(terms):
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


def sensitive_families(text):
    # Concept families implied by the *qualified* identifiers in an operand's
    # code text, string-literal contents stripped first.  Empty => not
    # sensitive.  Each identifier is judged on its own terms, so
    # `req.headers.authorization` is sensitive (STRONG) while `parser.token`
    # and `cache.key` are not (WEAK without a qualifier).
    code = strip_string_literals(text)
    fams = set()
    if re.search(r'\bx\s+signature\b', split_identifier_terms(code).lower()):
        fams.add('signature')
    for ident in identifier_re.findall(code):
        terms = identifier_terms(ident)
        if not identifier_is_sensitive(terms):
            continue
        for word in terms:
            fam = TERM_FAMILY.get(word)
            if fam:
                fams.add(fam)
    return fams


def term_families(text):
    # Every concept family named ANYWHERE in the operand, qualified or not.
    # Not a sensitivity signal on its own; used only to tell whether two
    # name-sensitive operands talk about the SAME secret concept (issue #61):
    # `doneToken !== sessionNonce` is token-vs-nonce, a public correlation
    # check, even though sessionNonce alone is a qualified (sensitive) name.
    norm = split_identifier_terms(strip_string_literals(text)).lower()
    return {TERM_FAMILY[w] for w in term_word_re.findall(norm) if w in TERM_FAMILY}


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
        if ch == '/' and idx + 1 < len(line) and line[idx + 1] == '/':
            break
        out.append(ch)
        idx += 1
    return ''.join(out)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    return re.sub(r'/\*.*?\*/', '', strip_line_comments(source_line))


def statement_from(lines, idx, max_lines=8):
    parts = []
    paren_balance = 0
    brace_balance = 0
    saw_code = False
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = code_line(lines[line_idx]).strip()
        if not current:
            if parts:
                break
            continue
        parts.append(current)
        saw_code = True
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if (';' in current or current.endswith('{')) and paren_balance <= 0 and brace_balance <= 0:
            break
    return ' '.join(parts) if saw_code else ""


def operand_identifiers(operand):
    return {
        token
        for token in identifier_re.findall(operand)
        if token not in keywords
    }


def is_sensitive_text(text):
    return bool(sensitive_families(text))


CONTINUATION_TAIL = ('=', '(', '[', ',', '&&', '||', '?', ':', '+', '=>', '.')
CONTINUATION_HEAD = ('.', '?', ':', ')', ']', '&&', '||', '+', '===', '!==', '==', '!=')


def statement_start(lines, index):
    # Walk upward over physical lines that belong to the same statement as
    # lines[index] (assignment/paren/operator continuations), so a suppression
    # marker placed above a MULTI-LINE statement still attaches to a finding
    # reported against one of its continuation lines. GH #91.
    start = index
    for _ in range(8):
        if start <= 0:
            break
        prev = code_line(lines[start - 1]).strip()
        cur = code_line(lines[start]).strip()
        if not prev:
            break
        if prev.endswith(CONTINUATION_TAIL) or cur.startswith(CONTINUATION_HEAD):
            start -= 1
            continue
        break
    return start


def has_ignore(lines, index):
    # Suppression markers live in comments, so they must be checked against the
    # RAW source line, never against comment-stripped text: code_line() removes
    # '// ubs:ignore' before it could ever match.
    # GH #84: a count-time miss here made suppressed findings still count in
    # totals and the exit code even though the report line was elided.
    # GH #91: honored placements are (a) trailing the flagged line, (b) any
    # physical line of the enclosing multi-line statement, (c) the line
    # immediately above the statement's FIRST line (not just above the flagged
    # continuation line), and (d) a comment-only line directly inside a block
    # opened by the flagged line — formatters commonly relocate a trailing
    # marker off a block-opening `if (...) {` onto the next line, which used to
    # silently detach the suppression.
    if not (0 <= index < len(lines)):
        return False
    if 'ubs:ignore' in lines[index]:
        return True
    start = statement_start(lines, index)
    for pos in range(max(0, start - 1), index):
        if 'ubs:ignore' in lines[pos]:
            return True
    if code_line(lines[index]).rstrip().endswith('{') and index + 1 < len(lines):
        relocated = lines[index + 1].strip()
        if relocated.startswith(('//', '/*', '*')) and 'ubs:ignore' in relocated:
            return True
    return False


def collect_sensitive_vars(lines):
    sensitive_vars = set()
    for idx, raw in enumerate(lines):
        stripped = code_line(raw).strip()
        if not stripped or has_ignore(lines, idx) or '=>' in stripped:
            continue
        statement = statement_from(lines, idx, max_lines=5)
        if not statement or safe_compare_re.search(statement):
            continue
        match = assignment_re.search(statement) or loose_assignment_re.search(statement)
        if not match:
            continue
        name = match.group('name')
        expr = match.group('expr')
        # Taint the variable name only if its own name, or its assigned
        # expression's *code* (string-literal contents stripped), names a
        # secret.  A sensitive word appearing only inside a string literal on
        # the RHS no longer taints the name (issue #61 / #54 parity).
        if sensitive_families(name) or sensitive_families(expr):
            sensitive_vars.add(name)
    return sensitive_vars


def clean_operand_text(operand):
    clean = operand.strip()
    clean = re.sub(r'^(?:if|while)\s*\(\s*', '', clean)
    clean = re.split(r'\s*(?:&&|\|\||[;{])', clean, maxsplit=1)[0].strip()
    while clean and clean[-1] in ';{}){':
        clean = clean[:-1].strip()
    return clean


def operand_is_nullish_or_shape_check(operand):
    clean = clean_operand_text(operand)
    if nullish_re.match(clean):
        return True
    if length_re.search(clean):
        return True
    if re.match(r'^[0-9]+(?:\.[0-9]+)?$', clean):
        return True
    return False


def unsafe_secret_compare(statement, sensitive_vars):
    if safe_compare_re.search(statement) or 'ubs:ignore' in statement:
        return False
    match = compare_re.search(statement)
    if not match:
        return False
    left = clean_operand_text(match.group('left'))
    right = clean_operand_text(match.group('right'))
    if operand_is_nullish_or_shape_check(left) or operand_is_nullish_or_shape_check(right):
        return False

    left_fams = sensitive_families(left)
    right_fams = sensitive_families(right)
    left_taint = bool(operand_identifiers(left) & sensitive_vars)
    right_taint = bool(operand_identifiers(right) & sensitive_vars)
    left_sensitive = bool(left_fams) or left_taint
    right_sensitive = bool(right_fams) or right_taint

    if not (left_sensitive or right_sensitive):
        return False

    # When BOTH operands carry secret vocabulary in their identifier *names*
    # (no data-flow taint from an assigned secret), require that they name the
    # SAME secret concept.  A genuine timing-attack self-comparison uses one
    # concept on both sides (userToken === validToken; authorization ===
    # expectedToken).  Comparing two *different* concepts (doneToken !==
    # sessionNonce) is almost always an unrelated/public value such as a
    # correlation nonce, not a real secret check -- so it is not flagged.
    # See issue #61.
    left_all = term_families(left)
    right_all = term_families(right)
    if left_all and right_all and not (left_taint or right_taint):
        return bool(left_all & right_all)

    return True


def scan_file(path: Path, sample_root: Path) -> list[tuple[str, int, str]]:
    """Per-file body of the heredoc walk: [(rel_path, line, code_text), ...]."""
    issues: list[tuple[str, int, str]] = []
    if path.suffix.lower() not in exts:
        return issues
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return issues
    sensitive_vars = collect_sensitive_vars(lines)
    seen_lines = set()
    for idx, raw in enumerate(lines):
        stripped = code_line(raw).strip()
        if not stripped or has_ignore(lines, idx) or ('==' not in stripped and '!=' not in stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or not unsafe_secret_compare(statement, sensitive_vars):
            continue
        if idx in seen_lines:
            continue
        seen_lines.add(idx)
        try:
            rel = path.relative_to(sample_root)
        except ValueError:
            rel = path
        issues.append((str(rel), idx + 1, stripped.replace('\t', ' ')))
    return issues


def collect_issues(root: Path) -> list[tuple[str, int, str]]:
    issues: list[tuple[str, int, str]] = []
    if root.is_file():
        candidates = [root]
        sample_root = root.parent
    else:
        candidates = []
        sample_root = root
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                candidates.append(Path(dirpath) / fname)

    for path in candidates:
        issues.extend(scan_file(path, sample_root))
    return issues


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    issues = collect_issues(root)
    print(len(issues))
    for entry in issues[:25]:
        print('\t'.join(str(part) for part in entry))
    return 0


_KIND = "unsafe_secret_compare"
_MESSAGE = "Secret, signature, or token compared with ==/!= without timing-safe equality"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        for rel, line, _sample in scan_file(path, cwd):
            yield {
                "rule": f"javascript.ctcompare.{_KIND}",
                "path": rel,
                "line": line,
                "col": 1,
                "layer": "ctcompare",
                "lang": "javascript",
                "severity": "critical",
                "message": _MESSAGE,
            }


_POSITIVE_SRC = """export function nonceReplayCheck(sessionNonce: string, expectedNonce: string): boolean {
  return sessionNonce === expectedNonce;
}

export function doneTokenCheck(doneAuthToken: string, expectedAuthToken: string): boolean {
  if (doneAuthToken !== expectedAuthToken) {
    return false;
  }
  return true;
}
"""


def _selftest_positive() -> None:
    statement = "return sessionNonce === expectedNonce;"
    assert unsafe_secret_compare(statement, collect_sensitive_vars([statement])), statement
    statement = "if (doneAuthToken !== expectedAuthToken) {"
    assert unsafe_secret_compare(statement, collect_sensitive_vars([statement])), statement


def _selftest_suppression() -> None:
    lines = [
        "export function verifyToken(authToken: string, expectedAuthToken: string): boolean {",
        "  if (authToken !== expectedAuthToken) { // ubs:ignore -- deliberate: not a secret comparison",
        "    return false;",
        "  }",
        "  return true;",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
        target = Path(tmp) / "suppressed.ts"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_safe_compare_negative() -> None:
    lines = [
        "import crypto from 'crypto';",
        "export function safeCheck(left: string, right: string): boolean {",
        "  return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_run(tmp_prefix: str = "ubs_core_ctcompare_js_") -> None:
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.ts"
        target.write_text(_POSITIVE_SRC, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 2, findings
    assert findings[0]["rule"] == "javascript.ctcompare.unsafe_secret_compare"
    assert findings[0]["line"] == 2
    assert findings[1]["line"] == 6
    assert findings[0]["severity"] == "critical"


def _selftest_main_dialect(tmp_prefix: str = "ubs_core_ctcompare_js_") -> None:
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.ts"
        target.write_text(_POSITIVE_SRC, encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            old_argv = sys.argv
            sys.argv = ["ctcompare_js", str(tmp)]
            try:
                assert main() == 0
            finally:
                sys.argv = old_argv
    lines_out = stdout.getvalue().splitlines()
    assert lines_out[0] == "2", lines_out
    assert lines_out[1].startswith("leaky.ts\t2\t"), lines_out


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("positive_detects_secret_compare", _selftest_positive),
    ("ubs_ignore_suppresses", _selftest_suppression),
    ("timing_safe_equal_negative", _selftest_safe_compare_negative),
    ("run_finds_unsafe_compares", _selftest_run),
    ("main_reproduces_count_dialect", _selftest_main_dialect),
)

register(Analyzer(layer="ctcompare", lang="javascript", name="ctcompare_js", run=run, selftests=SELF_TESTS))
