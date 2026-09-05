"""ubs_core.cpp_detectors.weak_random — category 7 non-crypto randomness (bead 0xjg.9).

Verbatim port of the run_security_randomness_checks heredoc
(modules/ubs-cpp.sh 1003-1237). Critical: "Security token generated with
non-cryptographic randomness".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "cpp.detector.weak-random"
CATEGORY = 7
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = ("Use RAND_bytes/RAND_priv_bytes, getrandom, BCryptGenRandom, "
               "randombytes_buf, or another OS/crypto-backed random byte source "
               "for tokens, nonces, salts, OTPs, and reset codes")

SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SECURITY_CONTEXT_RE = re.compile(
    r'\b(?:session|csrf|xsrf|token|secret|nonce|salt|otp|password|passwd|pwd|reset|invite|'
    r'invitation|verification|verify|auth|oauth|bearer|credential|jwt|cookie|signature|'
    r'signing|encrypt(?:ion)?|decrypt(?:ion)?|api\s*key|access\s*key|private\s*key|public\s*key|'
    r'recovery\s*code|backup\s*code|totp|mfa|2fa)\b',
    re.IGNORECASE,
)
UNSAFE_RANDOM_CALL_RE = re.compile(
    r'(?<![A-Za-z0-9_:])(?:std::)?(?:rand|srand)\s*\('
    r'|(?<![A-Za-z0-9_:])(?:random|srandom|drand48|erand48|lrand48|mrand48|srand48)\s*\('
)
PREDICTABLE_SOURCE_RE = re.compile(
    r'(?<![A-Za-z0-9_:])(?:std::)?time\s*\('
    r'|\b(?:std::chrono::)?(?:system_clock|steady_clock|high_resolution_clock)::now\s*\('
    r'|(?<![A-Za-z0-9_:])clock\s*\('
    r'|(?<![A-Za-z0-9_:])(?:getpid|GetCurrentProcessId)\s*\('
    r'|\bstd::hash\s*<'
)
INSECURE_ENGINE_TYPE_RE = re.compile(
    r'\b(?:std::|boost::random::)?(?:mt19937(?:_64)?|minstd_rand(?:0)?|default_random_engine|'
    r'ranlux(?:24|48)(?:_base)?|knuth_b|linear_congruential_engine|mersenne_twister_engine|'
    r'subtract_with_carry_engine|random_device)\b'
)
ENGINE_DECL_RE = re.compile(
    r'\b(?:std::|boost::random::)?(?:mt19937(?:_64)?|minstd_rand(?:0)?|default_random_engine|'
    r'ranlux(?:24|48)(?:_base)?|knuth_b|linear_congruential_engine|mersenne_twister_engine|'
    r'subtract_with_carry_engine|random_device)(?:\s*<[^;{}()]*>)?\s+([A-Za-z_][A-Za-z0-9_]*)\b'
)
AUTO_ENGINE_DECL_RE = re.compile(
    r'\bauto(?:\s+const)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:std::|boost::random::)?'
    r'(?:mt19937(?:_64)?|minstd_rand(?:0)?|default_random_engine|ranlux(?:24|48)(?:_base)?|knuth_b|random_device)\b'
)
DISTRIBUTION_RE = re.compile(
    r'\b(?:std::|boost::random::)?(?:uniform_(?:int|real)_distribution|normal_distribution|'
    r'bernoulli_distribution|binomial_distribution|poisson_distribution|discrete_distribution)\b'
)


def code_without_comments_or_strings(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            out.append(' ')
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(' ')
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def strip_block_comments_preserve_lines(text: str) -> str:
    out = []
    i = 0
    in_comment = False
    while i < len(text):
        if in_comment:
            if text.startswith('*/', i):
                out.extend('  ')
                i += 2
                in_comment = False
                continue
            out.append('\n' if text[i] == '\n' else ' ')
            i += 1
            continue
        if text.startswith('/*', i):
            out.extend('  ')
            i += 2
            in_comment = True
            continue
        out.append(text[i])
        i += 1
    return ''.join(out)


def normalize_security_text(text: str) -> str:
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', text)
    text = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', text)
    text = re.sub(r'[_\-.]+', ' ', text)
    return text


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = code_without_comments_or_strings(lines[idx])
    balance = statement.count('(') - statement.count(')')
    has_end = ';' in statement or '{' in statement or '}' in statement
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = code_without_comments_or_strings(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line
        lookahead += 1
    return statement


def context_around(lines, line_no):
    start = max(0, line_no - 8)
    end = min(len(lines), line_no + 8)
    return '\n'.join(code_without_comments_or_strings(line) for line in lines[start:end])


def has_security_context(statement, context):
    normalized = normalize_security_text(statement + '\n' + context)
    return bool(SECURITY_CONTEXT_RE.search(normalized))


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def collect_insecure_rng_vars(lines):
    vars_found = set()
    for idx, _ in enumerate(lines, start=1):
        statement = logical_statement(lines, idx)
        for match in ENGINE_DECL_RE.finditer(statement):
            vars_found.add(match.group(1))
        for match in AUTO_ENGINE_DECL_RE.finditer(statement):
            vars_found.add(match.group(1))
    return vars_found


def uses_insecure_rng_var(statement, rng_vars):
    for var in rng_vars:
        escaped = re.escape(var)
        if re.search(rf'\b[A-Za-z_][A-Za-z0-9_]*\s*\(\s*{escaped}\b', statement):
            return True
        if DISTRIBUTION_RE.search(statement) and re.search(rf'\b{escaped}\b', statement):
            return True
        if re.search(rf'\b{escaped}\s*\(', statement):
            return True
    return False


def random_issue_reason(statement, rng_vars):
    if UNSAFE_RANDOM_CALL_RE.search(statement):
        return 'weak random API'
    if INSECURE_ENGINE_TYPE_RE.search(statement):
        return 'non-cryptographic random engine'
    if uses_insecure_rng_var(statement, rng_vars):
        return 'non-cryptographic random engine output'
    if PREDICTABLE_SOURCE_RE.search(statement):
        return 'predictable seed or token material'
    return ''


def analyze(path: Path, cwd: Path) -> list[tuple[str, int, str]]:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    if not (
        UNSAFE_RANDOM_CALL_RE.search(text)
        or PREDICTABLE_SOURCE_RE.search(text)
        or INSECURE_ENGINE_TYPE_RE.search(text)
    ):
        return []
    raw_lines = text.splitlines()
    code_lines = strip_block_comments_preserve_lines(text).splitlines()
    while len(code_lines) < len(raw_lines):
        code_lines.append('')
    rng_vars = collect_insecure_rng_vars(code_lines)
    try:
        rel = str(path.resolve().relative_to(cwd))
    except ValueError:
        rel = path.name
    seen = set()
    issues = []
    for idx, _ in enumerate(code_lines, start=1):
        if has_ignore(raw_lines, idx):
            continue
        statement = logical_statement(code_lines, idx)
        context = context_around(code_lines, idx)
        if not has_security_context(statement, context):
            continue
        if not random_issue_reason(statement, rng_vars):
            continue
        key = (rel, idx)
        if key in seen:
            continue
        seen.add(key)
        issues.append((rel, idx, source_line(raw_lines, idx)))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in EXTS:
            continue
        for rel, line_no, code in analyze(path, cwd):
            yield rel, line_no, 1, code
