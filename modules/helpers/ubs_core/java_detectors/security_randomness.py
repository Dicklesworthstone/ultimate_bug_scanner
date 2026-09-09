"""ubs_core.java_detectors.security_randomness — category 4 (bead 0xjg.8).

Verbatim port of run_security_randomness_checks (modules/ubs-java.sh
1995-2274): flags Random/ThreadLocalRandom/SplittableRandom/Math.random/
UUID.randomUUID/predictable-time sources used in security-sensitive contexts
(token, secret, otp, nonce, salt, ... identifiers or sensitive method names).
Tracks insecure-RNG variables across assignments and the enclosing method
name via a brace-depth stack. Current+previous-line ubs:ignore suppresses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.registry import RunContext  # noqa: F401  (parity with analyzers)
from ubs_core.java_detectors._common import iter_java_files, read_lines, strip_line_comments

RULE_ID = "java.security.insecure-randomness"
CATEGORY = 4
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = (
    "Use java.security.SecureRandom or a framework helper backed by SecureRandom "
    "for tokens, sessions, CSRF nonces, OTPs, salts, API keys, and secrets"
)

RNG_METHODS = (
    'nextInt', 'nextLong', 'nextDouble', 'nextFloat', 'nextBoolean', 'nextBytes',
    'ints', 'longs', 'doubles', 'nextGaussian',
)
SECURITY_TERMS = (
    'apikey', 'accesskey', 'privatekey', 'publickey', 'clientsecret',
    'secret', 'token', 'session', 'cookie', 'csrf', 'xsrf', 'otp', 'totp',
    'mfa', 'nonce', 'salt', 'password', 'passwd', 'pwd', 'auth', 'bearer',
    'credential', 'reset', 'invite', 'verification', 'verify', 'confirm',
    'confirmation', 'magiclink', 'recovery', 'signature',
)
ASSIGN_RE = re.compile(
    # The type-token class must not contain a space: with one, it overlapped
    # the `\s+` separator and the enclosing `+` made the split ambiguous —
    # ~6x per extra token, so a 40-token line of a scanned Java/Kotlin file hung the
    # scan (ReDoS on attacker-supplied source). Multi-token generics still
    # match: the outer `+` re-enters after the space.
    r'^\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*'
    r'(?:(?:public|private|protected|internal|static|final|volatile|transient|var|val)\s+)*'
    r'(?:[\w.$<>?,\[\]]+\s+)*(?:this\.)?'
    r'(?P<lhs>[A-Za-z_$][A-Za-z0-9_$]*)(?:\s*:\s*[\w.$<>?,\[\]]+)?\s*=\s*(?P<rhs>.+)'
)
FUNC_RE = re.compile(
    r'^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native)\s+)*'
    r'(?:[A-Za-z_$][A-Za-z0-9_$.<>,?\[\]]+\s+)+'
    r'(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;]*\)\s*(?:throws\s+[^{]+)?\{?'
)
KOTLIN_FUNC_RE = re.compile(
    r'^\s*(?:(?:public|private|protected|internal|override|suspend|inline|operator|open|final)\s+)*'
    r'fun\s+(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\('
)
UNSAFE_CTOR_RE = re.compile(r'\b(?:new\s+)?(?:(?:java\.util|kotlin\.random)\.)?Random\s*\(')
UNSAFE_SPLITTABLE_CTOR_RE = re.compile(r'\b(?:new\s+)?(?:java\.util\.)?SplittableRandom\s*\(')
THREAD_LOCAL_CALL_RE = re.compile(
    rf'\b(?:java\.util\.concurrent\.)?ThreadLocalRandom\.current\s*\(\s*\)\s*\.'
    rf'(?:{"|".join(RNG_METHODS)})\s*\('
)
KOTLIN_RANDOM_OBJECT_CALL_RE = re.compile(
    rf'\b(?:kotlin\.random\.)?Random(?:\.Default)?\s*\.\s*(?:{"|".join(RNG_METHODS)})\s*\('
)
KOTLIN_RANDOM_CTOR_CALL_RE = re.compile(
    rf'\b(?:kotlin\.random\.)?Random\s*\([^)]*\)\s*\.\s*(?:{"|".join(RNG_METHODS)})\s*\('
)
MATH_RANDOM_RE = re.compile(r'\bMath\.random\s*\(')
UUID_RANDOM_RE = re.compile(r'\b(?:java\.util\.)?UUID\.randomUUID\s*\(')
PREDICTABLE_SOURCE_RE = re.compile(
    r'\bSystem\.(?:currentTimeMillis|nanoTime)\s*\('
    r'|\bInstant\.now\s*\(\s*\)\.toEpochMilli\s*\('
    r'|\bClock\.System\.now\s*\(\s*\)\.toEpochMilliseconds\s*\('
    r'|\bnew\s+Date\s*\(\s*\)\.getTime\s*\('
    r'|\bSystem\.identityHashCode\s*\('
    r'|\bProcessHandle\.current\s*\(\s*\)\.pid\s*\(',
)
TOKEN_MATERIAL_RE = re.compile(
    r'\b(?:Long|Integer|Short|Byte)\.toString\s*\('
    r'|\bString\.format\s*\('
    r'|\b(?:Base64|HexFormat)\.'
    r'|\bnew\s+String\s*\('
    r'|\.toString\s*\(',
)


def normalized(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', text.lower())


def has_security_context(statement: str, method_name: str) -> bool:
    text = f'{statement} {method_name or ""}'
    compact = normalized(text)
    if any(term in compact for term in SECURITY_TERMS):
        return True
    return bool(re.search(r'(?<![A-Za-z0-9_])(?:key|sig)(?![A-Za-z0-9_])', text, re.IGNORECASE))


def rng_method_pattern(name: str) -> re.Pattern:
    return re.compile(rf'\b{re.escape(name)}\.(?:{"|".join(RNG_METHODS)})\s*\(')


def starts_method(statement: str):
    match = FUNC_RE.match(statement)
    if match:
        return match.group('name')
    match = KOTLIN_FUNC_RE.match(statement)
    return match.group('name') if match else None


def update_insecure_rng_vars(statement: str, insecure_rng_vars):
    assign = ASSIGN_RE.match(statement)
    if not assign:
        return
    name = assign.group('lhs')
    rhs = assign.group('rhs')
    if re.search(r'\b(?:java\.security\.)?SecureRandom(?:\.getInstance(?:Strong)?|\.getInstance)?\s*\(', rhs):
        insecure_rng_vars.discard(name)
        return
    if (
        UNSAFE_CTOR_RE.search(rhs)
        or UNSAFE_SPLITTABLE_CTOR_RE.search(rhs)
        or re.search(r'\b(?:java\.util\.concurrent\.)?ThreadLocalRandom\.current\s*\(', rhs)
        or re.search(r'\b(?:kotlin\.random\.)?Random(?:\.Default)?\b', rhs)
    ):
        insecure_rng_vars.add(name)


def unsafe_source(statement: str, insecure_rng_vars, sensitive: bool, line_sensitive: bool):
    for regex in (THREAD_LOCAL_CALL_RE, KOTLIN_RANDOM_OBJECT_CALL_RE, KOTLIN_RANDOM_CTOR_CALL_RE, MATH_RANDOM_RE, UUID_RANDOM_RE):
        match = regex.search(statement)
        if match:
            return match.group(0).strip()
    split_direct = re.search(
        rf'\b(?:new\s+)?(?:java\.util\.)?SplittableRandom\s*\([^)]*\)\s*\.(?:{"|".join(RNG_METHODS)})\s*\(',
        statement,
    )
    if split_direct:
        return split_direct.group(0).strip()
    ctor = UNSAFE_CTOR_RE.search(statement)
    if ctor:
        return ctor.group(0).strip()
    for name in sorted(insecure_rng_vars):
        match = rng_method_pattern(name).search(statement)
        if match:
            return match.group(0).strip()
    uuid_random = UUID_RANDOM_RE.search(statement)
    if uuid_random:
        return uuid_random.group(0).strip()
    predictable = PREDICTABLE_SOURCE_RE.search(statement)
    if predictable and sensitive and (line_sensitive or TOKEN_MATERIAL_RE.search(statement)):
        return predictable.group(0).strip()
    return None


def analyze(path: Path, issues):
    text = path.read_text(encoding='utf-8', errors='ignore')
    if not any(token in text for token in (
        'Random', 'ThreadLocalRandom', 'Math.random', 'currentTimeMillis', 'nanoTime',
        'Instant.now()', 'Date().getTime', 'identityHashCode', 'ProcessHandle.current()',
        'randomUUID', 'Clock.System.now()',
    )):
        return
    lines = text.splitlines()
    insecure_rng_vars = set()
    method_stack = []
    brace_depth = 0
    seen = set()
    for idx, raw in enumerate(lines, start=1):
        raw_statement = strip_line_comments(raw).strip()
        while method_stack and brace_depth < method_stack[-1][1]:
            method_stack.pop()
        method_name = starts_method(raw_statement)
        opens = raw_statement.count('{')
        closes = raw_statement.count('}')
        if method_name:
            method_stack.append((method_name, brace_depth + max(opens, 1)))
        current_method = method_stack[-1][0] if method_stack else ''
        from ubs_core.java_detectors._common import has_ignore
        if has_ignore(lines, idx) or not raw_statement:
            brace_depth += opens - closes
            continue
        pieces = []
        for part in lines[idx - 1:min(len(lines), idx + 7)]:
            piece = strip_line_comments(part).strip()
            if not piece:
                continue
            pieces.append(piece)
            if ';' in piece or '{' in piece or '}' in piece:
                break
        statement = ' '.join(pieces)
        update_insecure_rng_vars(statement, insecure_rng_vars)
        line_sensitive = has_security_context(statement, '')
        sensitive = line_sensitive or has_security_context('', current_method)
        source = unsafe_source(statement, insecure_rng_vars, sensitive, line_sensitive)
        if source and sensitive:
            key = (str(path), idx, source)
            if key not in seen:
                seen.add(key)
                issues.append((path, idx, f"{source_line(lines, idx)}  [{source} in security-sensitive generation context]"))
        brace_depth += opens - closes


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, str]] = []
    for path in iter_java_files(files):
        try:
            analyze(path, issues)
        except OSError:
            continue
    for path, line_no, detail in issues:
        yield path, line_no, 1, detail
