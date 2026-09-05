"""ubs_core.go_detectors.security_randomness — category 9 security (bead 0xjg.6).

Port of run_security_randomness_checks (modules/ubs-golang.sh 5555-5821):
flags security-sensitive token generation from non-cryptographic sources
— math/rand calls under any import alias (Int/Intn/Int31/Int63/Uint32/
Uint64/Float*/NormFloat64/ExpFloat64/Perm/Shuffle/Read/Seed/New/
NewSource), methods on variables seeded via ``<rng> := math/rand.New``,
and predictable sources (time.Now().Unix*/os.Getpid/uintptr/unsafe.
Pointer/fnv|crc32|crc64|adler32) when the line or enclosing function is
security-flavored (token/session/secret/csrf/otp/salt/password/auth/…
terms, or bare key/sig words) and the predictable branch additionally
needs token material on the line (fmt.Sprintf, strconv formatting,
hex/base64, .String(), []byte(...)) or the line itself being sensitive.
crypto/rand usage (rand.Reader, io.ReadFull(... Reader), cryptoRand-style
aliases) is the sanitizer. ``<rng> := math/rand.New`` registrations are
cleared by a SAFE_RANDOM assignment to the same name; function membership
is tracked with a brace-depth stack.

Legacy: ``print_finding critical $N "Security token generated with
non-cryptographic randomness" "Use crypto/rand with rand.Read,
io.ReadFull(rand.Reader, ...), or a helper backed by crypto/rand for
tokens, sessions, CSRF nonces, OTPs, salts, API keys, and secrets"``.
Same-file and previous-line ``ubs:ignore`` markers suppress a hit;
dedupe is per (file, line, source). The rglob/SKIP_DIRS traversal is
replaced by the contract file list; the v2 record count equals the
heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MARKER = "ubs:ignore"

RULE_ID = "go.security.insecure-random"
CATEGORY = 9
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = ("Use crypto/rand with rand.Read, io.ReadFull(rand.Reader, ...), "
               "or a helper backed by crypto/rand for tokens, sessions, CSRF "
               "nonces, OTPs, salts, API keys, and secrets")

RAND_METHODS = (
    'Int', 'Intn', 'Int31', 'Int31n', 'Int63', 'Int63n', 'Uint32', 'Uint64',
    'Float32', 'Float64', 'NormFloat64', 'ExpFloat64', 'Perm', 'Shuffle',
    'Read', 'Seed', 'New', 'NewSource',
)
RNG_METHODS = (
    'Int', 'Intn', 'Int31', 'Int31n', 'Int63', 'Int63n', 'Uint32', 'Uint64',
    'Float32', 'Float64', 'NormFloat64', 'ExpFloat64', 'Perm', 'Shuffle', 'Read',
)
SECURITY_TERMS = (
    'apikey', 'accesskey', 'privatekey', 'publickey', 'clientsecret',
    'secret', 'token', 'session', 'cookie', 'csrf', 'xsrf', 'otp', 'totp',
    'mfa', 'nonce', 'salt', 'password', 'passwd', 'pwd', 'auth', 'bearer',
    'credential', 'reset', 'invite', 'verification', 'verify', 'confirm',
    'confirmation', 'magiclink', 'recovery', 'signature',
)
PREDICTABLE_TOKENS = (
    'time.Now()', 'os.Getpid()', 'unsafe.Pointer', 'fnv.', 'crc32.',
    'crc64.', 'adler32.',
)
SAFE_RANDOM_RE = re.compile(
    r'\b(?:cryptoRand|cryptorand|secureRand|secureRandom|cryptoRandom)\.(?:Read|Int)\s*\('
    r'|\b(?:cryptoRand|cryptorand|secureRand|secureRandom|cryptoRandom)\.Reader\b'
    r'|\brand\.Reader\b'
    r'|\b(?:io\.)?ReadFull\s*\([^)]*\b(?:rand|cryptoRand|cryptorand|secureRand|secureRandom|cryptoRandom)\.Reader\b',
    re.IGNORECASE,
)
PREDICTABLE_SOURCE_RE = re.compile(
    r'\btime\.Now\s*\(\s*\)\.(?:Unix|UnixNano|UnixMilli|UnixMicro)\s*\('
    r'|\bos\.Getpid\s*\('
    r'|\buintptr\s*\('
    r'|\bunsafe\.Pointer\s*\('
    r'|\b(?:fnv|crc32|crc64|adler32)\.',
    re.IGNORECASE,
)
TOKEN_MATERIAL_RE = re.compile(
    r'\bfmt\.Sprintf\s*\('
    r'|\bstrconv\.(?:FormatInt|FormatUint|Itoa)\s*\('
    r'|\b(?:hex|base64)\.'
    r'|\.String\s*\('
    r'|\[\]byte\s*\(',
    re.IGNORECASE,
)
IMPORT_LINE_RE = re.compile(r'^\s*(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|\.)\s+)?["`]math/rand["`]')
IMPORT_ONE_RE = re.compile(r'^\s*import\s+(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|\.)\s+)?["`]math/rand["`]')
ASSIGN_RE = re.compile(r'^\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(?P<rhs>.+)')
FUNC_RE = re.compile(r'^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(')


def _strip_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == '/':
                break
            if nxt == '*':
                end = line.find('*/', i + 2)
                if end == -1:
                    break
                i = end + 2
                continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def _find_math_rand_aliases(lines):
    aliases = set()
    in_block = False
    for raw in lines:
        line = _strip_comments(raw).strip()
        if not line:
            continue
        if line.startswith('import ('):
            in_block = True
            continue
        if in_block and line == ')':
            in_block = False
            continue
        match = IMPORT_ONE_RE.match(line) if not in_block else IMPORT_LINE_RE.match(line)
        if not match:
            continue
        alias = match.group('alias')
        if alias == '.':
            aliases.add('.')
        elif alias:
            aliases.add(alias)
        else:
            aliases.add('rand')
    return aliases


def _normalized(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', text.lower())


def _has_security_context(statement: str, func_name: str) -> bool:
    text = f'{statement} {func_name or ""}'
    compact = _normalized(text)
    if any(term in compact for term in SECURITY_TERMS):
        return True
    return bool(re.search(r'(?<![A-Za-z0-9_])(?:key|sig)(?![A-Za-z0-9_])', text, re.IGNORECASE))


def _method_pattern(alias: str, methods) -> re.Pattern:
    method_alt = '|'.join(re.escape(method) for method in methods)
    if alias == '.':
        return re.compile(rf'(?<![A-Za-z0-9_.])(?:{method_alt})\s*\(')
    return re.compile(rf'\b{re.escape(alias)}\.(?:{method_alt})\s*\(')


def _unsafe_source(statement: str, math_aliases, insecure_rng_vars, sensitive: bool, line_sensitive: bool):
    if SAFE_RANDOM_RE.search(statement):
        return None
    for alias in math_aliases:
        match = _method_pattern(alias, RAND_METHODS).search(statement)
        if match:
            return match.group(0).strip()
    for name in sorted(insecure_rng_vars):
        match = re.search(
            rf'\b{re.escape(name)}\.(?:{"|".join(re.escape(method) for method in RNG_METHODS)})\s*\(',
            statement,
        )
        if match:
            return match.group(0).strip()
    predictable = PREDICTABLE_SOURCE_RE.search(statement)
    if predictable and sensitive and (line_sensitive or TOKEN_MATERIAL_RE.search(statement)):
        return predictable.group(0).strip()
    return None


def _starts_function(statement: str):
    match = FUNC_RE.match(statement)
    return match.group('name') if match else None


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ('math/rand' in text or any(token in text for token in PREDICTABLE_TOKENS)):
        return
    lines = text.splitlines()
    math_aliases = _find_math_rand_aliases(lines)
    has_predictable = any(token in text for token in PREDICTABLE_TOKENS)
    if not math_aliases and not has_predictable:
        return
    insecure_rng_vars = set()
    func_stack = []
    brace_depth = 0
    seen = set()
    for idx, raw in enumerate(lines, start=1):
        statement = _strip_comments(raw).strip()
        while func_stack and brace_depth < func_stack[-1][1]:
            func_stack.pop()
        func_name = _starts_function(statement)
        opens = statement.count('{')
        closes = statement.count('}')
        if func_name:
            func_stack.append((func_name, brace_depth + max(opens, 1)))
        current_func = func_stack[-1][0] if func_stack else ''
        if _has_ignore(lines, idx) or not statement:
            brace_depth += opens - closes
            continue
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            if SAFE_RANDOM_RE.search(rhs):
                insecure_rng_vars.discard(name)
            else:
                for alias in math_aliases:
                    if _method_pattern(alias, ('New',)).search(rhs):
                        insecure_rng_vars.add(name)
                        break
        line_sensitive = _has_security_context(statement, '')
        sensitive = line_sensitive or _has_security_context('', current_func)
        source = _unsafe_source(statement, math_aliases, insecure_rng_vars, sensitive, line_sensitive)
        if source and sensitive:
            key = (path, idx, source)
            if key not in seen:
                seen.add(key)
                issues.append((path, idx, 1, f"{_source_line(lines, idx)}  [{source} in security-sensitive generation context]"))
        brace_depth += opens - closes


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
