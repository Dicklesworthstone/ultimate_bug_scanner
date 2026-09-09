"""ubs_core.csharp_detectors.security_randomness — cat 8 security (bead 0xjg.12).

Verbatim port of the ubs-csharp.sh ``run_security_randomness_checks`` heredoc
(2638-2871): same RNG method/security-term vocabulary, insecure-RNG variable
tracking (safe reassignment kills), method-stack context, predictable-source
gating on token material, brace-depth bookkeeping, and the /* */-aware comment
stripper. The NUL-filelist loader is replaced by iteration over ``files``;
per-file match logic is unchanged.

Legacy emission: critical "Security token generated with non-cryptographic
randomness".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.csharp_detectors._common import (
    logical_statement_randomness,
    relpath,
    source_line,
    strip_line_comments_block as strip_line_comments,
)

RULE_ID = "csharp.security.weak-randomness"
CATEGORY = 8
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = "Use RandomNumberGenerator.GetBytes/GetHexString/GetInt32 or a cryptographic helper"

RNG_METHODS = (
    'Next', 'NextInt64', 'NextBytes', 'NextDouble', 'NextSingle',
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
    # ~6x per extra token, so a 40-token line of a scanned C# file hung the
    # scan (ReDoS on attacker-supplied source). Multi-token generics still
    # match: the outer `+` re-enters after the space.
    r'^\s*(?:\[[^\]]+\]\s*)*'
    r'(?:(?:public|private|protected|internal|static|readonly|const|volatile|var)\s+)*'
    r'(?:[A-Za-z_][A-Za-z0-9_.<>,?\[\]]+\s+)*(?:this\.)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)'
)
METHOD_RE = re.compile(
    r'^\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|partial|readonly)\s+)*'
    r'(?:[A-Za-z_][A-Za-z0-9_.<>,?\[\]]+\s+)+'
    r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:=>|\{)?'
)
UNSAFE_CTOR_RE = re.compile(r'\bnew\s+(?:System\.)?Random\s*\(')
RANDOM_SHARED_RE = re.compile(rf'\b(?:System\.)?Random\.Shared\.(?:{"|".join(RNG_METHODS)})\s*\(')
GUID_RE = re.compile(r'\bGuid\.NewGuid\s*\(')
PREDICTABLE_SOURCE_RE = re.compile(
    r'\bDateTime\.(?:UtcNow|Now)\.(?:Ticks|Millisecond|Second)\b'
    r'|\bEnvironment\.TickCount(?:64)?\b'
    r'|\bStopwatch\.GetTimestamp\s*\('
    r'|\bProcess\.GetCurrentProcess\s*\(\s*\)\.Id\b'
    r'|\.GetHashCode\s*\(',
)
SAFE_RANDOM_RE = re.compile(
    r'\b(?:System\.Security\.Cryptography\.)?RandomNumberGenerator\.'
    r'(?:GetBytes|Fill|GetInt32|GetHexString)\s*\('
    r'|\b(?:RandomNumberGenerator|RNGCryptoServiceProvider)\.Create\s*\('
    r'|\bRNGCryptoServiceProvider\b',
)
TOKEN_MATERIAL_RE = re.compile(
    r'\b(?:Convert\.(?:ToBase64String|ToHexString)|BitConverter\.ToString|'
    r'Encoding\.[A-Za-z0-9_]+\.GetString|string\.Format|Guid\.NewGuid)\s*\('
    r'|\.ToString\s*\(',
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
    match = METHOD_RE.match(statement)
    return match.group('name') if match else None


def update_insecure_rng_vars(statement: str, insecure_rng_vars):
    assign = ASSIGN_RE.match(statement)
    if not assign:
        return
    name = assign.group('lhs')
    rhs = assign.group('rhs')
    if SAFE_RANDOM_RE.search(rhs):
        insecure_rng_vars.discard(name)
        return
    if UNSAFE_CTOR_RE.search(rhs) or re.search(r'\b(?:System\.)?Random\.Shared\b', rhs):
        insecure_rng_vars.add(name)


def unsafe_source(statement: str, insecure_rng_vars, sensitive: bool, line_sensitive: bool):
    if SAFE_RANDOM_RE.search(statement):
        return None
    for regex in (RANDOM_SHARED_RE, GUID_RE):
        match = regex.search(statement)
        if match:
            return match.group(0).strip()
    direct = re.search(rf'\bnew\s+(?:System\.)?Random\s*\([^)]*\)\s*\.(?:{"|".join(RNG_METHODS)})\s*\(', statement)
    if direct:
        return direct.group(0).strip()
    ctor = UNSAFE_CTOR_RE.search(statement)
    if ctor and sensitive:
        return ctor.group(0).strip()
    for name in sorted(insecure_rng_vars):
        match = rng_method_pattern(name).search(statement)
        if match:
            return match.group(0).strip()
    predictable = PREDICTABLE_SOURCE_RE.search(statement)
    if predictable and sensitive and (line_sensitive or TOKEN_MATERIAL_RE.search(statement)):
        return predictable.group(0).strip()
    return None


def analyze(path: Path, base_dir: Path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not any(token in text for token in (
        'Random', 'Guid.NewGuid', 'DateTime.', 'Environment.TickCount',
        'Stopwatch.GetTimestamp', 'GetHashCode', 'Process.GetCurrentProcess',
    )):
        return
    lines = text.splitlines()
    insecure_rng_vars = set()
    method_stack = []
    pending_method = ''
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
            if opens > 0:
                method_stack.append((method_name, brace_depth + opens))
                pending_method = ''
            elif '=>' in raw_statement or ';' in raw_statement:
                pending_method = ''
            else:
                pending_method = method_name
        elif pending_method and opens > 0:
            method_stack.append((pending_method, brace_depth + opens))
            pending_method = ''
        current_method = method_name or (method_stack[-1][0] if method_stack else '')
        has_ignore = (
            0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
        ) or (
            0 <= idx - 2 < len(lines) and 'ubs:ignore' in lines[idx - 2]
        )
        if has_ignore or not raw_statement:
            brace_depth += opens - closes
            continue
        statement = logical_statement_randomness(lines, idx)
        update_insecure_rng_vars(statement, insecure_rng_vars)
        line_sensitive = has_security_context(statement, '')
        sensitive = line_sensitive or has_security_context('', current_method)
        source = unsafe_source(statement, insecure_rng_vars, sensitive, line_sensitive)
        if source and sensitive:
            key = (relpath(path, base_dir), idx, source)
            if key not in seen:
                seen.add(key)
                issues.append((relpath(path, base_dir), idx, f"{source_line(lines, idx)}  [{source} in security-sensitive generation context]"))
        brace_depth += opens - closes


def find(files: Sequence[Path], base_dir: Path | None = None) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[str, int, str]] = []
    base = base_dir if base_dir is not None else Path.cwd()
    for path in files:
        if path.suffix.lower() not in {'.cs', '.csx'}:
            continue
        analyze(path, base, issues)
    for name, line_no, code in issues:
        yield (name, line_no, 1, code)
