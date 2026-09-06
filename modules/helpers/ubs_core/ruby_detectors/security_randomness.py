"""ubs_core.ruby_detectors.security_randomness — category 6 security (bead 0xjg.10).

Port of run_security_randomness_checks (modules/ubs-ruby.sh 1893-2117): a
line tracker with a def/block stack that flags rand/Random/srand sources
and predictable material (Time.now, Process.pid, object_id, #hash) used in
security-sensitive contexts (token/session/csrf/... naming on the line or
its enclosing def), tracking Random.new instances and clearing them on
SecureRandom reassignment. Same-file and previous-line `ubs:ignore` markers
suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.ruby_detectors._common import (
    EXTS,
    has_ignore,
    identifier_search_text,
    logical_statement,
    read_lines,
    ruby_files,
    source_line,
    strip_line_comments,
)

RULE_ID = "ruby.security.non-crypto-random"
CATEGORY = 6
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = (
    "Use SecureRandom.hex/base64/urlsafe_base64/uuid/random_bytes/"
    "alphanumeric for tokens, sessions, CSRF nonces, API keys, OTPs, salts, "
    "and secrets"
)

SECURITY_CONTEXT_RE = re.compile(
    r'(?:^|[^A-Za-z0-9])(?:api[_-]?key|access[_-]?key|private[_-]?key|public[_-]?key|secret|client[_-]?secret|'
    r'token|session|cookie|csrf|xsrf|otp|totp|mfa|nonce|salt|password|passwd|pwd|auth|bearer|credential|'
    r'reset|invite|verification|verify|confirm|confirmation|magic[_-]?link|recovery|signature|sig|key)(?:[^A-Za-z0-9]|$)',
    re.IGNORECASE,
)
SAFE_RANDOM_RE = re.compile(
    r'\bSecureRandom\.(?:hex|base64|urlsafe_base64|uuid|random_bytes|alphanumeric)\s*\('
    r'|\bOpenSSL::Random\.random_bytes\s*\('
    r'|\b(?:secure|crypto|cryptographic|random_bytes|secure_token|safe_token|csrf_token|signed_token|generate_secure_token)\b',
    re.IGNORECASE,
)
UNSAFE_RANDOM_RE = re.compile(
    r'(?<![A-Za-z0-9_:])(?:Kernel\.)?rand\s*\('
    r'|\bRandom\.rand\s*\('
    r'|\bRandom\.new(?:\s*\([^)]*\))?\.rand\s*\('
    r'|\bRandom\.new\s*\('
    r'|(?<![A-Za-z0-9_:])srand\s*\(',
    re.IGNORECASE,
)
PREDICTABLE_SOURCE_RE = re.compile(
    r'\bTime\.(?:now|new)\b'
    r'|\bDateTime\.now\b'
    r'|\bProcess\.pid\b'
    r'|(?<![A-Za-z0-9_:])(?:object_id|__id__)\b'
    r'|(?<![A-Za-z0-9_])hash\s*\('
    r'|\.[A-Za-z0-9_]*hash\b',
    re.IGNORECASE,
)
TOKEN_MATERIAL_RE = re.compile(
    r'#\{'
    r'|\.to_(?:s|i)\b'
    r'|\.strftime\s*\('
    r'|\bDigest::(?:MD5|SHA1|SHA256|SHA512)\.'
    r'|\bBase64\.'
    r'|\.pack\s*\('
    r'|\.join\s*\(',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(r'^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$')
DEF_RE = re.compile(r'^\s*def\s+(?:self\.)?(?P<name>[A-Za-z_][A-Za-z0-9_!?=]*)')
BLOCK_RE = re.compile(r'^\s*(?:class|module|if|unless|case|begin|for|while|until)\b|\bdo(?:\s*\|[^|]*\|)?\s*(?:#.*)?$')
END_TOKEN_RE = re.compile(r'(?:^|[;\s])end(?:[;\s]|$)')
ENDLESS_DEF_RE = re.compile(r'^\s*def\s+(?:self\.)?[A-Za-z_][A-Za-z0-9_!?]*(?:\s*\([^)]*\))?\s*=')


def is_sensitive_context(statement, method_stack):
    context = identifier_search_text(statement)
    if method_stack:
        context += " " + " ".join(name for name in method_stack if name)
    return bool(SECURITY_CONTEXT_RE.search(context))


def unsafe_source(statement, insecure_rng_vars, sensitive):
    if SAFE_RANDOM_RE.search(statement):
        return None
    direct = UNSAFE_RANDOM_RE.search(statement)
    if direct:
        return direct.group(0).strip()
    for name in sorted(insecure_rng_vars):
        match = re.search(rf"\b{re.escape(name)}\.rand\s*\(", statement)
        if match:
            return match.group(0).strip()
    predictable = PREDICTABLE_SOURCE_RE.search(statement)
    if predictable and sensitive and TOKEN_MATERIAL_RE.search(statement):
        return predictable.group(0).strip()
    return None


def push_blocks(statement, block_stack):
    stripped = statement.strip()
    method = DEF_RE.match(stripped)
    if method:
        block_stack.append(method.group("name"))
    elif BLOCK_RE.search(stripped):
        block_stack.append("")


def pop_blocks(statement, block_stack):
    stripped = statement.strip()
    end_count = len(END_TOKEN_RE.findall(stripped))
    if ENDLESS_DEF_RE.match(stripped):
        end_count += 1
    for _ in range(end_count):
        if block_stack:
            block_stack.pop()


def current_methods(block_stack):
    return [name for name in block_stack if name]


def analyze(lines, issues, path_str):
    if not lines:
        return
    text = "\n".join(lines)
    if not (UNSAFE_RANDOM_RE.search(text) or PREDICTABLE_SOURCE_RE.search(text)):
        return
    if not SECURITY_CONTEXT_RE.search(text):
        return
    block_stack = []
    insecure_rng_vars = set()
    seen = set()
    for idx in range(1, len(lines) + 1):
        raw_statement = strip_line_comments(lines[idx - 1])
        push_blocks(raw_statement, block_stack)
        if has_ignore(lines, idx):
            pop_blocks(raw_statement, block_stack)
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            pop_blocks(raw_statement, block_stack)
            continue
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            if SAFE_RANDOM_RE.search(rhs):
                insecure_rng_vars.discard(name)
            elif re.search(r"\bRandom\.new\s*\(", rhs):
                insecure_rng_vars.add(name)
        sensitive = is_sensitive_context(statement, current_methods(block_stack))
        source = unsafe_source(statement, insecure_rng_vars, sensitive)
        if not source or not sensitive:
            pop_blocks(raw_statement, block_stack)
            continue
        key = (path_str, idx, source)
        if key in seen:
            pop_blocks(raw_statement, block_stack)
            continue
        seen.add(key)
        issues.append(
            (path_str, idx, 1, f"{source_line(lines, idx)}  [{source} in security-sensitive generation context]")
        )
        pop_blocks(raw_statement, block_stack)


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        issues: list[tuple] = []
        analyze(lines, issues, str(path))
        yield from issues
