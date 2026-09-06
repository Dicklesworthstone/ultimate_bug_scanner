"""swift_detectors.security_randomness — cat 7 non-crypto randomness check.

Verbatim port of the run_security_randomness_checks heredoc in
modules/ubs-swift.sh. The legacy shell printed ONE critical finding plus up
to DETAIL_LIMIT code samples; the aggregate record carries the samples.
"""
from __future__ import annotations

import re
from pathlib import Path

from ubs_core.swift_detectors._common import MARKER, iter_swift_files, rel

RULE_ID = "swift.crypto.weak-randomness"
CATEGORY = 7
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"

SKIP_DIRS = {
    '.git', '.hg', '.svn', '.build', 'build', 'DerivedData', '.swiftpm',
    '.sourcery', '.periphery', '.mint', '.cache', '.xcarchive', '.xcresult',
    'Pods', 'Carthage', 'vendor'
}
NAME = r'[A-Za-z_][A-Za-z0-9_]*'

SECURITY_CONTEXT_RE = re.compile(
    r'(?:^|[^A-Za-z0-9])(?:api[_-]?key|access[_-]?key|private[_-]?key|public[_-]?key|secret|client[_-]?secret|'
    r'token|session|cookie|csrf|xsrf|otp|totp|mfa|nonce|salt|password|passwd|pwd|auth|bearer|credential|'
    r'reset|invite|verification|verify|confirm|confirmation|magic[_-]?link|recovery|signature|sig|key)(?:[^A-Za-z0-9]|$)',
    re.IGNORECASE,
)
SAFE_RANDOM_RE = re.compile(
    r'\bSecRandomCopyBytes\s*\('
    r'|\bkSecRandomDefault\b'
    r'|\b(?:CryptoKit\.)?SymmetricKey\s*\(\s*size\s*:'
    r'|\b(?:AES|ChaChaPoly)\.(?:GCM\.)?Nonce\s*\('
    r'|\bsecure(?:Random|Token|Nonce|Secret|Bytes)\b'
    r'|\bcrypto(?:Random|Token|Nonce|Bytes)\b'
    r'|\brandomBytes\s*\(',
    re.IGNORECASE,
)
UNSAFE_RANDOM_RE = re.compile(
    r'\b(?:Int|UInt|UInt8|UInt16|UInt32|UInt64|Double|Float|CGFloat|Bool)\.random\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\([^)]*\))?\.randomElement\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\([^)]*\))?\.shuffled\s*\('
    r'|\bSystemRandomNumberGenerator\s*\('
    r'|\b(?:GKRandomSource|GKARC4RandomSource|GKLinearCongruentialRandomSource|GKMersenneTwisterRandomSource)\b'
    r'|\barc4random(?:_uniform|_buf)?\s*\('
    r'|(?<![A-Za-z0-9_])(?:rand|random|drand48|lrand48|mrand48|srand|srandom|srand48)\s*\(',
)
PREDICTABLE_SOURCE_RE = re.compile(
    r'\bDate\s*\(\s*\)'
    r'|\bDate\.now\b'
    r'|\bNSDate\s*\('
    r'|\btimeIntervalSince(?:1970|ReferenceDate)\b'
    r'|\bDispatchTime\.now\s*\('
    r'|\buptimeNanoseconds\b'
    r'|\bProcessInfo\.processInfo\.(?:processIdentifier|globallyUniqueString)\b'
    r'|\bObjectIdentifier\s*\('
    r'|\bhashValue\b'
    r'|\bCFAbsoluteTimeGetCurrent\s*\('
    r'|\bCACurrentMediaTime\s*\('
    r'|\bmach_absolute_time\s*\(',
)
TOKEN_MATERIAL_RE = re.compile(
    r'\\\('
    r'|\.description\b'
    r'|\.uuidString\b'
    r'|\bString\s*\('
    r'|\bData\s*\('
    r'|\bSHA(?:256|384|512)\.'
    r'|\bInsecure\.(?:MD5|SHA1)\.'
    r'|\bbase64EncodedString\s*\('
    r'|\.map\s*\('
    r'|\.joined\s*\(',
)
ASSIGN_RE = re.compile(rf'^\s*(?:let|var)\s+({NAME})\b[^=]*=\s*(.+)$')
FUNC_RE = re.compile(rf'\bfunc\s+({NAME})\b')
RNG_ASSIGN_RE = re.compile(
    rf'^\s*(?:let|var)\s+({NAME})\b[^=]*=\s*(?:SystemRandomNumberGenerator\s*\(|'
    rf'(?:GKRandomSource|GKARC4RandomSource|GKLinearCongruentialRandomSource|GKMersenneTwisterRandomSource)\b)'
)


def strip_line_comments(line: str) -> str:
    """The randomness heredoc's stripper: string content kept, only `//` cut."""
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
        if ch == '"':
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def expression_search_text(expr: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escape:
                if ch == '(':
                    depth = 1
                    j = i + 1
                    interpolation = []
                    while j < len(expr) and depth > 0:
                        current = expr[j]
                        if current == '(':
                            depth += 1
                        elif current == ')':
                            depth -= 1
                            if depth == 0:
                                break
                        interpolation.append(current)
                        j += 1
                    out.append(' ')
                    out.append(''.join(interpolation))
                    out.append(' ')
                    i = j + 1
                    escape = False
                    continue
                escape = False
                i += 1
                continue
            if ch == '\\':
                escape = True
                i += 1
                continue
            if ch == quote:
                quote = ''
            i += 1
            continue
        if ch == '"':
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def context_search_text(expr: str) -> str:
    visible = expression_search_text(expr)
    camel_split = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', visible)
    separators = re.sub(r'[_-]+', ' ', camel_split)
    return f"{visible} {separators}"


def logical_statement(lines: list[str], line_no: int) -> str:
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') - statement.count(')') - statement.count(']')
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        if balance <= 0 and not statement.rstrip().endswith((',', '+', '\\')) and not next_line.startswith('.'):
            break
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') - next_line.count(')') - next_line.count(']')
        lookahead += 1
    return statement


def has_ignore(lines: list[str], line_no: int) -> bool:
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def current_function_context(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 25)
    for raw in reversed(lines[start:line_no]):
        match = FUNC_RE.search(strip_line_comments(raw))
        if match:
            return match.group(0)
    return ''


def is_security_sensitive(statement: str, function_context: str) -> bool:
    visible = context_search_text(statement)
    return bool(SECURITY_CONTEXT_RE.search(visible) or SECURITY_CONTEXT_RE.search(context_search_text(function_context)))


def unsafe_source(statement: str, insecure_rng_vars: set, sensitive: bool):
    visible = expression_search_text(statement)
    direct = UNSAFE_RANDOM_RE.search(visible)
    if direct:
        return direct.group(0).strip()
    for name in sorted(insecure_rng_vars, key=len, reverse=True):
        if re.search(rf'\b{re.escape(name)}\s*\.\s*(?:next|nextInt|nextUniform|nextBool)\s*\(', visible):
            return f'{name}.next(...)'
    predictable = PREDICTABLE_SOURCE_RE.search(visible)
    if predictable and (sensitive or TOKEN_MATERIAL_RE.search(visible) or SECURITY_CONTEXT_RE.search(visible)):
        return predictable.group(0).strip()
    return None


def updates_rng_vars(statement: str, insecure_rng_vars: set) -> None:
    visible = expression_search_text(statement)
    match = RNG_ASSIGN_RE.search(visible)
    if match:
        insecure_rng_vars.add(match.group(1))
        return
    assign = ASSIGN_RE.search(visible)
    if assign and assign.group(1) in insecure_rng_vars and SAFE_RANDOM_RE.search(assign.group(2)):
        insecure_rng_vars.discard(assign.group(1))


def collect_findings(root: Path):
    base = root if root.is_dir() else root.parent
    findings = []
    for path in iter_swift_files(root, base, SKIP_DIRS):
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        if not (UNSAFE_RANDOM_RE.search(text) or PREDICTABLE_SOURCE_RE.search(text)):
            continue
        lines = text.splitlines()
        insecure_rng_vars = set()
        seen = set()
        for line_no in range(1, len(lines) + 1):
            if has_ignore(lines, line_no):
                continue
            statement = logical_statement(lines, line_no)
            updates_rng_vars(statement, insecure_rng_vars)
            function_context = current_function_context(lines, line_no)
            sensitive = is_security_sensitive(statement, function_context)
            if not sensitive:
                continue
            source = unsafe_source(statement, insecure_rng_vars, sensitive)
            if not source:
                continue
            key = (rel(path, base), line_no)
            if key in seen:
                continue
            seen.add(key)
            findings.append((rel(path, base), line_no, f"{lines[line_no - 1].strip()}  [{source}]"))
    return findings


def scan(ctx):
    root = ctx.project_dir.resolve()
    findings = collect_findings(root)
    if not findings:
        return
    samples = [
        {"path": file_name, "line": line_no, "code": code}
        for file_name, line_no, code in findings[:25]
    ]
    yield {
        "rule": RULE_ID,
        "category": CATEGORY,
        "path": findings[0][0],
        "line": findings[0][1],
        "severity": SEVERITY,
        "count": len(findings),
        "title": TITLE,
        "message": TITLE,
        "samples": samples,
    }
