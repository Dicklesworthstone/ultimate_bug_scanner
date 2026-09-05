"""ubs_core.analyzers.sec_jwt — JWT decode/verify bypass risk (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "JWT decode/verify bypass risk"
(``jwt_verification_report``): same import/require collection, same decode/verify
candidate regexes, same 12-line statement window, same claim-binding rule
(issuer AND audience must both be present), same ``ubs:ignore`` placement rules
(trigger line, line above, or anywhere inside the collected statement).
The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.jwt"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = ("JWT decode/verify bypass risk: Use jwt.verify()/jose.jwtVerify() with explicit "
           "algorithms, issuer, audience, and expiration checks before trusting claims")

import_jsonwebtoken_re = re.compile(
    r'\bimport\s+(?:(?P<default>[A-Za-z_$][A-Za-z0-9_$]*)\s*,?\s*)?'
    r'(?P<named>\{[^}]+\})?\s+from\s+[\'"]jsonwebtoken[\'"]'
)
import_jsonwebtoken_namespace_re = re.compile(
    r'\bimport\s+\*\s+as\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+[\'"]jsonwebtoken[\'"]'
)
import_jose_re = re.compile(r'\bimport\s+(?P<named>\{[^}]+\})\s+from\s+[\'"]jose[\'"]')
import_jwt_decode_re = re.compile(
    r'\bimport\s+(?:\{\s*jwtDecode\s*(?:as\s+(?P<named>[A-Za-z_$][A-Za-z0-9_$]*))?\s*\}|(?P<default>[A-Za-z_$][A-Za-z0-9_$]*))\s+from\s+[\'"]jwt-decode[\'"]'
)
require_jsonwebtoken_re = re.compile(r'\b(?:const|let|var)\s+(?P<target>[A-Za-z_$][A-Za-z0-9_$]*|\{[^}]+\})\s*=\s*require\s*\(\s*[\'"]jsonwebtoken[\'"]\s*\)')
require_jwt_decode_re = re.compile(r'\b(?:const|let|var)\s+(?P<target>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*[\'"]jwt-decode[\'"]\s*\)')

decode_call_re = re.compile(r'(?<![\w$.])(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(')
member_decode_re = re.compile(r'\b(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*decode\s*\(')
member_verify_re = re.compile(r'\b(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*verify\s*\(')
verify_call_re = re.compile(r'(?<![\w$.])(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(')
unsafe_verify_re = re.compile(
    r'\b(?:ignoreExpiration|ignoreNotBefore|allowInvalidAsymmetricKeyTypes)\s*:\s*true\b'
    r'|\balgorithms?\s*:\s*\[[^\]]*[\'"]none[\'"][^\]]*\]',
    re.IGNORECASE,
)
issuer_re = re.compile(r'\bissuer\s*:', re.IGNORECASE)
audience_re = re.compile(r'\baudience\s*:', re.IGNORECASE)


def mask_string_literals(text):
    chars = list(text)
    quote = ''
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            if ch != '\n':
                chars[i] = ' '
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            chars[i] = ' '
        i += 1
    return ''.join(chars)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def statement_from(lines, idx, max_lines=12):
    parts = []
    paren_balance = 0
    brace_balance = 0
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = code_line(lines[line_idx]).strip()
        if not current:
            continue
        parts.append(current)
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if ';' in current and paren_balance <= 0 and brace_balance <= 0:
            break
    return ' '.join(parts)


def names_from_named_import(named_text, wanted):
    names = set()
    if not named_text:
        return names
    for raw_part in named_text.strip('{}').split(','):
        part = raw_part.strip()
        if not part:
            continue
        pieces = re.split(r'\s+as\s+', part)
        if len(pieces) == 1 and ':' in part:
            imported, local = [piece.strip() for piece in part.split(':', 1)]
        else:
            imported = pieces[0].strip()
            local = pieces[-1].strip()
        if imported in wanted:
            names.add(local)
    return names


def collect_names(lines):
    jwt_objects = {'jwt', 'jsonwebtoken'}
    decode_names = {'decodeJwt', 'jwtDecode'}
    verify_names = {'verify', 'jwtVerify'}
    for raw in lines:
        line = code_line(raw)
        if not line:
            continue
        m = import_jsonwebtoken_namespace_re.search(line)
        if m:
            jwt_objects.add(m.group('name'))
        m = import_jsonwebtoken_re.search(line)
        if m:
            if m.group('default'):
                jwt_objects.add(m.group('default'))
            decode_names.update(names_from_named_import(m.group('named'), {'decode'}))
            verify_names.update(names_from_named_import(m.group('named'), {'verify'}))
        m = import_jose_re.search(line)
        if m:
            decode_names.update(names_from_named_import(m.group('named'), {'decodeJwt'}))
            verify_names.update(names_from_named_import(m.group('named'), {'jwtVerify', 'compactVerify'}))
        m = import_jwt_decode_re.search(line)
        if m:
            decode_names.add(m.group('named') or m.group('default') or 'jwtDecode')
        m = require_jsonwebtoken_re.search(line)
        if m:
            target = m.group('target').strip()
            if target.startswith('{'):
                decode_names.update(names_from_named_import(target, {'decode'}))
                verify_names.update(names_from_named_import(target, {'verify'}))
            else:
                jwt_objects.add(target)
        m = require_jwt_decode_re.search(line)
        if m:
            decode_names.add(m.group('target'))
    return jwt_objects, decode_names, verify_names


def line_has_candidate_call(text, decode_names, verify_names):
    call_text = mask_string_literals(text)
    if member_decode_re.search(call_text) or member_verify_re.search(call_text):
        return True
    for name in decode_names | verify_names:
        if re.search(rf'(?<![\w$.]){re.escape(name)}\s*\(', call_text):
            return True
    return False


def verify_lacks_claim_binding(statement):
    return not (issuer_re.search(statement) and audience_re.search(statement))


def scan_file_findings(path: Path) -> Iterator[int]:
    """Yield 1-based line numbers per detection; match logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    jwt_objects, decode_names, verify_names = collect_names(lines)
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        if not line_has_candidate_call(stripped, decode_names, verify_names):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        call_statement = mask_string_literals(statement)
        unsafe = False
        for match in member_decode_re.finditer(call_statement):
            if match.group('name') in jwt_objects:
                unsafe = True
                break
        if not unsafe:
            for match in decode_call_re.finditer(call_statement):
                if match.group('name') in decode_names:
                    unsafe = True
                    break
        if not unsafe:
            for match in member_verify_re.finditer(call_statement):
                if match.group('name') in jwt_objects and (
                    unsafe_verify_re.search(statement) or verify_lacks_claim_binding(statement)
                ):
                    unsafe = True
                    break
        if not unsafe:
            for match in verify_call_re.finditer(call_statement):
                if match.group('name') in verify_names and (
                    unsafe_verify_re.search(statement) or verify_lacks_claim_binding(statement)
                ):
                    unsafe = True
                    break
        if not unsafe:
            continue
        yield idx + 1

def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs relative to the scan root (cwd)
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for line in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_decode_trust_flagged(tmp_prefix: str = "ubs_core_sec_jwt_") -> None:
    import tempfile

    src = "\n".join([
        "import jwt from 'jsonwebtoken';",
        "import { decodeJwt } from 'jose';",
        "",
        "export function trustsDecodedRole(req) {",
        "  const token = req.headers.authorization.replace('Bearer ', '');",
        "  const claims = jwt.decode(token);",
        "  return claims.role;",
        "}",
        "",
        "export function trustsJoseDecode(token) {",
        "  return decodeJwt(token);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "auth.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [6, 11], findings


def _selftest_verify_requires_claim_binding(tmp_prefix: str = "ubs_core_sec_jwt_bind_") -> None:
    import tempfile

    insecure = "\n".join([
        "import jwt from 'jsonwebtoken';",
        "",
        "export function verifyLoose(token, publicKey) {",
        "  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });",
        "}",
        "",
    ])
    safe = "\n".join([
        "import jwt from 'jsonwebtoken';",
        "",
        "export function verifyStrict(token, publicKey, issuer, audience) {",
        "  return jwt.verify(token, publicKey, {",
        "    algorithms: ['RS256'],",
        "    issuer,",
        "    audience,",
        "  });",
        "}",
        "",
    ])
    none_alg = "\n".join([
        "import jwt from 'jsonwebtoken';",
        "",
        "export function acceptsNone(token, secret) {",
        "  return jwt.verify(token, secret, { algorithms: ['none'], issuer: 'i', audience: 'a' });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        loose = Path(tmp) / "loose.ts"
        loose.write_text(insecure, encoding="utf-8")
        strict = Path(tmp) / "strict.ts"
        strict.write_text(safe, encoding="utf-8")
        nonef = Path(tmp) / "none.ts"
        nonef.write_text(none_alg, encoding="utf-8")
        assert list(scan_file_findings(loose)) == [4], "loose verify must be flagged"
        assert list(scan_file_findings(strict)) == [], "claim-bound verify must stay clean"
        assert list(scan_file_findings(nonef)) == [4], "none algorithm must be flagged"


def _selftest_documentation_string_clean(tmp_prefix: str = "ubs_core_sec_jwt_doc_") -> None:
    import tempfile

    # Documented unsafe examples inside string literals / block comments stay clean.
    src = "\n".join([
        "import jwt from 'jsonwebtoken';",
        "",
        "export function documentationMentionsDoNotCount() {",
        "  const decodeExample = 'jwt.decode(token)';",
        "  /* jwt.verify(token, key, { algorithms: ['none'] }) */",
        "  return decodeExample.length;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "doc.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_jwt_ign_") -> None:
    import tempfile

    # ubs:ignore on the line above, on the line itself, and inside the statement
    # window all suppress (heredoc placement rules).
    above = "import jwt from 'jsonwebtoken';\n\n// ubs:ignore\nconst claims = jwt.decode(token);\n"
    same = "import jwt from 'jsonwebtoken';\n\nconst claims = jwt.decode(token); // ubs:ignore\n"
    in_stmt = "\n".join([
        "import jwt from 'jsonwebtoken';",
        "",
        "export function verifyLoose(token, publicKey) {",
        "  return jwt.verify(token, publicKey, { // ubs:ignore",
        "    algorithms: ['RS256'],",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        for name, body in (("above.ts", above), ("same.ts", same), ("stmt.ts", in_stmt)):
            target = Path(tmp) / name
            target.write_text(body, encoding="utf-8")
            assert list(scan_file_findings(target)) == [], (name, body)


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_jwt_run_") -> None:
    import tempfile

    src = "import jwt from 'jsonwebtoken';\nconst claims = jwt.decode(token);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "auth.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 2 and rec["col"] == 1, rec
        assert "JWT decode/verify bypass risk" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("decode-trust-flagged", _selftest_decode_trust_flagged),
    ("verify-claim-binding", _selftest_verify_requires_claim_binding),
    ("documentation-string-clean", _selftest_documentation_string_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_jwt", run=run, selftests=SELF_TESTS))
