"""ubs_core.analyzers.ctcompare_py — Python timing-safe secret comparison analysis (bead A2).

Extracted verbatim from the ``run_constant_time_compare_checks`` heredoc in
modules/ubs-python.sh: an AST walk that flags ``==``/``!=`` comparisons
involving secret material (HMACs, API keys, CSRF tokens, reset tokens, ...)
where ``hmac.compare_digest()`` / ``secrets.compare_digest()`` should be used.

Two-tier vocabulary (GH #85): strong terms (secret, password, signature, ...)
are security-sensitive on their own unless the very next identifier term is
schema/metadata vocabulary (signature_format, credential_type, jwt_header).
Weak terms (token, key, digest, nonce, ...) are ordinary parser/domain
vocabulary and only become sensitive next to a security qualifier in the same
identifier (auth_token, api_key, session_token, webhook_signature).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT: Path = Path.cwd()
BASE_DIR: Path = ROOT

SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
# GH #85 two-tier vocabulary (same sets as the Rust module). Strong terms are
# security-sensitive on their own unless the very next identifier term is
# schema/metadata vocabulary (signature_format, credential_type, jwt_header).
# Weak terms (token, key, digest, nonce, session, mac, ...) are ordinary
# parser/domain vocabulary and only become sensitive next to a security
# qualifier in the same identifier (auth_token, api_key, session_token,
# webhook_signature). Identifiers are split into terms first, so `TARGET_SIGS`
# no longer matches `sig` by substring and a bare parser `token == "rm"` is
# not reported as a secret comparison.
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

def identifier_terms(text):
    text = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', text)
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', text)
    return re.findall(r'[a-z0-9]+', text.lower())

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def name_is_sensitive(name):
    if not name:
        return False
    terms = identifier_terms(name)
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

class ConstantTimeCompareAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.sensitive_names = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_sensitive(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.sensitive_names or name_is_sensitive(node.id)
        if isinstance(node, ast.Attribute):
            # Judge only the attribute being compared. Including the receiver
            # made ORM column comparisons like `Token.user_id == user_uuid`
            # look sensitive purely because of the model class name (#64).
            return name_is_sensitive(node.attr)
        if isinstance(node, ast.Subscript):
            key = const_string(node.slice)
            return name_is_sensitive(key or '') or self.expr_is_sensitive(node.value)
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            owner = name.rsplit('.', 1)[0] if '.' in name else ''
            return (
                name_is_sensitive(name)
                or short in {'digest', 'hexdigest'}
                or name in {'hmac.new', 'hashlib.pbkdf2_hmac'}
                or owner == 'hmac'
            )
        if isinstance(node, ast.BinOp):
            return self.expr_is_sensitive(node.left) or self.expr_is_sensitive(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self.expr_is_sensitive(value) for value in node.values)
        return False

    def mark_assignment(self, names, value):
        value_sensitive = self.expr_is_sensitive(value)
        for name in names:
            if name_is_sensitive(name) or value_sensitive:
                self.sensitive_names.add(name)
            else:
                self.sensitive_names.discard(name)

    def visit_FunctionDef(self, node):
        old_sensitive = set(self.sensitive_names)
        self.sensitive_names.clear()
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            if name_is_sensitive(arg.arg):
                self.sensitive_names.add(arg.arg)
        if node.args.vararg and name_is_sensitive(node.args.vararg.arg):
            self.sensitive_names.add(node.args.vararg.arg)
        if node.args.kwarg and name_is_sensitive(node.args.kwarg.arg):
            self.sensitive_names.add(node.args.kwarg.arg)
        for stmt in node.body:
            self.visit(stmt)
        self.sensitive_names = old_sensitive

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            values = [node.left] + list(node.comparators)
            # Comparing against a number, boolean, or None (e.g.
            # `total_tokens == 0`) can never leak secret material through
            # timing; only string/bytes comparisons are timing-sensitive (#64).
            non_secret_literal = any(
                isinstance(value, ast.Constant) and not isinstance(value.value, (str, bytes))
                for value in values
            )
            if not non_secret_literal and any(self.expr_is_sensitive(value) for value in values):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = ConstantTimeCompareAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)


def main(argv: list[str] | None = None) -> int:
    """CLI driver: same stdout as the extracted heredoc for the same argv."""
    global ROOT, BASE_DIR
    args = list(sys.argv if argv is None else argv)
    if len(args) < 2:
        print('usage: ctcompare_py <project_dir>', file=sys.stderr)
        return 2
    ROOT = Path(args[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f'__COUNT__\t{len(issues)}')
    for file_name, line_no, code in issues[:25]:
        print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
    return 0


_RULE_KIND = "secret_eq"
_SEVERITY = "critical"
_MESSAGE = (
    "Secret, signature, or token compared with ==/!=; "
    "use hmac.compare_digest() or secrets.compare_digest()"
)


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        issues: list[tuple[str, int, str]] = []
        analyze(path, issues)
        for _file, line_no, _code in issues:
            display = str(path)
            if path.is_absolute():
                try:
                    display = str(path.relative_to(cwd))
                except ValueError:
                    display = str(path)
            yield {
                "rule": f"python.ctcompare.{_RULE_KIND}",
                "path": display,
                "line": line_no,
                "col": 1,
                "layer": "ctcompare",
                "lang": "python",
                "severity": _SEVERITY,
                "message": _MESSAGE,
            }


def _scan_code(code: str) -> list[tuple[str, int, str]]:
    lines = code.splitlines()
    visitor = ConstantTimeCompareAnalyzer(Path("memory.py"), lines)
    visitor.visit(ast.parse(code))
    return visitor.issues


def _selftest_secret_eq_positive() -> None:
    code = (
        "import hmac\n"
        "def verify(password, stored):\n"
        "    return password == stored\n"
    )
    issues = _scan_code(code)
    assert len(issues) == 1, issues
    assert issues[0][1] == 3


def _selftest_ubs_ignore_suppression() -> None:
    code = (
        "def verify(password, stored):\n"
        "    return password == stored  # ubs:ignore\n"
    )
    assert not _scan_code(code)


def _selftest_counter_compare_negative() -> None:
    code = (
        "def disabled(total_tokens):\n"
        "    return total_tokens == 0\n"
    )
    assert not _scan_code(code)


def _selftest_hmac_digest_positive() -> None:
    code = (
        "import hmac\n"
        "def valid(sig):\n"
        "    return sig == hmac.new(b'k', b'm', 'sha256').hexdigest()\n"
    )
    issues = _scan_code(code)
    assert len(issues) == 1, issues
    assert issues[0][1] == 3


def _selftest_run_finds_secret_eq(tmp_prefix: str = "ubs_core_ctcompare_py_") -> None:
    import tempfile

    code = (
        "def reset(password, candidate):\n"
        "    return password == candidate\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "secrets.py"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.ctcompare.secret_eq"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("secret_eq_positive", _selftest_secret_eq_positive),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("counter_compare_negative", _selftest_counter_compare_negative),
    ("hmac_digest_positive", _selftest_hmac_digest_positive),
    ("run_finds_secret_eq", _selftest_run_finds_secret_eq),
)

register(Analyzer(layer="ctcompare", lang="python", name="ctcompare_py", run=run, selftests=SELF_TESTS))
