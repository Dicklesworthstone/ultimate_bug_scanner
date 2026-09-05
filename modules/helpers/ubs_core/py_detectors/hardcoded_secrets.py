"""ubs_core.py_detectors.hardcoded_secrets — category 7 (bead 0xjg.5).

Verbatim port of run_hardcoded_secrets_checks (modules/ubs-python.sh
11028-11323, "Hardcoded secrets" subheader of CATEGORY 7): an ast.NodeVisitor
flagging secret-ish names assigned literal fallbacks. It catches sensitive
targets (`password = "..."`, `self.api_key = "..."`, `CONF["token"] = ...`,
`dict(key="...")` keywords, `os.getenv("SECRET", "fallback")` defaults,
`setdefault` calls and function argument defaults) where the literal is a
plausible credential: >=8 chars, alphanumeric, no whitespace, not a URL,
not a placeholder/example string. Names denoting metadata about a secret
(`token_uri`, `api_key_id`, `token_count`, …) are excluded (#64).

Same-file AND previous-line `ubs:ignore` markers suppress a hit; per-file
line dedupe (legacy `issue_lines`) is preserved. Legacy traversal
(SHOULD_SKIP dirs / rglob) is replaced by the contract file list; the
legacy heredoc accepts .py/.pyi/.pyx. Detail is the source line
(strip, tabs→spaces) exactly like the legacy __SAMPLE__ payloads.
"""
from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.hardcoded-secrets"
CATEGORY = 7
TITLE = "Potential hardcoded secrets"
SEVERITY = "critical"
DESCRIPTION = ("Use secret manager or required env vars; do not keep literal "
               "fallbacks for secret env vars")

EXTS = {'.py', '.pyi', '.pyx'}

SECRET_WORD_RE = re.compile(
    r'(?:'
    r'\bsecret\b|\bpassword\b|\bpasswd\b|\bpwd\b|\btoken\b|\bapi[_-]?key\b|'
    r'\bprivate[_-]?key\b|\bclient[_-]?secret\b|\bwebhook[_-]?secret\b|'
    r'\bjwt[_-]?secret\b|\baccess[_-]?token\b|\brefresh[_-]?token\b|'
    r'\bsession[_-]?secret\b|\bcookie[_-]?secret\b|\bsigning[_-]?secret\b|'
    r'\bencryption[_-]?key\b|\bsecret[_-]?key[_-]?base\b|\bcredential(?:s)?\b'
    r')'
)
SECRET_PHRASE_RE = re.compile(
    r'\b(?:'
    r'api\s+key|private\s+key|client\s+secret|webhook\s+secret|jwt\s+secret|'
    r'access\s+token|refresh\s+token|session\s+secret|cookie\s+secret|'
    r'signing\s+secret|encryption\s+key|secret\s+key\s+base'
    r')\b'
)
PLACEHOLDERS = {
    'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change_me',
    'not_a_secret', 'your_secret_here', 'your-api-key', 'localhost',
    '127.0.0.1', 'http://localhost', 'https://localhost', 'https://example.com',
}

# Names that mention a secret-ish word but denote non-secret metadata about
# it: `token_uri` / `token_url` are OAuth endpoint locations, `api_key_id` is
# an identifier, `token_count` a metric, and so on (#64).
NON_SECRET_SUFFIX_RE = re.compile(
    r'(?:^|_)(?:url|uri|endpoint|host|hostname|domain|path|file|filename|dir|'
    r'name|type|kind|label|prefix|suffix|header|field|param|hint|display|'
    r'id|count|len|length|size|ttl|timeout|expiry|expires|lifetime|max_age)$'
)

# ast.Index is deprecated (3.9+ parsers never produce it) and may be gone
# outright in newer interpreters; the legacy check is kept behind a guard.
_INDEX_CLS = getattr(ast, 'Index', None)


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


def normalize_name(name: str) -> str:
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', str(name or ''))
    text = re.sub(r'[^A-Za-z0-9]+', '_', text)
    return text.lower().strip('_')


def is_sensitive_name(name: str) -> bool:
    normalized = normalize_name(name)
    if NON_SECRET_SUFFIX_RE.search(normalized):
        return False
    spaced = normalized.replace('_', ' ')
    return bool(SECRET_WORD_RE.search(normalized) or SECRET_WORD_RE.search(spaced) or SECRET_PHRASE_RE.search(spaced))


def literal_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def looks_like_secret_literal(value: str) -> bool:
    compact = value.strip()
    lowered = compact.lower()
    if len(compact) < 8:
        return False
    if lowered in PLACEHOLDERS:
        return False
    if 'example.' in lowered or lowered.startswith(('example_', 'sample_', 'dummy_')):
        return False
    if not re.search(r'[A-Za-z0-9]', compact):
        return False
    # URLs are endpoint configuration, not secret material, even when the
    # surrounding name mentions tokens (e.g. an OAuth token endpoint) (#64).
    if '://' in compact:
        return False
    # Real credentials are single opaque strings; anything with internal
    # whitespace is prose (descriptions, messages), not a secret literal.
    if any(ch.isspace() for ch in compact):
        return False
    return True


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def subscript_key_name(node):
    target = node.slice if isinstance(node, ast.Subscript) else None
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return target.value
    if _INDEX_CLS is not None and isinstance(target, _INDEX_CLS) and isinstance(target.value, ast.Constant) and isinstance(target.value.value, str):
        return target.value.value
    return ''


def target_names(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.Subscript):
        key = subscript_key_name(node)
        return [key] if key else []
    if isinstance(node, (ast.Tuple, ast.List)):
        names = []
        for elt in node.elts:
            names.extend(target_names(elt))
        return names
    return []


class HardcodedSecretAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.os_aliases = {'os'}
        self.environ_aliases = {'environ'}
        self.getenv_aliases = set()
        self.issues = []
        self.issue_lines = set()

    def remember_issue(self, node):
        line_no = getattr(node, 'lineno', 0)
        if line_no <= 0 or line_no in self.issue_lines or has_ignore(self.lines, line_no):
            return
        self.issue_lines.add(line_no)
        self.issues.append((self.path, line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == 'os':
                self.os_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == 'os':
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == 'environ':
                    self.environ_aliases.add(local)
                elif alias.name == 'getenv':
                    self.getenv_aliases.add(local)
        self.generic_visit(node)

    def env_fallback(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        is_getenv = name in self.getenv_aliases or any(name == f'{alias}.getenv' for alias in self.os_aliases)
        is_environ_get = any(name == f'{alias}.get' for alias in self.environ_aliases)
        is_os_environ_get = any(name == f'{alias}.environ.get' for alias in self.os_aliases)
        if not (is_getenv or is_environ_get or is_os_environ_get):
            return False
        if not node.args:
            return False
        env_name = literal_string(node.args[0]) or ''
        default_node = node.args[1] if len(node.args) > 1 else None
        for keyword in node.keywords:
            if keyword.arg == 'default':
                default_node = keyword.value
        default = literal_string(default_node) if default_node is not None else None
        return bool(is_sensitive_name(env_name) and default is not None and looks_like_secret_literal(default))

    def value_is_hardcoded_secret(self, node):
        literal = literal_string(node)
        if literal is not None:
            return looks_like_secret_literal(literal)
        return self.env_fallback(node)

    def check_argument_defaults(self, node):
        positional_args = list(getattr(node.args, 'posonlyargs', [])) + list(node.args.args)
        positional_defaults = list(node.args.defaults)
        if positional_defaults:
            for arg, default in zip(positional_args[-len(positional_defaults):], positional_defaults):
                if is_sensitive_name(arg.arg) and self.value_is_hardcoded_secret(default):
                    self.remember_issue(default)
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if default is not None and is_sensitive_name(arg.arg) and self.value_is_hardcoded_secret(default):
                self.remember_issue(default)

    def visit_Assign(self, node):
        sensitive_target = any(is_sensitive_name(name) for target in node.targets for name in target_names(target))
        if sensitive_target and self.value_is_hardcoded_secret(node.value):
            self.remember_issue(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        sensitive_target = any(is_sensitive_name(name) for name in target_names(node.target))
        if sensitive_target and node.value is not None and self.value_is_hardcoded_secret(node.value):
            self.remember_issue(node)
        self.generic_visit(node)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            key_name = literal_string(key) if key is not None else None
            if key_name and is_sensitive_name(key_name) and self.value_is_hardcoded_secret(value):
                self.remember_issue(value)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.env_fallback(node):
            self.remember_issue(node)
        for keyword in node.keywords:
            if keyword.arg and is_sensitive_name(keyword.arg) and self.value_is_hardcoded_secret(keyword.value):
                self.remember_issue(keyword.value)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'setdefault' and len(node.args) >= 2:
            key_name = literal_string(node.args[0]) or ''
            if is_sensitive_name(key_name) and self.value_is_hardcoded_secret(node.args[1]):
                self.remember_issue(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.check_argument_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.check_argument_defaults(node)
        self.generic_visit(node)

    def visit_Lambda(self, node):
        self.check_argument_defaults(node)
        self.generic_visit(node)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in EXTS:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            # The legacy heredoc discarded stderr; parsing fixture files with
            # invalid escapes makes CPython emit its own SyntaxWarning.
            warnings.simplefilter('ignore', SyntaxWarning)
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        analyzer = HardcodedSecretAnalyzer(path, lines)
        analyzer.visit(tree)
        for _path, line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
