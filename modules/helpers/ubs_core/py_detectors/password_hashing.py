"""ubs_core.py_detectors.password_hashing — weak/plaintext password hashing.

Port of run_password_hashing_checks (modules/ubs-python.sh 3798-4044): an
ast.NodeVisitor flagging werkzeug ``generate_password_hash`` calls with a weak
method, passlib ``CryptContext(schemes=[...])`` with a weak scheme,
``PASSWORD_HASHERS`` settings containing weak Django hasher strings,
``make_password(hasher=...)`` with a weak scheme, and direct use of weak
passlib hashers (``passlib.hash.md5_crypt`` et al).

Same-file and previous-line ``ubs:ignore`` markers suppress a hit, and hits
are line-deduped per file (legacy ``seen_lines``).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.password-hashing"
CATEGORY = 7
TITLE = "Weak or plaintext password hashing configured"
SEVERITY = "critical"
DESCRIPTION = "Use Argon2, bcrypt, scrypt, or PBKDF2-SHA256 with current work factors"

WEAK_SCHEMES = {
    'plain', 'plaintext', 'md5', 'sha1', 'unsalted_md5', 'unsalted_sha1',
    'md5_crypt', 'des_crypt', 'ldap_md5', 'ldap_salted_md5', 'pbkdf2_sha1',
}
WEAK_DJANGO_HASHER_RE = re.compile(
    r'(?:^|\.)(?:((?:un)?salted)?(?:md5|sha1)|pbkdf2sha1)passwordhasher$|(?:^|\.)cryptpasswordhasher$',
    re.IGNORECASE,
)


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''


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
    if isinstance(target, ast.Attribute):
        return [call_name(target)]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []


def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def normalized_scheme(value):
    text = value.strip().lower()
    if ':' in text:
        return text.split(':', 1)[0]
    return text


def is_weak_scheme_string(value):
    scheme = normalized_scheme(value)
    lowered = value.strip().lower()
    return scheme in WEAK_SCHEMES or lowered.startswith('pbkdf2:sha1') or bool(WEAK_DJANGO_HASHER_RE.search(value))


def string_literals(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            yield from string_literals(elt)
    elif isinstance(node, ast.Dict):
        for key in node.keys:
            if key is not None:
                yield from string_literals(key)
        for value in node.values:
            yield from string_literals(value)


def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


class PasswordHashingAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.issues = []
        self.seen_lines = set()
        self.werkzeug_modules = {'werkzeug.security'}
        self.generate_password_hash_names = {'generate_password_hash'}
        self.crypt_context_names = {'CryptContext', 'passlib.context.CryptContext'}
        self.make_password_names = {'make_password', 'django.contrib.auth.hashers.make_password'}
        self.passlib_hash_modules = {'passlib.hash'}
        self.weak_passlib_hashers = set(WEAK_SCHEMES)

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'werkzeug.security':
                self.werkzeug_modules.add(local)
            elif alias.name == 'passlib.hash':
                self.passlib_hash_modules.add(local)
            elif alias.name == 'passlib.context':
                self.crypt_context_names.add(f'{local}.CryptContext')
            elif alias.name == 'django.contrib.auth.hashers':
                self.make_password_names.add(f'{local}.make_password')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'werkzeug.security' and alias.name == 'generate_password_hash':
                self.generate_password_hash_names.add(local)
            elif module == 'passlib.context' and alias.name == 'CryptContext':
                self.crypt_context_names.add(local)
            elif module == 'django.contrib.auth.hashers' and alias.name == 'make_password':
                self.make_password_names.add(local)
            elif module == 'passlib.hash':
                if alias.name in WEAK_SCHEMES:
                    self.weak_passlib_hashers.add(local)
        self.generic_visit(node)

    def is_generate_password_hash(self, name):
        return name in self.generate_password_hash_names or any(name == f'{module}.generate_password_hash' for module in self.werkzeug_modules)

    def is_crypt_context(self, name):
        return name in self.crypt_context_names

    def is_make_password(self, name):
        return name in self.make_password_names

    def passlib_hasher_is_weak(self, name):
        parts = name.split('.')
        if len(parts) >= 2 and parts[-1] in {'hash', 'verify'}:
            owner = parts[-2]
            if owner in self.weak_passlib_hashers or owner in WEAK_SCHEMES:
                return True
        for module in self.passlib_hash_modules:
            prefix = f'{module}.'
            if name.startswith(prefix):
                rest = name[len(prefix):].split('.')
                if rest and rest[0] in WEAK_SCHEMES:
                    return True
        return False

    def call_uses_weak_method(self, node, keyword, positional_index=None):
        value = keyword_value(node, keyword)
        if value is None and positional_index is not None and len(node.args) > positional_index:
            value = node.args[positional_index]
        literal = const_string(value) if value is not None else None
        return bool(literal and is_weak_scheme_string(literal))

    def crypt_context_is_weak(self, node):
        schemes = keyword_value(node, 'schemes')
        if schemes is None:
            return False
        return any(is_weak_scheme_string(value) for value in string_literals(schemes))

    def password_hashers_value_is_weak(self, node):
        return any(is_weak_scheme_string(value) for value in string_literals(node))

    def visit_Assign(self, node):
        if any(name.endswith('PASSWORD_HASHERS') for target in node.targets for name in target_names(target)):
            if self.password_hashers_value_is_weak(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        if self.is_generate_password_hash(name) and self.call_uses_weak_method(node, 'method', positional_index=1):
            self.remember_issue(node.lineno)
        elif self.is_crypt_context(name) and self.crypt_context_is_weak(node):
            self.remember_issue(node.lineno)
        elif self.is_make_password(name) and self.call_uses_weak_method(node, 'hasher', positional_index=1):
            self.remember_issue(node.lineno)
        elif self.passlib_hasher_is_weak(name):
            self.remember_issue(node.lineno)
        self.generic_visit(node)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        analyzer = PasswordHashingAnalyzer(text.splitlines())
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
