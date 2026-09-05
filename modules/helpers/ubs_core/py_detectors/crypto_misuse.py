"""ubs_core.py_detectors.crypto_misuse — weak crypto modes / static IVs.

Port of run_crypto_misuse_checks (modules/ubs-python.sh 4046-4297): an
ast.NodeVisitor flagging ECB mode usage, legacy cipher constructors
(DES, TripleDES, ARC4/ARC2, Blowfish, CAST5, IDEA, SEED), and static
IV/nonce material fed to IV-based modes, PyCrypto/PyCryptodome ``new()``
3-arg form, or AEAD ``encrypt``/``decrypt`` calls. Tracks variables bound
to static material and variables bound to AEAD cipher instances.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit, and hits
are line-deduped per file (legacy ``seen_lines``).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.crypto-misuse"
CATEGORY = 7
TITLE = "Weak cryptographic mode, cipher, or static IV/nonce"
SEVERITY = "critical"
DESCRIPTION = ("Use AEAD modes such as AES-GCM or ChaCha20-Poly1305 with fresh random nonces, "
               "and avoid ECB/DES/ARC4/static IVs")

WEAK_ALGORITHMS = {'ARC2', 'ARC4', 'Blowfish', 'CAST5', 'DES', 'IDEA', 'SEED', 'TripleDES'}
IV_MODES = {'CBC', 'CFB', 'CFB8', 'OFB', 'CTR', 'GCM'}
STATIC_PARAM_NAMES = {'iv', 'nonce', 'initial_value', 'initial_counter'}
AEAD_CONSTRUCTORS = {'AESCCM', 'AESGCM', 'ChaCha20Poly1305'}


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


def short_name(name):
    return name.rsplit('.', 1)[-1] if name else ''


def owner_short_name(name):
    parts = name.split('.')
    return parts[-2] if len(parts) >= 2 else ''


def is_int_constant(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, int)


def is_static_literal(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
        return len(node.value) > 0
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    if isinstance(node, (ast.Tuple, ast.List)):
        return bool(node.elts) and all(isinstance(elt, ast.Constant) for elt in node.elts)
    return False


def is_static_material(node, static_names):
    if isinstance(node, ast.Name):
        return node.id in static_names
    if is_static_literal(node):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return is_static_material(node.left, static_names) and is_static_material(node.right, static_names)
        if isinstance(node.op, ast.Mult):
            return (
                is_static_material(node.left, static_names) and is_int_constant(node.right)
            ) or (
                is_static_material(node.right, static_names) and is_int_constant(node.left)
            )
    if isinstance(node, ast.Call):
        name = call_name(node.func)
        short = short_name(name)
        if short in {'bytes', 'bytearray'} and node.args and is_int_constant(node.args[0]):
            return True
        if name in {'bytes.fromhex', 'bytearray.fromhex'} and node.args and is_static_literal(node.args[0]):
            return True
        if short in {'b64decode', 'urlsafe_b64decode', 'unhexlify'} and node.args and is_static_literal(node.args[0]):
            return True
    return False


def is_mode_attr(node, mode_name):
    name = call_name(node)
    return name == f'MODE_{mode_name}' or name.endswith(f'.MODE_{mode_name}')


def is_ecb_mode(node):
    name = call_name(node)
    short = short_name(name)
    if isinstance(node, ast.Call):
        return short == 'ECB'
    return is_mode_attr(node, 'ECB')


def is_iv_mode(node):
    name = call_name(node)
    short = short_name(name)
    if isinstance(node, ast.Call):
        return short in IV_MODES
    return any(is_mode_attr(node, mode) for mode in IV_MODES)


class CryptoMisuseAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.static_names = set()
        self.aead_vars = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, source_line(self.lines, line_no)))

    def mark_assignment(self, names, value):
        constructs_aead = self.call_constructs_aead(value)
        is_static = is_static_material(value, self.static_names)
        for name in names:
            if constructs_aead:
                self.aead_vars.add(name)
            else:
                self.aead_vars.discard(name)
            if is_static:
                self.static_names.add(name)
            else:
                self.static_names.discard(name)

    def call_constructs_aead(self, node):
        return isinstance(node, ast.Call) and short_name(call_name(node.func)) in AEAD_CONSTRUCTORS

    def call_uses_weak_algorithm(self, node):
        name = call_name(node.func)
        short = short_name(name)
        owner = owner_short_name(name)
        return short in WEAK_ALGORITHMS or (short == 'new' and owner in WEAK_ALGORITHMS)

    def call_uses_static_iv_or_nonce(self, node):
        name = call_name(node.func)
        short = short_name(name)
        owner = owner_short_name(name)

        for keyword in node.keywords:
            if keyword.arg in STATIC_PARAM_NAMES and is_static_material(keyword.value, self.static_names):
                return True

        if short in IV_MODES and node.args and is_static_material(node.args[0], self.static_names):
            return True

        if short == 'new' and len(node.args) >= 3 and owner in {'AES', 'DES', 'DES3', 'Blowfish', 'CAST', 'ARC2'}:
            mode = node.args[1]
            if is_iv_mode(mode) and is_static_material(node.args[2], self.static_names):
                return True

        if short in {'encrypt', 'decrypt'} and node.args:
            receiver = call_name(node.func.value) if isinstance(node.func, ast.Attribute) else ''
            receiver_short = short_name(receiver)
            if receiver_short in AEAD_CONSTRUCTORS or receiver in self.aead_vars:
                return is_static_material(node.args[0], self.static_names)

        return False

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

    def visit_Call(self, node):
        if is_ecb_mode(node) or self.call_uses_weak_algorithm(node) or self.call_uses_static_iv_or_nonce(node):
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
        analyzer = CryptoMisuseAnalyzer(text.splitlines())
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
