"""ubs_core.py_detectors.file_permissions — world-writable modes / umask(0).

Port of run_file_permission_checks (modules/ubs-python.sh 4739-4945): an
ast.NodeVisitor flagging chmod/lchmod/fchmod/fchmodat and mkdir/makedirs
calls with a world-writable mode (``& 0o002``), ``os.open`` with a
world-writable mode, and ``umask(0)``. Constant modes resolve through
``stat.S_I*`` bit names and simple tracked assignments (``mode = 0o777``).

Same-file and previous-line ``ubs:ignore`` markers suppress a hit, and hits
are line-deduped per file (legacy ``seen_lines``).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.file-permissions"
CATEGORY = 7
TITLE = "World-writable file mode or permissive umask"
SEVERITY = "critical"
DESCRIPTION = ("Avoid 0o777/0o666-style modes and umask(0); use least-privilege modes such as "
               "0o700 for directories and 0o600/0o640 for files")

STAT_MODE_BITS = {
    'S_IRUSR': 0o400, 'S_IWUSR': 0o200, 'S_IXUSR': 0o100,
    'S_IRGRP': 0o040, 'S_IWGRP': 0o020, 'S_IXGRP': 0o010,
    'S_IROTH': 0o004, 'S_IWOTH': 0o002, 'S_IXOTH': 0o001,
    'S_IRWXU': 0o700, 'S_IRWXG': 0o070, 'S_IRWXO': 0o007,
}


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


def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def short_name(name):
    return name.rsplit('.', 1)[-1] if name else ''


def mode_value(node, mode_names):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in mode_names:
            return mode_names[node.id]
        if node.id in STAT_MODE_BITS:
            return STAT_MODE_BITS[node.id]
    if isinstance(node, ast.Attribute):
        name = call_name(node)
        attr = short_name(name)
        if attr in STAT_MODE_BITS and (name.startswith('stat.') or attr == name):
            return STAT_MODE_BITS[attr]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = mode_value(node.left, mode_names)
        right = mode_value(node.right, mode_names)
        if left is not None and right is not None:
            return left | right
    return None


def is_world_writable(mode):
    return mode is not None and bool(mode & 0o002)


def has_insecure_mode_arg(node, mode_names, positional_index):
    mode_node = keyword_value(node, 'mode')
    if mode_node is None and len(node.args) > positional_index:
        mode_node = node.args[positional_index]
    return is_world_writable(mode_value(mode_node, mode_names))


class FilePermissionAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.mode_names = {}
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((line_no, source_line(self.lines, line_no)))

    def mark_assignment(self, names, value):
        value = mode_value(value, self.mode_names)
        for name in names:
            if value is None:
                self.mode_names.pop(name, None)
            else:
                self.mode_names[name] = value

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
        name = call_name(node.func)
        short = short_name(name)
        if short in {'chmod', 'lchmod', 'fchmod', 'fchmodat'}:
            mode_index = 0 if isinstance(node.func, ast.Attribute) and not name.startswith('os.') else 1
            if has_insecure_mode_arg(node, self.mode_names, positional_index=mode_index):
                self.remember_issue(node.lineno)
        elif short in {'mkdir', 'makedirs'}:
            mode_index = 0 if isinstance(node.func, ast.Attribute) and not name.startswith('os.') else 1
            if has_insecure_mode_arg(node, self.mode_names, positional_index=mode_index):
                self.remember_issue(node.lineno)
        elif name == 'os.open' or short == 'open':
            if name == 'os.open' and has_insecure_mode_arg(node, self.mode_names, positional_index=2):
                self.remember_issue(node.lineno)
        elif short == 'umask':
            mode_node = node.args[0] if node.args else keyword_value(node, 'mask')
            if mode_value(mode_node, self.mode_names) == 0:
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
        analyzer = FilePermissionAnalyzer(text.splitlines())
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield path, line_no, 1, code[:240]
