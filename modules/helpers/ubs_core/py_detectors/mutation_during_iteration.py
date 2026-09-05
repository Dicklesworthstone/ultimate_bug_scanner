"""ubs_core.py_detectors.mutation_during_iteration — category 3 (bead 0xjg.5).

Verbatim port of the "Mutation during iteration" heredoc
(modules/ubs-python.sh 10794-10853): an ast walk flagging `for x in items:`
loops whose body mutates the iterated name — a mutating method call
(items.append/extend/insert/pop/remove/clear/update/discard/add) on the
plain iterated name, or a plain-name assignment / augmented assignment to
it. The check covers ONLY node.body (not orelse), exactly like the legacy
body_mutates() wrapper that re-wraps the body in an ast.Module; only
ast.For (not ast.AsyncFor) and only ast.Name iterators, like legacy.

Legacy counted one hit per mutating loop (no line dedupe) and printed ONE
warning "Possible mutation during iteration" with an examples description;
v2 yields one record per mutating loop, reporting the loop line with its
code sample as the detail. The heredoc walked rglob("*.py"), so .pyi files
are not scanned here.

`ubs:ignore` on the hit line or the line immediately before suppresses a
record, mirroring the marker semantics of the other detector ports (the
legacy heredoc predated the marker).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_scan import MARKER

RULE_ID = "py.collections.mutation-during-iteration"
CATEGORY = 3
TITLE = "Possible mutation during iteration"
SEVERITY = "warning"
DESCRIPTION = "Copy or iterate over snapshot"

# Legacy skip set, checked against the path parts below the scan root.
SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', '.tox', '__pycache__'}

# Verbatim from the heredoc's mutating_attrs set.
MUTATING_ATTRS = {"append", "extend", "insert", "pop", "remove", "clear",
                  "update", "discard", "add"}


def _body_mutates(body, name):
    """Verbatim port of the heredoc body_mutates(): does any statement in
    `body` call a mutating method on `name` or (aug)assign to it?"""
    module = ast.Module(body=body, type_ignores=[])
    for node in ast.walk(module):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == name and func.attr in MUTATING_ATTRS:
                    return True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return True
        elif isinstance(node, ast.AugAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id == name:
                return True
    return False


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() != '.py':
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.For) or not isinstance(node.iter, ast.Name):
                continue
            if not _body_mutates(node.body, node.iter.id):
                continue
            line_no = node.lineno
            idx = line_no - 1
            if any(0 <= i < len(lines) and MARKER in lines[i] for i in (idx, idx - 1)):
                continue
            code = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ''
            yield path, line_no, 1, code
