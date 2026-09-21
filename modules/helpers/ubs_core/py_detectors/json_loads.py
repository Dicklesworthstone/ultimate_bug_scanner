"""ubs_core.py_detectors.json_loads — category 9 json.loads without try (bead 0xjg.5).

Port of the cat-9 heredoc (modules/ubs-python.sh 11400-11456): an ast walker
flagging every ``json.loads(...)`` call — Attribute ``loads`` on a Name
``json`` — that no enclosing ``try`` actually protects. Each unguarded call is
one detection (the heredoc's count has no dedupe; its 3-example cap was
display-only), reported at the call's own ``node.lineno``.

The literal heredoc applied no ubs:ignore filtering; the contract-mandated
suppression (marker on the hit line or the line immediately before) is added
here so annotated call sites stay silent.

This is the only rule for ``json.loads``. The ast-grep pack rule
``py.json.loads-no-try`` used to fire alongside it, so every unguarded call was
reported twice under two ids — a user-visible double count (GH #109 §3). It was
removed rather than kept for parity, because the two disagreed about nothing
except the guard test below, and that half was worth keeping. ``json.load`` is
a different function and keeps its own pack rule, ``py.json-load-no-try``.

What the pack rule got right, and this now does too: a ``try`` only protects
what it wraps if it has an ``except`` clause. ``try: ... finally:`` guarantees
cleanup, not error handling, so the ``json.loads`` inside it still crashes the
caller on malformed input. Neither does a ``try`` protect its own ``except``,
``else`` or ``finally`` bodies — an exception raised there propagates past the
handlers that are already running or have already been skipped. So the guard is
"some enclosing ``try`` has handlers *and* reaches this call through its ``try``
body", not "some ``ast.Try`` is an ancestor".
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.parsing.json-loads-no-try"
CATEGORY = 9
TITLE = "json.loads without error handling"
SEVERITY = "warning"
DESCRIPTION = "Wrap in try/except ValueError"

MARKER = "ubs:ignore"


def _suppressed(lines: list[str], line_no: int) -> bool:
    """Same-line or previous-line ubs:ignore suppresses the hit."""
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def _guarded(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """True when some enclosing ``try`` with handlers wraps this call.

    Walks child-to-parent so the *entry point* into each ``ast.Try`` is known:
    only the ``body`` is protected. Reaching a ``Try`` through ``handlers``,
    ``orelse`` or ``finalbody`` means the call runs after that ``try``'s
    protection has been decided, so the walk continues outward instead of
    stopping — an inner ``finally`` nested in an outer ``try/except`` is still
    guarded by the outer one.
    """
    child = node
    parent = parents.get(child)
    while parent is not None:
        if isinstance(parent, ast.Try) and parent.handlers and child in parent.body:
            return True
        child = parent
        parent = parents.get(child)
    return False


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        # Legacy heredoc walked root.rglob("*.py") — .py only, not .pyi.
        if path.suffix.lower() != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "loads"):
                continue
            if not (isinstance(func.value, ast.Name) and func.value.id == "json"):
                continue
            if _guarded(node, parents):
                continue
            line_no = node.lineno
            if _suppressed(lines, line_no):
                continue
            idx = line_no - 1
            detail = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ""
            yield path, line_no, node.col_offset + 1, detail
