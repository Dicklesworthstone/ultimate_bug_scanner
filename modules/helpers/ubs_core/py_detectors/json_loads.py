"""ubs_core.py_detectors.json_loads — category 9 json.loads without try (bead 0xjg.5).

Port of the cat-9 heredoc (modules/ubs-python.sh 11400-11456): an ast walker
flagging every ``json.loads(...)`` call — Attribute ``loads`` on a Name
``json`` — that has no enclosing ``ast.Try`` ancestor. Each unguarded call is
one detection (the heredoc's count has no dedupe; its 3-example cap was
display-only), reported at the call's own ``node.lineno``.

The literal heredoc applied no ubs:ignore filtering; the contract-mandated
suppression (marker on the hit line or the line immediately before) is added
here so annotated call sites stay silent. The ast-grep pack rules
``py.json.loads-no-try`` / ``py.json-load-no-try`` keep firing alongside, as
they did in legacy (heredoc + pack were both counted).
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
            current = parents.get(node)
            while current is not None and not isinstance(current, ast.Try):
                current = parents.get(current)
            if current is not None:
                continue  # inside a try block — guarded
            line_no = node.lineno
            if _suppressed(lines, line_no):
                continue
            idx = line_no - 1
            detail = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ""
            yield path, line_no, node.col_offset + 1, detail
