"""ubs_core.py_detectors.is_literal — category 4 'is' with literals (bead 0xjg.5).

Port of run_is_literal_comparison_checks (modules/ubs-python.sh 9037-9176):
an ast.NodeVisitor flagging `x is <literal>` / `x is not <literal>` where the
literal operand is an int/float/complex/str/bytes constant, a list/tuple/
dict/set/f-string display, or a unary +/-/~ over one of those. `None`,
`Ellipsis`, and `NotImplemented` are deliberately excluded — identity
comparison is idiomatic there. Findings report at the literal operand's own
line so multi-line comparisons point at the literal.

`True` and `False` are excluded for the same reason, and for a second one:
the advice does not hold for them. `True` and `False` are interned
singletons, so `x is True` is well defined — and it is not equivalent to
`x == True`, because `1 == True` and `1.0 == True` are both true. Code that
writes `value is True or value == 1` is deliberately separating the two;
rewriting it to `==` would be the bug. (The self-scan reported 22 of these,
every one of them a tri-state check.)

Same-file and previous-line `ubs:ignore` markers suppress a hit (9102-9108).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.comparison.is-literal"
CATEGORY = 4
TITLE = "Using 'is' with literals"
SEVERITY = "warning"
DESCRIPTION = "Use '==' (only None uses 'is')"

SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache',
             '.pytest_cache', '.cache', 'build', 'dist'}

LITERAL_CONSTANTS = (int, float, complex, str, bytes)
LITERAL_NODES = (ast.List, ast.Tuple, ast.Dict, ast.Set, ast.JoinedStr)


def _is_literal_operand(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        # bool is a subclass of int: check it first so `x is True` is not
        # reported as an int-literal identity comparison.
        if isinstance(node.value, bool):
            return False
        return isinstance(node.value, LITERAL_CONSTANTS)
    if isinstance(node, LITERAL_NODES):
        return True
    # -1 / +1 / ~0 are literals wearing a unary operator.
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert)):
        return _is_literal_operand(node.operand)
    return False


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            # Parsing a file that really does contain `x is "literal"` makes
            # CPython emit a SyntaxWarning of its own; suppress it.
            warnings.simplefilter('ignore', SyntaxWarning)
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        seen: set[int] = set()
        stack = [tree]
        while stack:
            node = stack.pop()
            for child in ast.iter_child_nodes(node):
                stack.append(child)
            if not isinstance(node, ast.Compare):
                continue
            operands = [node.left] + list(node.comparators)
            for index, op in enumerate(node.ops):
                if not isinstance(op, (ast.Is, ast.IsNot)):
                    continue
                # `operands` is built one longer than `ops` — ubs:ignore[py.collections.index-arithmetic]
                left, right = operands[index], operands[index + 1]
                if not (_is_literal_operand(left) or _is_literal_operand(right)):
                    continue
                # Report at the operand's own line so multi-line comparisons
                # point at the literal rather than the start of the statement.
                target = right if _is_literal_operand(right) else left
                line_no = getattr(target, 'lineno', getattr(node, 'lineno', 0))
                if line_no in seen or line_no <= 0:
                    continue
                idx = line_no - 1
                if any(
                    0 <= i < len(lines) and 'ubs:ignore' in lines[i]
                    for i in (idx, idx - 1)
                ):
                    continue
                seen.add(line_no)
                code = lines[idx].strip() if 0 <= idx < len(lines) else ''
                yield path, line_no, 1, code
