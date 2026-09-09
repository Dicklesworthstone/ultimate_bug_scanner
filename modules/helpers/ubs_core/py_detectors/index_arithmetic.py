"""ubs_core.py_detectors.index_arithmetic — category 3 index arithmetic (GH self-scan).

Replaces the line regex that used to live in ``ubs_core.py_patterns.foundations``
(``\\[\\s*name\\s*[+-]\\s*digits\\s*\\]`` — legacy ubs-python.sh 10786-10791). The
regex matched the *shape* `x[i + 1]` and nothing else, so it reported every
guarded neighbour lookup a text scanner performs:

    if i + 1 < len(line) and line[i + 1] == '/':      # bound checked inline
    for idx, _ in enumerate(lines, start=1): lines[idx - 1]   # 1-based idiom

Both are in-bounds by construction. On the ubs tree itself the regex produced
224 warnings, all of them guarded — the rule was measuring "does this project
scan text", not "can this index go out of range".

This port keeps the legacy shape (an identifier plus or minus an integer
literal, directly inside a subscript) and the legacy severity ladder, and adds
the missing question: *is the offset bounded?* An access is treated as guarded
when any of these hold:

1. **A bounding comparison is in scope.** Every enclosing ``if`` / ``while`` /
   ``assert`` test, conditional expression, comprehension filter, and every
   earlier operand of the enclosing boolean expression is searched for a
   comparison that bounds the index on the side the offset moves toward.
   ``i + 1 < len(line)`` and ``0 <= idx - 1`` guard a forward and a backward
   offset respectively; ``idx == 0 or …`` is the equality form of a lower
   bound.
2. **The loop supplies the bound.** ``for i in range(len(x) - 1)`` covers
   ``x[i + 1]``; ``for i in range(1, n)`` covers ``x[i - 1]``; and
   ``for i, v in enumerate(seq, start=1)`` covers ``seq[i - 1]`` — the offset
   exactly undoes the ``start``.
3. **An early exit removed the bad case.** ``if start <= 0: break`` (or
   ``continue`` / ``return`` / ``raise``) earlier in the same block means the
   surviving path knows ``start > 0``.
4. **IndexError is handled.** The access sits under a ``try`` whose handlers
   name ``IndexError``, ``LookupError`` or a bare ``except``.

A negative index is not an IndexError in Python (``x[-1]`` wraps), but it is
still a logic bug, so an unguarded ``x[i - 1]`` under a plain
``enumerate(seq)`` is reported exactly as legacy did.

Ladder (legacy 10786-10791), on the project-wide count of unguarded lines:
    warning > 12  "Array index arithmetic - verify bounds"
    info    > 0   "Index arithmetic present - review"
The info tier gets its own id, ``py.collections.index-arithmetic-info``,
mirroring ``ruby.collections.index-arithmetic-info``.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_scan import MARKER

RULES = (
    ("py.collections.index-arithmetic", 3,
     "Array index arithmetic - verify bounds", "warning",
     "Check the offset against len() before indexing"),
    ("py.collections.index-arithmetic-info", 3,
     "Index arithmetic present - review", "info", ""),
)

# Legacy ladder (ubs-python.sh 10786-10791): warning above 12, else info.
WARNING_ABOVE = 12

_UPPER_OPS = (ast.Lt, ast.LtE)
_LOWER_OPS = (ast.Gt, ast.GtE)
_EQ_OPS = (ast.Eq, ast.NotEq)

# `except IndexError` / `except LookupError` / bare `except` all absorb an
# out-of-range subscript.
_INDEX_ERRORS = frozenset({"IndexError", "LookupError", "Exception", "BaseException"})


def _offset(slice_node: ast.AST) -> tuple[str, int] | None:
    """(index name, signed offset) for the legacy `name ± int` slice shape."""
    if not isinstance(slice_node, ast.BinOp):
        return None
    if not isinstance(slice_node.op, (ast.Add, ast.Sub)):
        return None
    name, const = slice_node.left, slice_node.right
    if not isinstance(name, ast.Name):
        return None
    if not (isinstance(const, ast.Constant) and isinstance(const.value, int)
            and not isinstance(const.value, bool)):
        return None
    delta = const.value if isinstance(slice_node.op, ast.Add) else -const.value
    return name.id, delta


def _mentions(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _compare_bounds(
    node: ast.AST, name: str, want_upper: bool, *, negate: bool = False
) -> bool:
    """True when `node` contains a comparison bounding `name` on the wanted side.

    ``negate`` flips the sense of every comparison, for the early-exit idiom:
    after ``if start <= 0: break`` the surviving path knows ``start > 0``.
    """
    for cmp_node in ast.walk(node):
        if not isinstance(cmp_node, ast.Compare):
            continue
        operands = [cmp_node.left] + list(cmp_node.comparators)
        for i, op in enumerate(cmp_node.ops):
            # `operands` is built one longer than `ops` — ubs:ignore[py.collections.index-arithmetic]
            left, right = operands[i], operands[i + 1]
            left_has, right_has = _mentions(left, name), _mentions(right, name)
            if not (left_has or right_has):
                continue
            if isinstance(op, _EQ_OPS):
                return True  # `idx == 0 or …` / `if i != 0:` — an explicit case split
            upper_op = isinstance(op, _UPPER_OPS)
            if not upper_op and not isinstance(op, _LOWER_OPS):
                continue
            if negate:
                upper_op = not upper_op
            # left < right bounds `left` from above and `right` from below.
            if (left_has and upper_op == want_upper) or (
                right_has and upper_op != want_upper
            ):
                return True
    return False


_TERMINATORS = (ast.Break, ast.Continue, ast.Return, ast.Raise)


def _early_exit_bounds(block: list[ast.stmt], upto: ast.AST,
                       name: str, want_upper: bool) -> bool:
    """`if <not in range>: break` earlier in the same block bounds the index."""
    for stmt in block:
        if stmt is upto:
            return False
        if not isinstance(stmt, ast.If) or stmt.orelse:
            continue
        if not all(isinstance(inner, _TERMINATORS) for inner in stmt.body):
            continue
        if _compare_bounds(stmt.test, name, want_upper, negate=True):
            return True
    return False


def _range_guards(call: ast.Call, want_upper: bool, offset: int) -> bool:
    """`for i in range(...)`: does the range keep `i ± offset` in bounds?"""
    if not (isinstance(call.func, ast.Name) and call.func.id == "range"):
        return False
    args = call.args
    if want_upper:
        # A stop of `len(x) - k` covers a forward offset of at most k.
        stop = args[1] if len(args) >= 2 else (args[0] if args else None)
        if stop is None:
            return False
        if (isinstance(stop, ast.BinOp) and isinstance(stop.op, ast.Sub)
                and isinstance(stop.right, ast.Constant)
                and isinstance(stop.right.value, int)):
            return stop.right.value >= offset
        return False
    # A start of k covers a backward offset of at most k.
    if len(args) < 2:
        return False
    start = args[0]
    return (isinstance(start, ast.Constant) and isinstance(start.value, int)
            and not isinstance(start.value, bool) and start.value >= offset)


def _enumerate_guards(call: ast.Call, want_upper: bool, offset: int) -> bool:
    """`for i, v in enumerate(seq, start=k)`: `seq[i - k]` is exactly in range."""
    if not (isinstance(call.func, ast.Name) and call.func.id == "enumerate"):
        return False
    if want_upper:
        return False  # enumerate never leaves room above the last index
    start: ast.AST | None = call.args[1] if len(call.args) >= 2 else None
    for kw in call.keywords:
        if kw.arg == "start":
            start = kw.value
    if not (isinstance(start, ast.Constant) and isinstance(start.value, int)
            and not isinstance(start.value, bool)):
        return False
    return start.value >= offset


def _handles_index_error(node: ast.Try) -> bool:
    for handler in node.handlers:
        if handler.type is None:
            return True
        names = [handler.type] if not isinstance(handler.type, ast.Tuple) else handler.type.elts
        for entry in names:
            label = entry.attr if isinstance(entry, ast.Attribute) else getattr(entry, "id", "")
            if label in _INDEX_ERRORS:
                return True
    return False


def _guarded(
    node: ast.Subscript,
    name: str,
    delta: int,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    want_upper = delta > 0
    offset = abs(delta)
    child: ast.AST = node
    parent = parents.get(child)
    while parent is not None:
        if isinstance(parent, ast.BoolOp):
            # Short-circuit: only operands evaluated before this one can guard.
            for value in parent.values:
                if value is child:
                    break
                if _compare_bounds(value, name, want_upper):
                    return True
        elif isinstance(parent, (ast.If, ast.While, ast.IfExp)):
            if child is not parent.test and _compare_bounds(parent.test, name, want_upper):
                return True
        elif isinstance(parent, ast.Assert):
            if child is not parent.test and _compare_bounds(parent.test, name, want_upper):
                return True
        elif isinstance(parent, ast.comprehension):
            if any(_compare_bounds(cond, name, want_upper) for cond in parent.ifs):
                return True
        elif isinstance(parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for gen in parent.generators:
                if any(_compare_bounds(cond, name, want_upper) for cond in gen.ifs):
                    return True
                if _loop_guards(gen.target, gen.iter, name, want_upper, offset):
                    return True
        elif isinstance(parent, (ast.For, ast.AsyncFor)):
            if _loop_guards(parent.target, parent.iter, name, want_upper, offset):
                return True
        elif isinstance(parent, ast.Try):
            if child in parent.body and _handles_index_error(parent):
                return True
        for block_name in ("body", "orelse", "finalbody"):
            block = getattr(parent, block_name, None)
            if isinstance(block, list) and any(stmt is child for stmt in block):
                if _early_exit_bounds(block, child, name, want_upper):
                    return True
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module,
                               ast.ClassDef, ast.Lambda)):
            break
        child = parent
        parent = parents.get(child)
    return False


def _loop_guards(
    target: ast.AST, iterated: ast.AST, name: str, want_upper: bool, offset: int
) -> bool:
    """Does this loop header bind `name` such that `name ± offset` is in range?"""
    bound_names = {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
    if name not in bound_names:
        return False
    if not isinstance(iterated, ast.Call):
        return False
    return (_range_guards(iterated, want_upper, offset)
            or _enumerate_guards(iterated, want_upper, offset))


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    hits: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        seen: set[int] = set()  # DISTINCT lines, as the legacy line count did
        for node in ast.walk(tree):
            if not isinstance(node, ast.Subscript):
                continue
            shape = _offset(node.slice)
            if shape is None:
                continue
            name, delta = shape
            if delta == 0:
                continue
            if _guarded(node, name, delta, parents):
                continue
            line_no = node.slice.lineno
            if line_no in seen:
                continue
            idx = line_no - 1
            if any(0 <= i < len(lines) and MARKER in lines[i] for i in (idx, idx - 1)):
                continue
            seen.add(line_no)
            code = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ''
            hits.append((path, line_no, node.col_offset + 1, code))
    if not hits:
        return
    rule = ("py.collections.index-arithmetic" if len(hits) > WARNING_ABOVE
            else "py.collections.index-arithmetic-info")
    for path, line_no, col, code in hits:
        yield rule, path, line_no, col, code
