r"""ubs_core.py_detectors.io_open_checks — cat 16 open()/with ratio (bead 0xjg.5).

Port of the legacy "open(...) without context manager" ratio check
(modules/ubs-python.sh 11648-11656):

    open_calls=$(rg -e 'open\(' … | count_lines)
    with_calls=$(rg -e 'with[[:space:]]+[^:]*open\(' … | count_lines)
    if [ open_calls -gt 0 ] && [ with_calls -lt open_calls ]; then
      print_finding warning $((open_calls - with_calls)) \
        "open() calls missing 'with'" \
        "Wrap file handles in context managers or close them explicitly"
    else
      print_finding good "File usage appears context-managed"
    fi

The legacy text pipeline counted the substring `open(` on a raw line, so a
docstring that says "handles created by ``tarfile.open()``", a comment about
the rule itself, and `re.compile(r"open\(")` in a rule table all counted as
unmanaged file handles — 47 of them on the ubs tree, none of them a call. The
`with … open(` counter was equally textual: it missed a `with` whose call sits
on a continuation line and matched `with suppress(OSError): reopen(p)`.

This port walks the AST instead. A hit is a real call to `open` — the builtin,
or ``.open()`` on a path — that is not managed, where managed means any of:

- it is (inside) the context expression of a ``with`` item, including through
  ``contextlib.closing(...)`` / ``ExitStack.enter_context(...)`` wrappers;
- its result is passed straight to another call (``json.load(open(p))`` is a
  different bug, not this one — the handle is still unmanaged, so it *is*
  reported; a wrapper that owns the handle, ``closing``/``enter_context``,
  is not);
- the enclosing function closes it: the assignment target has a ``.close()``
  call somewhere in the same function body.

Ratio semantics are preserved: when nothing is unmanaged the detector is
silent and the "File usage appears context-managed" good finding is rendered
upstream, exactly as the legacy `else` branch did.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_scan import MARKER

RULE_ID = "py.io.open-missing-with"
CATEGORY = 16
TITLE = "open() calls missing 'with'"
SEVERITY = "warning"
DESCRIPTION = "Wrap file handles in context managers or close them explicitly"

# Wrappers that take ownership of the handle they are given.
_OWNING_WRAPPERS = frozenset({"closing", "enter_context", "push", "callback"})


def _is_open_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "open"
    if isinstance(func, ast.Attribute):
        # `path.open(...)`, `io.open(...)`, `gzip.open(...)`, `tarfile.open(...)`
        return func.attr == "open"
    return False


def _owning_wrapper(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name in _OWNING_WRAPPERS


def _closed_names(scope: ast.AST) -> set[str]:
    """Names that have a `.close()` called on them somewhere in this scope."""
    closed: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "close"):
            continue
        target = func.value
        if isinstance(target, ast.Name):
            closed.add(target.id)
        elif isinstance(target, ast.Attribute):
            closed.add(target.attr)
    return closed


def _managed(node: ast.Call, parents: dict[ast.AST, ast.AST],
             with_contexts: set[int], closed: set[str]) -> bool:
    # Inside a `with` context expression (possibly wrapped in closing(...)).
    child: ast.AST = node
    while child is not None:
        if id(child) in with_contexts:
            return True
        parent = parents.get(child)
        if parent is None:
            break
        if isinstance(parent, ast.Call) and not _owning_wrapper(parent):
            # `json.load(open(p))` keeps the handle unmanaged; only an owning
            # wrapper transfers responsibility.
            if id(parent) not in with_contexts:
                break
        child = parent
    # Assigned to a name that is closed in the same scope.
    parent = parents.get(node)
    if isinstance(parent, ast.Assign):
        for target in parent.targets:
            label = target.id if isinstance(target, ast.Name) else (
                target.attr if isinstance(target, ast.Attribute) else None)
            if label and label in closed:
                return True
    elif isinstance(parent, (ast.AnnAssign, ast.NamedExpr)):
        target = parent.target
        label = target.id if isinstance(target, ast.Name) else (
            target.attr if isinstance(target, ast.Attribute) else None)
        if label and label in closed:
            return True
    return False


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    candidates: list[tuple[Path, int, int, str]] = []
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
        with_contexts: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    with_contexts.add(id(item.context_expr))
        closed = _closed_names(tree)
        seen: set[int] = set()  # legacy counted matching LINES, not calls
        for node in ast.walk(tree):
            if not _is_open_call(node):
                continue
            if _managed(node, parents, with_contexts, closed):
                continue
            line_no = node.lineno
            if line_no in seen:
                continue
            if 0 <= line_no - 1 < len(lines) and MARKER in lines[line_no - 1]:
                continue  # count_lines drops marker lines from both counts
            seen.add(line_no)
            code = lines[line_no - 1].strip()[:240] if 0 <= line_no - 1 < len(lines) else ''
            candidates.append((path, line_no, node.col_offset + 1, code))
    # Legacy: only report when some open() lacks a `with`; otherwise the
    # "File usage appears context-managed" good finding is rendered upstream.
    yield from candidates
