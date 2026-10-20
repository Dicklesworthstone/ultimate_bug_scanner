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
  an owning wrapper (``contextlib.closing(...)``, ``ExitStack.enter_context``);
- it is assigned to a name (or attribute) that has ``.close()`` called on it
  somewhere in the file;
- an integer descriptor from resolved ``os.open`` is immediately registered
  with a live ``ExitStack`` or transferred to a resolved ``os.fdopen`` context.

Passing the handle straight to another call does *not* manage it:
``json.load(open(p))`` leaks the file object and is still reported. The
``.close()`` search is file-wide rather than scope-aware on purpose — a missed
close would be a false positive, and this rule is a warning.

Ratio semantics are preserved: when nothing is unmanaged the detector is
silent and the "File usage appears context-managed" good finding is rendered
upstream, exactly as the legacy `else` branch did.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions

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
    """Names (and attribute tails) with a `.close()` call anywhere in `scope`."""
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


def _owned_descriptors(tree: ast.AST) -> tuple[set[int], set[int]]:
    """Exact stdlib ownership of integer os.open descriptors.

    Integers cannot supply .close(). Registering os.close with a live stack
    immediately after allocation transfers ownership on every later exit.
    Require resolved imports and no manager escape or rebinding; an arbitrary
    callback method, unclosed descriptor or shadowed API establishes nothing.
    """
    nodes = tuple(ast.walk(tree))
    parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name in {'os', 'contextlib'}:
                    aliases[name.asname or name.name] = name.name
        elif isinstance(node, ast.ImportFrom) and node.module in {'os', 'contextlib'}:
            for name in node.names:
                if name.name in {'open', 'close', 'fdopen', 'ExitStack'}:
                    aliases[name.asname or name.name] = f'{node.module}.{name.name}'

    def root_name(node):
        while isinstance(node, ast.Attribute):
            node = node.value
        return node.id if isinstance(node, ast.Name) else ''

    invalid = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            invalid.add(node.id)
        elif isinstance(node, ast.arg):
            invalid.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            invalid.add(node.name)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            invalid.add(root_name(node))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
                'exec', 'eval', 'globals', 'locals', 'vars'}:
            invalid.update(aliases)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for name in node.names:
                local = name.asname or name.name.split('.')[0]
                actual = name.name if isinstance(node, ast.Import) else f'{node.module}.{name.name}'
                if local in aliases and aliases[local] != actual:
                    invalid.add(local)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in aliases:
            identity = aliases[node.id]
            parent = parents.get(node)
            if identity in {'os', 'contextlib'} and not (
                    isinstance(parent, ast.Attribute) and parent.value is node):
                invalid.add(node.id)
            elif identity == 'contextlib.ExitStack' and not (
                    isinstance(parent, ast.Call) and parent.func is node):
                invalid.add(node.id)
    aliases = {name: value for name, value in aliases.items() if name not in invalid}

    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, '')
        if isinstance(node, ast.Attribute):
            base = qualified(node.value)
            return f'{base}.{node.attr}' if base else ''
        return ''

    descriptors = {id(node) for node in nodes if isinstance(node, ast.Call)
                   and qualified(node.func) == 'os.open'}
    managed = set()

    # A builtin open context owns the descriptor returned by its opener.
    # Require the inline callback to return os.open directly, and prove that
    # `open` is not rebound/imported or replaced through dynamic code.
    bound_names = invalid | {name.asname or name.name.split('.')[0]
                             for node in nodes if isinstance(node, (ast.Import, ast.ImportFrom))
                             for name in node.names}
    builtin_open = 'open' not in bound_names and not any(
        (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
         and node.func.id in {'exec', 'eval', 'globals', 'locals', 'vars'})
        or (isinstance(node, ast.Attribute) and node.attr == 'open'
            and isinstance(node.ctx, (ast.Store, ast.Del))) for node in nodes)
    if builtin_open:
        for node in nodes:
            if not (isinstance(node, ast.With)):
                continue
            for item in node.items:
                call = item.context_expr
                if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == 'open'):
                    continue
                if any(keyword.arg is None or (keyword.arg == 'closefd' and not (
                        isinstance(keyword.value, ast.Constant) and keyword.value.value is True))
                       for keyword in call.keywords):
                    continue
                for keyword in call.keywords:
                    if (keyword.arg == 'opener' and isinstance(keyword.value, ast.Lambda)
                            and id(keyword.value.body) in descriptors):
                        managed.add(id(keyword.value.body))

    def statement_blocks(node):
        # Conditional/loop bodies execute within the same stack lifetime.
        # A nested callable or class body does not establish ownership here.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                if value and all(isinstance(child, ast.stmt) for child in value):
                    yield value
                for child in value:
                    if isinstance(child, ast.AST):
                        yield from statement_blocks(child)
            elif isinstance(value, ast.AST):
                yield from statement_blocks(value)

    def allocation_name(statement):
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and id(statement.value) in descriptors):
            return statement.targets[0].id
        return ''

    # fdopen takes ownership only when closefd is true. Require an immediate
    # first context expression with inert arguments: an earlier context or a
    # dynamic argument can raise before the transfer and leak the descriptor.
    for parent in nodes:
        for _, block in ast.iter_fields(parent):
            if not isinstance(block, list) or not all(isinstance(child, ast.stmt) for child in block):
                continue
            for allocation, following in zip(block, block[1:]):
                name = allocation_name(allocation)
                if not name or not isinstance(following, ast.With) or not following.items:
                    continue
                call = following.items[0].context_expr
                if not (isinstance(call, ast.Call) and qualified(call.func) == 'os.fdopen'
                        and 1 <= len(call.args) <= 2 and isinstance(call.args[0], ast.Name)
                        and call.args[0].id == name):
                    continue
                modes = [call.args[1]] if len(call.args) == 2 else []
                valid = True
                for keyword in call.keywords:
                    if keyword.arg == 'mode' and not modes:
                        modes.append(keyword.value)
                    elif not (keyword.arg == 'closefd' and isinstance(keyword.value, ast.Constant)
                              and keyword.value.value is True):
                        valid = False
                if valid and all(isinstance(mode, ast.Constant) and isinstance(mode.value, str)
                                 and mode.value in {'r', 'w', 'a', 'rb', 'wb', 'ab'} for mode in modes):
                    managed.add(id(allocation.value))

    for node in nodes:
        if not isinstance(node, ast.With) or len(node.items) != 1:
            continue
        for item in node.items:
            if not (isinstance(item.context_expr, ast.Call)
                    and qualified(item.context_expr.func) == 'contextlib.ExitStack'
                    and not item.context_expr.args and not item.context_expr.keywords
                    and isinstance(item.optional_vars, ast.Name)):
                continue
            manager = item.optional_vars.id
            blocks = list(statement_blocks(node))
            callbacks = [child.value for block in blocks for child in block if isinstance(child, ast.Expr)
                         and isinstance(child.value, ast.Call)
                         and isinstance(child.value.func, ast.Attribute)
                         and isinstance(child.value.func.value, ast.Name)
                         and child.value.func.value.id == manager
                         and child.value.func.attr == 'callback']
            uses = {id(call.func.value) for call in callbacks}
            # A popped/escaped/reassigned manager can abandon its callbacks.
            if any(isinstance(child, ast.Name) and child.id == manager and id(child) not in uses
                   for statement in node.body for child in ast.walk(statement)):
                continue
            for block in blocks:
                for allocation, registration in zip(block, block[1:]):
                    name = allocation_name(allocation)
                    if not (name and isinstance(registration, ast.Expr) and registration.value in callbacks):
                        continue
                    call = registration.value
                    if (len(call.args) == 2 and not call.keywords
                            and qualified(call.args[0]) == 'os.close'
                            and isinstance(call.args[1], ast.Name) and call.args[1].id == name):
                        managed.add(id(allocation.value))
    return descriptors, managed


def _managed(node: ast.Call, parents: dict[ast.AST, ast.AST],
             with_contexts: set[int], closed: set[str]) -> bool:
    # Inside a `with` context expression (possibly wrapped in closing(...)).
    child: ast.AST = node
    while True:
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
    # Assigned to a name that is closed somewhere in the file.
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
    suppressions = SourceSuppressions("python")
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
        index = suppressions.index(path, text)
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
        descriptors, managed_descriptors = _owned_descriptors(tree)
        seen: set[int] = set()  # legacy counted matching LINES, not calls
        for node in ast.walk(tree):
            if not _is_open_call(node) and id(node) not in descriptors:
                continue
            if id(node) in managed_descriptors:
                continue
            if id(node) not in descriptors and _managed(node, parents, with_contexts, closed):
                continue
            line_no = node.lineno
            if line_no in seen:
                continue
            if index.is_suppressed(line_no, RULE_ID):
                continue
            seen.add(line_no)
            code = lines[line_no - 1].strip()[:240] if 0 <= line_no - 1 < len(lines) else ''
            candidates.append((path, line_no, node.col_offset + 1, code))
    # Legacy: only report when some open() lacks a `with`; otherwise the
    # "File usage appears context-managed" good finding is rendered upstream.
    yield from candidates
