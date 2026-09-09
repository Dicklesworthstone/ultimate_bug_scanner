"""ubs_core.py_detectors._pathlike — static "is this expression a path?" hints.

`pathlib.PurePath` overloads ``/`` (``__truediv__``) for path joining, so an
``ast.BinOp`` with ``ast.Div`` is *not* necessarily a division: ``base / name``
is the single most common way to build a path in modern Python. Any detector
that reasons about ``/`` has to tell the two apart or it reports every path
join in the project as a possible division by zero (GH: ubs self-scan reported
78 of 85 "Division by variable" warnings on path joins).

The inference here is deliberately syntactic and file-local — no imports are
resolved, no cross-module types are inferred — because a false "this is a path"
only costs one skipped division, while a false "this is arithmetic" costs a
wrong warning. Three signals, in order of strength:

1. **Constructors and path-returning members.** ``Path(...)``, ``Path.cwd()``,
   ``x.parent``, ``x.resolve()``, ``x.with_suffix(...)`` and friends.
2. **Bindings.** ``p = Path(root)`` / ``p: Path = ...`` / ``def f(p: Path)`` /
   ``for p in root.iterdir()`` make ``p`` path-like for the whole file. The
   analysis is flow-insensitive and runs to a small fixpoint so that
   ``a = Path(x)`` followed by ``b = a / "y"`` marks both.
3. **Naming.** An identifier that ends in ``dir``/``path``/``root``/``folder``
   is path-like — including the *callee* name of a call (``get_cache_dir()``).
   This is the weakest signal, and it never applies to an anonymous result.

The module name starts with ``_`` so ``ubs_core.py_scan.run_detectors`` skips
it when it enumerates detector modules.
"""
from __future__ import annotations

import ast

# Constructors that always produce a PurePath.
_PATH_CTORS = frozenset({
    "Path", "PurePath", "PosixPath", "WindowsPath",
    "PurePosixPath", "PureWindowsPath",
})

# Classmethods/methods on a path that return another path.
_PATH_RETURNING_ATTRS = frozenset({
    "parent", "absolute", "resolve", "expanduser", "with_suffix", "with_name",
    "with_stem", "joinpath", "relative_to", "readlink", "cwd", "home",
})

# `x.parents[0]` is a path; `x.parents` alone is a sequence of paths.
_PATH_SEQUENCE_ATTRS = frozenset({"parents", "iterdir", "glob", "rglob"})

# Type annotations that mean "path".
_PATH_ANNOTATIONS = frozenset({
    "Path", "PurePath", "PosixPath", "WindowsPath",
    "PurePosixPath", "PureWindowsPath", "os.PathLike", "PathLike",
})

# Weakest signal: identifier vocabulary. Suffix match on a lowercased name.
# Deliberately short: `file`, `parent` and `home` are not here because they
# swallow ordinary words (`profile` ends in `file`) and the shapes that matter
# — `x.parent`, `Path.home()`, `p = q.parent` — are already covered by the
# member and binding signals.
_PATH_NAME_SUFFIXES = ("dir", "path", "root", "folder", "cwd")
_PATH_NAME_EXACT = frozenset({"pth", "tempdir"})


def _dotted(node: ast.AST) -> str:
    """Render Name/Attribute chains as `a.b.c`; anything else as ''."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return f"{head}.{node.attr}" if head else node.attr
    return ""


def _annotation_is_path(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return any(name in node.value for name in _PATH_ANNOTATIONS)
    dotted = _dotted(node)
    if dotted:
        return dotted in _PATH_ANNOTATIONS or dotted.rsplit(".", 1)[-1] in _PATH_ANNOTATIONS
    # `Path | None`, `Optional[Path]`, `list[Path]` …
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _annotation_is_path(node.left) or _annotation_is_path(node.right)
    if isinstance(node, ast.Subscript):
        return _annotation_is_path(node.slice) or _annotation_is_path(node.value)
    if isinstance(node, ast.Tuple):
        return any(_annotation_is_path(e) for e in node.elts)
    return False


def _name_looks_path(identifier: str) -> bool:
    low = identifier.lower().rstrip("_")
    if low in _PATH_NAME_EXACT:
        return True
    return any(low.endswith(suffix) for suffix in _PATH_NAME_SUFFIXES)


class PathHints:
    """File-local "is this expression a path?" oracle."""

    def __init__(self, tree: ast.AST) -> None:
        self._names: set[str] = set()
        self._seed(tree)

    # ── public ──────────────────────────────────────────────────────────
    def is_path(self, node: ast.AST, *, allow_name_heuristic: bool = True) -> bool:
        """True when `node` statically looks like a pathlib path."""
        if isinstance(node, ast.Call):
            func = node.func
            tail = func.attr if isinstance(func, ast.Attribute) else _dotted(func)
            if tail in _PATH_CTORS or tail in _PATH_RETURNING_ATTRS:
                return True
            # A helper named `*_dir()` / `get_*_path()` returns a path, not a
            # number. The naming heuristic applies to the callee name only —
            # never to an anonymous call result.
            return allow_name_heuristic and bool(tail) and _name_looks_path(tail)
        if isinstance(node, ast.Attribute):
            if node.attr in _PATH_RETURNING_ATTRS:
                return True
            if self.is_path(node.value, allow_name_heuristic=allow_name_heuristic):
                return True
            return allow_name_heuristic and _name_looks_path(node.attr)
        if isinstance(node, ast.Name):
            if node.id in self._names:
                return True
            return allow_name_heuristic and _name_looks_path(node.id)
        if isinstance(node, ast.Subscript):
            # `x.parents[1]`, `paths[i]`
            value = node.value
            if isinstance(value, ast.Attribute) and value.attr in _PATH_SEQUENCE_ATTRS:
                return True
            return self.is_path(value, allow_name_heuristic=allow_name_heuristic)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            # `a / b` is itself a path when it is a join (see is_path_join).
            right = node.right
            if isinstance(right, ast.Constant) and isinstance(right.value, (str, bytes)):
                return True
            if isinstance(right, ast.JoinedStr):
                return True
            return self.is_path(node.left, allow_name_heuristic=allow_name_heuristic)
        if isinstance(node, ast.IfExp):
            return self.is_path(node.body, allow_name_heuristic=allow_name_heuristic) or \
                self.is_path(node.orelse, allow_name_heuristic=allow_name_heuristic)
        return False

    def is_path_join(self, node: ast.BinOp) -> bool:
        """True when `a / b` is a pathlib join rather than arithmetic.

        The right-hand side of a join is a name/str, never a number, so a
        string constant or f-string denominator alone settles it. Otherwise the
        left operand has to look like a path.
        """
        return self.is_path(node)

    # ── seeding ─────────────────────────────────────────────────────────
    def _seed(self, tree: ast.AST) -> None:
        # Two passes so `a = Path(x)` before `b = a / "y"` marks both, in
        # either source order.
        for _ in range(2):
            before = len(self._names)
            for node in ast.walk(tree):
                self._seed_node(node)
            if len(self._names) == before:
                break

    def _seed_node(self, node: ast.AST) -> None:
        if isinstance(node, ast.AnnAssign):
            if _annotation_is_path(node.annotation):
                self._bind(node.target)
            elif node.value is not None and self.is_path(node.value, allow_name_heuristic=False):
                self._bind(node.target)
        elif isinstance(node, ast.Assign):
            if self.is_path(node.value, allow_name_heuristic=False):
                for target in node.targets:
                    self._bind(target)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            every = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
            if args.vararg is not None:
                every.append(args.vararg)
            if args.kwarg is not None:
                every.append(args.kwarg)
            for arg in every:
                if _annotation_is_path(arg.annotation):
                    self._names.add(arg.arg)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            iterated = node.iter
            if isinstance(iterated, ast.Call):
                iterated = iterated.func
            if isinstance(iterated, ast.Attribute) and iterated.attr in _PATH_SEQUENCE_ATTRS:
                self._bind(node.target)
        elif isinstance(node, ast.withitem):
            pass  # `with open(p) as fh` binds a file object, never a path

    def _bind(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt)
