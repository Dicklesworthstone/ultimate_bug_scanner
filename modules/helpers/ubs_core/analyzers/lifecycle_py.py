"""ubs_core.analyzers.lifecycle_py — Python resource lifecycle analysis (bead A2).

Logic moved verbatim from modules/helpers/resource_lifecycle_py.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable, Optional

from ubs_core.registry import Analyzer as _RegistryAnalyzer, RunContext, register

TARGET_SIGS: dict[tuple[Optional[str], str], str] = {
    (None, "open"): "file_handle",
    ("builtins", "open"): "file_handle",
    ("io", "open"): "file_handle",
    ("pathlib", "open"): "file_handle",
    ("pathlib.Path", "open"): "file_handle",
    ("tempfile", "NamedTemporaryFile"): "file_handle",
    ("tempfile", "TemporaryFile"): "file_handle",
    ("tempfile", "SpooledTemporaryFile"): "file_handle",
    ("socket", "socket"): "socket_handle",
    ("socket", "create_connection"): "socket_handle",
    ("socket", "socketpair"): "socket_handle",
    ("subprocess", "Popen"): "popen_handle",
    ("asyncio", "create_task"): "asyncio_task",
}

RELEASE_METHODS = {
    "file_handle": {"close"},
    "socket_handle": {"close"},
    "popen_handle": {"wait", "communicate"},
    "asyncio_task": {"cancel"},
}

TASK_SUPERVISOR_SIGS = {
    ("asyncio", "gather"),
    ("asyncio", "wait"),
    ("asyncio", "wait_for"),
}

MESSAGE_TEMPLATES = {
    "file_handle": "File handle {name} opened without context manager or close()",
    "socket_handle": "Socket {name} opened without close()",
    "popen_handle": "subprocess handle {name} never waited for or communicated with",
    "asyncio_task": "asyncio task {name} neither awaited nor cancelled",
}

IGNORED_PARTS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "env",
    "envs",
    "site-packages",
    "target",
}


class ResourceRecord:
    __slots__ = ("name", "kind", "lineno", "released")

    def __init__(self, name: Optional[str], kind: str, lineno: int) -> None:
        self.name = name
        self.kind = kind
        self.lineno = lineno
        self.released = False


class Binding:
    """A resource, collection, supervisor, or context owner; not binding history."""

    __slots__ = ("record", "items", "ordered", "awaited", "cancel_children", "context", "closes_context", "symbol",
                 "releases")

    def __init__(
        self,
        record: Optional[ResourceRecord] = None,
        items: Optional[tuple[Binding, ...]] = None,
        *,
        ordered: bool = True,
        awaited: Optional[tuple[Binding, ...]] = None,
        cancel_children: bool = False,
        context: Optional[Binding] = None,
        closes_context: bool = False,
        symbol: Optional[str] = None,
        releases: tuple[ResourceRecord, ...] = (),
    ) -> None:
        self.record = record
        self.items = items
        self.ordered = ordered
        self.awaited = awaited
        self.cancel_children = cancel_children
        self.context = context
        self.closes_context = closes_context
        self.symbol = symbol
        # A nested function that releases enclosing-scope resources: calling
        # it releases them; merely defining it does not.
        self.releases = releases


UNKNOWN_BINDING = Binding()


class Scope:
    def __init__(self, kind: str = "module") -> None:
        self.kind = kind
        self.by_name: dict[str, Binding] = {}
        self.attribute_children: dict[str, set[str]] = {}
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        # Enclosing-scope resources this function body releases. They count
        # only where the function is called.
        self.deferred_releases: list[ResourceRecord] = []


class _ScopeNames(ast.NodeVisitor):
    """Collect lexical locals without entering deferred bodies or class namespaces."""

    def __init__(self) -> None:
        self.locals: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.locals.add(node.id)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_Import(self, node: ast.Import) -> None:
        self.locals.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.locals.update(alias.asname or alias.name for alias in node.names if alias.name != "*")

    def _defaults(self, args: ast.arguments) -> None:
        for value in (*args.defaults, *args.kw_defaults):
            if value is not None:
                self.visit(value)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.locals.add(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._defaults(node.args)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._defaults(node.args)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.locals.add(node.name)
        for value in (*node.decorator_list, *node.bases):
            self.visit(value)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.locals.add(node.name)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        # Comprehension targets are not locals of the containing function.
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)

    def visit_MatchAs(self, node: ast.AST) -> None:
        if node.name:
            self.locals.add(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node: ast.AST) -> None:
        if node.rest:
            self.locals.add(node.rest)
        self.generic_visit(node)


class Analyzer(ast.NodeVisitor):
    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.records: list[ResourceRecord] = []
        self.call_bindings: dict[int, Binding] = {}
        self.scope_stack: list[Scope] = [Scope()]

    @property
    def current_scope(self) -> Scope:
        return self.scope_stack[-1]

    def _lookup_symbol_binding(self, name: str) -> Optional[Binding]:
        root = name.split(".")[0]
        skip_classes = False
        nonlocal_only = False
        for scope in reversed(self.scope_stack):
            if scope.kind == "class" and skip_classes:
                continue
            if nonlocal_only and scope.kind != "function":
                continue
            if name in scope.by_name:
                return scope.by_name[name]
            if root in scope.globals:
                return self.scope_stack[0].by_name.get(name)
            if root in scope.nonlocals:
                nonlocal_only = True
            skip_classes = True
        return UNKNOWN_BINDING if nonlocal_only else None

    def _lookup_execution_binding(self, name: str) -> Optional[Binding]:
        for scope in reversed(self.scope_stack):
            if name in scope.by_name:
                return scope.by_name[name]
            # Class bodies execute now, whereas merely visiting a function body
            # cannot prove that an outer resource was ever cleaned up.
            if scope.kind == "function":
                break
        return None

    # Scopes -------------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.AST) -> None:
        for decorator in getattr(node, "decorator_list", ()):
            self.visit(decorator)
        for value in (*node.args.defaults, *node.args.kw_defaults):
            if value is not None:
                self.visit(value)
        if not isinstance(node, ast.Lambda):
            self._bind_name(node.name, UNKNOWN_BINDING)
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        names = _ScopeNames()
        for statement in body:
            names.visit(statement)
        args = node.args
        parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        parameters.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
        names.locals.update(arg.arg for arg in parameters)
        scope = Scope("function")
        scope.globals = names.globals
        scope.nonlocals = names.nonlocals
        scope.by_name.update((name, UNKNOWN_BINDING) for name in names.locals - names.globals - names.nonlocals)
        self.scope_stack.append(scope)
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.scope_stack.pop()
        if scope.deferred_releases and not isinstance(node, ast.Lambda):
            self._bind_name(node.name, Binding(releases=tuple(scope.deferred_releases)))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for value in (*node.decorator_list, *node.bases):
            self.visit(value)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.scope_stack.append(Scope("class"))
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope_stack.pop()
        self._bind_name(node.name, UNKNOWN_BINDING)

    # Imports -------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            asname = alias.asname or alias.name.split(".")[0]
            self._bind_name(asname, Binding(symbol=alias.name if alias.asname else asname))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            asname = alias.asname or alias.name
            symbol = f"{module}.{alias.name}" if node.level == 0 and module else None
            self._bind_name(asname, Binding(symbol=symbol))

    # Return/Yield -------------------------------------------------------
    def visit_Return(self, node: ast.Return) -> None:
        if node.value:
            self._handle_return_yield(node.value)
        self.generic_visit(node)

    def visit_Yield(self, node: ast.Yield) -> None:
        if node.value:
            self._handle_return_yield(node.value)
        self.generic_visit(node)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        if node.value:
            self._handle_return_yield(node.value)
        self.generic_visit(node)

    def _handle_return_yield(self, value: ast.AST) -> None:
        # Returning/yielding a resource is an *escape*, not a cleanup. UBS should still
        # report resources that were acquired but never explicitly closed/cancelled.
        #
        # This intentionally errs on the side of catching leaks: callers frequently
        # forget to close handles returned from helpers, and our scanning target is
        # "likely bugs" rather than enforcing ownership conventions.
        _ = value

    # With/async with -----------------------------------------------------
    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node.items, node.body, is_async=False)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node.items, node.body, is_async=True)

    def _visit_with(self, items: list[ast.withitem], body: list[ast.stmt], *, is_async: bool) -> None:
        releases: list[ResourceRecord] = []
        for item in items:
            self.visit(item.context_expr)
            binding = self._binding_from_expr(item.context_expr)
            entered = UNKNOWN_BINDING
            if binding.context is not None:
                if not is_async or not binding.closes_context:
                    entered = binding.context
                    record = entered.record
                    if binding.closes_context and record is not None and "close" in RELEASE_METHODS[record.kind]:
                        releases.append(record)
            elif not is_async and binding.record is not None and binding.record.kind in {
                "file_handle", "socket_handle", "popen_handle"
            }:
                entered = binding
                releases.append(binding.record)
            if item.optional_vars is not None:
                for name, bound in self._target_bindings(item.optional_vars, entered):
                    self._bind_name(name, bound)
        for statement in body:
            self.visit(statement)
        # __exit__ owns the objects captured at entry, even if their names were
        # rebound in the body. Unknown wrappers do not imply ownership transfer.
        for record in releases:
            record.released = True

    # Assignments --------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        # Python evaluates the complete RHS before replacing any target binding.
        self.visit(node.value)
        self._handle_assignment(node.targets, node.value)
        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._handle_assignment([node.target], node.value)
        self.visit(node.target)
        self.visit(node.annotation)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._handle_assignment([node.target], node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        for name in self._collect_names(node.target):
            self._bind_name(name, UNKNOWN_BINDING)

    def visit_Delete(self, node: ast.Delete) -> None:
        self.generic_visit(node)
        for target in node.targets:
            for name in self._collect_names(target):
                self._bind_name(name, UNKNOWN_BINDING)

    def _handle_assignment(self, targets: list[ast.expr], value: ast.AST) -> None:
        binding = self._binding_from_expr(value)
        assignments = [
            pair for target in targets for pair in self._target_bindings(target, binding)
        ]
        for name, bound in assignments:
            self._bind_name(name, bound)

    def _target_bindings(self, target: ast.AST, binding: Binding) -> Iterable[tuple[str, Binding]]:
        if isinstance(target, ast.Starred):
            yield from self._target_bindings(target.value, binding)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            items = binding.items if binding.ordered else None
            stars = [i for i, item in enumerate(target.elts) if isinstance(item, ast.Starred)]
            if len(stars) == 1 and items is not None and len(items) >= len(target.elts) - 1:
                start = stars[0]
                end = len(items) - (len(target.elts) - start - 1)
                items = items[:start] + (Binding(items=items[start:end]),) + items[end:]
            elif items is None or len(items) != len(target.elts):
                items = (UNKNOWN_BINDING,) * len(target.elts)
            for child, item in zip(target.elts, items):
                yield from self._target_bindings(child, item)
        else:
            for name in self._collect_names(target):
                yield name, binding

    def _bind_name(self, name: str, binding: Binding) -> None:
        # Replacing an object also replaces its tracked attributes. Acquisitions
        # remain in self.records, and independent aliases keep their identities.
        for child in self.current_scope.attribute_children.get(name, ()):
            self.current_scope.by_name[child] = UNKNOWN_BINDING
        parts = name.split(".")
        for size in range(1, len(parts)):
            self.current_scope.attribute_children.setdefault(".".join(parts[:size]), set()).add(name)
        self.current_scope.by_name[name] = binding
        if binding.record is not None and binding.record.name is None:
            binding.record.name = name

    def _binding_from_expr(self, expr: ast.AST) -> Binding:
        if isinstance(expr, ast.Call):
            return self.call_bindings.get(id(expr), UNKNOWN_BINDING)
        if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
            return Binding(
                items=tuple(self._binding_from_expr(item) for item in expr.elts),
                ordered=not isinstance(expr, ast.Set),
            )
        if isinstance(expr, ast.NamedExpr):
            return self._binding_from_expr(expr.target)
        if isinstance(expr, (ast.Name, ast.Attribute)):
            name = self._dotted_name(expr)
            binding = self._lookup_execution_binding(name) if name is not None else None
            if binding is not None:
                return binding
            symbol = self._qualified_reference(expr)
            return Binding(symbol=symbol) if symbol is not None else UNKNOWN_BINDING
        return UNKNOWN_BINDING

    def _collect_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Starred):
            return self._collect_names(node.value)
        if isinstance(node, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in node.elts:
                names.extend(self._collect_names(elt))
            return names
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            dotted = self._dotted_name(node)
            return [dotted] if dotted else []
        return []

    # Calls/releases -----------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        sig = self._call_signature(node)
        if sig in TARGET_SIGS:
            if sig == ("socket", "socketpair"):
                # A socketpair allocates two independently owned descriptors.
                self.call_bindings[id(node)] = Binding(items=tuple(
                    Binding(self._add_record(None, "socket_handle", node.lineno))
                    for _ in range(2)
                ))
            else:
                self.call_bindings[id(node)] = Binding(
                    self._add_record(None, TARGET_SIGS[sig], node.lineno)
                )
        elif sig in TASK_SUPERVISOR_SIGS:
            self.call_bindings[id(node)] = self._supervisor_binding(node, sig[1])
        elif sig in {("contextlib", "closing"), ("contextlib", "nullcontext")}:
            keyword = "thing" if sig[1] == "closing" else "enter_result"
            argument = self._first_argument(node, keyword, {keyword}, max_positional=1)
            self.call_bindings[id(node)] = Binding(
                context=self._binding_from_expr(argument) if argument is not None else UNKNOWN_BINDING,
                closes_context=sig[1] == "closing",
            )
        self._handle_release(node)

    def visit_Await(self, node: ast.Await) -> None:
        self.generic_visit(node)
        self._release_awaitable(self._binding_from_expr(node.value))

    def _handle_release(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            binding = self._lookup_execution_binding(func.id)
            if binding is not None:
                self._release_records(binding.releases)
        if isinstance(func, ast.Attribute):
            binding = self._binding_from_expr(func.value)
            record = binding.record
            if record is not None and func.attr in RELEASE_METHODS[record.kind]:
                record.released = True
            elif func.attr == "cancel" and binding.cancel_children:
                self._release_awaitable(binding)
            elif record is None and self.current_scope.kind == "function":
                # A closure releasing an enclosing-scope resource: that
                # release happens only if and when this function is called.
                name = self._dotted_name(func.value)
                outer = self._lookup_symbol_binding(name) if name is not None else None
                if (outer is not None and outer.record is not None
                        and func.attr in RELEASE_METHODS[outer.record.kind]):
                    self.current_scope.deferred_releases.append(outer.record)

    def _release_records(self, records: tuple[ResourceRecord, ...]) -> None:
        """Calling a closure releases what it releases, in this frame or later."""
        if not records:
            return
        if self.current_scope.kind != "function":
            for record in records:
                record.released = True
            return
        owned = {id(binding.record) for binding in self.current_scope.by_name.values()
                 if binding.record is not None}
        for record in records:
            if id(record) in owned:
                record.released = True
            else:
                self.current_scope.deferred_releases.append(record)

    def _first_argument(
        self, node: ast.Call, name: str, allowed_keywords: set[str], *, max_positional: int
    ) -> Optional[ast.AST]:
        if len(node.args) > max_positional or any(isinstance(arg, ast.Starred) for arg in node.args):
            return None
        if any(kw.arg not in allowed_keywords for kw in node.keywords):
            return None
        keywords = {kw.arg: kw.value for kw in node.keywords}
        if node.args:
            return None if name in keywords else node.args[0]
        return keywords.get(name)

    def _supervisor_binding(self, node: ast.Call, name: str) -> Binding:
        children: list[Binding] = []
        if name == "gather":
            if any(kw.arg != "return_exceptions" for kw in node.keywords):
                return UNKNOWN_BINDING
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    items = self._binding_from_expr(arg.value).items
                    if items is None:
                        return UNKNOWN_BINDING
                    children.extend(items)
                else:
                    children.append(self._binding_from_expr(arg))
        elif name == "wait_for":
            argument = self._first_argument(node, "fut", {"fut", "timeout"}, max_positional=2)
            timeout_keywords = sum(kw.arg == "timeout" for kw in node.keywords)
            if (len(node.args) == 2) + timeout_keywords != 1:
                return UNKNOWN_BINDING
            if argument is not None:
                children.append(self._binding_from_expr(argument))
        elif name == "wait":
            argument = self._first_argument(node, "fs", {"fs", "timeout", "return_when"}, max_positional=1)
            options = {kw.arg: kw.value for kw in node.keywords}
            timeout = options.get("timeout")
            completion = options.get("return_when")
            # wait() returns pending tasks on timeout / early completion. Unlike
            # wait_for(), it does not cancel them. Unknown options cannot prove a join.
            full_join = (
                (timeout is None or isinstance(timeout, ast.Constant) and timeout.value is None)
                and (completion is None or self._reference_signature(completion) == ("asyncio", "ALL_COMPLETED"))
            )
            if argument is not None and full_join:
                items = self._binding_from_expr(argument).items
                if items is not None:
                    # wait() accepts Tasks/Futures, not wait_for/wait coroutines.
                    if not any(item.awaited is not None and not item.cancel_children for item in items):
                        children.extend(items)
        return Binding(awaited=tuple(children), cancel_children=name == "gather")

    def _release_awaitable(self, binding: Binding) -> None:
        pending = [binding]
        seen: set[int] = set()
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            if current.record is not None and current.record.kind == "asyncio_task":
                current.record.released = True
            # A collection itself is not awaitable. Only an actual supervisor
            # observes its recorded children; shared DAGs are traversed once.
            if current.awaited is not None:
                pending.extend(current.awaited)

    # Helpers ------------------------------------------------------------
    def _add_record(self, name: Optional[str], kind: str, lineno: int) -> ResourceRecord:
        rec = ResourceRecord(name, kind, lineno)
        self.records.append(rec)
        return rec

    def _call_signature(self, call: ast.Call) -> Optional[tuple[Optional[str], str]]:
        return self._reference_signature(call.func)

    def _reference_signature(self, func: ast.AST) -> Optional[tuple[Optional[str], str]]:
        symbol = self._qualified_reference(func)
        if symbol is not None and "." in symbol:
            module, name = symbol.rsplit(".", 1)
            return (module, name)
        return None

    def _qualified_reference(self, expr: ast.AST) -> Optional[str]:
        if isinstance(expr, ast.Name):
            binding = self._lookup_symbol_binding(expr.id)
            if binding is not None:
                return binding.symbol
            return "builtins.open" if expr.id == "open" else None
        if isinstance(expr, ast.Attribute):
            base = self._qualified_reference(expr.value)
            if base is None:
                return None
            dotted = self._dotted_name(expr)
            binding = self._lookup_symbol_binding(dotted) if dotted is not None else None
            return binding.symbol if binding is not None else f"{base}.{expr.attr}"
        if isinstance(expr, ast.Call):
            # Only a known Path constructor gives meaning to chained .open().
            # An arbitrary factory with a similar name is not a stdlib object.
            symbol = self._qualified_reference(expr.func)
            if symbol in {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}:
                return "pathlib.Path"
        return None

    def _dotted_name(self, expr: ast.expr) -> Optional[str]:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            base = self._dotted_name(expr.value)
            if base:
                return f"{base}.{expr.attr}"
        return None


def collect_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if root.is_file() and root.suffix == ".py":
        return [root]
    for path in root.rglob("*.py"):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        files.append(path)
    return files


def scan_file(path: Path, root: Path) -> list[tuple[Path, ResourceRecord]]:
    """Return (display_path, unreleased record) findings for one file."""
    try:
        # Let Python's parser honor encoding cookies and UTF-8 BOMs. Decoding
        # as UTF-8 first rejects valid Python before lifecycle analysis starts.
        text = path.read_bytes()
    except OSError as e:
        print(f"WARN: Could not read {path}: {e}", file=sys.stderr)
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        print(f"WARN: Syntax error in {path}: {e}", file=sys.stderr)
        return []
    analyzer = Analyzer(tree)
    analyzer.visit(tree)
    display: Path
    try:
        display = path.relative_to(root)
    except ValueError:
        display = path
    records = sorted(analyzer.records, key=lambda r: (r.lineno, r.kind, r.name or ""))
    return [(display, rec) for rec in records if not rec.released]


def analyze(path: Path, root: Path) -> list[str]:
    issues: list[str] = []
    for display, rec in scan_file(path, root):
        template = MESSAGE_TEMPLATES.get(rec.kind, "Resource not released")
        subject = rec.name or rec.kind
        message = template.format(name=subject)
        issues.append(f"{display}:{rec.lineno}\t{rec.kind}\t{message}")
    return issues


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: resource_lifecycle_py.py <project_dir>", file=sys.stderr)
        sys.exit(2)
    root = Path(sys.argv[1])
    issues: list[str] = []
    for path in sorted(collect_files(root), key=lambda p: str(p)):
        issues.extend(analyze(path, root))
    if issues:
        print("\n".join(issues))


_SEVERITY = {
    "file_handle": "critical",
    "socket_handle": "warning",
    "popen_handle": "warning",
    "asyncio_task": "warning",
}


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() != ".py":
            continue
        for display, rec in scan_file(path, cwd):
            template = MESSAGE_TEMPLATES.get(rec.kind, "Resource not released")
            yield {
                "rule": f"python.lifecycle.{rec.kind}",
                "path": str(display),
                "line": rec.lineno,
                "layer": "lifecycle",
                "lang": "python",
                "severity": _SEVERITY.get(rec.kind, "warning"),
                "message": template.format(name=rec.name or rec.kind),
            }


def _collect_unreleased(code: str) -> list[ResourceRecord]:
    tree = ast.parse(code)
    analyzer = Analyzer(tree)
    analyzer.visit(tree)
    return [rec for rec in analyzer.records if not rec.released]


def _selftest_unclosed_file() -> None:
    code = "def f():\n    handle = open('data.txt')\n    return handle\n"
    leaks = _collect_unreleased(code)
    assert len(leaks) == 1, leaks
    assert leaks[0].kind == "file_handle"
    assert leaks[0].name == "handle"
    assert leaks[0].lineno == 2


def _selftest_with_suppression() -> None:
    code = "def f():\n    with open('data.txt') as handle:\n        return handle.read()\n"
    assert not _collect_unreleased(code)


def _selftest_close_suppression() -> None:
    code = "def f():\n    handle = open('data.txt')\n    handle.close()\n"
    assert not _collect_unreleased(code)


def _selftest_task_await_suppression() -> None:
    code = "import asyncio\n\nasync def main():\n    task = asyncio.create_task(work())\n    await task\n"
    assert not _collect_unreleased(code)


def _selftest_run_finds_leak(tmp_prefix: str = "ubs_core_lifecycle_py_") -> None:
    import tempfile

    code = "import socket\nsock = socket.socket()\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leak.py"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.lifecycle.socket_handle"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "warning"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("unclosed_file_leak", _selftest_unclosed_file),
    ("with_suppression", _selftest_with_suppression),
    ("close_suppression", _selftest_close_suppression),
    ("task_await_suppression", _selftest_task_await_suppression),
    ("run_finds_leak", _selftest_run_finds_leak),
)

register(_RegistryAnalyzer(layer="lifecycle", lang="python", name="lifecycle_py", run=run, selftests=SELF_TESTS))
