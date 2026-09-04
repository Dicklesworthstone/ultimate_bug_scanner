"""ubs_core.analyzers.narrowing_py — Python partial-None-guard analysis (bead D4).

Detects `if x is None:` (or `== None`) guards whose branch merely logs (or does
anything short of exiting / re-binding x) followed LATER by a dereference of
`x.attr`, `x[i]`, or `x.method()` outside the guard branch. Because the guard
does not exit, the fall-through path still runs with x possibly None — the
Python twin of narrowing_rust's partial-guard-unwrap and narrowing_csharp's
non-exiting null guard.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

_RULE = "python.narrowing.partial_none_guard"
_MESSAGE = "{name} dereferenced after non-exiting None guard"

_EXIT_NODES = (ast.Return, ast.Raise, ast.Continue, ast.Break)
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_DEREF_NODES = (ast.Attribute, ast.Subscript)
_ASSIGN_NODES = (ast.Assign, ast.AnnAssign, ast.AugAssign)


def _pos(node: ast.AST) -> tuple[int, int]:
    return (node.lineno, node.col_offset)  # type: ignore[attr-defined]


def _iter_nodes_no_functions(node: ast.AST) -> Iterator[ast.AST]:
    """Yield descendants of node without entering nested scopes."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_NODES):
            continue
        if hasattr(child, "lineno"):
            yield child
        yield from _iter_nodes_no_functions(child)


def _iter_stmt_lists(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Yield every statement list reachable without entering a nested scope."""
    for field, value in ast.iter_fields(node):
        if not isinstance(value, list):
            if isinstance(value, ast.AST) and not isinstance(value, _SCOPE_NODES):
                yield from _iter_stmt_lists(value)
            continue
        stmts = [item for item in value if isinstance(item, ast.stmt)]
        if stmts:
            yield stmts
        for item in value:
            if isinstance(item, ast.AST) and not isinstance(item, _SCOPE_NODES):
                yield from _iter_stmt_lists(item)


def _guard_name(test: ast.expr) -> str | None:
    """Return the guarded identifier for `x is None` / `None == x` style tests."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    if not isinstance(test.ops[0], (ast.Is, ast.Eq)):
        return None
    left, right = test.left, test.comparators[0]
    if isinstance(right, ast.Constant) and right.value is None and isinstance(left, ast.Name):
        return left.id
    if isinstance(left, ast.Constant) and left.value is None and isinstance(right, ast.Name):
        return right.id
    return None


def _has_exit(body: list[ast.stmt]) -> bool:
    """True when any return/raise/continue/break appears in the block subtree."""
    if any(isinstance(stmt, _EXIT_NODES) for stmt in body):
        return True
    for stmt in body:
        for node in _iter_nodes_no_functions(stmt):
            if isinstance(node, _EXIT_NODES):
                return True
    return False


def _assign_targets(stmt: ast.AST) -> Iterator[ast.Name]:
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        targets = [stmt.target]
        if isinstance(stmt, ast.AnnAssign) and stmt.value is None:
            return
    else:
        return
    for target in targets:
        if isinstance(target, ast.Name):
            yield target


def _assigns_name(stmt: ast.AST, name: str) -> bool:
    return any(target.id == name for target in _assign_targets(stmt))


def _rebinds_in_body(guard: ast.If, name: str) -> bool:
    if any(isinstance(stmt, _ASSIGN_NODES) and _assigns_name(stmt, name) for stmt in guard.body):
        return True
    for stmt in guard.body:
        for node in _iter_nodes_no_functions(stmt):
            if isinstance(node, _ASSIGN_NODES) and _assigns_name(node, name):
                return True
    return False


def _deref_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value  # type: ignore[assignment]
    return node.id if isinstance(node, ast.Name) else None  # type: ignore[attr-defined]


def _is_boundary(node: ast.AST, name: str) -> bool:
    """A later re-binding of x, or a later *exiting* None check, ends the unsafe region."""
    if isinstance(node, _ASSIGN_NODES) and _assigns_name(node, name):
        return True
    if isinstance(node, ast.If) and _guard_name(node.test) == name and _has_exit(node.body):
        return True
    return False


def _unsafe_use(
    guard: ast.If, later: list[ast.stmt], name: str
) -> tuple[int, int] | None:
    """Earliest (line, col) dereference of name after the guard's span, or None."""
    guard_end = (guard.end_lineno, guard.end_col_offset)  # type: ignore[attr-defined]
    nodes = [
        node
        for stmt in later
        for node in ([stmt] if hasattr(stmt, "lineno") else []) + list(_iter_nodes_no_functions(stmt))
    ]
    boundary: tuple[int, int] | None = None
    for node in nodes:
        pos = _pos(node)
        if pos <= guard_end:
            continue
        if _is_boundary(node, name):
            if boundary is None or pos < boundary:
                boundary = pos
    best: tuple[int, int] | None = None
    for node in nodes:
        if not isinstance(node, _DEREF_NODES) or _deref_name(node) != name:
            continue
        pos = _pos(node)
        if pos <= guard_end:
            continue
        if boundary is not None and pos >= boundary:
            continue
        if best is None or pos < best:
            best = pos
    return best


def scan_text(text: str) -> list[tuple[int, int, str]]:
    """Return (line, col, message) findings for one file's text."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    issues: list[tuple[int, int, str]] = []
    roots: list[ast.AST] = [tree]
    roots.extend(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
    for root in roots:
        for stmts in _iter_stmt_lists(root):
            for index, stmt in enumerate(stmts):
                if not isinstance(stmt, ast.If):
                    continue
                name = _guard_name(stmt.test)
                if name is None or _has_exit(stmt.body) or _rebinds_in_body(stmt, name):
                    continue
                use = _unsafe_use(stmt, stmts[index + 1 :], name)
                if use is None:
                    continue
                line, col = use
                issues.append((line, col + 1, _MESSAGE.format(name=name)))
    return sorted(set(issues))


def run(ctx: RunContext) -> Iterable[dict]:
    if os.environ.get('UBS_SKIP_TYPE_NARROWING', '') == '1': return []
    cwd = Path.cwd()
    findings: list[dict] = []
    for path in ctx.files:
        if path.suffix != ".py":
            continue
        try:
            issues = scan_text(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        try:
            rel = str(path.resolve().relative_to(cwd))
        except ValueError:
            rel = str(path)
        for line, col, message in issues:
            findings.append(
                {
                    "rule": _RULE,
                    "path": rel,
                    "line": line,
                    "layer": "narrowing",
                    "lang": "python",
                    "severity": "warning",
                    "message": message,
                    "col": col,
                }
            )
    return findings


def _analyze_snippet(code: str) -> list[tuple[int, int, str]]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_narrowing_py_") as tmp:
        target = Path(tmp) / "snippet.py"
        target.write_text(code, encoding="utf-8")
        return scan_text(target.read_text(encoding="utf-8"))


def _selftest_detects_use_after_partial_guard() -> None:
    code = (
        "import logging\n"
        "\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "\n"
        "def describe(user):\n"
        "    if user is None:\n"
        "        log.warning('user missing; continuing')\n"
        "    return user.name\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 9, (line, col, message)
    assert col == 12, (line, col, message)
    assert message == "user dereferenced after non-exiting None guard", message


def _selftest_exiting_guard_suppresses() -> None:
    code = (
        "def describe(user):\n"
        "    if user is None:\n"
        "        log.warning('user missing')\n"
        "        return 'anonymous'\n"
        "    return user.name\n"
    )
    assert _analyze_snippet(code) == []


def _selftest_reassignment_suppresses() -> None:
    code = (
        "def pick(config):\n"
        "    if config is None:\n"
        "        log.warning('config missing')\n"
        "        config = {}\n"
        "    return config['primary']\n"
    )
    assert _analyze_snippet(code) == []


def _selftest_later_exiting_guard_suppresses() -> None:
    code = (
        "def render(widget):\n"
        "    if widget is None:\n"
        "        log.warning('widget missing')\n"
        "    if widget is None:\n"
        "        return ''\n"
        "    return widget.render()\n"
    )
    assert _analyze_snippet(code) == []


def _selftest_subscript_and_method_uses_detected() -> None:
    code = (
        "def load(table, payload):\n"
        "    if table is None:\n"
        "        log.warning('no table')\n"
        "    if payload == None:\n"
        "        log.warning('no payload')\n"
        "    return table['k'], payload.encode()\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 2, issues
    assert all(issue[0] == 6 for issue in issues), issues
    names = {issue[2].split()[0] for issue in issues}
    assert names == {"table", "payload"}, issues


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_py_run_") -> None:
    import tempfile

    code = (
        "def send(payload):\n"
        "    if payload is None:\n"
        "        log.warning('payload missing')\n"
        "    return payload.encode('utf-8')\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "sample.py"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="python", files=[target])))
        assert len(findings) == 1, findings
        assert findings[0]["rule"] == "python.narrowing.partial_none_guard", findings[0]
        assert findings[0]["layer"] == "narrowing", findings[0]
        assert findings[0]["severity"] == "warning", findings[0]
        assert findings[0]["line"] == 4, findings[0]
        assert findings[0]["message"] == "payload dereferenced after non-exiting None guard", findings[0]
        previous = os.environ.get("UBS_SKIP_TYPE_NARROWING")
        try:
            os.environ["UBS_SKIP_TYPE_NARROWING"] = "1"
            assert list(run(RunContext(lang="python", files=[target]))) == []
        finally:
            if previous is None:
                os.environ.pop("UBS_SKIP_TYPE_NARROWING", None)
            else:
                os.environ["UBS_SKIP_TYPE_NARROWING"] = previous


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_use_after_partial_guard", _selftest_detects_use_after_partial_guard),
    ("exiting_guard_suppresses", _selftest_exiting_guard_suppresses),
    ("reassignment_suppresses", _selftest_reassignment_suppresses),
    ("later_exiting_guard_suppresses", _selftest_later_exiting_guard_suppresses),
    ("subscript_and_method_uses_detected", _selftest_subscript_and_method_uses_detected),
    ("run_finds_partial_none_guard", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="python", name="narrowing_py", run=run, selftests=SELF_TESTS))
