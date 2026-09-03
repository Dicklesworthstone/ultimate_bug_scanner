"""ubs_core.analyzers.lifecycle_java — JDBC resource lifecycle analysis (bead A2).

Logic moved verbatim from modules/helpers/resource_lifecycle_java.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", "node_modules", "dist", "build", "bin", "out", ".venv", "vendor"}
STATEMENT_RE = re.compile(r"\b(?:PreparedStatement|CallableStatement|Statement)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=.*?;", re.DOTALL)
RESULTSET_RE = re.compile(r"\bResultSet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=.*?;", re.DOTALL)
TRY_RE = re.compile(r"\btry\s*\(")


def strip_comments(text: str) -> str:
    return strip_comments_and_strings(text, lang="java")


def iter_java_files(root: Path) -> Iterable[Path]:
    if root.is_file() and root.suffix.lower() == ".java":
        yield root
        return
    for path in root.rglob("*.java"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def has_close(name: str, code_text: str, start_pos: int) -> bool:
    pattern = re.compile(rf"\b{name}\.close\s*\(")
    return bool(pattern.search(code_text, start_pos))


def inside_try_with(text: str, start: int) -> bool:
    match = None
    for candidate in TRY_RE.finditer(text, 0, start):
        match = candidate
    if not match:
        return False
    depth = 1
    for ch in text[match.end():start]:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return False
    return depth > 0


def scan_text(path: Path, text: str, project_root: Path) -> list[tuple[str, str, int]]:
    """Return (kind, rel_path, line) findings for one file's text."""
    issues: list[tuple[str, str, int]] = []
    if not text.strip():
        return issues
    code_text = strip_comments(text)
    rel = str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path)

    def handle_matches(regex: re.Pattern[str], kind: str) -> None:
        for match in regex.finditer(code_text):
            name = match.group(1)
            if name == "_":
                continue
            start = match.start()
            line_no = text.count("\n", 0, start) + 1
            if inside_try_with(code_text, start):
                continue
            if has_close(name, code_text, start):
                continue
            issues.append((kind, rel, line_no))

    handle_matches(STATEMENT_RE, "statement_handle")
    handle_matches(RESULTSET_RE, "resultset_handle")
    return issues


def collect_issues(root: Path) -> list[tuple[str, str, int]]:
    issues: list[tuple[str, str, int]] = []
    project_root = root if root.is_dir() else root.parent
    for path in iter_java_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        issues.extend(scan_text(path, text, project_root))
    return issues


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("usage: resource_lifecycle_java.py <project_dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    issues = collect_issues(root)
    for kind, rel, line in issues:
        print(f"{rel}:{line}\t{kind}")
    return 0


_MESSAGE = {
    "statement_handle": "JDBC Statement/PreparedStatement created outside try-with-resources and never closed",
    "resultset_handle": "ResultSet created outside try-with-resources and never closed",
}


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() != ".java":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, rel, line in scan_text(path, text, cwd):
            yield {
                "rule": f"java.lifecycle.{kind}",
                "path": rel,
                "line": line,
                "layer": "lifecycle",
                "lang": "java",
                "severity": "warning",
                "message": _MESSAGE[kind],
            }


def _selftest_try_with() -> None:
    code = "class A { void f() { try (Statement s = conn.create()) { s.q(); } } }"
    match = STATEMENT_RE.search(strip_comments(code))
    assert match is not None
    assert inside_try_with(code, match.start())


def _selftest_close_suppression() -> None:
    code = "class A { void f() { Statement s = conn.create(); s.q(); s.close(); } }"
    match = STATEMENT_RE.search(strip_comments(code))
    assert match is not None
    assert has_close(match.group(1), code, match.start())
    assert not inside_try_with(code, match.start())


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_java_") -> None:
    import tempfile

    code = "class A { void f() { ResultSet rs = st.executeQuery(q); } }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.java"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "java.lifecycle.resultset_handle"
    assert findings[0]["line"] == 1


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("try_with_suppression", _selftest_try_with),
    ("close_suppression", _selftest_close_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="java", name="lifecycle_java", run=run, selftests=SELF_TESTS))
