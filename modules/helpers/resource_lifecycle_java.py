#!/usr/bin/env python3
"""Detect JDBC lifecycle leaks (Statement/PreparedStatement/ResultSet)."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

HELPERS_DIR = Path(__file__).resolve().parent
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.lexer import strip_comments_and_strings as core_strip  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "dist", "build", "bin", "out", ".venv", "vendor"}
STATEMENT_RE = re.compile(r"\b(?:PreparedStatement|CallableStatement|Statement)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=.*?;", re.DOTALL)
RESULTSET_RE = re.compile(r"\bResultSet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=.*?;", re.DOTALL)
TRY_RE = re.compile(r"\btry\s*\(")


def strip_comments(text: str) -> str:
    return core_strip(text, lang="java")


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


def collect_issues(root: Path) -> list[tuple[str, str, int]]:
    issues: list[tuple[str, str, int]] = []
    project_root = root if root.is_dir() else root.parent
    for path in iter_java_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not text.strip():
            continue
        code_text = strip_comments(text)
        # lines = text.splitlines()
        def handle_matches(regex: re.Pattern[str], kind: str) -> None:
            for match in regex.finditer(code_text):
                name = match.group(1)
                if name == "_":
                    continue
                start = match.start()
                line_no = text.count("\n", 0, start) + 1
                # line_idx = line_no - 1
                # line_text = lines[line_idx] if 0 <= line_idx < len(lines) else ""
                # prefix = line_text.split(name, 1)[0]
                if inside_try_with(code_text, start):
                    continue
                if has_close(name, code_text, start):
                    continue
                rel = str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path)
                issues.append((kind, rel, line_no))
        handle_matches(STATEMENT_RE, "statement_handle")
        handle_matches(RESULTSET_RE, "resultset_handle")
    return issues


def main() -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
