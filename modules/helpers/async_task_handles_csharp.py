#!/usr/bin/env python3
"""Detect C# Task.Run/StartNew handles that are created but never observed."""
from __future__ import annotations

import re
import sys
from pathlib import Path

HELPERS_DIR = Path(__file__).resolve().parent
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import line_col  # noqa: E402
from ubs_core.lexer import strip_comments_and_strings as core_strip  # noqa: E402

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "bin",
    "obj",
    "packages",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "TestResults",
    ".idea",
    ".vscode",
}

ASSIGNED_TASK_PATTERN = re.compile(
    r"\b(?:var|Task(?:<[^>=;\n]+>)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:Task\.Run|Task\.Factory\.StartNew)\s*\(",
    re.MULTILINE,
)
ASSIGN_TEMPLATE = r"\b{name}\s*="
OBSERVED_TEMPLATES = (
    r"\bawait\s+{name}\b",
    r"\breturn\s+{name}\b",
    r"\bTask\.(?:WhenAll|WhenAny)\s*\([^;\n]*\b{name}\b",
    r"\b{name}\.(?:Wait|GetAwaiter\s*\(\)\s*\.GetResult)\s*\(",
)


def iter_csharp_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {".cs", ".csx"} and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for ext in ("*.cs", "*.csx"):
        for path in root.rglob(ext):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


def strip_comments_and_strings(text: str) -> str:
    return core_strip(text, lang="csharp")


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    code_text = strip_comments_and_strings(text)
    issues: list[tuple[int, int, str]] = []
    seen = set()

    for match in ASSIGNED_TASK_PATTERN.finditer(code_text):
        name = match.group(1)
        start = match.end()
        assign_regex = re.compile(ASSIGN_TEMPLATE.format(name=re.escape(name)))
        first_reassignment = assign_regex.search(code_text, start)
        search_end = first_reassignment.start() if first_reassignment else len(code_text)

        observed = False
        for template in OBSERVED_TEMPLATES:
            observed_regex = re.compile(template.format(name=re.escape(name)))
            if observed_regex.search(code_text, start, search_end):
                observed = True
                break
        if observed:
            continue

        line, col = line_col(text, match.start())
        message = f"Task handle '{name}' is created but never awaited/observed"
        key = (line, col, message)
        if key in seen:
            continue
        seen.add(key)
        issues.append((line, col, message))
    return issues


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: async_task_handles_csharp.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    base = root if root.is_dir() else root.parent
    for path in iter_csharp_files(root):
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        try:
            display = path.relative_to(base)
        except ValueError:
            display = path
        for line, col, message in issues:
            print(f"{display}:{line}:{col}\twarning\tunobserved_task_handle\t{message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
