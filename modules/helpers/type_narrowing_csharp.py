#!/usr/bin/env python3
"""Detect C# null/guard patterns that continue before dereferencing guarded values."""
from __future__ import annotations

import re
import sys
from pathlib import Path

HELPERS_DIR = Path(__file__).resolve().parent
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import extract_statement_region, find_block_end, line_col, skip_ws  # noqa: E402

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

NEGATIVE_GUARD_PATTERNS = (
    re.compile(r"if\s*\(\s*([A-Za-z_][\w]*)\s*(?:==|is)\s*null\b[^)]*\)", re.MULTILINE),
    re.compile(r"if\s*\(\s*string\.IsNullOr(?:Empty|WhiteSpace)\s*\(\s*([A-Za-z_][\w]*)\s*\)\s*\)", re.MULTILINE),
)
POSITIVE_GUARD_PATTERNS = (
    re.compile(r"if\s*\(\s*([A-Za-z_][\w]*)\s*(?:!=|is\s+not)\s*null\b[^)]*\)", re.MULTILINE),
)
TRY_GET_VALUE_PATTERN = re.compile(
    r"if\s*\(\s*!\s*[A-Za-z_][\w.]*\.TryGetValue\s*\([^)]*?\bout\s+(?:var\s+)?([A-Za-z_][\w]*)\s*\)\s*\)",
    re.MULTILINE,
)

ASSIGN_TEMPLATE = r"\b{name}\s*="
FORCE_TEMPLATE = r"\b{name}\s*!"
MEMBER_TEMPLATE = r"\b{name}\s*\."
INDEX_TEMPLATE = r"\b{name}\s*\["
EXIT_PATTERN = re.compile(r"\b(?:return|throw|continue|break)\b", re.MULTILINE)
ELSE_PATTERN = re.compile(r"\belse\b", re.MULTILINE)


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


def skip_optional_else(text: str, idx: int) -> int:
    idx = skip_ws(text, idx)
    match = ELSE_PATTERN.match(text, idx)
    if not match:
        return idx
    _, end = extract_statement_region(text, match.end())
    return end


def contains_exit(block_text: str) -> bool:
    return bool(EXIT_PATTERN.search(block_text))


def find_unsafe_use(text: str, name: str, start_idx: int) -> tuple[int, int] | None:
    assign_regex = re.compile(ASSIGN_TEMPLATE.format(name=re.escape(name)))
    candidates = [
        re.compile(FORCE_TEMPLATE.format(name=re.escape(name))),
        re.compile(MEMBER_TEMPLATE.format(name=re.escape(name))),
        re.compile(INDEX_TEMPLATE.format(name=re.escape(name))),
    ]
    earliest = None
    for regex in candidates:
        match = regex.search(text, start_idx)
        if match and (earliest is None or match.start() < earliest.start()):
            earliest = match
    if earliest is None:
        return None
    if assign_regex.search(text, start_idx, earliest.start()):
        return None
    return line_col(text, earliest.start())


def collect_guard_issues(
    text: str,
    pattern: re.Pattern[str],
    message: str,
    *,
    skip_on_exit: bool,
) -> list[tuple[int, int, str]]:
    issues: list[tuple[int, int, str]] = []
    for match in pattern.finditer(text):
        name = match.group(1)
        block_text, guard_end = extract_statement_region(text, match.end())
        if skip_on_exit and contains_exit(block_text):
            continue
        search_from = skip_optional_else(text, guard_end)
        loc = find_unsafe_use(text, name, search_from)
        if not loc:
            continue
        line, col = loc
        issues.append((line, col, message.format(name=name)))
    return issues


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    issues: list[tuple[int, int, str]] = []

    for pattern in NEGATIVE_GUARD_PATTERNS:
        issues.extend(
            collect_guard_issues(
                text,
                pattern,
                "{name} dereferenced after non-exiting null/empty guard",
                skip_on_exit=True,
            )
        )
    for pattern in POSITIVE_GUARD_PATTERNS:
        issues.extend(
            collect_guard_issues(
                text,
                pattern,
                "{name} dereferenced after positive null guard without narrowing the fallthrough path",
                skip_on_exit=False,
            )
        )
    issues.extend(
        collect_guard_issues(
            text,
            TRY_GET_VALUE_PATTERN,
            "{name} used after non-exiting TryGetValue guard",
            skip_on_exit=True,
        )
    )

    deduped: list[tuple[int, int, str]] = []
    seen = set()
    for line, col, message in issues:
        key = (line, col, message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((line, col, message))
    return deduped


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: type_narrowing_csharp.py <project_dir>", file=sys.stderr)
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
            print(f"{display}:{line}:{col}\twarning\t{message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
