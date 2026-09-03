#!/usr/bin/env python3
"""Detect likely C/C++ resource lifecycle leaks with lightweight variable tracking."""
from __future__ import annotations

import re
import sys
from pathlib import Path

HELPERS_DIR = Path(__file__).resolve().parent
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import format_location, line_col  # noqa: E402
from ubs_core.lexer import strip_comments_and_strings as core_strip  # noqa: E402

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "cmake-build-relwithdebinfo",
    "cmake-build-minsizerel",
    "out",
    "dist",
    "vendor",
    "third_party",
    "_deps",
    "target",
    "node_modules",
}

SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".cppm",
    ".mpp",
    ".ixx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ipp",
    ".tpp",
}

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
THREAD_DECL = re.compile(rf"\bstd::thread\s+({IDENT})\s*(?:\(|\{{|=)")
THREAD_AUTO = re.compile(rf"\bauto\s+({IDENT})\s*=\s*std::thread\s*\(")
MALLOC_ASSIGN = re.compile(
    rf"\b({IDENT})\s*=\s*(?:(?:static|reinterpret|const)_cast<[^>]+>\s*\([^)]*\)|\([^)]*\))?\s*(?:malloc|calloc|realloc)\s*\(",
    re.MULTILINE,
)
FOPEN_ASSIGN = re.compile(rf"\b(?:FILE\s*\*\s*|auto\s+)({IDENT})\s*=\s*fopen\s*\(")
FOPEN_REASSIGN = re.compile(rf"\b({IDENT})\s*=\s*fopen\s*\(")


def is_ignored(path: Path, root: Path) -> bool:
    base = root if root.is_dir() else root.parent
    try:
        rel = path.relative_to(base)
    except ValueError:
        rel = path
    return any(part in SKIP_DIRS for part in rel.parts[:-1])


def iter_cpp_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in SOURCE_SUFFIXES and not is_ignored(root, root):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if is_ignored(path, root):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    return core_strip(text, lang="cpp")


def line_text(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos)
    end = text.find("\n", pos)
    if start == -1:
        start = 0
    else:
        start += 1
    if end == -1:
        end = len(text)
    return text[start:end]


def has_thread_release(name: str, code: str, start: int) -> bool:
    return re.search(rf"\b{re.escape(name)}\s*\.\s*(?:join|detach)\s*\(", code[start:]) is not None


def has_c_release(name: str, func: str, code: str, start: int) -> bool:
    return re.search(rf"\b{func}\s*\(\s*{re.escape(name)}\b", code[start:]) is not None


def is_thread_function_decl(name: str, text: str, pos: int) -> bool:
    return re.search(rf"\bstd::thread\s+{re.escape(name)}\s*\(\s*\)\s*;", line_text(text, pos)) is not None


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_cpp_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not text.strip():
            continue
        code = strip_comments_and_strings(text)
        seen: set[tuple[str, str, str]] = set()

        for pattern in (THREAD_DECL, THREAD_AUTO):
            for match in pattern.finditer(code):
                name = match.group(1)
                if name == "_" or is_thread_function_decl(name, text, match.start()):
                    continue
                if has_thread_release(name, code, match.end()):
                    continue
                issue = (
                    format_location(base, path, match.start(), text),
                    "thread_join",
                    f"std::thread is started without join/detach ({name})",
                )
                if issue not in seen:
                    seen.add(issue)
                    issues.append(issue)

        for match in MALLOC_ASSIGN.finditer(code):
            name = match.group(1)
            if name == "_" or has_c_release(name, "free", code, match.end()):
                continue
            issue = (
                format_location(base, path, match.start(), text),
                "malloc_heap",
                f"Heap allocation is never released with free() ({name})",
            )
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)

        for pattern in (FOPEN_ASSIGN, FOPEN_REASSIGN):
            for match in pattern.finditer(code):
                name = match.group(1)
                if name == "_" or has_c_release(name, "fclose", code, match.end()):
                    continue
                issue = (
                    format_location(base, path, match.start(), text),
                    "fopen_handle",
                    f"FILE* handle is never closed with fclose() ({name})",
                )
                if issue not in seen:
                    seen.add(issue)
                    issues.append(issue)

    return issues


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_cpp.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
