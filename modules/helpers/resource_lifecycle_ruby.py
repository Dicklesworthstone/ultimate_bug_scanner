#!/usr/bin/env python3
"""Detect likely Ruby resource lifecycle leaks with lightweight variable tracking."""
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
    "vendor",
    "node_modules",
    "tmp",
    "log",
    "coverage",
    ".bundle",
}

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

FILE_ASSIGN = re.compile(rf"\b({IDENT})\s*=\s*File\.open\s*\(")
FILE_BLOCK = re.compile(r"\bFile\.open\s*\([^)\n]*\)\s*(?:do\b|\{)")

THREAD_NEW = re.compile(rf"(?:\b({IDENT})\s*=\s*)?Thread\.new\b")
HTTP_START = re.compile(rf"(?:\b({IDENT})\s*=\s*)?Net::HTTP\.start\s*\(")
HTTP_BLOCK = re.compile(r"\bNet::HTTP\.start\s*\([^)\n]*\)\s*(?:do\b|\{)")


def is_ignored(path: Path, root: Path) -> bool:
    base = root if root.is_dir() else root.parent
    try:
        rel = path.relative_to(base)
    except ValueError:
        rel = path
    return any(part in SKIP_DIRS for part in rel.parts[:-1])


def iter_ruby_files(root: Path):
    suffixes = {".rb", ".rake", ".ru", ".gemspec"}
    if root.is_file():
        if root.suffix.lower() in suffixes and not is_ignored(root, root):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in suffixes:
            continue
        if is_ignored(path, root):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    return core_strip(text, lang="ruby")


def has_named_release(name: str, pattern: str, text: str, start: int) -> bool:
    return re.search(rf"\b{re.escape(name)}{pattern}", text[start:]) is not None


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_ruby_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        code = strip_comments_and_strings(text)
        seen: set[tuple[str, str, str]] = set()

        for match in FILE_ASSIGN.finditer(code):
            name = match.group(1)
            if FILE_BLOCK.search(code, match.start(), match.end() + 80):
                continue
            if has_named_release(name, r"\.close\b", code, match.end()):
                continue
            issue = (format_location(base, path, match.start(), text), "file_handle", f"File handle is never closed ({name})")
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)

        for match in THREAD_NEW.finditer(code):
            name = match.group(1)
            if name:
                if has_named_release(name, r"\.(?:join|value)\b", code, match.end()):
                    continue
                detail = f"Thread is started without join/value ({name})"
            else:
                if re.search(r"\.join\b|\.(?:value|kill)\b", code[match.end():]):
                    continue
                detail = "Thread.new launches work without an obvious join/value"
            issue = (format_location(base, path, match.start(), text), "thread_join", detail)
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)

        for match in HTTP_START.finditer(code):
            name = match.group(1)
            if HTTP_BLOCK.search(code, match.start(), match.end() + 120):
                continue
            if name and has_named_release(name, r"\.finish\b", code, match.end()):
                continue
            if not name and re.search(r"\.finish\b", code[match.end():]):
                continue
            detail = f"Net::HTTP session is never finished ({name})" if name else "Net::HTTP session is never finished"
            issue = (format_location(base, path, match.start(), text), "http_session", detail)
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)

    return issues


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_ruby.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
