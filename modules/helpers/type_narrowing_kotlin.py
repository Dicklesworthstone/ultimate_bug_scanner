#!/usr/bin/env python3
"""Detect Kotlin null guards that do not exit before using the guarded value with `!!`."""
from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "build", "out", "dist", "target", ".gradle", ".idea", "node_modules"}
NEGATIVE_GUARD_PATTERN = re.compile(r"if\s*\(\s*([A-Za-z_][\w]*)\s*(?:==|===)\s*null[^)]*\)", re.MULTILINE)
POSITIVE_GUARD_PATTERN = re.compile(r"if\s*\(\s*([A-Za-z_][\w]*)\s*!=\s*null[^)]*\)", re.MULTILINE)
SAFE_CALL_GUARD_PATTERN = re.compile(r"if\s*\(\s*([A-Za-z_][\w]*)\s*\?\.[^)]*\)", re.MULTILINE)
DOUBLE_BANG_PATTERN = "{name}\\s*!!"
ASSIGN_PATTERN = re.compile(r"{name}\s*=")
EXIT_PATTERN = re.compile(r"\b(return|throw|continue|break)\b")
SMART_CAST_PATTERN = re.compile(r"\b(?:val|var)\s+([A-Za-z_][\w]*)\s*=\s*[^;\n]+as\?\s+[A-Za-z0-9_.]+")
ELVIS_ASSIGN_PATTERN = re.compile(r"\b(?:val|var)\s+([A-Za-z_][\w]*)\s*=\s*[^;\n]+?\?:")


def iter_kotlin_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {".kt", ".kts"} and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return

    for path in root.rglob("*.kt"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def find_block_end(text: str, brace_start: int) -> int:
    depth = 0
    for idx in range(brace_start, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text) - 1


def first_non_space(text: str, idx: int) -> int:
    while idx < len(text) and text[idx].isspace():
        idx += 1
    return idx


def extract_guard_region(text: str, match_end: int) -> tuple[str, int]:
    """Return guard body text and index immediately following the guard."""
    idx = first_non_space(text, match_end)
    if idx < len(text) and text[idx] == "{":
        block_end = find_block_end(text, idx)
        return text[idx : block_end + 1], block_end + 1

    newline = text.find("\n", idx)
    if newline == -1:
        newline = len(text)
    return text[idx:newline], newline


def contains_exit(block_text: str) -> bool:
    return bool(EXIT_PATTERN.search(block_text))


def line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    last_newline = text.rfind("\n", 0, pos)
    if last_newline == -1:
        col = pos + 1
    else:
        col = pos - last_newline
    return line, col


def collect_guard_issues(text: str, pattern: re.Pattern[str], message: str):
    issues = []
    for match in pattern.finditer(text):
        var_name = match.group(1)
        block_text, guard_end = extract_guard_region(text, match.end())
        if contains_exit(block_text):
            continue
        assign_regex = re.compile(ASSIGN_PATTERN.pattern.format(name=re.escape(var_name)))
        double_regex = re.compile(DOUBLE_BANG_PATTERN.format(name=re.escape(var_name)))
        search_pos = guard_end
        while True:
            double_match = double_regex.search(text, search_pos)
            if not double_match:
                break
            assign_match = assign_regex.search(text, search_pos, double_match.start())
            if assign_match:
                break
            absolute_pos = double_match.start()
            line, col = line_col(text, absolute_pos)
            issues.append((line, col, message.format(name=var_name)))
            break
    return issues


def collect_double_bang_usage(text: str, name: str, start: int) -> tuple[int, int] | None:
    double_regex = re.compile(DOUBLE_BANG_PATTERN.format(name=re.escape(name)))
    match = double_regex.search(text, start)
    if match:
        return line_col(text, match.start())
    return None


def collect_smart_cast_issues(text: str):
    issues = []
    for match in SMART_CAST_PATTERN.finditer(text):
        name = match.group(1)
        location = collect_double_bang_usage(text, name, match.end())
        if location:
            line, col = location
            issues.append((line, col, f"{name} forced (!!) after as? smart cast"))
    return issues


def collect_elvis_issues(text: str):
    issues = []
    for match in ELVIS_ASSIGN_PATTERN.finditer(text):
        name = match.group(1)
        location = collect_double_bang_usage(text, name, match.end())
        if location:
            line, col = location
            issues.append((line, col, f"{name} assigned via Elvis operator but later forced with !!"))
    return issues


def analyze_file(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    issues = []
    issues.extend(collect_guard_issues(text, SAFE_CALL_GUARD_PATTERN, "{name}!! used after ?. guard without exit"))
    issues.extend(collect_guard_issues(text, NEGATIVE_GUARD_PATTERN, "{name}!! after non-exiting null guard"))
    issues.extend(collect_guard_issues(text, POSITIVE_GUARD_PATTERN, "{name}!! used after '!= null' guard without exit"))
    issues.extend(collect_smart_cast_issues(text))
    issues.extend(collect_elvis_issues(text))
    deduped = []
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
        print("Usage: type_narrowing_kotlin.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    any_output = False
    for path in iter_kotlin_files(root):
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        for line, col, message in issues:
            any_output = True
            print(f"{path}:{line}:{col}\t{message}")
    return 0 if any_output or root.is_dir() else 0


if __name__ == "__main__":
    raise SystemExit(main())
