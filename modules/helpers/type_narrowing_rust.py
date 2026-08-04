#!/usr/bin/env python3
"""Detect Rust guard clauses that still unwrap the guarded Option/Result later."""
from __future__ import annotations

import json
import os
import re
import sys
from json import JSONDecodeError
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

SKIP_DIRS = {"target", ".git", ".hg", ".svn", "node_modules"}
UNWRAP_PATTERN = r"\b{name}\s*\.(?:unwrap|expect)\s*\("
ASSIGN_PATTERN = r"\b{name}\s*="
IDENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class GuardMatch:
    path: Path
    expr: str
    start: int
    end: int


def is_safe_path(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base)
        return True
    except ValueError:
        return False


def read_file(path: Path, cache: dict[Path, str]) -> str:
    if path not in cache:
        cache[path] = path.read_text(encoding="utf-8", errors="ignore")
    return cache[path]


def safe_json_loads(line: str) -> dict | None:
    try:
        payload = json.JSONDecoder().decode(line)
    except JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    last_newline = text.rfind("\n", 0, pos)
    if last_newline == -1:
        col = pos + 1
    else:
        col = pos - last_newline
    return line, col


def iter_rust_files(root: Path) -> Iterable[Path]:
    base = root.resolve()
    listing = os.environ.get("UBS_RUST_FILE_LIST", "")
    if listing and os.path.isfile(listing):
        # GH #70: consume the calling module's authoritative filtered file
        # list (--exclude / --strict-gitignore / --exclude-tests) instead of
        # re-walking the tree with a local skip list.
        with open(listing, encoding="utf-8") as fh:
            for line in fh:
                entry = line.rstrip("\n")
                if entry.endswith(".rs"):
                    path = Path(entry)
                    if is_safe_path(path, base):
                        yield path
        return
    if root.is_file():
        if root.suffix == ".rs" and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # Modify dirnames in-place to prune traversal
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            if filename.endswith(".rs"):
                path = Path(dirpath) / filename
                if is_safe_path(path, base):
                    yield path


def analyze_guard(text: str, guard: GuardMatch) -> tuple[int, int] | None:
    # For 'if let Some', exiting the block means we only reach the unwrap if None (panic).
    # Continuing means we reach it in both cases (panic if None).
    # So we don't check EXIT_PATTERN here.
    remainder = text[guard.end :]
    assign_match = re.search(ASSIGN_PATTERN.format(name=re.escape(guard.expr)), remainder)
    search_region = remainder
    if assign_match:
        search_region = remainder[: assign_match.start()]
    unwrap_regex = re.compile(UNWRAP_PATTERN.format(name=re.escape(guard.expr)))
    unwrap_match = unwrap_regex.search(search_region)
    if not unwrap_match:
        return None
    absolute_pos = guard.end + unwrap_match.start()
    return line_col(text, absolute_pos)


def guard_from_match(entry: dict) -> GuardMatch | None:
    singles = entry.get("metaVariables", {}).get("single", {})
    source_node = singles.get("SOURCE") or singles.get("S")
    if not source_node:
        return None
    expr = source_node.get("text", "")
    if not IDENT_PATTERN.match(expr):
        return None
    guard_range = entry.get("range", {}).get("byteOffset", {})
    start = guard_range.get("start")
    end = guard_range.get("end")
    file_path = entry.get("file")
    if start is None or end is None or not file_path:
        return None
    return GuardMatch(Path(file_path), expr, int(start), int(end))


def analyze_with_ast_json(root: Path, json_path: Path) -> List[tuple[Path, int, int, str]]:
    base = root.resolve()
    base_dir = base if base.is_dir() else base.parent
    if not json_path.exists():
        return []
    guards: List[GuardMatch] = []
    try:
        with json_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                match = safe_json_loads(line)
                if match is None:
                    continue
                guard = guard_from_match(match)
                if not guard:
                    continue
                guard_path = guard.path
                if not guard_path.is_absolute():
                    guard_path = (base_dir / guard_path).resolve()
                else:
                    guard_path = guard_path.resolve()
                guard = GuardMatch(guard_path, guard.expr, guard.start, guard.end)
                if is_safe_path(guard.path, base_dir):
                    guards.append(guard)
    except OSError:
        return []
    if not guards:
        return []

    cache: dict[Path, str] = {}
    findings: List[tuple[Path, int, int, str]] = []
    for guard in guards:
        try:
            text = read_file(guard.path, cache)
        except OSError:
            continue
        loc = analyze_guard(text, guard)
        if not loc:
            continue
        line, col = loc
        findings.append((guard.path, line, col, f"{guard.expr} unwrap/expect after partial guard"))
    return findings


# Legacy regex fallback ----------------------------------------------------- #
GUARD_PATTERN = re.compile(r"if\s+let\s+(?:Some|Ok)\s*\([^)]*\)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.MULTILINE)


def find_block_end(text: str, start: int) -> int:
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text)


def analyze_file_regex(path: Path) -> List[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    issues: List[tuple[int, int, str]] = []
    for match in GUARD_PATTERN.finditer(text):
        expr = match.group(1)
        brace_start = text.find("{", match.start())
        if brace_start == -1:
            continue
        brace_end = find_block_end(text, brace_start)
        # For 'if let Some', exiting the block means we only reach the unwrap if None (panic).
        # Continuing means we reach it in both cases (panic if None).
        remainder = text[brace_end + 1 :]
        if not remainder.strip():
            continue
        assign_match = re.search(ASSIGN_PATTERN.format(name=re.escape(expr)), remainder)
        search_region = remainder if not assign_match else remainder[: assign_match.start()]
        unwrap_regex = re.compile(UNWRAP_PATTERN.format(name=re.escape(expr)))
        unwrap_match = unwrap_regex.search(search_region)
        if unwrap_match:
            absolute_pos = brace_end + 1 + unwrap_match.start()
            line, col = line_col(text, absolute_pos)
            issues.append((line, col, f"{expr} unwrap/expect after partial guard"))
    return issues


def analyze_with_regex(root: Path) -> List[tuple[Path, int, int, str]]:
    findings: List[tuple[Path, int, int, str]] = []
    for path in iter_rust_files(root):
        try:
            issues = analyze_file_regex(path)
        except OSError:
            continue
        for line, col, msg in issues:
            findings.append((path, line, col, msg))
    return findings


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: type_narrowing_rust.py <project_dir> [--ast-json path]", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0

    json_path = None
    if len(sys.argv) >= 4 and sys.argv[2] == "--ast-json":
        json_path = Path(sys.argv[3]).resolve()

    issues: List[tuple[Path, int, int, str]] = []
    if json_path:
        issues = analyze_with_ast_json(root, json_path)
    if not issues:
        issues = analyze_with_regex(root)

    for path, line, col, message in issues:
        print(f"{path}:{line}:{col}\t{message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
