"""ubs_core.analyzers.lifecycle_ruby — Ruby resource lifecycle leak analysis (bead A2).

Logic moved verbatim from modules/helpers/resource_lifecycle_ruby.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ubs_core.io import format_location, line_col
from ubs_core.lexer import strip_comments_and_strings as core_strip
from ubs_core.registry import Analyzer, RunContext, register

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

RUBY_SUFFIXES = frozenset({".rb", ".rake", ".ru", ".gemspec"})

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
    if root.is_file():
        if root.suffix.lower() in RUBY_SUFFIXES and not is_ignored(root, root):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in RUBY_SUFFIXES:
            continue
        if is_ignored(path, root):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    return core_strip(text, lang="ruby")


def has_named_release(name: str, pattern: str, text: str, start: int) -> bool:
    return re.search(rf"\b{re.escape(name)}{pattern}", text[start:]) is not None


def scan_file(path: Path, text: str) -> list[tuple[int, str, str]]:
    """Return (match_pos, kind, message) findings for one file's text."""
    issues: list[tuple[int, str, str]] = []
    code = strip_comments_and_strings(text)
    seen: set[tuple[int, str, str]] = set()

    for match in FILE_ASSIGN.finditer(code):
        name = match.group(1)
        if FILE_BLOCK.search(code, match.start(), match.end() + 80):
            continue
        if has_named_release(name, r"\.close\b", code, match.end()):
            continue
        issue = (match.start(), "file_handle", f"File handle is never closed ({name})")
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
        issue = (match.start(), "thread_join", detail)
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
        issue = (match.start(), "http_session", detail)
        if issue not in seen:
            seen.add(issue)
            issues.append(issue)

    return issues


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_ruby_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pos, kind, message in scan_file(path, text):
            issues.append((format_location(base, path, pos, text), kind, message))

    return issues


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_ruby.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in RUBY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for pos, kind, message in scan_file(path, text):
            line, col = line_col(text, pos)
            yield {
                "rule": f"ruby.lifecycle.{kind}",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "ruby",
                "severity": "warning",
                "message": message,
            }


def _selftest_file_handle_detected() -> None:
    code = 'log = File.open("app.log", "w")\nlog.puts "line"\n'
    stripped = strip_comments_and_strings(code)
    match = FILE_ASSIGN.search(stripped)
    assert match is not None and match.group(1) == "log"
    assert not FILE_BLOCK.search(stripped, match.start(), match.end() + 80)
    assert not has_named_release("log", r"\.close\b", stripped, match.end())


def _selftest_close_suppression() -> None:
    code = 'log = File.open("app.log", "w")\nlog.puts "line"\nlog.close\n'
    stripped = strip_comments_and_strings(code)
    match = FILE_ASSIGN.search(stripped)
    assert match is not None
    assert has_named_release(match.group(1), r"\.close\b", stripped, match.end())


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_ruby_") -> None:
    import tempfile

    code = 'handle = File.open("data.txt")\nhandle.read\n'
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "ruby.lifecycle.file_handle"
    assert findings[0]["line"] == 1
    assert findings[0]["col"] == 1


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("file_handle_detected", _selftest_file_handle_detected),
    ("close_suppression", _selftest_close_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="ruby", name="lifecycle_ruby", run=run, selftests=SELF_TESTS))
