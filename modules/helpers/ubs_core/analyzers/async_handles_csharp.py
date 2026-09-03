"""ubs_core.analyzers.async_handles_csharp — unobserved C# Task.Run/StartNew handle analysis (bead A2).

Logic moved verbatim from modules/helpers/async_task_handles_csharp.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.io import line_col
from ubs_core.lexer import strip_comments_and_strings as core_strip
from ubs_core.registry import Analyzer, RunContext, register

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


def scan_text(text: str) -> list[tuple[int, int, str]]:
    """Return (line, col, message) findings for one file's text."""
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


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return scan_text(text)


def collect_issues(root: Path) -> list[tuple[Path, int, int, str]]:
    """Return (display_path, line, col, message) findings for every file under root."""
    base = root if root.is_dir() else root.parent
    results: list[tuple[Path, int, int, str]] = []
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
            results.append((display, line, col, message))
    return results


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: async_task_handles_csharp.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for display, line, col, message in collect_issues(root):
        print(f"{display}:{line}:{col}\twarning\tunobserved_task_handle\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for line, col, message in issues:
            yield {
                "rule": "csharp.lifecycle.unobserved_task_handle",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "csharp",
                "severity": "warning",
                "message": message,
            }


def _selftest_detects_unobserved() -> None:
    code = "var job = Task.Run(() => 1);\n_ = job.Id;\n"
    issues = scan_text(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 1 and col == 1, issues[0]
    assert "job" in message


def _selftest_awaits_suppresses() -> None:
    assert scan_text("var job = Task.Run(() => 1);\nawait job.ConfigureAwait(false);\n") == []
    assert scan_text("var started = Task.Factory.StartNew(() => 2); return started;") == []


def _selftest_run(tmp_prefix: str = "ubs_core_async_handles_csharp_") -> None:
    import tempfile

    code = "public class A { void F() { var job = Task.Factory.StartNew(() => 2); } }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.lifecycle.unobserved_task_handle"
    assert findings[0]["line"] == 1


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_unobserved_handle", _selftest_detects_unobserved),
    ("await_suppresses", _selftest_awaits_suppresses),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="csharp", name="async_handles_csharp", run=run, selftests=SELF_TESTS))
