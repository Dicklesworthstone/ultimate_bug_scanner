"""ubs_core.analyzers.lifecycle_csharp — C# disposable/resource lifecycle analysis (bead A2).

Logic moved verbatim from modules/helpers/resource_lifecycle_csharp.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
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

RESOURCE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "warning",
        "Stream-like handle acquired without using/Dispose/Close",
        re.compile(
            r"\b(?:var|FileStream|StreamReader|StreamWriter|BinaryReader|BinaryWriter)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(?:FileStream|StreamReader|StreamWriter|BinaryReader|BinaryWriter)\b",
            re.MULTILINE,
        ),
    ),
    (
        "warning",
        "CancellationTokenSource acquired without Dispose",
        re.compile(
            r"\b(?:var|CancellationTokenSource)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+CancellationTokenSource\b",
            re.MULTILINE,
        ),
    ),
    (
        "warning",
        "Timer/PeriodicTimer acquired without Dispose",
        re.compile(
            r"\b(?:var|Timer|PeriodicTimer)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(?:Timer|PeriodicTimer)\b",
            re.MULTILINE,
        ),
    ),
    (
        "warning",
        "HttpRequestMessage created without Dispose",
        re.compile(
            r"\b(?:var|HttpRequestMessage)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+HttpRequestMessage\b",
            re.MULTILINE,
        ),
    ),
    (
        "warning",
        "HttpResponseMessage result not disposed",
        re.compile(
            r"\b(?:var|HttpResponseMessage)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:await\s+)?[^;\n]*\.(?:GetAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync)\s*\(",
            re.MULTILINE,
        ),
    ),
    (
        "warning",
        "SQL disposable handle acquired without Dispose/Close",
        re.compile(
            r"\b(?:var|SqlConnection|SqlCommand|SqlDataReader)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+(?:SqlConnection|SqlCommand)\b|(?:await\s+)?[^;\n]*\.ExecuteReader\s*\()",
            re.MULTILINE,
        ),
    ),
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


def line_number(text: str, pos: int) -> int:
    return line_col(text, pos)[0]


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


def using_declared(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("using ") or stripped.startswith("await using ")


def has_release(name: str, code_text: str, start_pos: int) -> bool:
    release_patterns = (
        re.compile(rf"\b{name}\.(?:Dispose|DisposeAsync|Close)\s*\("),
        re.compile(rf"\bawait\s+using\s+var\s+{name}\b"),
        re.compile(rf"\busing\s+var\s+{name}\b"),
    )
    return any(pattern.search(code_text, start_pos) for pattern in release_patterns)


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, str, int, str]]:
    """Return (display, severity, line, message) findings for one file's text."""
    issues: list[tuple[str, str, int, str]] = []
    if not text.strip():
        return issues
    code_text = strip_comments_and_strings(text)
    try:
        display = str(path.relative_to(base))
    except ValueError:
        display = str(path)
    seen = set()
    for severity, message, pattern in RESOURCE_PATTERNS:
        for match in pattern.finditer(code_text):
            name = match.group(1)
            if name == "_":
                continue
            start = match.start()
            line = line_number(text, start)
            if using_declared(line_text(text, start)):
                continue
            if has_release(name, code_text, start):
                continue
            key = (display, line, message)
            if key in seen:
                continue
            seen.add(key)
            issues.append((display, severity, line, message))
    return issues


def collect_issues(root: Path) -> list[tuple[str, str, int, str]]:
    issues: list[tuple[str, str, int, str]] = []
    base = root if root.is_dir() else root.parent
    for path in iter_csharp_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        issues.extend(scan_text(path, text, base))
    return issues


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("usage: resource_lifecycle_csharp.py <project_dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for rel, severity, line, message in collect_issues(root):
        print(f"{rel}:{line}:1\t{severity}\t{message}")
    return 0


_KIND = {
    "Stream-like handle acquired without using/Dispose/Close": "stream_handle",
    "CancellationTokenSource acquired without Dispose": "cts_handle",
    "Timer/PeriodicTimer acquired without Dispose": "timer_handle",
    "HttpRequestMessage created without Dispose": "http_request_message",
    "HttpResponseMessage result not disposed": "http_response_message",
    "SQL disposable handle acquired without Dispose/Close": "sql_handle",
}


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for display, severity, line, message in scan_text(path, text, cwd):
            yield {
                "rule": f"csharp.lifecycle.{_KIND[message]}",
                "path": display,
                "line": line,
                "layer": "lifecycle",
                "lang": "csharp",
                "severity": severity,
                "message": message,
            }


def _selftest_stream_leak() -> None:
    code = (
        "class A {\n"
        "  void F() {\n"
        "    var s = new FileStream(p, FileMode.Open);\n"
        "    s.Read(b);\n"
        "  }\n"
        "}"
    )
    code_text = strip_comments_and_strings(code)
    match = RESOURCE_PATTERNS[0][2].search(code_text)
    assert match is not None
    assert not using_declared(line_text(code, match.start()))
    assert not has_release(match.group(1), code_text, match.start())


def _selftest_suppression() -> None:
    using_decl = (
        "class A {\n"
        "  void F() {\n"
        "    using var s = new FileStream(p, FileMode.Open);\n"
        "    s.Read(b);\n"
        "  }\n"
        "}"
    )
    code_text = strip_comments_and_strings(using_decl)
    match = RESOURCE_PATTERNS[0][2].search(code_text)
    assert match is not None
    assert using_declared(line_text(using_decl, match.start()))

    disposed = (
        "class A {\n"
        "  void F() {\n"
        "    var s = new FileStream(p, FileMode.Open);\n"
        "    s.Read(b);\n"
        "    s.Dispose();\n"
        "  }\n"
        "}"
    )
    code_text = strip_comments_and_strings(disposed)
    match = RESOURCE_PATTERNS[0][2].search(code_text)
    assert match is not None
    assert not using_declared(line_text(disposed, match.start()))
    assert has_release(match.group(1), code_text, match.start())


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_csharp_") -> None:
    import tempfile

    code = (
        "using System.IO;\n"
        "class A {\n"
        "  void F() {\n"
        "    var s = new FileStream(p, FileMode.Open);\n"
        "    s.Read(b);\n"
        "  }\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.lifecycle.stream_handle"
    assert findings[0]["line"] == 4
    assert findings[0]["message"] == "Stream-like handle acquired without using/Dispose/Close"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("stream_leak_detected", _selftest_stream_leak),
    ("using_suppression", _selftest_using_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="csharp", name="lifecycle_csharp", run=run, selftests=SELF_TESTS))
