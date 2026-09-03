"""ubs_core.analyzers.lifecycle_cpp — C/C++ resource lifecycle analysis (bead A2).

Logic moved verbatim from modules/helpers/resource_lifecycle_cpp.py, which remains
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

_MESSAGE = {
    "thread_join": "std::thread is started without join/detach",
    "malloc_heap": "Heap allocation is never released with free()",
    "fopen_handle": "FILE* handle is never closed with fclose()",
}


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


def scan_text(path: Path, text: str, project_root: Path) -> list[tuple[str, str, str, int, int]]:
    """Return (kind, name, rel_path, line, col) findings for one file's text."""
    findings: list[tuple[str, str, str, int, int]] = []
    if not text.strip():
        return findings
    code = strip_comments_and_strings(text)
    try:
        rel = path.relative_to(project_root)
    except ValueError:
        rel = path
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, name: str, pos: int) -> None:
        line, col = line_col(text, pos)
        loc = f"{rel}:{line}:{col}"
        issue = (loc, kind, f"{_MESSAGE[kind]} ({name})")
        if issue not in seen:
            seen.add(issue)
            findings.append((kind, name, str(rel), line, col))

    for pattern in (THREAD_DECL, THREAD_AUTO):
        for match in pattern.finditer(code):
            name = match.group(1)
            if name == "_" or is_thread_function_decl(name, text, match.start()):
                continue
            if has_thread_release(name, code, match.end()):
                continue
            add("thread_join", name, match.start())

    for match in MALLOC_ASSIGN.finditer(code):
        name = match.group(1)
        if name == "_" or has_c_release(name, "free", code, match.end()):
            continue
        add("malloc_heap", name, match.start())

    for pattern in (FOPEN_ASSIGN, FOPEN_REASSIGN):
        for match in pattern.finditer(code):
            name = match.group(1)
            if name == "_" or has_c_release(name, "fclose", code, match.end()):
                continue
            add("fopen_handle", name, match.start())

    return findings


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_cpp_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, name, rel, line, col in scan_text(path, text, base):
            issues.append((f"{rel}:{line}:{col}", kind, f"{_MESSAGE[kind]} ({name})"))

    return issues


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_cpp.py <project_dir>", file=sys.stderr)
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
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, name, rel, line, col in scan_text(path, text, cwd):
            yield {
                "rule": f"cpp.lifecycle.{kind}",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "cpp",
                "severity": "warning",
                "message": f"{_MESSAGE[kind]} ({name})",
            }


def _selftest_thread_join_positive() -> None:
    import tempfile

    code = "void f() {\n    std::thread worker(run_task);\n}\n"
    root = Path(tempfile.gettempdir())
    findings = scan_text(root / "probe.cpp", code, root)
    assert len(findings) == 1, findings
    kind, name, _rel, line, _col = findings[0]
    assert kind == "thread_join", kind
    assert name == "worker", name
    assert line == 2, line


def _selftest_release_suppression() -> None:
    import tempfile

    code = (
        "void f() {\n"
        "    std::thread worker(run_task);\n"
        "    worker.join();\n"
        "    char* buf = (char*)malloc(32);\n"
        "    free(buf);\n"
        "    FILE* fp = fopen(\"x\", \"r\");\n"
        "    fclose(fp);\n"
        "}\n"
    )
    root = Path(tempfile.gettempdir())
    findings = scan_text(root / "probe.cpp", code, root)
    assert findings == [], findings


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_cpp_") -> None:
    import tempfile

    code = "void f() {\n    char* buf = (char*)malloc(32);\n}\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "cpp.lifecycle.malloc_heap"
    assert findings[0]["line"] == 2


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("thread_join_positive", _selftest_thread_join_positive),
    ("release_suppression", _selftest_release_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="cpp", name="lifecycle_cpp", run=run, selftests=SELF_TESTS))
