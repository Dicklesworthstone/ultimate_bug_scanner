"""ubs_core.analyzers.narrowing_csharp — C# null/guard narrowing analysis (bead A2).

Logic moved verbatim from modules/helpers/type_narrowing_csharp.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.io import extract_statement_region, find_block_end, line_col, skip_ws
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

_NEGATIVE_GUARD_MESSAGE = "{name} dereferenced after non-exiting null/empty guard"
_POSITIVE_GUARD_MESSAGE = "{name} dereferenced after positive null guard without narrowing the fallthrough path"
_TRY_GET_VALUE_MESSAGE = "{name} used after non-exiting TryGetValue guard"


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


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    """Return (kind, line, col, message) findings for one file's text."""
    issues: list[tuple[str, int, int, str]] = []

    for pattern in NEGATIVE_GUARD_PATTERNS:
        for line, col, message in collect_guard_issues(text, pattern, _NEGATIVE_GUARD_MESSAGE, skip_on_exit=True):
            issues.append(("negative_guard", line, col, message))
    for pattern in POSITIVE_GUARD_PATTERNS:
        for line, col, message in collect_guard_issues(text, pattern, _POSITIVE_GUARD_MESSAGE, skip_on_exit=False):
            issues.append(("positive_guard", line, col, message))
    for line, col, message in collect_guard_issues(text, TRY_GET_VALUE_PATTERN, _TRY_GET_VALUE_MESSAGE, skip_on_exit=True):
        issues.append(("try_get_value", line, col, message))

    deduped: list[tuple[str, int, int, str]] = []
    seen = set()
    for kind, line, col, message in issues:
        key = (line, col, message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((kind, line, col, message))
    return deduped


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [(line, col, message) for _, line, col, message in scan_text(text)]


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


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for kind, line, col, message in scan_text(text):
            yield {
                "rule": f"csharp.narrowing.{kind}",
                "path": rel,
                "line": line,
                "layer": "narrowing",
                "lang": "csharp",
                "col": col,
                "severity": "warning",
                "message": message,
            }


def _selftest_detects_non_exiting_null_guard() -> None:
    code = "class A { int F(string raw) { if (raw == null) { log(raw); } return raw.Length; } }"
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "negative_guard"
    assert line == 1
    assert message == "raw dereferenced after non-exiting null/empty guard"


def _selftest_exiting_guard_suppresses() -> None:
    code = "class A { int F(string raw) { if (raw == null) { return 0; } return raw.Length; } }"
    assert scan_text(code) == []


def _selftest_positive_guard_fallthrough() -> None:
    code = "class A { int F(string raw) { if (raw != null) { return raw.Length; } return raw.Length; } }"
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, _line, _col, message = findings[0]
    assert kind == "positive_guard"
    assert message == "raw dereferenced after positive null guard without narrowing the fallthrough path"


def _selftest_trygetvalue_guard() -> None:
    code = (
        "class A {\n"
        "  int F(Dictionary<string, int> map, string key) {\n"
        "    if (!map.TryGetValue(key, out var token)) { log(); }\n"
        "    return token.Length;\n"
        "  }\n"
        "}"
    )
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "try_get_value"
    assert line == 4
    assert message == "token used after non-exiting TryGetValue guard"


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_csharp_") -> None:
    import tempfile

    code = (
        "class A {\n"
        "  int F(string raw) {\n"
        "    if (raw == null) { log(raw); }\n"
        "    return raw.Length;\n"
        "  }\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.narrowing.negative_guard"
    assert findings[0]["line"] == 4
    assert findings[0]["path"] == str(target)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_non_exiting_null_guard", _selftest_detects_non_exiting_null_guard),
    ("exiting_guard_suppresses", _selftest_exiting_guard_suppresses),
    ("positive_guard_fallthrough", _selftest_positive_guard_fallthrough),
    ("trygetvalue_guard", _selftest_trygetvalue_guard),
    ("run_finds_non_exiting_guard", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="csharp", name="narrowing_csharp", run=run, selftests=SELF_TESTS))
