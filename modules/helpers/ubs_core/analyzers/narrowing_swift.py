"""ubs_core.analyzers.narrowing_swift — Swift guard let / optional binding narrowing analysis (bead A2).

The standalone helper remains a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ubs_core.io import line_col
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", ".hg", ".svn", "build", "DerivedData", ".swiftpm", ".idea", "node_modules"}
GUARD_PATTERN = re.compile(r"\bguard\s+let\s+([A-Za-z_]\w*)\s*=\s*[^\n]+?\s+else\s*\{")
NEGATIVE_NIL_GUARD = re.compile(r"\bif\b\s*\(?\s*([A-Za-z_]\w*)\s*==\s*nil\b[^{};]*\{")
POSITIVE_NIL_GUARD = re.compile(r"\bif\b\s*\(?\s*([A-Za-z_]\w*)\s*!=\s*nil\b[^{};]*\{")
OPTIONAL_CHAIN_GUARD = re.compile(r"\bif\b\s*\(?\s*([A-Za-z_]\w*)\s*\?\.[^{};]*\{")
EXIT_PATTERN = re.compile(
    r"\b(?:return|throw|break|continue)\b|\b(?:fatalError|preconditionFailure)\b",
    re.IGNORECASE,
)

# (kind, pattern, message template, skip_on_exit) — messages must stay byte-identical
# with the original helper's main() stdout.
_GUARD_SPECS = (
    ("negative_nil_guard", NEGATIVE_NIL_GUARD, "{name}! used after == nil guard without exit", True),
    ("positive_nil_guard", POSITIVE_NIL_GUARD, "{name}! used after '!= nil' guard without exit", False),
    ("optional_chain_guard", OPTIONAL_CHAIN_GUARD, "{name}! forced after ?. guard without exit", False),
)
_GUARD_LET_KIND = "guard_let_no_exit"
_GUARD_LET_TEMPLATE = "guard let '{name}' else-block does not exit before continuing"


def iter_swift_files(root: Path):
    if root.is_file():
        if root.suffix == ".swift" and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for path in root.rglob("*.swift"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def brace_scopes(code: str):
    """Index each block and its parent once, at original source offsets."""
    stack = []
    parents = {}
    ends = {None: len(code)}
    for brace in re.finditer(r"[{}]", code):
        pos = brace.start()
        if code[pos] == "{":
            parents[pos] = stack[-1] if stack else None
            ends[pos] = len(code)
            stack.append(pos)
        elif stack:
            ends[stack.pop()] = pos
    return parents, ends


def unwrap_after_guard(code: str, start: int, end: int, name: str) -> int | None:
    # A selected member of another object does not write or unwrap this
    # unqualified binding, even across whitespace or comments after the dot.
    operation = re.compile(rf"\b{re.escape(name)}(?:!(?!=)|\s*=(?!=))")
    for match in operation.finditer(code, start, end):
        previous = match.start() - 1
        while previous >= 0 and code[previous].isspace():
            previous -= 1
        if previous >= 0 and code[previous] == ".":
            continue
        return match.start() if match[0].endswith("!") else None
    return None


def scan_text(path: Path, text: str) -> list[tuple[str, Path, int, int, str]]:
    """Return (kind, path, line, col, message) findings for one file's text."""
    issues: list[tuple[str, Path, int, int, str]] = []
    code = strip_comments_and_strings(text, "swift")
    parents, ends = brace_scopes(code)
    for kind, pattern, template, skip_on_exit in _GUARD_SPECS:
        for match in pattern.finditer(code):
            brace = match.end() - 1
            if skip_on_exit and EXIT_PATTERN.search(code, brace, ends[brace]):
                continue
            name = match.group(1)
            pos = unwrap_after_guard(code, ends[brace] + 1, ends[parents[brace]], name)
            if pos is not None:
                line, col = line_col(text, pos)
                issues.append((kind, path, line, col, template.format(name=name)))
    for match in GUARD_PATTERN.finditer(code):
        name = match.group(1)
        brace = match.end() - 1
        if EXIT_PATTERN.search(code, brace, ends[brace]):
            continue
        line, col = line_col(text, match.start())
        message = _GUARD_LET_TEMPLATE.format(name=name)
        issues.append((_GUARD_LET_KIND, path, line, col, message))
    return issues


def collect_issues(root: Path) -> list[tuple[str, Path, int, int, str]]:
    issues: list[tuple[str, Path, int, int, str]] = []
    for path in iter_swift_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        issues.extend(scan_text(path, text))
    return issues


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print("Usage: type_narrowing_swift.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for path in iter_swift_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for _kind, fpath, line, col, message in scan_text(path, text):
            print(f"{fpath}:{line}:{col}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix != ".swift":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, _fpath, line, col, message in scan_text(path, text):
            rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
            yield {
                "rule": f"swift.narrowing.{kind}",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "narrowing",
                "lang": "swift",
                "severity": "warning",
                "message": message,
            }


def _selftest_guard_let_detects_missing_exit() -> None:
    code = (
        "func f(raw: String?) {\n"
        "    guard let name = raw else {\n"
        "        print(\"missing\")\n"
        "    }\n"
        "    print(name)\n"
        "}\n"
    )
    issues = scan_text(Path("F.swift"), code)
    assert len(issues) == 1, issues
    kind, _path, line, _col, message = issues[0]
    assert kind == "guard_let_no_exit"
    assert line == 2, line
    assert message == "guard let 'name' else-block does not exit before continuing"


def _selftest_guard_let_suppressed_by_return() -> None:
    code = (
        "func f(raw: String?) {\n"
        "    guard let name = raw else {\n"
        "        return\n"
        "    }\n"
        "    print(name)\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code) == []


def _selftest_nil_guard_suppression() -> None:
    escaped = (
        "func f(x: String?) {\n"
        "    if x == nil {\n"
        "        return\n"
        "    }\n"
        "    print(x!.count)\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), escaped) == []
    unsafe = (
        "func f(x: String?) {\n"
        "    if x != nil {\n"
        "        NSLog(\"might exist\")\n"
        "    }\n"
        "    NSLog(\"length \\(x!.count)\")\n"
        "}\n"
    )
    issues = scan_text(Path("F.swift"), unsafe)
    assert len(issues) == 1, issues
    kind, _path, line, _col, _message = issues[0]
    assert kind == "positive_nil_guard"
    assert line == 5, line


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_swift_") -> None:
    import tempfile

    code = (
        "func f(raw: String?) {\n"
        "    guard let name = raw else {\n"
        "        print(\"missing\")\n"
        "    }\n"
        "    print(name)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "F.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.narrowing.guard_let_no_exit"
    assert findings[0]["line"] == 2
    assert findings[0]["col"] == 5
    assert findings[0]["lang"] == "swift"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("guard_let_detects_missing_exit", _selftest_guard_let_detects_missing_exit),
    ("guard_let_suppressed_by_return", _selftest_guard_let_suppressed_by_return),
    ("nil_guard_suppression", _selftest_nil_guard_suppression),
    ("run_finds_guard_let", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="swift", name="narrowing_swift", run=run, selftests=SELF_TESTS))
