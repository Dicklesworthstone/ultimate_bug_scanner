"""ubs_core.analyzers.narrowing_kotlin — Kotlin null-guard type narrowing (bead A2).

Detect Kotlin null guards that do not exit before using the guarded value with
`!!`. Logic moved verbatim from modules/helpers/type_narrowing_kotlin.py, which
remains as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

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

    # Glob both .kt and .kts files (Kotlin script files)
    for ext in ("*.kt", "*.kts"):
        for path in root.rglob(ext):
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


def collect_guard_issues(text: str, pattern: re.Pattern[str], message: str, skip_on_exit: bool = True):
    issues = []
    for match in pattern.finditer(text):
        var_name = match.group(1)
        block_text, guard_end = extract_guard_region(text, match.end())
        if skip_on_exit and contains_exit(block_text):
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


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    """Return (kind, line, col, message) findings for one file's text."""
    issues: list[tuple[str, int, int, str]] = []
    # ?. guard: if (x?.prop) { ... }
    # If block exits, x might be null (if prop was false/null). So x!! is unsafe.
    # If block continues, x might be null (if prop was false/null). So x!! is unsafe.
    # So we should NOT skip on exit.
    for line, col, message in collect_guard_issues(text, SAFE_CALL_GUARD_PATTERN, "{name}!! used after ?. guard without exit", skip_on_exit=False):
        issues.append(("safecall_guard", line, col, message))

    # == null guard: if (x == null) { ... }
    # If block exits, x is not null. Safe.
    # If block continues, x is null. Unsafe.
    # So we SHOULD skip on exit.
    for line, col, message in collect_guard_issues(text, NEGATIVE_GUARD_PATTERN, "{name}!! after non-exiting null guard", skip_on_exit=True):
        issues.append(("negative_guard", line, col, message))

    # != null guard: if (x != null) { ... }
    # If block exits, x is null. Unsafe.
    # If block continues, x is null. Unsafe.
    # So we should NOT skip on exit.
    for line, col, message in collect_guard_issues(text, POSITIVE_GUARD_PATTERN, "{name}!! used after '!= null' guard without exit", skip_on_exit=False):
        issues.append(("positive_guard", line, col, message))

    for line, col, message in collect_smart_cast_issues(text):
        issues.append(("smart_cast", line, col, message))
    for line, col, message in collect_elvis_issues(text):
        issues.append(("elvis_force", line, col, message))
    return issues


def analyze_file(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    deduped = []
    seen = set()
    for _kind, line, col, message in scan_text(text):
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
    for path in iter_kotlin_files(root):
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        for line, col, message in issues:
            print(f"{path}:{line}:{col}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".kt", ".kts"}:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for kind, line, col, message in scan_text(text):
            yield {
                "rule": f"kotlin.narrowing.{kind}",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "narrowing",
                "lang": "kotlin",
                "severity": "warning",
                "message": message,
            }


def _selftest_negative_guard_detection() -> None:
    code = "fun f(job: Job?) {\n    if (job == null) { log() }\n    val n = job!!\n}\n"
    findings = [item for item in scan_text(code) if item[0] == "negative_guard"]
    assert len(findings) == 1, findings
    assert findings[0][1] == 3, findings
    assert findings[0][3] == "job!! after non-exiting null guard", findings


def _selftest_exit_guard_suppressed() -> None:
    code = "fun f(user: User?) {\n    if (user == null) { return }\n    val n = user!!\n}\n"
    findings = [item for item in scan_text(code) if item[0] == "negative_guard"]
    assert findings == [], findings
    assert scan_text(code) == [], findings


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_kotlin_") -> None:
    import tempfile

    code = "fun f(admin: Any?) {\n    val a = admin as? Admin\n    val n = a!!\n}\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "Unsafe.kt"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="kotlin", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "kotlin.narrowing.smart_cast", findings
    assert findings[0]["line"] == 3, findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("negative_guard_detection", _selftest_negative_guard_detection),
    ("exit_guard_suppressed", _selftest_exit_guard_suppressed),
    ("run_finds_smart_cast_force", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="kotlin", name="narrowing_kotlin", run=run, selftests=SELF_TESTS))
