"""ubs_core.analyzers.narrowing_cpp — C++ partial-null-guard narrowing analysis (bead D4).

Detects null guards whose branch does not exit:

- ``if (!p) { log; }`` followed later by ``p->field`` or ``*p`` — the branch
  merely logs, so the fall-through path still runs with ``p`` possibly null;
- ``if (p == nullptr)`` (also ``NULL``/``0``, either operand order) whose
  branch falls through and is followed by a dereference of ``p``.

The guard branch must exit (``return``/``throw``/``continue``/``break``/
``goto``/``exit``/``abort``) for the fall-through path to be safe; a re-binding
of the pointer between guard and use also re-narrows it. A use inside a
balanced ``else`` branch is safe (that path is the non-null case).

`UBS_SKIP_TYPE_NARROWING=1` disables the analyzer (uniform D4 gate in `run`).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.io import extract_statement_region, line_col, skip_ws
from ubs_core.registry import Analyzer, RunContext, register

_RULE = "cpp.narrowing.partial_null_guard"
_NEGATION_MESSAGE = "{name} dereferenced after non-exiting negation guard"
_NULL_COMPARE_MESSAGE = "{name} dereferenced after non-exiting null-comparison guard"

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "build",
    "out",
    "dist",
    "target",
    "cmake-build-debug",
    "cmake-build-release",
    "node_modules",
}

CPP_SUFFIXES = frozenset({".cpp", ".cc", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++", ".ipp", ".tpp"})

# `if (!p)` / `if (!p || other)` — the branch handles the null case.
NEGATION_GUARD_PATTERN = re.compile(r"if\s*\(\s*!\s*([A-Za-z_]\w*)\s*\)", re.MULTILINE)
# `if (p == nullptr)` / `if (p == NULL)` / `if (p == 0)` and Yoda order.
NULL_COMPARE_GUARD_PATTERNS = (
    re.compile(r"if\s*\(\s*([A-Za-z_]\w*)\s*==\s*(?:nullptr|NULL|0)\b[^)]*\)", re.MULTILINE),
    re.compile(r"if\s*\(\s*(?:nullptr|NULL|0)\s*==\s*([A-Za-z_]\w*)\b[^)]*\)", re.MULTILINE),
)

ASSIGN_TEMPLATE = r"\b{name}\s*=(?!=)"
ARROW_TEMPLATE = r"\b{name}\s*->"
STAR_TEMPLATE = r"\*\s*{name}\b"
EXIT_PATTERN = re.compile(r"\b(?:return|throw|continue|break|goto|exit|abort)\b")
ELSE_PATTERN = re.compile(r"\belse\b")
IF_PATTERN = re.compile(r"\bif\b")
COMMENT_PATTERN = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def iter_cpp_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in CPP_SUFFIXES and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for ext in ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hh", "*.hpp", "*.hxx"):
        for path in root.rglob(ext):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


def contains_exit(block_text: str) -> bool:
    return bool(EXIT_PATTERN.search(COMMENT_PATTERN.sub(" ", block_text)))


def _matching_paren(text: str, open_idx: int) -> int:
    """Index of the `)` closing the `(` at open_idx, or len(text)."""
    depth = 0
    n = len(text)
    for idx in range(open_idx, n):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return n


def skip_optional_else(text: str, idx: int) -> int:
    """Skip a balanced `else` / `else if` chain after a guard body."""
    while True:
        idx = skip_ws(text, idx)
        if not ELSE_PATTERN.match(text, idx):
            return idx
        idx = skip_ws(text, idx + len("else"))
        if IF_PATTERN.match(text, idx):
            open_paren = text.find("(", idx)
            if open_paren == -1:
                return idx
            idx = _matching_paren(text, open_paren) + 1
        _, idx = extract_statement_region(text, idx)


def find_unsafe_use(text: str, name: str, start_idx: int) -> tuple[int, int] | None:
    """Earliest (line, col) dereference of name (`name->` / `*name`) at/after start_idx.

    A re-binding of name between start_idx and the use cancels the finding.
    """
    assign_regex = re.compile(ASSIGN_TEMPLATE.format(name=re.escape(name)))
    arrow_regex = re.compile(ARROW_TEMPLATE.format(name=re.escape(name)))
    star_regex = re.compile(STAR_TEMPLATE.format(name=re.escape(name)))
    candidates = []
    arrow_match = arrow_regex.search(text, start_idx)
    if arrow_match:
        candidates.append(arrow_match)
    star_match = star_regex.search(text, start_idx)
    while star_match:
        # A `*` glued to a left operand (`a * p`, `f(x) * p`, `arr[i] * p`)
        # is multiplication, not a dereference.
        prev = text[star_match.start() - 1] if star_match.start() > 0 else ""
        if not (prev.isalnum() or prev in ")]_."):
            candidates.append(star_match)
            break
        star_match = star_regex.search(text, star_match.end())
    if not candidates:
        return None
    earliest = min(candidates, key=lambda match: match.start())
    if assign_regex.search(text, start_idx, earliest.start()):
        return None
    return line_col(text, earliest.start())


def collect_guard_issues(text: str, pattern: re.Pattern[str], message: str) -> list[tuple[int, int, str]]:
    issues: list[tuple[int, int, str]] = []
    for match in pattern.finditer(text):
        name = match.group(1)
        block_text, guard_end = extract_statement_region(text, match.end())
        if contains_exit(block_text):
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
    for line, col, message in collect_guard_issues(text, NEGATION_GUARD_PATTERN, _NEGATION_MESSAGE):
        issues.append(("negation_guard", line, col, message))
    for pattern in NULL_COMPARE_GUARD_PATTERNS:
        for line, col, message in collect_guard_issues(text, pattern, _NULL_COMPARE_MESSAGE):
            issues.append(("null_compare_guard", line, col, message))

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
        print("Usage: narrowing_cpp.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    base = root if root.is_dir() else root.parent
    for path in iter_cpp_files(root):
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
    if os.environ.get("UBS_SKIP_TYPE_NARROWING", "") == "1":
        return []
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in CPP_SUFFIXES:
            continue
        try:
            issues = scan_text(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        try:
            rel = str(path.resolve().relative_to(cwd))
        except ValueError:
            rel = str(path)
        for _kind, line, col, message in issues:
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line,
                "layer": "narrowing",
                "lang": "cpp",
                "severity": "warning",
                "message": message,
                "col": col,
            }


def _analyze_snippet(code: str) -> list[tuple[int, int, str]]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_narrowing_cpp_") as tmp:
        target = Path(tmp) / "snippet.cpp"
        target.write_text(code, encoding="utf-8")
        return analyze_file(target)


def _selftest_detects_arrow_after_negation_guard() -> None:
    code = (
        "struct S { int id; };\n"
        "int f(S *p) {\n"
        "    if (!p) { log_null(); }\n"
        "    return p->id;\n"
        "}\n"
    )
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "negation_guard", findings
    assert line == 4, findings
    assert message == "p dereferenced after non-exiting negation guard", findings


def _selftest_detects_star_after_null_compare_guard() -> None:
    code = (
        "int f(int *p) {\n"
        "    if (p == nullptr) { log_null(); }\n"
        "    return *p;\n"
        "}\n"
    )
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "null_compare_guard", findings
    assert line == 3, findings
    assert message == "p dereferenced after non-exiting null-comparison guard", findings


def _selftest_exiting_guard_suppresses() -> None:
    code = (
        "int f(int *p) {\n"
        "    if (p == nullptr) { return -1; }\n"
        "    return *p;\n"
        "}\n"
    )
    assert scan_text(code) == [], scan_text(code)


def _selftest_else_branch_use_is_safe() -> None:
    code = (
        "int f(int *p) {\n"
        "    if (!p) { log_null(); } else { return *p; }\n"
        "    return 0;\n"
        "}\n"
    )
    assert scan_text(code) == [], scan_text(code)


def _selftest_reassignment_suppresses() -> None:
    # After the guarded pointer is re-bound, a later dereference is not the guard's fault.
    code = (
        "int f(int *p) {\n"
        "    int local = 7;\n"
        "    if (!p) { log_null(); }\n"
        "    p = &local;\n"
        "    return *p;\n"
        "}\n"
    )
    assert scan_text(code) == [], scan_text(code)


def _selftest_run_and_skip_gate(tmp_prefix: str = "ubs_core_narrowing_cpp_run_") -> None:
    import tempfile

    code = (
        "int f(int *p) {\n"
        "    if (p == NULL) { log_null(); }\n"
        "    return *p;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
        assert len(findings) == 1, findings
        assert findings[0]["rule"] == "cpp.narrowing.partial_null_guard", findings[0]
        assert findings[0]["line"] == 3, findings[0]
        assert findings[0]["lang"] == "cpp", findings[0]
        previous = os.environ.get("UBS_SKIP_TYPE_NARROWING")
        os.environ["UBS_SKIP_TYPE_NARROWING"] = "1"
        try:
            assert list(run(RunContext(lang="cpp", files=[target]))) == []
        finally:
            if previous is None:
                os.environ.pop("UBS_SKIP_TYPE_NARROWING", None)
            else:
                os.environ["UBS_SKIP_TYPE_NARROWING"] = previous


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_arrow_after_negation_guard", _selftest_detects_arrow_after_negation_guard),
    ("detects_star_after_null_compare_guard", _selftest_detects_star_after_null_compare_guard),
    ("exiting_guard_suppresses", _selftest_exiting_guard_suppresses),
    ("else_branch_use_is_safe", _selftest_else_branch_use_is_safe),
    ("reassignment_suppresses", _selftest_reassignment_suppresses),
    ("run_and_skip_gate", _selftest_run_and_skip_gate),
)

register(Analyzer(layer="narrowing", lang="cpp", name="narrowing_cpp", run=run, selftests=SELF_TESTS))
