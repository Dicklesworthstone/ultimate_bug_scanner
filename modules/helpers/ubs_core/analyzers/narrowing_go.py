"""ubs_core.analyzers.narrowing_go — Go error/nil-guard narrowing analysis (bead 1b9j.4).

Detects partial guards whose block falls through, leaving the guarded value
unusable on the continuation path:

1. `if err != nil { log/... }` whose block does not exit (no return/continue/
   break/goto, panic, os.Exit, log.Fatal*, or runtime.Goexit) followed by use
   of the guarded error or of the companion value from the `x, err := ...`
   assignment that produced it — the companion may be a zero value whenever
   the guard fell through (rule go.narrowing.partial_err_guard).
2. `if p == nil { log/... }` whose block does not exit followed by a
   `p.field` / `p[index]` dereference — p may still be nil on the fallthrough
   path.

Scanning runs on comment/string-stripped text with offsets preserved. Only
exact single conditions narrow (`||`/`&&` tails change the contract and are
left alone). Three guards count as handled and are not scanned: an exiting
block (narrowing holds on the fallthrough path), a re-check
`if name ==/!= nil` guard between the partial guard and a candidate use (the
re-check is the narrowing point), and an init-scoped guard
(`if err := f(); err != nil {` — the names are invisible past the chain in
valid Go). A non-exiting guard whose error branch reassigns the companion
likewise re-establishes the value for the fallthrough path. Also exposes a
structured `run(ctx)` for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Callable, Iterable

from ubs_core.io import extract_statement_region, find_block_end, line_col, skip_ws
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", ".hg", ".svn", "vendor", "node_modules", "dist", "build", "bin", ".venv"}

_RULE = "go.narrowing.partial_err_guard"

# `if err != nil {` / `if p == nil {`, optionally behind an init statement
# (`if v, err := f(); err != nil {`). The lookahead keeps match.end() on the
# `{` so extract_statement_region sees the guard body directly.
ERR_GUARD_PATTERN = re.compile(
    r"\bif\b(?:[^;{}]*;)?\s*\(?\s*([A-Za-z_]\w*)\s*!=\s*nil\s*\)?(?=\{)", re.MULTILINE
)
NIL_GUARD_PATTERN = re.compile(
    r"\bif\b(?:[^;{}]*;)?\s*\(?\s*([A-Za-z_]\w*)\s*==\s*nil\s*\)?(?=\{)", re.MULTILINE
)
RECHECK_PATTERN = re.compile(
    r"\bif\b(?:[^;{}]*;)?\s*\(?\s*([A-Za-z_]\w*)\s*(?:==|!=)\s*nil\s*\)?(?=\{)", re.MULTILINE
)
# `x, err := ...` / `x, err = ...` (longer tuples allowed, `err` must be last).
PAIR_ASSIGN_PATTERN = re.compile(
    r"\b([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*?)\s*,\s*([A-Za-z_]\w*)\s*:?=(?!=)"
)
ELSE_PATTERN = re.compile(r"\belse\b")
EXIT_PATTERN = re.compile(
    r"\b(?:return|continue|break|goto)\b"
    r"|\bpanic\s*\("
    r"|\bos\.Exit\s*\("
    r"|\blog\.(?:Fatal|Fatalf|Fatalln)\s*\("
    r"|\bruntime\.Goexit\s*\("
)
ASSIGN_TEMPLATE = r"\b{name}\s*:?=(?!=)"
REF_TEMPLATE = r"\b{name}\b"
MEMBER_TEMPLATE = r"\b{name}\s*\."
INDEX_TEMPLATE = r"\b{name}\s*\["

_ERR_MESSAGE = "{name} used after non-exiting err guard"
_NIL_MESSAGE = "{name} dereferenced after non-exiting nil guard"


def iter_go_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() == ".go" and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for path in root.rglob("*.go"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def contains_exit(block_text: str) -> bool:
    return bool(EXIT_PATTERN.search(block_text))


def skip_optional_else(text: str, idx: int) -> int:
    """Step over an `else` / `else if` branch following a guard block."""
    idx = skip_ws(text, idx)
    match = ELSE_PATTERN.match(text, idx)
    if not match:
        return idx
    idx = skip_ws(text, match.end())
    if idx < len(text) and text[idx] == "{":
        return find_block_end(text, idx) + 1
    brace = text.find("{", idx)
    if brace == -1:
        _, end = extract_statement_region(text, idx)
        return end
    return find_block_end(text, brace) + 1


def companions_for(text: str, match: re.Match[str], name: str) -> list[str]:
    """Return companion names bound alongside `name` by the nearest pair assignment.

    The init statement of the guard itself (`if data, err := f(); err != nil {`)
    takes precedence over earlier assignments elsewhere in the file.
    """
    regions = (text[match.start() : match.start(1)], text[: match.start()])
    for region in regions:
        found: list[str] = []
        for pair in PAIR_ASSIGN_PATTERN.finditer(region):
            if pair.group(2) == name:
                found = [part.strip() for part in pair.group(1).split(",")]
        if found:
            return found
    return []


def guard_is_scoped(text: str, match: re.Match[str]) -> bool:
    """True when the guarded name is scoped to the if statement's init clause.

    `if err := f(); err != nil { ... }` makes the names invisible past the
    if/else chain in valid Go, so nothing after the guard can use them.
    """
    return ";" in text[match.start() : match.start(1)]


_ASSIGN_CACHE: dict[str, re.Pattern[str]] = {}


def _assign_pattern(name: str) -> re.Pattern[str]:
    rx = _ASSIGN_CACHE.get(name)
    if rx is None:
        rx = _ASSIGN_CACHE[name] = re.compile(ASSIGN_TEMPLATE.format(name=re.escape(name)))
    return rx


def _ref_patterns(name: str) -> tuple[re.Pattern[str], ...]:
    return (re.compile(REF_TEMPLATE.format(name=re.escape(name))),)


def _deref_patterns(name: str) -> tuple[re.Pattern[str], ...]:
    return (
        re.compile(MEMBER_TEMPLATE.format(name=re.escape(name))),
        re.compile(INDEX_TEMPLATE.format(name=re.escape(name))),
    )


def find_unsafe_use(
    text: str,
    start: int,
    watch: tuple[str, ...],
    use_patterns: Callable[[str], tuple[re.Pattern[str], ...]],
) -> tuple[int, int, str] | None:
    """Locate the first offending use of a watched name at/after `start`.

    Returns (line, col, name) or None. The search gives up when a watched name
    is reassigned first (the value was refreshed) or when a re-check
    `if name ==/!= nil` guard appears first (the re-check is the narrowing
    point). An offending use before either wins.
    """
    best: tuple[int, int, str, re.Match[str], str] | None = None
    for name in watch:
        assign = _assign_pattern(name).search(text, start)
        if assign and (best is None or (assign.start(), 0) < best[:2]):
            best = (assign.start(), 0, "assign", assign, name)
        for rx in use_patterns(name):
            use = rx.search(text, start)
            if use and (best is None or (use.start(), 1) < best[:2]):
                best = (use.start(), 1, "use", use, name)
    recheck = RECHECK_PATTERN.search(text, start)
    if recheck and recheck.group(1) in watch and (best is None or recheck.start() < best[0]):
        return None
    if best is None or best[2] == "assign":
        return None
    _, _, _, found, name = best
    line, col = line_col(text, found.start())
    return line, col, name


def collect_err_guard_issues(text: str) -> list[tuple[int, int, str]]:
    """Flag uses of err / its companions after a non-exiting `err != nil` guard."""
    issues: list[tuple[int, int, str]] = []
    for match in ERR_GUARD_PATTERN.finditer(text):
        name = match.group(1)
        block_text, guard_end = extract_statement_region(text, match.end())
        if contains_exit(block_text):
            continue
        watch = (name, *companions_for(text, match, name))
        if guard_is_scoped(text, match):
            continue
        if any(_assign_pattern(c).search(block_text) for c in watch[1:]):
            # The guard's error branch reassigns the companion, re-establishing
            # the value for the fallthrough path in both cases.
            continue
        loc = find_unsafe_use(text, skip_optional_else(text, guard_end), watch, _ref_patterns)
        if not loc:
            continue
        line, col, used = loc
        issues.append((line, col, _ERR_MESSAGE.format(name=used)))
    return issues


def collect_nil_guard_issues(text: str) -> list[tuple[int, int, str]]:
    """Flag dereferences after a non-exiting `p == nil` guard."""
    issues: list[tuple[int, int, str]] = []
    for match in NIL_GUARD_PATTERN.finditer(text):
        name = match.group(1)
        block_text, guard_end = extract_statement_region(text, match.end())
        if contains_exit(block_text):
            continue
        loc = find_unsafe_use(text, skip_optional_else(text, guard_end), (name,), _deref_patterns)
        if not loc:
            continue
        line, col, used = loc
        issues.append((line, col, _NIL_MESSAGE.format(name=used)))
    return issues


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    """Return (kind, line, col, message) findings for one file's text."""
    stripped = strip_comments_and_strings(text, lang="go")
    issues: list[tuple[str, int, int, str]] = []
    for line, col, message in collect_err_guard_issues(stripped):
        issues.append(("err_guard", line, col, message))
    for line, col, message in collect_nil_guard_issues(stripped):
        issues.append(("nil_guard", line, col, message))
    deduped: list[tuple[str, int, int, str]] = []
    seen: set[tuple[int, int, str]] = set()
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
        print("usage: python3 -m ubs_core.analyzers.narrowing_go <path>", file=sys.stderr)
        return 2
    for path in iter_go_files(Path(sys.argv[1])):
        for line, col, message in analyze_file(path):
            print(f"{path}:{line}:{col} - {message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    if os.environ.get("UBS_SKIP_TYPE_NARROWING", "") == "1":
        return []
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() != ".go":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for kind, line, col, message in scan_text(text):
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line,
                "layer": "narrowing",
                "lang": "go",
                "col": col,
                "severity": "warning",
                "message": message,
            }


def _analyze_snippet(code: str) -> list[tuple[int, int, str]]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_narrowing_go_") as tmp:
        target = Path(tmp) / "snippet.go"
        target.write_text(code, encoding="utf-8")
        return analyze_file(target)


def _selftest_detects_partial_err_guard() -> None:
    code = (
        "package main\n"
        "\n"
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 8, (line, col, message)
    assert col == 13, (line, col, message)
    assert message == "data used after non-exiting err guard", message


def _selftest_detects_nil_guard_fallthrough() -> None:
    code = (
        "package main\n"
        "\n"
        "func f(id string) string {\n"
        "    u := lookup(id)\n"
        "    if u == nil {\n"
        "        log.Println(\"no user\")\n"
        "    }\n"
        "    name := u.Name\n"
        "    return name\n"
        "}\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 8, (line, col, message)
    assert col == 13, (line, col, message)
    assert message == "u dereferenced after non-exiting nil guard", message


def _selftest_exiting_guards_are_clean() -> None:
    err_code = (
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        return\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    nil_code = (
        "func f(id string) string {\n"
        "    u := lookup(id)\n"
        "    if u == nil {\n"
        "        return \"\"\n"
        "    }\n"
        "    return u.Name\n"
        "}\n"
    )
    assert _analyze_snippet(err_code) == [], _analyze_snippet(err_code)
    assert _analyze_snippet(nil_code) == [], _analyze_snippet(nil_code)


def _selftest_recheck_rescue_suppresses() -> None:
    # An exiting re-check between the partial guard and the use narrows err to
    # nil, so the companion use on the fallthrough path is safe.
    code = (
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"retrying: %v\", err)\n"
        "    }\n"
        "    if err != nil {\n"
        "        return\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


def _selftest_reassignment_suppresses() -> None:
    # After the companion is reassigned, a later use is not the guard's fault.
    code = (
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"falling back: %v\", err)\n"
        "    }\n"
        "    data = defaultConfig()\n"
        "    process(data)\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


def _selftest_run_and_env_gate(tmp_prefix: str = "ubs_core_narrowing_go_run_") -> None:
    import tempfile

    code = (
        "package main\n"
        "\n"
        "func f(path string) {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    process(data)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.go"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="go", files=[target])))
        assert len(findings) == 1, findings
        finding = findings[0]
        assert finding["rule"] == "go.narrowing.partial_err_guard", finding
        assert finding["line"] == 8, finding
        assert finding["col"] == 13, finding
        assert finding["message"] == "data used after non-exiting err guard", finding

        os.environ["UBS_SKIP_TYPE_NARROWING"] = "1"
        try:
            assert list(run(RunContext(lang="go", files=[target]))) == []
        finally:
            del os.environ["UBS_SKIP_TYPE_NARROWING"]


def _selftest_scoped_guard_out_of_scope() -> None:
    # Init-scoped err is invisible past the if chain, so the guard must not
    # leak its scan into following functions.
    code = (
        "func f(path string) bool {\n"
        "    if _, err := os.Stat(path); err != nil {\n"
        "        log.Printf(\"stat failed: %v\", err)\n"
        "    }\n"
        "    return false\n"
        "}\n"
        "\n"
        "func g(path string) {\n"
        "    _, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    fmt.Println(\"done\")\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


def _selftest_error_branch_reassign_suppresses() -> None:
    # A non-exiting re-check whose error branch reassigns the companion keeps
    # the fallthrough path valid in both cases.
    code = (
        "func f(path string) []byte {\n"
        "    data, err := os.ReadFile(path)\n"
        "    if err != nil {\n"
        "        log.Printf(\"read failed: %v\", err)\n"
        "    }\n"
        "    if err != nil {\n"
        "        data = defaultConfig()\n"
        "    }\n"
        "    return data, err\n"
        "}\n"
    )
    assert _analyze_snippet(code) == [], _analyze_snippet(code)


SELF_TESTS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("detects_partial_err_guard", _selftest_detects_partial_err_guard),
    ("detects_nil_guard_fallthrough", _selftest_detects_nil_guard_fallthrough),
    ("exiting_guards_are_clean", _selftest_exiting_guards_are_clean),
    ("recheck_rescue_suppresses", _selftest_recheck_rescue_suppresses),
    ("reassignment_suppresses", _selftest_reassignment_suppresses),
    ("scoped_guard_out_of_scope", _selftest_scoped_guard_out_of_scope),
    ("error_branch_reassign_suppresses", _selftest_error_branch_reassign_suppresses),
    ("run_and_env_gate", _selftest_run_and_env_gate),
)


register(Analyzer(layer="narrowing", lang="go", name="narrowing_go", run=run, selftests=SELF_TESTS))
