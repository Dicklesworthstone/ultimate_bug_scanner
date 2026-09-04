"""ubs_core.analyzers.narrowing_elixir — Elixir nil-guard narrowing analysis (bead D4).

Regex-based detection of partial nil guards: a `case value do nil -> ...`
clause or an `if is_nil(value)` check whose nil-branch does not halt
(raise/throw/exit), while execution continues to dereference the guarded
value (`value.field`) afterwards — a crash waiting for the nil case.
Block tracking is elixir-aware (`do`/`fn` ... `end` nesting, `;`-separated
clauses, keyword `if ... do: ...` form). Also exposes a structured `run(ctx)`
for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ubs_core.io import line_col
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", "_build", "deps", "node_modules", "cover", ".elixir_ls"}
RULE = "elixir.narrowing.partial_nil_guard"

CASE_PATTERN = re.compile(r"\bcase\s+([A-Za-z_][A-Za-z0-9_]*)\s+do\b")
IF_NIL_BLOCK_PATTERN = re.compile(r"\bif\s+is_nil\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*do\b")
IF_NIL_KEYWORD_PATTERN = re.compile(r"\bif\s+is_nil\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*,\s*do\s*:")
HALT_PATTERN = re.compile(r"\b(?:raise|throw|exit)\b")
# `=` rebinds the guarded name; `(?!=)` keeps `==` comparisons from counting as rebinds.
ASSIGN_PATTERN = r"\b{name}\s*=(?!=)"
FIELD_PATTERN = r"\b{name}\s*\.(?:[A-Za-z_][A-Za-z0-9_!?]*|\()"
# Function/module definition headers mark scope boundaries; "default" & friends must not match.
DEF_PATTERN = re.compile(r"\bdef(?:p|module|macro|protocol|impl|delegate|guard|overridable|exception)?\b")
BLOCK_TOKEN_RE = re.compile(r"\b(?:fn|do|end)\b")
CLAUSE_TOKEN_RE = re.compile(r"\b(?:fn|do|end)\b|->|[;\n]")
ELSE_RE = re.compile(r",\s*else\s*:")


def find_block_end(text: str, start: int) -> int:
    """Return the index of the `end` closing a block opened just before `start`.

    `start` must point just past the opening `do`/`fn`; nesting of `do`-blocks
    and anonymous `fn` blocks (each closed by its own `end`) is tracked.
    """
    depth = 1
    for match in BLOCK_TOKEN_RE.finditer(text, start):
        token = match.group(0)
        if token in ("fn", "do"):
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return match.start()
    return len(text)


def scan_if_block(text: str, start: int) -> tuple[Optional[int], int]:
    """Scan an `if ... do` block body starting at `start` (just past `do`).

    Returns `(else_pos, block_end)`: `else_pos` is the index of the depth-0
    `else` keyword (or None) and `block_end` the index of the matching `end`.
    """
    depth = 0
    else_pos: Optional[int] = None
    for match in re.finditer(r"\b(?:fn|do|end|else)\b", text[start:]):
        token = match.group(0)
        if token in ("fn", "do"):
            depth += 1
        elif token == "end":
            if depth == 0:
                return else_pos, start + match.start()
            depth -= 1
        elif depth == 0 and else_pos is None:
            else_pos = start + match.start()
    return else_pos, len(text)


def _has_top_level_arrow(text: str, start: int) -> bool:
    """True if a clause `->` appears at block depth 0 in text[start:]."""
    depth = 0
    pos = start
    while True:
        match = CLAUSE_TOKEN_RE.search(text, pos)
        if not match:
            return False
        token = match.group(0)
        if token in ("fn", "do"):
            depth += 1
        elif token == "end":
            if depth:
                depth -= 1
        elif not depth and token == "->":
            return True
        pos = match.end()


def split_case_clauses(body: str) -> List[Tuple[str, int]]:
    """Split a `case ... do` body into top-level `(pattern, body_start)` clauses.

    Handles newline- and `;`-separated clauses; bodies containing nested
    `do`/`fn` blocks are kept whole because separators inside them are ignored.
    """
    clauses: List[Tuple[str, int]] = []
    depth = 0
    arrow_seen = False
    pattern_start = 0
    for match in CLAUSE_TOKEN_RE.finditer(body):
        token = match.group(0)
        if token in ("fn", "do"):
            depth += 1
        elif token == "end":
            if depth:
                depth -= 1
        elif depth:
            continue
        elif token == "->":
            if not arrow_seen:
                clauses.append((body[pattern_start : match.start()].strip(), match.end()))
                arrow_seen = True
        elif arrow_seen:
            # `;`/newline after a clause body: a new clause follows only if a
            # further top-level arrow remains in the body.
            if _has_top_level_arrow(body, match.end()):
                pattern_start = match.end()
                arrow_seen = False
        else:
            pattern_start = match.end()
    return clauses


def _until_next_def(text: str, start: int) -> str:
    """Text from `start` to the next definition header — uses stay in-scope."""
    match = DEF_PATTERN.search(text, start)
    return text[start : match.start()] if match else text[start:]


def _use_after_guard(clean: str, name: str, resume: int) -> Optional[Tuple[int, int, str]]:
    """First `name.field` use after a guard, unless the name is rebound first."""
    region = _until_next_def(clean, resume)
    assign = re.search(ASSIGN_PATTERN.format(name=re.escape(name)), region)
    search_region = region if assign is None else region[: assign.start()]
    use = re.search(FIELD_PATTERN.format(name=re.escape(name)), search_region)
    if use:
        line, col = line_col(clean, resume + use.start())
        return line, col, f"{name} field access after partial nil guard"
    return None


def _case_findings(clean: str) -> List[Tuple[int, int, str]]:
    issues: List[Tuple[int, int, str]] = []
    for match in CASE_PATTERN.finditer(clean):
        name = match.group(1)
        body_start = match.end()
        block_end = find_block_end(clean, body_start)
        body = clean[body_start:block_end]
        clauses = split_case_clauses(body)
        # Only the first `nil ->` clause matters: Elixir picks it first, and a
        # halting first clause makes any later nil clause unreachable.
        for idx, (pattern, body_off) in enumerate(clauses):
            if pattern != "nil":
                continue
            clause_end = clauses[idx + 1][1] if idx + 1 < len(clauses) else len(body)
            if HALT_PATTERN.search(body[body_off:clause_end]):
                break
            finding = _use_after_guard(clean, name, min(block_end + 3, len(clean)))
            if finding:
                issues.append(finding)
            break
    return issues


def _if_nil_findings(clean: str) -> List[Tuple[int, int, str]]:
    issues: List[Tuple[int, int, str]] = []
    for match in IF_NIL_KEYWORD_PATTERN.finditer(clean):
        name = match.group(1)
        rest = clean[match.end() :]
        else_match = ELSE_RE.search(rest)
        newline = rest.find("\n")
        then_end = else_match.start() if else_match else (newline if newline != -1 else len(rest))
        if HALT_PATTERN.search(rest[:then_end]):
            continue
        resume = match.end() + (newline if newline != -1 else len(rest))
        finding = _use_after_guard(clean, name, resume)
        if finding:
            issues.append(finding)
    for match in IF_NIL_BLOCK_PATTERN.finditer(clean):
        name = match.group(1)
        else_pos, block_end = scan_if_block(clean, match.end())
        then_end = else_pos if else_pos is not None else block_end
        if HALT_PATTERN.search(clean[match.end() : then_end]):
            continue
        finding = _use_after_guard(clean, name, min(block_end + 3, len(clean)))
        if finding:
            issues.append(finding)
    return issues


def analyze_text(text: str) -> List[Tuple[int, int, str]]:
    """Return `(line, col, message)` findings for one file's text."""
    clean = strip_comments_and_strings(text, lang="elixir")
    issues = _case_findings(clean)
    issues.extend(_if_nil_findings(clean))
    return issues


def analyze_file(path: Path) -> List[Tuple[int, int, str]]:
    return analyze_text(path.read_text(encoding="utf-8", errors="ignore"))


def run(ctx: RunContext) -> Iterable[dict]:
    if os.environ.get("UBS_SKIP_TYPE_NARROWING", "") == "1":
        return []
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix not in (".ex", ".exs"):
            continue
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        try:
            rel = str(path.resolve().relative_to(cwd))
        except ValueError:
            rel = str(path)
        for line, col, message in issues:
            yield {
                "rule": RULE,
                "path": rel,
                "line": line,
                "layer": "narrowing",
                "lang": "elixir",
                "severity": "warning",
                "message": message,
                "col": col,
            }


def _selftest_case_nil_non_halting() -> None:
    code = (
        "def f(user) do\n"
        "  case user do\n"
        "    nil -> \"\"\n"
        "    _ -> :ok\n"
        "  end\n"
        "  user.name\n"
        "end\n"
    )
    issues = analyze_text(code)
    assert len(issues) == 1, issues
    line, _col, message = issues[0]
    assert line == 6, issues
    assert message == "user field access after partial nil guard", message


def _selftest_case_nil_halting_clean() -> None:
    code = (
        "def f(user) do\n"
        "  case user do\n"
        "    nil -> raise ArgumentError, \"user required\"\n"
        "    _ -> :ok\n"
        "  end\n"
        "  user.name\n"
        "end\n"
    )
    assert analyze_text(code) == [], analyze_text(code)


def _selftest_if_is_nil_block_form() -> None:
    buggy = (
        "def f(user) do\n"
        "  if is_nil(user) do\n"
        "    IO.puts(\"missing\")\n"
        "  end\n"
        "  user.id\n"
        "end\n"
    )
    issues = analyze_text(buggy)
    assert len(issues) == 1, issues
    assert issues[0][0] == 5, issues
    halting = (
        "def f(user) do\n"
        "  if is_nil(user) do\n"
        "    raise ArgumentError, \"user required\"\n"
        "  else\n"
        "    :ok\n"
        "  end\n"
        "  user.id\n"
        "end\n"
    )
    assert analyze_text(halting) == [], analyze_text(halting)


def _selftest_if_is_nil_keyword_form_and_rebind() -> None:
    buggy = (
        "def f(user) do\n"
        "  if is_nil(user), do: IO.puts(\"missing\"), else: :ok\n"
        "  user.id\n"
        "end\n"
    )
    issues = analyze_text(buggy)
    assert len(issues) == 1, issues
    assert issues[0][0] == 3, issues
    rebound = (
        "def f(user) do\n"
        "  case user do\n"
        "    nil -> \"\"\n"
        "    _ -> :ok\n"
        "  end\n"
        "  user = user || default_user()\n"
        "  user.id\n"
        "end\n"
    )
    assert analyze_text(rebound) == [], analyze_text(rebound)


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_elixir_run_") -> None:
    import tempfile

    code = (
        "defmodule M do\n"
        "  def f(user) do\n"
        "    case user do\n"
        "      nil -> \"\"\n"
        "      _ -> :ok\n"
        "    end\n"
        "    user.name\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "m.ex"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == RULE, findings
    assert findings[0]["line"] == 7, findings
    assert findings[0]["message"] == "user field access after partial nil guard", findings

    os.environ["UBS_SKIP_TYPE_NARROWING"] = "1"
    try:
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "m.ex"
            target.write_text(code, encoding="utf-8")
            findings = list(run(RunContext(lang="elixir", files=[target])))
    finally:
        os.environ.pop("UBS_SKIP_TYPE_NARROWING", None)
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("case_nil_non_halting", _selftest_case_nil_non_halting),
    ("case_nil_halting_clean", _selftest_case_nil_halting_clean),
    ("if_is_nil_block_form", _selftest_if_is_nil_block_form),
    ("if_is_nil_keyword_form_and_rebind", _selftest_if_is_nil_keyword_form_and_rebind),
    ("run_finds_nil_guard_and_env_gate", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="elixir", name="narrowing_elixir", run=run, selftests=SELF_TESTS))
