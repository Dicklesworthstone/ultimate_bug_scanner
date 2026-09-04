"""ubs_core.analyzers.narrowing_ruby — Ruby nil-guard type narrowing (bead D4).

Detects partial nil guards: `if obj.nil?` (or a bare `unless obj`, in block or
modifier form) whose guarded branch does NOT exit. Because the branch keeps
falling through, `obj` can still be nil after the guard, so a later plain
`obj.method` call raises NoMethodError. Mirrors the narrowing_kotlin/narrowing_rust
shape: a text scanner for `analyze_file`/`main`, plus a structured `run(ctx)` for
the `python3 -m ubs_core` CLI, self-tests, and self-registration.

Semantics:
- A guard whose branch exits (`return`/`raise`/`next`/... ) narrows the fallthrough
  to non-nil and is never reported.
- Safe navigation (`obj&.method`) and re-checks (`obj.nil?`) are not dereferences.
- A reassignment of the guarded name bounds the scan (later calls are not its fault).
- The scan never crosses into the next line-leading `def`/`class`/`module`, and an
  intervening *exiting* guard for the same name clears the suspicion.
- Comments, strings and multiline constructs are masked via ubs_core.lexer while
  preserving offsets, so (line, col) always match the original source.

`UBS_SKIP_TYPE_NARROWING=1` disables the analyzer (uniform D4 gate in `run`).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.io import line_col
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", ".bundle", "vendor", "bundle", "node_modules", "coverage"}
_RULE = "ruby.narrowing.partial_nil_guard"
_EXIT_KEYWORDS = r"(?:return|raise|fail|throw|next|break|retry|abort|exit)"

# Horizontal-whitespace anchors keep every guard pattern on one physical line.
_H = r"[^\S\n]"
# Local variables, instance/class variables and globals — as written in source.
_NAME = r"(?:@{1,2}|\$)?[A-Za-z_][A-Za-z0-9_]*"

# Block forms: `if obj.nil?` / `unless obj` alone on their line.
NIL_GUARD_RE = re.compile(rf"^{_H}*if{_H}+(?P<name>{_NAME})\.nil\?{_H}*$", re.MULTILINE)
UNLESS_GUARD_RE = re.compile(rf"^{_H}*unless{_H}+(?P<name>{_NAME}){_H}*$", re.MULTILINE)
# Modifier forms: `do_something if obj.nil?` — the statement is the guarded branch.
MODIFIER_NIL_RE = re.compile(
    rf"^{_H}*(?P<body>\S.*?){_H}+if{_H}+(?P<name>{_NAME})\.nil\?{_H}*$", re.MULTILINE
)
MODIFIER_UNLESS_RE = re.compile(
    rf"^{_H}*(?P<body>\S.*?){_H}+unless{_H}+(?P<name>{_NAME}){_H}*$", re.MULTILINE
)
ELSE_RE = re.compile(rf"{_H}*(?:else|elsif)\b")
EXIT_RE = re.compile(rf"\b{_EXIT_KEYWORDS}\b")
LINE_OPENER_RE = re.compile(rf"^{_H}*(?:if|unless|case|def|begin|class|module|while|until|for)\b")
DO_TOKEN_RE = re.compile(r"\bdo\b")
END_TOKEN_RE = re.compile(r"\bend\b")
BOUNDARY_RE = re.compile(rf"^{_H}*(?:def|class|module){_H}+", re.MULTILINE)


def use_pattern(name: str) -> re.Pattern[str]:
    """Plain `name.method` dereference: no safe navigation, no `.nil?` re-check."""
    escaped = re.escape(name)
    return re.compile(rf"(?<![\w.@$]){escaped}{_H}*\.(?!nil\?)(?=[A-Za-z_])")


def assign_pattern(name: str) -> re.Pattern[str]:
    escaped = re.escape(name)
    return re.compile(rf"(?<![\w.@$]){escaped}{_H}*=(?![=~>])")


def guard_pattern(name: str) -> re.Pattern[str]:
    """Block-form nil guards for one name, used to detect later clearance."""
    escaped = re.escape(name)
    return re.compile(
        rf"^{_H}*(?:if{_H}+{escaped}\.nil\?|unless{_H}+{escaped}){_H}*$", re.MULTILINE
    )


def exiting_modifier_pattern(name: str) -> re.Pattern[str]:
    """`return if obj.nil?` / `next unless obj` style guards that clear suspicion."""
    escaped = re.escape(name)
    return re.compile(
        rf"^{_H}*{_EXIT_KEYWORDS}\b.*{_H}+(?:if{_H}+{escaped}\.nil\?|unless{_H}+{escaped}){_H}*$",
        re.MULTILINE,
    )


def find_keyword_block(code: str, start: int) -> tuple[int | None, int]:
    """Locate the ``end`` closing a block whose header ends at ``start``.

    Returns ``(split, block_end)``: ``split`` is the offset of the guard's own
    line-leading ``else``/``elsif`` (None when absent) and ``block_end`` is the
    offset just past the matching ``end`` (end of input when unbalanced).
    """
    depth = 1
    split = None
    for line_match in re.finditer(r"[^\n]+", code[start:]):
        line = line_match.group(0)
        line_off = start + line_match.start()
        opens_line = LINE_OPENER_RE.match(line)
        delta = 1 if opens_line else (1 if DO_TOKEN_RE.search(line) else 0)
        delta -= len(END_TOKEN_RE.findall(line))
        if depth == 1 and split is None and ELSE_RE.match(line):
            split = line_off
        depth += delta
        if depth <= 0:
            last_end = None
            for end_match in END_TOKEN_RE.finditer(line):
                last_end = end_match
            return split, line_off + (last_end.end() if last_end else len(line))
    return split, len(code)


def branch_is_exiting(code: str, body_start: int, body_end: int) -> bool:
    return bool(EXIT_RE.search(code[body_start:body_end]))


def first_use_after(code: str, start: int, name: str) -> tuple[int, int] | None:
    """First plain dereference of ``name`` after ``start``, or None.

    The search stops at a reassignment (later calls are the new value's problem)
    and is cleared by the next line-leading ``def``/``class``/``module`` or by an
    intervening exiting guard for the same name.
    """
    use_re = use_pattern(name)
    assign = assign_pattern(name).search(code, start)
    limit = assign.start() if assign else len(code)

    use = use_re.search(code, start, limit)
    cleared_at = None
    boundary = BOUNDARY_RE.search(code, start, limit)
    if boundary:
        cleared_at = boundary.start()
    for guard in guard_pattern(name).finditer(code, start, limit):
        split, block_end = find_keyword_block(code, guard.end())
        body_end = split if split is not None else block_end
        if branch_is_exiting(code, guard.end(), body_end):
            cleared_at = block_end if cleared_at is None else min(cleared_at, block_end)
    for modifier in exiting_modifier_pattern(name).finditer(code, start, limit):
        cleared_at = modifier.end() if cleared_at is None else min(cleared_at, modifier.end())

    if use and (cleared_at is None or use.start() < cleared_at):
        return line_col(code, use.start())
    return None


def scan_text(text: str) -> list[tuple[int, int, str]]:
    """Return (line, col, message) findings for one file's text."""
    code = strip_comments_and_strings(text, lang="ruby")
    issues: list[tuple[int, int, str]] = []
    for pattern in (NIL_GUARD_RE, UNLESS_GUARD_RE, MODIFIER_NIL_RE, MODIFIER_UNLESS_RE):
        for match in pattern.finditer(code):
            if pattern in (MODIFIER_NIL_RE, MODIFIER_UNLESS_RE):
                body_start = match.start("body")
                body_end = match.end("body")
            else:
                split, block_end = find_keyword_block(code, match.end())
                body_start = match.end()
                body_end = split if split is not None else block_end
            if branch_is_exiting(code, body_start, body_end):
                continue
            use = first_use_after(code, match.end(), match.group("name"))
            if use:
                line, col = use
                issues.append(
                    (
                        line,
                        col,
                        f"{match.group('name')} method call after non-exiting nil guard",
                    )
                )
    return issues


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    deduped: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int, str]] = set()
    for line, col, message in scan_text(text):
        key = (line, col, message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((line, col, message))
    return deduped


def iter_ruby_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix == ".rb" and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename.endswith(".rb"):
                path = Path(dirpath) / filename
                if not any(part in SKIP_DIRS for part in path.parts):
                    yield path


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: narrowing_ruby.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for path in iter_ruby_files(root):
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        for line, col, message in issues:
            print(f"{path}:{line}:{col}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    if os.environ.get("UBS_SKIP_TYPE_NARROWING", "") == "1":
        return []
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix != ".rb":
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for line, col, message in issues:
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line,
                "col": col,
                "layer": "narrowing",
                "lang": "ruby",
                "severity": "warning",
                "message": message,
            }


def _analyze_snippet(code: str) -> list[tuple[int, int, str]]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_narrowing_ruby_") as tmp:
        target = Path(tmp) / "snippet.rb"
        target.write_text(code, encoding="utf-8")
        return analyze_file(target)


def _selftest_detects_use_after_nil_guard() -> None:
    code = (
        "def render(user)\n"
        "  if user.nil?\n"
        "    logger.warn('missing user')\n"
        "  end\n"
        "  user.profile.name\n"
        "end\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 5, (line, col, message)
    assert col == 3, (line, col, message)
    assert message == "user method call after non-exiting nil guard", message


def _selftest_exiting_guard_suppressed() -> None:
    code = (
        "def render(user)\n"
        "  if user.nil?\n"
        "    return default_user\n"
        "  end\n"
        "  user.profile.name\n"
        "end\n"
    )
    assert _analyze_snippet(code) == []


def _selftest_unless_truthiness_detected() -> None:
    code = (
        "def charge(account)\n"
        "  unless account\n"
        "    logger.info('no account')\n"
        "  end\n"
        "  account.balance\n"
        "end\n"
    )
    issues = _analyze_snippet(code)
    assert len(issues) == 1, issues
    line, col, message = issues[0]
    assert line == 5, (line, col, message)
    assert message == "account method call after non-exiting nil guard", message


def _selftest_reassignment_suppresses() -> None:
    # After the guarded source is reassigned, a later call is not its fault.
    code = (
        "def load(session)\n"
        "  if session.nil?\n"
        "    logger.debug('fresh session')\n"
        "  end\n"
        "  session = Session.new\n"
        "  session.id\n"
        "end\n"
    )
    assert _analyze_snippet(code) == []


def _selftest_safe_nav_and_def_boundary() -> None:
    # Safe navigation is not a dereference, and the scan stops at the next def.
    code = (
        "def label(user)\n"
        "  if user.nil?\n"
        "    logger.warn('anonymous')\n"
        "  end\n"
        "  user&.profile&.label\n"
        "end\n"
        "\n"
        "def other(user)\n"
        "  user.touch!\n"
        "end\n"
    )
    assert _analyze_snippet(code) == []


def _selftest_modifier_guard_and_masking() -> None:
    # Modifier form detects; comments/strings must not create phantom guards.
    flagged = (
        "def touch(session)\n"
        "  logger.debug('missing') if session.nil?\n"
        "  session.touch!\n"
        "end\n"
    )
    issues = _analyze_snippet(flagged)
    assert len(issues) == 1, issues
    assert issues[0][0] == 3, issues

    masked = (
        "def documented(user)\n"
        "  # if user.nil? nothing to see here\n"
        "  puts 'if user.nil? then skip'\n"
        "  user.display_name\n"
        "end\n"
    )
    assert _analyze_snippet(masked) == []


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_ruby_run_") -> None:
    import tempfile

    code = (
        "def ship(order)\n"
        "  if order.nil?\n"
        "    logger.warn('missing order')\n"
        "  end\n"
        "  order.commit!\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "buggy.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
        assert len(findings) == 1, findings
        assert findings[0]["rule"] == _RULE, findings[0]
        assert findings[0]["line"] == 5, findings[0]
        assert findings[0]["col"] == 3, findings[0]
        assert findings[0]["layer"] == "narrowing", findings[0]
        assert findings[0]["lang"] == "ruby", findings[0]
        assert findings[0]["severity"] == "warning", findings[0]
        saved = os.environ.get("UBS_SKIP_TYPE_NARROWING")
        os.environ["UBS_SKIP_TYPE_NARROWING"] = "1"
        try:
            assert list(run(RunContext(lang="ruby", files=[target]))) == []
        finally:
            if saved is None:
                os.environ.pop("UBS_SKIP_TYPE_NARROWING", None)
            else:
                os.environ["UBS_SKIP_TYPE_NARROWING"] = saved


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_use_after_nil_guard", _selftest_detects_use_after_nil_guard),
    ("exiting_guard_suppressed", _selftest_exiting_guard_suppressed),
    ("unless_truthiness_detected", _selftest_unless_truthiness_detected),
    ("reassignment_suppresses", _selftest_reassignment_suppresses),
    ("safe_nav_and_def_boundary", _selftest_safe_nav_and_def_boundary),
    ("modifier_guard_and_masking", _selftest_modifier_guard_and_masking),
    ("run_finds_partial_nil_guard", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="ruby", name="narrowing_ruby", run=run, selftests=SELF_TESTS))
