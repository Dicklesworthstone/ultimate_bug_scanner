"""ubs_core.analyzers.async_map_ignored — async map callback result is ignored
(bead A4-js wave 1).

Verbatim port of the legacy ubs-js.sh heredoc "ignored async map callback
results": same regexes (plain ``.map(`` — this heredoc has no TS generic
form), same 16-line expression window, same paren-balance stop rule, same
statement-prefix lookback (max 6 previous lines, reset on blank/comment),
same observation heuristics (Promise.all/allSettled call, const/let/var
declaration, return, await, or assignment in the statement prefix), and same
``ubs:ignore`` placement rules (anywhere inside the collected expression
text). The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.async.map-ignored"
CATEGORY_ID = "js.async"
MESSAGE = ("async map callback result is ignored: Await "
           "Promise.all(array.map(async ...)) or use for...of so the generated "
           "promises are observed")

START_RE = re.compile(r'\.\s*map\s*\(')
ASYNC_MAP_RE = re.compile(r'\.\s*map\s*\(\s*(?:async\b|async\s+function\b)', re.DOTALL)
OBSERVED_CALL_RE = re.compile(r'\bPromise\.(?:all|allSettled)\s*\(')
DECLARATION_RE = re.compile(r'^\s*(?:const|let|var)\b')
RETURN_RE = re.compile(r'^\s*return\b')
AWAIT_RE = re.compile(r'^\s*await\b')
ASSIGNMENT_RE = re.compile(r'(?<![=!<>])=(?!=)')


def statement_prefix(lines: list[str], idx: int, line_prefix: str) -> str:
    """Verbatim port of the heredoc helper: collect the current statement text
    from up to 6 previous non-comment lines plus the text before the match."""
    prefix_lines = []
    for prev_idx in range(max(0, idx - 6), idx):
        current = lines[prev_idx].strip()
        if not current or current.startswith(("//", "/*", "*")):
            prefix_lines = []
            continue
        prefix_lines.append(current)
    prefix = ' '.join(prefix_lines + [line_prefix.strip()])
    return re.split(r'[;{}]', prefix)[-1].strip()


def result_is_observed(prefix: str) -> bool:
    """Verbatim port of the heredoc helper: the map result counts as observed
    when the statement prefix wraps it in Promise.all/allSettled, declares it,
    returns it, awaits it, or assigns it."""
    if OBSERVED_CALL_RE.search(prefix):
        return True
    if DECLARATION_RE.search(prefix) or RETURN_RE.search(prefix) or AWAIT_RE.search(prefix):
        return True
    if ASSIGNMENT_RE.search(prefix):
        return True
    return False


def scan_file_findings(path: Path) -> Iterator[tuple[int, int]]:
    """Yield (line, col) per detection; match logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        match = START_RE.search(line)
        if not match:
            continue
        expression_lines = []
        paren_balance = 0
        for expr_idx in range(idx, min(len(lines), idx + 16)):
            current = lines[expr_idx].strip()
            expression_lines.append(current)
            paren_balance += current.count('(') - current.count(')')
            if expr_idx > idx and paren_balance <= 0:
                break
        expression_text = ' '.join(expression_lines)
        if 'ubs:ignore' in expression_text or not ASYNC_MAP_RE.search(expression_text):
            continue
        prefix = statement_prefix(lines, idx, line[:match.start()])
        if result_is_observed(prefix):
            continue
        yield idx + 1, match.start() + 1


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs relative to the scan root (cwd)
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for line, col in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": col,
                "severity": "warning",
                "message": MESSAGE,
            }


def _selftest_unobserved_map_flagged(tmp_prefix: str = "ubs_core_async_map_ignored_") -> None:
    import tempfile

    src = "\n".join([
        "async function send(user) { return fetch(user.email); }",
        "",
        "export async function inviteUsers(users) {",
        "  users.map(async (user) => {",
        "    await send(user);",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 4, findings
        assert col == 8, findings


def _selftest_declaration_clean(tmp_prefix: str = "ubs_core_async_map_ignored_decl_") -> None:
    import tempfile

    # const tasks = map(async ...) (results awaited later) is observed -> silent.
    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  const tasks = users.map(async (user) => send(user));",
        "  for (const task of tasks) {",
        "    await task;",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_promise_all_clean(tmp_prefix: str = "ubs_core_async_map_ignored_pa_") -> None:
    import tempfile

    # Promise.all(arr.map(async ...)) and plain assignment are observed -> silent.
    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  await Promise.all(users.map(async (user) => send(user)));",
        "}",
        "",
        "let cached;",
        "export function warm(users) {",
        "  cached = users.map(async (user) => send(user));",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_same_line_ignore_suppressed(tmp_prefix: str = "ubs_core_async_map_ignored_ign_") -> None:
    import tempfile

    # ubs:ignore on the map start line suppresses.
    src = "\n".join([
        "users.map(async (user) => { // ubs:ignore",
        "  await send(user);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_window_ignore_suppressed(tmp_prefix: str = "ubs_core_async_map_ignored_wign_") -> None:
    import tempfile

    # ubs:ignore on any line inside the collected expression window suppresses.
    src = "\n".join([
        "users.map(async (user) => {",
        "  await send(user); // ubs:ignore",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_async_map_ignored_run_") -> None:
    import tempfile

    src = "users.map(async (user) => send(user));\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 6, rec
        assert "Promise.all" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("unobserved-map-flagged", _selftest_unobserved_map_flagged),
    ("declaration-clean", _selftest_declaration_clean),
    ("promise-all-clean", _selftest_promise_all_clean),
    ("same-line-ignore-suppressed", _selftest_same_line_ignore_suppressed),
    ("window-ignore-suppressed", _selftest_window_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="async_map_ignored", run=run, selftests=SELF_TESTS))
