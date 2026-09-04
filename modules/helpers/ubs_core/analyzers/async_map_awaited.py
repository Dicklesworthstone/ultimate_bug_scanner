"""ubs_core.analyzers.async_map_awaited — ``await arr.map(async ...)`` does not
await the mapped promises (bead A4-js wave 1).

Verbatim port of the legacy ubs-js.sh heredoc "awaited async map callback
results": same regexes (including the TS generic form ``map<T>(``), same
16-line expression window, same paren-balance stop rule, same statement-prefix
lookback (max 6 previous lines, reset on blank/comment), and same
``ubs:ignore`` placement rules (anywhere inside the collected expression
text). A match is reported only when the statement prefix contains ``await``
but no ``Promise.all``/``Promise.allSettled`` call. The heredoc's os.walk over
the project is replaced by iteration over ``RunContext.files``; per-file match
logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.async.map-awaited"
CATEGORY_ID = "js.async"
MESSAGE = ("awaiting map(async ...) does not await the mapped promises: Wrap the "
           "async map in Promise.all/allSettled or await each promise explicitly")

START_RE = re.compile(r'\.\s*map\s*(?:<[^()\n]+>)?\s*\(')
ASYNC_MAP_RE = re.compile(r'\.\s*map\s*(?:<[^()\n]+>)?\s*\(\s*(?:async\b|async\s+function\b)', re.DOTALL)
AWAIT_RE = re.compile(r'\bawait\b')
PROMISE_ALL_RE = re.compile(r'\bPromise\.(?:all|allSettled)\s*\(')


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
        if not AWAIT_RE.search(prefix) or PROMISE_ALL_RE.search(prefix):
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


def _selftest_awaited_map_flagged(tmp_prefix: str = "ubs_core_async_map_awaited_") -> None:
    import tempfile

    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  await users.map(async (user) => {",
        "    await sendWelcomeEmail(user);",
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
        assert line == 2, findings
        assert col == 14, findings


def _selftest_promise_all_clean(tmp_prefix: str = "ubs_core_async_map_awaited_pa_") -> None:
    import tempfile

    # await Promise.all(arr.map(async ...)) is the correct pattern -> silent.
    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  await Promise.all(users.map(async (user) => {",
        "    await sendWelcomeEmail(user);",
        "  }));",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_unawaited_map_clean(tmp_prefix: str = "ubs_core_async_map_awaited_un_") -> None:
    import tempfile

    # map(async ...) without a leading await (results handled separately) -> silent.
    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  const tasks = users.map(async (user) => {",
        "    await sendWelcomeEmail(user);",
        "  });",
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


def _selftest_same_line_ignore_suppressed(tmp_prefix: str = "ubs_core_async_map_awaited_ign_") -> None:
    import tempfile

    # ubs:ignore on the map start line suppresses.
    src = "\n".join([
        "await users.map(async (user) => { // ubs:ignore",
        "  await sendWelcomeEmail(user);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_window_ignore_suppressed(tmp_prefix: str = "ubs_core_async_map_awaited_wign_") -> None:
    import tempfile

    # ubs:ignore on any line inside the collected expression window suppresses.
    src = "\n".join([
        "await users.map(async (user) => {",
        "  await sendWelcomeEmail(user); // ubs:ignore",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_async_map_awaited_run_") -> None:
    import tempfile

    src = "await users.map(async (user) => send(user));\n"
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
        assert rec["line"] == 1 and rec["col"] == 12, rec
        assert "Promise.all" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("awaited-map-flagged", _selftest_awaited_map_flagged),
    ("promise-all-clean", _selftest_promise_all_clean),
    ("unawaited-map-clean", _selftest_unawaited_map_clean),
    ("same-line-ignore-suppressed", _selftest_same_line_ignore_suppressed),
    ("window-ignore-suppressed", _selftest_window_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="async_map_awaited", run=run, selftests=SELF_TESTS))
