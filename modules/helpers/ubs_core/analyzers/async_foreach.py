"""ubs_core.analyzers.async_foreach — async callbacks passed to ``forEach``
(bead A4-js wave 1).

Verbatim port of the legacy ubs-js.sh heredoc "async callbacks passed to
forEach": same regexes, same 14-line callback window, same paren-balance stop
rule, same ``ubs:ignore`` placement rules (anywhere inside the collected
callback text). The heredoc's os.walk over the project is replaced by
iteration over ``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.async.foreach"
CATEGORY_ID = "js.async"
MESSAGE = ("async forEach callback is not awaited: Use for...of for sequential "
           "awaits or Promise.all(array.map(async ...)) for parallel work")

START_RE = re.compile(r'\.\s*forEach\s*\(')
ASYNC_FOREACH_RE = re.compile(r'\.\s*forEach\s*\(\s*(?:async\b|async\s+function\b)', re.DOTALL)


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
        if not START_RE.search(line):
            continue
        callback_lines = []
        paren_balance = 0
        for callback_idx in range(idx, min(len(lines), idx + 14)):
            current = lines[callback_idx].strip()
            callback_lines.append(current)
            paren_balance += current.count('(') - current.count(')')
            if paren_balance <= 0:
                break
        callback_text = ' '.join(callback_lines)
        if 'ubs:ignore' in callback_text or not ASYNC_FOREACH_RE.search(callback_text):
            continue
        yield idx + 1, START_RE.search(line).start() + 1


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


def _selftest_async_foreach_flagged(tmp_prefix: str = "ubs_core_async_foreach_") -> None:
    import tempfile

    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  users.forEach(async (user) => {",
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
        assert col == 8, findings


def _selftest_for_of_clean(tmp_prefix: str = "ubs_core_async_foreach_clean_") -> None:
    import tempfile

    src = "\n".join([
        "export async function inviteUsers(users) {",
        "  for (const user of users) {",
        "    await sendWelcomeEmail(user);",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_sync_foreach_clean(tmp_prefix: str = "ubs_core_async_foreach_sync_") -> None:
    import tempfile

    # forEach with a non-async callback must not be flagged.
    src = "\n".join([
        "users.forEach(function (user) {",
        "  console.log(user);",
        "});",
        "items.forEach((item) => log(item));",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "misc.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_same_line_ignore_suppressed(tmp_prefix: str = "ubs_core_async_foreach_ign_") -> None:
    import tempfile

    # ubs:ignore on the forEach start line suppresses.
    src = "\n".join([
        "users.forEach(async (user) => { // ubs:ignore",
        "  await sendWelcomeEmail(user);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_window_ignore_suppressed(tmp_prefix: str = "ubs_core_async_foreach_wign_") -> None:
    import tempfile

    # ubs:ignore on any line inside the collected callback window suppresses.
    src = "\n".join([
        "users.forEach(async (user) => {",
        "  await sendWelcomeEmail(user); // ubs:ignore",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invite.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_async_foreach_run_") -> None:
    import tempfile

    src = "users.forEach(async (user) => { await send(user); });\n"
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
        assert "forEach" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("async-foreach-flagged", _selftest_async_foreach_flagged),
    ("for-of-clean", _selftest_for_of_clean),
    ("sync-foreach-clean", _selftest_sync_foreach_clean),
    ("same-line-ignore-suppressed", _selftest_same_line_ignore_suppressed),
    ("window-ignore-suppressed", _selftest_window_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="async_foreach", run=run, selftests=SELF_TESTS))
