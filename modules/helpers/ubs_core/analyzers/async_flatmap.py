"""ubs_core.analyzers.async_flatmap — async flatMap callback is not awaited
(bead A4-js wave 1).

Verbatim port of the legacy ubs-js.sh heredoc "async callbacks passed to
flatMap": same regexes, same 16-line callback window with the saw-flatMap
paren-balance gate (paren counting only starts once the ``.flatMap(`` opener
has been seen), and same ``ubs:ignore`` placement rules (anywhere inside the
collected callback text). Note the legacy heredoc has no result-observation
check — every ``.flatMap(async ...)`` is flagged unless suppressed. The
heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.async.flatmap"
CATEGORY_ID = "js.async"
MESSAGE = ("async flatMap callback is not awaited: Resolve async expansions "
           "before flatMap, then flatten with a synchronous callback")

START_RE = re.compile(r'\.\s*flatMap\s*\(')
ASYNC_FLATMAP_RE = re.compile(r'\.\s*flatMap\s*\(\s*(?:async\b|async\s+function\b)', re.DOTALL)


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
        callback_lines = []
        paren_balance = 0
        saw_flatmap = False
        for callback_idx in range(idx, min(len(lines), idx + 16)):
            current = lines[callback_idx].strip()
            callback_lines.append(current)
            if START_RE.search(current):
                saw_flatmap = True
            if saw_flatmap:
                paren_balance += current.count('(') - current.count(')')
            if saw_flatmap and callback_idx > idx and paren_balance <= 0:
                break
        callback_text = ' '.join(callback_lines)
        if 'ubs:ignore' in callback_text or not ASYNC_FLATMAP_RE.search(callback_text):
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


def _selftest_async_flatmap_flagged(tmp_prefix: str = "ubs_core_async_flatmap_") -> None:
    import tempfile

    src = "\n".join([
        "async function load(order) { return Promise.resolve([order.id]); }",
        "",
        "export async function recommended(orders) {",
        "  return orders.flatMap(async (order) => {",
        "    return load(order);",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "orders.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 4, findings
        assert col == 16, findings


def _selftest_sync_flatmap_clean(tmp_prefix: str = "ubs_core_async_flatmap_clean_") -> None:
    import tempfile

    # A synchronous callback is the correct pattern -> silent.
    src = "\n".join([
        "export function flatten(orders) {",
        "  return orders.flatMap((order) => order.items);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "orders.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_wrapped_promise_all_still_flagged(tmp_prefix: str = "ubs_core_async_flatmap_pa_") -> None:
    import tempfile

    # The legacy heredoc has no result-observation check: unlike map, wrapping
    # the flatMap in Promise.all does NOT silence it (verbatim behavior).
    src = "\n".join([
        "export async function recommended(orders) {",
        "  return Promise.all(orders.flatMap(async (order) => load(order)));",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "orders.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings


def _selftest_same_line_ignore_suppressed(tmp_prefix: str = "ubs_core_async_flatmap_ign_") -> None:
    import tempfile

    # ubs:ignore on the flatMap start line suppresses.
    src = "\n".join([
        "orders.flatMap(async (order) => { // ubs:ignore",
        "  return load(order);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "orders.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_window_ignore_suppressed(tmp_prefix: str = "ubs_core_async_flatmap_wign_") -> None:
    import tempfile

    # ubs:ignore on any line inside the collected callback window suppresses.
    src = "\n".join([
        "orders.flatMap(async (order) => {",
        "  return load(order); // ubs:ignore",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "orders.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_async_flatmap_run_") -> None:
    import tempfile

    src = "const xs = orders.flatMap(async (order) => load(order));\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "orders.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 18, rec
        assert "flatMap" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("async-flatmap-flagged", _selftest_async_flatmap_flagged),
    ("sync-flatmap-clean", _selftest_sync_flatmap_clean),
    ("wrapped-promise-all-still-flagged", _selftest_wrapped_promise_all_still_flagged),
    ("same-line-ignore-suppressed", _selftest_same_line_ignore_suppressed),
    ("window-ignore-suppressed", _selftest_window_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="async_flatmap", run=run, selftests=SELF_TESTS))
