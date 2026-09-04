"""ubs_core.analyzers.async_reduce — async reduce callback returns a Promise
accumulator (bead A4-js wave 1).

Verbatim port of the legacy ubs-js.sh heredoc "async callbacks passed to
reduce": same regexes (including the TS generic form ``reduce<T>(``), same
18-line callback window with the saw-reduce paren-balance gate (paren counting
only starts once the ``.reduce(``/``.reduceRight(`` opener has been seen), and
same ``ubs:ignore`` placement rules (anywhere inside the collected callback
text). The heredoc has no result-observation check — a const declaration or
Promise.all wrapper does not silence it. The heredoc's os.walk over the
project is replaced by iteration over ``RunContext.files``; per-file match
logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.async.reduce"
CATEGORY_ID = "js.async"
MESSAGE = ("async reduce callback returns a Promise accumulator: Resolve async "
           "values before reduce, or await the accumulator explicitly and "
           "return a Promise intentionally")

START_RE = re.compile(r'\.\s*(?:reduce|reduceRight)\s*(?:<[^()\n]+>)?\s*\(')
ASYNC_REDUCE_RE = re.compile(
    r'\.\s*(reduce|reduceRight)\s*(?:<[^()\n]+>)?\s*\(\s*(?:async\b|async\s+function\b)',
    re.DOTALL,
)


def scan_file_findings(path: Path) -> Iterator[tuple[int, int, str]]:
    """Yield (line, col, method) per detection; match logic identical to the heredoc."""
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
        saw_reduce = False
        for callback_idx in range(idx, min(len(lines), idx + 18)):
            current = lines[callback_idx].strip()
            callback_lines.append(current)
            if START_RE.search(current):
                saw_reduce = True
            if saw_reduce:
                paren_balance += current.count('(') - current.count(')')
            if saw_reduce and callback_idx > idx and paren_balance <= 0:
                break
        callback_text = ' '.join(callback_lines)
        if 'ubs:ignore' in callback_text:
            continue
        async_match = ASYNC_REDUCE_RE.search(callback_text)
        if not async_match:
            continue
        yield idx + 1, match.start() + 1, async_match.group(1)


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
        for line, col, method in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": col,
                "severity": "warning",
                "message": f"{MESSAGE} ({method})",
            }


def _selftest_async_reduce_flagged(tmp_prefix: str = "ubs_core_async_reduce_") -> None:
    import tempfile

    src = "\n".join([
        "async function loadTotal(id) { return Promise.resolve(id.length); }",
        "",
        "export async function invoiceTotal(invoices) {",
        "  return invoices.reduce(async (total, invoice) => {",
        "    const itemTotal = await loadTotal(invoice.id);",
        "    return total + itemTotal;",
        "  }, 0);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invoice.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col, method = findings[0]
        assert line == 4, findings
        assert col == 18, findings
        assert method == "reduce", findings


def _selftest_reduce_right_generic_flagged(tmp_prefix: str = "ubs_core_async_reduce_rr_") -> None:
    import tempfile

    # reduceRight with a TS generic form; the legacy heredoc has no
    # result-observation check, so a const declaration does NOT silence it.
    src = (
        "const total = items.reduceRight<string>(async (acc, item) => "
        "acc + (await load(item)), 0);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invoice.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col, method = findings[0]
        assert line == 1, findings
        assert col == 20, findings
        assert method == "reduceRight", findings


def _selftest_sync_reduce_clean(tmp_prefix: str = "ubs_core_async_reduce_clean_") -> None:
    import tempfile

    # A synchronous callback is the correct pattern -> silent.
    src = "\n".join([
        "export function invoiceTotal(lineItemTotals) {",
        "  return lineItemTotals.reduce((total, lineItemTotal) => total + lineItemTotal, 0);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invoice.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_same_line_ignore_suppressed(tmp_prefix: str = "ubs_core_async_reduce_ign_") -> None:
    import tempfile

    # ubs:ignore on the reduce start line suppresses.
    src = "\n".join([
        "invoices.reduce(async (total, invoice) => { // ubs:ignore",
        "  return total + (await load(invoice.id));",
        "}, 0);",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invoice.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_window_ignore_suppressed(tmp_prefix: str = "ubs_core_async_reduce_wign_") -> None:
    import tempfile

    # ubs:ignore on any line inside the collected callback window suppresses.
    src = "\n".join([
        "invoices.reduce(async (total, invoice) => {",
        "  return total + (await load(invoice.id)); // ubs:ignore",
        "}, 0);",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invoice.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_async_reduce_run_") -> None:
    import tempfile

    src = (
        "const total = items.reduceRight<string>(async (acc, item) => "
        "acc + (await load(item)), 0);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "invoice.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 20, rec
        assert "(reduceRight)" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("async-reduce-flagged", _selftest_async_reduce_flagged),
    ("reduce-right-generic-flagged", _selftest_reduce_right_generic_flagged),
    ("sync-reduce-clean", _selftest_sync_reduce_clean),
    ("same-line-ignore-suppressed", _selftest_same_line_ignore_suppressed),
    ("window-ignore-suppressed", _selftest_window_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="async_reduce", run=run, selftests=SELF_TESTS))
