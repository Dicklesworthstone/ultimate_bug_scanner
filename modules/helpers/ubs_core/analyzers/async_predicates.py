"""ubs_core.analyzers.async_predicates — async callbacks passed to array predicates (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "async callbacks passed to array
predicates": ``filter``/``some``/``every``/``find``/``findIndex`` expect a
synchronous boolean, but an ``async`` predicate returns a Promise, so every element
coerces to truthy ("[object Promise]") and the check never filters. The heredoc
scans for a predicate entry line, joins the paren-balanced callback window
(14 lines), and flags ``async``/``async function`` predicates unless the window
contains ``ubs:ignore``.

run(ctx) iterates ctx.files instead of self-walking; match logic is identical.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

START_RE = re.compile(r'\.\s*(?:filter|some|every|find|findIndex)\s*\(')
ASYNC_PREDICATE_RE = re.compile(
    r'\.\s*(filter|some|every|find|findIndex)\s*\(\s*(?:async\b|async\s+function\b)',
    re.DOTALL,
)

RULE_ID = "js.async.predicate"
WINDOW = 14


def scan_lines(lines: list[str]) -> list[tuple[int, int, str]]:
    """Return (line, col, method) findings for one file's lines; heredoc match logic."""
    issues = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        start_match = START_RE.search(line)
        if not start_match:
            continue
        callback_lines = []
        paren_balance = 0
        for callback_idx in range(idx, min(len(lines), idx + WINDOW)):
            current = lines[callback_idx].strip()
            callback_lines.append(current)
            paren_balance += current.count('(') - current.count(')')
            if paren_balance <= 0:
                break
        callback_text = ' '.join(callback_lines)
        if 'ubs:ignore' in callback_text:
            continue
        match = ASYNC_PREDICATE_RE.search(callback_text)
        if not match:
            continue
        issues.append((idx + 1, start_match.start() + 1, match.group(1)))
    return issues


def scan_file(path: Path) -> list[tuple[int, int, str]]:
    """Return (line, col, method) findings for one file; heredoc match logic."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return []
    return scan_lines(lines)


def collect_issues(root: Path) -> list[tuple[str, int, str, str]]:
    """Heredoc parity entrypoint: (rel_path, line, method, sample_text) per issue."""
    root = root.resolve()
    issues = []
    if root.is_file():
        candidates = [root]
        sample_root = root.parent
    else:
        candidates = []
        sample_root = root
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                candidates.append(Path(dirpath) / fname)
    for path in candidates:
        if path.suffix.lower() not in EXTS:
            continue
        try:
            lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except Exception:
            continue
        for issue_line, _col, method in scan_lines(lines):
            try:
                rel = path.relative_to(sample_root)
            except ValueError:
                rel = path
            issues.append((str(rel), issue_line, method, lines[issue_line - 1].strip().replace('\t', ' ')))
    return issues


def main(argv=None) -> int:
    """Byte-parity entrypoint: same stdout as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    issues = collect_issues(Path(argv[1]))
    print(len(issues))
    for entry in issues[:25]:
        print('\t'.join(str(part) for part in entry))
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        rel_parts = resolved.relative_to(cwd).parts if resolved.is_relative_to(cwd) else ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        rel = str(resolved.relative_to(cwd)) if resolved.is_relative_to(cwd) else str(path)
        for line, col, method in scan_file(path):
            yield {
                "rule": RULE_ID,
                "category_id": "js.async",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "regex",
                "lang": "javascript",
                "severity": "warning",
                "message": f"async array predicate callback is not awaited ({method})",
            }


def _selftest_detects_async_filter(tmp_prefix: str = "ubs_core_async_pred_") -> None:
    import tempfile

    code = (
        "async function paid(customers) {\n"
        "  return customers.filter(async (customer) => {\n"
        "    return hasPaidInvoice(customer);\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "paid.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == RULE_ID, findings
    assert findings[0]["line"] == 2, findings
    assert findings[0]["col"] == 19, findings
    assert "(filter)" in findings[0]["message"], findings
    assert findings[0]["category_id"] == "js.async", findings


def _selftest_detects_some_find_variants() -> None:
    some_code = "const anyPaid = customers.some(async (customer) => hasPaidInvoice(customer));\n"
    find_code = (
        "const first = customers.find(\n"
        "  async function (customer) {\n"
        "    return hasPaidInvoice(customer);\n"
        "  }\n"
        ");\n"
    )
    assert scan_lines(some_code.splitlines()) == [(1, 26, "some")], scan_lines(some_code.splitlines())
    assert scan_lines(find_code.splitlines()) == [(1, 24, "find")], scan_lines(find_code.splitlines())

def _selftest_sync_predicate_clean(tmp_prefix: str = "ubs_core_async_pred_clean_") -> None:
    import tempfile

    code = (
        "const paid = customers.filter((customer) => customer.paid);\n"
        "const idx = customers.findIndex((customer) => customer.paid);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_pred_ign_") -> None:
    import tempfile

    code = (
        "const paid = customers.filter(async (customer) => { // ubs:ignore\n"
        "  return hasPaidInvoice(customer);\n"
        "});\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_async_filter", _selftest_detects_async_filter),
    ("detects_some_find_variants", _selftest_detects_some_find_variants),
    ("sync_predicate_clean", _selftest_sync_predicate_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_predicates", run=run, selftests=SELF_TESTS))
