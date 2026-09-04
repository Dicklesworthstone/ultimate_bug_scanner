"""ubs_core.analyzers.async_promise_all_foreach — Promise.all over forEach results (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "Promise.all over forEach results":
``Array.prototype.forEach`` always returns ``undefined``, so ``Promise.all(...)`` /
``Promise.allSettled(...)`` fed by a ``forEach`` await nothing and rejections escape
unhandled. The heredoc scans for a ``Promise.all(``/``Promise.allSettled(`` entry
line, joins the paren-balanced expression window (35 lines), and flags a
``.forEach(`` call inside that expression unless the window contains ``ubs:ignore``.

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

PROMISE_ALL_RE = re.compile(r'\bPromise\.(?:all|allSettled)\s*\(')
FOREACH_RE = re.compile(r'\.\s*forEach\s*\(')

RULE_ID = "js.async.promise-all-foreach"
WINDOW = 35


def scan_lines(lines: list[str]) -> list[tuple[int, int]]:
    """Return (line, col) findings for one file's lines; heredoc match logic."""
    issues = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        if not PROMISE_ALL_RE.search(line):
            continue
        expression_lines = []
        paren_balance = 0
        for expr_idx in range(idx, min(len(lines), idx + WINDOW)):
            current = lines[expr_idx].strip()
            expression_lines.append(current)
            paren_balance += current.count('(') - current.count(')')
            if expr_idx > idx and paren_balance <= 0:
                break
        expression = '\n'.join(expression_lines)
        if 'ubs:ignore' in expression:
            continue
        match = FOREACH_RE.search(expression)
        if not match:
            continue
        sample_line = idx + expression[:match.start()].count('\n') + 1
        col_match = FOREACH_RE.search(lines[sample_line - 1])
        col = col_match.start() + 1 if col_match else 1
        issues.append((sample_line, col))
    return issues


def scan_file(path: Path) -> list[tuple[int, int]]:
    """Return (line, col) findings for one file; heredoc match logic."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return []
    return scan_lines(lines)


def collect_issues(root: Path) -> list[tuple[str, int, str]]:
    """Heredoc parity entrypoint: (rel_path, line, sample_text) per issue."""
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
        for sample_line, _col in scan_lines(lines):
            try:
                rel = path.relative_to(sample_root)
            except ValueError:
                rel = path
            issues.append((str(rel), sample_line, lines[sample_line - 1].strip().replace('\t', ' ')))
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
        for line, col in scan_file(path):
            yield {
                "rule": RULE_ID,
                "category_id": "js.async",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "regex",
                "lang": "javascript",
                "severity": "warning",
                "message": "Promise.all receives forEach result",
            }


def _selftest_detects_foreach_in_promise_all(tmp_prefix: str = "ubs_core_async_paf_") -> None:
    import tempfile

    code = (
        "async function warm(ids) {\n"
        "  await Promise.all(\n"
        "    ids.forEach((id) => {\n"
        "      fetchUser(id);\n"
        "    }),\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "warm.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == RULE_ID, findings
    assert findings[0]["line"] == 3, findings
    assert findings[0]["col"] == 8, findings
    assert findings[0]["category_id"] == "js.async", findings


def _selftest_detects_all_settled_single_line() -> None:
    code = "Promise.allSettled(items.forEach((item) => run(item)));\n"
    assert scan_lines(code.splitlines()) == [(1, 25)], scan_lines(code.splitlines())


def _selftest_map_based_code_clean(tmp_prefix: str = "ubs_core_async_paf_clean_") -> None:
    import tempfile

    code = (
        "async function warm(ids) {\n"
        "  const tasks = ids.map((id) => fetchUser(id));\n"
        "  await Promise.all(tasks);\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_paf_ign_") -> None:
    import tempfile

    code = (
        "async function warm(ids) {\n"
        "  await Promise.all(\n"
        "    ids.forEach((id) => { // ubs:ignore\n"
        "      fetchUser(id);\n"
        "    }),\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_foreach_in_promise_all", _selftest_detects_foreach_in_promise_all),
    ("detects_all_settled_single_line", _selftest_detects_all_settled_single_line),
    ("map_based_code_clean", _selftest_map_based_code_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_promise_all_foreach", run=run, selftests=SELF_TESTS))
