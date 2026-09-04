"""ubs_core.analyzers.async_promise_all_map — Promise.all map callbacks without return (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "Promise.all map callbacks without
return": a ``.map(callback)`` whose block body never ``return``s produces an array of
``undefined`` values, so ``Promise.all`` resolves before any work finishes. The
heredoc scans for a line containing ``Promise.all``, joins the paren-balanced
expression window (35 lines), and flags every block-bodied non-async ``.map(``
callback without a ``return`` in its body unless the window contains ``ubs:ignore``.

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

MAP_BLOCK_RE = re.compile(
    r'\.\s*map\s*\(\s*(?!async\b)(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{',
    re.DOTALL,
)
RETURN_RE = re.compile(r'\breturn\b')
MAP_DOT_RE = re.compile(r'\.\s*map\s*\(')

RULE_ID = "js.async.promise-all-map"
WINDOW = 35


def matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for idx in range(open_index, len(text)):
        char = text[idx]
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return idx
    return -1


def scan_lines(lines: list[str]) -> list[tuple[int, int]]:
    """Return (line, col) findings for one file's lines; heredoc match logic."""
    issues = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if 'Promise.all' not in line or not stripped or stripped.startswith(("//", "/*", "*")):
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
        for match in MAP_BLOCK_RE.finditer(expression):
            open_brace = match.end() - 1
            close_brace = matching_brace(expression, open_brace)
            if close_brace < 0:
                continue
            callback_body = expression[open_brace + 1:close_brace]
            if RETURN_RE.search(callback_body):
                continue
            sample_line = idx + expression[:match.start()].count('\n') + 1
            col_match = MAP_DOT_RE.search(lines[sample_line - 1])
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
                "message": "Promise.all map callback does not return a promise",
            }


def _selftest_detects_map_without_return(tmp_prefix: str = "ubs_core_async_pam_") -> None:
    import tempfile

    code = (
        "async function warm(ids) {\n"
        "  await Promise.all(\n"
        "    ids.map((id) => {\n"
        "      fetchUser(id);\n"
        "    })\n"
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


def _selftest_returning_callback_clean(tmp_prefix: str = "ubs_core_async_pam_clean_") -> None:
    import tempfile

    code = (
        "async function warm(ids) {\n"
        "  return Promise.all(\n"
        "    ids.map((id) => {\n"
        "      return fetchUser(id);\n"
        "    })\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_expression_and_async_bodies_clean() -> None:
    expression_body = "const users = await Promise.all(ids.map((id) => fetchUser(id)));\n"
    async_block_body = "const users = await Promise.all(ids.map(async (id) => { await fetchUser(id); }));\n"
    assert scan_lines(expression_body.splitlines()) == [], scan_lines(expression_body.splitlines())
    assert scan_lines(async_block_body.splitlines()) == [], scan_lines(async_block_body.splitlines())


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_pam_ign_") -> None:
    import tempfile

    code = (
        "async function warm(ids) {\n"
        "  await Promise.all( // ubs:ignore\n"
        "    ids.map((id) => {\n"
        "      fetchUser(id);\n"
        "    })\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_map_without_return", _selftest_detects_map_without_return),
    ("returning_callback_clean", _selftest_returning_callback_clean),
    ("expression_and_async_bodies_clean", _selftest_expression_and_async_bodies_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_promise_all_map", run=run, selftests=SELF_TESTS))
