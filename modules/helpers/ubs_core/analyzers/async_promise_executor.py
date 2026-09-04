"""ubs_core.analyzers.async_promise_executor — async Promise executor detection (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "async Promise executors":
``new Promise(async (...) => ...)`` — an executor declared ``async`` returns a
Promise the constructor discards, so ``throw`` inside it never rejects the outer
promise (the error is lost). The heredoc scans for a ``new Promise(`` entry line
(optional generic), joins the paren-balanced expression window (16 lines), and
flags ``async``/``async function`` executors unless the window contains
``ubs:ignore``.

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

START_RE = re.compile(r'\bnew\s+Promise(?:\s*<[^>\n]+>)?\s*\(')
ASYNC_EXECUTOR_RE = re.compile(
    r'\bnew\s+Promise(?:\s*<[^>\n]+>)?\s*\(\s*(?:async\b|async\s+function\b)',
    re.DOTALL,
)

RULE_ID = "js.async.promise-executor"
WINDOW = 16


def scan_file(path: Path):
    """Return (line, col) findings for one file; heredoc match logic."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return []
    issues = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        start_match = START_RE.search(line)
        if not start_match:
            continue
        expression_lines = []
        paren_balance = 0
        saw_promise = False
        for expr_idx in range(idx, min(len(lines), idx + WINDOW)):
            current = lines[expr_idx].strip()
            expression_lines.append(current)
            if START_RE.search(current):
                saw_promise = True
            if saw_promise:
                paren_balance += current.count('(') - current.count(')')
            if saw_promise and expr_idx > idx and paren_balance <= 0:
                break
        expression_text = ' '.join(expression_lines)
        if 'ubs:ignore' in expression_text or not ASYNC_EXECUTOR_RE.search(expression_text):
            continue
        issues.append((idx + 1, start_match.start() + 1))
    return issues


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
        for line, _col in scan_file(path):
            try:
                rel = path.relative_to(sample_root)
            except ValueError:
                rel = path
            try:
                sample = path.read_text(encoding='utf-8', errors='ignore').splitlines()[line - 1]
            except Exception:
                sample = ''
            issues.append((str(rel), line, sample.strip().replace('\t', ' ')))
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
                "message": "async Promise executor drops thrown errors",
            }


def _selftest_detects_async_executor(tmp_prefix: str = "ubs_core_async_promise_executor_") -> None:
    import tempfile

    code = (
        "export function loadProfile(userId: string): Promise<string> {\n"
        "  return new Promise<string>(async (resolve) => {\n"
        "    const response = await fetch(`/api/profiles/${userId}`);\n"
        "    if (!response.ok) {\n"
        "      throw new Error(\"profile load failed\");\n"
        "    }\n"
        "    resolve(await response.text());\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "profile.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "js.async.promise-executor", findings
    assert findings[0]["line"] == 2, findings
    assert findings[0]["message"] == "async Promise executor drops thrown errors", findings


def _selftest_detects_async_function_executor(tmp_prefix: str = "ubs_core_async_promise_executor_fn_") -> None:
    import tempfile

    code = (
        "export function loadProfile(userId) {\n"
        "  return new Promise(async function (resolve, reject) {\n"
        "    try {\n"
        "      resolve(await load(userId));\n"
        "    } catch (error) {\n"
        "      reject(error);\n"
        "    }\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "profile.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 2, findings


def _selftest_sync_executor_clean(tmp_prefix: str = "ubs_core_async_promise_executor_clean_") -> None:
    import tempfile

    code = (
        "export function loadProfile(cache: Map<string, string>, userId: string): Promise<string> {\n"
        "  return new Promise<string>((resolve, reject) => {\n"
        "    const cachedProfile = cache.get(userId);\n"
        "    if (cachedProfile === undefined) {\n"
        "      reject(new Error(\"profile missing\"));\n"
        "      return;\n"
        "    }\n"
        "    resolve(cachedProfile);\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_promise_executor_ign_") -> None:
    import tempfile

    code = (
        "export function loadProfile(userId) {\n"
        "  return new Promise(async (resolve) => { // ubs:ignore\n"
        "    resolve(await load(userId));\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_async_executor", _selftest_detects_async_executor),
    ("detects_async_function_executor", _selftest_detects_async_function_executor),
    ("sync_executor_clean", _selftest_sync_executor_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_promise_executor", run=run, selftests=SELF_TESTS))
