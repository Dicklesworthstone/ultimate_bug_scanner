"""ubs_core.analyzers.async_event_listener — async addEventListener callback detection (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "async callbacks passed to event
listeners": ``addEventListener`` ignores the returned Promise, so async listener
callbacks drop rejections (unhandled rejection / silent failure). The heredoc scans
for an ``addEventListener(`` entry line, joins the paren-balanced callback window
(16 lines), and flags ``async``/``async function`` as the second argument unless the
window contains ``ubs:ignore``.

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

START_RE = re.compile(r'\baddEventListener\s*\(')
ASYNC_LISTENER_RE = re.compile(
    r'\baddEventListener\s*\(\s*[^,]+,\s*(?:async\b|async\s+function\b)',
    re.DOTALL,
)

RULE_ID = "js.async.event-listener"
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
        callback_lines = []
        paren_balance = 0
        saw_listener = False
        for callback_idx in range(idx, min(len(lines), idx + WINDOW)):
            current = lines[callback_idx].strip()
            callback_lines.append(current)
            if START_RE.search(current):
                saw_listener = True
            if saw_listener:
                paren_balance += current.count('(') - current.count(')')
            if saw_listener and callback_idx > idx and paren_balance <= 0:
                break
        callback_text = ' '.join(callback_lines)
        if 'ubs:ignore' in callback_text:
            continue
        if not ASYNC_LISTENER_RE.search(callback_text):
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
                "message": "async event listener callback is not awaited",
            }


def _selftest_detects_async_listener(tmp_prefix: str = "ubs_core_async_event_listener_") -> None:
    import tempfile

    code = (
        "export function bindTracking(target: EventTarget): void {\n"
        "  target.addEventListener('click', async () => {\n"
        "    await sendAnalytics('checkout-clicked');\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "track.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "js.async.event-listener", findings
    assert findings[0]["line"] == 2, findings


def _selftest_detects_async_function_multiline(tmp_prefix: str = "ubs_core_async_event_listener_fn_") -> None:
    import tempfile

    code = (
        "el.addEventListener('submit',\n"
        "  async function handleSubmit(event) {\n"
        "    await persist(event.target);\n"
        "  }\n"
        ");\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "form.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 1, findings


def _selftest_sync_handler_clean(tmp_prefix: str = "ubs_core_async_event_listener_clean_") -> None:
    import tempfile

    code = (
        "const handleClick = (): void => {\n"
        "  void sendAnalytics('checkout-clicked').catch(reportAnalyticsError);\n"
        "};\n"
        "target.addEventListener('click', handleClick);\n"
        "return () => target.removeEventListener('click', handleClick);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_event_listener_ign_") -> None:
    import tempfile

    code = (
        "target.addEventListener('click', async () => { // ubs:ignore\n"
        "  await sendAnalytics('checkout-clicked');\n"
        "});\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_async_listener", _selftest_detects_async_listener),
    ("detects_async_function_multiline", _selftest_detects_async_function_multiline),
    ("sync_handler_clean", _selftest_sync_handler_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_event_listener", run=run, selftests=SELF_TESTS))
