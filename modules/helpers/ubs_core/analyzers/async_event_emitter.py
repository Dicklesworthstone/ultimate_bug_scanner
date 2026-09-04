"""ubs_core.analyzers.async_event_emitter — async EventEmitter listener detection (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "async callbacks passed to
EventEmitter listeners": ``on``/``once``/``addListener``/``prependListener``/
``prependOnceListener`` callbacks declared ``async`` return a Promise the emitter
discards, so rejections become unhandled. The heredoc scans for a ``.on(``-style
entry line, joins the paren-balanced callback window (16 lines), and flags
``async``/``async function`` listeners unless the window contains ``ubs:ignore``.

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

START_RE = re.compile(r'\.\s*(?:on|once|addListener|prependListener|prependOnceListener)\s*\(')
ASYNC_EMITTER_RE = re.compile(
    r'\.\s*(on|once|addListener|prependListener|prependOnceListener)\s*\(\s*[^,]+,\s*(?:async\b|async\s+function\b)',
    re.DOTALL,
)

RULE_ID = "js.async.event-emitter"
WINDOW = 16


def scan_file(path: Path):
    """Return (line, col, method) findings for one file; heredoc match logic."""
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
        match = ASYNC_EMITTER_RE.search(callback_text)
        if not match:
            continue
        issues.append((idx + 1, start_match.start() + 1, match.group(1)))
    return issues


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
        for line, _col, method in scan_file(path):
            try:
                rel = path.relative_to(sample_root)
            except ValueError:
                rel = path
            try:
                sample = path.read_text(encoding='utf-8', errors='ignore').splitlines()[line - 1]
            except Exception:
                sample = ''
            issues.append((str(rel), line, method, sample.strip().replace('\t', ' ')))
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
                "message": f"async EventEmitter listener callback is not awaited ({method})",
            }


def _selftest_detects_async_emitter_listener(tmp_prefix: str = "ubs_core_async_event_emitter_") -> None:
    import tempfile

    code = (
        "async function persistMessage(payload: string): Promise<void> {\n"
        "  await Promise.resolve(payload);\n"
        "}\n"
        "\n"
        "export function bindBus(bus: EventBus): void {\n"
        "  bus.on(\"message\", async (payload) => {\n"
        "    await persistMessage(payload);\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "bus.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "js.async.event-emitter", findings
    assert findings[0]["line"] == 6, findings
    assert "(on)" in findings[0]["message"], findings


def _selftest_detects_once_and_addlistener(tmp_prefix: str = "ubs_core_async_event_emitter_var_") -> None:
    import tempfile

    code = (
        "export function bindBus(bus) {\n"
        "  bus.once(\"tick\", async function handleTick() {\n"
        "    await tick();\n"
        "  });\n"
        "  emitter.prependListener('drain', async () => {\n"
        "    await drain();\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "bus.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 2, findings
    assert {f["line"] for f in findings} == {2, 5}, findings
    assert any("(once)" in f["message"] for f in findings), findings
    assert any("(prependListener)" in f["message"] for f in findings), findings


def _selftest_sync_listener_clean(tmp_prefix: str = "ubs_core_async_event_emitter_clean_") -> None:
    import tempfile

    code = (
        "function reportListenerError(error: unknown): void {\n"
        "  console.error(\"message listener failed\", error);\n"
        "}\n"
        "\n"
        "export function bindBus(bus: EventBus): () => void {\n"
        "  const handleMessage = (payload: string): void => {\n"
        "    void persistMessage(payload).catch(reportListenerError);\n"
        "  };\n"
        "\n"
        "  bus.on(\"message\", handleMessage);\n"
        "  return () => bus.off(\"message\", handleMessage);\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_event_emitter_ign_") -> None:
    import tempfile

    code = (
        "export function bindBus(bus: EventBus): void {\n"
        "  bus.on(\"message\", async (payload) => { // ubs:ignore\n"
        "    await persistMessage(payload);\n"
        "  });\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ts"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_async_emitter_listener", _selftest_detects_async_emitter_listener),
    ("detects_once_and_addlistener", _selftest_detects_once_and_addlistener),
    ("sync_listener_clean", _selftest_sync_listener_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_event_emitter", run=run, selftests=SELF_TESTS))
