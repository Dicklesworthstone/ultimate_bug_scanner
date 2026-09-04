"""ubs_core.analyzers.async_jsx_handler — async JSX event-handler detection (bead A4).

Ported verbatim from the modules/ubs-js.sh heredoc "async callbacks passed to JSX
event handlers": JSX handlers declared ``async`` return a Promise, so React (or any
JSX consumer) ignores the returned Promise and thrown errors surface as unhandled
rejections. The heredoc scans for an ``onXxx={`` entry line, joins the
brace-balanced attribute window (18 lines) with newlines, and flags
``async``/``async function`` handlers unless the window contains ``ubs:ignore``.

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

START_RE = re.compile(r'\bon[A-Z][A-Za-z0-9_]*\s*=\s*\{')
ASYNC_HANDLER_RE = re.compile(
    r'\bon[A-Z][A-Za-z0-9_]*\s*=\s*\{\s*(?:async\b|async\s+function\b)',
    re.DOTALL,
)

RULE_ID = "js.async.jsx-handler"
WINDOW = 18


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
        attribute_lines = []
        brace_balance = 0
        saw_attribute = False
        for attr_idx in range(idx, min(len(lines), idx + WINDOW)):
            current = lines[attr_idx].strip()
            attribute_lines.append(current)
            if START_RE.search(current):
                saw_attribute = True
            if saw_attribute:
                brace_balance += current.count('{') - current.count('}')
            if saw_attribute and attr_idx > idx and brace_balance <= 0:
                break
        attribute_text = '\n'.join(attribute_lines)
        if 'ubs:ignore' in attribute_text or not ASYNC_HANDLER_RE.search(attribute_text):
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
                "message": "async JSX event handler callback is not awaited",
            }


def _selftest_detects_async_jsx_handler(tmp_prefix: str = "ubs_core_async_jsx_handler_") -> None:
    import tempfile

    code = (
        "async function submitProfile(): Promise<void> {\n"
        "  await Promise.resolve();\n"
        "}\n"
        "\n"
        "export function ProfileButton() {\n"
        "  return (\n"
        "    <button\n"
        "      onClick={async () => {\n"
        "        await submitProfile();\n"
        "      }}\n"
        "    >\n"
        "      Save\n"
        "    </button>\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "button.tsx"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "js.async.jsx-handler", findings
    assert findings[0]["line"] == 8, findings
    assert findings[0]["message"] == "async JSX event handler callback is not awaited", findings


def _selftest_detects_async_function_handler(tmp_prefix: str = "ubs_core_async_jsx_handler_fn_") -> None:
    import tempfile

    code = (
        "export function Dialog() {\n"
        "  return (\n"
        "    <form onSubmit={async function handleSubmit(event) {\n"
        "      await save(event);\n"
        "    }}>\n"
        "      <input />\n"
        "    </form>\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "dialog.jsx"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 3, findings


def _selftest_sync_handler_clean(tmp_prefix: str = "ubs_core_async_jsx_handler_clean_") -> None:
    import tempfile

    code = (
        "function reportError(error: unknown): void {\n"
        "  console.error(error);\n"
        "}\n"
        "\n"
        "export function ProfileButton() {\n"
        "  return (\n"
        "    <button\n"
        "      onClick={() => {\n"
        "        void submitProfile().catch(reportError);\n"
        "      }}\n"
        "    >\n"
        "      Save\n"
        "    </button>\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.tsx"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_async_jsx_handler_ign_") -> None:
    import tempfile

    code = (
        "export function ProfileButton() {\n"
        "  return (\n"
        "    <button\n"
        "      onClick={async () => { // ubs:ignore\n"
        "        await submitProfile();\n"
        "      }}\n"
        "    >\n"
        "      Save\n"
        "    </button>\n"
        "  );\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.tsx"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_async_jsx_handler", _selftest_detects_async_jsx_handler),
    ("detects_async_function_handler", _selftest_detects_async_function_handler),
    ("sync_handler_clean", _selftest_sync_handler_clean),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
)

register(Analyzer(layer="regex", lang="javascript", name="async_jsx_handler", run=run, selftests=SELF_TESTS))
