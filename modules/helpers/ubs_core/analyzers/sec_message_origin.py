"""ubs_core.analyzers.sec_message_origin — window/globalThis message listener
without an event.origin check (bead A4-js security wave).

Port of the legacy "message event listener without origin check" heredoc
from modules/ubs-js.sh: verbatim match semantics (window/globalThis listener
start detection, paren+brace balanced 25-line window, message-arg/onmessage
confirmation, ubs:ignore / origin-guard suppression) with a run(ctx) adapter
on top.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.message-origin"
CATEGORY_ID = "js.security"
MESSAGE = "message event listener without origin check"

LISTENER_START_RE = re.compile(r'(?<![\w$.])(?:window|globalThis)\s*\.\s*(?:addEventListener\s*\(|onmessage\s*=)')
MESSAGE_ARG_RE = re.compile(r'\baddEventListener\s*\(\s*(?:"message"|\'message\'|`message`)')
ONMESSAGE_RE = re.compile(r'\bonmessage\s*=')
ORIGIN_RE = re.compile(r'\.origin\b|\borigin\s*(?:===?|!==?|in\b)|\btrustedOrigin\b|\ballowedOrigins\b')


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
        if not LISTENER_START_RE.search(line):
            continue
        listener_lines = []
        paren_balance = 0
        brace_balance = 0
        saw_listener = False
        for listener_idx in range(idx, min(len(lines), idx + 25)):
            current = lines[listener_idx].strip()
            listener_lines.append(current)
            if 'addEventListener' in current or 'onmessage' in current:
                saw_listener = True
            if saw_listener:
                paren_balance += current.count('(') - current.count(')')
                brace_balance += current.count('{') - current.count('}')
            if saw_listener and listener_idx > idx and paren_balance <= 0 and brace_balance <= 0:
                break
        listener_text = ' '.join(listener_lines)
        if not (ONMESSAGE_RE.search(listener_text) or MESSAGE_ARG_RE.search(listener_text)):
            continue
        if 'ubs:ignore' in listener_text or ORIGIN_RE.search(listener_text):
            continue
        yield idx + 1, LISTENER_START_RE.search(line).start() + 1


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


def _selftest_unchecked_origin_flagged(tmp_prefix: str = "ubs_core_sec_message_origin_") -> None:
    import tempfile

    src = "\n".join([
        "export function listen() {",
        "  window.addEventListener('message', (event) => {",
        "    handle(event.data);",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "listen.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 2, findings
        assert col == 3, findings


def _selftest_origin_guard_clean(tmp_prefix: str = "ubs_core_sec_message_origin_clean_") -> None:
    import tempfile

    src = "\n".join([
        "const TRUSTED = ['https://app.example.com'];",
        "window.addEventListener('message', (event) => {",
        "  if (!TRUSTED.includes(event.origin)) return;",
        "  handle(event.data);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "listen.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_onmessage_unchecked_flagged(tmp_prefix: str = "ubs_core_sec_message_origin_onmsg_") -> None:
    import tempfile

    src = "globalThis.onmessage = (event) => { postMessage(event.data.toUpperCase()); };\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "worker.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 1, findings


def _selftest_ignore_suppressed(tmp_prefix: str = "ubs_core_sec_message_origin_ign_") -> None:
    import tempfile

    # ubs:ignore anywhere inside the collected listener window suppresses.
    src = "\n".join([
        "window.addEventListener('message', (event) => { // ubs:ignore",
        "  handle(event.data);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "listen.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_non_window_listener_ignored(tmp_prefix: str = "ubs_core_sec_message_origin_doc_") -> None:
    import tempfile

    # document/element listeners are out of scope for the legacy heredoc.
    src = "\n".join([
        "document.addEventListener('message', (event) => {",
        "  handle(event.data);",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "listen.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_message_origin_run_") -> None:
    import tempfile

    src = "window.addEventListener('message', (event) => handle(event.data));\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "listen.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1, rec
        assert "origin" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("unchecked-origin-flagged", _selftest_unchecked_origin_flagged),
    ("origin-guard-clean", _selftest_origin_guard_clean),
    ("onmessage-unchecked-flagged", _selftest_onmessage_unchecked_flagged),
    ("ignore-suppressed", _selftest_ignore_suppressed),
    ("non-window-listener-ignored", _selftest_non_window_listener_ignored),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_message_origin", run=run, selftests=SELF_TESTS))
