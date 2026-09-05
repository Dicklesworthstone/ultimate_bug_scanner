"""ubs_core.analyzers.sec_post_message — postMessage with a wildcard "*"
target origin (bead A4-js security wave).

Port of the legacy "postMessage wildcard target origin" heredoc from
modules/ubs-js.sh: verbatim match semantics (per-line call detection,
paren-balanced call window, wildcard-origin regex over the joined call text,
ubs:ignore suppression) with a run(ctx) adapter on top.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.post-message"
CATEGORY_ID = "js.security"
MESSAGE = "postMessage uses wildcard target origin"

CALL_RE = re.compile(r'\bpostMessage\s*\(')
WILDCARD_ORIGIN_RE = re.compile(r'\bpostMessage\s*\([\s\S]*?,\s*(?:"\*"|\'\*\'|`\*`)\s*(?:[,)]|$)')


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
        if not CALL_RE.search(line):
            continue
        call_lines = []
        paren_balance = 0
        saw_call = False
        for call_idx in range(idx, min(len(lines), idx + 10)):
            current = lines[call_idx].strip()
            call_lines.append(current)
            if 'postMessage' in current:
                saw_call = True
            if saw_call:
                paren_balance += current.count('(') - current.count(')')
            if saw_call and paren_balance <= 0:
                break
        call_text = ' '.join(call_lines)
        if 'ubs:ignore' in call_text or not WILDCARD_ORIGIN_RE.search(call_text):
            continue
        yield idx + 1, CALL_RE.search(line).start() + 1


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


def _selftest_wildcard_flagged(tmp_prefix: str = "ubs_core_sec_post_message_") -> None:
    import tempfile

    src = "\n".join([
        "export function relay(evt: MessageEvent) {",
        "  const win = evt.source as Window;",
        "  win.postMessage(evt.data, '*');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "relay.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 3, findings
        assert col == 7, findings


def _selftest_specific_origin_clean(tmp_prefix: str = "ubs_core_sec_post_message_clean_") -> None:
    import tempfile

    src = "\n".join([
        "export function relay(evt: MessageEvent) {",
        "  const win = evt.source as Window;",
        "  win.postMessage(evt.data, 'https://trusted.example.com');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "relay.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_multiline_wildcard_flagged(tmp_prefix: str = "ubs_core_sec_post_message_ml_") -> None:
    import tempfile

    # Wildcard origin on a continuation line: the paren-balanced window and
    # the joined call text must still catch it (heredoc parity).
    src = "\n".join([
        "worker.postMessage(",
        "  { type: 'chunk', payload },",
        "  '*',",
        ");",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "worker.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 1, findings


def _selftest_ignore_suppressed(tmp_prefix: str = "ubs_core_sec_post_message_ign_") -> None:
    import tempfile

    # ubs:ignore anywhere inside the collected call window suppresses.
    src = "worker.postMessage(payload, '*'); // ubs:ignore\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "worker.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_post_message_run_") -> None:
    import tempfile

    src = "win.postMessage(data, '*');\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "relay.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1, rec
        assert "wildcard" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("wildcard-flagged", _selftest_wildcard_flagged),
    ("specific-origin-clean", _selftest_specific_origin_clean),
    ("multiline-wildcard-flagged", _selftest_multiline_wildcard_flagged),
    ("ignore-suppressed", _selftest_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_post_message", run=run, selftests=SELF_TESTS))
