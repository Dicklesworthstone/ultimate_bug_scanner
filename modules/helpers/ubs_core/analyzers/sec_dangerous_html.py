"""ubs_core.analyzers.sec_dangerous_html — dangerouslySetInnerHTML without a
sanitizer (bead A4-js security wave).

Port of the legacy "dangerouslySetInnerHTML without sanitizer" heredoc from
modules/ubs-js.sh: verbatim match semantics (raw-line detection, JSX tag
window with brace balance, ubs:ignore / sanitizer suppression) with a
run(ctx) adapter on top.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.dangerous-html"
CATEGORY_ID = "js.security"
MESSAGE = "dangerouslySetInnerHTML without sanitizer"

DANGEROUS_RE = re.compile(r'\bdangerouslySetInnerHTML\b')
SAFE_RE = re.compile(
    r'\b(DOMPurify\.sanitize|sanitizeHtml|escapeHtml|sanitizeInput|sanitize)\s*\(',
    re.IGNORECASE,
)


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
        if not DANGEROUS_RE.search(line):
            continue
        start_idx = idx
        for back_idx in range(idx, max(-1, idx - 6), -1):
            if '<' in lines[back_idx]:
                start_idx = back_idx
                break
        tag_lines = []
        brace_balance = 0
        for tag_idx in range(start_idx, min(len(lines), idx + 12)):
            current = lines[tag_idx].strip()
            tag_lines.append(current)
            brace_balance += current.count('{') - current.count('}')
            if tag_idx >= idx and '>' in current and brace_balance <= 0:
                break
        tag_text = ' '.join(tag_lines)
        if 'ubs:ignore' in tag_text or SAFE_RE.search(tag_text):
            continue
        yield idx + 1, DANGEROUS_RE.search(line).start() + 1


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


def _selftest_unsanitized_flagged(tmp_prefix: str = "ubs_core_sec_dangerous_html_") -> None:
    import tempfile

    src = "\n".join([
        "export function Body({ html }: { html: string }) {",
        "  return (",
        "    <div",
        "      dangerouslySetInnerHTML={{ __html: html }}",
        "    />",
        "  );",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "body.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 4, findings
        assert col == 7, findings


def _selftest_sanitizer_clean(tmp_prefix: str = "ubs_core_sec_dangerous_html_clean_") -> None:
    import tempfile

    src = "\n".join([
        "import DOMPurify from 'dompurify';",
        "export function Body({ html }: { html: string }) {",
        "  return (",
        "    <div",
        "      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}",
        "    />",
        "  );",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "body.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppressed(tmp_prefix: str = "ubs_core_sec_dangerous_html_ign_") -> None:
    import tempfile

    # ubs:ignore anywhere inside the collected tag window suppresses.
    src = "\n".join([
        "export function Body({ html }: { html: string }) {",
        "  return (",
        "    <div",
        "      dangerouslySetInnerHTML={{ __html: html }} // ubs:ignore",
        "    />",
        "  );",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "body.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_dangerous_html_run_") -> None:
    import tempfile

    src = "export const Body = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "body.jsx"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1, rec
        assert "dangerouslySetInnerHTML" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("unsanitized-flagged", _selftest_unsanitized_flagged),
    ("sanitizer-clean", _selftest_sanitizer_clean),
    ("ignore-suppressed", _selftest_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_dangerous_html", run=run, selftests=SELF_TESTS))
