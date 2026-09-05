"""ubs_core.analyzers.sec_jsx_target_blank — JSX target="_blank" without
noopener/noreferrer (bead A4-js security wave).

Port of the legacy "JSX target=_blank without noopener" heredoc from
modules/ubs-js.sh: verbatim match semantics (per-line target detection,
backward '<' tag-start window, forward tag window, ubs:ignore / rel-safe
suppression) with a run(ctx) adapter on top.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.jsx-target-blank"
CATEGORY_ID = "js.security"
MESSAGE = "JSX target=_blank without noopener/noreferrer"

TARGET_RE = re.compile(r'target\s*=\s*(?:"_blank"|\'_blank\'|\{\s*(?:"_blank"|\'_blank\'|`_blank`)\s*\})')
REL_SAFE_RE = re.compile(
    r'rel\s*=\s*(?:"[^"]*(?:noopener|noreferrer)[^"]*"|\'[^\']*(?:noopener|noreferrer)[^\']*\'|\{[^}]*\b(?:noopener|noreferrer)\b[^}]*\})',
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
        if not TARGET_RE.search(line):
            continue
        start_idx = idx
        for back_idx in range(idx, max(-1, idx - 8), -1):
            if '<' in lines[back_idx]:
                start_idx = back_idx
                break
        tag_lines = []
        for tag_idx in range(start_idx, min(len(lines), idx + 8)):
            tag_lines.append(lines[tag_idx].strip())
            if '>' in lines[tag_idx]:
                break
        tag_text = ' '.join(tag_lines)
        if 'ubs:ignore' in tag_text or REL_SAFE_RE.search(tag_text):
            continue
        yield idx + 1, TARGET_RE.search(line).start() + 1


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


def _selftest_missing_rel_flagged(tmp_prefix: str = "ubs_core_sec_jsx_target_blank_") -> None:
    import tempfile

    src = "\n".join([
        "export function Link({ href }: { href: string }) {",
        "  return (",
        "    <a",
        "      href={href}",
        "      target=\"_blank\"",
        "    >external</a>",
        "  );",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "link.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 5, findings
        assert col == 7, findings


def _selftest_noopener_rel_clean(tmp_prefix: str = "ubs_core_sec_jsx_target_blank_clean_") -> None:
    import tempfile

    src = "\n".join([
        "export function Link({ href }: { href: string }) {",
        "  return <a href={href} target=\"_blank\" rel=\"noopener noreferrer\">external</a>;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "link.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppressed(tmp_prefix: str = "ubs_core_sec_jsx_target_blank_ign_") -> None:
    import tempfile

    # ubs:ignore anywhere inside the collected tag window suppresses.
    src = "\n".join([
        "export function Link({ href }: { href: string }) {",
        "  return <a href={href} target='_blank'>external</a>; // ubs:ignore",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "link.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_jsx_target_blank_run_") -> None:
    import tempfile

    src = "export const Link = ({ href }) => <a href={href} target=\"_blank\">x</a>;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "link.jsx"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1, rec
        assert "noopener" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("missing-rel-flagged", _selftest_missing_rel_flagged),
    ("noopener-rel-clean", _selftest_noopener_rel_clean),
    ("ignore-suppressed", _selftest_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_jsx_target_blank", run=run, selftests=SELF_TESTS))
