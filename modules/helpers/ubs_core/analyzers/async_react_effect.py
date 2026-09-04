"""ubs_core.analyzers.async_react_effect — async function passed directly to React
useEffect (bead A4-js wave 1).

Verbatim port of the legacy ubs-js.sh heredoc "async React effect callbacks":
same regexes, same 12-line effect window, same paren-balance stop rule, same
``ubs:ignore`` placement rules (anywhere inside the collected effect text).
The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.async.react-effect"
CATEGORY_ID = "js.async"
MESSAGE = ("async React effect callback: Do not pass an async function directly "
           "to useEffect; define and call an inner async function instead")

START_RE = re.compile(r'\b(?:React\.)?use(?:Layout|Insertion)?Effect\s*\(')
ASYNC_EFFECT_RE = re.compile(r'\b(?:React\.)?use(?:Layout|Insertion)?Effect\s*\(\s*async\b')


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
        if not START_RE.search(line):
            continue
        effect_lines = []
        paren_balance = 0
        saw_effect = False
        for effect_idx in range(idx, min(len(lines), idx + 12)):
            current = lines[effect_idx].strip()
            effect_lines.append(current)
            if START_RE.search(current):
                saw_effect = True
            if saw_effect:
                paren_balance += current.count('(') - current.count(')')
            if saw_effect and effect_idx > idx and paren_balance <= 0:
                break
        effect_text = ' '.join(effect_lines)
        if 'ubs:ignore' in effect_text or not ASYNC_EFFECT_RE.search(effect_text):
            continue
        yield idx + 1, START_RE.search(line).start() + 1


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


def _selftest_async_effect_flagged(tmp_prefix: str = "ubs_core_async_react_effect_") -> None:
    import tempfile

    src = "\n".join([
        "import { useEffect } from 'react';",
        "",
        "export function Panel({ id }) {",
        "  useEffect(",
        "    async () => {",
        "      const data = await fetch('/api/item/' + id);",
        "      setData(await data.json());",
        "    },",
        "    [id]",
        "  );",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "panel.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 4, findings
        assert col == 3, findings


def _selftest_sync_effect_clean(tmp_prefix: str = "ubs_core_async_react_effect_clean_") -> None:
    import tempfile

    src = "\n".join([
        "import { useEffect } from 'react';",
        "",
        "export function Panel({ id }) {",
        "  useEffect(() => {",
        "    let cancelled = false;",
        "    async function load() {",
        "      const data = await fetch('/api/item/' + id);",
        "      if (!cancelled) setData(await data.json());",
        "    }",
        "    void load();",
        "    return () => { cancelled = true; };",
        "  }, [id]);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "panel.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_same_line_ignore_suppressed(tmp_prefix: str = "ubs_core_async_react_effect_ign_") -> None:
    import tempfile

    # ubs:ignore on the useEffect start line (inside the effect window) suppresses.
    src = "\n".join([
        "useEffect( // ubs:ignore",
        "  async () => {",
        "    await load();",
        "  },",
        "  [],",
        ");",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "panel.jsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_window_ignore_suppressed(tmp_prefix: str = "ubs_core_async_react_effect_wign_") -> None:
    import tempfile

    # ubs:ignore on any line inside the collected effect window suppresses.
    src = "\n".join([
        "useEffect(",
        "  async () => {",
        "    await load(); // ubs:ignore",
        "  },",
        "  [],",
        ");",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "panel.jsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_async_react_effect_run_") -> None:
    import tempfile

    src = "useEffect(async () => { await load(); }, []);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "panel.jsx"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 1, rec
        assert "useEffect" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("async-effect-flagged", _selftest_async_effect_flagged),
    ("sync-effect-clean", _selftest_sync_effect_clean),
    ("same-line-ignore-suppressed", _selftest_same_line_ignore_suppressed),
    ("window-ignore-suppressed", _selftest_window_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="async_react_effect", run=run, selftests=SELF_TESTS))
