"""ubs_core.analyzers.guards_ruby — Ruby deep method chain guard analysis (bead A2).

Logic moved verbatim from the `analyze_rb_chain_guards` heredoc in
modules/ubs-ruby.sh (which keeps its heredoc until that module's port bead —
transitional duplication is sanctioned). The heredoc consumes an ast-grep
`--json=stream` match file plus a sample limit and prints one JSON metric
payload; main() reproduces that behavior exactly. Also exposes a structured
`run(ctx)` for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from ubs_core.io import line_col
from ubs_core.registry import Analyzer, RunContext, register

RUBY_SUFFIXES = frozenset({".rb"})

# The shell's own non-AST fallback for "$A.$B.$C.$D": three dots on one line.
CHAIN_RE = re.compile(r"\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*")
SAFE_NAV_RE = re.compile(r"\&\.")
INLINE_GUARD_RE = re.compile(r"\bif\b.+\bnil\?")

_MESSAGE = {
    "unguarded": "Deep method chain without guard (prefer &. safe navigation or guard clauses)",
    "guarded": "Deep method chain guarded by safe navigation or inline nil? guard",
}


def load_stream(path):
    data = []
    try:
        for line in open(path, 'r', encoding='utf-8'):
            line=line.strip()
            if not line: continue
            try: data.append(json.loads(line))
            except Exception: pass
    except FileNotFoundError: pass
    return data


def main(argv: list[str] | None = None) -> int:
    """Reproduce the shell heredoc: argv[1]=ast-grep stream file, argv[2]=limit."""
    import sys

    if argv is None:
        argv = sys.argv
    matches_path, limit_raw = argv[1:3]
    limit = int(limit_raw)
    matches = load_stream(matches_path)
    unguarded = 0; guarded = 0; samples = []
    safe_nav = re.compile(r'\&\.')
    for m in matches:
        file_path = m.get('file')
        code = (m.get('lines') or '').strip()
        rng = m.get('range') or {}
        start = rng.get('start') or {}
        line = start.get('row', 0) + 1
        suppressed = bool(safe_nav.search(code)) or bool(re.search(r'\bif\b.+\bnil\?', code))
        if suppressed:
            guarded += 1
        else:
            unguarded += 1
            if len(samples) < limit:
                samples.append({'file': file_path, 'line': line, 'code': code})
    print(json.dumps({'unguarded': unguarded, 'guarded': guarded, 'samples': samples}))
    return 0


def classify_line(code: str) -> str | None:
    """Return 'unguarded'/'guarded' for a deep-chain line, else None."""
    if not CHAIN_RE.search(code):
        return None
    if SAFE_NAV_RE.search(code) or INLINE_GUARD_RE.search(code):
        return "guarded"
    return "unguarded"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in RUBY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        offset = 0
        for raw_line in text.splitlines(keepends=True):
            kind = classify_line(raw_line)
            if kind is not None:
                for m in CHAIN_RE.finditer(raw_line):
                    line, col = line_col(text, offset + m.start())
                    yield {
                        "rule": f"ruby.guards.{kind}",
                        "path": rel,
                        "line": line,
                        "col": col,
                        "layer": "guards",
                        "lang": "ruby",
                        "severity": "info",
                        "message": _MESSAGE[kind],
                    }
            offset += len(raw_line)


def _selftest_unguarded_detected() -> None:
    assert classify_line("  out = a.b.c.d\n") == "unguarded"
    assert classify_line("  x = foo.bar\n") is None  # short chain: ast-grep $A.$B.$C.$D would not match
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_guards_ruby_") as tmp:
        target = Path(tmp) / "chainy.rb"
        target.write_text("out = a.b.c.d\n", encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "ruby.guards.unguarded"
    assert findings[0]["line"] == 1
    assert findings[0]["col"] == 8  # chain regex starts at the first dot of a.b.c.d
    assert findings[0]["severity"] == "info"


def _selftest_safe_nav_suppression() -> None:
    # Pure safe-nav chains have no three literal dots: ast-grep $A.$B.$C.$D never
    # feeds them to the classifier, so there is no candidate line at all.
    assert classify_line("  name = user&.profile&.contact&.email\n") is None
    # Line-level suppression mirrors the heredoc: a chain candidate on a line
    # holding a &. or an inline `if ... nil?` guard counts as guarded.
    assert classify_line("  v = config.settings.database.url if cfg&.loaded?\n") == "guarded"
    assert classify_line("  full = a.b.c.d if opts.nil? == false\n") == "guarded"
    assert classify_line("  plain = q.w.e.r\n") == "unguarded"
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_guards_ruby_") as tmp:
        target = Path(tmp) / "guarded.rb"
        target.write_text("v = config.settings.database.url if cfg&.loaded?\n", encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert [f["rule"] for f in findings] == ["ruby.guards.guarded"], findings


def _selftest_main_emit_dialect() -> None:
    import io as _io
    import contextlib
    import tempfile

    rows = [
        {"file": "a.rb", "lines": "  x = a.b.c.d", "range": {"start": {"row": 4}}},
        {"file": "b.rb", "lines": "  y = u&.v&.w&.z", "range": {"start": {"row": 9}}},
        {"file": "c.rb", "lines": "  z = p.q.r.s", "range": {}},
        "this is not json",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_guards_ruby_") as tmp:
        stream = Path(tmp) / "stream.jsonl"
        with stream.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(row if isinstance(row, str) else json.dumps(row))
                fh.write("\n")
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["guards_ruby.py", str(stream), "1"])
    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert payload == {
        "unguarded": 2,
        "guarded": 1,
        "samples": [{"file": "a.rb", "line": 5, "code": "x = a.b.c.d"}],
    }, payload


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("unguarded_detected", _selftest_unguarded_detected),
    ("safe_nav_suppression", _selftest_safe_nav_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="guards", lang="ruby", name="guards_ruby", run=run, selftests=SELF_TESTS))
