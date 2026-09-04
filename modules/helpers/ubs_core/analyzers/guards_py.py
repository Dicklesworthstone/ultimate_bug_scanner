"""ubs_core.analyzers.guards_py — deep attribute-chain guard analysis (bead A2).

Logic moved verbatim from the analyze_py_attr_guards heredoc in
modules/ubs-python.sh, which keeps its own copy until that module's port bead.
The heredoc consumes two ast-grep `--json=stream` files (depth-4 attribute
chains and `if`-statement bodies) plus a sample limit, and prints one JSON
payload `{"unguarded": N, "guarded": M, "samples": [...]}`. main() reproduces
that byte-for-byte for the same argv. run(ctx) mirrors the same detection over
ctx.files using Python's ast module instead of ast-grep.
"""
from __future__ import annotations

import ast
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

RULE_ID = "python.guards.deep_attr_chain"
_SEVERITY = "info"  # GH #90: defensive-access lint — info tier, never critical
_MESSAGE = "Deep attribute chain without an explicit guard; check with if or model structure with dataclass/attrs"


def load_stream(path):
    data = []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: data.append(json.loads(line))
                except json.JSONDecodeError: pass
    except FileNotFoundError: return data
    return data


def as_pos(node):
    row = node.get('row')
    if row is None:
        row = node.get('line', 0)
    return (row, node.get('column', 0))


def ge(a, b):
    return a[0] > b[0] or (a[0] == b[0] and a[1] >= b[1])


def le(a, b):
    return a[0] < b[0] or (a[0] == b[0] and a[1] <= b[1])


def within(target, region):
    start, end = target
    rs, re = region
    return ge(start, rs) and le(end, re)


def classify(matches, guards, limit):
    """Heredoc core verbatim: split chain matches into unguarded/guarded."""
    # Store BODY ranges per file
    bodies_by_file = defaultdict(list)
    for guard in guards:
        file_path = guard.get('file')
        if not file_path:
            continue
        # ast-grep versions vary in whether metaVariables are included in JSON output.
        # Prefer the BODY meta range when present; otherwise fall back to the whole match range.
        start = end = None
        body = guard.get('metaVariables', {}).get('single', {}).get('BODY')
        if body:
            rng = body.get('range') or {}
            start = rng.get('start'); end = rng.get('end')
        if not start or not end:
            rng = guard.get('range') or {}
            start = rng.get('start'); end = rng.get('end')
        if not start or not end:
            continue
        bodies_by_file[file_path].append((as_pos(start), as_pos(end)))

    unguarded = 0
    guarded = 0
    samples = []

    for match in matches:
        file_path = match.get('file')
        rng = match.get('range') or {}
        start = rng.get('start'); end = rng.get('end')
        if not file_path or not start or not end: continue
        start_pos = as_pos(start); end_pos = as_pos(end)
        regions = bodies_by_file.get(file_path, [])
        if any(within((start_pos, end_pos), region) for region in regions):
            guarded += 1; continue
        unguarded += 1
        if len(samples) < limit:
            snippet = (match.get('lines') or '').strip()
            samples.append({'file': file_path, 'line': start_pos[0] + 1, 'code': snippet})

    return unguarded, guarded, samples


def main() -> int:
    import sys

    matches_path, guards_path, limit_raw = sys.argv[1:4]
    limit = int(limit_raw)
    matches = load_stream(matches_path)
    guards = load_stream(guards_path)

    unguarded, guarded, samples = classify(matches, guards, limit)

    print(json.dumps({'unguarded': unguarded, 'guarded': guarded, 'samples': samples}, ensure_ascii=False))
    return 0


# ── structured run(ctx): same detection via Python ast ──────────────────────

def _chain_depth(node: ast.expr) -> int:
    depth = 1  # dotted segments (a.b.c.d -> 4), matching `$A.$B.$C.$D`
    while isinstance(node, ast.Attribute):
        depth += 1
        node = node.value
    return depth


def _region_of(if_node: ast.If) -> tuple[tuple[int, int], tuple[int, int]]:
    """(start, end) 0-based (row, col) span of the if body, mirroring the
    ast-grep BODY metaVariable range (first body stmt start .. last stmt end)."""
    first, last = if_node.body[0], if_node.body[-1]
    return (
        (first.lineno - 1, first.col_offset),
        (last.end_lineno - 1, last.end_col_offset),
    )


def scan_tree(tree: ast.AST) -> list[tuple[int, int, int]]:
    """Return (line, col, end_col) for each unguarded depth>=4 attribute chain.

    Mirrors the heredoc: every Attribute node whose dotted chain reaches depth
    4 (tree-sitter reports each such subtree, so a depth-5 chain matches twice,
    exactly like `$A.$B.$C.$D`); a match inside any if-body region is guarded.
    """
    bodies = [
        _region_of(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
    ]
    hits: list[tuple[int, int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if _chain_depth(node) < 4:
            continue
        target = ((node.lineno - 1, node.col_offset), (node.end_lineno - 1, node.end_col_offset))
        if any(within(target, region) for region in bodies):
            continue
        hits.append((node.lineno, node.col_offset + 1, node.end_col_offset + 1))
    return hits


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for line, col, _end_col in scan_tree(tree):
            yield {
                "rule": RULE_ID,
                "path": str(path),
                "line": line,
                "col": col,
                "layer": "guards",
                "lang": "python",
                "severity": _SEVERITY,
                "message": _MESSAGE,
            }


def _selftest_unguarded_positive(tmp_prefix: str = "ubs_core_guards_py_") -> None:
    import tempfile

    code = "def fetch(c):\n    return c.db.settings.host\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "deep.py"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == RULE_ID, findings[0]
    assert findings[0]["line"] == 2, findings[0]
    assert findings[0]["col"] == 12, findings[0]
    assert findings[0]["severity"] == "info", findings[0]


def _selftest_guarded_suppression(tmp_prefix: str = "ubs_core_guards_py_") -> None:
    import tempfile

    code = "def fetch(c, flag):\n    if flag:\n        return c.db.settings.host\n    return None\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "guarded.py"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="python", files=[target])))
    assert findings == [], findings


def _selftest_within_boundaries() -> None:
    # within(target=(chain_start, chain_end), region=(body_start, body_end))
    assert within(((2, 4), (2, 40)), ((2, 4), (2, 40)))
    assert within(((2, 10), (2, 39)), ((2, 4), (2, 40)))
    assert not within(((1, 0), (1, 20)), ((2, 4), (2, 40)))
    assert not within(((3, 0), (3, 20)), ((2, 4), (2, 40)))
    assert not within(((2, 41), (2, 60)), ((2, 4), (2, 40)))
    assert not within(((2, 4), (2, 41)), ((2, 4), (2, 40)))


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_guards_py_") -> None:
    """main() must emit the heredoc's JSON payload for identical streams."""
    import contextlib
    import io
    import sys
    import tempfile

    matches = [
        {"file": "a.py", "range": {"start": {"line": 0, "column": 4}, "end": {"line": 0, "column": 23}}, "lines": "    a.b.c.d"},
        {"file": "b.py", "range": {"start": {"line": 4, "column": 0}, "end": {"line": 4, "column": 19}}, "lines": "x.y.z.w"},
        {"file": "b.py", "range": {"start": {"line": 6, "column": 8}, "end": {"line": 6, "column": 27}}, "lines": "    y = p.q.r.s"},
    ]
    guards = [
        {"file": "b.py", "metaVariables": {"single": {"BODY": {
            "range": {"start": {"line": 6, "column": 4}, "end": {"line": 6, "column": 31}},
        }}}},
    ]
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        mpath = Path(tmp) / "attrs.jsonstream"
        gpath = Path(tmp) / "ifs.jsonstream"
        mpath.write_text("\n".join(json.dumps(m) for m in matches) + "\n", encoding="utf-8")
        gpath.write_text(json.dumps(guards[0]) + "\n", encoding="utf-8")
        buf = io.StringIO()
        old_argv = sys.argv
        try:
            sys.argv = ["guards_py.py", str(mpath), str(gpath), "1"]
            with contextlib.redirect_stdout(buf):
                assert main() == 0
        finally:
            sys.argv = old_argv
    payload = json.loads(buf.getvalue())
    assert buf.getvalue() == (
        json.dumps({'unguarded': 2, 'guarded': 1, 'samples': [
            {'file': 'a.py', 'line': 1, 'code': '    a.b.c.d'.strip()},
        ]}, ensure_ascii=False) + "\n"
    ), repr(buf.getvalue())
    assert payload["samples"][0]["line"] == 1
    # limit=1 truncated the remaining unguarded sample
    assert len(payload["samples"]) == 1 and payload["unguarded"] == 2


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("unguarded_positive", _selftest_unguarded_positive),
    ("guarded_suppression", _selftest_guarded_suppression),
    ("within_boundaries", _selftest_within_boundaries),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="guards", lang="python", name="guards_py", run=run, selftests=SELF_TESTS))
