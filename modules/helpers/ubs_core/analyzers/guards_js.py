"""ubs_core.analyzers.guards_js — deep property access guard analysis (bead A2).

Logic moved verbatim from the ``analyze_deep_property_guards`` heredoc in
modules/ubs-js.sh. The heredoc consumes three ast-grep ``--json=stream`` files
(``$OBJ.$P1.$P2.$P3`` matches, ``if ($COND) $BODY`` matches and optional
``$COND ? $THEN : $ELSE`` matches) plus a sample limit, and prints one JSON
summary line: ``{"unguarded": N, "guarded": M, "samples": [...]}``.

``main()`` reproduces that behavior exactly for the same argv
``<props_stream> <ifs_stream> <limit> [ternaries_stream]``. ``run(ctx)``
mirrors the same detection logic over plain source files for the structured
NDJSON layer (regex span scan feeding the very same region/classification
primitives the heredoc uses).
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register


def load_stream(path):
    entries = []
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return entries
    return entries


# GH #90: membership-test idioms count as explicit guards, same as `a && a.b`.
#   Object.prototype.hasOwnProperty.call(obj, key)  /  Object.hasOwn(obj, key)
#   `key in obj` (the binary `in` operator, not for-in)
HAS_OWN_RE = re.compile(r'\bhasOwnProperty\s*\.\s*call\s*\(|\bObject\s*\.\s*hasOwn\s*\(')
IN_OPERATOR_RE = re.compile(r'(?<![\w$.])in(?![\w$])')


def is_guard_condition(text):
    if '&&' in text:
        return True
    if HAS_OWN_RE.search(text):
        return True
    if IN_OPERATOR_RE.search(text):
        return True
    return False


def as_pos(data):
    line = data.get('line')
    if line is None:
        line = data.get('row', 0)
    return (line, data.get('column', 0))


def ge(a, b):
    return a[0] > b[0] or (a[0] == b[0] and a[1] >= b[1])


def le(a, b):
    return a[0] < b[0] or (a[0] == b[0] and a[1] <= b[1])


def within(target, guard):
    start, end = target
    g_start, g_end = guard
    return ge(start, g_start) and le(end, g_end)


def build_guards_by_file(guards, ternaries):
    guards_by_file = defaultdict(list)
    for guard in guards:
        file_path = guard.get('file')
        cond = guard.get('metaVariables', {}).get('single', {}).get('COND')
        if not file_path or not cond:
            continue
        cond_text = cond.get('text') or ''
        # Explicit short-circuit guards and membership-test guards (GH #90)
        # both count as "guarding" deep chains. Short-circuit conditions keep the
        # historical behavior (suppress chains inside the condition itself);
        # membership tests (hasOwnProperty.call / Object.hasOwn / `in`) extend to
        # the whole if statement, matching the ternary-guard treatment below.
        if HAS_OWN_RE.search(cond_text) or IN_OPERATOR_RE.search(cond_text):
            rng = guard.get('range') or {}
        elif '&&' in cond_text:
            rng = cond.get('range') or {}
        else:
            continue
        start = rng.get('start')
        end = rng.get('end')
        if not start or not end:
            continue
        guards_by_file[file_path].append((as_pos(start), as_pos(end)))

    # GH #90: `guard ? guardedAccess : fallback` ternaries. When the condition is a
    # membership test (hasOwnProperty.call / Object.hasOwn / `in`) or a short-circuit
    # chain, the whole ternary expression is treated as a guarded region, so the
    # access in its branches is not reported as unguarded.
    for ternary in ternaries:
        file_path = ternary.get('file')
        cond = (ternary.get('metaVariables') or {}).get('single', {}).get('COND')
        if not file_path or not cond:
            continue
        cond_text = cond.get('text') or ''
        if not is_guard_condition(cond_text):
            continue
        rng = ternary.get('range') or {}
        start = rng.get('start')
        end = rng.get('end')
        if not start or not end:
            continue
        guards_by_file[file_path].append((as_pos(start), as_pos(end)))
    return guards_by_file


# GH #90: static built-in prototype-method borrowing is itself the guard idiom
# (Object.prototype.hasOwnProperty.call, Array.prototype.slice.call, ...) and
# can never be a null deref; never report it as an unguarded chain.
SAFE_CHAIN_ROOTS = {'Object', 'Array', 'Function', 'String', 'Number', 'Reflect', 'JSON', 'Math'}


def is_safe_builtin_chain(match):
    single = (match.get('metaVariables') or {}).get('single', {})
    obj = (single.get('OBJ') or {}).get('text', '')
    p1 = (single.get('P1') or {}).get('text', '')
    if obj in SAFE_CHAIN_ROOTS and p1 == 'prototype':
        return True
    return False


def analyze(matches, guards, ternaries, limit):
    """Heredoc driver: classify chains and return the summary dict."""
    guards_by_file = build_guards_by_file(guards, ternaries)

    unguarded = 0
    guarded = 0
    samples = []

    for match in matches:
        file_path = match.get('file')
        rng = match.get('range') or {}
        start = rng.get('start')
        end = rng.get('end')
        if not file_path or not start or not end:
            continue
        if is_safe_builtin_chain(match):
            guarded += 1
            continue
        start_pos = as_pos(start)
        end_pos = as_pos(end)
        guard_hits = guards_by_file.get(file_path, [])
        is_guarded = any(within((start_pos, end_pos), guard) for guard in guard_hits)
        if is_guarded:
            guarded += 1
            continue
        unguarded += 1
        if len(samples) < limit:
            snippet = (match.get('lines') or '').strip()
            samples.append({'file': file_path, 'line': start_pos[0] + 1, 'code': snippet})

    return {'unguarded': unguarded, 'guarded': guarded, 'samples': samples}


def main() -> int:
    matches_path, guards_path, limit_raw = sys.argv[1:4]
    ternaries_path = sys.argv[4] if len(sys.argv) > 4 else None
    limit = int(limit_raw)
    matches = load_stream(matches_path)
    guards = load_stream(guards_path)
    ternaries = load_stream(ternaries_path) if ternaries_path else []
    print(json.dumps(analyze(matches, guards, ternaries, limit), ensure_ascii=False))
    return 0


# ────────────────────────────────────────────────────────────────────────────
# Structured NDJSON layer: mirror the ast-grep patterns as plain-text spans
# over ctx.files, then reuse the exact region/classification primitives above.
# ────────────────────────────────────────────────────────────────────────────

JS_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

# $OBJ.$P1.$P2.$P3 — four dot-joined identifiers; the lookbehind keeps longer
# chains anchored at their first identifier (mirrors the single ast-grep match).
_CHAIN_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)"
)
_IF_RE = re.compile(r"\bif\s*\(")


def _pos0(text: str, offset: int) -> tuple[int, int]:
    """0-based (line, column) for an offset, matching ast-grep coordinates."""
    line = text.count("\n", 0, offset)
    col = offset - (text.rfind("\n", 0, offset) + 1)
    return (line, col)


def _rng(text: str, a: int, b: int) -> dict:
    return {
        "start": dict(zip(("line", "column"), _pos0(text, a))),
        "end": dict(zip(("line", "column"), _pos0(text, b))),
    }


def _matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _stmt_end(text: str, close_paren: int) -> int:
    """End of the if statement: matching brace of the body, or end of line/;."""
    n = len(text)
    i = close_paren + 1
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i < n and text[i] == "{":
        depth = 0
        while i < n:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return n
    while i < n and text[i] not in ";\n":
        i += 1
    return i


def _expr_start(text: str, q: int) -> int:
    """Start of the expression ending just before a '?'."""
    depth = 0
    i = q - 1
    while i >= 0:
        ch = text[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                return i + 1
            depth -= 1
        elif depth == 0 and ch in ";,{}:":
            return i + 1
        i -= 1
    return 0


def _ternary_end(text: str, q: int) -> int:
    """End of the ternary starting at '?': after its alternate branch."""
    n = len(text)
    depth = 0
    i = q + 1
    while i < n:
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0:
            if ch == "?" and i + 1 < n and text[i + 1] == "?":
                i += 1  # skip the ?? operator token
            elif ch == ";":
                return i
        i += 1
    return n


def _line_at(text: str, offset: int) -> str:
    nl = text.find("\n", offset)
    return text[text.rfind("\n", 0, offset) + 1: nl if nl >= 0 else len(text)]


def _synthetic_streams(file_key: str, text: str) -> tuple[list, list, list]:
    """Mirror the shell's three ast-grep scans as ast-grep-shaped dicts."""
    stripped = strip_comments_and_strings(text)

    matches = []
    for m in _CHAIN_RE.finditer(stripped):
        obj, p1, p2, p3 = m.groups()
        matches.append({
            "file": file_key,
            "range": _rng(stripped, m.start(), m.end()),
            "lines": _line_at(text, m.start()),
            "metaVariables": {"single": {
                "OBJ": {"text": obj},
                "P1": {"text": p1},
                "P2": {"text": p2},
                "P3": {"text": p3},
            }},
        })

    guards = []
    for m in _IF_RE.finditer(stripped):
        open_idx = m.end() - 1
        close = _matching_paren(stripped, open_idx)
        if close < 0:
            continue
        cond_text = stripped[open_idx + 1: close]
        # Same if/elif ordering as the heredoc: membership guards extend to the
        # whole if statement; bare `&&` conditions guard only their own range.
        if HAS_OWN_RE.search(cond_text) or IN_OPERATOR_RE.search(cond_text):
            region = _rng(stripped, m.start(), _stmt_end(stripped, close))
        elif "&&" in cond_text:
            region = _rng(stripped, open_idx + 1, close)
        else:
            continue
        guards.append({
            "file": file_key,
            "range": region,
            "metaVariables": {"single": {
                "COND": {"text": cond_text, "range": _rng(stripped, open_idx + 1, close)},
            }},
        })

    ternaries = []
    for m in re.finditer(r"\?(?!\.)", stripped):
        q = m.start()
        if (q > 0 and text[q - 1] == "?") or (q + 1 < len(text) and text[q + 1] == "?"):
            continue  # ?? / ?. are not ternaries
        start = _expr_start(stripped, q)
        cond_text = stripped[start:q]
        if not is_guard_condition(cond_text):
            continue
        end = _ternary_end(stripped, q)
        ternaries.append({
            "file": file_key,
            "range": _rng(stripped, start, end),
            "metaVariables": {"single": {
                "COND": {"text": cond_text, "range": _rng(stripped, start, q)},
            }},
        })

    return matches, guards, ternaries


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    pending: list[dict] = []
    for path in ctx.files:
        if path.suffix.lower() not in JS_EXTS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            file_key = str(path.relative_to(cwd))
        except ValueError:
            file_key = str(path)
        matches, guards, ternaries = _synthetic_streams(file_key, text)
        guards_by_file = build_guards_by_file(guards, ternaries)
        for match in matches:
            if is_safe_builtin_chain(match):
                continue
            start_pos = as_pos(match["range"]["start"])
            end_pos = as_pos(match["range"]["end"])
            if any(within((start_pos, end_pos), guard) for guard in guards_by_file.get(file_key, [])):
                continue
            pending.append({
                "rule": "javascript.guards.deep_unguarded_chain",
                "path": file_key,
                "line": start_pos[0] + 1,
                "col": start_pos[1] + 1,
                "layer": "guards",
                "lang": "javascript",
                "message": "Deep property access without explicit guard (obj?.a?.b?.c or if/membership check)",
            })
    # Legacy ladder (ubs-js.sh 3905-3917): warning > 20 unguarded chains,
    # info for 1..20, nothing at 0 — resolved project-wide.
    if pending:
        severity = "warning" if len(pending) > 20 else "info"
        for rec in pending:
            yield dict(rec, severity=severity)


def _selftest_guard_condition_predicates() -> None:
    assert is_guard_condition("a && a.b")
    assert is_guard_condition("Object.prototype.hasOwnProperty.call(o, k)")
    assert is_guard_condition("Object.hasOwn(o, k)")
    assert is_guard_condition("k in o")
    assert not is_guard_condition("a.b")
    assert not is_guard_condition("x === y")


def _selftest_run_finds_unguarded(tmp_prefix: str = "ubs_core_guards_js_") -> None:
    import tempfile

    code = "const total = config.a.b.c.length;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "x.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "javascript.guards.deep_unguarded_chain"
    assert findings[0]["line"] == 1
    assert findings[0]["col"] == code.index("config") + 1


def _selftest_and_cond_suppression(tmp_prefix: str = "ubs_core_guards_js_") -> None:
    import tempfile

    code = "if (cfg && cfg.a.b.c) { ok(); }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "x.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_and_cond_body_still_reported(tmp_prefix: str = "ubs_core_guards_js_") -> None:
    import tempfile

    # `&&` guards only suppress chains inside the condition itself; a deep
    # chain in the if body stays unguarded (historical heredoc behavior).
    code = "if (cfg && cfg.a) { touch(cfg.a.b.c); }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "x.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 1


def _selftest_membership_suppression(tmp_prefix: str = "ubs_core_guards_js_") -> None:
    import tempfile

    for code in (
        "if ('a' in cfg) { log(cfg.a.b.c); }\n",
        "if (Object.hasOwn(cfg, 'a')) { save(cfg.a.b.c); }\n",
        "if (Object.prototype.hasOwnProperty.call(cfg, 'a')) { use(cfg.a.b.c); }\n",
    ):
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "x.js"
            target.write_text(code, encoding="utf-8")
            findings = list(run(RunContext(lang="javascript", files=[target])))
        assert findings == [], (code, findings)


def _selftest_ternary_suppression(tmp_prefix: str = "ubs_core_guards_js_") -> None:
    import tempfile

    code = "const v = cfg && cfg.a ? cfg.a.b.c.d : 0;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "x.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_safe_builtin_suppression(tmp_prefix: str = "ubs_core_guards_js_") -> None:
    import tempfile

    code = "const has = Object.prototype.hasOwnProperty.call(opts, key);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "x.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("guard_condition_predicates", _selftest_guard_condition_predicates),
    ("run_finds_unguarded", _selftest_run_finds_unguarded),
    ("and_cond_suppression", _selftest_and_cond_suppression),
    ("and_cond_body_still_reported", _selftest_and_cond_body_still_reported),
    ("membership_suppression", _selftest_membership_suppression),
    ("ternary_suppression", _selftest_ternary_suppression),
    ("safe_builtin_suppression", _selftest_safe_builtin_suppression),
)

register(Analyzer(layer="guards", lang="javascript", name="guards_js", run=run, selftests=SELF_TESTS))
