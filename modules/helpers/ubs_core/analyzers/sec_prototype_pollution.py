"""ubs_core.analyzers.sec_prototype_pollution — request-derived object merge
prototype pollution (bead A4-js final wave).

Verbatim port of the legacy ubs-js.sh heredoc "Request-derived object merge
prototype pollution" (ubs-js.sh 5788-5995): same taint sources, same merge
sinks, same logical-statement/context windows, same per-file taint tracking,
same ``ubs:ignore`` placement rules (RAW line, line above, or anywhere inside
the collected logical statement — markers live in comments, so the
comment-stripped statement check is retained for fidelity), same safe-helper
suppressions (including the dynamic-write safe context requiring BOTH a
prototype-key validator and ``Object.create(null)`` in the context window).
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

RULE = "js.security.prototype-pollution"
CATEGORY_ID = "js.security"
SEVERITY = "critical"
MESSAGE = "Request-derived object merge may allow prototype pollution"

SOURCE_RE = re.compile(
    r'\b(?:req|request|ctx|context|event)\.(?:body|query|params|headers|cookies)\b'
    r'|\b(?:req|request)\.json\s*\('
    r'|\b(?:req|request|ctx|context)\.(?:get|header|param|query)\s*\('
    r'|\bsearchParams\.(?:get|getAll|entries)\s*\('
    r'|\bJSON\.parse\s*\(\s*(?:req|request|event)\.body\b',
    re.IGNORECASE,
)
MERGE_SINK_RE = re.compile(
    r'\b(?:Object\.assign|(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|extend)|'
    r'deepmerge|merge|mergeWith|defaultsDeep|extend)\s*\('
)
DYNAMIC_WRITE_RE = re.compile(r'\[[^\]]+\]\s*=')
ASSIGN_RE = re.compile(
    r'^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(.+)'
)
SAFE_RE = re.compile(
    r'\b(?:sanitizePrototypeKeys|stripPrototypeKeys|rejectPrototypeKeys|'
    r'validatePrototypeKeys|assertNoPrototypeKeys|safeMerge|secureMerge|'
    r'mergeWithoutPrototype|schema\.parse|z\.object|Object\.create\s*\(\s*null\s*\))\b'
)


def strip_line_comments(line: str) -> str:
    quote = ''
    escaped = False
    for idx, ch in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '/' and idx + 1 < len(line) and line[idx + 1] == '/':
            return line[:idx]
    return line


def mask_strings(text: str) -> str:
    chars = list(text)
    quote = ''
    escaped = False
    for idx, ch in enumerate(chars):
        if quote:
            if escaped:
                escaped = False
                chars[idx] = ' '
            elif ch == '\\':
                escaped = True
                chars[idx] = ' '
            elif ch == quote:
                quote = ''
                chars[idx] = ' '
            else:
                chars[idx] = ' '
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            chars[idx] = ' '
    return ''.join(chars)


def logical_statement(lines, index, max_lines=8):
    parts = []
    balance = 0
    for offset in range(index, min(len(lines), index + max_lines)):
        current = strip_line_comments(lines[offset]).strip()
        if not current:
            continue
        parts.append(current)
        balance += current.count('(') - current.count(')')
        balance += current.count('{') - current.count('}')
        balance += current.count('[') - current.count(']')
        if offset > index and balance <= 0:
            break
        if ';' in current and balance <= 0:
            break
    return ' '.join(parts)


def context_window(lines, index):
    start = max(0, index - 8)
    end = min(len(lines), index + 4)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])


def has_untrusted(expr: str, tainted_vars: set) -> bool:
    visible = mask_strings(expr)
    if SOURCE_RE.search(visible):
        return True
    return any(re.search(rf'\b{re.escape(name)}\b', visible) for name in tainted_vars)


def update_taint(statement: str, tainted_vars: set) -> None:
    match = ASSIGN_RE.match(statement)
    if not match:
        return
    target, rhs = match.groups()
    if SAFE_RE.search(rhs):
        tainted_vars.discard(target)
    elif has_untrusted(rhs, tainted_vars):
        tainted_vars.add(target)


def dynamic_write_has_safe_context(context: str) -> bool:
    return bool(
        re.search(r'\b(?:validatePrototypeKeys|assertNoPrototypeKeys|rejectPrototypeKeys)\b', context)
        and re.search(r'\bObject\.create\s*\(\s*null\s*\)', context)
    )


def scan_file_findings(path: Path) -> Iterator[int]:
    """Yield 1-based line numbers per detection; match logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    if not any(token in '\n'.join(lines) for token in (
        'Object.assign', 'merge', 'defaultsDeep', 'extend', 'req.', 'request.', 'searchParams',
    )):
        return
    tainted_vars = set()
    seen = set()
    for idx, raw in enumerate(lines):
        stripped = strip_line_comments(raw).strip()
        if not stripped or stripped.startswith(('*', 'import ', 'export type ', 'type ', 'interface ')):
            continue
        # Suppression markers live in comments, so they must be tested on the
        # RAW line (and the line above) -- logical_statement() is built from
        # comment-stripped text and can never contain the marker (GH #84).
        if 'ubs:ignore' in raw or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        statement = logical_statement(lines, idx)
        if 'ubs:ignore' in statement:
            continue
        update_taint(statement, tainted_vars)
        visible_statement = mask_strings(statement)
        context = context_window(lines, idx)
        if SAFE_RE.search(statement):
            continue
        risky = False
        if MERGE_SINK_RE.search(visible_statement) and has_untrusted(visible_statement, tainted_vars):
            risky = True
        elif (
            DYNAMIC_WRITE_RE.search(visible_statement)
            and has_untrusted(visible_statement, tainted_vars)
            and not dynamic_write_has_safe_context(context)
        ):
            risky = True
        if not risky:
            continue
        key = (str(path), idx + 1)
        if key in seen:
            continue
        seen.add(key)
        yield idx + 1


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
        for line in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_merge_sink_flagged(tmp_prefix: str = "ubs_core_sec_prototype_pollution_") -> None:
    import tempfile

    src = "\n".join([
        "export function assignBody(req) {",
        "  const payload = req.body;",
        "  return Object.assign({}, payload);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "merge.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        # Line 1 is flagged too: the logical statement starting at the
        # function signature spans the body and reaches the tainted sink
        # (same semantics the fixture parity run confirmed for the heredoc).
        assert findings == [1, 3], findings


def _selftest_dynamic_write_flagged(tmp_prefix: str = "ubs_core_sec_prototype_pollution_dyn_") -> None:
    import tempfile

    src = "\n".join([
        "export function write(req) {",
        "  const key = req.query.field;",
        "  const target = {};",
        "  target[key] = req.params.value;",
        "  return target;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "write.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        # Same spanning-statement rule flags the signature line as well.
        assert findings == [1, 4], findings


def _selftest_safe_helpers_clean(tmp_prefix: str = "ubs_core_sec_prototype_pollution_safe_") -> None:
    import tempfile

    src = "\n".join([
        "function validatePrototypeKeys(key) {",
        "  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {",
        "    throw new Error('unsafe object key');",
        "  }",
        "  return key;",
        "}",
        "export function assignSanitized(req) {",
        "  const payload = stripPrototypeKeys(req.body);",
        "  return Object.assign({}, payload);",
        "}",
        "export function safeMergeBody(req) {",
        "  return safeMerge({ theme: 'light' }, req.body);",
        "}",
        "export function write(req) {",
        "  const key = validatePrototypeKeys(req.query.field);",
        "  const target = Object.create(null);",
        "  target[key] = req.params.value;",
        "  return target;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_prototype_pollution_ign_") -> None:
    import tempfile

    # ubs:ignore on the RAW line above and on the RAW line itself both
    # suppress. The statement-window check is inert for comment markers
    # (logical_statement() strips comments, GH #84), so a marker inside a
    # spanning statement only suppresses its own line and the line below —
    # the statement-start line still reports, exactly like the heredoc.
    above = "// ubs:ignore\nconst payload = req.body;\nconst out = Object.assign({}, payload);\n"
    same = "const merged = Object.assign({}, req.body); // ubs:ignore\n"
    in_stmt = "\n".join([
        "export function mergePatch(req) {",
        "  const patch = await request.json(); // ubs:ignore",
        "  return merge({ enabled: true }, patch);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "above.ts"
        target.write_text(above, encoding="utf-8")
        assert list(scan_file_findings(target)) == [], "above-line marker must suppress"
        target = Path(tmp) / "same.ts"
        target.write_text(same, encoding="utf-8")
        assert list(scan_file_findings(target)) == [], "same-line marker must suppress"
        target = Path(tmp) / "stmt.ts"
        target.write_text(in_stmt, encoding="utf-8")
        assert list(scan_file_findings(target)) == [1], "spanning statement still flags line 1"
def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_prototype_pollution_run_") -> None:
    import tempfile
    src = "const payload = req.body;\nconst out = Object.assign({}, payload);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "merge.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "critical", rec
        assert rec["line"] == 2 and rec["col"] == 1, rec
        assert "Request-derived object merge may allow prototype pollution" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("merge-sink-flagged", _selftest_merge_sink_flagged),
    ("dynamic-write-flagged", _selftest_dynamic_write_flagged),
    ("safe-helpers-clean", _selftest_safe_helpers_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_prototype_pollution", run=run, selftests=SELF_TESTS))
