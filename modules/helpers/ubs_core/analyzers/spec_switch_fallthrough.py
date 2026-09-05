"""ubs_core.analyzers.spec_switch_fallthrough — switch clauses that can fall
through into the next clause (bead A4-js final wave).

Verbatim port of the legacy ubs-js.sh heredoc "Switch cases without
break/return" (GH #74): clause-level analysis per switch statement instead of
comparing global ``case:``/``break;`` counts. Same FALLTHROUGH_RE / TERMINATOR_RE
regexes, same comment/string-blanking strip_code (offset-preserving), same
depth-1 clause-label discovery, same empty-clause (grouped label) exemption,
same fall-through-comment exemption, same ``ubs:ignore`` placement rule
(anywhere in the raw span from the flagged label through the next label).
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

RULE = "js.control-flow.switch-fallthrough"
CATEGORY_ID = "js.control-flow"
MESSAGE = ("Switch cases may be missing break: "
           "Add break or /* falls through */")

FALLTHROUGH_RE = re.compile(r'falls?[\s_-]*through', re.IGNORECASE)
TERMINATOR_RE = re.compile(
    r'(?:^|[\s;{}])(?:break|continue)\b\s*(?:[A-Za-z_$][\w$]*)?\s*;?\s*\}*\s*;?\s*$'
    r'|(?:^|[\s;{}])(?:return|throw)\b[^;]*;?\s*\}*\s*;?\s*$'
    r'|\bprocess\s*\.\s*exit\s*\('
)
REGEX_PREFIX_CHARS = set('(,=:[!&|?{};+-*%~^<>')


def strip_code(text):
    """Blank out comments and string/template literal contents, preserving
    line structure so offsets and line numbers stay aligned with the source."""
    out = []
    i = 0
    n = len(text)
    state = 'code'
    prev_code = ''
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if state == 'code':
            if ch == '/' and nxt == '/':
                state = 'line_comment'
                out.append('  ')
                i += 2
                continue
            if ch == '/' and nxt == '*':
                state = 'block_comment'
                out.append('  ')
                i += 2
                continue
            if ch == '/' and (prev_code == '' or prev_code in REGEX_PREFIX_CHARS):
                state = 'regex'
                out.append(' ')
                i += 1
                continue
            if ch == "'":
                state = 'single'
                out.append(' ')
                i += 1
                continue
            if ch == '"':
                state = 'double'
                out.append(' ')
                i += 1
                continue
            if ch == '`':
                state = 'template'
                out.append(' ')
                i += 1
                continue
            out.append(ch)
            if not ch.isspace():
                prev_code = ch
            i += 1
            continue
        if state == 'line_comment':
            if ch == '\n':
                state = 'code'
                out.append('\n')
            else:
                out.append(' ')
            i += 1
            continue
        if state == 'block_comment':
            if ch == '*' and nxt == '/':
                state = 'code'
                out.append('  ')
                i += 2
            else:
                out.append('\n' if ch == '\n' else ' ')
                i += 1
            continue
        if state in ('single', 'double', 'template', 'regex'):
            closer = {'single': "'", 'double': '"', 'template': '`', 'regex': '/'}[state]
            if ch == '\\':
                out.append(' ')
                if nxt:
                    out.append('\n' if nxt == '\n' else ' ')
                i += 2
                continue
            if ch == closer:
                state = 'code'
                out.append(' ')
                i += 1
                continue
            if ch == '\n':
                if state in ('single', 'double', 'regex'):
                    state = 'code'
                out.append('\n')
                i += 1
                continue
            out.append(' ')
            i += 1
            continue
    return ''.join(out)


def find_matching(text, start, open_ch, close_ch):
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == open_ch:
            depth += 1
        elif text[pos] == close_ch:
            depth -= 1
            if depth == 0:
                return pos
    return -1


def label_colon(text, start, end):
    """Find the colon terminating a case label expression starting at `start`."""
    paren = bracket = brace = ternary = 0
    for pos in range(start, end):
        ch = text[pos]
        if ch == '(':
            paren += 1
        elif ch == ')':
            paren -= 1
        elif ch == '[':
            bracket += 1
        elif ch == ']':
            bracket -= 1
        elif ch == '{':
            brace += 1
        elif ch == '}':
            brace -= 1
        elif ch == '?':
            if pos + 1 < end and text[pos + 1] in '.?':
                continue
            ternary += 1
        elif ch == ':' and paren == 0 and bracket == 0 and brace == 0:
            if ternary > 0:
                ternary -= 1
            else:
                return pos
    return -1


def clause_terminated(content):
    lines = [l for l in content.splitlines()]
    for raw in reversed(lines):
        stripped = raw.strip()
        if not stripped:
            continue
        if re.fullmatch(r'[\s;{}()\[\]]*', stripped):
            continue
        return bool(TERMINATOR_RE.search(stripped))
    return None  # empty clause (grouped labels)


def scan_file_findings(path: Path) -> Iterator[tuple[int, int]]:
    """Yield (line, col) of each non-final clause that can fall through;
    match logic identical to the heredoc."""
    try:
        raw_text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return
    text = strip_code(raw_text)
    raw_lines = raw_text.splitlines()

    for switch_match in re.finditer(r'\bswitch\s*\(', text):
        paren_open = switch_match.end() - 1
        paren_close = find_matching(text, paren_open, '(', ')')
        if paren_close < 0:
            continue
        body_open = text.find('{', paren_close)
        if body_open < 0 or text[paren_close + 1:body_open].strip():
            continue
        body_close = find_matching(text, body_open, '{', '}')
        if body_close < 0:
            continue

        # Locate clause labels at depth 1 of the switch body.
        labels = []
        depth = 1
        pos = body_open + 1
        while pos < body_close:
            ch = text[pos]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            elif depth == 1 and text.startswith('case', pos) and \
                    not (pos > 0 and (text[pos - 1].isalnum() or text[pos - 1] in '_$')) and \
                    not (text[pos + 4].isalnum() or text[pos + 4] in '_$'):
                colon = label_colon(text, pos + 4, body_close)
                if colon > 0:
                    labels.append((pos, colon))
                    pos = colon + 1
                    continue
            elif depth == 1 and text.startswith('default', pos) and \
                    not (pos > 0 and (text[pos - 1].isalnum() or text[pos - 1] in '_$')) and \
                    not (text[pos + 7].isalnum() or text[pos + 7] in '_$'):
                colon = text.find(':', pos + 7, body_close)
                if colon > 0 and not text[pos + 7:colon].strip():
                    labels.append((pos, colon))
                    pos = colon + 1
                    continue
            pos += 1

        for index, (label_pos, colon_pos) in enumerate(labels):
            content_end = labels[index + 1][0] if index + 1 < len(labels) else body_close
            if index + 1 >= len(labels):
                continue  # final clause falls out of the switch, not into a case
            content = text[colon_pos + 1:content_end]
            terminated = clause_terminated(content)
            if terminated is None or terminated:
                continue
            label_line = text.count('\n', 0, label_pos) + 1
            next_label_line = text.count('\n', 0, content_end) + 1
            raw_span = '\n'.join(raw_lines[label_line - 1:next_label_line])
            if FALLTHROUGH_RE.search(raw_span) or 'ubs:ignore' in raw_span:
                continue
            yield label_line, label_pos - text.rfind('\n', 0, label_pos)


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


def _selftest_fallthrough_flagged(tmp_prefix: str = "ubs_core_switch_fallthrough_") -> None:
    import tempfile

    src = "\n".join([
        "export function applyChange(kind, payload) {",
        "  let result = null;",
        "  switch (kind) {",
        '    case "create":',
        '      result = { op: "create", payload };',
        '    case "update":',
        '      result = { op: "update", payload };',
        "      break;",
        '    case "delete":',
        '      result = { op: "delete", payload };',
        "      break;",
        "    default:",
        '      result = { op: "noop", payload };',
        "  }",
        "  return result;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "control_flow.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        line, col = findings[0]
        assert line == 4, findings
        assert col == 5, findings


def _selftest_terminated_and_grouped_clean(tmp_prefix: str = "ubs_core_switch_fallthrough_clean_") -> None:
    import tempfile

    # return/throw-terminated clauses, grouped labels, loop breaks, terminal
    # default without break, and a documented fall-through are all fine.
    src = "\n".join([
        "export function classify(kind) {",
        "  switch (kind) {",
        '    case "a":',
        "      return 1;",
        '    case "b":',
        "      return 2;",
        '    case "c":',
        '    case "d":',
        "      return 34;",
        "    default:",
        "      throw new Error(`unknown kind: ${kind}`);",
        "  }",
        "}",
        "",
        "export function accumulate(mode, values) {",
        "  let total = 0;",
        "  switch (mode) {",
        '    case "sum":',
        "      for (const value of values) {",
        "        if (value < 0) break;",
        "        total += value;",
        "      }",
        "      break;",
        '    case "double":',
        "      total = values.length * 2;",
        "      // fall through",
        '    case "count":',
        "      total += values.length;",
        "      break;",
        "    default:",
        "      total = values.length;",
        "  }",
        "  return total;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_fallthrough_comment_variants_suppressed(tmp_prefix: str = "ubs_core_switch_fallthrough_comment_") -> None:
    import tempfile

    # FALLTHROUGH_RE is case-insensitive and allows whitespace/underscore/
    # hyphen separators between "fall" and "through".
    for marker in ("/* FALLS_THROUGH */", "// falls through", "/* Fall-Through */"):
        src = "\n".join([
            "function f(v) {",
            "  switch (v) {",
            '    case 1:',
            "      start();",
            "      " + marker,
            '    case 2:',
            "      break;",
            "  }",
            "}",
            "",
        ])
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "marked.js"
            target.write_text(src, encoding="utf-8")
            findings = list(scan_file_findings(target))
            assert findings == [], (marker, findings)


def _selftest_span_ignore_suppressed(tmp_prefix: str = "ubs_core_switch_fallthrough_ign_") -> None:
    import tempfile

    # ubs:ignore anywhere in the raw span from the flagged label through the
    # next label suppresses.
    for ignored_src in (
        "    case 1: // ubs:ignore",
        "      start(); // ubs:ignore",
    ):
        src = "\n".join([
            "function f(v) {",
            "  switch (v) {",
            ignored_src,
            "      start();",
            "    case 2:",
            "      break;",
            "  }",
            "}",
            "",
        ])
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "ignored.js"
            target.write_text(src, encoding="utf-8")
            findings = list(scan_file_findings(target))
            assert findings == [], (ignored_src, findings)


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_switch_fallthrough_run_") -> None:
    import tempfile

    src = "\n".join([
        "function f(v) {",
        "  switch (v) {",
        "    case 1:",
        "      start();",
        "    case 2:",
        "      break;",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "shape.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 3 and rec["col"] == 5, rec
        assert "missing break" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("fallthrough-flagged", _selftest_fallthrough_flagged),
    ("terminated-and-grouped-clean", _selftest_terminated_and_grouped_clean),
    ("fallthrough-comment-variants-suppressed", _selftest_fallthrough_comment_variants_suppressed),
    ("span-ignore-suppressed", _selftest_span_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="spec_switch_fallthrough", run=run, selftests=SELF_TESTS))
