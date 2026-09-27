"""ubs_core.analyzers.sec_fetch_abort — fetch() without AbortSignal cancellation
(bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "fetch without AbortSignal
cancellation": same regexes, same two-pass safe-variable collection, same
14-line statement window with the fetch_start/new Request/'=' saw_open rule,
same ubs:ignore placement rules (the marker must survive code_line() inside
the collected call text — the heredoc tests the comment-stripped statement).
The heredoc's os.walk over the project is replaced by iteration over
RunContext.files; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}

RULE = "js.security.fetch-abort"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "fetch() without AbortSignal cancellation"

fetch_start_re = re.compile(r'(?<![\w$.])(?:(?:window|globalThis)\s*(?:\?\s*)?\.\s*)?fetch\s*\(')
# A formatter may break `window.fetch(` after the receiver (GH #148):
#     return window
#       .fetch(url)
# The continuation line alone looks like a method call on an unknown object.
continued_fetch_re = re.compile(r'^(\s*)((?:\?\s*)?\.\s*fetch\s*\()')
global_receiver_tail_re = re.compile(r'(?<![\w$.])(window|globalThis)\s*$')
definition_re = re.compile(r'^\s*(?:export\s+)?(?:async\s+)?function\s+fetch\s*\(|^\s*declare\s+function\s+fetch\s*\(')
assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
identifier_re = re.compile(r'^([A-Za-z_$][A-Za-z0-9_$]*)\b')
signal_property_re = re.compile(r'\bsignal\s*:')
signal_shorthand_re = re.compile(r'[{,]\s*signal\s*(?:[,}])')


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def join_global_receivers(lines):
    """Re-attach a `window`/`globalThis` receiver that ends the previous code
    line to a line starting with `.fetch(`, so the call is seen whole. Line
    count and numbering are preserved; only the continuation line changes."""
    joined = list(lines)
    previous_code = ""
    for idx, line in enumerate(lines):
        current = code_line(line)
        if not current.strip():
            continue
        continuation = continued_fetch_re.match(current)
        receiver = global_receiver_tail_re.search(previous_code) if continuation else None
        if receiver:
            joined[idx] = continuation.group(1) + receiver.group(1) + current[continuation.start(2):]
        previous_code = current
    return joined


def statement_from(lines, idx, max_lines=14):
    parts = []
    paren_balance = 0
    saw_open = False
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = code_line(lines[line_idx]).strip()
        if not current:
            continue
        parts.append(current)
        if fetch_start_re.search(current) or 'new Request' in current or '=' in current:
            saw_open = True
        if saw_open:
            paren_balance += current.count('(') - current.count(')')
        if line_idx > idx and paren_balance <= 0:
            break
        if ';' in current and paren_balance <= 0:
            break
    return ' '.join(parts)


def has_signal_option(text):
    return bool(signal_property_re.search(text) or signal_shorthand_re.search(text))


def extract_fetch_args(call_text):
    match = fetch_start_re.search(call_text)
    if not match:
        return ""
    start = match.end()
    depth = 1
    quote = ""
    escaped = False
    for pos in range(start, len(call_text)):
        ch = call_text[pos]
        if quote:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return call_text[start:pos]
    return call_text[start:]


def split_top_level_args(args_text):
    args = []
    current = []
    depth = 0
    quote = ""
    escaped = False
    for ch in args_text:
        if quote:
            current.append(ch)
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            current.append(ch)
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        args.append(tail)
    return args


def leading_identifier(arg):
    match = identifier_re.match(arg.strip())
    return match.group(1) if match else ""


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line, sample_text) per detection; logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    lines = join_global_receivers(lines)

    safe_init_vars = set()
    safe_request_vars = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped:
            continue
        assignment = assignment_re.search(stripped)
        if assignment:
            statement = statement_from(lines, idx)
            name = assignment.group(1)
            if 'new Request' in statement and has_signal_option(statement):
                safe_request_vars.add(name)
            elif has_signal_option(statement):
                safe_init_vars.add(name)

    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or definition_re.search(stripped) or not fetch_start_re.search(stripped):
            continue
        call_text = statement_from(lines, idx)
        if 'ubs:ignore' in call_text:
            continue
        args = split_top_level_args(extract_fetch_args(call_text))
        first_arg = args[0] if args else ""
        options_arg = args[1] if len(args) > 1 else ""
        first_ident = leading_identifier(first_arg)
        options_ident = leading_identifier(options_arg)
        if options_arg and (has_signal_option(options_arg) or options_ident in safe_init_vars):
            continue
        if first_ident in safe_request_vars:
            continue
        if first_arg.startswith('new Request') and has_signal_option(first_arg):
            continue
        yield idx + 1, stripped.replace('\t', ' ')


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        rel = path.resolve()
        for line, _sample in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_bare_fetch_flagged(tmp_prefix: str = "ubs_core_sec_fetch_abort_") -> None:
    import tempfile

    src = "\n".join([
        "export async function loadUser(userId: string) {",
        "  const response = await fetch(`/api/users/${userId}`);",
        "  return response.json();",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "client.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 2, findings


def _selftest_signal_wiring_clean(tmp_prefix: str = "ubs_core_sec_fetch_abort_signal_") -> None:
    import tempfile

    # Direct option, AbortSignal shorthand object, and shared RequestInit all suppress.
    src = "\n".join([
        "export async function a(signal: AbortSignal) {",
        "  return fetch('/api/a', { signal });",
        "}",
        "export function b() {",
        "  return fetch('/api/b', { signal: AbortSignal.timeout(5000) });",
        "}",
        "export function c() {",
        "  const requestInit: RequestInit = { signal: AbortSignal.timeout(3000) };",
        "  return window.fetch('/api/c', requestInit);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "client.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_wrapped_global_receiver(tmp_prefix: str = "ubs_core_sec_fetch_abort_wrap_") -> None:
    import tempfile

    # GH #148: a formatter breaks the chain after the global receiver.
    src = "\n".join([
        "export function a(id: string) {",          # 1
        "  return window",                          # 2
        "    .fetch(`/api/${id}`)",                 # 3  flagged
        "    .then((r) => r.text());",              # 4
        "}",                                        # 5
        "export function b() {",                    # 6
        "  return globalThis // comment",           # 7
        "",                                         # 8
        "    ?.fetch('/api/b');",                   # 9  flagged
        "}",                                        # 10
        "export function c(signal: AbortSignal) {", # 11
        "  return window",                          # 12
        "    .fetch('/api/c', { signal })",         # 13 has signal
        "    .then((r) => r.text());",              # 14
        "}",                                        # 15
        "export function d(controller: AbortController) {",  # 16
        "  return window",                          # 17
        "    .fetch('/api/d', {",                   # 18
        "      method: 'POST',",                    # 19
        "      signal: controller.signal,",         # 20 multi-line options
        "    });",                                  # 21
        "}",                                        # 22
        "export function e(api: Client) {",         # 23
        "  return api",                             # 24
        "    .fetch('/api/e');",                    # 25 method on a client
        "}",                                        # 26
        "export function f(x: Wrapper) {",          # 27
        "  return x.window",                        # 28
        "    .fetch('/api/f');",                    # 29 not the global
        "}",                                        # 30
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "client.ts"
        target.write_text(src, encoding="utf-8")
        lines = [line for line, _sample in scan_file_findings(target)]
        assert lines == [3, 9], lines


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_fetch_abort_run_") -> None:
    import tempfile

    src = "await fetch('/api/x');\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "client.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1, rec
        assert rec["message"] == MESSAGE, rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("bare-fetch-flagged", _selftest_bare_fetch_flagged),
    ("signal-wiring-clean", _selftest_signal_wiring_clean),
    ("wrapped-global-receiver", _selftest_wrapped_global_receiver),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_fetch_abort", run=run, selftests=SELF_TESTS))
