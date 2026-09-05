"""ubs_core.go_detectors.request_body_limit — category 8 filesystem (bead 0xjg.6).

Port of run_request_body_limit_checks (modules/ubs-golang.sh 5307-5501):
flags unbounded request-body reads — io/ioutil.ReadAll(r.Body) and
json.NewDecoder(<body>).Decode(...) directly or via a saved decoder
variable — plus ``body := r.Body`` aliases resolved back to their
request field. A read is suppressed when the surrounding context (up to
35 lines back to the enclosing ``func``, 10 forward) wraps the same body
value in http.MaxBytesReader or io.LimitReader. Alias and decoder maps
reset at each ``func`` boundary.

Unlike the sibling trackers, the ``ubs:ignore`` window here is three
lines: the hit line plus the two lines above it (idx-2..idx). Legacy
detail is the raw source line (strip, tabs→spaces) — not the
comment-stripped statement — and dedupe is per (file, line) inside each
file (legacy per-file ``seen`` set).

Legacy: ``print_finding warning $N "Request body read without explicit
byte limit" "Wrap request bodies with http.MaxBytesReader or
io.LimitReader before io.ReadAll/ioutil.ReadAll to prevent memory
exhaustion"``. The rglob/SKIP_DIRS traversal is replaced by the contract
file list; the v2 record count equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MARKER = "ubs:ignore"

RULE_ID = "go.filesystem.request-body-limit"
CATEGORY = 8
TITLE = "Request body read without explicit byte limit"
SEVERITY = "warning"
DESCRIPTION = ("Wrap request bodies with http.MaxBytesReader or io.LimitReader "
               "before io.ReadAll/ioutil.ReadAll to prevent memory exhaustion")

READALL_BODY_RE = re.compile(
    r'\b(?:io|ioutil)\.ReadAll\s*\(\s*(?P<body>[A-Za-z_][A-Za-z0-9_]*(?:\.Body)?)\s*\)'
)
JSON_DIRECT_BODY_RE = re.compile(
    r'\bjson\.NewDecoder\s*\(\s*(?P<body>[A-Za-z_][A-Za-z0-9_]*(?:\.Body)?)\s*\)'
    r'\s*\.\s*Decode\s*\('
)
JSON_DECODER_ASSIGN_RE = re.compile(
    r'\b(?P<decoder>[A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*'
    r'json\.NewDecoder\s*\(\s*(?P<body>[A-Za-z_][A-Za-z0-9_]*(?:\.Body)?)\s*\)'
)
JSON_DECODE_CALL_RE = re.compile(r'\b(?P<decoder>[A-Za-z_][A-Za-z0-9_]*)\.Decode\s*\(')
BODY_ALIAS_ASSIGN_RE = re.compile(
    r'\b(?:var\s+)?(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*'
    r'(?P<body>[A-Za-z_][A-Za-z0-9_]*\.Body)\b'
)


def _strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escaped = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ''
        if quote:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and nxt == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def _has_ignore(lines, idx):
    start = max(0, idx - 2)
    return any(MARKER in lines[pos] for pos in range(start, idx + 1))


def _context_around(lines, idx):
    start = idx
    while start > 0 and idx - start < 35:
        prior = _strip_line_comments(lines[start - 1]).strip()
        if prior.startswith('func ') or prior.startswith('func('):
            start -= 1
            break
        start -= 1
    end = min(len(lines), idx + 10)
    return '\n'.join(lines[start:end])


def _body_is_limited(context: str, body: str) -> bool:
    escaped = re.escape(body)
    return bool(
        re.search(rf'\b(?:http\.)?MaxBytesReader\s*\([^;\n]*\b{escaped}\b', context)
        or re.search(rf'\b(?:io\.)?LimitReader\s*\(\s*{escaped}\b', context)
    )


def _resolve_body(body_aliases, body: str) -> str | None:
    if '.Body' in body:
        return body
    return body_aliases.get(body)


def _add_issue(issues, seen, path: Path, idx: int, raw: str):
    key = (path, idx + 1)
    if key in seen:
        return
    seen.add(key)
    issues.append((path, idx + 1, 1, raw.strip().replace('\t', ' ')))


def _analyze(path: Path, issues: list) -> None:
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    seen = set()
    body_aliases = {}
    decoder_bodies = {}
    for idx, raw in enumerate(lines):
        if _has_ignore(lines, idx):
            continue
        stripped = _strip_line_comments(raw).strip()
        if not stripped:
            continue
        if stripped.startswith(('func ', 'func(', 'func (')):
            body_aliases.clear()
            decoder_bodies.clear()

        alias_assignment = BODY_ALIAS_ASSIGN_RE.search(stripped)
        if alias_assignment:
            body_aliases[alias_assignment.group('alias')] = alias_assignment.group('body')

        assignment = JSON_DECODER_ASSIGN_RE.search(stripped)
        if assignment:
            decoder_body = _resolve_body(body_aliases, assignment.group('body'))
            if decoder_body:
                decoder_bodies[assignment.group('decoder')] = (
                    decoder_body,
                    idx,
                    raw,
                )

        for match in (READALL_BODY_RE.search(stripped), JSON_DIRECT_BODY_RE.search(stripped)):
            if not match:
                continue
            body = _resolve_body(body_aliases, match.group('body'))
            if not body:
                continue
            context = _context_around(lines, idx)
            if _body_is_limited(context, body):
                continue
            _add_issue(issues, seen, path, idx, raw)

        decode_call = JSON_DECODE_CALL_RE.search(stripped)
        if not decode_call:
            continue
        decoder = decode_call.group('decoder')
        if decoder not in decoder_bodies:
            continue
        body, assignment_idx, assignment_raw = decoder_bodies[decoder]
        context = _context_around(lines, idx)
        if _body_is_limited(context, body):
            continue
        _add_issue(issues, seen, path, assignment_idx, assignment_raw)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
