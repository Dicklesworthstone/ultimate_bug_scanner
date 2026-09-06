"""ubs_core.elixir_detectors.response_header_injection — category 4 security.

Verbatim port of run_request_response_header_checks (modules/ubs-elixir.sh
1144-1502): request-derived values (conn/socket params, cookies, req headers,
upload filenames) reaching NON-Location response-header sinks
(put_resp_header/put_merge_resp_headers/put_resp_content_type) without a
safe-named helper, header encoding, CRLF stripping, or a CRLF-check +
reject context in the preceding 18 lines. `def` boundaries clear the taint
map; same-file and previous-line `ubs:ignore` markers suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.elixir_detectors._common import (
    EXTS,
    elixir_files,
    has_ignore,
    read_lines,
    source_line,
    strip_line_comments,
)

RULE_ID = "ex.header-injection.response"
CATEGORY = 4
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = (
    "Reject or strip CR/LF before writing request data to response headers; "
    "encode Content-Disposition filenames or use a header-safe helper."
)

VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
HEADER_KEY = r'(?:header|trace|name|file|filename|token|tenant|id|value|download|export|disposition|etag|cache|language|encoding|type)'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    rf'\b(?:conn|socket)\.(?:params|query_params|path_params|body_params|cookies|req_cookies)\s*(?:\[|\|>)|'
    rf'\bparams\s*(?:\[|\|>)|'
    rf'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.(?:params|query_params|path_params|body_params|cookies|req_cookies))\b|'
    rf'\bget_in\s*\(\s*(?:params|conn\.(?:params|query_params|path_params|body_params|cookies|req_cookies))\b|'
    rf'\b(?:conn|socket)\.(?:host|request_path|query_string)\b|'
    rf'\b(?:Plug\.Conn\.)?get_req_header\s*\(\s*(?:conn|socket)\s*,|'
    rf'\b(?:conn|socket)\s*\|>\s*(?:Plug\.Conn\.)?get_req_header\s*\(|'
    rf'\b[A-Za-z_][A-Za-z0-9_?!]*\.filename\b|'
    rf'%Plug\.Upload\{{[^}}]*filename\s*:',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|query_params|path_params|body_params|cookies|req_cookies)\b|\bparams\b|'
    r'\b(?:Plug\.Conn\.)?get_req_header\s*\(\s*(?:conn|socket)\s*,',
    re.IGNORECASE,
)
HEADERISH_NAME_RE = re.compile(HEADER_KEY, re.IGNORECASE)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_header(?:_value)?|safeHeader(?:Value)?|safe_response_header(?:_value)?|'
    r'sanitize_header(?:_value)?|sanitizeHeader(?:Value)?|sanitized_header(?:_value)?|'
    r'clean_header(?:_value)?|encode_header(?:_value)?|encoded_header(?:_value)?|'
    r'encoded_filename|safe_filename_for_header|safe_content_disposition_filename|'
    r'strip_crlf|remove_crlf|without_crlf|reject_crlf|valid_header_value\?|'
    r'is_header_value_safe\?|header_safe\?)\b',
    re.IGNORECASE,
)
ENCODING_RE = re.compile(r'\b(?:URI\.encode(?:_www_form)?|Base\.encode(?:16|32|64))\s*\(', re.IGNORECASE)
STRIP_RE = re.compile(
    r'\bString\.replace\s*\([^)]*(?:["\']\\[rn]["\']|~r/[^/]*\\[rn])|'
    r'\bRegex\.replace\s*\(\s*~r/[^/]*\\[rn]',
    re.IGNORECASE,
)
CRLF_CHECK_RE = re.compile(
    r'\\r|\\n|(?:\r|\n)|crlf|newline|'
    r'String\.contains\?\s*\([^)]*["\']\\[rn]["\']|'
    r'Regex\.match\?\s*\(\s*~r/[^/]*\\[rn]',
    re.IGNORECASE,
)
REJECT_RE = re.compile(r'(?:\b(?:raise|throw)\b|\{:error|\b(?:halt|send_resp)\s*\(|\bjson\s*\([^)]*\{:error)', re.IGNORECASE)
SINK_RE = re.compile(
    r'\b(?:Plug\.Conn\.)?put_resp_header\s*\(|'
    r'\|\>\s*(?:Plug\.Conn\.)?put_resp_header\s*\(|'
    r'\b(?:Plug\.Conn\.)?(?:put|merge)_resp_headers\s*\(|'
    r'\|\>\s*(?:Plug\.Conn\.)?(?:put|merge)_resp_headers\s*\(|'
    r'\b(?:Plug\.Conn\.)?put_resp_content_type\s*\(|'
    r'\|\>\s*(?:Plug\.Conn\.)?put_resp_content_type\s*\(',
    re.IGNORECASE,
)
PATH_LIMIT = 4


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 10:
        upcoming = strip_line_comments(lines[lookahead]).lstrip()
        if not upcoming:
            probe = lookahead + 1
            while probe < len(lines) and probe < idx + 10:
                upcoming = strip_line_comments(lines[probe]).lstrip()
                if upcoming:
                    break
                probe += 1
        if balance <= 0 and has_end and not upcoming.startswith('|>'):
            break
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
        lookahead += 1
    return statement


def identifier_search_text(expr: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escape:
                escape = False
                i += 1
                continue
            if ch == '\\':
                escape = True
                i += 1
                continue
            if ch == '#' and i + 1 < len(expr) and expr[i + 1] == '{':
                depth = 1
                j = i + 2
                interpolation = []
                while j < len(expr) and depth > 0:
                    current = expr[j]
                    if current == '{':
                        depth += 1
                    elif current == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    interpolation.append(current)
                    j += 1
                out.append(' ')
                out.append(''.join(interpolation))
                out.append(' ')
                i = j + 1
                continue
            if ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement) or ENCODING_RE.search(statement) or STRIP_RE.search(statement))


def has_request_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement):
        return True
    return bool(target_name and HEADERISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(statement))


def refs_in_statement(statement: str, tainted: dict[str, dict]):
    code_text = re.sub(r'\b[a-z_][A-Za-z0-9_?!]*\s*:', ' ', identifier_search_text(statement))
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', code_text)]


def has_non_location_header_sink(statement: str) -> bool:
    keys = []
    keys.extend(re.findall(r'put_resp_header\s*\([^,]+,\s*["\']([^"\']+)["\']', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\|\>\s*(?:Plug\.Conn\.)?put_resp_header\s*\(\s*["\']([^"\']+)["\']', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\{\s*["\']([^"\']+)["\']\s*,', statement))
    if re.search(r'put_resp_content_type\s*\(', statement, re.IGNORECASE):
        keys.append('content-type')
    if keys:
        return any(key.lower() != 'location' for key in keys)
    return True


def taint_from_statement(statement: str, tainted: dict[str, dict], target_name: str = ''):
    if is_safe_expression(statement):
        return None
    if has_request_source(statement, target_name):
        source = REQUEST_SOURCE_RE.search(statement)
        return {'path': [(source.group(0) if source else target_name or 'request value').strip()]}
    refs = refs_in_statement(statement, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no]]
    for ref in refs:
        ref_lines = [
            line for line in context_lines
            if re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line))
        ]
        if not ref_lines:
            continue
        if any(is_safe_expression(line) for line in ref_lines):
            return True
        for pos, line in enumerate(context_lines):
            if not re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line)):
                continue
            if not CRLF_CHECK_RE.search(line):
                continue
            reject_window = '\n'.join(context_lines[pos:pos + 5])
            if REJECT_RE.search(reject_window):
                return True
    return False


def scan_file_findings(path: Path) -> Iterable[tuple[int, int, str]]:
    lines = read_lines(path)
    if lines is None:
        return
    text = "\n".join(lines)
    if not (re.search(r'\b(?:conn|params|Plug\.Conn|query_params|cookies|req_cookies)\b', text) and SINK_RE.search(text)):
        return
    tainted: dict[str, dict] = {}
    seen: set[int] = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        if re.match(r'^\s*def(?:p|macro)?\b', statement):
            tainted.clear()

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_statement(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif is_safe_expression(rhs):
                tainted.pop(variable, None)
            else:
                tainted.pop(variable, None)

        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if not has_non_location_header_sink(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_request_source(statement)
        refs = refs_in_statement(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, idx, refs):
            continue
        if idx in seen:
            continue
        seen.add(idx)
        if direct:
            source = REQUEST_SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('response header')
            path_desc = ' -> '.join(seq)
        yield idx, 1, f"{source_line(lines, idx)}  [{path_desc}]"


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in elixir_files(files, EXTS):
        for line_no, col, code in scan_file_findings(path):
            yield str(path), line_no, col, code
