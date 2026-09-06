"""ubs_core.elixir_detectors.outbound_url — category 4 security (bead 0xjg.13).

Verbatim port of run_request_outbound_url_checks (modules/ubs-elixir.sh
1504-1769): request-derived URL-ish values (params, query strings, headers,
conn host/request_path) reaching outbound HTTP client sinks (Req, HTTPoison,
HTTPotion, Finch, Tesla, :hackney, :httpc, Mint.HTTP.connect) without a
safe-named helper or a URI.parse + scheme/host allow-list + reject context in
the preceding 24 lines. Same-file and previous-line `ubs:ignore` markers
suppress a hit.
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

RULE_ID = "ex.ssrf.outbound-url"
CATEGORY = 4
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate outbound URLs with URI parsing plus explicit https scheme and "
    "host allow-lists before calling Req, HTTPoison, Finch, Tesla, hackney, "
    "Mint, or :httpc."
)

VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
URL_KEY = r'(?:url|uri|host|origin|callback|webhook|redirect|endpoint|target|remote|link|location|referer|referrer|next)'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    rf'\b(?:conn|socket)\.(?:params|query_params)\s*(?:\[|\|>)|'
    rf'\bparams\s*(?:\[|\|>)|'
    rf'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{URL_KEY}|'
    rf'\bget_in\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{URL_KEY}|'
    rf'\b(?:conn|socket)\.(?:host|request_path|query_string)\b|'
    rf'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,[^)]*{URL_KEY}|'
    rf'\|>\s*Plug\.Conn\.get_req_header\s*\([^)]*{URL_KEY}',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|query_params)\b|\bparams\b|'
    r'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,',
    re.IGNORECASE,
)
URLISH_NAME_RE = re.compile(URL_KEY, re.IGNORECASE)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_outbound_url|safeOutboundUrl|safe_outbound_uri|safeOutboundUri|'
    r'validate_outbound_url|validateOutboundUrl|validated_outbound_url|validatedOutboundUrl|'
    r'allowed_outbound_url|allowedOutboundUrl|allowlisted_url|allowlistedUrl|'
    r'trusted_url|trustedUrl|sanitize_url|sanitizeUrl|sanitize_uri|sanitizeUri|'
    r'resolve_allowed_url|resolveAllowedUrl|require_allowed_host|requireAllowedHost|'
    r'allowed_host\?|allowedHost\?|ensure_allowed_host|ensureAllowedHost)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bReq\.(?:get!?|post!?|put!?|patch!?|delete!?|request!?)\s*\(|'
    r'\bHTTPoison\.(?:get!?|post!?|put!?|patch!?|delete!?|request!?)\s*\(|'
    r'\bHTTPotion\.(?:get|post|put|patch|delete|request)\s*\(|'
    r'\bFinch\.build\s*\(|'
    r'\bTesla\.(?:get|post|put|patch|delete|request)\s*\(|'
    r'(?<![A-Za-z0-9_]):hackney\.(?:get|post|put|patch|delete|request)\s*\(|'
    r'(?<![A-Za-z0-9_]):httpc\.request\s*\(|'
    r'\bMint\.HTTP\.connect\s*\(',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:URI\.parse|URI\.new!?)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:scheme|host)\b|'
    r'\b(?:allowed_hosts|allowed_host|host_allowlist|trusted_hosts|@allowed_hosts)\b|'
    r'\b(?:MapSet\.member\?|Enum\.member\?|String\.starts_with\?)\s*\(|'
    r'\bin\s+@?allowed_hosts\b|'
    r'==\s*"https"',
    re.IGNORECASE,
)
REJECT_RE = re.compile(r'(?:\b(?:raise|throw)\b|\{:error|\b(?:halt|send_resp)\s*\(|\bjson\s*\([^)]*\{:error)', re.IGNORECASE)
PATH_LIMIT = 4


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0
        lookahead += 1
    return statement


def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement))


def has_request_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement) and (URLISH_NAME_RE.search(statement) or re.search(r'\b(?:conn|socket)\.(?:host|request_path|query_string)\b', statement)):
        return True
    return bool(target_name and URLISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(statement))


def refs_in_statement(statement: str, tainted: dict[str, dict]):
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', statement)]


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


def has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_NAMED_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))


def scan_file_findings(path: Path) -> Iterable[tuple[int, int, str]]:
    lines = read_lines(path)
    if lines is None:
        return
    text = "\n".join(lines)
    if not (re.search(r'\b(?:conn|params|Plug\.Conn|query_params)\b', text) and SINK_RE.search(text)):
        return
    tainted: dict[str, dict] = {}
    seen: set[int] = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_statement(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif is_safe_expression(rhs):
                tainted.pop(variable, None)

        if not SINK_RE.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_request_source(statement)
        refs = refs_in_statement(statement, tainted)
        if not direct and not refs:
            continue
        if has_allowlist_context(lines, idx, refs):
            continue
        if idx in seen:
            continue
        seen.add(idx)
        if direct:
            source = REQUEST_SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> outbound HTTP"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('outbound HTTP')
            path_desc = ' -> '.join(seq)
        yield idx, 1, f"{source_line(lines, idx)}  [{path_desc}]"


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in elixir_files(files, EXTS):
        for line_no, col, code in scan_file_findings(path):
            yield str(path), line_no, col, code
