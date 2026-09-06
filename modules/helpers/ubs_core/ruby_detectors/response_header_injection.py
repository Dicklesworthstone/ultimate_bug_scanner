"""ubs_core.ruby_detectors.response_header_injection — category 6 security (bead 0xjg.10).

Port of run_response_header_injection_checks (modules/ubs-ruby.sh 1305-1626):
a line tracker that taints names assigned from request sources (params,
cookies, request accessors, Rack env values), then flags NON-Location
response-header writes whose value is request-derived. CR/LF stripping or
checking helpers, encoded-filename helpers, header-safe escapes, and a
CR/LF check followed by a reject (raise/head :bad_request/render status:)
within 5 lines suppress the hit. Same-file and previous-line `ubs:ignore`
markers suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.ruby_detectors._common import (
    EXTS,
    has_ignore,
    identifier_search_text,
    logical_statement,
    read_lines,
    ruby_files,
    source_line,
    strip_line_comments,
    word_regex,
)

RULE_ID = "ruby.header-injection.response"
CATEGORY = 6
TITLE = "Request-derived value reaches response header"
SEVERITY = "critical"
DESCRIPTION = (
    "Reject or strip CR/LF before writing request data to response headers; "
    "use encoded filenames or a header-safe helper for Content-Disposition values"
)

SOURCE_RE = re.compile(
    r'\b(?:params|request\.params)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:cookies|request\.cookies)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:path|path_info|fullpath|original_fullpath|query_string|url|'
    r'referer|referrer|host|host_with_port|raw_host_with_port|domain|subdomain|subdomains|remote_ip|ip)\b'
    r'|\b(?:request|req|rack_request)\.(?:get|post|params|query|POST|GET|headers)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.get_header\s*\('
    r'|\b(?:env|request\.env)\s*\[\s*[\'"](?:REQUEST_URI|QUERY_STRING|HTTP_REFERER|HTTP_ORIGIN|HTTP_HOST|HTTP_X_FORWARDED_HOST|HTTP_[A-Z0-9_]+)[\'"]\s*\]'
    r'|\bRack::Request\.new\s*\([^)]*\)\.params\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:_header|_header_value|_response_header|Header|HeaderValue|ResponseHeader)|'
    r'sanitize(?:_header|_header_value|_response_header|Header|HeaderValue|ResponseHeader)|'
    r'clean(?:_header|_header_value|Header|HeaderValue)|'
    r'encode(?:_header|_header_value|_filename|Header|HeaderValue|Filename)|'
    r'header_safe|header_value_safe|strip_crlf|remove_crlf|reject_crlf|without_crlf|valid_header_value\?)\b'
    r'|\b(?:CGI|Rack::Utils)\.(?:escape|escape_path|escape_html)\s*\('
    r'|\bERB::Util\.(?:url_encode|html_escape|html_escape_once)\s*\('
    r'|\bURI\.encode_www_form_component\s*\('
    r'|\.(?:delete|tr)\s*\(\s*[\'"][^\'"]*(?:\\r|\\n)[^\'"]*[\'"]'
    r'|\.gsub\s*\(\s*/[^/\n]*(?:\\r|\\n|\[:cntrl:\])',
    re.IGNORECASE,
)
CRLF_CHECK_RE = re.compile(
    r'(?:\\r|\\n|\[:cntrl:\]|CRLF|newline|newlines)'
    r'|\.include\?\s*\(\s*[\'"]\\[rn][\'"]\s*\)'
    r'|\.match\?\s*\(\s*/[^/\n]*(?:\\r|\\n|\[:cntrl:\])'
    r'|=~\s*/[^/\n]*(?:\\r|\\n|\[:cntrl:\])',
    re.IGNORECASE,
)
REJECT_RE = re.compile(
    r'\b(?:raise|fail|return\s+false|return\s+nil|halt|head\s+:bad_request|head\s+:forbidden|bad_request|forbidden|render\s+status:)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:response\.headers|headers|response)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*='
    r'|\b(?:response\.headers|headers|response)\.(?:\[\]=|store|set|merge!?|update)\s*\('
    r'|\bresponse\.set_header\s*\('
    r'|\bheaders\.set\s*\('
    r'|\bsend_(?:data|file)\b[^#\n]*\bfilename:',
    re.IGNORECASE,
)
LOCATION_SINK_RE = re.compile(
    r'\[\s*[\'"]Location[\'"]\s*\]\s*='
    r'|\.(?:\[\]=|store|set)\s*\(\s*[\'"]Location[\'"]'
    r'|set_header\s*\(\s*[\'"]Location[\'"]'
    r'|[\'"]Location[\'"]\s*=>',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(r'^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$')
PATH_LIMIT = 4


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    code_text = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\s*:', " ", identifier_search_text(expr))
    for name in tainted:
        if word_regex(name).search(code_text):
            refs.append(name)
    return refs


def taint_from_expr(expr, tainted):
    if is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct:
        return {"path": [direct.group(0).strip("(")]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get("path", [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {"path": path}


def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no]]
    for ref in refs:
        ref_lines = [
            line for line in context_lines
            if word_regex(ref).search(identifier_search_text(line))
        ]
        if not ref_lines:
            continue
        if any(SAFE_EXPR_RE.search(line) for line in ref_lines):
            return True
        for pos, line in enumerate(context_lines):
            if not word_regex(ref).search(identifier_search_text(line)):
                continue
            if not CRLF_CHECK_RE.search(line):
                continue
            reject_window = "\n".join(context_lines[pos:pos + 5])
            if REJECT_RE.search(reject_window):
                return True
    return False


def analyze(lines, issues, path_str):
    if not lines:
        return
    text = "\n".join(lines)
    if not (re.search(r'\b(?:params|request|env|Rack::Request|cookies)\b', text) and SINK_RE.search(text)):
        return
    tainted = {}
    seen = set()
    for idx in range(1, len(lines) + 1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        if re.match(r'^\s*def\b', statement):
            tainted.clear()
            continue
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not SINK_RE.search(statement) or LOCATION_SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = SOURCE_RE.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, idx, refs):
            continue
        key = (path_str, idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get("path", [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append("response header")
            path_desc = " -> ".join(seq)
        issues.append((path_str, idx, 1, f"{source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        issues: list[tuple] = []
        analyze(lines, issues, str(path))
        yield from issues
