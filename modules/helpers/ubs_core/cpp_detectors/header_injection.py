"""ubs_core.cpp_detectors.header_injection — category 7 CRLF/header taint (bead 0xjg.9).

Verbatim port of the run_response_header_checks heredoc
(modules/ubs-cpp.sh 1829-2145). Critical: "Request-controlled value reaches
HTTP response header".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "cpp.detector.header-injection"
CATEGORY = 7
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = ("Reject or strip CR/LF before writing request data to response "
               "headers; encode Content-Disposition filenames or use a "
               "header-safe helper.")

SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|header|cookie|cookies|'
    r'getCookie|get_cookie|getHost|get_host|host|target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:headers|cookies|host|target|raw_url|url)\b'
    r'|\b(?:FCGX_GetParam)\s*\('
    r'|\bgetenv\s*\(\s*"(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_COOKIE|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
CGI_FORM_OUT_RE = re.compile(
    r'\bcgiFormString\s*\(\s*[^,]+,\s*(?:&\s*)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*,'
)
HEADERISH_NAME_RE = re.compile(
    r'(header|trace|name|file|filename|token|tenant|id|value|download|export|disposition|etag|cache|language|encoding|type|cookie)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:HeaderValue|Header|ResponseHeader|ResponseHeaderValue|ContentDispositionFilename)|'
    r'safe_(?:header_value|header|response_header|response_header_value|content_disposition_filename)|'
    r'sanitize(?:HeaderValue|Header|ResponseHeader|ResponseHeaderValue)|'
    r'sanitize_(?:header_value|header|response_header|response_header_value)|'
    r'clean(?:HeaderValue|Header|ResponseHeader)|clean_(?:header_value|header|response_header)|'
    r'encode(?:HeaderValue|Header|ResponseHeader|Filename)|encoded(?:HeaderValue|Header|Filename)|'
    r'encode_(?:header_value|header|response_header|filename)|encoded_(?:header_value|header|filename)|'
    r'url_encode|uri_encode|percent_encode|base64_encode|strip_crlf|remove_crlf|without_crlf|reject_crlf|'
    r'validate(?:HeaderValue|Header)|validate_(?:header_value|header)|isSafeHeaderValue|is_safe_header_value|'
    r'isHeaderValueSafe|is_header_value_safe)\b'
    r'|\b(?:std::regex_replace|boost::algorithm::erase_all|boost::algorithm::replace_all)\s*\(',
    re.IGNORECASE,
)
STRIP_RE = re.compile(
    r'\.\s*(?:erase|replace)\s*\([^;\n]*(?:[\'"]\\[rn][\'"]|CR|LF|crlf|newline)',
    re.IGNORECASE,
)
CRLF_CHECK_RE = re.compile(
    r'\\r|\\n|crlf|newline|'
    r'\.\s*(?:find|contains)\s*\([^;\n]*(?:[\'"]\\[rn][\'"]|CR|LF)|'
    r'(?:std::regex_search|std::regex_match|boost::regex_search)\s*\([^;\n]*(?:\\[rn]|crlf|newline)',
    re.IGNORECASE,
)
REJECT_RE = re.compile(
    r'\b(?:throw|return\s+false|return\s+\{\}|abort|forbid|deny|bad_request|invalid_argument|runtime_error|domain_error)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:set_header|setHeader|add_header|addHeader|append_header|appendHeader|write_header|writeHeader|'
    r'send_header|sendHeader|header|set)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:set_header|setHeader|add_header|addHeader|append_header|appendHeader|'
    r'write_header|writeHeader|send_header|sendHeader|header|set|insert|emplace)\s*\('
    r'|\b(?:set_content_type|setContentType|content_type|contentType)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:set_content_type|setContentType|content_type|contentType)\s*\('
    r'|\b(?:headers|response_headers|resp_headers)\s*\[\s*["\'][^"\']+["\']\s*\]\s*='
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:headers|response_headers|resp_headers)\s*\[\s*["\'][^"\']+["\']\s*\]\s*='
    r'|\b(?:printf|fprintf|snprintf|FCGX_FPrintF|mg_printf|mg_send|send|write)\s*\([^;\n]*(?:["\'][A-Za-z0-9_-]+:\s*%s|["\'][A-Za-z0-9_-]+:\s*)',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(
    r'^\s*(?:const\s+)?(?:auto|std::string(?:_view)?|string(?:_view)?|'
    r'QString|char\s*(?:const\s*)?\*|const\s+char\s*\*)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
PATH_LIMIT = 4


def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = ';' in statement or '{' in statement or '}' in statement
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line
        lookahead += 1
    return statement


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def identifier_search_text(expr):
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
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


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr) or STRIP_RE.search(expr))


def refs_in_expr(expr, tainted):
    code = identifier_search_text(expr)
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', code):
            refs.append(name)
    return refs


def has_request_source(expr, target_name=''):
    if SOURCE_RE.search(expr):
        return True
    return bool(target_name and HEADERISH_NAME_RE.search(target_name) and re.search(r'\b(?:req|request|headers|cookies|getenv|cgiFormString)\b', expr, re.IGNORECASE))


def taint_from_expr(expr, tainted, target_name=''):
    if is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct and has_request_source(expr, target_name):
        return {'path': [direct.group(0).strip('(')]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_non_location_header_sink(statement):
    keys = []
    keys.extend(re.findall(r'(?:set_header|setHeader|add_header|addHeader|append_header|appendHeader|write_header|writeHeader|send_header|sendHeader|header|set)\s*\(\s*["\']([^"\']+)["\']', statement, re.IGNORECASE))
    keys.extend(re.findall(r'(?:set|insert|emplace)\s*\(\s*(?:boost::beast::http::field::|http::field::)([A-Za-z_][A-Za-z0-9_]*)', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\[\s*["\']([^"\']+)["\']\s*\]\s*=', statement))
    keys.extend(re.findall(r'\{\s*["\']([^"\']+)["\']\s*,', statement))
    keys.extend(re.findall(r'["\']([A-Za-z0-9_-]+):\s*%s', statement))
    keys.extend(re.findall(r'["\']([A-Za-z0-9_-]+):\s*["\']', statement))
    if re.search(r'(?:set_content_type|setContentType|content_type|contentType)\s*\(', statement, re.IGNORECASE):
        keys.append('content-type')
    if keys:
        return any(key.lower().replace('_', '-') != 'location' for key in keys)
    return True


def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no]]
    for ref in refs:
        ref_lines = [
            line for line in context_lines
            if re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line))
        ]
        if not ref_lines:
            continue
        if any(is_safe_expr(line) for line in ref_lines):
            return True
        for pos, line in enumerate(context_lines):
            if not re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line)):
                continue
            if not CRLF_CHECK_RE.search(line):
                continue
            reject_window = '\n'.join(context_lines[pos:pos + 6])
            if REJECT_RE.search(reject_window):
                return True
    return False


def analyze(path: Path, cwd: Path) -> list[tuple[str, int, str]]:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
        return []
    lines = text.splitlines()
    tainted = {}
    try:
        rel = str(path.resolve().relative_to(cwd))
    except ValueError:
        rel = path.name
    seen = set()
    issues = []
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        cgi_out = CGI_FORM_OUT_RE.search(statement)
        if cgi_out:
            name = cgi_out.group('lhs')
            tainted[name] = {'path': [f"cgiFormString(..., {name}, ...)"]}
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            taint = taint_from_expr(rhs, tainted, name)
            if taint:
                tainted[name] = taint
            else:
                tainted.pop(name, None)
        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if not has_non_location_header_sink(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = SOURCE_RE.search(statement) and has_request_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, idx, refs):
            continue
        key = (rel, idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip('(')} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('response header')
            path_desc = ' -> '.join(seq)
        issues.append((rel, idx, f"{source_line(lines, idx)}  [{path_desc}]"))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in EXTS:
            continue
        for rel, line_no, code in analyze(path, cwd):
            yield rel, line_no, 1, code
