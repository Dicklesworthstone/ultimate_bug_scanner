"""ubs_core.cpp_detectors.outbound_url — category 7 SSRF taint (bead 0xjg.9).

Verbatim port of the run_outbound_url_checks heredoc
(modules/ubs-cpp.sh 2172-2411). Critical: "Request-derived URL reaches
outbound HTTP client".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "cpp.detector.outbound-url"
CATEGORY = 7
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = ("Validate outbound URLs with explicit scheme and host "
               "allow-lists before configuring or sending client requests")

SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|getHost|get_host|host|'
    r'target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:host|target|raw_url|url)\b'
    r'|\b(?:cgiFormString|FCGX_GetParam)\s*\('
    r'|\bgetenv\s*\(\s*"(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
CGI_FORM_OUT_RE = re.compile(
    r'\bcgiFormString\s*\(\s*[^,]+,\s*(?:&\s*)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*,'
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:URL|Url|Uri|URI|OutboundURL|OutboundUrl|OutboundURI|WebhookURL|CallbackURL|HttpURL)|'
    r'safe_(?:url|uri|outbound_url|webhook_url|callback_url|http_url)|'
    r'secure(?:URL|Url|Uri|URI|OutboundURL|WebhookURL|CallbackURL)|'
    r'secure_(?:url|uri|outbound_url|webhook_url|callback_url)|'
    r'allow(?:URL|Url|Uri|URI|Host|OutboundURL)|allowed(?:URL|Url|Uri|URI|Host|OutboundURL)|'
    r'validate(?:URL|Url|Uri|URI|Host|OutboundURL|WebhookURL|CallbackURL)|'
    r'validate_(?:url|uri|host|outbound_url|webhook_url|callback_url)|'
    r'sanitize(?:URL|Url|Uri|URI|OutboundURL)|sanitize_(?:url|uri|outbound_url)|'
    r'isAllowedHost|is_allowed_host|isSafeURL|isSafeUrl|is_safe_url)\b',
    re.IGNORECASE,
)
URL_PARSE_RE = re.compile(r'\b(?:Poco::URI|QUrl|ada::parse|boost::urls::parse_uri|boost::urls::url_view|curl_url)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\b(?:allowedHosts|allowed_hosts|allowlist|hostAllowlist|host_allowlist|trustedHosts|trusted_hosts|isAllowedHost|is_allowed_host)\b'
    r'|\.\s*(?:host|scheme|getHost|getScheme|isValid)\s*\('
    r'|\b(?:starts_with|rfind|compare)\s*\([^;\n]*https://'
)
REJECT_RE = re.compile(
    r'\b(?:throw|return\s+false|return\s+\{\}|abort|forbid|deny|invalid_argument|runtime_error|domain_error)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bcurl_easy_setopt\s*\([^;\n]*\bCURLOPT_URL\b'
    r'|\bcurl_url_set\s*\([^;\n]*\bCURLUPART_URL\b'
    r'|\b(?:cpr::(?:Get|Post|Put|Delete|Patch|Head|Options)|QNetworkRequest|Poco::URI|QUrl)\s*\('
    r'|\b(?:httplib::Client|httplib::SSLClient|Poco::Net::HTTPClientSession)\s*\('
    r'|\b(?:client|httpClient|http_client|restClient|rest_client|webClient|web_client|session|request|manager|'
    r'[A-Za-z_][A-Za-z0-9_]*(?:Client|Http|HTTP|Rest|Web|Session|Request|Curl)[A-Za-z0-9_]*)(?:\.|->)'
    r'(?:Get|Post|Put|Patch|Delete|Head|get|post|put|patch|delete|head|request|send|setUrl|openUrl)\s*\(',
)
ASSIGN_RE = re.compile(
    r'^\s*(?:const\s+)?(?:auto|std::string(?:_view)?|string(?:_view)?|'
    r'QUrl|Poco::URI|boost::urls::url(?:_view)?|char\s*(?:const\s*)?\*|const\s+char\s*\*)?\s*'
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
    balance = statement.count('(') - statement.count(')')
    has_end = ';' in statement or '{' in statement or '}' in statement
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line
        lookahead += 1
    return statement


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def taint_from_expr(expr, tainted):
    if is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct:
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


def has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URL_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))


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
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = SOURCE_RE.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_allowlist_context(lines, idx, refs):
            continue
        key = (rel, idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> outbound HTTP"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('outbound HTTP')
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
