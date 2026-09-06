"""swift_detectors.outbound_url — cat 6 "Request-derived outbound HTTP URLs" (SSRF).

Verbatim port of the run_request_outbound_url_checks heredoc in
modules/ubs-swift.sh. The legacy shell aggregated the heredoc's output into
ONE critical finding whose description embeds the first three samples.
"""
from __future__ import annotations

import re
from pathlib import Path

from ubs_core.swift_detectors._common import (
    SKIP_DIRS, has_ignore, iter_swift_files, logical_statement, rel,
    source_line, strip_line_comments,
)

RULE_ID = "swift.taint.outbound-url"
CATEGORY = 6
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
PATH_LIMIT = 4

name_re = r'[A-Za-z_][A-Za-z0-9_]*'
assign_re = re.compile(rf'\b(?:let|var)\s+({name_re})\s*(?::[^=]+)?=\s*(.+)')
url_key = r'(?:url|uri|host|origin|callback|webhook|redirect|endpoint|target|remote|link|location|referer|referrer)'
request_source = re.compile(
    rf'\b(?:req|request)\s*\.\s*(?:query|parameters|params)\s*(?:\[[^\]]*{url_key}[^\]]*\]|\.\s*get\s*\([^)]*{url_key}[^)]*\))|'
    rf'\b(?:req|request)\s*\.\s*headers\s*(?:\[[^\]]*{url_key}[^\]]*\]|\.\s*first\s*\([^)]*{url_key}[^)]*\)|\.\s*get\s*\([^)]*{url_key}[^)]*\))|'
    r'\b(?:req|request)\s*\.\s*(?:url|uri)\s*(?:\.\s*(?:string|absoluteString|description|host|path|query))?\b|'
    rf'\b(?:req|request)\s*\.\s*content\s*\.\s*get\s*\([^)]*\bat\s*:\s*["\'][^"\']*{url_key}[^"\']*["\']',
    re.IGNORECASE,
)
request_collection_source = re.compile(
    r'\b(?:req|request)\s*\.\s*(?:query|parameters|params|headers)\b(?:\s*\[[^\]]+\]|\s*\.\s*(?:get|first)\s*\([^)]*\))?',
    re.IGNORECASE,
)
content_source = re.compile(r'\b(?:req|request)\s*\.\s*content\b')
urlish_name = re.compile(r'(url|uri|host|origin|callback|webhook|redirect|endpoint|target|remote|link)', re.IGNORECASE)
safe_named = re.compile(
    r'\b(?:safe(?:Outbound)?URL|safeURL|safeURI|validated(?:Outbound)?URL|validate(?:Outbound)?URL|'
    r'allowed(?:Outbound)?URL|allowlistedURL|trustedURL|sanitizeURL|sanitizeURI|'
    r'resolveAllowedURL|requireAllowedHost|isAllowedHost|allowedHost)\b',
    re.IGNORECASE,
)
url_parse_re = re.compile(r'\b(?:URL|URLComponents)\s*\(\s*(?:string\s*:)?')
host_check_re = re.compile(
    r'\.(?:scheme|host)\b|'
    r'\b(?:allowedHosts|allowedHost|hostAllowlist|trustedHosts|ALLOWED_HOSTS)\b|'
    r'\.contains\s*\('
)
reject_re = re.compile(r'\b(?:throw|return(?:\s+(?:nil|false))?|abort|preconditionFailure)\b')
sink_re = re.compile(
    r'\bURLSession(?:\s*\.\s*shared)?\s*\.\s*(?:dataTask|downloadTask|uploadTask|streamTask|webSocketTask|data|bytes|download)\s*\(|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:dataTask|downloadTask|uploadTask|streamTask|webSocketTask)\s*\(|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:data|bytes|download)\s*\(\s*(?:from|for)\s*:|'
    r'\b(?:Data|String)\s*\(\s*contentsOf\s*:|'
    r'\b(?:AF|Alamofire)\s*\.\s*request\s*\(|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:get|post|put|patch|delete|fetch|request)\s*\(\s*(?:url\s*:|with\s*:|URLRequest)'
)


def is_safe_expression(statement: str) -> bool:
    return bool(safe_named.search(statement))


def has_source(statement: str, target_name: str = '') -> bool:
    if request_source.search(statement):
        return True
    if target_name and urlish_name.search(target_name) and request_collection_source.search(statement):
        return True
    return bool(target_name and urlish_name.search(target_name) and content_source.search(statement))


def refs_in_expr(expr: str, tainted: dict) -> list:
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def taint_from_expr(expr: str, tainted: dict, target_name: str = ''):
    if is_safe_expression(expr):
        return None
    direct = has_source(expr, target_name)
    if direct:
        source = request_source.search(expr)
        return {'path': [(source.group(0) if source else target_name or 'request content').strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_allowlist_context(lines: list[str], line_no: int, refs: list) -> bool:
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if safe_named.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(url_parse_re.search(context) and host_check_re.search(context) and reject_re.search(context))


def scan(ctx):
    project = ctx.project_dir
    root = project.resolve()
    base = root if root.is_dir() else root.parent
    findings = []
    for path in iter_swift_files(root, base, SKIP_DIRS):
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        if not (re.search(r'\b(?:req|request)\b', text) and sink_re.search(text)):
            continue

        lines = text.splitlines()
        tainted = {}
        seen = set()
        for line_no in range(1, len(lines) + 1):
            if has_ignore(lines, line_no):
                continue
            statement = logical_statement(lines, line_no).strip()
            if not statement:
                continue

            assignment = assign_re.search(statement)
            if assignment:
                variable, rhs = assignment.group(1), assignment.group(2)
                taint = taint_from_expr(rhs, tainted, variable)
                if taint:
                    tainted[variable] = taint
                elif variable in tainted and is_safe_expression(rhs):
                    tainted.pop(variable, None)

            if not sink_re.search(statement):
                continue
            if is_safe_expression(statement):
                continue
            direct = has_source(statement)
            refs = refs_in_expr(statement, tainted)
            if not direct and not refs:
                continue
            if has_allowlist_context(lines, line_no, refs):
                continue
            key = (rel(path, base), line_no)
            if key in seen:
                continue
            seen.add(key)
            if direct:
                source = request_source.search(statement)
                path_desc = f"{(source.group(0) if source else 'request source').strip()} -> outbound HTTP"
            else:
                ref = refs[0]
                seq = list(tainted.get(ref, {}).get('path', [ref]))
                if len(seq) >= PATH_LIMIT:
                    seq = seq[-(PATH_LIMIT - 1):]
                seq.append('outbound HTTP')
                path_desc = ' -> '.join(seq)
            findings.append((rel(path, base), line_no, f"{source_line(lines, line_no)} [{path_desc}]"))

    if not findings:
        return
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    desc = "Validate outbound URLs with URL parsing plus explicit https scheme and host allow-list checks before URLSession, URLRequest, Data(contentsOf:), or HTTP client calls."
    yield {
        "rule": RULE_ID,
        "category": CATEGORY,
        "path": findings[0][0],
        "line": findings[0][1],
        "severity": SEVERITY,
        "count": len(findings),
        "title": TITLE,
        "message": TITLE,
        "description": f"{desc} Examples: {samples}",
    }
