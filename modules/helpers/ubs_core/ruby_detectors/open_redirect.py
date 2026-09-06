"""ubs_core.ruby_detectors.open_redirect — category 6 security (bead 0xjg.10).

Port of run_open_redirect_checks (modules/ubs-ruby.sh 1628-1890): a line
tracker that taints names assigned from redirect-keyed request sources
(params[:return_url]-shaped keys, request.url/fullpath/referer/host
accessors, Rack env REQUEST_URI/HTTP_REFERER/... values), then flags
redirect sinks (redirect_to/redirect/head location/Location header writes)
whose target is request-derived. Safe-redirect helpers, local-path
start_with?('/'), url_from, allow_other_host: false, and URI.parse + host
allow-list + reject contexts within the preceding 24 lines suppress the hit.
Same-file and previous-line `ubs:ignore` markers suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.ruby_detectors._common import (
    EXTS,
    has_ignore,
    logical_statement,
    read_lines,
    ruby_files,
    source_line,
    strip_line_comments,
    word_regex,
)

RULE_ID = "ruby.redirect.open"
CATEGORY = 6
TITLE = "Unvalidated redirect from request data"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate redirect targets with local-url checks or explicit scheme and "
    "host allow-lists before redirect_to, redirect, or Location headers"
)

REDIRECT_KEY = r'(?:return(?:_url|_uri|_to)?|returnurl|returnto|redirect(?:_url|_uri|_to)?|next|continue|callback|target|destination|location|url|uri)'

SOURCE_RE = re.compile(
    rf'\b(?:params|request\.params)\s*(?:\[[^\]]*{REDIRECT_KEY}[^\]]*\]|\.fetch\s*\([^)]*{REDIRECT_KEY}[^)]*\)|\.dig\s*\([^)]*{REDIRECT_KEY}[^)]*\))'
    rf'|\b(?:request|req|rack_request)\.(?:get|post|params|query|POST|GET|headers)\s*(?:\[[^\]]*{REDIRECT_KEY}[^\]]*\]|\.fetch\s*\([^)]*{REDIRECT_KEY}[^)]*\)|\.dig\s*\([^)]*{REDIRECT_KEY}[^)]*\))'
    r'|\b(?:request|req|rack_request)\.(?:url|fullpath|original_fullpath|query_string|referer|referrer|host|host_with_port|raw_host_with_port)\b'
    rf'|\b(?:env|request\.env)\s*\[\s*[\'"](?:REQUEST_URI|QUERY_STRING|HTTP_REFERER|HTTP_ORIGIN|HTTP_HOST|HTTP_X_FORWARDED_HOST|HTTP_LOCATION)[\'"]\s*\]'
    rf'|\bRack::Request\.new\s*\([^)]*\)\.params\s*(?:\[[^\]]*{REDIRECT_KEY}[^\]]*\]|\.fetch\s*\([^)]*{REDIRECT_KEY}[^)]*\)|\.dig\s*\([^)]*{REDIRECT_KEY}[^)]*\))',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:params|request\.params)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:get|post|params|query|POST|GET|headers)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\bRack::Request\.new\s*\([^)]*\)\.params\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()',
    re.IGNORECASE,
)
URLISH_NAME_RE = re.compile(REDIRECT_KEY, re.IGNORECASE)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:_redirect|_redirect_url|_redirect_uri|_redirect_target|Redirect|RedirectURL|RedirectURI|RedirectTarget)|'
    r'secure(?:_redirect|_redirect_url|_redirect_target|Redirect|RedirectURL|RedirectTarget)|'
    r'validate(?:_redirect|_redirect_url|_return_url|Redirect|RedirectURL|ReturnURL)|'
    r'sanitize(?:_redirect|_redirect_url|Redirect|RedirectURL)|'
    r'allowed(?:_redirect|_redirect_url|_redirect_host|Redirect|RedirectURL|RedirectHost)|'
    r'allowlisted(?:_redirect|_redirect_url|Redirect|RedirectURL)|'
    r'local_redirect|local_url\?|safe_redirect\?|allowed_redirect\?|allowed_host\?|same_origin_redirect\?|url_from)\b'
    r'|allow_other_host:\s*false',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:URI|Addressable::URI)\.(?:parse|join)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:host|hostname|scheme)\b'
    r'|\b(?:ALLOWED_HOSTS|ALLOWED_REDIRECT_HOSTS|allowed_hosts|allowed_redirect_hosts|redirect_allowlist|trusted_hosts|allowed_host\?)\b'
    r'|%w\['
    r'|allow_other_host:\s*false'
)
LOCAL_PATH_RE = re.compile(r'\.start_with\?\s*\(\s*[\'"]/[\'"]\s*\)|\A\s*[A-Za-z_][A-Za-z0-9_]*\.start_with\?\s*\(\s*[\'"]/[\'"]\s*\)', re.IGNORECASE)
REJECT_RE = re.compile(r'\b(?:raise|return\s+false|return\s+nil|halt|head\s+:forbidden|head\s+:bad_request|forbidden|bad_request|render\s+status:)\b', re.IGNORECASE)
SINK_RE = re.compile(
    r'\bredirect_to\s*\(?'
    r'|(?:^|[^\w.])redirect\s+(?!to\b)'
    r'|\bredirect\s*\('
    r'|\bhead\s+[^#\n]*\blocation:'
    r'|\b(?:response\.headers|response|headers)\s*\[\s*[\'"]Location[\'"]\s*\]\s*='
    r'|\b(?:response\.headers|response|headers)\.(?:\[\]=|store)\s*\(\s*[\'"]Location[\'"]',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(r'^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$')
PATH_LIMIT = 4


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if word_regex(name).search(expr):
            refs.append(name)
    return refs


def has_source(expr, target_name=""):
    if SOURCE_RE.search(expr):
        return True
    return bool(target_name and URLISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(expr))


def taint_from_expr(expr, tainted, target_name=""):
    if is_safe_expr(expr):
        return None
    direct = has_source(expr, target_name)
    if direct:
        source = SOURCE_RE.search(expr)
        return {"path": [(source.group(0) if source else target_name or "request redirect target").strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get("path", [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {"path": path}


def has_safe_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = "\n".join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(word_regex(ref).search(context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(word_regex(ref).search(line) for ref in refs):
            return True
    return bool(
        (URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))
        or (LOCAL_PATH_RE.search(context) and REJECT_RE.search(context))
    )


def analyze(lines, issues, path_str):
    if not lines:
        return
    text = "\n".join(lines)
    if not (re.search(r'\b(?:params|request|env|Rack::Request)\b', text) and SINK_RE.search(text)):
        return
    tainted = {}
    seen = set()
    for idx in range(1, len(lines) + 1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            taint = taint_from_expr(rhs, tainted, name)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = has_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_safe_context(lines, idx, refs):
            continue
        key = (path_str, idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request redirect target').strip()} -> redirect sink"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get("path", [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append("redirect sink")
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
