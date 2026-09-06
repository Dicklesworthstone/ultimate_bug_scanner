"""ubs_core.rust_detectors.open_redirect — category 8 security (bead 0xjg.7).

Port of rust_open_redirect_matches (modules/ubs-rust.sh 2371-2664): a logical
statement tracker that taints names assigned from redirect-keyed request
sources (params/query/form/body/json payload getters, req.query_param/header
accessors, env QUERY_STRING/REQUEST_URI/HTTP_HOST/... values), then flags
redirect sinks (axum/rocket/poem/warp Redirect::*, redirect/send_redirect
calls, Location header writes) whose target is request-derived, annotating
each hit with the taint path. Safe-redirect helpers, a local-path
starts_with('/') && !starts_with('//') check, and Url::parse + host check +
reject contexts within the preceding 24 lines suppress the hit. Same-line and
previous-line `ubs:ignore` markers suppress a hit.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

RULE_ID = "rust.security.open-redirect"
CATEGORY = 8
TITLE = "Unvalidated redirect from request data"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate redirect targets with same-origin relative paths or explicit "
    "scheme and host allow-lists before redirects or Location headers"
)

# Documentation only: the orchestrator already passes the filtered file list
# (legacy rglob fallback applied this skip list).
skip_dirs = {".git", "target", ".cargo", "node_modules"}
path_limit = 4
redirect_key = r"(?:return[_-]?to|return[_-]?url|redirect(?:[_-]?url)?|next|continue|callback|target|destination|location|uri|url)"

source_re = re.compile(
    rf'\b(?:params|query|form|body|json|payload)\s*\.\s*get\s*\(\s*"[^"]*{redirect_key}[^"]*"\s*\)'
    rf'|\b(?:headers|header_map)\s*\.\s*get\s*\(\s*"[^"]*{redirect_key}[^"]*"\s*\)'
    rf'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|host)\s*\('
    rf'|\b(?:req|request|http_request)\s*\.\s*(?:query_param|query|param|header)\s*\(\s*"[^"]*{redirect_key}[^"]*"\s*\)'
    rf'|\b(?:params|query|form|body|json|payload)\s*\.\s*(?:redirect_url|return_url|return_to|next|continue_url|callback_url|target_url|location|uri|url)\b'
    r'|\b(?:std::)?env::(?:var|var_os)\s*\(\s*"(?:(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_REFERER|HTTP_REFERRER|HTTP_[A-Z0-9_]*(?:REDIRECT|RETURN|CALLBACK|LOCATION|URL|URI|TARGET|NEXT)[A-Z0-9_]*))"\s*\)',
    re.IGNORECASE,
)
request_collection_re = re.compile(
    r'\b(?:params|query|form|body|json|payload|headers|header_map)\s*\.\s*get\s*\('
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|host|query_param|query|param)\s*\('
    r'|\b(?:std::)?env::(?:var|var_os)\s*\(',
    re.IGNORECASE,
)
redirectish_name_re = re.compile(
    r"(?:redirect|return|callback|next|continue|target|destination|location|uri|url)",
    re.IGNORECASE,
)
host_source_re = re.compile(
    r'\b(?:req|request|http_request)\s*\.\s*(?:host|uri)\s*\('
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\(\s*"host"\s*\)'
    r'|\b(?:std::)?env::(?:var|var_os)\s*\(\s*"HTTP_HOST"\s*\)',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\b(?:axum::response::)?Redirect::(?:to|temporary|permanent|found|see_other)\s*\('
    r'|\b(?:rocket::response::)?Redirect::(?:to|temporary|permanent|found|see_other)\s*\('
    r'|\b(?:poem::web::)?Redirect::(?:temporary|permanent|see_other|moved_permanently|found)\s*\('
    r'|\b(?:warp::)?redirect::(?:redirect|temporary|permanent|see_other|found)\s*\('
    r'|\b(?:redirect|send_redirect|http_redirect)\s*\('
    r'|\b(?:append_header|insert_header|header)\s*\([^;\n]*(?:"Location"|LOCATION|header::LOCATION|http::header::LOCATION)'
    r'|\b(?:headers|header_map|response_headers)\s*\.\s*insert\s*\(\s*(?:"Location"|LOCATION|header::LOCATION|http::header::LOCATION)'
    r'|\b(?:Response|HttpResponse)::builder\s*\(\s*\)\s*\.\s*header\s*\([^;\n]*(?:"Location"|LOCATION|header::LOCATION|http::header::LOCATION)',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
safe_expr_re = re.compile(
    r'\b(?:safe(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectTarget)|'
    r'safe_(?:redirect_url|redirect_uri|redirect_target)|'
    r'validated?(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectHost|RedirectTarget)|'
    r'validate_(?:redirect_url|redirect_uri|redirect_host|redirect_target)|'
    r'allow(?:ed)?(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectHost|RedirectTarget)|'
    r'allowlist(?:ed)?(?:RedirectURL|RedirectUrl|RedirectURI|RedirectHost|RedirectTarget)|'
    r'(?:allowed|allowlist|allowlisted)_(?:redirect_url|redirect_uri|redirect_host|redirect_target)|'
    r'local(?:RedirectURL|RedirectUrl|RedirectURI|RedirectTarget)|'
    r'local_(?:redirect_url|redirect_uri|redirect_target)|'
    r'same_origin_redirect|sameOriginRedirect|is_local_redirect|isLocalRedirect|'
    r'is_allowed_redirect_host|isAllowedRedirectHost|allowed_redirect_hosts)\b',
    re.IGNORECASE,
)
parse_re = re.compile(r'\b(?:url::)?Url::parse\s*\(|\.parse\s*::\s*<\s*(?:http::)?Uri\s*>\s*\(')
host_check_re = re.compile(
    r'\b(?:host_str|scheme|allowed_redirect_hosts|allowed_hosts|redirect_host_allowlist|trusted_redirect_hosts|is_allowed_redirect_host)\b'
)
local_path_re = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*starts_with\s*\(\s*["\']/["\']\s*\)'
    r'(?:(?!;).)*(?:&&|\band\b)(?:(?!;).)*!\s*\1\s*\.\s*starts_with\s*\(\s*["\']//["\']\s*\)'
    r'|!\s*\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*starts_with\s*\(\s*["\']//["\']\s*\)'
    r'(?:(?!;).)*(?:&&|\band\b)(?:(?!;).)*\2\s*\.\s*starts_with\s*\(\s*["\']/["\']\s*\)',
    re.IGNORECASE | re.DOTALL,
)
reject_re = re.compile(r'\b(?:return\s+Err|Err\s*\(|bail!\s*\(|ensure!\s*\(|anyhow!\s*\(|return\s+None|None\b|panic!\s*\()\b')


def strip_line_comments(line: str) -> str:
    out = []
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if raw_hashes is not None:
            out.append(ch)
            if ch == '"' and line.startswith("#" * raw_hashes, i + 1):
                out.extend("#" * raw_hashes)
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "r":
            j = i + 1
            while j < len(line) and line[j] == "#":
                j += 1
            if j < len(line) and line[j] == '"':
                raw_hashes = j - i - 1
                out.extend(line[i : j + 1])
                i = j + 1
                continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren = statement.count("(") - statement.count(")")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (paren > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        paren += nxt.count("(") - nxt.count(")")
        has_end = has_end or ";" in nxt or "{" in nxt or "}" in nxt
        lookahead += 1
    return statement


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and "ubs:ignore" in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and "ubs:ignore" in lines[idx - 1]
    )


def is_safe_expr(expr: str) -> bool:
    return bool(safe_expr_re.search(expr))


def has_request_source(expr: str, target_name: str = "") -> bool:
    if source_re.search(expr):
        return bool(redirectish_name_re.search(expr) or host_source_re.search(expr))
    return bool(target_name and redirectish_name_re.search(target_name) and request_collection_re.search(expr))


def refs_in_expr(expr: str, tainted):
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', expr)]


def taint_from_expr(expr: str, tainted, target_name: str = ""):
    if is_safe_expr(expr):
        return None
    direct = source_re.search(expr)
    if direct and has_request_source(expr, target_name):
        return {"path": [direct.group(0).strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get("path", [ref]))
    if len(path) >= path_limit:
        path = path[-(path_limit - 1):]
    path.append(ref)
    return {"path": path}


def has_redirect_validation_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = "\n".join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if safe_expr_re.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(
        (parse_re.search(context) and host_check_re.search(context) and reject_re.search(context))
        or (local_path_re.search(context) and reject_re.search(context))
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not (request_collection_re.search(text) and sink_re.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for line_no, _ in enumerate(lines, start=1):
        if has_ignore(lines, line_no):
            continue
        raw_line = strip_line_comments(lines[line_no - 1]).strip()
        if not raw_line:
            continue
        statement = logical_statement(lines, line_no).strip()
        if not statement:
            continue
        assign = assign_re.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            taint = taint_from_expr(rhs, tainted, name)
            if taint:
                tainted[name] = taint
            else:
                tainted.pop(name, None)
        if not sink_re.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = source_re.search(statement) and has_request_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_redirect_validation_context(lines, line_no, refs):
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = source_re.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> redirect"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get("path", [ref]))
            if len(seq) >= path_limit:
                seq = seq[-(path_limit - 1):]
            seq.append("redirect")
            path_desc = " -> ".join(seq)
        issues.append((path, line_no, f"{source_line(lines, line_no)}  [{path_desc}]"))


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy deduped finding, in legacy
    order. `files` is the ordered list of Path entries to scan."""
    issues = []
    for rust_file in files:
        analyze(rust_file, issues)
    for path, line_no, code in issues:
        yield (path, line_no, 1, code)


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
