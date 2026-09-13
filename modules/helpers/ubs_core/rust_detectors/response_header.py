"""ubs_core.rust_detectors.response_header — request-controlled response-header taint (bead 0xjg.7).

Port of rust_response_header_matches (modules/ubs-rust.sh 3074-3400).

The legacy heredoc consumed UBS_RUST_FILE_LIST (GH #70) or rglob'd the tree;
`find(files)` instead iterates the orchestrator's already-filtered file list in
order. The legacy code never called .resolve() on list entries, so neither does
this port; the local skip_dirs set is kept for documentation only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

RULE_ID = "rust.security.response-header"
CATEGORY = 8
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = (
    "Reject or strip CR/LF, use HeaderValue::from_str, percent-encode filename "
    "fragments, or route through a header-safe helper before writing response headers"
)

skip_dirs = {".git", "target", ".cargo", "node_modules"}  # documentation-only (see module docstring)
path_limit = 4

source_re = re.compile(
    r'\b(?:params|query|form|body|json|payload)\s*\.\s*get\s*\(\s*"[^"]+"\s*\)'
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\(\s*"[^"]+"\s*\)'
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|host)\s*\('
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_param|query|param|header)\s*\(\s*"[^"]+"\s*\)'
    r'|\b(?:std::)?env::(?:var|var_os)\s*\(\s*"HTTP_[A-Z0-9_]+"\s*\)',
    re.IGNORECASE,
)
request_collection_re = re.compile(
    r'\b(?:params|query|form|body|json|payload|headers|header_map)\s*\.\s*get\s*\('
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|host|query_param|query|param)\s*\('
    r'|\b(?:std::)?env::(?:var|var_os)\s*\(',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\b(?:Response|HttpResponse)::builder\s*\(\s*\)\s*\.\s*header\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*headers_mut\s*\(\s*\)\s*\.\s*(?:insert|append)\s*\('
    r'|\b(?:headers|header_map|response_headers|resp_headers)\s*\.\s*(?:insert|append)\s*\('
    r'|\b(?:append_header|insert_header|header)\s*\([^;\n]*',
    re.IGNORECASE,
)
location_header_re = re.compile(
    r'(?:"Location"|(?<![A-Za-z0-9_])(?:LOCATION|(?:http::)?header::LOCATION)(?![A-Za-z0-9_]))',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
safe_expr_re = re.compile(
    r'\b(?:safe(?:Header|HeaderValue|ResponseHeader|Disposition|Filename|FileName)|'
    r'safe_(?:header|header_value|response_header|disposition|filename|file_name)|'
    r'secure(?:Header|HeaderValue|ResponseHeader|Disposition|Filename|FileName)|'
    r'secure_(?:header|header_value|response_header|disposition|filename|file_name)|'
    r'sanitize(?:Header|HeaderValue|ResponseHeader|Disposition|CRLF|CrLf|Filename|FileName)|'
    r'sanitize_(?:header|header_value|response_header|disposition|crlf|filename|file_name)|'
    r'validate(?:Header|HeaderValue|ResponseHeader|Filename|FileName)|'
    r'validate_(?:header|header_value|response_header|filename|file_name)|'
    r'strip(?:CRLF|CrLf|Newlines)|strip_(?:crlf|newlines)|'
    r'remove(?:CRLF|CrLf|Newlines)|remove_(?:crlf|newlines)|'
    r'header_safe|crlf_safe|is_safe_header_value|valid_header_value|'
    r'HeaderValue::from_(?:str|static|bytes|maybe_shared))\b'
    r'|\b(?:urlencoding::encode|percent_encoding::utf8_percent_encode|percent_encode|'
    r'form_urlencoded::byte_serialize)\s*\('
    r'|\.replace\s*\([^;\n]*(?:\\r|\\n|\\\\r|\\\\n)',
    re.IGNORECASE,
)
crlf_check_re = re.compile(
    r'\.(?:contains|find)\s*\([^;\n]*(?:\\r|\\n|\\\\r|\\\\n)'
    r'|\bcontains_crlf\s*\('
    r'|(?:\\r|\\n|\\\\r|\\\\n)',
    re.IGNORECASE,
)
reject_re = re.compile(
    r'\b(?:return\s+Err|Err\s*\(|bail!\s*\(|ensure!\s*\(|anyhow!\s*\(|'
    r'return\s+None|StatusCode::BAD_REQUEST|BadRequest|panic!\s*\(|return\s+Response)\b',
    re.IGNORECASE,
)


def rust_files(files):
    """Legacy rust_files(): consume the orchestrator's authoritative filtered
    file list (--exclude / --strict-gitignore / --exclude-tests) instead of
    re-walking the tree with a local skip list. The legacy listing path kept
    .rs entries only and never resolved them."""
    for entry in files:
        if entry.suffix == ".rs":
            yield entry


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


def without_string_literals(expr: str) -> str:
    chars = list(expr)
    i = 0
    quote = ""
    raw_hashes = None
    escape = False
    while i < len(chars):
        ch = chars[i]
        if raw_hashes is not None:
            chars[i] = " "
            if ch == '"' and expr.startswith("#" * raw_hashes, i + 1):
                for pos in range(i + 1, min(i + 1 + raw_hashes, len(chars))):
                    chars[pos] = " "
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            chars[i] = " "
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
            while j < len(chars) and chars[j] == "#":
                j += 1
            if j < len(chars) and chars[j] == '"':
                for pos in range(i, j + 1):
                    chars[pos] = " "
                raw_hashes = j - i - 1
                i = j + 1
                continue
        if ch in ('"', "'"):
            chars[i] = " "
            quote = ch
        i += 1
    return "".join(chars)


def refs_in_expr(expr: str, tainted):
    searchable = without_string_literals(expr)
    names = set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', searchable))
    names.update(re.findall(r'\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::|})', expr))
    return [name for name in tainted if name in names]


def taint_from_expr(expr: str, tainted):
    if is_safe_expr(expr):
        return None
    direct = source_re.search(expr)
    if direct:
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


def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context = "\n".join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    return bool(crlf_check_re.search(context) and reject_re.search(context))


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
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            else:
                tainted.pop(name, None)
        if not sink_re.search(statement):
            continue
        if location_header_re.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = source_re.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, line_no, refs):
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip()} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get("path", [ref]))
            if len(seq) >= path_limit:
                seq = seq[-(path_limit - 1):]
            seq.append("response header")
            path_desc = " -> ".join(seq)
        issues.append((path, line_no, f"{source_line(lines, line_no)}  [{path_desc}]"))


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy deduped finding, in legacy order."""
    issues = []
    for rust_file in rust_files(files):
        analyze(rust_file, issues)
    for path, line_no, code in issues:
        yield path, line_no, 1, code


if __name__ == "__main__":
    import sys
    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
