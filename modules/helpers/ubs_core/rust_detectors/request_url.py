"""ubs_core.rust_detectors.request_url — request-derived outbound-URL taint (bead 0xjg.7).

Port of rust_request_url_matches (modules/ubs-rust.sh 3442-3695).

The legacy heredoc consumed UBS_RUST_FILE_LIST (GH #70) or rglob'd the tree;
`find(files)` instead iterates the orchestrator's already-filtered file list in
order. The legacy code never called .resolve() on list entries, so neither does
this port; the local skip_dirs set is kept for documentation only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

RULE_ID = "rust.security.request-url"
CATEGORY = 8
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate outbound URLs with explicit scheme and host allow-lists before "
    "sending client requests"
)

skip_dirs = {".git", "target", ".cargo", "node_modules"}  # documentation-only (see module docstring)
path_limit = 4

source_re = re.compile(
    r'\b(?:std::)?env::(?:var|var_os)\s*\(\s*"[^"]*(?:URL|URI|HOST|CALLBACK|WEBHOOK|REDIRECT|TARGET|ENDPOINT|REMOTE)[^"]*"\s*\)'
    r'|\b(?:std::)?env::args(?:_os)?\s*\('
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|host)\s*\('
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\(\s*"[^"]*(?:url|uri|host|callback|webhook|redirect|target|endpoint|origin|referer|referrer|location)[^"]*"\s*\)'
    r'|\b(?:params|query|form|body|json|payload|headers)\s*\.\s*get\s*\(\s*"[^"]*(?:url|uri|host|callback|webhook|redirect|target|endpoint|origin|remote)[^"]*"\s*\)'
    r'|\b(?:params|query|form|body|json|payload)\s*\.\s*(?:url|uri|host|callback_url|webhook_url|redirect_url|target_url|endpoint|remote_url)\b',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\breqwest(?:::blocking)?::(?:get|Client::new\(\)\.(?:get|post|put|patch|delete|head|request))\s*\('
    r'|\bureq::(?:get|post|put|delete|patch|head|request)\s*\('
    r'|\bsurf::(?:get|post|put|delete|patch|head|request)\s*\('
    r'|\bisahc::(?:get|post|put|delete|patch|head|request)\s*\('
    r'|\b(?:hyper|http)::Request::builder\s*\(\s*\)\s*\.\s*uri\s*\('
    r'|\b(?:client|http_client|reqwest_client|rest_client|web_client|agent|request_builder|builder|api_client|webhook_client)\s*\.\s*(?:get|post|put|patch|delete|head|request|uri)\s*\(',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
safe_expr_re = re.compile(
    r'\b(?:safe(?:URL|Url|Uri|URI|OutboundURL|OutboundUrl|OutboundURI|WebhookURL|CallbackURL|HttpURL)|'
    r'safe_(?:url|uri|outbound_url|webhook_url|callback_url|http_url)|'
    r'validated?(?:URL|Url|Uri|URI|Host|OutboundURL|WebhookURL|CallbackURL)|'
    r'validate_(?:url|uri|host|outbound_url|webhook_url|callback_url)|'
    r'allowed?(?:URL|Url|Uri|URI|Host|OutboundURL)|'
    r'allowlisted?(?:URL|Url|Uri|URI|Host|OutboundURL)|'
    r'is_allowed_host|is_safe_url|allowed_hosts|host_allowlist|trusted_hosts)\b',
    re.IGNORECASE,
)
parse_re = re.compile(r'\b(?:url::)?Url::parse\s*\(|\.parse\s*::\s*<\s*(?:hyper::)?Uri\s*>\s*\(')
host_check_re = re.compile(
    r'\b(?:host_str|domain|scheme|allowed_hosts|host_allowlist|trusted_hosts|is_allowed_host|is_safe_url)\b'
)
reject_re = re.compile(r'\b(?:return\s+Err|Err\s*\(|bail!\s*\(|ensure!\s*\(|anyhow!\s*\(|panic!\s*\()\b')


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


def refs_in_expr(expr: str, tainted):
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', expr)]


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


def has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = "\n".join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if safe_expr_re.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(parse_re.search(context) and host_check_re.search(context) and reject_re.search(context))


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
    if not (source_re.search(text) and sink_re.search(text)):
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
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not sink_re.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = source_re.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_allowlist_context(lines, line_no, refs):
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip()} -> outbound HTTP"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get("path", [ref]))
            if len(seq) >= path_limit:
                seq = seq[-(path_limit - 1):]
            seq.append("outbound HTTP")
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
