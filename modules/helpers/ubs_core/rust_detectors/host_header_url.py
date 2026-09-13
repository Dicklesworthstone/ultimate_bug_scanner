"""ubs_core.rust_detectors.host_header_url — category 8 security (bead 0xjg.7).

Port of rust_host_header_url_matches (modules/ubs-rust.sh 2706-3032): a
logical statement tracker that taints names assigned from Host-derived
sources (req.host(), req.uri().host(), headers().get("host"/HOST/
x-forwarded-host/forwarded/x-original-host), env HTTP_HOST), then flags
absolute-URL construction sinks (format!("https://..."), string-literal
"https://" concatenations, Uri::builder().scheme("https").authority(...))
whose input is Host-derived, annotating each hit with the taint path (format
placeholders like `{host}` count as references). Taint resets at each `fn`
boundary. Safe/canonical/validated host helpers and allow-list constants plus
a reject (Err/None/panic) within the preceding 20 lines suppress the hit.
Same-line and previous-line `ubs:ignore` markers suppress a hit.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

RULE_ID = "rust.security.host-header-url"
CATEGORY = 8
TITLE = "Request Host header used to build absolute URL"
SEVERITY = "critical"
DESCRIPTION = (
    "Use a configured canonical origin or validate Host/X-Forwarded-Host "
    "against an explicit allow-list before generating links"
)

# Documentation only: the orchestrator already passes the filtered file list
# (legacy rglob fallback applied this skip list).
skip_dirs = {".git", "target", ".cargo", "node_modules"}
path_limit = 4

host_key = r"(?:host|x-forwarded-host|forwarded|x-original-host)"
source_re = re.compile(
    rf'\b(?:req|request|http_request)\s*\.\s*host\s*\('
    rf'|\b(?:req|request|http_request)\s*\.\s*uri\s*\(\s*\)\s*\.\s*host\s*\('
    rf'|\b(?:req|request|http_request)\s*\.\s*headers\s*\(\s*\)\s*\.\s*get\s*\(\s*(?:"{host_key}"|header::HOST|http::header::HOST|HOST)\s*\)'
    rf'|\b(?:headers|header_map)\s*\.\s*get\s*\(\s*(?:"{host_key}"|header::HOST|http::header::HOST|HOST)\s*\)'
    r'|\b(?:std::)?env::(?:var|var_os)\s*\(\s*"HTTP_HOST"\s*\)',
    re.IGNORECASE,
)
sink_prefilter_re = re.compile(
    r'https?://'
    r'|\b(?:http::)?Uri::builder\s*\(',
    re.IGNORECASE,
)
absolute_url_re = re.compile(
    r'\bformat!\s*\(\s*(?:r#*)?"https?://'
    r'|(?:r#*)?"https?://[^"\n]*"\s*(?:\.to(?:_owned|_string)\s*\(\s*\))?\s*\+'
    r'|\b(?:http::)?Uri::builder\s*\(\s*\)[^;\n]*\.scheme\s*\(\s*(?:r#*)?"https?"\s*\)[^;\n]*\.authority\s*\(',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
fn_re = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\b')
safe_expr_re = re.compile(
    r'\b(?:safe|secure|trusted|canonical|validated|allowed)[A-Za-z0-9_]*(?:Host|Origin|Url|URL|Uri|URI|BaseUrl|BaseURL|LinkOrigin)[A-Za-z0-9_]*\s*\('
    r'|\b(?:safe|secure|trusted|canonical|validated|allowed)_(?:host|origin|url|uri|base_url|link_origin)[A-Za-z0-9_]*\s*\('
    r'|\b(?:validate|assert|ensure|require|check)[A-Za-z0-9_]*(?:Host|Origin|Url|URL|Uri|URI|BaseUrl|BaseURL|Canonical|Allowed|Trusted)[A-Za-z0-9_]*\s*\('
    r'|\b(?:validate|assert|ensure|require|check)_(?:host|origin|url|uri|base_url|canonical|allowed|trusted)[A-Za-z0-9_]*\s*\('
    r'|\b(?:is|has)[A-Za-z0-9_]*(?:Allowed|Trusted|Safe)[A-Za-z0-9_]*(?:Host|Origin|Url|URL|Uri|URI)?[A-Za-z0-9_]*\s*\('
    r'|\b(?:is|has)_(?:allowed|trusted|safe)[A-Za-z0-9_]*(?:host|origin|url|uri)?[A-Za-z0-9_]*\s*\('
    r'|\b(?:ALLOWED_HOSTS|TRUSTED_HOSTS|HOST_ALLOWLIST|ORIGIN_ALLOWLIST|ALLOWED_ORIGINS|TRUSTED_ORIGINS|allowed_hosts|trusted_hosts|host_allowlist|origin_allowlist|allowed_origins|trusted_origins)\b',
    re.IGNORECASE,
)
reject_re = re.compile(
    r'\b(?:return\s+Err|Err\s*\(|bail!\s*\(|ensure!\s*\(|anyhow!\s*\(|return\s+None|None\b|panic!\s*\()\b',
    re.IGNORECASE,
)


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


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = (
        statement.count("(") - statement.count(")")
        + statement.count("{") - statement.count("}")
        + statement.count("[") - statement.count("]")
    )
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 12:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        balance += (
            nxt.count("(") - nxt.count(")")
            + nxt.count("{") - nxt.count("}")
            + nxt.count("[") - nxt.count("]")
        )
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
    searchable = without_string_literals(expr)
    names = set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', searchable))
    names.update(re.findall(r'\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::|})', expr))
    return [name for name in tainted if name in names]


def is_absolute_url_construction(expr: str) -> bool:
    return bool(absolute_url_re.search(expr))


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
    start = max(0, line_no - 20)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no]]
    context = "\n".join(context_lines)
    ref_lines = [
        line for line in context_lines
        if any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs)
    ]
    if not ref_lines:
        return False
    return bool(
        any(safe_expr_re.search(line) for line in ref_lines)
        and reject_re.search(context)
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
    if not (source_re.search(text) and sink_prefilter_re.search(text)):
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
        if fn_re.search(raw_line):
            tainted = {}
            if not (source_re.search(raw_line) and is_absolute_url_construction(raw_line)):
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
        direct = source_re.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if not is_absolute_url_construction(statement):
            continue
        if is_safe_expr(statement) or has_allowlist_context(lines, line_no, refs):
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip()} -> absolute URL"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get("path", [ref]))
            if len(seq) >= path_limit:
                seq = seq[-(path_limit - 1):]
            seq.append("absolute URL")
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
