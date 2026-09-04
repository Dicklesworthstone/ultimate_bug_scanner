"""ubs_core.analyzers.taint_rust — Rust open-redirect taint analysis (bead A2).

Logic moved verbatim from the request-derived open-redirect heredoc in
modules/ubs-rust.sh (rust_open_redirect_matches), which keeps its own copy
until that module's port bead. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.

Emit dialects:
- main(argv) reproduces the heredoc byte-for-byte: one
  `<path>:<line>:<source>  [<taint path>]` row per finding, with paths from
  the rglob walk or the UBS_RUST_FILE_LIST file exactly as the heredoc reads
  them.
- run(ctx) yields one NDJSON finding per detection with rule id
  `rust.taint.open_redirect` (registry lang prefix).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

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


def rust_files(path: Path):
    import os as _ubs_os
    _ubs_listing = _ubs_os.environ.get("UBS_RUST_FILE_LIST", "")
    if _ubs_listing and _ubs_os.path.isfile(_ubs_listing):
        # GH #70: consume the module's authoritative filtered file list
        # (--exclude / --strict-gitignore / --exclude-tests) instead of
        # re-walking the tree with a local skip list.
        with open(_ubs_listing, encoding="utf-8") as _ubs_fh:
            for _ubs_line in _ubs_fh:
                _ubs_entry = _ubs_line.rstrip("\n")
                if _ubs_entry.endswith(".rs"):
                    yield Path(_ubs_entry)
        return
    if path.is_file():
        if path.suffix == ".rs":
            yield path
        return
    for child in path.rglob("*.rs"):
        if skip_dirs.intersection(child.parts):
            continue
        yield child


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


def main(argv=None) -> int:
    """Byte-parity entrypoint: same behavior as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    root = Path(argv[1])
    issues = []
    for rust_file in rust_files(root):
        analyze(rust_file, issues)
    for path, line_no, code in issues:
        print(f"{path}:{line_no}:{code}")
    return 0


_RULE = "rust.taint.open_redirect"
_SEVERITY = "critical"
_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix != ".rs":
            continue
        issues: list[tuple[Path, int, str]] = []
        analyze(path, issues)
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for _path, line_no, code in issues:
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "rust",
                "severity": _SEVERITY,
                "message": f"{_MESSAGE} ({code})",
            }


def _selftest_direct_flow(tmp_prefix: str = "ubs_core_taint_rust_") -> None:
    import tempfile

    code = (
        "fn handler(params: Params) -> Redirect {\n"
        "    let target = params.get(\"redirect_url\").unwrap_or_default();\n"
        "    Redirect::to(&target)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "handler.rs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="rust", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "rust.taint.open_redirect", findings
    assert findings[0]["line"] == 3, findings
    assert findings[0]["severity"] == "critical", findings
    assert findings[0]["path"].endswith("handler.rs"), findings
    assert 'params.get("redirect_url") -> redirect' in findings[0]["message"], findings


def _selftest_ubs_ignore_suppression(tmp_prefix: str = "ubs_core_taint_rust_ign_") -> None:
    import tempfile

    code = (
        "fn handler(params: Params) -> Redirect {\n"
        "    let target = params.get(\"redirect_url\").unwrap_or_default();\n"
        "    Redirect::to(&target) // ubs:ignore\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "suppressed.rs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="rust", files=[target])))
    assert findings == [], findings


def _selftest_validated_flow_suppression(tmp_prefix: str = "ubs_core_taint_rust_val_") -> None:
    import tempfile

    code = (
        "fn handler(params: Params) -> Result<Redirect, Error> {\n"
        "    let target = params.get(\"redirect_url\").unwrap_or_default();\n"
        "    if !is_allowed_redirect_host(&target) {\n"
        "        return Err(Error::BadRedirect);\n"
        "    }\n"
        "    Redirect::to(&target)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "validated.rs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="rust", files=[target])))
    assert findings == [], findings


def _selftest_main_dialect(tmp_prefix: str = "ubs_core_taint_rust_main_") -> None:
    import contextlib
    import io as _io
    import os
    import tempfile
    from unittest import mock

    code = (
        "fn handler(params: Params) -> Redirect {\n"
        "    let target = params.get(\"redirect_url\").unwrap_or_default();\n"
        "    Redirect::to(&target)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "dialect.rs"
        target.write_text(code, encoding="utf-8")
        listing = Path(tmp) / "files.txt"
        listing.write_text(f"{target}\n", encoding="utf-8")
        buffer = _io.StringIO()
        with mock.patch.dict(os.environ):
            os.environ.pop("UBS_RUST_FILE_LIST", None)
            with contextlib.redirect_stdout(buffer):
                rc = main(["ubs", str(tmp)])
        walk_out = buffer.getvalue()
        buffer = _io.StringIO()
        with mock.patch.dict(os.environ):
            os.environ["UBS_RUST_FILE_LIST"] = str(listing)
            with contextlib.redirect_stdout(buffer):
                rc = main(["ubs", str(tmp)])
        list_out = buffer.getvalue()
    assert rc == 0
    expected = (
        f"{target}:3:Redirect::to(&target)  "
        '[params.get("redirect_url") -> redirect]\n'
    )
    assert walk_out == expected, repr(walk_out)
    assert list_out == expected, repr(list_out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_flow_detects", _selftest_direct_flow),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("validated_flow_suppression", _selftest_validated_flow_suppression),
    ("main_dialect_walk_and_file_list", _selftest_main_dialect),
)

register(Analyzer(layer="taint", lang="rust", name="taint_rust", run=run, selftests=SELF_TESTS))
