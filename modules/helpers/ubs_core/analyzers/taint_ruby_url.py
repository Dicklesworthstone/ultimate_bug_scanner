"""ubs_core.analyzers.taint_ruby_url — request-derived outbound URL taint (bead A2).

Logic moved verbatim from the run_outbound_url_checks heredoc in
modules/ubs-ruby.sh; the shell keeps its copy until that module's port bead
lands (transitional duplication is sanctioned). main(argv) reproduces the
heredoc's __COUNT__/__SAMPLE__ stdout byte-for-byte for the same argv;
run(ctx) mirrors the same detection over RunContext.files as NDJSON findings.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT = Path.cwd()
BASE_DIR = ROOT

SKIP_DIRS = {'.git', '.bundle', 'vendor', 'node_modules', 'tmp', 'log', 'coverage', '.cache', 'dist', 'build'}
EXTS = {'.rb', '.rake', '.ru', '.gemspec', '.erb', '.haml', '.slim', '.rbi', '.rbs', '.jbuilder'}

SOURCE_RE = re.compile(
    r'\b(?:params|request\.params)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:path|path_info|fullpath|original_fullpath|query_string|url|'
    r'referer|referrer|host|host_with_port|raw_host_with_port|domain|subdomain|subdomains|port|remote_ip|ip)\b'
    r'|\b(?:request|req|rack_request)\.(?:get|post|params|query|POST|GET|headers)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:env|request\.env)\s*\[\s*[\'"](?:REQUEST_URI|QUERY_STRING|HTTP_REFERER|HTTP_ORIGIN|HTTP_HOST|HTTP_X_FORWARDED_HOST)[\'"]\s*\]'
    r'|\bRack::Request\.new\s*\([^)]*\)\.params\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:_url|_uri|_outbound_url|_webhook_url|_callback_url|URL|Uri|URI|OutboundURL|WebhookURL|CallbackURL)|'
    r'secure(?:_url|_uri|_outbound_url|URL|Uri|URI|OutboundURL)|'
    r'allow(?:_url|_uri|_host|URL|Uri|URI|Host)|allowed(?:_url|_uri|_host|URL|Uri|URI|Host)|'
    r'validate(?:_url|_uri|_host|_outbound_url|URL|Uri|URI|Host|OutboundURL)|'
    r'sanitize(?:_url|_uri|URL|Uri|URI)|resolve_allowed(?:_url|_uri)|'
    r'is_allowed_host|allowed_host\?|safe_url\?|safe_uri\?|safe_outbound_url\?)\b',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:URI|Addressable::URI)\.(?:parse|join)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:host|hostname|scheme)\b'
    r'|\b(?:ALLOWED_HOSTS|allowed_hosts|allowlist|host_allowlist|trusted_hosts|allowed_host\?)\b'
    r'|%w\['
)
REJECT_RE = re.compile(r'\b(?:raise|return\s+false|halt|head\s+:forbidden|forbidden|bad_request)\b', re.IGNORECASE)
SINK_RE = re.compile(
    r'\b(?:URI|OpenURI)\.open\s*\('
    r'|\bopen\s*\('
    r'|\bNet::HTTP\.(?:get|get_response|post|post_form|start|new)\s*\('
    r'|\b(?:Faraday|HTTParty|RestClient|Excon|HTTP|Typhoeus|Curl)\.(?:get|post|put|patch|delete|head|request)\s*\('
    r'|\.request\s*\('
    r'|\.get\s*\(',
)
ASSIGN_RE = re.compile(r'^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$')
PATH_LIMIT = 4

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

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
        if ch == '#':
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
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

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
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
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
        key = (relpath(path), idx)
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
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))


def _configure(root: Path) -> None:
    """Bind ROOT/BASE_DIR the way the heredoc derived them from sys.argv[1]."""
    global ROOT, BASE_DIR
    ROOT = root
    BASE_DIR = root if root.is_dir() else root.parent


MESSAGE = "Request-derived URL reaches outbound HTTP client"
REMEDY = (
    "Validate outbound URLs with explicit scheme and host allow-lists before "
    "using Net::HTTP, URI.open, Faraday, HTTParty, or RestClient"
)


def main(argv: list[str] | None = None) -> int:
    """Print the heredoc's __COUNT__/__SAMPLE__ report for one project dir."""
    if argv is None:
        argv = sys.argv[1:]
    _configure(Path(argv[0]).resolve())
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    """Mirror the heredoc detection over ctx.files as NDJSON findings."""
    _configure(Path.cwd())
    for path in ctx.files:
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            path.relative_to(BASE_DIR)
        except ValueError:
            pass  # outside the scan root: the heredoc's glob never applied SKIP_DIRS there
        else:
            if should_skip(path):
                continue
        issues: list[tuple[str, int, str]] = []
        analyze(path, issues)
        for rel, line_no, code in issues:
            yield {
                "rule": "ruby.taint.outbound_url",
                "path": rel,
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "ruby",
                "severity": "critical",
                "message": f"{MESSAGE}: {code}",
            }


def _selftest_positive_run() -> None:
    import tempfile

    code = (
        "class Fetcher\n"
        "  def pull\n"
        "    target = params[:url]\n"
        "    Net::HTTP.get(URI.parse(target))\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_url_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "ruby.taint.outbound_url", findings
    assert findings[0]["line"] == 4, findings


def _selftest_validate_url_suppression() -> None:
    import tempfile

    code = (
        "class Fetcher\n"
        "  def pull\n"
        "    target = validate_url(params[:url])\n"
        "    Net::HTTP.get(URI.parse(target))\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_url_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert findings == [], findings


def _selftest_allowlist_context_suppression() -> None:
    import tempfile

    code = (
        "class Fetcher\n"
        "  ALLOWED_HOSTS = %w[example.com]\n"
        "  def pull\n"
        "    target = params[:url]\n"
        "    uri = URI.parse(target)\n"
        "    raise 'untrusted host' unless ALLOWED_HOSTS.include?(uri.host)\n"
        "    Net::HTTP.get(uri)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_url_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect() -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "class Fetcher\n"
        "  def pull\n"
        "    target = params[:url]\n"
        "    Net::HTTP.get(URI.parse(target))\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_url_") as tmp:
        (Path(tmp) / "app.rb").write_text(code, encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main([tmp])
    lines = buffer.getvalue().splitlines()
    assert rc == 0
    assert lines[0] == "__COUNT__\t1", lines
    assert lines[1].startswith("__SAMPLE__\tapp.rb\t4\t"), lines


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("positive_run", _selftest_positive_run),
    ("validate_url_suppression", _selftest_validate_url_suppression),
    ("allowlist_context_suppression", _selftest_allowlist_context_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="ruby", name="taint_ruby_url", run=run, selftests=SELF_TESTS))
