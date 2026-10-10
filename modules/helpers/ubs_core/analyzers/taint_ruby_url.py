"""Outbound URL policy for the shared scoped Ruby taint frontend."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.analyzers.taint_ruby_traversal import flow_findings

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
SINK_RE = re.compile(
    r'\b(?:URI|OpenURI)\.open\s*\('
    r'|\bopen\s*\('
    r'|\bNet::HTTP\.(?:get|get_response|post|post_form|start|new)\s*\('
    r'|\b(?:Faraday|HTTParty|RestClient|Excon|HTTP|Typhoeus|Curl)\.(?:get|post|put|patch|delete|head|request)\s*\('
    r'|\.request\s*\('
    r'|\.get\s*\(',
)

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

def analyze(path, issues):
    for rule, line, code, extras in flow_findings(path, 'url'):
        issues.append((relpath(path), line, code))


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
    """Emit the URL policy's findings and source-to-sink witnesses."""
    _configure(Path.cwd())
    for path in ctx.files:
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        for rule, line_no, code, extras in flow_findings(path, 'url'):
            yield {
                "rule": "ruby.taint.outbound_url",
                "path": relpath(path),
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "ruby",
                "severity": "critical",
                "message": f"{MESSAGE}: {code}",
                "extras": extras,
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


def _selftest_unproven_validate_url() -> None:
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
    assert len(findings) == 1 and findings[0]['line'] == 4, findings


def _selftest_host_only_guard_is_not_url_validation() -> None:
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
    assert len(findings) == 1 and findings[0]['line'] == 7, findings


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
    ("unproven_validate_url", _selftest_unproven_validate_url),
    ("host_only_guard_is_not_url_validation", _selftest_host_only_guard_is_not_url_validation),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="ruby", name="taint_ruby_url", run=run, selftests=SELF_TESTS))
