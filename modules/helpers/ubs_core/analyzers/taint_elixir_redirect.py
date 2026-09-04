"""ubs_core.analyzers.taint_elixir_redirect — Elixir open-redirect taint (bead A2).

Logic moved verbatim from the open-redirect heredoc in modules/ubs-elixir.sh
(run_request_open_redirect_checks), which keeps its own copy until that
module's port bead. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.

Emit dialects:
- main(argv) reproduces the heredoc byte-for-byte: a `__COUNT__<TAB>count`
  header row followed by at most five `__SAMPLE__<TAB>file<TAB>line<TAB>code`
  rows, where code carries the heredoc's `  [source -> redirect]` suffix.
- run(ctx) yields one NDJSON finding per detection with rule id
  `elixir.taint.open_redirect` (registry lang prefix).

Adaptations vs the heredoc (detection logic untouched):
- ROOT/BASE_DIR become module globals set by main(argv) instead of being
  derived from sys.argv at import time.
- analyze() delegates the per-file loop to scan_file_findings() so main() and
  run() share one copy of the detection logic.
- run(ctx) skips a file only when its cwd-relative parts hit SKIP_DIRS; the
  heredoc computes the same check against its own ROOT, while ctx.files are
  handed in by the caller (self-test tempdirs live outside the project).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT: Path = Path()
BASE_DIR: Path = Path()



SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
REDIRECT_KEY = r'(?:return[_-]?to|return[_-]?url|redirect(?:[_-]?url)?|next|continue|callback|target|destination|location|url|uri)'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    rf'\b(?:conn|socket)\.(?:params|query_params)\s*(?:\[|\|>)|'
    rf'\bparams\s*(?:\[|\|>)|'
    rf'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{REDIRECT_KEY}|'
    rf'\bget_in\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{REDIRECT_KEY}|'
    rf'\b(?:conn|socket)\.(?:host|request_path|query_string)\b|'
    rf'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,[^)]*{REDIRECT_KEY}|'
    rf'\|>\s*Plug\.Conn\.get_req_header\s*\([^)]*{REDIRECT_KEY}',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|query_params)\b|\bparams\b|'
    r'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,',
    re.IGNORECASE,
)
REDIRECTISH_NAME_RE = re.compile(
    r'(redirect|return|callback|next|continue|target|destination|location|url|uri)',
    re.IGNORECASE,
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_redirect(?:_url|_uri|_target)?|safeRedirect(?:Url|Uri|Target)?|'
    r'validate_redirect(?:_url|_uri|_target)?|validateRedirect(?:Url|Uri|Target)?|'
    r'validated_redirect(?:_url|_uri|_target)?|validatedRedirect(?:Url|Uri|Target)?|'
    r'sanitize_redirect(?:_url|_uri|_target)?|sanitizeRedirect(?:Url|Uri|Target)?|'
    r'allowed_redirect(?:_url|_uri|_host|_target)?|allowedRedirect(?:Url|Uri|Host|Target)?|'
    r'local_redirect(?:_url|_uri|_target)?|localRedirect(?:Url|Uri|Target)?|'
    r'same_origin_redirect(?:_url|_target)?|sameOriginRedirect(?:Url|Target)?|'
    r'allowed_redirect_host\?|allowedRedirectHost\?|local_redirect\?|localRedirect\?|'
    r'is_local_redirect|isLocalRedirect)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:Phoenix\.Controller\.)?redirect\s*\([^)]*(?:to|external)\s*:|'
    r'\|\>\s*(?:Phoenix\.Controller\.)?redirect\s*\([^)]*(?:to|external)\s*:|'
    r'\b(?:Plug\.Conn\.)?put_resp_header\s*\([^)]*["\']location["\']\s*,|'
    r'\|\>\s*(?:Plug\.Conn\.)?put_resp_header\s*\(\s*["\']location["\']\s*,|'
    r'\b(?:Plug\.Conn\.)?resp\s*\([^)]*30[1278][^)]*["\']location["\']',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:URI\.parse|URI\.new!?)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:scheme|host)\b|'
    r'\b(?:allowed_redirect_hosts|allowed_hosts|allowed_host|redirect_host_allowlist|trusted_redirect_hosts|@allowed_redirect_hosts|@allowed_hosts)\b|'
    r'\b(?:MapSet\.member\?|Enum\.member\?|String\.starts_with\?)\s*\(|'
    r'\bin\s+@?(?:allowed_redirect_hosts|allowed_hosts)\b|'
    r'==\s*"https"',
    re.IGNORECASE,
)
LOCAL_PATH_RE = re.compile(
    r'String\.starts_with\?\s*\(\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*,\s*["\']/["\']\s*\).*'
    r'not\s+String\.starts_with\?\s*\(\s*\1\s*,\s*["\']//["\']\s*\)|'
    r'not\s+String\.starts_with\?\s*\(\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*,\s*["\']//["\']\s*\).*'
    r'String\.starts_with\?\s*\(\s*\2\s*,\s*["\']/["\']\s*\)',
    re.IGNORECASE | re.DOTALL,
)
REJECT_RE = re.compile(r'(?:\b(?:raise|throw)\b|\{:error|\b(?:halt|send_resp)\s*\(|\bjson\s*\([^)]*\{:error)', re.IGNORECASE)
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

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 10:
        upcoming = strip_line_comments(lines[lookahead]).lstrip()
        if not upcoming:
            probe = lookahead + 1
            while probe < len(lines) and probe < idx + 10:
                upcoming = strip_line_comments(lines[probe]).lstrip()
                if upcoming:
                    break
                probe += 1
        if balance <= 0 and has_end and not upcoming.startswith('|>'):
            break
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

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

def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement))

def has_request_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement):
        if REDIRECTISH_NAME_RE.search(statement) or re.search(r'\b(?:conn|socket)\.(?:host|request_path|query_string)\b', statement):
            return True
    return bool(target_name and REDIRECTISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(statement))

def refs_in_statement(statement: str, tainted: dict[str, dict]):
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', statement)]

def taint_from_statement(statement: str, tainted: dict[str, dict], target_name: str = ''):
    if is_safe_expression(statement):
        return None
    if has_request_source(statement, target_name):
        source = REQUEST_SOURCE_RE.search(statement)
        return {'path': [(source.group(0) if source else target_name or 'request value').strip()]}
    refs = refs_in_statement(statement, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}

def has_redirect_validation_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_NAMED_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(
        (URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))
        or (LOCAL_PATH_RE.search(context) and REJECT_RE.search(context))
    )


def scan_file_findings(path: Path):
    """Verbatim per-file detection loop from the heredoc's analyze().

    Yields (line_no, col, sample_code) per finding, where sample_code
    already carries the heredoc's `  [flow]` suffix; relpath aggregation
    and the five-sample __SAMPLE__ cap stay in analyze()/main().
    """
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (re.search(r'\b(?:conn|params|Plug\.Conn|query_params)\b', text) and SINK_RE.search(text)):
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

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_statement(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif is_safe_expression(rhs):
                tainted.pop(variable, None)
            else:
                tainted.pop(variable, None)

        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_request_source(statement)
        refs = refs_in_statement(statement, tainted)
        if not direct and not refs:
            continue
        if has_redirect_validation_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = REQUEST_SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> redirect"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect')
            path_desc = ' -> '.join(seq)
        yield idx, SINK_RE.search(current_line).start() + 1, f"{source_line(lines, idx)}  [{path_desc}]"


def analyze(path, issues):
    """Heredoc aggregation: collect one (relpath, line, code) tuple per finding."""
    for idx, _col, code in scan_file_findings(path):
        issues.append((relpath(path), idx, code))


def main(argv=None) -> int:
    """Byte-parity entrypoint: same behavior as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    global ROOT, BASE_DIR
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:5]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd().resolve()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        resolved = path.resolve()
        try:
            rel = resolved.relative_to(cwd)
            parts = rel.parts
        except ValueError:
            rel = path.name
            parts = ()
        if any(part in SKIP_DIRS for part in parts):
            continue
        for line_no, col, code in scan_file_findings(path):
            yield {
                "rule": "elixir.taint.open_redirect",
                "path": str(rel),
                "line": line_no,
                "col": col,
                "layer": "taint",
                "lang": "elixir",
                "severity": "critical",
                "message": f"{_MESSAGE} ({code})",
            }


def _selftest_direct_redirect(tmp_prefix: str = "ubs_core_taint_elixir_redir_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "redirect_to.ex"
        target.write_text(
            "def redirect_to(conn, params) do\n"
            "  target = params[\"url\"]\n"
            "  redirect(conn, external: target)\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "elixir.taint.open_redirect", findings
    assert findings[0]["line"] == 3, findings
    assert findings[0]["col"] == 3, findings
    assert findings[0]["severity"] == "critical", findings
    assert "params[ -> redirect" in findings[0]["message"], findings


def _selftest_local_path_validation_suppression(tmp_prefix: str = "ubs_core_taint_elixir_redir_local_") -> None:
    import tempfile

    code = (
        "def redirect_to(conn, params) do\n"
        "  target = params[\"url\"]\n"
        "  unless String.starts_with?(target, \"/\") and not String.starts_with?(target, \"//\") do\n"
        "    raise \"untrusted redirect\"\n"
        "  end\n"
        "  redirect(conn, external: target)\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe_redirect.ex"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert findings == [], findings


def _selftest_ignore_comment_suppression(tmp_prefix: str = "ubs_core_taint_elixir_redir_ign_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ex"
        target.write_text(
            "# ubs:ignore\n"
            "target = params[\"url\"]\n"
            "redirect(conn, external: target)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_elixir_redir_main_") -> None:
    import tempfile
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "redirect_to.ex"
        target.write_text(
            "def redirect_to(conn, params) do\n"
            "  target = params[\"url\"]\n"
            "  redirect(conn, external: target)\n"
            "end\n",
            encoding="utf-8",
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main(["x", tmp])
        assert rc == 0
        out = buffer.getvalue()
    assert out == (
        "__COUNT__\t1\n"
        "__SAMPLE__\tredirect_to.ex\t3\tredirect(conn, external: target)  [params[ -> redirect]\n"
    ), repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_redirect", _selftest_direct_redirect),
    ("local_path_validation_suppression", _selftest_local_path_validation_suppression),
    ("ignore_comment_suppression", _selftest_ignore_comment_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="elixir", name="taint_elixir_redirect", run=run, selftests=SELF_TESTS))
