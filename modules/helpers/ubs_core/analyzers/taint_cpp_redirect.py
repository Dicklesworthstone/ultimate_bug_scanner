"""C/C++ redirect dataflow with value-bound, branch-specific URL proof."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.analyzers.taint_cpp_traversal import Engine
from ubs_core.taint_flow import CLEAN, Trace, join, retag

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|getHost|get_host|host|'
    r'target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:host|target|raw_url|url)\b'
    r'|\b(?:FCGX_GetParam)\s*\('
    r'|\bgetenv\s*\(\s*"(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_REFERER|HTTP_REFERRER|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|getHost|get_host|host|'
    r'target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:cgiFormString|FCGX_GetParam|getenv)\s*\('
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:res|resp|response|reply|http_response|httpResponse|ctx|context)(?:\.|->)\s*'
    r'(?:redirect|Redirect|sendRedirect|setRedirect|set_redirect)\s*\('
    r'|\b(?:redirect|send_redirect|sendRedirect|http_redirect|httpRedirect)\s*\('
    r'|\b(?:set_header|setHeader|add_header|addHeader|header|set)\s*\([^;\n]*(?:"Location"|\'Location\')\s*,'
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:set_header|setHeader|add_header|addHeader|header|set)\s*\([^;\n]*(?:"Location"|\'Location\')\s*,'
    r'|\b(?:headers|response_headers|resp_headers)\s*\[\s*(?:"Location"|\'Location\')\s*\]\s*='
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:headers|response_headers|resp_headers)\s*\[\s*(?:"Location"|\'Location\')\s*\]\s*=',
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

LOCAL_TAGS = frozenset({'url-slash', 'url-not-network', 'url-no-backslash',
                       'url-no-cr', 'url-no-lf', 'url-no-tab'})


class RedirectEngine(Engine):
    source_re, sink_re = SOURCE_RE, SINK_RE
    sink_label = 'redirect'
    rule = 'cpp.taint.open_redirect'

    def safe(self, trace):
        return ('url-constant' in trace.tags or LOCAL_TAGS <= trace.tags or
            (LOCAL_TAGS - {'url-slash', 'url-not-network'} | {'url-https', 'url-host'}) <= trace.tags)

    def constant_string(self, name, state, bindings):
        value = state.get(bindings.get(name, name), CLEAN)
        literals = {trace.key[0] for trace in value if trace.kind == 'constant'}
        return next(iter(literals)) if len(literals) == 1 and all(trace.kind == 'constant' for trace in value) else None

    def assigned_value(self, start, offset, low, high, value, state, bindings):
        declaration = self.parser.compact(start, offset)
        if (declaration.startswith('conststd::unordered_set<std::string>') or
                declaration.startswith('conststd::set<std::string>')):
            if self.parser.value(low) == '{' and self.parser.pairs.get(low) == high - 1:
                hosts = tuple(self.literal(a, b) for a, b in self.parser.parts(low + 1, high - 1))
                if hosts and all(host is not None and re.fullmatch(r'[A-Za-z0-9.-]+', host) for host in hosts):
                    return frozenset({Trace('allowlist', (offset, hosts), frozenset({'literal-hosts'}))})
        return value

    def external_call(self, name, spans, arguments, receiver, offset, state, bindings):
        member = re.fullmatch(r'([A-Za-z_]\w*)\.(find|substr)', name)
        if member and len(spans) == 2:
            root, method = member.groups()
            binding = bindings.get(root, root)
            original = state.get(binding, CLEAN)
            if method == 'find' and self.literal(*spans[0]) == '/':
                prefix = re.fullmatch(r'([A-Za-z_]\w*)\.size\(\)', self.parser.compact(*spans[1]))
                if prefix and self.constant_string(prefix.group(1), state, bindings) == 'https://':
                    relation = Trace('host-end', (binding, self.fingerprint(original), prefix.group(1)))
                    return join(self.without_proof(original), frozenset({relation}))
            if method == 'substr':
                prefix = re.fullmatch(r'([A-Za-z_]\w*)\.size\(\)', self.parser.compact(*spans[0]))
                length = re.fullmatch(r'([A-Za-z_]\w*)-([A-Za-z_]\w*)\.size\(\)', self.parser.compact(*spans[1]))
                if (prefix and length and prefix.group(1) == length.group(2)
                        and self.constant_string(prefix.group(1), state, bindings) == 'https://'):
                    end_value = state.get(bindings.get(length.group(1), length.group(1)), CLEAN)
                    identity = (binding, self.fingerprint(original), prefix.group(1))
                    if any(trace.kind == 'host-end' and trace.key == identity for trace in end_value):
                        relation = Trace('host', identity)
                        return join(self.without_proof(original), frozenset({relation}))
        return super().external_call(name, spans, arguments, receiver, offset, state, bindings)

    def call_sink(self, name, spans, arguments, offset, receiver=CLEAN):
        method = re.split(r'::|\.|->', name)[-1]
        targets = []
        if method in {'redirect', 'Redirect', 'sendRedirect', 'setRedirect', 'set_redirect',
                      'http_redirect', 'httpRedirect'}:
            targets = [0]
        elif method == 'send_redirect':
            targets = [len(arguments) - 1]
        elif method in {'set_header', 'setHeader', 'add_header', 'addHeader', 'header', 'set'}:
            if len(spans) >= 2 and self.literal(*spans[0]) == 'Location':
                targets = [1]
        for index in targets:
            if 0 <= index < len(arguments):
                self.record(offset, arguments[index])

    def atomic_guard(self, start, end):
        import json

        raw = self.parser.compact(start, end)
        result = []
        check = re.fullmatch(r'([A-Za-z_]\w*)\.(starts_with|rfind)\(("(?:[^"\\]|\\.)*")(?:,0)?\)(?:(==|!=)(0|false|true|std::string::npos))?', raw)
        if check:
            name, method, quoted, operator, compared = check.groups()
            try:
                literal = json.loads(quoted)
            except ValueError:
                literal = None
            truth = True if method == 'starts_with' and operator is None else None
            if method == 'rfind' and compared == '0':
                truth = operator == '=='
            elif method == 'starts_with' and compared in {'true', 'false', '0'}:
                truth = (compared == 'true') == (operator == '==')
            if truth is not None and literal in {'/', '//', 'https://'}:
                result.append((not truth if literal == '//' else truth,
                    (name, {'/': 'url-slash', '//': 'url-not-network', 'https://': 'url-https'}[literal])))
        check = re.fullmatch(r'([A-Za-z_]\w*)\.rfind\(([A-Za-z_]\w*),0\)(==|!=)0', raw)
        if check:
            result.append((check.group(3) == '==', ('https-prefix', check.group(1), check.group(2))))
        check = re.fullmatch(r'([A-Za-z_]\w*)\.find\(([A-Za-z_]\w*)\)(==|!=)\1\.end\(\)', raw)
        if check:
            result.append((check.group(3) == '!=', ('host-allowlist', check.group(1), check.group(2))))
        check = re.fullmatch(r'([A-Za-z_]\w*)\.(find|find_first_of)\(("(?:[^"\\]|\\.)*")\)(==|!=)std::string::npos', raw)
        if check:
            name, method, quoted, operator = check.groups()
            try:
                characters = json.loads(quoted)
            except ValueError:
                characters = ''
            if method == 'find_first_of' or len(characters) == 1:
                for char, tag in (('\\', 'url-no-backslash'), ('\r', 'url-no-cr'), ('\n', 'url-no-lf'), ('\t', 'url-no-tab')):
                    if char in characters:
                        result.append((operator == '==', (name, tag)))
        check = re.fullmatch(r'([A-Za-z_]\w*)(==|!=)("(?:[^"\\]|\\.)*")', raw)
        if check:
            try:
                literal = json.loads(check.group(3))
            except ValueError:
                literal = ''
            if (literal.startswith('/') and not literal.startswith('//')
                    and not any(char in literal for char in '\\\r\n\t')):
                result.append((check.group(2) == '==', (check.group(1), 'url-constant')))
        return result

    def apply_guard(self, guard, state, bindings):
        if guard[0] == 'https-prefix':
            _, name, prefix = guard
            if self.constant_string(prefix, state, bindings) != 'https://':
                return state
            guard = name, 'url-https'
        if guard[0] == 'host-allowlist':
            _, allowlist, host = guard
            hosts = state.get(bindings.get(allowlist, allowlist), CLEAN)
            if not hosts or not all(trace.kind == 'allowlist' and 'literal-hosts' in trace.tags for trace in hosts):
                return state
            value = state.get(bindings.get(host, host), CLEAN)
            for trace in value:
                if trace.kind != 'host':
                    continue
                target, identity, prefix = trace.key
                original = state.get(target, CLEAN)
                if (self.fingerprint(original) == identity and
                        self.constant_string(prefix, state, bindings) == 'https://'):
                    state[target] = retag(original, add=frozenset({'url-host'}))
            return state
        name, tag = guard
        binding = bindings.get(name, name)
        state[binding] = retag(state.get(binding, CLEAN), add=frozenset({tag}))
        return state

    def transfer(self, action, state):
        kind, span, bindings, guard, reads = action
        if kind == 'simple':
            start, end = span
            raw = self.parser.raw(start, end)
            location = re.match(r'(?:[A-Za-z_]\w*(?:\.|->))?(?:headers|response_headers|resp_headers)\s*\[\s*"Location"\s*\]\s*=', raw)
            if location:
                equals = next(i for i in self.top_tokens(start, end) if self.parser.value(i) == '=')
                self.record(start, self.expression(equals + 1, end, state, reads))
                return state
        return super().transfer(action, state)


def analyze(path, issues):
    text = path.read_text(encoding='utf-8')
    if not (REQUEST_COLLECTION_RE.search(text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    for line, fact in sorted(RedirectEngine(path, text).analyze().items()):
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        source = witness.evidence[0].label if witness.evidence else 'request source'
        issues.append((relpath(path), line, f"{source_line(lines, line)}  [{source} -> redirect]"))


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


_KIND = "open_redirect"
_SEVERITY = "critical"
_MESSAGE = "Unvalidated redirect from request data"


def _path_desc(code: str) -> str:
    """Recover the taint-flow description from an analyze() sample row."""
    if "  [" in code and code.endswith("]"):
        return code.rsplit("  [", 1)[1][:-1]
    return code


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR
    cwd = Path.cwd()
    BASE_DIR = cwd
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        if not ctx.rule_enabled('cpp.taint.open_redirect'):
            continue
        rel = path.resolve()
        issues = []
        analyze(path, issues)
        for _rel, line_no, code in issues:
            yield {
                "rule": f"cpp.taint.{_KIND}",
                "path": str(rel),
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "cpp",
                "severity": _SEVERITY,
                "message": f"{_MESSAGE} ({_path_desc(code)})",
            }


def _selftest_direct_redirect(tmp_prefix: str = "ubs_core_taint_cpp_redir_") -> None:
    import tempfile

    code = (
        "std::string url = req.getParam(\"next\");\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "cpp.taint.open_redirect", findings
    assert findings[0]["line"] == 2, findings
    assert "req.getParam -> redirect" in findings[0]["message"], findings


def _selftest_inverted_guard_is_unsafe(tmp_prefix: str = "ubs_core_taint_cpp_redir_val_") -> None:
    import tempfile

    code = (
        "std::string url = req.getParam(\"next\");\n"
        "if (url.starts_with(\"/\") && !url.starts_with(\"//\")) return false;\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert [(finding['rule'], finding['line']) for finding in findings] == [
        ('cpp.taint.open_redirect', 3)], findings


def _selftest_unknown_sanitizer_is_unsafe(tmp_prefix: str = "ubs_core_taint_cpp_redir_san_") -> None:
    import tempfile

    code = (
        "std::string url = validate_redirect_target(req.getParam(\"next\"));\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert [(finding['rule'], finding['line']) for finding in findings] == [
        ('cpp.taint.open_redirect', 2)], findings


def _selftest_selected_literal_helper(tmp_prefix: str = "ubs_core_taint_cpp_redir_fixed_") -> None:
    import tempfile

    code = (
        'std::string destination(std::string input) { return "/home"; }\n'
        'void handle(Request& req, Response& res) {\n'
        '  auto url = destination(req.getParam("next"));\n'
        '  res.redirect(url);\n'
        '}\n'
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_cpp_redir_main_") -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "std::string url = req.getParam(\"next\");\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["taint_cpp_redirect.py", tmp])
    out = buf.getvalue()
    assert rc == 0, rc
    assert out == (
        "__COUNT__\t1\n"
        "__SAMPLE__\tmain.cpp\t2\tres.redirect(url);  [req.getParam -> redirect]\n"
    ), repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_redirect", _selftest_direct_redirect),
    ("inverted_guard_is_unsafe", _selftest_inverted_guard_is_unsafe),
    ("unknown_sanitizer_is_unsafe", _selftest_unknown_sanitizer_is_unsafe),
    ("selected_literal_helper", _selftest_selected_literal_helper),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="cpp", name="taint_cpp_redirect", run=run, selftests=SELF_TESTS))
