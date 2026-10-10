"""Java/Kotlin redirect policy on the existing finite JVM flow frontend.

Only selected helper bodies and dominating, value-specific URL checks prove
safety. Names, filesystem transformations and unrelated checks confer no trust.
The frontend's unsupported/budget errors remain explicit incomplete analysis.
"""
from __future__ import annotations

from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
import re
import sys
from pathlib import Path
import json
from ubs_core.analyzers.taint_java_traversal import Engine
from ubs_core.taint_flow import CLEAN, advance, join, retag
from ubs_core.suppression import SourceSuppressions

SKIP_DIRS = {'.git', '.gradle', '.mvn', 'build', 'target', 'out', 'node_modules', '.cache'}

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getRequestURI|getRequestURL|getServletPath|'
    r'getPathInfo|getHeader|getServerName|getServerPort|getRemoteHost|getRemoteAddr|'
    r'getLocalName|getLocalAddr|queryParam|queryParams|pathParam|pathParams|formParam|formParams)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters|headers)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall)\.request\.(?:path|uri|local|host|port|origin|queryParameters|headers|header)\s*(?:\(|\[|\b|\.get\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters|headers)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam|'
    r'FormParam|MatrixParam)\b(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?)*\s+'
    r'(?:final\s+)?(?:String|URI|URL|Object|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\.\s*sendRedirect\s*\('
    r'|\.\s*respondRedirect\s*\('
    r'|\.\s*redirect\s*\('
    r'|\bnew\s+(?:RedirectView|ModelAndView)\s*\('
    r'|\b(?:RedirectView|ModelAndView)\s*\('
    r'|\breturn\s+["\']redirect:'
    r'|\.\s*(?:setHeader|addHeader|header|add)\s*\(\s*["\']Location["\']\s*,',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.java', '.kt', '.kts'}:
            yield root
        return
    for suffix in ('*.java', '*.kt', '*.kts'):
        for path in root.rglob(suffix):
            if path.is_file() and not should_skip(path):
                yield path

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

LOCAL_TAGS = frozenset({'url-slash', 'url-not-network', 'url-no-backslash', 'url-no-cr', 'url-no-lf', 'url-no-tab'})


class RedirectEngine(Engine):
    source_re, sink_re = SOURCE_RE, SINK_RE
    sink_label = 'redirect sink'
    path_constructors = False

    def __init__(self, path, text):
        super().__init__(path, text)
        self.uri_builtin = self.builtin_type('URI')
        self.host_sets = set()
        declarations = re.finditer(
            r'\bprivate\s+(?:(?:static|final)\s+)*(?:Set\s*<\s*String\s*>\s+|val\s+)'
            r'([A-Za-z_]\w*)\s*=\s*(?:Set\.of|setOf)\s*\(([^()]*)\)', text)
        for declaration in declarations:
            name, content = declaration.group(1, 2)
            if self.code[declaration.start():declaration.start() + len('private')] != 'private':
                continue
            if (' val ' not in ' ' + declaration.group() and not re.search(r'\bfinal\b', declaration.group())):
                continue
            if (not self.builtin_type('Set') or any(function.name == 'setOf' for function in self.parser.functions.values())
                    or re.search(r'\bimport\s+(?!kotlin\.collections\.setOf\b)[\w.]+\.setOf\b|\bimport\s+[\w.]+\s+as\s+setOf\b', self.code)):
                continue
            if not re.fullmatch(r'\s*"[A-Za-z0-9.-]+"(?:\s*,\s*"[A-Za-z0-9.-]+")*\s*', content):
                continue
            uses = [m for m in re.finditer(r'\b' + re.escape(name) + r'\b', self.code)
                    if not declaration.start() <= m.start() < declaration.end()]
            if all(re.match(r'\s*\.contains\s*\(', self.code[m.end():]) or
                   re.search(r'\bin\s*$', self.code[max(0, m.start() - 8):m.start()]) for m in uses):
                owner = tuple(owner for low, high, owner in self.parser.owners if low < declaration.start() < high)
                self.host_sets.add((owner, name))

    def safe(self, trace):
        tags = trace.tags
        uri = any(tag.startswith('uri:') for tag in tags)
        return (LOCAL_TAGS <= tags or (uri and 'uri-text' in tags and (
                {'uri-https', 'uri-host'} <= tags or
                {'uri-relative', 'uri-no-authority', 'uri-path-slash', 'uri-path-not-network', 'uri-text-not-network'} <= tags)))

    def record(self, offset, value):
        unsafe = frozenset(trace for trace in value if not self.safe(trace))
        if unsafe:
            self.effects[offset] = join(self.effects.get(offset, CLEAN), advance(unsafe, self.step(offset, 'sink', self.sink_label)))

    def summary_effect(self, summary, fact):
        return fact

    def summary_return(self, fact, offset):
        # A URI constructor inside a helper may execute at several call sites.
        # Keep those objects distinct when propagating a checked path alias.
        return join(*(retag(frozenset({trace}), add=frozenset({'uri-call:' + str(offset)}))
                      if any(tag.startswith('uri:') for tag in trace.tags) else frozenset({trace}) for trace in fact))

    def uri_identity(self, trace):
        return trace.kind, trace.key, frozenset(tag for tag in trace.tags if tag.startswith(('uri:', 'uri-call:')))

    def without_proof(self, value):
        return retag(value, remove=frozenset(tag for trace in value for tag in trace.tags if tag != 'jvm-string'))

    def source(self, offset, label):
        value = super().source(offset, label)
        return value if label.startswith('@request') else retag(value, add=frozenset({'jvm-string'}))

    def external_call(self, name, arguments, value, offset, bindings, state):
        if self.source_re.search(name + '('):
            return retag(self.without_proof(value), add=frozenset({'jvm-string'}))
        if name == 'java.net.URI.create' or (name == 'URI.create' and self.uri_builtin and 'URI' not in bindings):
            return retag(self.without_proof(value), add=frozenset({'uri:' + str(offset), 'uri-value'}), remove=frozenset({'jvm-string'}))
        root, _, method = name.rpartition('.')
        receiver = state.get(bindings.get(root, root), CLEAN)
        if not arguments and receiver and method in {'toString', 'getPath', 'getRawAuthority', 'getScheme', 'getHost', 'isAbsolute'}:
            if all('uri-value' in trace.tags or (method == 'toString' and 'jvm-string' in trace.tags) for trace in receiver):
                return receiver
        return retag(self.without_proof(value), remove=frozenset({'jvm-string'}))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if arguments and name in {'toString', 'getPath', 'getRawAuthority', 'getScheme', 'getHost', 'isAbsolute'}:
            return retag(self.without_proof(value), remove=frozenset({'jvm-string'}))
        if name in {'getPath', 'path'}:
            return join(*(retag(frozenset({trace}), add=frozenset({'uri-path', 'jvm-string'}), remove=frozenset({'uri-value', 'uri-text'}))
                          if 'uri-value' in trace.tags else self.without_proof(frozenset({trace})) for trace in value))
        if name == 'toString':
            return join(*(retag(frozenset({trace}), add=frozenset({'uri-text', 'jvm-string'}), remove=frozenset({'uri-value', 'uri-path'}))
                          if 'uri-value' in trace.tags else frozenset({trace}) for trace in value))
        if name == 'create':
            return value
        if name in {'getRawAuthority', 'getScheme', 'getHost', 'isAbsolute', 'rawAuthority', 'scheme', 'host'}:
            return retag(value, remove=frozenset({'uri-value', 'uri-text', 'uri-path'}))
        return self.without_proof(value)

    def expression(self, start, end, state, bindings, depth=0):
        prefix = re.match(r'\s*"redirect:"\s*\+', self.text[start:end])
        if prefix:
            start += prefix.end()
        value = super().expression(start, end, state, bindings, depth)
        if '+' in self.code[start:end]:
            value = self.without_proof(value)
        return value

    def call_sink(self, name, call, value, offset, bindings):
        spans, argument_names, arguments = call.spans, call.names, call.values
        method = name.rsplit('.', 1)[-1]
        target = None
        if method in {'sendRedirect', 'respondRedirect', 'redirect', 'RedirectView'}:
            target = 0
            if method == 'respondRedirect' and 'url' in argument_names:
                target = argument_names.index('url')
        elif method == 'ModelAndView' and spans and re.match(r'\s*"redirect:', self.text[slice(*spans[0])]):
            target = 0
        elif method in {'setHeader', 'addHeader', 'header', 'add'} and len(spans) >= 2:
            if self.text[slice(*spans[0])].strip().casefold() == '"location"':
                target = 1
        if target is not None and target < len(arguments):
            self.record(offset, arguments[target])
        return False

    def guard_facts(self, span):
        start, end = span
        while start < end and self.text[start].isspace():
            start += 1
        while end > start and end > 0 and self.text[end - 1].isspace():
            end -= 1
        if self.code[start:start + 1] == '(' and self.parser.pairs.get(start) == end - 1:
            return self.guard_facts((start + 1, end - 1))
        cursor = start
        for operator, truth in (('||', False), ('&&', True)):
            cursor, beginning, parts = start, start, []
            while cursor < end:
                if cursor in self.parser.pairs:
                    cursor = self.parser.pairs[cursor] + 1
                elif self.code.startswith(operator, cursor):
                    parts.append((beginning, cursor))
                    cursor += 2
                    beginning = cursor
                else:
                    cursor += 1
            if parts:
                parts.append((beginning, end))
                return [(truth, guard) for part in parts for positive, guard in self.guard_facts(part) if positive == truth]
        if self.code[start:start + 1] == '!':
            return [(not truth, guard) for truth, guard in self.guard_facts((start + 1, end))]
        raw = self.text[start:end].strip()
        checks = []
        check = re.fullmatch(r'([A-Za-z_]\w*)(\.(?:getPath\(\)|path|toString\(\)))?\.(startsWith|contains)\s*\(\s*("(?:[^"\\]|\\.)*")\s*\)', raw)
        if check:
            name, member, method, quoted = check.groups()
            try:
                literal = json.loads(quoted)
            except ValueError:
                return []
            proof = {('startsWith', '/'): (True, 'url-slash'), ('startsWith', '//'): (False, 'url-not-network'),
                     ('contains', '\\'): (False, 'url-no-backslash'), ('contains', '\r'): (False, 'url-no-cr'),
                     ('contains', '\n'): (False, 'url-no-lf'), ('contains', '\t'): (False, 'url-no-tab')}.get((method, literal))
            if proof:
                checks.append((proof[0], (name, proof[1], 'text' if member == '.toString()' else 'path' if member else None, None)))
        absolute = re.fullmatch(r'([A-Za-z_]\w*)\.(?:isAbsolute\(\)|isAbsolute)', raw)
        if absolute:
            checks.extend([(True, (absolute.group(1), 'uri-absolute', False, None)),
                           (False, (absolute.group(1), 'uri-relative', False, None))])
        authority = re.fullmatch(r'([A-Za-z_]\w*)\.(?:getRawAuthority\(\)|rawAuthority)\s*(==|!=)\s*null', raw)
        if authority:
            checks.append((authority.group(2) == '==', (authority.group(1), 'uri-no-authority', False, None)))
        scheme = re.fullmatch(r'"https"\.equals\(([A-Za-z_]\w*)\.getScheme\(\)\)|([A-Za-z_]\w*)\.scheme\s*==\s*"https"', raw)
        if scheme:
            checks.append((True, (scheme.group(1) or scheme.group(2), 'uri-https', False, None)))
        host = re.fullmatch(r'([A-Za-z_]\w*)\.contains\(([A-Za-z_]\w*)\.getHost\(\)\)|([A-Za-z_]\w*)\.host\s+in\s+([A-Za-z_]\w*)', raw)
        if host:
            allowlist, uri = (host.group(1), host.group(2)) if host.group(1) else (host.group(4), host.group(3))
            if (self.function.owner, allowlist) in self.host_sets:
                checks.append((True, (uri, 'uri-host', False, allowlist)))
        return checks

    def apply_guard(self, guard, state, bindings):
        name, tag, member, allowlist = guard
        if allowlist in bindings:
            return state
        binding = bindings.get(name, name)
        original = state.get(binding, CLEAN)
        state[binding] = join(*(retag(frozenset({trace}), add=frozenset({tag}))
                               if not member and (('jvm-string' in trace.tags if tag.startswith('url-') else 'uri-value' in trace.tags))
                               else frozenset({trace}) for trace in original))
        for representation in ('path', 'text'):
            identities = {self.uri_identity(trace) for trace in original
                       if (member == representation and 'uri-value' in trace.tags) or (not member and 'uri-' + representation in trace.tags)
                       if any(part.startswith('uri:') for part in trace.tags)}
            if identities and tag in {'url-slash', 'url-not-network'}:
                uri_tag = 'uri-' + representation + '-' + tag.removeprefix('url-')
                for key, fact in list(state.items()):
                    state[key] = join(*(retag(frozenset({trace}), add=frozenset({uri_tag}))
                                        if self.uri_identity(trace) in identities else frozenset({trace}) for trace in fact))
        return state

    def transfer(self, action, state):
        kind, span, bindings, guard, reads = action
        start, end = span
        if kind == 'return' and re.match(r'\s*return\s+"redirect:', self.text[start:end]):
            self.record(start, self.expression(start + self.code[start:end].index('return') + 6, end, state, bindings))
        result = super().transfer(action, state)
        assignment = self.assignment(span) if kind == 'simple' else None
        if assignment and assignment[4] == '+=':
            binding = bindings.get(assignment[0], assignment[0])
            result[binding] = self.without_proof(result.get(binding, CLEAN))
        return result


def analyze(path, issues):
    text = path.read_text(encoding='utf-8')
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and SINK_RE.search(text)):
        return
    engine = RedirectEngine(path, text)
    lines = text.splitlines()
    lang = 'kotlin' if path.suffix.lower() in {'.kt', '.kts'} else 'java'
    suppressions = SourceSuppressions(lang)
    for line, fact in sorted(engine.analyze().items()):
        if suppressions.is_suppressed(path, line, lang + '.taint.open_redirect'):
            continue
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        extras = {'taint_path': [step.record() for step in witness.evidence],
                  'source_count': len({trace.key for trace in fact})}
        issues.append((relpath(path), line, source_line(lines, line), extras))

def main(argv: list[str] | None = None) -> int:
    """Reproduce the module heredoc: `python3 - <project_dir> <<PY` emit dialect."""
    global ROOT, BASE_DIR

    argv = sys.argv if argv is None else list(argv)
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code, _extras in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_RUN_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR

    BASE_DIR = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".java", ".kt", ".kts"}:
            continue
        lang = 'kotlin' if path.suffix.lower() in {'.kt', '.kts'} else 'java'
        if not ctx.rule_enabled(lang + '.taint.open_redirect'):
            continue
        issues: list[tuple[str, int, str, dict]] = []
        analyze(path, issues)
        for rel_path, line_no, _sample, extras in issues:
            yield {
                "rule": "java.taint.open_redirect",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "severity": "critical",
                "message": _RUN_MESSAGE,
                "extras": extras,
            }


def _selftest_direct_source_to_redirect() -> None:
    import tempfile

    code = (
        "String target = request.getParameter(\"url\");\n"
        "response.sendRedirect(target);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_redirect_") as tmp:
        target_file = Path(tmp) / "A.java"
        target_file.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target_file])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "java.taint.open_redirect"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "String target = request.getParameter(\"url\");\n"
        "response.sendRedirect(target);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_redirect_") as tmp:
        target_file = Path(tmp) / "A.java"
        target_file.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target_file])))
    assert findings == [], findings


def _selftest_allowlist_guard_suppression() -> None:
    import tempfile

    code = (
        "String target = request.getParameter(\"url\");\n"
        'if (!(target.startsWith("/") && !target.startsWith("//") && !target.contains("\\\\")'
        ' && !target.contains("\\r") && !target.contains("\\n") && !target.contains("\\t"))) { throw new SecurityException("bad"); }\n'
        "response.sendRedirect(target);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_redirect_") as tmp:
        target_file = Path(tmp) / "A.java"
        target_file.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target_file])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_redirect", _selftest_direct_source_to_redirect),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("allowlist_guard_suppression", _selftest_allowlist_guard_suppression),
)

register(Analyzer(layer="taint", lang="java", name="taint_java_redirect", run=run, selftests=SELF_TESTS))
