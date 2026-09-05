"""ubs_core.py_detectors.header_injection — HTTP response header injection (bead 0xjg.5).

Port of run_header_injection_checks (modules/ubs-python.sh 2188-2491): a
taint-style ast.NodeVisitor flagging request-controlled values that reach
response header sinks — `resp.headers[...] = value` subscript assignments,
`.headers.add/set/setdefault/append/update` calls, response-factory
`headers=`/`response_headers=` dict keywords, and FileResponse-style
filename keywords (`download_name` family). A value is tainted when it roots
at `request` (or `*_request`), comes from input()/sys.stdin, or indexes
sys.argv/os.environ, unless it passes through a SAFE_HEADER_FUNCS sanitizer.
Function scopes reset the taint/safe tracking, exactly like the legacy
analyzer.

Same-file and previous-line `ubs:ignore` markers suppress a hit; hits dedupe
per line within a file (legacy `seen_lines`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.header-injection"
CATEGORY = 7
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = ("Reject CR/LF, use fixed header names, and encode filenames with "
               "framework-safe helpers before setting headers")

REQUEST_NAMES = {'request'}
HEADER_DICT_KEYWORDS = {'headers', 'response_headers'}
FILENAME_KEYWORDS = {'download_name', 'attachment_filename', 'filename', 'as_attachment_filename'}
HEADER_METHODS = {'add', 'set', 'setdefault', 'append', 'update'}
RESPONSE_FACTORIES = {
    'Response', 'flask.Response', 'make_response', 'flask.make_response',
    'HttpResponse', 'django.http.HttpResponse',
    'JsonResponse', 'django.http.JsonResponse',
    'StreamingHttpResponse', 'django.http.StreamingHttpResponse',
    'HTMLResponse', 'PlainTextResponse', 'JSONResponse',
    'starlette.responses.HTMLResponse', 'starlette.responses.PlainTextResponse',
    'starlette.responses.JSONResponse', 'fastapi.responses.HTMLResponse',
    'fastapi.responses.PlainTextResponse', 'fastapi.responses.JSONResponse',
    'FileResponse', 'django.http.FileResponse',
    'RedirectResponse', 'starlette.responses.RedirectResponse',
}
FILE_RESPONSE_FACTORIES = {
    'send_file', 'flask.send_file', 'FileResponse', 'django.http.FileResponse',
    'starlette.responses.FileResponse', 'fastapi.responses.FileResponse',
}
SAFE_HEADER_FUNCS = {
    'secure_filename', 'werkzeug.utils.secure_filename',
    'quote', 'urllib.parse.quote', 'quote_plus', 'urllib.parse.quote_plus',
    'urlquote', 'url_quote', 'escape_uri_path', 'iri_to_uri',
    'quote_header_value', 'sanitize_header_value', 'validate_header_value',
    'safe_header_value', 'clean_header_value',
}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ''


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return _rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return _rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return _rooted_at_request(node.value)
    return False


def _direct_untrusted_source(node):
    name = _call_name(node)
    if _rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and _call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False


def _keyword_values(node, names):
    return [keyword.value for keyword in getattr(node, 'keywords', []) if keyword.arg in names]


def _dict_values(node):
    if not isinstance(node, ast.Dict):
        return []
    return [value for key, value in zip(node.keys, node.values) if key is not None]


class _HeaderInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.tainted_values = set()
        self.safe_values = set()
        self.issue_lines = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issue_lines.append(line_no)

    def expr_is_safe_header(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_HEADER_FUNCS or short in SAFE_HEADER_FUNCS:
                return True
            if name in {'str', 'bytes'} and node.args:
                return self.expr_is_safe_header(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_header(node.left) and self.expr_is_safe_header(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_safe_header(value.value):
                    continue
                return False
            return True
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_safe_header(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if _direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_header(value)
        is_tainted = (not is_safe) and self.expr_contains_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
            else:
                self.safe_values.discard(name)
            if is_tainted:
                self.tainted_values.add(name)
            else:
                self.tainted_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.tainted_values)
        self.safe_values.clear()
        self.tainted_values.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.tainted_values = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        if any(self.assignment_target_is_header(target) for target in node.targets):
            if self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
        names = [name for target in node.targets for name in _target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            if self.assignment_target_is_header(node.target) and self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
            names = _target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def assignment_target_is_header(self, target):
        if not isinstance(target, ast.Subscript):
            return False
        owner = _call_name(target.value)
        header_name = _const_string(target.slice)
        if owner.endswith('.headers'):
            return True
        if header_name and (owner in HEADER_DICT_KEYWORDS or owner.endswith('_headers')):
            return True
        if header_name and any(part in owner.lower() for part in {'response', 'resp', 'httpresponse'}):
            return True
        if header_name and any(part in header_name.lower() for part in {'header', 'content-', 'location', 'etag', 'cache-control'}):
            return True
        return False

    def call_header_values(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        values = []
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if short in HEADER_METHODS and receiver is not None and _call_name(receiver).endswith('.headers'):
            if short == 'update':
                for arg in node.args:
                    if isinstance(arg, ast.Dict):
                        values.extend(_dict_values(arg))
                    else:
                        values.append(arg)
                values.extend(keyword.value for keyword in node.keywords)
            else:
                values.extend(node.args)
                values.extend(keyword.value for keyword in node.keywords if keyword.arg in {'value', 'default'})
        if name in RESPONSE_FACTORIES or short in RESPONSE_FACTORIES:
            for header_dict in _keyword_values(node, HEADER_DICT_KEYWORDS):
                if isinstance(header_dict, ast.Dict):
                    values.extend(_dict_values(header_dict))
                else:
                    values.append(header_dict)
        if name in FILE_RESPONSE_FACTORIES or short in FILE_RESPONSE_FACTORIES:
            values.extend(_keyword_values(node, FILENAME_KEYWORDS))
        return values

    def visit_Call(self, node):
        if any(self.expr_contains_taint(value) for value in self.call_header_values(node)):
            self.remember_issue(node.lineno)
        self.generic_visit(node)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        analyzer = _HeaderInjectionAnalyzer(lines)
        analyzer.visit(tree)
        for line_no in analyzer.issue_lines:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
