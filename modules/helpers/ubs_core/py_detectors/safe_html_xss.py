"""ubs_core.py_detectors.safe_html_xss — category 7 safe-HTML XSS (bead 0xjg.5).

Port of run_safe_html_xss_checks (modules/ubs-python.sh 7584-7851): an
ast.NodeVisitor flagging mark_safe/Markup/SafeString/SafeText calls whose
arguments carry request, stdin, argv, or environ taint. Local names holding
constants, escaped/sanitized values, or pure compositions of those are
tracked as "safe"; assignments from untrusted sources are tracked as
"tainted", with per-function scoping. Import aliases for markupsafe, flask,
jinja2, and django.utils.safestring/html extend the sink/sanitizer tables.

Same-file and previous-line `ubs:ignore` markers suppress a hit, with
per-file line dedupe, exactly like the heredoc.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.safe-html-xss"
CATEGORY = 7
TITLE = "Request-controlled value marked as safe HTML"
SEVERITY = "critical"
DESCRIPTION = ("Escape with html.escape()/markupsafe.escape(), sanitize with "
               "bleach/nh3, or render as normal escaped template context "
               "instead of marking user input safe")

REQUEST_NAMES = {'request'}
SAFE_HTML_SINKS = {
    'mark_safe', 'django.utils.safestring.mark_safe',
    'SafeString', 'django.utils.safestring.SafeString',
    'SafeText', 'django.utils.safestring.SafeText',
    'Markup', 'markupsafe.Markup', 'flask.Markup', 'jinja2.Markup',
}
HTML_SAFE_FUNCS = {
    'html.escape', 'markupsafe.escape', 'flask.escape',
    'django.utils.html.escape', 'conditional_escape',
    'django.utils.html.conditional_escape',
    'bleach.clean', 'nh3.clean', 'sanitize_html', 'clean_html',
    'sanitize_fragment',
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


class _SafeHtmlXssAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted_values = set()
        self.safe_values = set()
        self.safe_html_sinks = set(SAFE_HTML_SINKS)
        self.html_safe_funcs = set(HTML_SAFE_FUNCS)
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name in {'markupsafe', 'flask', 'jinja2', 'django.utils.safestring', 'django.utils.html'}:
                self.safe_html_sinks.add(f'{local}.Markup')
                self.safe_html_sinks.add(f'{local}.mark_safe')
                self.safe_html_sinks.add(f'{local}.SafeString')
                self.safe_html_sinks.add(f'{local}.SafeText')
                self.html_safe_funcs.add(f'{local}.escape')
                self.html_safe_funcs.add(f'{local}.conditional_escape')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            qualified = f'{module}.{alias.name}' if module else alias.name
            if qualified in SAFE_HTML_SINKS or alias.name in SAFE_HTML_SINKS:
                self.safe_html_sinks.add(local)
            if qualified in HTML_SAFE_FUNCS or alias.name in HTML_SAFE_FUNCS:
                self.html_safe_funcs.add(local)
        self.generic_visit(node)

    def call_is_html_safe_func(self, node):
        name = _call_name(node)
        short = name.rsplit('.', 1)[-1]
        return name in self.html_safe_funcs or ('.' not in name and short in self.html_safe_funcs)

    def expr_is_html_safe(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            if self.call_is_html_safe_func(node.func):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return self.expr_is_html_safe(node.func.value) and all(
                    self.expr_is_html_safe(arg) for arg in node.args
                ) and all(self.expr_is_html_safe(keyword.value) for keyword in node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_html_safe(node.left) and self.expr_is_html_safe(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_html_safe(value.value):
                    continue
                return False
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self.expr_is_html_safe(elt) for elt in node.elts)
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_html_safe(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if _direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_html_safe(value)
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
        names = [name for target in node.targets for name in _target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = _target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if (name in self.safe_html_sinks or short in self.safe_html_sinks) and any(
            self.expr_contains_taint(arg) for arg in node.args
        ):
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
        analyzer = _SafeHtmlXssAnalyzer(path, text, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
