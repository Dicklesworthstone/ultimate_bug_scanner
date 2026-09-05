"""ubs_core.py_detectors.template_injection — category 7 server-side template injection (bead 0xjg.5).

Port of run_template_injection_checks (modules/ubs-python.sh 1930-2186): an
ast.NodeVisitor that flags jinja2/mako.template/django.template Template(...)
constructors, Jinja from_string(), and flask render_template_string() when the
template source argument carries request/sys.argv/os.environ/input()-derived
data (directly or through tainted names). Literal strings, constant-only
f-strings, and safe-name assignments do not trigger; function bodies start
with a clean tainted/safe slate (legacy visit_FunctionDef scope reset).

Same-file and previous-line `ubs:ignore` markers suppress a hit; a per-file
`seen` line set dedupes repeats (legacy remember_issue).
"""
from __future__ import annotations

import ast
from typing import Iterable, Sequence

RULE_ID = "py.security.template-injection"
CATEGORY = 7
TITLE = "Request-controlled template source reaches renderer"
SEVERITY = "critical"
DESCRIPTION = ("Render fixed templates and pass user data only as escaped context values")

REQUEST_NAMES = {'request'}
TEMPLATE_SOURCE_KEYWORDS = {'source', 'text', 'template', 'template_string', 'string'}


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []


def keyword_value(node, names):
    for keyword in getattr(node, 'keywords', []):
        if keyword.arg in names:
            return keyword.value
    return None


def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False


def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False


class TemplateInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, text, lines):
        self.text = text
        self.lines = lines
        self.template_modules = {'jinja2', 'mako.template', 'django.template'}
        self.template_constructors = {'Template'}
        self.render_template_string_names = {'render_template_string'}
        self.tainted_templates = set()
        self.safe_templates = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in {'jinja2', 'mako.template', 'django.template'}:
                self.template_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in {'flask'}:
            for alias in node.names:
                if alias.name == 'render_template_string':
                    self.render_template_string_names.add(alias.asname or alias.name)
        if node.module in {'jinja2', 'mako.template', 'django.template'}:
            for alias in node.names:
                if alias.name == 'Template':
                    self.template_constructors.add(alias.asname or alias.name)
        self.generic_visit(node)

    def expr_is_safe_template(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_templates
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_template(node.left) and self.expr_is_safe_template(node.right)
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(value, ast.Constant) for value in node.values)
        return False

    def expr_contains_untrusted_template(self, node):
        if self.expr_is_safe_template(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_templates
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_untrusted_template(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_template(value)
        is_tainted = (not is_safe) and self.expr_contains_untrusted_template(value)
        for name in names:
            if is_safe:
                self.safe_templates.add(name)
            else:
                self.safe_templates.discard(name)
            if is_tainted:
                self.tainted_templates.add(name)
            else:
                self.tainted_templates.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_templates)
        old_tainted = set(self.tainted_templates)
        self.safe_templates.clear()
        self.tainted_templates.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_templates = old_safe
        self.tainted_templates = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def constructor_template_source(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        parts = name.split('.')
        if (
            short in self.template_constructors
            or name in self.template_constructors
            or (len(parts) >= 2 and parts[-1] == 'Template' and '.'.join(parts[:-1]) in self.template_modules)
        ):
            return node.args[0] if node.args else keyword_value(node, TEMPLATE_SOURCE_KEYWORDS)
        return None

    def render_template_string_source(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if name in self.render_template_string_names or short in self.render_template_string_names:
            return node.args[0] if node.args else keyword_value(node, {'source', 'template_string', 'string'})
        if short == 'from_string':
            return node.args[0] if node.args else keyword_value(node, {'source', 'template_string', 'string'})
        return None

    def visit_Call(self, node):
        source = self.render_template_string_source(node) or self.constructor_template_source(node)
        if source is not None and self.expr_contains_untrusted_template(source):
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
        analyzer = TemplateInjectionAnalyzer(text, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, source_line(lines, line_no)[:240]
