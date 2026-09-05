"""ubs_core.py_detectors.redos_regex — category 7 request-controlled regex (bead 0xjg.5).

Port of run_regex_dos_checks (modules/ubs-python.sh 1669-1928): an ast
.NodeVisitor that flags re/regex module sinks (compile, match, fullmatch,
search, findall, finditer, split, sub, subn) and pandas .str.<op>(regex=...)
calls whose pattern argument contains request/sys.argv/os.environ/input()
derived data. re.escape (and from re import escape) or fully literal patterns
sanitize; per-file assignment tracking marks safe vs tainted pattern names.

Same-file and previous-line `ubs:ignore` markers suppress a hit; a per-file
`seen` line set dedupes repeats (legacy remember_issue).
"""
from __future__ import annotations

import ast
from typing import Iterable, Sequence

RULE_ID = "py.security.redos-regex"
CATEGORY = 7
TITLE = "Request-controlled regex pattern reaches regex engine"
SEVERITY = "critical"
DESCRIPTION = ("Use fixed allow-listed regexes or escape user input with re.escape "
               "before building patterns")

REGEX_SINKS = {'compile', 'match', 'fullmatch', 'search', 'findall', 'finditer', 'split', 'sub', 'subn'}
PANDAS_REGEX_SINKS = {'contains', 'match', 'fullmatch', 'replace', 'extract', 'extractall', 'split'}
REQUEST_NAMES = {'request'}


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


def keyword_value(node, name):
    for keyword in getattr(node, 'keywords', []):
        if keyword.arg == name:
            return keyword.value
    return None


def is_false(node):
    return isinstance(node, ast.Constant) and node.value is False


def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES
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


class RegexPatternAnalyzer(ast.NodeVisitor):
    def __init__(self, text, lines):
        self.text = text
        self.lines = lines
        self.regex_modules = {'re', 'regex'}
        self.regex_functions = {}
        self.escape_functions = set()
        self.tainted_patterns = set()
        self.safe_patterns = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in {'re', 'regex'}:
                self.regex_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in {'re', 'regex'}:
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in REGEX_SINKS:
                    self.regex_functions[local] = alias.name
                elif alias.name == 'escape':
                    self.escape_functions.add(local)
        self.generic_visit(node)

    def is_regex_escape_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        if name in self.escape_functions:
            return True
        parts = name.split('.')
        return len(parts) >= 2 and parts[-1] == 'escape' and parts[-2] in self.regex_modules

    def expr_is_sanitized_regex(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_patterns
        if self.is_regex_escape_call(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_sanitized_regex(node.left) and self.expr_is_sanitized_regex(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_sanitized_regex(value.value):
                    continue
                return False
            return True
        if isinstance(node, ast.Call) and call_name(node.func) in {'str', 'bytes'} and node.args:
            return self.expr_is_sanitized_regex(node.args[0])
        return False

    def expr_contains_untrusted_pattern(self, node):
        if self.expr_is_sanitized_regex(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_patterns
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_untrusted_pattern(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_sanitized_regex(value)
        is_tainted = (not is_safe) and self.expr_contains_untrusted_pattern(value)
        for name in names:
            if is_safe:
                self.safe_patterns.add(name)
            else:
                self.safe_patterns.discard(name)
            if is_tainted:
                self.tainted_patterns.add(name)
            else:
                self.tainted_patterns.discard(name)

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

    def regex_pattern_arg(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        parts = name.split('.')
        if isinstance(node.func, ast.Name) and node.func.id in self.regex_functions:
            return node.args[0] if node.args else keyword_value(node, 'pattern')
        if len(parts) >= 2 and parts[-1] in REGEX_SINKS and parts[-2] in self.regex_modules:
            return node.args[0] if node.args else keyword_value(node, 'pattern')
        if short in PANDAS_REGEX_SINKS and '.str.' in f'.{name}.':
            regex_keyword = keyword_value(node, 'regex')
            if regex_keyword is not None and is_false(regex_keyword):
                return None
            return node.args[0] if node.args else keyword_value(node, 'pat')
        return None

    def visit_Call(self, node):
        pattern = self.regex_pattern_arg(node)
        if pattern is not None and self.expr_contains_untrusted_pattern(pattern):
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
        analyzer = RegexPatternAnalyzer(text, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, source_line(lines, line_no)[:240]
