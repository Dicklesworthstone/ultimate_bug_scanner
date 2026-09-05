"""ubs_core.py_detectors.xml_parser_security — category 7 unsafe XML (bead 0xjg.5).

Port of run_xml_parser_security_checks (modules/ubs-python.sh 8259-8525): an
ast.NodeVisitor tracking unsafe XML module aliases (xml.etree.ElementTree,
xml.dom.minidom, xml.sax, lxml.etree) versus defusedxml imports, then
flagging (a) lxml XMLParser constructors with dangerous flags
(resolve_entities/load_dtd/huge_tree on, no_network off) and (b) unsafe
fromstring/XML/parseString/parse calls fed request/stream/stdin-derived
data (with a small taint tracker over request/data/body/files markers).

Same-file and previous-line `ubs:ignore` markers suppress a hit; the
heredoc keeps NO line dedupe here, so a line can carry several records —
preserved verbatim.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.xml-parser"
CATEGORY = 7
TITLE = "Unsafe XML parser on untrusted input"
SEVERITY = "critical"
DESCRIPTION = "Use defusedxml or disable DTD/entity resolution before parsing request, upload, or stdin XML"

UNSAFE_MODULES = {
    'xml.etree.ElementTree',
    'xml.dom.minidom',
    'xml.sax',
    'lxml.etree',
}
SAFE_MODULE_PREFIXES = ('defusedxml',)
PARSE_FUNCS = {'fromstring', 'XML', 'parseString', 'parse'}
STRING_PARSE_FUNCS = {'fromstring', 'XML', 'parseString'}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ''


def _const_value(node):
    return node.value if isinstance(node, ast.Constant) else None


def _is_enabled(node):
    value = _const_value(node)
    if value is True:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 1:
        return True
    if isinstance(value, str) and value.strip().lower() in {'1', 'true', 'yes', 'on'}:
        return True
    return False


def _is_disabled(node):
    value = _const_value(node)
    if value is False:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 0:
        return True
    if isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'}:
        return True
    return False


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
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []


def _expr_text(node):
    try:
        return ast.unparse(node).lower()
    except Exception:
        return ''


class _XmlSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.issues = []
        self.unsafe_aliases = set()
        self.safe_aliases = set()
        self.unsafe_functions = set()
        self.safe_functions = set()
        self.tainted = set()

    def remember_issue(self, line_no):
        if _has_ignore(self.lines, line_no):
            return
        self.issues.append(line_no)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name.startswith(SAFE_MODULE_PREFIXES):
                self.safe_aliases.add(local)
            elif alias.name in UNSAFE_MODULES or alias.name == 'lxml.etree':
                self.unsafe_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            full_name = f'{module}.{alias.name}' if module else alias.name
            if module.startswith(SAFE_MODULE_PREFIXES):
                self.safe_aliases.add(local)
                self.safe_functions.add(local)
            elif module == 'lxml' and alias.name == 'etree':
                self.unsafe_aliases.add(local)
            elif full_name in UNSAFE_MODULES or module in UNSAFE_MODULES:
                if alias.name in PARSE_FUNCS or alias.name == 'XMLParser':
                    self.unsafe_functions.add(local)
                else:
                    self.unsafe_aliases.add(local)
            elif module == 'xml.etree' and alias.name == 'ElementTree':
                self.unsafe_aliases.add(local)
        self.generic_visit(node)

    def is_untrusted_expr(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Attribute):
            name = _call_name(node).lower()
            return (
                'request.' in name and name.rsplit('.', 1)[-1] in {'data', 'body', 'text', 'content', 'files', 'stream'}
            ) or name in {'sys.stdin', 'stdin'}
        if isinstance(node, ast.Subscript):
            name = _call_name(node.value).lower()
            return 'request.files' in name or 'request.files' in _expr_text(node) or self.is_untrusted_expr(node.value)
        if isinstance(node, ast.Call):
            name = _call_name(node.func).lower()
            text = _expr_text(node)
            if name in {'input', 'raw_input', 'sys.stdin.read', 'stdin.read'}:
                return True
            if 'request.' in name and name.endswith(('.get_data', '.get_json', '.read')):
                return True
            if name.endswith('.read') and any(marker in text for marker in ('request', 'upload', 'file', 'stream', 'stdin')):
                return True
            return any(self.is_untrusted_expr(arg) for arg in node.args)
        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.JoinedStr, ast.Tuple, ast.List, ast.Set)):
            return any(self.is_untrusted_expr(child) for child in ast.iter_child_nodes(node))
        return False

    def is_safe_name(self, name):
        first = name.split('.', 1)[0]
        return first in self.safe_aliases or name in self.safe_functions or name.startswith('defusedxml.')

    def is_unsafe_parse_call(self, name):
        if not name or self.is_safe_name(name):
            return False
        if name in self.unsafe_functions:
            return True
        if '.' not in name:
            return False
        prefix, func = name.rsplit('.', 1)
        first = prefix.split('.', 1)[0]
        if func not in PARSE_FUNCS:
            return False
        if first in self.unsafe_aliases:
            return True
        return any(prefix.endswith(module) for module in UNSAFE_MODULES)

    def is_lxml_parser_call(self, name):
        if not name or self.is_safe_name(name):
            return False
        if name in self.unsafe_functions and name.endswith('XMLParser'):
            return True
        if not name.endswith('.XMLParser'):
            return False
        prefix = name.rsplit('.', 1)[0]
        first = prefix.split('.', 1)[0]
        return first in self.unsafe_aliases or prefix.endswith('lxml.etree')

    def parser_has_dangerous_flags(self, node):
        for keyword in node.keywords:
            if keyword.arg in {'resolve_entities', 'load_dtd', 'huge_tree'} and _is_enabled(keyword.value):
                return True
            if keyword.arg == 'no_network' and _is_disabled(keyword.value):
                return True
        return False

    def visit_Assign(self, node):
        if self.is_untrusted_expr(node.value):
            for target in node.targets:
                self.tainted.update(_target_names(target))
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and self.is_untrusted_expr(node.value):
            self.tainted.update(_target_names(node.target))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        if self.is_lxml_parser_call(name) and self.parser_has_dangerous_flags(node):
            self.remember_issue(node.lineno)
        if self.is_unsafe_parse_call(name) and node.args:
            func = name.rsplit('.', 1)[-1]
            if func in STRING_PARSE_FUNCS and self.is_untrusted_expr(node.args[0]):
                self.remember_issue(node.lineno)
            elif func == 'parse' and self.is_untrusted_expr(node.args[0]):
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
        analyzer = _XmlSecurityAnalyzer(path, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
