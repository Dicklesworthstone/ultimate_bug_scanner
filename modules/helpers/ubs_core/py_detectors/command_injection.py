"""ubs_core.py_detectors.command_injection — category 7 command-injection dataflow (bead 0xjg.5).

Port of run_command_injection_checks (modules/ubs-python.sh 3108-3428):
an ast.NodeVisitor that tracks request-derived taint (request.args/form/json,
sys.argv, os.environ, input(), ...) through assignments and flags subprocess
and os execution sinks whose command or executable is a dynamic string
(f-string / format / % / concatenation), a tainted name, a `sh -c` payload, or
shell=True input. shlex.quote / pipes.quote sanitize a segment.

Same-file and previous-line `ubs:ignore` markers suppress a hit; a per-file
`seen` line set dedupes repeats (legacy remember_issue).
"""
from __future__ import annotations

import ast
import os
import re
from typing import Iterable, Sequence

RULE_ID = "py.security.command-injection"
CATEGORY = 7
TITLE = "User-controlled command reaches shell or executable selection"
SEVERITY = "critical"
DESCRIPTION = ("Use a fixed executable with argv arrays, validate command allow-lists "
               "before dispatch, and avoid shell=True or shell -c")

SUBPROCESS_CALLS = {'run', 'call', 'check_call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput'}
OS_COMMAND_CALLS = {'system', 'popen'}
OS_EXEC_CALLS = {'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execle', 'execlp', 'execlpe'}
OS_SPAWN_CALLS = {'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe'}
SHELL_NAMES = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'cmd', 'powershell', 'pwsh'}
SHELL_FLAGS = {'-c', '-lc', '/c', '-command', '-encodedcommand'}
SOURCE_RE = re.compile(
    r"(?:request\.(?:args|form|values|json|data|body|GET|POST|get_json)|"
    r"flask\.request|django\.http\.request|sys\.argv|os\.environ|"
    r"event\s*\[|params\s*\[|input\s*\(|raw_input\s*\()",
    re.IGNORECASE,
)
SANITIZER_RE = re.compile(r"\b(?:shlex\.quote|pipes\.quote)\s*\(", re.IGNORECASE)


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
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


def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def is_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def all_static_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return all_static_strings(node.left) and all_static_strings(node.right)
    return False


def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []


def shell_name(value):
    if not value:
        return ''
    return os.path.basename(value).lower()


class CommandInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, text, lines):
        self.text = text
        self.lines = lines
        self.subprocess_modules = {'subprocess'}
        self.os_modules = {'os'}
        self.direct_calls = {}
        self.tainted_names = set()
        self.shell_command_vars = set()
        self.executable_vars = set()
        self.issues = []
        self.seen_lines = set()

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def expr_is_sanitized(self, node):
        return bool(SANITIZER_RE.search(self.segment(node)))

    def expr_has_source(self, node):
        return bool(SOURCE_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def expr_is_tainted(self, node):
        if self.expr_is_sanitized(node):
            return False
        return self.expr_has_source(node) or bool(self.names_in(node) & self.tainted_names)

    def expr_is_dynamic_string(self, node):
        if self.expr_is_tainted(node):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(part, ast.FormattedValue) for part in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not all_static_strings(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return True
        return False

    def arg_is_shell_command(self, node):
        if isinstance(node, ast.Name) and node.id in self.shell_command_vars:
            return True
        return self.expr_is_dynamic_string(node)

    def executable_is_dynamic(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.executable_vars or node.id in self.tainted_names
        return self.expr_is_dynamic_string(node)

    def shell_c_payload(self, node):
        if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) < 3:
            return None
        executable = const_string(node.elts[0])
        flag = const_string(node.elts[1])
        if shell_name(executable) in SHELL_NAMES and flag and flag.lower() in SHELL_FLAGS:
            return node.elts[2]
        return None

    def list_executable_is_dynamic(self, node):
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            return self.executable_is_dynamic(node.elts[0])
        return False

    def canonical_call(self, node):
        name = call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for module in self.subprocess_modules:
            for func in SUBPROCESS_CALLS:
                if name == f'{module}.{func}':
                    return f'subprocess.{func}'
        for module in self.os_modules:
            for func in OS_COMMAND_CALLS | OS_EXEC_CALLS | OS_SPAWN_CALLS:
                if name == f'{module}.{func}':
                    return f'os.{func}'
        return ''

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'subprocess':
                self.subprocess_modules.add(local)
            elif alias.name == 'os':
                self.os_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'subprocess' and alias.name in SUBPROCESS_CALLS:
                self.direct_calls[local] = f'subprocess.{alias.name}'
            elif module == 'os' and alias.name in (OS_COMMAND_CALLS | OS_EXEC_CALLS | OS_SPAWN_CALLS):
                self.direct_calls[local] = f'os.{alias.name}'
        self.generic_visit(node)

    def mark_assignment(self, names, value):
        tainted = self.expr_is_tainted(value)
        shell_command = self.expr_is_dynamic_string(value)
        dynamic_executable = self.list_executable_is_dynamic(value)
        for name in names:
            if tainted:
                self.tainted_names.add(name)
            else:
                self.tainted_names.discard(name)
            if shell_command:
                self.shell_command_vars.add(name)
            else:
                self.shell_command_vars.discard(name)
            if dynamic_executable:
                self.executable_vars.add(name)
            else:
                self.executable_vars.discard(name)

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

    def subprocess_arg_is_unsafe(self, node):
        if not node.args:
            return False
        command = node.args[0]
        shell_payload = self.shell_c_payload(command)
        if shell_payload is not None:
            return self.arg_is_shell_command(shell_payload)
        if is_true(keyword_value(node, 'shell')):
            return self.arg_is_shell_command(command)
        return self.list_executable_is_dynamic(command) or (
            isinstance(command, ast.Name) and command.id in self.executable_vars
        )

    def os_exec_arg_is_unsafe(self, node, func):
        if func in OS_SPAWN_CALLS:
            executable_index = 1
        else:
            executable_index = 0
        if len(node.args) <= executable_index:
            return False
        return self.executable_is_dynamic(node.args[executable_index])

    def visit_Call(self, node):
        canonical = self.canonical_call(node)
        if canonical:
            module, func = canonical.rsplit('.', 1)
            unsafe = False
            if module == 'subprocess':
                if func in {'getoutput', 'getstatusoutput'}:
                    unsafe = bool(node.args and self.arg_is_shell_command(node.args[0]))
                else:
                    unsafe = self.subprocess_arg_is_unsafe(node)
            elif module == 'os' and func in OS_COMMAND_CALLS:
                unsafe = bool(node.args and self.arg_is_shell_command(node.args[0]))
            elif module == 'os' and func in (OS_EXEC_CALLS | OS_SPAWN_CALLS):
                unsafe = self.os_exec_arg_is_unsafe(node, func)
            if unsafe:
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
        analyzer = CommandInjectionAnalyzer(text, lines)
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            yield path, line_no, 1, source_line(lines, line_no)[:240]
