"""ubs_core.py_detectors.email_header_injection — email header injection (bead 0xjg.5).

Port of run_email_header_injection_checks (modules/ubs-python.sh 2493-2831): a
taint-style ast.NodeVisitor flagging request-controlled values that reach
email header or envelope sinks — email-constructor positional args and
subject/from/to/cc/bcc/reply_to/headers= keywords, django send_mail /
send_mass_mail / mail_admins / mail_managers, smtplib sendmail/send_message
envelope args, and `msg[...] = value` / add_header / replace_header calls.
A value is tainted when it roots at `request` (or `*_request`), comes from
input()/sys.stdin, or indexes sys.argv/os.environ, unless it passes through a
SAFE_EMAIL_FUNCS sanitizer or a `.format()` over safe parts. Function scopes
reset the taint/safe tracking, exactly like the legacy analyzer.

Same-file and previous-line `ubs:ignore` markers suppress a hit; hits dedupe
per line within a file (legacy `seen_lines`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.email-header-injection"
CATEGORY = 7
TITLE = "Request-controlled value reaches email header or envelope sink"
SEVERITY = "critical"
DESCRIPTION = ("Reject CR/LF, validate email addresses, and sanitize "
               "subject/from/to/cc/bcc/reply-to/custom headers before sending mail")

REQUEST_NAMES = {'request'}
EMAIL_CONSTRUCTORS = {
    'EmailMessage', 'django.core.mail.EmailMessage',
    'EmailMultiAlternatives', 'django.core.mail.EmailMultiAlternatives',
    'Message', 'flask_mail.Message',
}
SEND_MAIL_FUNCS = {
    'send_mail', 'django.core.mail.send_mail',
    'mail_admins', 'django.core.mail.mail_admins',
    'mail_managers', 'django.core.mail.mail_managers',
}
SEND_MASS_FUNCS = {'send_mass_mail', 'django.core.mail.send_mass_mail'}
SMTP_SEND_FUNCS = {'sendmail', 'send_message'}
EMAIL_HEADER_METHODS = {'add_header', 'replace_header'}
EMAIL_HEADER_NAMES = {
    'subject', 'from', 'to', 'cc', 'bcc', 'reply-to', 'sender',
    'return-path', 'resent-from', 'resent-to', 'resent-cc', 'resent-bcc',
}
HEADER_DICT_KEYWORDS = {'headers', 'extra_headers'}
EMAIL_VALUE_KEYWORDS = {
    'subject', 'from_email', 'from_addr', 'sender', 'recipient_list',
    'recipients', 'to', 'cc', 'bcc', 'reply_to', 'reply_to_email',
}
SAFE_EMAIL_FUNCS = {
    'sanitize_email_header', 'sanitize_email_address',
    'validate_email_header', 'validate_email_address',
    'allowlisted_email_address', 'allowlisted_email_header',
    'forbid_multi_line_headers', 'django.core.mail.message.forbid_multi_line_headers',
    'Header', 'email.header.Header',
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


class _EmailHeaderInjectionAnalyzer(ast.NodeVisitor):
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

    def expr_is_safe_email(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_EMAIL_FUNCS or short in SAFE_EMAIL_FUNCS:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return self.expr_is_safe_email(node.func.value) and all(
                    self.expr_is_safe_email(arg) for arg in node.args
                ) and all(self.expr_is_safe_email(keyword.value) for keyword in node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_email(node.left) and self.expr_is_safe_email(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_safe_email(value.value):
                    continue
                return False
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self.expr_is_safe_email(elt) for elt in node.elts)
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_safe_email(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if _direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_email(value)
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
        if any(self.assignment_target_is_email_header(target) for target in node.targets):
            if self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
        names = [name for target in node.targets for name in _target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            if self.assignment_target_is_email_header(node.target) and self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
            names = _target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def assignment_target_is_email_header(self, target):
        if not isinstance(target, ast.Subscript):
            return False
        owner = _call_name(target.value)
        header_name = _const_string(target.slice)
        if not header_name:
            return False
        owner_lower = owner.lower()
        header_lower = header_name.lower()
        if owner.endswith('_headers') and any(part in owner_lower for part in {'mail', 'email', 'mime', 'message'}):
            return True
        if any(part in owner_lower for part in {'msg', 'message', 'mail', 'email', 'mime'}):
            return header_lower in EMAIL_HEADER_NAMES or header_lower.startswith('x-')
        return False

    def constructor_values(self, node, short, name):
        values = []
        if short in EMAIL_CONSTRUCTORS or name in EMAIL_CONSTRUCTORS:
            if short == 'Message' or name == 'flask_mail.Message':
                arg_indexes = (0, 1, 4, 5, 6, 8, 11)
            elif short == 'EmailMultiAlternatives' or name == 'django.core.mail.EmailMultiAlternatives':
                arg_indexes = (0, 2, 3, 4, 8, 9)
            else:
                arg_indexes = (0, 2, 3, 4, 7, 8, 9)
            for idx in arg_indexes:
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(_keyword_values(node, EMAIL_VALUE_KEYWORDS))
            for header_dict in _keyword_values(node, HEADER_DICT_KEYWORDS):
                if isinstance(header_dict, ast.Dict):
                    values.extend(_dict_values(header_dict))
                else:
                    values.append(header_dict)
        return values

    def send_mail_values(self, node, short, name):
        values = []
        if short in SEND_MAIL_FUNCS or name in SEND_MAIL_FUNCS:
            for idx in (0, 2, 3):
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(_keyword_values(node, EMAIL_VALUE_KEYWORDS | HEADER_DICT_KEYWORDS))
        if short in SEND_MASS_FUNCS or name in SEND_MASS_FUNCS:
            if node.args:
                values.append(node.args[0])
            values.extend(_keyword_values(node, EMAIL_VALUE_KEYWORDS | HEADER_DICT_KEYWORDS))
        if short == 'sendmail':
            for idx in (0, 1):
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(_keyword_values(node, {'from_addr', 'to_addrs', 'sender', 'recipients', 'to'}))
        if short == 'send_message':
            for idx in (1, 2):
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(_keyword_values(node, {'from_addr', 'to_addrs', 'sender', 'recipients', 'to'}))
        return values

    def method_values(self, node, short):
        if short in EMAIL_HEADER_METHODS:
            return list(node.args[1:]) + [keyword.value for keyword in node.keywords]
        return []

    def visit_Call(self, node):
        name = _call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        values = []
        values.extend(self.constructor_values(node, short, name))
        values.extend(self.send_mail_values(node, short, name))
        values.extend(self.method_values(node, short))
        if values and any(self.expr_contains_taint(value) for value in values):
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
        analyzer = _EmailHeaderInjectionAnalyzer(lines)
        analyzer.visit(tree)
        for line_no in analyzer.issue_lines:
            yield path, line_no, 1, _source_line(lines, line_no)[:240]
