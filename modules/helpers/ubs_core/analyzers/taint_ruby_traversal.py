"""Scoped Ruby request flow for filesystem paths and outbound URLs.

The two policies share Ruby syntax, local bindings, a finite CFG solver and
argument-sensitive summaries. Unknown helper names propagate their arguments;
only the operations and dominating checks in a visible body establish safety.
Dynamic execution and request-derived state escaping a method are incomplete
analysis, never evidence that a scan is clean.
"""
from __future__ import annotations

import re
import sys
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Step, Trace, advance, join, retag, solve

ROOT = Path.cwd()
BASE_DIR = ROOT

SKIP_DIRS = {'.git', '.bundle', 'vendor', 'node_modules', 'tmp', 'log', 'coverage', '.cache', 'dist', 'build'}
EXTS = {'.rb', '.rake', '.ru', '.gemspec', '.erb', '.haml', '.slim', '.rbi', '.rbs', '.jbuilder'}

SOURCE_RE = re.compile(
    r'\b(?:params|request\.params)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:path|path_info|fullpath|original_fullpath|query_string|url)\b'
    r'|\b(?:request|req|rack_request)\.(?:get|post|params|query|POST|GET)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:headers|env)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.get_header\s*\('
    r'|\b(?:env|request\.env)\s*\[\s*[\'"](?:PATH_INFO|REQUEST_URI|QUERY_STRING|SCRIPT_NAME|HTTP_[A-Z0-9_]+)[\'"]\s*\]'
    r'|\bRack::Request\.new\s*\([^)]*\)\.params\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|\[)[A-Za-z_"\':][A-Za-z0-9_"\'\]:]*\]?\.(?:original_filename|filename)\b'
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:original_filename|filename)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bFile\.(?:read|binread|write|binwrite|open|delete|unlink|rename|chmod|chown|truncate|size|exist\?|directory\?|file\?)\s*\('
    r'|\bIO\.(?:read|binread|write|binwrite|open)\s*\('
    r'|\bFileUtils\.(?:cp|copy|mv|move|rm|remove|rm_f|rm_rf|remove_entry|mkdir|mkdir_p|touch|chmod|chown)\s*\('
    r'|\bDir\.(?:open|foreach|mkdir|entries|children|delete|rmdir)\s*\('
    r'|\b(?:send_file|serve_file|download_file|write_file_response)\s*\(?'
    r'|\brender\s+(?:file|template):',
)
PROOF_TAGS = frozenset({'url-host', 'url-scheme', 'contained-path'})
VALUE_TAGS = PROOF_TAGS | frozenset({'canonical-path', 'parsed-uri', 'basename-path', 'not-dot-name'})
RUBY_EXCEPTION_BASES = {
    'Exception': None, 'StandardError': 'Exception', 'RuntimeError': 'StandardError',
    'ArgumentError': 'StandardError', 'TypeError': 'StandardError', 'IOError': 'StandardError',
    'EOFError': 'IOError', 'IndexError': 'StandardError', 'KeyError': 'IndexError',
    'NameError': 'StandardError', 'NoMethodError': 'NameError', 'ZeroDivisionError': 'StandardError',
    'RangeError': 'StandardError', 'RegexpError': 'StandardError', 'SystemCallError': 'StandardError',
    'SecurityError': 'Exception', 'SystemExit': 'Exception', 'Interrupt': 'Exception',
    'ScriptError': 'Exception', 'SyntaxError': 'ScriptError', 'LoadError': 'ScriptError',
    'NotImplementedError': 'ScriptError', 'NoMemoryError': 'Exception', 'SystemStackError': 'Exception',
}

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

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement

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

@dataclass(frozen=True)
class RubyToken:
    value: str
    start: int
    end: int
    kind: str = 'code'
    parts: tuple = ()


class RubyLexer:
    """Keep literal contents out of code, but evaluate Ruby interpolation."""

    def __init__(self, text):
        self.text = text
        self.budget = Budget(max(1000, len(text) * 12))

    def quoted(self, start, limit, opener=None, closer=None, interpolate=None):
        text = self.text
        opener = opener or text[start]
        closer = closer or opener
        interpolate = opener != "'" if interpolate is None else interpolate
        cursor, nesting, parts = start + 1, 1, []
        while cursor < limit:
            self.budget.spend()
            if text[cursor] == '\\':
                cursor += 2
                continue
            if interpolate and text.startswith('#{', cursor):
                end = self.interpolation_end(cursor + 2, limit)
                parts.append(tuple(self.scan(cursor + 2, end)))
                cursor = end + 1
                continue
            if opener != closer and text[cursor] == opener:
                nesting += 1
            if text[cursor] == closer:
                nesting -= 1
                if nesting == 0:
                    return text[start + 1:cursor], tuple(parts), cursor + 1
            cursor += 1
        raise ValueError('Unterminated Ruby literal; analysis is incomplete')

    def interpolation_end(self, start, limit):
        cursor, depth = start, 1
        while cursor < limit:
            self.budget.spend()
            char = self.text[cursor]
            if char in "'\"`":
                _, _, cursor = self.quoted(cursor, limit)
                continue
            if char == '#':
                end = self.text.find('\n', cursor, limit)
                cursor = limit if end < 0 else end + 1
                continue
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if not depth:
                    return cursor
            cursor += 1
        raise ValueError('Unterminated Ruby interpolation; analysis is incomplete')

    def scan(self, start=0, limit=None):
        text, limit = self.text, len(self.text) if limit is None else limit
        output, cursor, heredocs = [], start, []
        while cursor < limit:
            self.budget.spend()
            if heredocs and cursor >= heredocs[0][0]:
                cursor = heredocs.pop(0)[1]
                continue
            char = text[cursor]
            if char in ' \t\r':
                cursor += 1
                continue
            if char == '#' or ((cursor == 0 or text[cursor - 1] == '\n') and text.startswith('=begin', cursor)):
                if char == '#':
                    end = text.find('\n', cursor, limit)
                else:
                    match = re.search(r'^=end\b[^\n]*', text[cursor:limit], re.MULTILINE)
                    if not match:
                        raise ValueError('Unterminated Ruby block comment; analysis is incomplete')
                    end = cursor + match.end()
                cursor = limit if end < 0 else end
                continue
            if char in "'\"`":
                body, parts, end = self.quoted(cursor, limit)
                kind = 'dynamic' if char == '`' else 'template' if parts else 'literal'
                output.append(RubyToken(body, cursor, end, kind, parts))
                cursor = end
                continue
            percent = re.match(r'%([qQwWrx])([^\w\s])', text[cursor:limit])
            if percent:
                form, opening = percent.groups()
                closing = {'[': ']', '{': '}', '(': ')', '<': '>'}.get(opening, opening)
                body, parts, end = self.quoted(cursor + 2, limit, opening, closing, form not in {'q', 'w'})
                kind = 'dynamic' if form == 'x' else 'template' if parts else 'words' if form in {'w', 'W'} else 'regex' if form == 'r' else 'literal'
                output.append(RubyToken(body, cursor, end, kind, parts))
                cursor = end
                continue
            heredoc = re.match(r'<<[-~]?(?:([\'\"])([A-Za-z_]\w*)\1|([A-Z][A-Z0-9_]*))', text[cursor:limit])
            if heredoc:
                marker = heredoc.group(2) or heredoc.group(3)
                body_start = text.find('\n', cursor, limit) + 1
                if not body_start:
                    raise ValueError('Unterminated Ruby heredoc; analysis is incomplete')
                if heredocs:
                    body_start = heredocs[-1][1]
                ending = re.search(r'^\s*' + re.escape(marker) + r'\s*$', text[body_start:limit], re.MULTILINE)
                if not ending:
                    raise ValueError('Unterminated Ruby heredoc; analysis is incomplete')
                body_end, skip_end = body_start + ending.start(), body_start + ending.end()
                parts, probe = [], body_start
                if heredoc.group(1) != "'":
                    while probe < body_end:
                        found = text.find('#{', probe, body_end)
                        if found < 0:
                            break
                        end = self.interpolation_end(found + 2, body_end)
                        parts.append(tuple(self.scan(found + 2, end)))
                        probe = end + 1
                output.append(RubyToken(text[body_start:body_end], cursor, cursor + heredoc.end(), 'template' if parts else 'literal', tuple(parts)))
                heredocs.append((text.find('\n', cursor, limit) + 1, skip_end))
                cursor += heredoc.end()
                continue
            if char == '/' and (not output or output[-1].value in {'=', '=~', '!~', '(', ',', 'return', 'when', '\n', ';'}):
                body, parts, end = self.quoted(cursor, limit, '/', '/', True)
                output.append(RubyToken(body, cursor, end, 'template' if parts else 'regex', parts))
                cursor = end
                continue
            word = re.match(r'(?:@@?|\$)?[A-Za-z_]\w*[!?]?', text[cursor:limit])
            number = re.match(r'\d+(?:\.\d+)?', text[cursor:limit])
            operator = re.match(r'\|\|=|&&=|\*\*|&\.|::|=>|==|!=|<=|>=|=~|!~|\|\||&&|\+=|-=|\*=|/=|\.\.|<<|>>', text[cursor:limit])
            match = word or number or operator
            end = cursor + (match.end() if match else 1)
            output.append(RubyToken(text[cursor:end], cursor, end, 'number' if number and not word else 'code'))
            cursor = end
        return output


def token_text(tokens):
    return ''.join(token.value if token.kind == 'code' else repr(token.value) for token in tokens)


def split_tokens(tokens, separators):
    """Split only executable, top-level delimiters (never string contents)."""
    depth, start, parts = 0, 0, []
    for index, token in enumerate(tokens):
        if token.kind != 'code':
            continue
        if token.value in {'(', '[', '{'}:
            depth += 1
        elif token.value in {')', ']', '}'}:
            depth -= 1
        elif depth == 0 and token.value in separators:
            parts.append(tuple(tokens[start:index]))
            start = index + 1
    return (*parts, tuple(tokens[start:]))


def closing_token(tokens, start):
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.kind != 'code':
            continue
        if token.value in {'(', '[', '{'}:
            stack.append(token.value)
        elif token.value in pairs:
            if not stack or stack.pop() != pairs[token.value]:
                raise ValueError('Unbalanced Ruby delimiters; analysis is incomplete')
            if not stack:
                return index
    raise ValueError('Unbalanced Ruby delimiters; analysis is incomplete')


def ungroup(tokens):
    tokens = tuple(token for token in tokens if token.value != '\n' or token.kind != 'code')
    while tokens and tokens[0].value == '(' and tokens[0].kind == 'code' and closing_token(tokens, 0) == len(tokens) - 1:
        tokens = tokens[1:-1]
    return tokens


@dataclass
class RubyStatement:
    kind: str
    tokens: tuple = ()
    body: tuple = ()
    alternate: tuple = ()
    names: tuple = ()
    handlers: tuple = ()
    finalizer: tuple = ()


@dataclass
class RubyFunction:
    key: int
    name: str
    owner: tuple
    parameters: tuple
    body: tuple
    singleton: bool = False
    scope: bool = False
    defaults: tuple = ()
    parameter_kinds: tuple = ()


class RubyParser:
    def __init__(self, text):
        self.tokens = RubyLexer(text).scan()
        self.position, self.depth = 0, 0
        self.functions, self.aliases = {}, {}
        self.singleton_scope = False
        body = self.block((), ())
        self.functions[-1] = RubyFunction(-1, '<script>', (), (), body, scope=True)

    def value(self):
        if self.position >= len(self.tokens):
            return ''
        token = self.tokens[self.position]
        return token.value if token.kind == 'code' else '<literal>'

    def separators(self):
        while self.value() in {'\n', ';', 'then'}:
            self.position += 1

    def take(self, stops=()):
        start, depth = self.position, 0
        while self.position < len(self.tokens):
            token = self.tokens[self.position]
            value = token.value if token.kind == 'code' else ''
            if not depth and value in {'\n', ';', 'then', 'end', 'else', 'elsif', *stops}:
                previous = self.tokens[self.position - 1].value if self.position > start else ''
                if previous in {'.', '&.'} and value not in {'\n', ';'}:
                    self.position += 1
                    continue
                if value == '\n' and previous in {'.', '&.', '&&', '||', '+', ',', '=', '\\'}:
                    self.position += 1
                    continue
                break
            if value in {'(', '[', '{'}:
                depth += 1
            elif value in {')', ']', '}'}:
                depth -= 1
            self.position += 1
        return tuple(self.tokens[start:self.position])

    def block(self, stops, owner):
        self.depth += 1
        if self.depth > 64:
            raise AnalysisLimit('Ruby block nesting limit exceeded; analysis is incomplete')
        body = []
        self.separators()
        while self.position < len(self.tokens) and self.value() not in stops:
            previous = self.position
            statement = self.statement(owner)
            if statement is not None:
                body.append(statement)
            if self.position == previous:
                raise ValueError('Unsupported Ruby block structure; analysis is incomplete')
            self.separators()
        self.depth -= 1
        return tuple(body)

    def end(self):
        if self.value() != 'end':
            raise ValueError('Unterminated Ruby block; analysis is incomplete')
        self.position += 1

    def branch(self, kind, owner):
        condition = self.take()
        self.separators()
        body = self.block({'else', 'elsif', 'end'}, owner)
        alternate = ()
        if self.value() == 'elsif':
            self.position += 1
            alternate = (self.branch('if', owner),)
            return RubyStatement(kind, condition, body, alternate)
        if self.value() == 'else':
            self.position += 1
            alternate = self.block({'end'}, owner)
        self.end()
        return RubyStatement(kind, condition, body, alternate)

    def exception_body(self, owner):
        """Parse explicit begin and Ruby's implicit method/block exception body."""
        body = self.block({'rescue', 'else', 'ensure', 'end'}, owner)
        handlers, alternate, finalizer = [], (), ()
        while self.value() == 'rescue':
            self.position += 1
            header = self.take()
            binding = split_tokens(header, {'=>'})
            names = ()
            if len(binding) > 2 or (len(binding) == 2 and
                    (len(binding[1]) != 1 or not re.fullmatch(r'[a-z_]\w*', binding[1][0].value))):
                raise ValueError('Unsupported Ruby exception binding; analysis is incomplete')
            if len(binding) == 2:
                names = (binding[1][0].value,)
            if binding[0] and not re.fullmatch(r'(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*(?:,(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*)*', token_text(binding[0])):
                raise ValueError('Dynamic Ruby rescue classes need dispatch analysis; analysis is incomplete')
            caught = self.block({'rescue', 'else', 'ensure', 'end'}, owner)
            handlers.append(RubyStatement('handler', header, caught, names=names))
        if self.value() == 'else':
            if not handlers:
                raise ValueError('Ruby exception else needs a rescue clause; analysis is incomplete')
            self.position += 1
            alternate = self.block({'ensure', 'end'}, owner)
        if self.value() == 'ensure':
            self.position += 1
            finalizer = self.block({'end'}, owner)
        self.end()
        if handlers or alternate or finalizer:
            return (RubyStatement('rescue', body=body, alternate=alternate,
                                  handlers=tuple(handlers), finalizer=finalizer),)
        return body

    def statement(self, owner):
        start, kind = self.position, self.value()
        if kind in {'class', 'module', 'def'}:
            self.position += 1
            header = self.take({'='} if kind == 'def' else ())
            if not header:
                raise ValueError('Unsupported Ruby definition; analysis is incomplete')
            if kind == 'def':
                opening = next((i for i, token in enumerate(header) if token.value == '('), None)
                name_end = opening if opening is not None else 1
                if opening is None and len(header) > 2 and header[1].value in {'.', '::'}:
                    name_end = 3
                name = token_text(header[:name_end])
                parameter_tokens = header[opening + 1:-1] if opening is not None else header[name_end:]
                parameter_parts = tuple(part for part in split_tokens(parameter_tokens, {','}) if part)
                parameters, defaults, kinds = [], [], []
                for part in parameter_parts:
                    if part[0].value in {'*', '**', '&'}:
                        parameters.append(part[1].value if len(part) > 1 else '<rest>')
                        defaults.append(())
                        kinds.append('rest')
                    else:
                        parameters.append(part[0].value)
                        keyword = len(part) > 1 and part[1].value == ':'
                        pieces = split_tokens(part, {'='})
                        defaults.append(part[2:] if keyword else pieces[1] if len(pieces) == 2 else ())
                        kinds.append('keyword' if keyword else 'positional')
                singleton = '.' in name or self.singleton_scope
                function_owner, method = owner, name
                if '.' in name:
                    receiver, method = name.rsplit('.', 1)
                    if receiver != 'self':
                        function_owner = (*owner, *receiver.split('::'))
                if self.value() == '=':
                    self.position += 1
                    body = (RubyStatement('simple', self.take()),)
                else:
                    self.separators()
                    body = self.exception_body(function_owner)
                key = self.tokens[start].start
                self.functions[key] = RubyFunction(key, method, function_owner, tuple(parameters), body, singleton,
                                                   defaults=tuple(defaults), parameter_kinds=tuple(kinds))
            else:
                if token_text(header) == '<<self':
                    previous = self.singleton_scope
                    self.singleton_scope = True
                    self.separators()
                    body = self.exception_body(owner)
                    self.singleton_scope = previous
                    return RubyStatement('block', body=body)
                name = token_text(split_tokens(header, {'<'})[0])
                child_owner = (*owner, *name.split('::'))
                previous = self.singleton_scope
                self.singleton_scope = False
                self.separators()
                body = self.exception_body(child_owner)
                self.singleton_scope = previous
                key = self.tokens[start].start
                self.functions[key] = RubyFunction(key, '<' + kind + '>', child_owner, (), body, scope=True)
            return None
        if kind in {'if', 'unless'}:
            self.position += 1
            return self.branch(kind, owner)
        if kind in {'while', 'until', 'for'}:
            self.position += 1
            condition = self.take({'do'})
            names = ()
            if kind == 'for':
                parts = split_tokens(condition, {'in'})
                if len(parts) != 2:
                    raise ValueError('Unsupported Ruby for binding; analysis is incomplete')
                names, condition = tuple(token.value for token in parts[0] if token.value != ','), parts[1]
            if self.value() == 'do':
                self.position += 1
            self.separators()
            body = self.block({'end'}, owner)
            self.end()
            return RubyStatement(kind, condition, body, names=names)
        if kind == 'begin':
            self.position += 1
            body = self.exception_body(owner)
            return RubyStatement('block', body=body)
        tokens = self.take({'do'})
        if any(tokens[index].value == '-' and tokens[index + 1].value == '>' for index in range(len(tokens) - 1)) or any(token.kind == 'code' and token.value in {'lambda', 'proc'} for token in tokens):
            raise ValueError('Ruby lambda/proc calls need closure binding analysis; analysis is incomplete')
        if kind in {'alias', 'alias_method'}:
            names = [token.value for token in tokens[1:] if token.kind == 'literal' or re.fullmatch(r'[A-Za-z_]\w*[!?]?', token.value)]
            if len(names) != 2:
                raise ValueError('Dynamic Ruby method aliases need binding analysis; analysis is incomplete')
            key = owner, self.singleton_scope, names[0]
            self.aliases.setdefault(key, set()).add(names[1])
            return None
        for index, token in enumerate(tokens):
            if token.kind == 'code' and token.value in {'(', '['}:
                # Braces inside a call argument or array are not outer blocks.
                continue
            if token.kind == 'code' and token.value == '{' and index > 0 and tokens[index - 1].value not in {'=', '=>', ':', ',', '('}:
                end = closing_token(tokens, index)
                if end != len(tokens) - 1:
                    break
                inner, names = tokens[index + 1:end], []
                if inner and inner[0].value == '|':
                    closing = next((i for i in range(1, len(inner)) if inner[i].value == '|'), None)
                    if closing is None:
                        raise ValueError('Unterminated Ruby block binding; analysis is incomplete')
                    names = [item.value for item in inner[1:closing] if item.value != ',']
                    inner = inner[closing + 1:]
                saved_tokens, saved_position = self.tokens, self.position
                self.tokens, self.position = list(inner), 0
                body = self.block((), owner)
                self.tokens, self.position = saved_tokens, saved_position
                return RubyStatement('iterate', tokens[:index], body, names=tuple(names))
        if self.value() == 'do':
            self.position += 1
            names = []
            if self.value() == '|':
                self.position += 1
                while self.value() and self.value() != '|':
                    if self.value() != ',':
                        names.append(self.value())
                    self.position += 1
                if self.value() != '|':
                    raise ValueError('Unterminated Ruby block parameters; analysis is incomplete')
                self.position += 1
            self.separators()
            body = self.exception_body(owner)
            return RubyStatement('iterate', tokens, body, names=tuple(names))
        if len(split_tokens(tokens, {'rescue'})) > 1:
            raise ValueError('Ruby modifier rescue needs expression binding analysis; analysis is incomplete')
        for modifier in ('unless', 'if', 'while', 'until'):
            parts = split_tokens(tokens, {modifier})
            if len(parts) == 2:
                return RubyStatement(modifier, parts[1], (RubyStatement('simple', parts[0]),))
        return RubyStatement('simple', tokens)


@dataclass
class RubySummary:
    returned: Fact = CLEAN
    effects: dict = field(default_factory=dict)
    mutations: dict = field(default_factory=dict)
    raised: Fact = CLEAN

    def merged(self, other):
        effects = dict(self.effects)
        for site, fact in other.effects.items():
            effects[site] = join(effects.get(site, CLEAN), fact)
        mutations = dict(self.mutations)
        for parameter, fact in other.mutations.items():
            mutations[parameter] = join(mutations.get(parameter, CLEAN), fact)
        return RubySummary(join(self.returned, other.returned), effects, mutations,
                           join(self.raised, other.raised))


def tainted(fact):
    return frozenset(trace for trace in fact if trace.kind in {'source', 'parameter'})


def constant(value, kind='literal'):
    return frozenset({Trace('constant', (kind, value))})


def shape(kind, offset):
    return frozenset({Trace('shape', (kind, offset))})


def has_shape(fact, kind):
    return any(trace.kind == 'shape' and trace.key[0] == kind for trace in fact)


class RubyEngine:
    def __init__(self, path, text, policy='path'):
        self.path, self.text, self.policy = path, text, policy
        self.parser = RubyParser(text)
        self.lines = [0, *(index + 1 for index, char in enumerate(text) if char == '\n')]
        self.budget, self.graphs = Budget(), {}
        self.contexts, self.summaries = {}, {}
        self.pending_raises = CLEAN
        self.constants = {}
        # Only unconditional, literal constant definitions can be an allowlist
        # or trusted root. A second definition invalidates that static proof.
        for function in self.parser.functions.values():
            if not function.scope:
                continue
            for statement in function.body:
                parts = split_tokens(statement.tokens, {'='})
                if statement.kind == 'simple' and len(parts) == 2 and len(parts[0]) == 1 and re.fullmatch(r'[A-Z]\w*', parts[0][0].value):
                    key = (function.owner, parts[0][0].value)
                    self.constants[key] = CLEAN if key in self.constants else self.literal(parts[1])
        for function in self.parser.functions.values():
            self.context(function, tuple(CLEAN for _ in function.parameters), entry=True)

    def step(self, offset, kind, label):
        offset = max(0, offset)
        line_index = bisect_right(self.lines, offset) - 1
        return Step(str(self.path), line_index + 1, offset - self.lines[line_index] + 1, kind, label[:160])

    def source(self, offset, label):
        return frozenset({Trace('source', (str(self.path), offset, label), evidence=(self.step(offset, 'source', label),))})

    def exception_value(self, value, kind):
        previous = frozenset(tag for trace in value for tag in trace.tags if tag.startswith('exception-type:'))
        return join(retag(tainted(value), add=frozenset({'exception-type:' + kind}),
                          remove=VALUE_TAGS | previous), frozenset({Trace('exception', (kind,))}))

    def literal(self, tokens):
        tokens = ungroup(tokens)
        if len(tokens) >= 2 and token_text(tokens[-2:]) == '.freeze':
            tokens = tokens[:-2]
        if len(tokens) == 1:
            token = tokens[0]
            if token.kind in {'literal', 'number'} or token.value in {'nil', 'true', 'false'}:
                return constant(token.value, token.kind)
            if token.kind == 'words':
                return join(*(constant(word) for word in token.value.split()), shape('literal-list', token.start))
        if tokens and tokens[0].value == '[' and closing_token(tokens, 0) == len(tokens) - 1:
            values = [self.literal(part) for part in split_tokens(tokens[1:-1], {','}) if part]
            if all(values):
                return join(*values, shape('literal-list', tokens[0].start))
        return CLEAN

    def context(self, function, arguments, entry=False):
        key = function.key, arguments, entry
        if key not in self.contexts:
            self.budget.spend()
            if len(self.contexts) >= 2048:
                raise AnalysisLimit('Ruby call-context limit exceeded; analysis is incomplete')
            self.contexts[key] = function
            self.summaries[key] = RubySummary()
        return key

    def candidates(self, name, count):
        owner, singleton, method = self.function.owner, self.function.singleton, name
        if name.startswith('self.'):
            method = name[5:]
        elif '.' in name:
            receiver, method = name.rsplit('.', 1)
            if not re.fullmatch(r'[A-Z]\w*(?:::[A-Z]\w*)*', receiver):
                return []
            owner, singleton = tuple(receiver.split('::')), True
        names, pending = {method}, [method]
        while pending:
            for alias in self.parser.aliases.get((owner, singleton, pending.pop()), ()):
                if alias not in names:
                    names.add(alias)
                    pending.append(alias)
        def accepts(function):
            if 'rest' in function.parameter_kinds:
                return True
            required = sum(not default for default in function.defaults) if function.defaults else len(function.parameters)
            return required <= count <= len(function.parameters)
        matches = [function for function in self.parser.functions.values()
                   if not function.scope and function.name in names and function.owner == owner
                   and function.singleton == singleton and accepts(function)]
        if not matches and '.' not in name and owner:
            matches = [function for function in self.parser.functions.values()
                       if not function.scope and function.name == name and not function.owner
                       and not function.singleton and accepts(function)]
        return matches

    def argument(self, tokens, state, depth):
        if len(tokens) >= 2 and tokens[0].kind == 'code' and tokens[1].value == ':' and re.fullmatch(r'[A-Za-z_]\w*', tokens[0].value):
            return join(self.expression(tokens[2:], state, depth), frozenset({Trace('keyword', (tokens[0].value,))}))
        if tokens and tokens[0].value in {'*', '**', '&'}:
            raise ValueError('Ruby expanded call arguments need argument binding analysis; analysis is incomplete')
        return self.expression(tokens, state, depth)

    def bind_arguments(self, function, arguments, state):
        if 'rest' in function.parameter_kinds:
            raise ValueError('Ruby rest/block parameters need argument binding analysis; analysis is incomplete')
        positional, keywords = [], {}
        for fact in arguments:
            labels = [trace.key[0] for trace in fact if trace.kind == 'keyword']
            plain = frozenset(trace for trace in fact if trace.kind != 'keyword')
            if labels:
                for label in labels:
                    keywords[label] = join(keywords.get(label, CLEAN), plain)
            else:
                positional.append(plain)
        bound, position, defaults_state = [], 0, dict(state)
        kinds = function.parameter_kinds or tuple('positional' for _ in function.parameters)
        defaults = function.defaults or tuple(() for _ in function.parameters)
        for name, kind, default in zip(function.parameters, kinds, defaults):
            if kind == 'keyword' and name in keywords:
                value = keywords.pop(name)
            elif kind == 'positional' and position < len(positional):
                value = positional[position]
                position += 1
            elif default:
                # Defaults execute in the callee, after earlier parameters.
                previous = self.function
                self.function = function
                try:
                    value = self.expression(default, defaults_state)
                finally:
                    self.function = previous
            else:
                return None
            bound.append(value)
            defaults_state[name] = value
        return tuple(bound) if position == len(positional) and not keywords else None

    def record(self, offset, value, operation=''):
        unsafe = frozenset(trace for trace in tainted(value)
                           if ('contained-path' not in trace.tags if self.policy == 'path'
                               else not {'url-host', 'url-scheme'} <= trace.tags)
                           and not (self.policy == 'path' and 'basename-path' in trace.tags
                                    and ('not-dot-name' in trace.tags or operation == 'send_file'
                                         or re.fullmatch(r'(?:File|IO)\.(?:read|binread|write|binwrite|open|truncate)', operation))))
        if unsafe:
            label = 'file sink' if self.policy == 'path' else 'outbound URL sink'
            self.effects[offset] = join(self.effects.get(offset, CLEAN), advance(unsafe, self.step(offset, 'sink', label)))

    def mutate(self, previous, value, state, name=None):
        """Weakly update visible aliases and selected helper argument effects."""
        identities = {(trace.kind, trace.key) for trace in previous if trace.kind != 'constant'}
        value = retag(join(previous, value), remove=VALUE_TAGS)
        value = frozenset(trace for trace in value
                          if not (trace.kind == 'shape' and trace.key[0] in {'literal-list', 'canonical-path'}))
        if has_shape(previous, 'uri'):
            value = retag(value, add=frozenset({'parsed-uri'}))
        for binding, fact in tuple(state.items()):
            if binding.startswith('@block:'):
                continue
            if binding == name or identities & {(trace.kind, trace.key) for trace in fact if trace.kind != 'constant'}:
                if binding and binding[0].isupper() and tainted(value):
                    raise ValueError('Request-derived Ruby constant mutation needs shared-state analysis; analysis is incomplete')
                # Preserve dependencies, but an alias may no longer rely on
                # the old canonical path or literal allowlist membership.
                state[binding] = value
        for index, fact in self.parameter_values.items():
            if identities & {(trace.kind, trace.key) for trace in fact if trace.kind != 'constant'}:
                self.mutations[index] = join(self.mutations.get(index, CLEAN), value)
        return value

    def call(self, name, receiver, arguments, token, state):
        candidates = self.candidates(name, len(arguments))
        instances = {trace.key[0] for trace in receiver if trace.kind == 'instance'}
        if instances:
            method = name.rsplit('.', 1)[-1]
            candidates = [function for function in self.parser.functions.values()
                          if not function.scope and not function.singleton and function.name == method
                          and function.owner in instances]
        if candidates:
            returned = CLEAN
            matched = False
            for function in candidates:
                values = self.bind_arguments(function, arguments, state)
                if values is None:
                    continue
                matched = True
                call = self.step(token.start, 'call', name + '()')
                bound = tuple(advance(value, call) for value in values)
                summary = self.summaries[self.context(function, bound)]
                returned = join(returned, advance(summary.returned, call))
                self.pending_raises = join(self.pending_raises, advance(summary.raised, call))
                for site, fact in summary.effects.items():
                    self.effects[site] = join(self.effects.get(site, CLEAN), fact)
                for index, fact in summary.mutations.items():
                    if index < len(values):
                        self.mutate(values[index], fact, state)
            if matched:
                return returned
            if any(tainted(argument) for argument in arguments):
                raise ValueError('Ruby selected helper arguments could not bind; analysis is incomplete')
        method = name.rsplit('.', 1)[-1]
        value = join(receiver, *arguments)
        self.pending_raises = join(self.pending_raises, self.exception_value(value, '*'))
        if method == 'new':
            owner = tuple(name.rsplit('.', 1)[0].split('::'))
            if any(function.scope and function.owner == owner for function in self.parser.functions.values()):
                instance = frozenset({Trace('instance', (owner, token.start))})
                initializers = [function for function in self.parser.functions.values()
                                if function.owner == owner and function.name == 'initialize' and not function.singleton]
                if initializers:
                    self.call(name + '.initialize', instance, arguments, token, state)
                elif any(tainted(argument) for argument in arguments):
                    raise ValueError('Ruby constructor arguments need visible initialization analysis; analysis is incomplete')
                return instance
        if receiver and (method.endswith('!') or method in {'push', 'append', 'prepend', 'concat', 'replace', 'clear', 'unshift', 'insert', 'update', 'delete', 'delete_at', 'delete_if'}):
            return self.mutate(receiver, join(*arguments), state, name.split('.', 1)[0])
        if method in {'eval', 'instance_eval', 'class_eval', 'module_eval', 'send', 'public_send', '__send__', 'define_method'} and tainted(value):
            raise ValueError(f'{self.path}:{self.step(token.start, "call", name).line}: Request-derived dynamic Ruby execution needs dispatch analysis; analysis is incomplete')
        if name == 'Rack::Request.new':
            return shape('request', token.start)
        if method in {'fetch', 'dig', '[]'} and (has_shape(receiver, 'request-params') or has_shape(receiver, 'request-headers') or has_shape(receiver, 'environment')):
            return self.source(token.start, name)
        if name in {'URI.parse', 'URI.join', 'Addressable::URI.parse', 'Addressable::URI.join', 'URI'}:
            return join(retag(value, add=frozenset({'parsed-uri'})), shape('uri', token.start))
        if name in {'File.expand_path', 'File.realpath', 'File.realdirpath'}:
            return join(retag(value, add=frozenset({'canonical-path'})), shape('canonical-path', token.start))
        if name == 'Pathname.new':
            return join(value, shape('pathname', token.start))
        if method in {'expand_path', 'realpath', 'realdirpath', 'cleanpath'} and has_shape(receiver, 'pathname'):
            return join(retag(value, add=frozenset({'canonical-path'})), shape('canonical-path', token.start))
        if self.policy == 'path' and (name == 'File.basename' or (method == 'basename' and has_shape(receiver, 'pathname'))):
            return retag(value, add=frozenset({'basename-path'}), remove=VALUE_TAGS - frozenset({'basename-path'}))
        if self.policy == 'path' and (name == 'File.join' or method == 'join' and has_shape(receiver, 'pathname')):
            # A final basename is a leaf only while no later path component
            # is appended. In particular basename('..') is still a directory.
            result = CLEAN
            for index, argument in enumerate(arguments):
                keep = frozenset({'basename-path', 'not-dot-name'}) if index == len(arguments) - 1 else frozenset()
                result = join(result, retag(argument, remove=VALUE_TAGS - keep))
            return join(retag(receiver, remove=VALUE_TAGS), result)
        if self.policy == 'url':
            is_sink = (name in {'URI.open', 'OpenURI.open', 'open'}
                       or re.fullmatch(r'Net::HTTP\.(?:get|get_response|post|post_form|start|new)', name)
                       or re.fullmatch(r'(?:Faraday|HTTParty|RestClient|Excon|HTTP|Typhoeus|Curl)\.(?:get|post|put|patch|delete|head|request)', name)
                       or method in {'get', 'request'})
            if is_sink and arguments:
                self.record(token.start, join(receiver, arguments[0]))
        else:
            sink = re.fullmatch(r'(File|IO|FileUtils|Dir)\.(\w+[!?]?)', name)
            indexes = ()
            if sink:
                group, operation = sink.groups()
                if operation in {'rename', 'cp', 'copy', 'mv', 'move'}:
                    indexes = (0, 1)
                elif operation in {'chmod', 'chown'}:
                    indexes = (len(arguments) - 1,)
                elif operation in {'read', 'binread', 'write', 'binwrite', 'open', 'delete', 'unlink', 'truncate', 'size', 'exist?', 'directory?', 'file?', 'rm', 'remove', 'rm_f', 'rm_rf', 'remove_entry', 'mkdir', 'mkdir_p', 'touch', 'foreach', 'entries', 'children', 'rmdir'}:
                    indexes = (0,)
            elif name in {'send_file', 'serve_file', 'download_file', 'write_file_response'}:
                indexes = (0,)
            elif name == 'render':
                indexes = tuple(range(len(arguments)))
            for index in indexes:
                if 0 <= index < len(arguments):
                    self.record(token.start, arguments[index], name)
        if method in {'message', 'full_message', 'to_s', 'to_str'} and any(trace.kind == 'exception' for trace in receiver):
            return frozenset(trace for trace in value if trace.kind != 'exception')
        if method in {'freeze', 'to_s', 'to_str'}:
            return value
        if method in {'host', 'hostname', 'scheme', 'path', 'query', 'fragment', 'port'}:
            return retag(value, remove=PROOF_TAGS)
        # Unknown calls are not validators. Preserve request dependencies while
        # discarding proofs that their result still has the checked value.
        return retag(value, remove=VALUE_TAGS)

    def expression(self, tokens, state, depth=0):
        if depth > 64:
            raise AnalysisLimit('Ruby expression depth limit exceeded; analysis is incomplete')
        tokens = ungroup(tokens)
        if not tokens:
            return CLEAN
        literal = self.literal(tokens)
        if literal:
            return literal
        shifted = split_tokens(tokens, {'<<'})
        if len(shifted) == 2:
            previous = self.expression(shifted[0], state, depth + 1)
            value = self.expression(shifted[1], state, depth + 1)
            name = shifted[0][0].value if len(shifted[0]) == 1 else None
            return self.mutate(previous, value, state, name)
        for operators in ({'=>', ':'}, {'||', 'or'}, {'&&', 'and'}, {'==', '!=', '=~', '!~', '<', '>', '<=', '>='}, {'+', '-', '*', '/', '..'}):
            parts = split_tokens(tokens, operators)
            if len(parts) > 1:
                return retag(join(*(self.expression(part, state, depth + 1) for part in parts)), remove=VALUE_TAGS)
        value, cursor = CLEAN, 0
        while cursor < len(tokens):
            self.budget.spend()
            token = tokens[cursor]
            if token.kind in {'template', 'dynamic'}:
                atom = retag(join(*(self.expression(part, state, depth + 1) for part in token.parts)), remove=VALUE_TAGS)
                if token.kind == 'dynamic' and tainted(atom):
                    raise ValueError('Request-derived Ruby command interpolation needs execution analysis; analysis is incomplete')
                cursor += 1
                name = ''
            elif token.kind in {'literal', 'number', 'words', 'regex'}:
                atom = self.literal((token,))
                cursor += 1
                name = ''
            elif token.value in {'(', '[', '{'}:
                end = closing_token(tokens, cursor)
                atom = join(*(self.expression(part, state, depth + 1) for part in split_tokens(tokens[cursor + 1:end], {','})))
                cursor, name = end + 1, ''
            elif re.fullmatch(r'(?:@@?|\$)?[A-Za-z_]\w*[!?]?', token.value):
                name, cursor = token.value, cursor + 1
                while cursor + 1 < len(tokens) and tokens[cursor].value == '::':
                    name += '::' + tokens[cursor + 1].value
                    cursor += 2
                atom = state.get(name, CLEAN)
                if cursor < len(tokens) and tokens[cursor].value == '(':
                    end = closing_token(tokens, cursor)
                    arguments = [self.argument(part, state, depth + 1) for part in split_tokens(tokens[cursor + 1:end], {','}) if part]
                    atom = self.call(name, CLEAN, arguments, token, state)
                    cursor = end + 1
                elif cursor < len(tokens) and tokens[cursor].value not in {'.', '&.', '[', '::', ',', ')', ']', '}'}:
                    arguments = [self.argument(part, state, depth + 1) for part in split_tokens(tokens[cursor:], {','}) if part]
                    atom = self.call(name, CLEAN, arguments, token, state)
                    cursor = len(tokens)
                elif name not in state and self.candidates(name, 0):
                    atom = self.call(name, CLEAN, [], token, state)
            else:
                cursor += 1
                continue
            while cursor < len(tokens):
                if tokens[cursor].value == '[':
                    end = closing_token(tokens, cursor)
                    arguments = [self.expression(part, state, depth + 1) for part in split_tokens(tokens[cursor + 1:end], {','})]
                    atom = self.call(name + '.[]', atom, arguments, token, state)
                    cursor = end + 1
                elif tokens[cursor].value in {'.', '&.'} and cursor + 1 < len(tokens):
                    member = tokens[cursor + 1]
                    name = name + '.' + member.value if name else member.value
                    cursor += 2
                    arguments = []
                    if cursor < len(tokens) and tokens[cursor].value == '(':
                        end = closing_token(tokens, cursor)
                        arguments = [self.argument(part, state, depth + 1) for part in split_tokens(tokens[cursor + 1:end], {','}) if part]
                        cursor = end + 1
                    elif cursor < len(tokens) and tokens[cursor].value not in {'.', '&.', '[', ',', ')', ']', '}'}:
                        arguments = [self.argument(part, state, depth + 1) for part in split_tokens(tokens[cursor:], {','}) if part]
                        cursor = len(tokens)
                    if has_shape(atom, 'request') and member.value in {'params', 'query', 'get', 'post', 'GET', 'POST'}:
                        atom = shape('request-params', member.start)
                    elif has_shape(atom, 'request') and member.value in {'headers', 'env'}:
                        atom = shape('request-headers' if member.value == 'headers' else 'environment', member.start)
                    elif has_shape(atom, 'request') and member.value in {'path', 'path_info', 'fullpath', 'original_fullpath', 'query_string', 'url', 'referer', 'referrer', 'host', 'host_with_port', 'raw_host_with_port', 'domain', 'subdomain', 'subdomains', 'port', 'remote_ip', 'ip', 'get_header'}:
                        atom = self.source(token.start, name)
                    elif member.value in {'filename', 'original_filename'} and self.policy == 'path':
                        atom = self.source(token.start, name)
                    else:
                        atom = self.call(name, atom, arguments, token, state)
                else:
                    break
            value = join(value, atom)
        return value

    def proof(self, tokens, truth, state):
        tokens = ungroup(tokens)
        if not tokens:
            return {}
        if tokens[0].value in {'!', 'not'}:
            return self.proof(tokens[1:], not truth, state)
        for operators, all_required in (({'||', 'or'}, not truth), ({'&&', 'and'}, truth)):
            parts = split_tokens(tokens, operators)
            if len(parts) > 1:
                proofs = [self.proof(part, truth, state) for part in parts]
                names = set().union(*(proof.keys() for proof in proofs))
                return {name: (frozenset().union(*(proof.get(name, frozenset()) for proof in proofs))
                               if all_required else frozenset.intersection(*(proof.get(name, frozenset()) for proof in proofs)))
                        for name in names}
        text = token_text(tokens)
        if self.policy == 'url':
            equal = split_tokens(tokens, {'==' if truth else '!='})
            if len(equal) == 2:
                for member, literal in (equal, equal[::-1]):
                    match = re.fullmatch(r'([A-Za-z_]\w*)\.(scheme|host|hostname)', token_text(member))
                    values = self.literal(literal)
                    if match and len(values) == 1:
                        item = next(iter(values))
                        if item.kind == 'constant' and item.key[0] == 'literal':
                            if match.group(2) == 'scheme' and item.key[1] in {'https', 'http'}:
                                return {match.group(1): frozenset({'url-scheme'})}
                            if match.group(2) != 'scheme' and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', item.key[1]):
                                return {match.group(1): frozenset({'url-host'})}
            if truth:
                member = re.search(r'\.include\?\(([A-Za-z_]\w*)\.(host|hostname|scheme)\)$', text)
                if member:
                    split = next((index for index in range(len(tokens) - 1) if tokens[index].value == '.' and tokens[index + 1].value == 'include?'), None)
                    if split is not None:
                        allowed = self.expression(tokens[:split], state)
                        constants = [trace.key[1] for trace in allowed if trace.kind == 'constant' and trace.key[0] == 'literal']
                        if has_shape(allowed, 'literal-list') and not tainted(allowed) and constants:
                            valid = all(value in {'https', 'http'} for value in constants) if member.group(2) == 'scheme' else all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value) for value in constants)
                            if valid:
                                return {member.group(1): frozenset({'url-scheme' if member.group(2) == 'scheme' else 'url-host'})}
        elif truth:
            prefix = re.fullmatch(r'([A-Za-z_]\w*)\.start_with\?\(([A-Za-z_]\w*)\+(?:File::SEPARATOR|[\'\"]/[\'\"])\)', text)
            equality = re.fullmatch(r'([A-Za-z_]\w*)==([A-Za-z_]\w*)', text)
            match = prefix or equality
            if match:
                name, base = match.groups()
                base_fact = state.get(base, CLEAN)
                if has_shape(base_fact, 'canonical-path') and not tainted(base_fact) and any(trace.kind == 'constant' for trace in base_fact):
                    return {name: frozenset({'contained-path'})}
        elif self.policy == 'path' and not truth:
            match = re.fullmatch(r"\['\.', '\.\.'\]\.include\?\(([A-Za-z_]\w*)\)", text)
            # token_text has no whitespace between array elements.
            match = match or re.fullmatch(r"\['\.','\.\.'\]\.include\?\(([A-Za-z_]\w*)\)", text)
            if match:
                return {match.group(1): frozenset({'not-dot-name'})}
        return {}

    def block_call(self, tokens):
        """Identify bounded receiver/block return contracts in a statement."""
        expression = ungroup(split_tokens(tokens, {'=', '+=', '-=', '||=', '&&='})[-1])
        members = split_tokens(expression, {'.', '&.'})
        if len(members) < 2 or not members[-1]:
            return None
        member = members[-1]
        method = member[0].value
        if method not in {'map', 'collect', 'each', 'tap', 'then', 'yield_self'}:
            return None
        if len(member) != 1 and token_text(member[1:]) != '()':
            raise ValueError('Ruby block-call arguments need selected iterator binding; analysis is incomplete')
        receiver = expression[:len(expression) - len(member) - 1]
        return method, receiver, expression

    def graph(self, function):
        actions, edges = {}, {}

        def node(kind, tokens=(), targets=(), extra=None):
            self.budget.spend()
            key = len(actions)
            actions[key], edges[key] = (kind, tokens, extra), tuple(targets)
            return key

        exit_node = node('exit')
        raise_exit = node('raise-exit')

        def evaluate(kind, tokens, targets, exception_to):
            ordinary = node(kind, tokens, targets)
            # Each expression can fail before its assignment commits. The
            # exception action evaluates calls separately and joins their
            # possible side effects with the pre-expression bindings.
            exceptional = node('exception', tokens, (exception_to,))
            return node('branch', targets=(ordinary, exceptional))

        def block(statements, following, break_to=None, next_to=None,
                  return_to=exit_node, exception_to=raise_exit, retry_to=None):
            for statement in reversed(statements):
                kind, tokens = statement.kind, statement.tokens
                if kind == 'block':
                    following = block(statement.body, following, break_to, next_to,
                                      return_to, exception_to, retry_to)
                elif kind == 'rescue':
                    restart = node('branch')
                    cleaned, restored = {}, {}
                    exception_scope = 'rescue:' + str(restart)

                    def cleanup(target):
                        if target is None or not statement.finalizer:
                            return target
                        if target not in cleaned:
                            saved = 'ensure:' + str(len(actions))
                            restore = node('restore-result', targets=(target,), extra=saved)
                            finalizer = block(statement.finalizer, restore, break_to, next_to,
                                              return_to, exception_to, retry_to)
                            cleaned[target] = node('save-result', targets=(finalizer,), extra=saved)
                        return cleaned[target]

                    def restore_exception(target):
                        if target is not None and target not in restored:
                            restored[target] = node('restore-exception', targets=(target,), extra=exception_scope)
                        return restored.get(target)

                    finished = restore_exception(cleanup(following))
                    leave_return, leave_raise = restore_exception(cleanup(return_to)), cleanup(exception_to)
                    leave_break, leave_next, leave_retry = (restore_exception(cleanup(target))
                                                           for target in (break_to, next_to, retry_to))
                    normal = block(statement.alternate, finished, leave_break, leave_next,
                                   leave_return, leave_raise, leave_retry) if statement.alternate else finished
                    previous, handlers = [], []
                    for handler in statement.handlers:
                        classes = tuple(token_text(part).removeprefix('::') for part in
                                        split_tokens(split_tokens(handler.tokens, {'=>'})[0], {','}) if part) or ('StandardError',)
                        caught = block(handler.body, finished, leave_break, leave_next,
                                       leave_return, leave_raise, restore_exception(restart))
                        caught = node('catch', targets=(caught,), extra=handler.names)
                        handlers.append(node('exception-match', targets=(caught,), extra=(classes, tuple(previous))))
                        previous.extend(classes)
                    unhandled = node('exception-match', targets=(leave_raise,), extra=((), tuple(previous)))
                    dispatch = node('branch', targets=(*handlers, unhandled)) if handlers else leave_raise
                    protected = block(statement.body, normal, leave_break, leave_next,
                                      leave_return, dispatch, leave_retry)
                    edges[restart] = (protected,)
                    following = node('save-exception', targets=(restart,), extra=exception_scope)
                elif kind in {'if', 'unless'}:
                    yes = block(statement.body, following, break_to, next_to, return_to, exception_to, retry_to) if statement.body else node('nil', targets=(following,))
                    no = block(statement.alternate, following, break_to, next_to, return_to, exception_to, retry_to) if statement.alternate else node('nil', targets=(following,))
                    true_guard = node('guard', tokens, (yes if kind == 'if' else no,), True)
                    false_guard = node('guard', tokens, (no if kind == 'if' else yes,), False)
                    targets = (true_guard,) if token_text(tokens) == 'true' else (false_guard,) if token_text(tokens) in {'false', 'nil'} else (true_guard, false_guard)
                    following = evaluate('condition', tokens, targets, exception_to)
                elif kind == 'iterate' and self.block_call(tokens):
                    method, receiver, expression = self.block_call(tokens)
                    slot = '@iteration:' + str(tokens[0].start)
                    names = statement.names
                    separator = names.index(';') if ';' in names else len(names)
                    parameters, locals_ = names[:separator], names[separator + 1:]
                    names = (*parameters, *locals_)
                    if any(not re.fullmatch(r'[a-z_]\w*', name) for name in names):
                        raise ValueError('Ruby destructured block parameters need binding analysis; analysis is incomplete')
                    saved = (slot, names)
                    assign = node('block-assign', tokens, (following,), slot)
                    finish = node('restore', targets=(assign,), extra=saved) if names else assign

                    def leave(target):
                        discarded = node('block-discard', targets=(target,), extra=slot)
                        return node('restore', targets=(discarded,), extra=saved) if names else discarded

                    return_target, raise_target = leave(return_to), leave(exception_to)
                    output = node('block-result', targets=(finish,), extra=(slot, method, tokens[0].start))
                    repeated = method in {'map', 'collect', 'each'}
                    loop = node('branch') if repeated else output
                    collected = node('block-collect', targets=(loop,), extra=(slot, method, tokens[0].start)) if repeated else output
                    body = block(statement.body, collected, finish, collected,
                                 return_target, raise_target, retry_to)
                    bound = node('block-bind', targets=(body,), extra=(slot, parameters, locals_))
                    if repeated:
                        edges[loop] = (bound, output)
                        # Literal nonempty arrays execute at least one block;
                        # an empty array never evaluates the block body.
                        plain = ungroup(receiver)
                        if plain and plain[0].value == '[' and closing_token(plain, 0) == len(plain) - 1:
                            entered = bound if plain[1:-1] else output
                        else:
                            entered = loop
                    else:
                        entered = bound
                    start = node('block-enter', receiver, (entered,), (slot, method))
                    possible_raise = node('exception', expression, (exception_to,))
                    following = node('branch', targets=(start, possible_raise))
                    if names:
                        following = node('save', targets=(following,), extra=saved)
                elif kind in {'while', 'until', 'for', 'iterate'}:
                    loop = node('branch')
                    after = node('nil', targets=(following,))
                    break_target = following
                    return_target, raise_target = return_to, exception_to
                    saved = (str(tokens[0].start) if tokens else str(loop), statement.names)
                    if kind == 'iterate' and statement.names:
                        after = node('restore', targets=(after,), extra=saved)
                        break_target = node('restore', targets=(following,), extra=saved)
                        return_target = node('restore', targets=(return_to,), extra=saved)
                        raise_target = node('restore', targets=(exception_to,), extra=saved)
                    body = block(statement.body, loop, break_target, loop, return_target, raise_target, retry_to)
                    if statement.names:
                        bound = node('bind', tokens, (body,), statement.names)
                        body = node('branch', targets=(bound, node('exception', tokens, (raise_target,))))
                    yes = node('guard', tokens, (body,), kind != 'until')
                    no = node('guard', tokens, (after,), kind == 'until')
                    edges[loop] = (evaluate('condition', tokens, (yes, no), raise_target),)
                    following = node('save', targets=(loop,), extra=saved) if kind == 'iterate' and statement.names else loop
                else:
                    first = tokens[0].value if tokens and tokens[0].kind == 'code' else ''
                    if first == 'return':
                        following = evaluate('simple', tokens[1:], (return_to,), exception_to)
                    elif first in {'raise', 'fail', 'throw', 'abort', 'exit'}:
                        following = node('raise', tokens[1:], (exception_to,))
                    elif first in {'break', 'next'}:
                        target = break_to if first == 'break' else next_to
                        if target is None:
                            raise ValueError('Ruby nonlocal block completion needs closure analysis; analysis is incomplete')
                        following = evaluate('simple', tokens[1:], (target,), exception_to)
                    elif first == 'retry':
                        if retry_to is None:
                            raise ValueError('Ruby retry outside a rescue clause; analysis is incomplete')
                        following = node('branch', targets=(retry_to,))
                    else:
                        following = evaluate('simple', tokens, (following,), exception_to)
            return following

        return block(function.body, exit_node), actions, edges

    def assign(self, tokens, values, state):
        """Commit ordinary and completed block-call results to local bindings."""
        parts = split_tokens(tokens, {'=', '+=', '-=', '||=', '&&='})
        offset = sum(len(part) + 1 for part in parts[:-1]) - 1
        for lhs_group in reversed(parts[:-1]):
            operator = tokens[offset].value
            bindings = split_tokens(lhs_group, {','})
            for index, lhs in enumerate(bindings):
                if not lhs:
                    continue
                value = values[index] if index < len(values) else CLEAN
                if len(bindings) == 1:
                    value = join(*values)
                elif len(values) == 1 and tainted(values[0]):
                    # An unknown tuple/array can carry a request in any
                    # destructured position; literal packs bind exactly.
                    value = values[0]
                if len(lhs) == 1 and re.fullmatch(r'(?:@@?|\$)?[A-Za-z_]\w*', lhs[0].value):
                    name = lhs[0].value
                    if operator != '=':
                        value = retag(join(state.get(name, CLEAN), value), remove=VALUE_TAGS)
                    if (name.startswith(('@', '$')) or name[0].isupper()) and tainted(value):
                        raise ValueError('Request-derived Ruby instance/global state needs heap analysis; analysis is incomplete')
                    state[name] = advance(value, self.step(lhs[0].start, 'assign', name))
                else:
                    name = lhs[0].value
                    self.mutate(state.get(name, CLEAN), value, state, name)
            offset -= len(lhs_group) + 1
        state['@result'] = join(*values)
        return state

    def transfer(self, action, state):
        kind, tokens, extra = action
        if not state.get('@reachable'):
            return state
        self.pending_raises = CLEAN
        if kind == 'branch':
            return state
        if kind == 'exit':
            self.returned = join(self.returned, state.get('@result', CLEAN))
            return state
        if kind == 'raise-exit':
            self.raised = join(self.raised, state.get('@exception', CLEAN))
            return state
        if kind in {'save-result', 'restore-result'}:
            saved = '@result:' + extra
            pending = '@exception:' + extra
            if kind == 'save-result':
                state[saved] = state.get('@result', CLEAN)
                state[pending] = state.get('@exception', CLEAN)
            else:
                state['@result'] = state.pop(saved, CLEAN)
                state['@exception'] = state.pop(pending, CLEAN)
            return state
        if kind in {'save-exception', 'restore-exception'}:
            saved = '@exception:' + extra
            if kind == 'save-exception':
                state[saved] = state.get('@exception', CLEAN)
            else:
                state['@exception'] = state.get(saved, CLEAN)
            return state
        if kind == 'catch':
            for name in extra:
                state[name] = state.get('@exception', CLEAN)
            return state
        if kind == 'exception-match':
            classes, previous = extra
            def matches(raised, caught):
                if raised == '*' or any(name not in RUBY_EXCEPTION_BASES for name in caught):
                    return None
                parents, current = {raised}, raised
                while current in RUBY_EXCEPTION_BASES and RUBY_EXCEPTION_BASES[current]:
                    current = RUBY_EXCEPTION_BASES[current]
                    parents.add(current)
                return bool(parents.intersection(caught))
            kinds = {trace.key[0] for trace in state.get('@exception', CLEAN) if trace.kind == 'exception'} or {'*'}
            admitted = {name for name in kinds if matches(name, previous) is not True
                        and (not classes or matches(name, classes) is not False)}
            if not admitted:
                return {}
            state['@exception'] = frozenset(trace for trace in state.get('@exception', CLEAN)
                                            if (trace.kind != 'exception' or trace.key[0] in admitted)
                                            and (not tainted(frozenset({trace})) or
                                                 any('exception-type:' + name in trace.tags for name in admitted)))
            return state
        if kind in {'exception', 'raise'}:
            before = dict(state)
            expression = split_tokens(tokens, {'=', '+=', '-=', '||=', '&&='})[-1]
            value = self.expression(expression, state)
            if kind == 'exception':
                raised = self.pending_raises
                # A bare, unresolved Ruby identifier can be a zero-argument
                # method. Operators can also dispatch to user-defined code.
                bare_call = len(expression) == 1 and expression[0].kind == 'code' and re.fullmatch(r'[a-z_]\w*[!?]?', expression[0].value) and expression[0].value not in before and expression[0].value not in {'nil', 'true', 'false'}
                operators = any(token.kind == 'code' and token.value in {'+', '-', '*', '/', '==', '!=', '<', '>', '<=', '>='} for token in expression)
                if bare_call or operators:
                    raised = join(raised, self.exception_value(value, '*'))
                if not raised:
                    return {}
                for name, fact in before.items():
                    state[name] = join(fact, state.get(name, CLEAN))
            elif not tokens:
                raised = state.get('@exception') or frozenset({Trace('exception', ('RuntimeError',))})
            else:
                exception_class = tokens[0].value if tokens[0].value in RUBY_EXCEPTION_BASES else None
                if exception_class and any(function.owner and function.owner[-1] == exception_class and function.scope for function in self.parser.functions.values()):
                    exception_class = None
                existing = frozenset(trace for trace in value if trace.kind == 'exception')
                unknown_class = tokens[0].kind == 'code' and tokens[0].value[:1].isupper() and not exception_class
                known_string = any(trace.kind == 'constant' and trace.key[0] == 'literal' for trace in value) and not tainted(value)
                raised = value if existing and not exception_class else self.exception_value(
                    value, exception_class or ('*' if unknown_class or not known_string else 'RuntimeError'))
                # Evaluation of a raise argument can itself raise before the
                # surrounding raise executes. Keep each exception's message
                # correlated with its class through handler selection.
                raised = join(raised, self.pending_raises)
            state['@exception'] = join(retag(tainted(raised), remove=VALUE_TAGS),
                                       frozenset(trace for trace in raised if trace.kind == 'exception'))
            return state
        if kind == 'guard':
            for name, tags in self.proof(tokens, extra, state).items():
                state[name] = join(*(retag(frozenset({trace}), add=tags)
                                    if (self.policy == 'url' and 'parsed-uri' in trace.tags
                                        or self.policy == 'path' and ('canonical-path' in trace.tags or tags == frozenset({'not-dot-name'})))
                                    else frozenset({trace}) for trace in state.get(name, CLEAN)))
            return state
        if kind == 'nil':
            state['@result'] = constant('nil', 'code')
            return state
        if kind in {'save', 'restore'}:
            key, names = extra
            for name in names:
                saved = '@block:' + key + ':' + name
                if kind == 'save':
                    state[saved] = state.get(name, CLEAN)
                else:
                    state[name] = state.get(saved, CLEAN)
                    state.pop(saved, None)
            return state
        if kind == 'bind':
            value = self.expression(tokens, state)
            for name in extra:
                state[name] = value
            return state
        if kind == 'condition':
            self.expression(tokens, state)
            return state
        if kind == 'block-enter':
            slot, method = extra
            value = self.expression(tokens, state)
            instances = {trace.key[0] for trace in value if trace.kind == 'instance'}
            if self.candidates(token_text(tokens) + '.' + method, 0) or any(
                    not function.scope and not function.singleton and function.name == method
                    and function.owner in instances for function in self.parser.functions.values()):
                raise ValueError('Overridden Ruby block methods need callback dispatch analysis; analysis is incomplete')
            state[slot + ':receiver'] = advance(value, self.step(tokens[0].start, 'call', method + '()'))
            state[slot + ':values'] = shape('mapped-list', tokens[0].start)
            return state
        if kind == 'block-bind':
            slot, parameters, locals_ = extra
            for name in parameters:
                state[name] = state.get(slot + ':receiver', CLEAN)
            for name in locals_:
                state[name] = constant('nil', 'code')
            state['@result'] = constant('nil', 'code')
            return state
        if kind == 'block-collect':
            slot, method, offset = extra
            if method in {'map', 'collect'}:
                value = advance(state.get('@result', CLEAN), self.step(offset, 'return', method + ' block result'))
                state[slot + ':values'] = join(state.get(slot + ':values', CLEAN), value)
            return state
        if kind == 'block-result':
            slot, method, offset = extra
            if method in {'map', 'collect'}:
                value = state.get(slot + ':values', CLEAN)
            elif method in {'each', 'tap'}:
                value = state.get(slot + ':receiver', CLEAN)
            else:
                value = state.get('@result', CLEAN)
            state['@result'] = advance(value, self.step(offset, 'return', method + ' block result'))
            return state
        if kind in {'block-assign', 'block-discard'}:
            state.pop(extra + ':receiver', None)
            state.pop(extra + ':values', None)
            if kind == 'block-assign':
                return self.assign(tokens, [state.get('@result', CLEAN)], state)
            return state
        parts = split_tokens(tokens, {'=', '+=', '-=', '||=', '&&='})
        if len(parts) > 1 and parts[0]:
            rhs = ungroup(parts[-1])
            multiple = any(len(split_tokens(lhs, {','})) > 1 for lhs in parts[:-1])
            if multiple and rhs and rhs[0].value == '[' and closing_token(rhs, 0) == len(rhs) - 1:
                rhs = rhs[1:-1]
            values = [self.expression(part, state) for part in split_tokens(rhs, {','})]
            return self.assign(tokens, values, state)
        else:
            state['@result'] = self.expression(tokens, state)
        return state

    def analyze(self):
        changed = True
        while changed:
            changed = False
            contexts = tuple(self.contexts.items())
            for key, function in contexts:
                self.budget.spend()
                self.function, self.effects, self.returned, self.mutations, self.raised = function, {}, CLEAN, {}, CLEAN
                self.parameter_values = dict(enumerate(key[1]))
                state = {'@reachable': constant('reachable'),
                         'params': shape('request-params', function.key), 'env': shape('environment', function.key),
                         **{name: shape('request', function.key) for name in ('request', 'req', 'rack_request')}}
                for (owner, name), fact in self.constants.items():
                    if function.owner[:len(owner)] == owner:
                        state[name] = fact
                for index, (name, fact) in enumerate(zip(function.parameters, key[1])):
                    if key[2] and not fact and index < len(function.defaults) and function.defaults[index]:
                        fact = self.expression(function.defaults[index], state)
                    if fact or name not in state:
                        state[name] = fact
                if function.key not in self.graphs:
                    self.graphs[function.key] = self.graph(function)
                entry, actions, edges = self.graphs[function.key]
                solve(entry, state, edges, lambda node, incoming: self.transfer(actions[node], incoming), self.budget)
                updated = self.summaries[key].merged(RubySummary(self.returned, self.effects, self.mutations, self.raised))
                if updated != self.summaries[key]:
                    self.summaries[key], changed = updated, True
            changed = changed or len(contexts) != len(self.contexts)
        effects = {}
        for summary in self.summaries.values():
            for offset, fact in summary.effects.items():
                concrete = frozenset(trace for trace in fact if trace.kind == 'source')
                if concrete:
                    line = self.step(offset, 'sink', '').line
                    effects[line] = join(effects.get(line, CLEAN), concrete)
        return effects


def flow_findings(path, policy):
    text = path.read_text(encoding='utf-8')
    # Skip files with no request vocabulary before parsing unrelated Ruby DSLs.
    if not re.search(r'\b(?:params|request|req|rack_request|env|Rack::Request|original_filename|filename)\b', text):
        return
    engine = RubyEngine(path, text, policy)
    lines = text.splitlines()
    suppressions = build_index(text, lang='ruby')
    rule = 'ruby.taint.path_traversal' if policy == 'path' else 'ruby.taint.outbound_url'
    for line, fact in sorted(engine.analyze().items()):
        if suppressions.is_suppressed(line, rule):
            continue
        evidence = min((trace.evidence for trace in fact), key=lambda steps: (len(steps), steps))
        route = ' -> '.join(step.label for step in evidence)
        yield line, f'{source_line(lines, line)}  [{route}]', {
            'taint_path': [step.record() for step in evidence],
            'source_count': len({trace.key for trace in fact}),
        }


def analyze(path, issues):
    for line, code, extras in flow_findings(path, 'path'):
        issues.append((relpath(path), line, code))


def _configure(root: Path) -> None:
    """Bind ROOT/BASE_DIR the way the heredoc derived them from sys.argv[1]."""
    global ROOT, BASE_DIR
    ROOT = root
    BASE_DIR = root if root.is_dir() else root.parent


MESSAGE = "Request-derived path reaches file read/write/serve sink"
REMEDY = (
    "Validate paths with File.expand_path containment checks or reduce upload "
    "names to File.basename before opening, serving, or deleting files"
)


def main(argv: list[str] | None = None) -> int:
    """Print the heredoc's __COUNT__/__SAMPLE__ report for one project dir."""
    if argv is None:
        argv = sys.argv[1:]
    _configure(Path(argv[0]).resolve())
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    """Emit path findings; source-line suppression never erases later flow."""
    _configure(Path.cwd())
    for path in ctx.files:
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        for line_no, code, extras in flow_findings(path, 'path'):
            yield {
                "rule": "ruby.taint.path_traversal",
                "path": relpath(path),
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "ruby",
                "severity": "critical",
                "message": f"{MESSAGE}: {code}",
                "extras": extras,
            }


def _selftest_positive_run() -> None:
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = params[:file]\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "ruby.taint.path_traversal", findings
    assert findings[0]["line"] == 4, findings


def _selftest_basename_suppression() -> None:
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = File.basename(params[:file])\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert findings == [], findings


def _selftest_source_ignore_preserves_flow() -> None:
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = params[:file] # ubs:ignore\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1 and findings[0]['line'] == 4, findings


def _selftest_main_emit_dialect() -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = params[:file]\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        (Path(tmp) / "app.rb").write_text(code, encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main([tmp])
    lines = buffer.getvalue().splitlines()
    assert rc == 0
    assert lines[0] == "__COUNT__\t1", lines
    assert lines[1].startswith("__SAMPLE__\tapp.rb\t4\t"), lines


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("positive_run", _selftest_positive_run),
    ("basename_suppression", _selftest_basename_suppression),
    ("source_ignore_preserves_flow", _selftest_source_ignore_preserves_flow),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="ruby", name="taint_ruby_traversal", run=run, selftests=SELF_TESTS))
