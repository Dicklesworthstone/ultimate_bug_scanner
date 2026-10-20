"""ubs_core.lexer — Token spans, intervals, and comment/string stripping (bead A2).

Provides unified comment and string stripping while strictly preserving character
offsets and newlines so that (line, col) calculations match original sources.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


@dataclass(frozen=True)
class Span:
    """A contiguous half-open interval [start, end) in source text."""

    start: int
    end: int

    @property
    def length(self) -> int:
        return max(0, self.end - self.start)

    def contains(self, pos: int) -> bool:
        return self.start <= pos < self.end

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class Interval:
    """An annotated half-open interval [start, end) with attached metadata."""

    start: int
    end: int
    data: Any = None

    @property
    def span(self) -> Span:
        return Span(self.start, self.end)

    def contains(self, pos: int) -> bool:
        return self.start <= pos < self.end

    def overlaps(self, other: Interval | Span) -> bool:
        return self.start < other.end and other.start < self.end


_HASH_COMMENT_LANGS = frozenset({"ruby", "rb", "python", "py", "elixir", "ex", "exs", "sh", "bash"})
_NO_SINGLE_QUOTE_STRING_LANGS = frozenset({"swift"})
# Tokens after which Swift begins an expression, so a bare `/` there opens a
# regex literal rather than dividing.
_SWIFT_REGEX_PREFIX = frozenset({'', '=', '(', '[', '{', ',', ':', ';', '?',
                                 'return', 'throw', 'case', 'try', 'await'})
_RUST_CHAR_RE = re.compile(
    r"'(?:[^'\\\r\n\t]|\\(?:['\"\\nrt0]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}))'"
)


def javascript_lexical_views(text: str) -> tuple[str, str]:
    """Return comment-free source and executable code at original offsets.

    Template text is inert, but ${expressions} (including nested templates)
    are executable. Synthetic parentheses keep their boundaries balanced for
    argument scanning. No source text is evaluated. Regex recognition is
    intentionally lexical, not a claim to implement the JavaScript grammar.
    """
    source, code = list(text), list(text)
    frames = [['code', 0]]

    def mask(output, start, end):
        for pos in range(start, end):
            output[pos] = '\n' if text[pos] == '\n' else ' '

    def closes_jsx_tag(pos):
        # A self-closing tag after an attribute expression ends in `} />`.
        # That slash is not a regex opener. Prove the open tag in the already
        # lexed prefix; `/>/` remains a legal regex elsewhere and inside {...}.
        if not text.startswith('/>', pos):
            return False
        closing = {'}': '{', ')': '(', ']': '['}
        stack = []
        previous = pos - 1
        while previous >= 0:
            char = code[previous]
            if char in closing:
                stack.append(closing[char])
            elif char in '{([':
                if not stack or stack.pop() != char:
                    return False
            elif not stack:
                if char in '>;':
                    return False
                if char == '<':
                    return re.match(r'<[A-Za-z_$][\w$.:-]*(?=\s|/?>)', text[previous:pos + 2]) is not None
            previous -= 1
        return False

    def regex_allowed(pos):
        if closes_jsx_tag(pos):
            return False
        previous = pos - 1
        while previous >= 0 and code[previous].isspace():
            previous -= 1
        if previous < 0 or code[previous] in '=(:,[!&|?;{}':
            return True
        if previous > 0 and text[previous - 1:previous + 1] == '=>':
            return True
        end = previous + 1
        while previous >= 0 and (code[previous].isalnum() or code[previous] in '_$'):
            previous -= 1
        return ''.join(code[previous + 1:end]) in {'return', 'throw', 'yield', 'case', 'void', 'typeof', 'delete'}

    i = 0
    while i < len(text):
        ch = text[i]
        if frames[-1][0] == 'template':
            code[i] = '\n' if ch == '\n' else ' '
            if ch == '\\':
                mask(code, i, min(i + 2, len(text)))
                i += 2
                continue
            if ch == '`':
                code[i] = ')'
                frames.pop()
            elif text.startswith('${', i):
                code[i + 1] = '('
                frames.append(['expression', 0])
                i += 2
                continue
            i += 1
            continue

        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            end = len(text) if end < 0 else end
            mask(source, i, end)
            mask(code, i, end)
            i = end
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = len(text) if end < 0 else end + 2
            mask(source, i, end)
            mask(code, i, end)
            i = end
            continue
        if ch in ('"', "'"):
            end = i + 1
            while end < len(text):
                if text[end] == '\\':
                    end += 2
                elif text[end] == ch:
                    end += 1
                    break
                elif text[end] == '\n':
                    break
                else:
                    end += 1
            end = min(end, len(text))
            mask(code, i, end)
            code[i] = '0'  # an inert value, not missing syntax
            i = end
            continue
        if ch == '`':
            code[i] = '('
            frames.append(['template', 0])
            i += 1
            continue
        if ch == '/' and regex_allowed(i):
            end, character_class = i + 1, False
            while end < len(text) and text[end] != '\n':
                if text[end] == '\\':
                    end += 2
                    continue
                if text[end] == '[':
                    character_class = True
                elif text[end] == ']':
                    character_class = False
                elif text[end] == '/' and not character_class:
                    end += 1
                    while end < len(text) and text[end].isalpha():
                        end += 1
                    mask(code, i, end)
                    code[i] = '0'
                    i = end
                    break
                end += 1
            else:
                end = -1
            if end >= 0:
                continue
        if frames[-1][0] == 'expression':
            if ch == '{':
                frames[-1][1] += 1
            elif ch == '}':
                if frames[-1][1] == 0:
                    code[i] = ')'
                    frames.pop()
                else:
                    frames[-1][1] -= 1
        i += 1
    return ''.join(source), ''.join(code)


def swift_lexical_regions(text: str) -> tuple[Interval, ...]:
    """Swift comments, literal segments and executable interpolation spans.

    Regions retain Unicode character offsets. Literal regions include their
    interpolation ranges; string regions exclude the executable expressions.
    Regex literals are opaque literals, as in the Swift taint lexer: an
    extended `#/.../#` literal, or a bare `/.../` in expression position that
    SE-0354 lexes as a regex (no leading or trailing blank, closed on its
    line, no unbalanced `)`); any other `/` is the division operator.
    Unterminated comments, strings, extended regexes and interpolations are
    explicitly incomplete. This is lexical support, not Swift type or
    overload resolution.
    """
    regions: list[Interval] = []
    n = len(text)

    def region(start, end, kind, **metadata):
        regions.append(Interval(start, end, dict(kind=kind, **metadata)))

    def string(start, quote, hashes, depth):
        if depth > 128:
            raise ValueError("Swift lexical nesting limit; analysis is incomplete")
        triple = text.startswith('"""', quote)
        width = 3 if triple else 1
        closer = '"' * width + '#' * hashes
        escape = '\\' + '#' * hashes
        i, segment = quote + width, start
        expressions = []
        while i < n:
            if text.startswith(closer, i):
                end = i + len(closer)
                region(segment, end, "string")
                region(start, end, "literal", hashes=hashes, triple=triple,
                       expressions=tuple(expressions))
                return end
            if text.startswith(escape, i):
                after = i + len(escape)
                if after < n and text[after] == '(':
                    region(segment, after + 1, "string")
                    end = code(after + 1, depth + 1, True)
                    expressions.append((after + 1, end - 1))
                    segment = end - 1
                    i = end
                    continue
                i = min(n, after + 1)
                continue
            i += 1
        raise ValueError("Unterminated Swift string; analysis is incomplete")

    def bare_regex_end(start):
        # The end of a bare regex literal opening at `start`, or None when
        # Swift lexes this `/` as an operator instead.
        if start + 1 >= n or text[start + 1] in ' \t\r\n':
            return None
        i, parens = start + 1, 0
        while i < n and text[i] not in '\r\n':
            ch = text[i]
            if ch == '\\':
                if i + 1 < n and text[i + 1] in '\r\n':
                    return None
                i += 2
                continue
            if ch == '/':
                if text[i - 1] in ' \t' or parens < 0:
                    return None
                return i + 1
            if ch == '(':
                parens += 1
            elif ch == ')':
                parens -= 1
            i += 1
        return None

    def extended_regex_end(start, hashes):
        closer = '/' + '#' * hashes
        escape = '\\' + '#' * hashes
        i = start + hashes + 1
        while i < n:
            if text.startswith(closer, i):
                return i + len(closer)
            if text.startswith(escape, i):
                i += len(escape) + 1
                continue
            i += 1
        raise ValueError("Unterminated Swift regex literal; analysis is incomplete")

    def code(start, depth=0, interpolation=False):
        i, parens, previous = start, 0, ''
        while i < n:
            ch = text[i]
            if text.startswith('//', i):
                end = i + 2
                while end < n and text[end] not in '\r\n':
                    end += 1
                region(i, end, "comment")
                i = end
                continue
            if text.startswith('/*', i):
                end, nesting = i + 2, 1
                while end < n and nesting:
                    if text.startswith('/*', end):
                        nesting += 1
                        end += 2
                    elif text.startswith('*/', end):
                        nesting -= 1
                        end += 2
                    else:
                        end += 1
                if nesting:
                    raise ValueError("Unterminated Swift comment; analysis is incomplete")
                region(i, end, "comment")
                i = end
                continue
            quote = i
            while quote < n and text[quote] == '#':
                quote += 1
            if quote < n and text[quote] == '"':
                i = string(i, quote, quote - i, depth)
                previous = 'value'
                continue
            end = None
            if quote > i and quote < n and text[quote] == '/':
                end = extended_regex_end(i, quote - i)
            elif ch == '/' and previous in _SWIFT_REGEX_PREFIX:
                end = bare_regex_end(i)
            if end is not None:
                region(i, end, "string")
                region(i, end, "literal", hashes=quote - i, triple=False,
                       expressions=(), regex=True)
                i = end
                previous = 'value'
                continue
            if ch == '(':
                parens += 1
            elif ch == ')':
                if interpolation and not parens:
                    return i + 1
                parens -= 1
            if ch.isalpha() or ch == '_':
                end = i + 1
                while end < n and (text[end].isalnum() or text[end] == '_'):
                    end += 1
                previous = text[i:end]
                i = end
                continue
            if not ch.isspace():
                previous = ch
            i += 1
        if interpolation:
            raise ValueError("Unterminated Swift interpolation; analysis is incomplete")
        return i

    code(0)
    return tuple(sorted(regions, key=lambda item: (item.start, -item.end)))


def strip_comments_and_strings(
    text: str,
    lang: str = "c_like",
    *,
    strip_strings: bool = True,
    strip_comments: bool = True,
    preserve_comments: bool = False,
) -> str:
    """Mask out comments and strings with spaces while preserving newlines.

    With ``preserve_comments=True`` (requires ``strip_comments=True``), comment
    detection still runs — so quotes inside comments cannot open strings — but
    comment text is emitted verbatim instead of blanked. This lets marker
    parsers see `ubs:ignore` in comments while staying immune to apostrophes.

    String boundaries are recognized even with ``strip_strings=False`` so
    literal comment delimiters remain string contents when comments are masked.

    Ensures that (line, column) coordinates and string offsets in the returned text
    match the original text byte-for-byte.
    """
    lang_norm = lang.lower().strip()
    if lang_norm in {"php", "phtml"}:
        # PHP has three comment forms, heredoc/nowdoc strings and literal HTML
        # between code islands. Use the same lexical ownership as the native
        # analyzer so an example marker in a template cannot hide a finding.
        from ubs_core.php_frontend import lexical_spans

        characters = list(text)
        for kind, start, end in lexical_spans(text):
            mask = ((kind == "comment" and strip_comments and not preserve_comments)
                    or (kind in {"string", "html"} and strip_strings))
            if mask:
                for position in range(start, end):
                    if characters[position] != "\n":
                        characters[position] = " "
        return "".join(characters)
    if lang_norm == "swift":
        if not strip_strings and not strip_comments:
            return text
        output = list(text)
        for item in swift_lexical_regions(text):
            kind = item.data['kind']
            if (kind == 'string' and strip_strings) or (
                kind == 'comment' and strip_comments and not preserve_comments
            ):
                for pos in range(item.start, item.end):
                    output[pos] = '\n' if text[pos] == '\n' else ' '
        return ''.join(output)
    is_rust = lang_norm in {"rust", "rs"}
    is_hash_comment = lang_norm in _HASH_COMMENT_LANGS
    supports_single_quote_strings = lang_norm not in _NO_SINGLE_QUOTE_STRING_LANGS

    result: list[str] = []
    i = 0
    n = len(text)

    in_line_comment = False
    block_comment_depth = 0
    in_string = False
    in_triple_string = False
    string_quote = ""
    escaped = False

    def mask_char(ch: str) -> str:
        return "\n" if ch == "\n" else " "

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        nxt2 = text[i + 2] if i + 2 < n else ""

        # Inside line comment
        if in_line_comment:
            result.append(ch if preserve_comments else mask_char(ch))
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        # Inside block comment
        if block_comment_depth:
            result.append(ch if preserve_comments else mask_char(ch))
            if is_rust and ch == "/" and nxt == "*":
                result.append("*" if preserve_comments else " ")
                block_comment_depth += 1
                i += 2
            elif ch == "*" and nxt == "/":
                result.append("/" if preserve_comments else " ")
                block_comment_depth -= 1
                i += 2
            else:
                i += 1
            continue

        # Inside triple-quoted string
        if in_triple_string:
            result.append(mask_char(ch) if strip_strings else ch)
            if not escaped and ch == string_quote and nxt == string_quote and nxt2 == string_quote:
                result.append(" " if strip_strings else nxt)
                result.append(" " if strip_strings else nxt2)
                in_triple_string = False
                i += 3
            else:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                i += 1
            continue

        # Inside regular string
        if in_string:
            result.append(mask_char(ch) if strip_strings else ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == string_quote:
                in_string = False
            i += 1
            continue

        # Check comment start
        if strip_comments:
            if is_hash_comment and ch == "#":
                in_line_comment = True
                result.append(ch if preserve_comments else " ")
                i += 1
                continue

            if not is_hash_comment and ch == "/" and nxt == "/":
                in_line_comment = True
                result.extend("//" if preserve_comments else "  ")
                i += 2
                continue

            if not is_hash_comment and ch == "/" and nxt == "*":
                block_comment_depth = 1
                result.extend("/*" if preserve_comments else "  ")
                i += 2
                continue

        # Check string start
        if strip_strings or strip_comments:
            # Rust raw strings use an exact hash-delimited closer. Quotes,
            # escapes, and comment delimiters inside them are literal bytes.
            # Recognize the byte/C-string prefixes at the same token boundary.
            if is_rust and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                raw_start = i + 1 if ch == "r" else i + 2 if ch in {"b", "c"} and nxt == "r" else 0
                if raw_start:
                    quote = raw_start
                    while quote < n and text[quote] == "#":
                        quote += 1
                    if quote < n and text[quote] == '"':
                        closer = '"' + text[raw_start:quote]
                        end = text.find(closer, quote + 1)
                        end = n if end < 0 else end + len(closer)
                        literal = text[i:end]
                        if strip_strings:
                            result.extend(mask_char(char) for char in literal)
                        else:
                            result.append(literal)
                        i = end
                        continue

            # A Rust apostrophe starts a character only when a complete
            # one-character/escape literal follows. Lifetimes and loop labels
            # must not open a string that hides subsequent real comments.
            if is_rust and ch == "'":
                character = _RUST_CHAR_RE.match(text, i)
                if character is not None:
                    literal = character.group()
                    result.append(" " * len(literal) if strip_strings else literal)
                    i = character.end()
                    continue
                result.append(ch)
                i += 1
                continue

            # Triple quotes (""" or ''')
            if not is_rust and ch in {'"', "'"} and nxt == ch and nxt2 == ch:
                if ch == '"' or supports_single_quote_strings:
                    in_triple_string = True
                    string_quote = ch
                    result.extend("   " if strip_strings else ch * 3)
                    i += 3
                    continue

            # Regular quotes
            if ch == '"' or (supports_single_quote_strings and ch == "'"):
                in_string = True
                string_quote = ch
                result.append(mask_char(ch) if strip_strings else ch)
                i += 1
                continue

        result.append(ch)
        i += 1

    return "".join(result)
