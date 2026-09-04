"""ubs_core.lexer — Token spans, intervals, and comment/string stripping (bead A2).

Provides unified comment and string stripping while strictly preserving character
offsets and newlines so that (line, col) calculations match original sources.
"""
from __future__ import annotations

from dataclasses import dataclass
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

    Ensures that (line, column) coordinates and string offsets in the returned text
    match the original text byte-for-byte.
    """
    lang_norm = lang.lower().strip()
    is_hash_comment = lang_norm in _HASH_COMMENT_LANGS
    supports_single_quote_strings = lang_norm not in _NO_SINGLE_QUOTE_STRING_LANGS

    result: list[str] = []
    i = 0
    n = len(text)

    in_line_comment = False
    in_block_comment = False
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
        if in_block_comment:
            result.append(ch if preserve_comments else mask_char(ch))
            if ch == "*" and nxt == "/":
                result.append("/" if preserve_comments else " ")
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        # Inside triple-quoted string
        if in_triple_string:
            result.append(mask_char(ch))
            if not escaped and ch == string_quote and nxt == string_quote and nxt2 == string_quote:
                result.append(" ")
                result.append(" ")
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
            result.append(mask_char(ch))
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
                in_block_comment = True
                result.extend("/*" if preserve_comments else "  ")
                i += 2
                continue

        # Check string start
        if strip_strings:
            # Triple quotes (""" or ''')
            if ch in {'"', "'"} and nxt == ch and nxt2 == ch:
                if ch == '"' or supports_single_quote_strings:
                    in_triple_string = True
                    string_quote = ch
                    result.extend("   ")
                    i += 3
                    continue

            # Regular quotes
            if ch == '"' or (supports_single_quote_strings and ch == "'"):
                in_string = True
                string_quote = ch
                result.append(mask_char(ch))
                i += 1
                continue

        result.append(ch)
        i += 1

    return "".join(result)
