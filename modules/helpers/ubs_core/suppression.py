"""ubs_core.suppression — statement-interval suppression index (bead A7, GH #91).

One suppression implementation for every language. For each source file we
build an index of statement/block intervals and `ubs:ignore` marker lines, then
answer `is_suppressed(line, rule)`.

Semantics: a finding at line L is suppressed when a marker's anchor line
- lies inside the statement interval containing L (covers trailing markers and
  markers on any physical line of a multi-line statement),
- is on the line immediately preceding that interval's first line, or
- is a formatter-relocated marker on the first line inside a block whose
  opening line is L.

`ubs:ignore[rule-a,rule-b]` suppresses only the listed rule ids; a bare
`ubs:ignore` suppresses every rule. Marker detection runs on string-masked
text so a `ubs:ignore` inside a string literal is not a marker, while markers
in comments (their natural home) remain visible.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ubs_core.lexer import strip_comments_and_strings

MARKER_RE = re.compile(r"ubs:ignore(?:\[([A-Za-z0-9_.,\- ]+)\])?")

_HASH_LANGS = frozenset({"python", "ruby", "elixir"})
_BLOCK_KEYWORDS = {"ruby": ("def ", "end"), "elixir": ("do", "end")}
_C_CONTINUATION = ("\\", "(", "[", ",", "&&", "||", "=>", "=", "+", "-", "*", "/", "?", "|", "&", "<", ">", ".")
_PY_CONTINUATION = ("\\", "(", "[", "{", ",", "&", "|", "+", ".", "->", "do", "then", "else")


@dataclass(frozen=True)
class Interval:
    """A physical line interval [start_line, end_line], both inclusive."""

    start_line: int
    end_line: int

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


@dataclass(frozen=True)
class Marker:
    line: int
    rules: frozenset[str] | None  # None = bare marker (suppresses every rule)


@dataclass
class SuppressionIndex:
    intervals: list[Interval] = field(default_factory=list)
    markers: list[Marker] = field(default_factory=list)

    def _interval_for(self, line: int) -> Interval | None:
        best: Interval | None = None
        for interval in self.intervals:
            if interval.contains(line):
                span = interval.end_line - interval.start_line
                if best is None or span < (best.end_line - best.start_line):
                    best = interval
        return best

    def is_suppressed(self, line: int, rule: str) -> bool:
        interval = self._interval_for(line)
        candidates = {line}
        if interval is not None:
            candidates.add(interval.start_line - 1)  # marker on the previous line
            if interval.start_line == line:
                candidates.add(line + 1)  # formatter moved the marker inside
        return any(
            marker.line in candidates and (marker.rules is None or rule in marker.rules)
            for marker in self.markers
        )


def parse_markers(text: str, lang: str = "python") -> list[Marker]:
    """Return `ubs:ignore` markers per line, ignoring occurrences in strings.

    Comments survive the mask (strip_comments=False) because markers naturally
    live in comments; string contents are blanked so documented examples like
    `use "ubs:ignore" carefully` never suppress anything.
    """
    masked = strip_comments_and_strings(text, lang=lang, strip_strings=True, strip_comments=False)
    markers: list[Marker] = []
    for lineno, line in enumerate(masked.splitlines(), start=1):
        for match in MARKER_RE.finditer(line):
            rules_blob = match.group(1)
            if rules_blob is None:
                rules = None
            else:
                rules = frozenset(p.strip() for p in rules_blob.split(",") if p.strip()) or None
            markers.append(Marker(line=lineno, rules=rules))
    return markers


def _paren_depths(lines: list[str]) -> tuple[list[int], list[int]]:
    """Per-line paren/bracket depth before and after each physical line.

    `{`/`}` are block delimiters and are deliberately excluded: a block opens
    a NEW interval rather than continuing the statement.
    """
    n = len(lines)
    before = [0] * (n + 2)
    after = [0] * (n + 2)
    depth = 0
    for lineno, line in enumerate(lines, start=1):
        before[lineno] = depth
        for ch in line:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth = max(0, depth - 1)
        after[lineno] = depth
    return before, after


def _brace_blocks(lines: list[str]) -> list[Interval]:
    """Balanced `{...}` intervals (nested pairs included)."""
    blocks: list[Interval] = []
    stack: list[int] = []
    for lineno, line in enumerate(lines, start=1):
        for ch in line:
            if ch == "{":
                stack.append(lineno)
            elif ch == "}":
                if stack:
                    start = stack.pop()
                    if start != lineno:
                        blocks.append(Interval(start, lineno))
    return blocks


def _keyword_blocks(lines: list[str], lang: str) -> list[Interval]:
    """`do..end` / `def .. end` intervals for ruby and elixir."""
    spec = _BLOCK_KEYWORDS.get(lang)
    if spec is None:
        return []
    open_kw, close_kw = spec
    blocks: list[Interval] = []
    stack: list[int] = []
    for lineno, line in enumerate(lines, start=1):
        code = line.strip()
        if code.startswith(open_kw) or code.endswith(" do"):
            stack.append(lineno)
        elif code == close_kw and stack:
            start = stack.pop()
            if start != lineno:
                blocks.append(Interval(start, lineno))
    return blocks


def _python_indent_blocks(lines: list[str]) -> list[Interval]:
    """Header (`...:`) line plus its indented body, for python-style code."""
    blocks: list[Interval] = []
    header = 0
    header_indent = 0
    last_code = 0
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if header and indent > header_indent:
            last_code = lineno
            continue
        if header:
            if last_code >= header:
                blocks.append(Interval(header, last_code))
            header = 0
        if line.rstrip().endswith(":"):
            header = lineno
            header_indent = indent
        last_code = lineno
    if header and last_code >= header:
        blocks.append(Interval(header, last_code))
    return blocks


def _continues(code: str, paren_open: bool, lang: str) -> bool:
    if paren_open:
        return True
    suffixes = _PY_CONTINUATION if lang in _HASH_LANGS else _C_CONTINUATION
    return code.endswith(tuple(suffixes))


def build_index(text: str, lang: str = "python") -> SuppressionIndex:
    """Build the suppression index for one file's text."""
    masked = strip_comments_and_strings(
        text,
        lang="python" if lang in _HASH_LANGS else "c_like",
        strip_strings=True,
        strip_comments=False,
    )
    lines = masked.splitlines()
    index = SuppressionIndex()
    index.markers = parse_markers(text, lang=lang)

    paren_before, paren_after = _paren_depths(lines)
    index.intervals.extend(_brace_blocks(lines))
    index.intervals.extend(_keyword_blocks(lines, lang))
    if lang == "python":
        index.intervals.extend(_python_indent_blocks(lines))

    # Leaf statement intervals: group physical lines linked by open parens or
    # an explicit continuation suffix. A block brace ends the leaf statement.
    start = 0
    for lineno, line in enumerate(lines, start=1):
        code = line.strip()
        if not code:
            if start and paren_after[lineno] > 0:
                continue  # blank line inside open parens: statement continues
            if start:
                index.intervals.append(Interval(start, lineno - 1))
                start = 0
            continue
        if start == 0:
            start = lineno
        if _continues(code, paren_after[lineno] > 0, lang):
            continue
        index.intervals.append(Interval(start, lineno))
        start = 0
    if start:
        index.intervals.append(Interval(start, len(lines)))

    return index
