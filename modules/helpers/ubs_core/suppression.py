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
`ubs:ignore` suppresses every rule. Bare comment aliases `nolint`, `noqa`,
and `ubs: disable` have the same ownership. Qualified aliases are not broad
suppressions. Marker detection uses actual comments, never string literals
or ordinary source tokens.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ubs_core.lexer import strip_comments_and_strings

# An explicit empty scope is bare; a malformed scope must not backtrack to bare.
MARKER_RE = re.compile(r"ubs:ignore(?:\[([A-Za-z0-9_.,\- ]*)\])?(?!\[)")
BARE_ALIAS_RE = re.compile(
    r"(?<![\w:])(?:nolint|noqa|ubs:\s*disable)(?![\w.:/\-]|\s*[\[(:])",
    re.IGNORECASE,
)
_QUALIFIED_MARKER_RE = re.compile(
    r"(?:ubs:ignore|nolint|noqa|ubs:\s*disable)\s*"
    r"(?:\[[^\]\n]*(?:\]|$)|\([^\)\n]*(?:\)|$)|:[^\n]*)",
    re.IGNORECASE,
)

_HASH_LANGS = frozenset({"python", "ruby", "elixir"})
_BLOCK_KEYWORDS = {"ruby": ("def ", "end"), "elixir": ("do", "end")}
_C_CONTINUATION = ("\\", "(", "[", ",", "&&", "||", "=>", "=", "+", "-", "*", "/", "?", "|", "&", "<", ">", ".")
_PY_CONTINUATION = ("\\", "(", "[", "{", ",", "&", "|", "+", ".", "->", "do", "then", "else")


def may_have_markers(text: str) -> bool:
    """Cheap candidate check only; ``build_index`` decides lexical ownership."""
    return "ubs:ignore" in text or BARE_ALIAS_RE.search(text) is not None


def has_suppression_marker(text: str, rule: str | None = None) -> bool:
    """Classify marker scope at an existing caller-selected source anchor.

    This checks syntax only; callers retain their existing string masking and
    line/statement boundaries. An unknown rule accepts only bare markers (and
    empty scopes, as in ``parse_markers``), so collecting taint cannot discard
    a source merely because one particular finding was annotated.
    """
    for match in MARKER_RE.finditer(text):
        rules_blob = match.group(1)
        rules = frozenset(p.strip() for p in (rules_blob or "").split(",") if p.strip())
        if not rules or (rule is not None and rule in rules):
            return True
    return False


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
    standalone: bool = False


@dataclass
class SuppressionIndex:
    intervals: list[Interval] = field(default_factory=list)
    markers: list[Marker] = field(default_factory=list)
    statements: list[Interval] = field(default_factory=list)
    formatter_headers: dict[int, Interval] = field(default_factory=dict)

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
        statement = interval if interval in self.statements else None
        return any(
            (marker.rules is None or rule in marker.rules) and (
                marker.line == line
                or (statement is not None and statement.contains(marker.line))
                or (marker.line in self.formatter_headers
                    and self.formatter_headers[marker.line].contains(line))
                or (marker.standalone and interval is not None and (
                    marker.line == interval.start_line - 1
                    or (marker.line == line + 1 and any(
                        block.start_line == line and block.contains(marker.line)
                        and block not in self.statements
                        for block in self.intervals
                    ))
                ))
            )
            for marker in self.markers
        )


class SourceSuppressions:
    """Invocation-local source indexes for canonical finding records.

    Keep records without a concrete source location: project aggregates cannot
    be assigned an arbitrary source's marker. Unreadable sources likewise give
    no permission to suppress a finding. Nothing here is persisted in ScanCache.
    """

    def __init__(self, lang: str) -> None:
        self.lang = lang
        self.indexes: dict[Path, SuppressionIndex] = {}

    def index(self, path: str | Path, text: str | None = None) -> SuppressionIndex:
        try:
            source = Path(path).resolve()
        except (OSError, RuntimeError):
            return SuppressionIndex()
        if source not in self.indexes:
            if text is None:
                try:
                    text = source.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
            self.indexes[source] = (
                build_index(text, lang=self.lang) if may_have_markers(text) else SuppressionIndex()
            )
        return self.indexes[source]

    def is_suppressed(self, path: str | Path, line: int, rule: str | None) -> bool:
        return bool(path) and line > 0 and self.index(path).is_suppressed(line, rule or "")

    def filter(self, records: list[dict]) -> list[dict]:
        return [record for record in records if not self.is_suppressed(
            record.get("path", ""), int(record.get("line", 0) or 0), record.get("rule"),
        )]


def parse_markers(text: str, lang: str = "python") -> list[Marker]:
    """Return scoped markers and bare aliases from actual comments only.

    Comments survive the mask (preserve_comments=True) because markers naturally
    live in comments; string contents are blanked so documented examples like
    `use "ubs:ignore" carefully` never suppress anything. Comment detection
    stays active, so an apostrophe in a comment ("don't") cannot open a
    phantom string and hide later markers.
    """
    masked = strip_comments_and_strings(
        text, lang=lang, strip_strings=True, strip_comments=True, preserve_comments=True
    )
    code = strip_comments_and_strings(
        text, lang=lang, strip_strings=False, strip_comments=True
    )
    code_lines = code.splitlines()
    # Both views preserve offsets. Only comments survive the first mask while
    # disappearing in the second; ordinary code and preserved strings cannot
    # contribute markers. Retain newlines for physical source ownership.
    comments = "".join(
        char if char == "\n" or (char != code_char and code_char == " ") else " "
        for char, code_char in zip(masked, code)
    )
    markers: list[Marker] = []
    for lineno, line in enumerate(comments.splitlines(), start=1):
        standalone = lineno <= len(code_lines) and not code_lines[lineno - 1].strip()
        for match in MARKER_RE.finditer(line):
            rules_blob = match.group(1)
            if rules_blob is None:
                rules = None
            else:
                rules = frozenset(p.strip() for p in rules_blob.split(",") if p.strip()) or None
            markers.append(Marker(line=lineno, rules=rules, standalone=standalone))
        qualified_spans = [match.span() for match in _QUALIFIED_MARKER_RE.finditer(line)]
        for match in BARE_ALIAS_RE.finditer(line):
            # An alias word inside an unknown or malformed scope is not a
            # second, bare directive (for example `ubs:ignore[noqa]`).
            if not any(start <= match.start() < end for start, end in qualified_spans):
                markers.append(Marker(line=lineno, rules=None, standalone=standalone))
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
    headers: list[tuple[int, int]] = []
    last_code = 0
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        while headers and indent <= headers[-1][1]:
            header, _header_indent = headers.pop()
            if last_code >= header:
                blocks.append(Interval(header, last_code))
        if line.rstrip().endswith(":"):
            # Retain nested headers as well as their enclosing function/class.
            # Otherwise a formatter marker immediately inside an inner `if`
            # has no block opening to own, despite the source indentation.
            headers.append((lineno, indent))
        last_code = lineno
    for header, _header_indent in headers:
        if last_code >= header:
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
        lang=lang,
        strip_strings=True,
        strip_comments=True,
    )
    lines = masked.splitlines()
    index = SuppressionIndex()
    index.markers = parse_markers(text, lang=lang)

    paren_before, paren_after = _paren_depths(lines)
    brace_blocks = _brace_blocks(lines)
    index.intervals.extend(brace_blocks)
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
                index.statements.append(Interval(start, lineno - 1))
                start = 0
            continue
        if start == 0:
            start = lineno
        if _continues(code, paren_after[lineno] > 0, lang):
            continue
        index.statements.append(Interval(start, lineno))
        start = 0
    if start:
        index.statements.append(Interval(start, len(lines)))

    index.intervals.extend(index.statements)

    # A formatter can move the opening brace itself onto the next line:
    # `using (var item = acquire())` followed by `{ // ubs:ignore`.
    # Associate a marker on that brace-only line with its control header,
    # never with an ordinary preceding call or every statement in the block.
    for block in brace_blocks:
        if lines[block.start_line - 1].strip() != "{":
            continue
        header = next((statement for statement in index.statements
                       if statement.end_line == block.start_line - 1), None)
        if header is None:
            continue
        header_code = " ".join(lines[header.start_line - 1:header.end_line]).strip()
        if re.match(r"^(?:await\s+)?(?:if|else|for|while|switch|catch|using|lock|synchronized|try|do|finally|unsafe)\b",
                    header_code) and not header_code.endswith(";"):
            index.formatter_headers[block.start_line] = header

    return index
