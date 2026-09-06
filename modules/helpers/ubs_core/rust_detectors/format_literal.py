"""ubs_core.rust_detectors.format_literal — format!(literal) allocations (bead 0xjg.7).

Port of rust_format_literal_matches (modules/ubs-rust.sh 6805-6988): flags
`format!("literal")` calls whose first argument is a string literal with no
`{`/`}` placeholders and no further arguments (allocation equivalent to
`.to_string()`). The legacy UBS_RUST_FILE_LIST/rglob iteration is replaced by
the caller's `files` argument (the heredoc had no .resolve(); entries keep
their given spelling), and the legacy skip-dir list is documentation-only.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "rust.allocation.format-literal"
CATEGORY = 6
TITLE = "format!(literal) allocates - use .to_string()"
SEVERITY = "info"
DESCRIPTION = ""


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def is_ident(ch: str) -> bool:
    return ch == "_" or ch.isalnum()


def skip_ws(text: str, idx: int, end: int) -> int:
    while idx < end and text[idx].isspace():
        idx += 1
    return idx


def parse_raw_string(text: str, idx: int, end: int):
    start = idx
    if idx < end and text[idx] == "b":
        idx += 1
    if idx >= end or text[idx] != "r":
        return None
    idx += 1
    hashes = 0
    while idx < end and text[idx] == "#":
        hashes += 1
        idx += 1
    if idx >= end or text[idx] != '"':
        return None
    content_start = idx + 1
    close = '"' + ("#" * hashes)
    close_at = text.find(close, content_start)
    if close_at < 0 or close_at >= end:
        return None
    return close_at + len(close), text[content_start:close_at], start


def parse_cooked_string(text: str, idx: int, end: int):
    start = idx
    if idx < end and text[idx] == "b":
        idx += 1
    if idx >= end or text[idx] != '"':
        return None
    idx += 1
    content = []
    while idx < end:
        ch = text[idx]
        if ch == "\\":
            if idx + 1 < end:
                content.append(ch)
                content.append(text[idx + 1])
                idx += 2
                continue
        if ch == '"':
            return idx + 1, "".join(content), start
        content.append(ch)
        idx += 1
    return None


def parse_string_literal(text: str, idx: int, end: int):
    return parse_raw_string(text, idx, end) or parse_cooked_string(text, idx, end)


def skip_comment_string_or_char(text: str, idx: int, end: int) -> int:
    if text.startswith("//", idx):
        nl = text.find("\n", idx + 2, end)
        return end if nl < 0 else nl
    if text.startswith("/*", idx):
        close = text.find("*/", idx + 2, end)
        return end if close < 0 else close + 2
    parsed = parse_string_literal(text, idx, end)
    if parsed:
        return parsed[0]
    if text[idx] == "'":
        idx += 1
        while idx < end:
            if text[idx] == "\\":
                idx += 2
                continue
            if text[idx] == "'":
                return idx + 1
            if text[idx] == "\n":
                return idx
            idx += 1
    return idx


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    idx = open_idx
    end = len(text)
    while idx < end:
        skipped = skip_comment_string_or_char(text, idx, end)
        if skipped != idx:
            idx = skipped
            continue
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return -1


def iter_format_literal_lines(path: Path, text: str):
    idx = 0
    end = len(text)
    lines = text.splitlines()
    while idx < end:
        skipped = skip_comment_string_or_char(text, idx, end)
        if skipped != idx:
            idx = skipped
            continue
        if text.startswith("format!", idx) and (idx == 0 or not is_ident(text[idx - 1])):
            cursor = skip_ws(text, idx + len("format!"), end)
            if cursor < end and text[cursor] == "(":
                close = find_matching_paren(text, cursor)
                if close > cursor:
                    arg = skip_ws(text, cursor + 1, close)
                    parsed = parse_string_literal(text, arg, close)
                    if parsed:
                        literal_end, content, _ = parsed
                        rest = skip_ws(text, literal_end, close)
                        if rest < close and text[rest] == ",":
                            rest = skip_ws(text, rest + 1, close)
                        if rest == close and "{" not in content and "}" not in content:
                            line = line_number(text, idx)
                            code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                            if "ubs:ignore" not in code:
                                yield line, code
                    idx = close + 1
                    continue
        idx += 1


def find(files: Sequence[Path]) -> Iterable[tuple]:
    seen = set()
    for path in files:
        if path.suffix != ".rs":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line, code in iter_format_literal_lines(path, text):
            key = (str(path), line)
            if key in seen:
                continue
            seen.add(key)
            yield path, line, 1, code


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
