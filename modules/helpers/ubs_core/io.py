"""ubs_core.io — Line/column, location formatting, and delimiter navigation (bead A2).

Stdlib-only implementation reconciling line_col, format_location, find_block_end,
and statement extraction across UBS language helpers.
"""
from __future__ import annotations

from pathlib import Path


def line_col(text: str, pos: int) -> tuple[int, int]:
    """Return 1-indexed (line, column) for character offset `pos` in `text`."""
    if pos < 0:
        pos = 0
    if pos > len(text):
        pos = len(text)
    line = text.count("\n", 0, pos) + 1
    last_newline = text.rfind("\n", 0, pos)
    col = pos + 1 if last_newline == -1 else pos - last_newline
    return line, col


def format_location(base: Path | str, path: Path | str, pos: int, text: str) -> str:
    """Format path:line:col relative to `base` directory."""
    base_path = Path(base)
    file_path = Path(path)
    line, col = line_col(text, pos)
    try:
        rel = file_path.relative_to(base_path)
    except ValueError:
        rel = file_path
    return f"{rel}:{line}:{col}"


def find_block_end(
    text: str,
    brace_start: int,
    open_char: str = "{",
    close_char: str = "}",
) -> int:
    """Find the index of the matching close delimiter for a balanced block starting at or after `brace_start`.

    If delimiters are unbalanced or not closed, returns `len(text) - 1`.
    """
    n = len(text)
    if brace_start < 0 or brace_start >= n:
        return max(0, n - 1)

    idx = brace_start
    # If brace_start does not point directly to open_char, advance to first open_char
    if text[idx] != open_char:
        next_open = text.find(open_char, idx)
        if next_open == -1:
            return n - 1
        idx = next_open

    depth = 0
    while idx < n:
        ch = text[idx]
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return n - 1


def skip_ws(text: str, idx: int) -> int:
    """Advance `idx` past whitespace characters in `text`."""
    n = len(text)
    while idx < n and text[idx].isspace():
        idx += 1
    return idx


def extract_statement_region(
    text: str,
    start_idx: int,
    *,
    newline_terminates: bool = True,
) -> tuple[str, int]:
    """Extract next statement or brace-delimited block region starting at `start_idx`.

    Returns `(region_text, next_index)`.
    """
    idx = skip_ws(text, start_idx)
    n = len(text)
    if idx >= n:
        return "", n

    if text[idx] == "{":
        end = find_block_end(text, idx)
        return text[idx : end + 1], end + 1

    semi = text.find(";", idx)
    newline = text.find("\n", idx) if newline_terminates else -1

    if semi == -1 and newline == -1:
        return text[idx:], n
    if semi == -1:
        end = newline
    elif newline == -1:
        end = semi + 1
    else:
        end = min(semi + 1, newline)
    return text[idx:end], end

