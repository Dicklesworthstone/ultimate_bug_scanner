"""swift_detectors._common — helpers shared by the legacy heredoc ports.

The heredocs in modules/ubs-swift.sh each carried private copies of these
helpers with small behavioral differences (bracket sets, continuation rules,
quote handling); the variants are preserved exactly per detector.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

# skip_dirs of the four request-taint heredocs + the archive heredoc
SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'DerivedData', 'build', 'dist',
             'vendor', '.build', '.swiftpm'}

MARKER = "ubs:ignore"


def should_skip(path: Path, base: Path, skip_dirs=SKIP_DIRS) -> bool:
    try:
        parts = path.relative_to(base).parts
    except ValueError:
        parts = path.parts
    return any(part in skip_dirs for part in parts)


def iter_swift_files(root: Path, base: Path, skip_dirs=SKIP_DIRS) -> Iterator[Path]:
    """The heredocs' iter_swift_files: single file or rglob('*.swift')."""
    if root.is_file():
        if root.suffix == '.swift':
            yield root
        return
    for candidate in sorted(root.rglob('*.swift')):
        if candidate.is_file() and not should_skip(candidate, base, skip_dirs):
            yield candidate


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def strip_line_comments(line: str, single_quotes: bool = True) -> str:
    """Blank a `//` comment, honoring string literals (per-heredoc semantics)."""
    out = []
    quote = ''
    escape = False
    i = 0
    quotes = ('"', "'") if single_quotes else ('"',)
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
        if ch in quotes:
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def logical_statement(lines: list[str], line_no: int, brackets: str = "()",
                      dotted_continuation: bool = False,
                      trailing_continuation: bool = False,
                      single_quotes: bool = True) -> str:
    """Join continuation lines while brackets are unbalanced (heredoc variant).

    - brackets: "()" for the taint/archive heredocs, "()[]" for randomness
    - dotted_continuation: header-injection also joins lines starting with '.'
    - trailing_continuation: randomness also joins lines ending with , + \\
    """
    idx = line_no - 1
    statement = strip_line_comments(lines[idx], single_quotes)
    if brackets == "()[]":
        balance = (statement.count('(') + statement.count('[')
                   - statement.count(')') - statement.count(']'))
    else:
        balance = statement.count('(') - statement.count(')')
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead], single_quotes).strip()
        if dotted_continuation or trailing_continuation:
            if balance <= 0 and not next_line.startswith('.') and not (
                trailing_continuation and statement.rstrip().endswith((',', '+', '\\'))
            ):
                break
        elif balance <= 0:
            break
        statement += ' ' + next_line
        if brackets == "()[]":
            balance += (next_line.count('(') + next_line.count('[')
                        - next_line.count(')') - next_line.count(']'))
        else:
            balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement


def has_ignore(lines: list[str], line_no: int) -> bool:
    """Same-line or previous-line `ubs:ignore` (the heredocs' check)."""
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def source_line(lines: list[str], line_no: int) -> str:
    idx = line_no - 1
    return lines[idx].strip() if 0 <= idx < len(lines) else ''
