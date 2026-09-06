"""Shared helpers for the ubs_core.ruby_detectors heredoc ports.

Line utilities are verbatim from the module heredocs (identical bodies were
inlined in every detector there): comment/string stripping, the current +
previous-line `ubs:ignore` check, parenthesis-balanced logical statements,
source-line extraction.
"""
from __future__ import annotations

import re
from pathlib import Path

# The heredocs' shared extension whitelist (INCLUDE_EXT as a suffix set).
EXTS = frozenset({".rb", ".rake", ".ru", ".gemspec", ".erb", ".haml", ".slim", ".rbi", ".rbs", ".jbuilder"})
from typing import Iterable


def strip_line_comments(line: str) -> str:
    out = []
    quote = ""
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def has_ignore(lines, line_no: int) -> bool:
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and "ubs:ignore" in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and "ubs:ignore" in lines[idx - 1]
    )


def logical_statement(lines, line_no: int) -> str:
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count("(") - statement.count(")")
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead])
        statement += " " + next_line.strip()
        balance += next_line.count("(") - next_line.count(")")
        lookahead += 1
    return statement


def context_around(lines, line_no: int, before: int = 8, after: int = 10) -> str:
    start = max(0, line_no - before)
    end = min(len(lines), line_no + after)
    return "\n".join(strip_line_comments(line) for line in lines[start:end])


def source_line(lines, line_no: int) -> str:
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def identifier_search_text(expr: str) -> str:
    """Blank out string-literal bodies but keep #{} interpolation contents."""
    out = []
    quote = ""
    escape = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escape:
                escape = False
                i += 1
                continue
            if ch == "\\":
                escape = True
                i += 1
                continue
            if quote == '"' and ch == "#" and i + 1 < len(expr) and expr[i + 1] == "{":
                depth = 1
                j = i + 2
                interpolation = []
                while j < len(expr) and depth > 0:
                    current = expr[j]
                    if current == "{":
                        depth += 1
                    elif current == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    interpolation.append(current)
                    j += 1
                out.append(" ")
                out.append("".join(interpolation))
                out.append(" ")
                i = j + 1
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def ruby_files(files: Iterable[Path], exts) -> Iterable[Path]:
    """The heredocs' `iter_files`: suffix-filtered, files only."""
    for path in files:
        try:
            if path.is_file() and path.suffix.lower() in exts:
                yield path
        except OSError:
            continue


def read_lines(path: Path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None


def word_regex(name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(name)}\b")
