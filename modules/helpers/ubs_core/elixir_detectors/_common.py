"""Shared helpers for the ubs_core.elixir_detectors heredoc ports.

Comment/string stripping, the current + previous-line `ubs:ignore` check and
source-line extraction are identical in every elixir heredoc, so they live
here once. The per-detector logical_statement variants intentionally stay in
their detector modules (the heredocs differ in do/-> awareness, pipe
continuation handling and lookahead windows).
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

# The heredocs' shared extension whitelist (INCLUDE_EXT as a suffix set).
EXTS = frozenset({".ex", ".exs", ".eex", ".heex", ".leex", ".sface"})


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


def source_line(lines, line_no: int) -> str:
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def read_lines(path: Path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


def elixir_files(files: Iterable[Path], exts=EXTS) -> Iterable[Path]:
    """The heredocs' `iter_files`: suffix-filtered, files only."""
    for path in files:
        try:
            if path.is_file() and path.suffix.lower() in exts:
                yield path
        except OSError:
            continue
