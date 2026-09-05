"""ubs_core.cpp_detectors.async_errors — category 3 std::async coverage (bead 0xjg.9).

Port of run_async_error_checks (modules/ubs-cpp.sh 682-704): for every file
containing std::async, a std::future line with no `.get(` line at all is one
warning. Legacy counted per FILE (no source location); the sink record
carries the file with line 0, and the renderer prints it location-less.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.cpp_scan import MARKER

RULE_ID = "cpp.async.future-no-get"
CATEGORY = 3
TITLE = "std::future from std::async without get()"
SEVERITY = "warning"
DESCRIPTION = "Call get()/wait() on futures to surface exceptions"

_ASYNC_RE = re.compile(r"std::async[ \t]*\(")
_FUTURE_RE = re.compile(r"std::future")
_GET_RE = re.compile(r"\.get[ \t]*\(")


def _count(lines: list[str], regex: re.Pattern[str]) -> int:
    # legacy count_lines: distinct matching lines minus ubs:ignore marker lines
    return sum(1 for line in lines if regex.search(line) and MARKER not in line)


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h',
                                       '.hh', '.hpp', '.hxx', '.ipp', '.tpp',
                                       '.ixx', '.cppm', '.mpp'}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        if not any(_ASYNC_RE.search(line) and MARKER not in line for line in lines):
            continue
        if _count(lines, _FUTURE_RE) > 0 and _count(lines, _GET_RE) == 0:
            try:
                rel = str(path.resolve().relative_to(cwd))
            except ValueError:
                rel = path.name
            yield rel, 0, 1, DESCRIPTION
