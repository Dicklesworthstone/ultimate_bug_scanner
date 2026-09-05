"""ubs_core.java_detectors.io_loops — category 5 (bead 0xjg.8).

Port of the Files.readAllBytes-in-loop pipeline (modules/ubs-java.sh
3600-3602): legacy piped `rg 'for\\s*\\(|while\\s*\\('` through
`grep -A4 -F 'Files.readAllBytes('` and re-filtered for readAllBytes lines —
i.e. readAllBytes lines within 4 lines after a loop header. count_lines
marker semantics apply (ubs:ignore lines dropped).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_scan import MARKER
from ubs_core.java_detectors._common import iter_java_files, read_lines

RULE_ID = "java.io.readallbytes-loop"
CATEGORY = 5
TITLE = "Files.readAllBytes in loop - consider streaming"
SEVERITY = "warning"
DESCRIPTION = ""

LOOP_RE = re.compile(r"for[ \t]*\(|while[ \t]*\(")
TARGET = "Files.readAllBytes("
WINDOW = 4  # legacy grep -A4


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in iter_java_files(files):
        lines = read_lines(path)
        recent_loop_lines: list[int] = []
        for idx, line in enumerate(lines, start=1):
            if LOOP_RE.search(line):
                recent_loop_lines.append(idx)
            if TARGET not in line:
                continue
            if MARKER in line:
                continue  # count_lines drops marker lines from counts
            if any(idx - start <= WINDOW for start in recent_loop_lines):
                yield path, idx, 1, line.strip()[:240]
