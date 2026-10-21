"""ubs_core.java_detectors.streams_concat — category 10 (bead 0xjg.8).

Port of the string '+=' in loops pipeline (modules/ubs-java.sh 3732-3734):
legacy piped `rg 'for\\s*\\(|while\\s*\\('` through `grep -A3 '+="'` and a
word-match `grep -w '+="'` — i.e. `+=` lines within 3 lines after a loop
header. Source-owned directives filter findings after loop context is collected.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.java_detectors._common import iter_java_files, read_lines

RULE_ID = "java.streams-perf.string-plus-loop"
CATEGORY = 10
TITLE = "String '+=' in loops - prefer StringBuilder"
SEVERITY = "info"
DESCRIPTION = ""

LOOP_RE = re.compile(r"for[ \t]*\(|while[ \t]*\(")
TARGET_RE = re.compile(r"\+=")
WINDOW = 3  # legacy grep -A3


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions('java')
    for path in iter_java_files(files):
        lines = read_lines(path)
        suppression = suppressions.index(path, '\n'.join(lines))
        recent_loop_lines: list[int] = []
        for idx, line in enumerate(lines, start=1):
            if LOOP_RE.search(line):
                recent_loop_lines.append(idx)
            if not TARGET_RE.search(line):
                continue
            if any(idx - start <= WINDOW for start in recent_loop_lines):
                if not suppression.is_suppressed(idx, RULE_ID):
                    yield path, idx, 1, line.strip()[:240]
