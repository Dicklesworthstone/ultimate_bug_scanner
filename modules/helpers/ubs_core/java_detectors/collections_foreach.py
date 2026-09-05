"""ubs_core.java_detectors.collections_foreach — category 8 (bead 0xjg.8).

Port of the foreach-mutation window pipeline (modules/ubs-java.sh
3689-3691): legacy piped `rg 'for\\s*\\([^)]+:[^)]+\\)\\s*\\{'` through
`grep -A3 -F '.remove('` and re-filtered for .remove( lines — i.e. .remove(
lines within 3 lines after an enhanced-for header. count_lines marker
semantics apply.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_scan import MARKER
from ubs_core.java_detectors._common import iter_java_files, read_lines

RULE_ID = "java.collections.foreach-remove"
CATEGORY = 8
TITLE = "Possible modification of collection during iteration"
SEVERITY = "warning"
DESCRIPTION = ""

FOREACH_RE = re.compile(r"for[ \t]*\([^)]+:[^)]+\)[ \t]*\{")
TARGET = ".remove("
WINDOW = 3  # legacy grep -A3


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in iter_java_files(files):
        lines = read_lines(path)
        foreach_line = None
        for idx, line in enumerate(lines, start=1):
            if FOREACH_RE.search(line):
                foreach_line = idx
            if TARGET not in line:
                continue
            if MARKER in line:
                continue
            if foreach_line is not None and idx - foreach_line <= WINDOW:
                yield path, idx, 1, line.strip()[:240]
