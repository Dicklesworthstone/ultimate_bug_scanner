"""ubs_core.java_detectors.runtime_exec — category 4 (bead 0xjg.8).

Port of the Runtime.exec check (modules/ubs-java.sh 3550-3566) and its
`java_pattern_scan runtime_exec` fallback (589-591): both use the identical
line regex `Runtime\\.getRuntime\\(\\)\\.exec`, so the v2 keeps one per-line
detector. Legacy's rg layer dropped ubs:ignore lines via count_lines, but the
fallback then re-counted them — net effect: no marker suppression.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_detectors._common import iter_java_files, read_lines

RULE_ID = "java.security.runtime-exec"
CATEGORY = 4
TITLE = "Runtime.exec invoked"
SEVERITY = "critical"
DESCRIPTION = "Sanitize command arguments or avoid spawning shell commands"

EXEC_RE = re.compile(r"Runtime\.getRuntime\(\)\.exec")


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in iter_java_files(files):
        lines = read_lines(path)
        for idx, line in enumerate(lines, start=1):
            if EXEC_RE.search(line):
                yield path, idx, 1, line.strip()[:240]
