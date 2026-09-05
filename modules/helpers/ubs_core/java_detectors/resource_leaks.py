"""ubs_core.java_detectors.resource_leaks — category 19 (bead 0xjg.8).

Port of the `java_pattern_scan executor_leak` mode (modules/ubs-java.sh
595-614): a file instantiating an executor (Executors.newXxx / new
ThreadPoolExecutor) with no .shutdown(/.shutdownNow( anywhere yields ONE
warning anchored at its first instantiation line. No marker check in legacy
(the heredoc never inspected ubs:ignore).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_detectors._common import iter_java_files, read_lines

RULE_ID = "java.resource.executor-leak"
CATEGORY = 19
TITLE = "ExecutorService created without shutdown"
SEVERITY = "warning"
DESCRIPTION = "Call shutdown()/shutdownNow() in finally blocks"

POOL_RE = re.compile(r"Executors\.(?:new[A-Za-z]+)\s*\(|new\s+ThreadPoolExecutor\s*\(")
SHUTDOWN_RE = re.compile(r"\.shutdown(?:Now)?\s*\(")


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in iter_java_files(files):
        lines = read_lines(path)
        if not lines:
            continue
        text = "\n".join(lines)
        if not POOL_RE.search(text):
            continue
        if SHUTDOWN_RE.search(text):
            continue
        for idx, line in enumerate(lines, start=1):
            if POOL_RE.search(line):
                yield path, idx, 1, line.strip()[:240]
                break
