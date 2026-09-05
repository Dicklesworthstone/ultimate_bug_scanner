"""ubs_core.java_detectors.control_flow — category 9 (bead 0xjg.8).

Port of the classic-switch count-comparison checks (modules/ubs-java.sh
3703-3715): project-wide counts of switch / case(!!) / break / default lines;
when cases exceed breaks the difference is reported as "may be missing
break", when switches exceed defaults as "no default case". The reported
count is a delta, so the record stream anchors one record per counted unit
on the trailing case/switch lines (delta == that many unmatched lines).
count_lines marker semantics apply to every count.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_scan import MARKER
from ubs_core.java_detectors._common import iter_java_files, read_lines

CATEGORY = 9

RULES = (
    ("java.control-flow.switch-fallthrough", CATEGORY,
     "Switch cases may be missing break (classic switch)", "warning", ""),
    ("java.control-flow.switch-no-default", CATEGORY,
     "Some switch statements have no default case (classic syntax)", "info", ""),
)

SWITCH_RE = re.compile(r"switch[ \t]*\(")
CASE_RE = re.compile(r"case[ \t]+.*:")
BREAK_RE = re.compile(r"\bbreak[ \t]*;")
DEFAULT_RE = re.compile(r"default[ \t]*:")
ARROW_RE = re.compile(r"->")


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    switch_lines: list[tuple[Path, int, str]] = []
    case_lines: list[tuple[Path, int, str]] = []
    breaks = 0
    defaults = 0
    for path in iter_java_files(files):
        lines = read_lines(path)
        for idx, line in enumerate(lines, start=1):
            if MARKER in line:
                continue  # count_lines drops marker lines from counts
            if SWITCH_RE.search(line):
                switch_lines.append((path, idx, line.strip()[:240]))
            if CASE_RE.search(line) and not ARROW_RE.search(line):
                case_lines.append((path, idx, line.strip()[:240]))
            if BREAK_RE.search(line):
                breaks += 1
            if DEFAULT_RE.search(line):
                defaults += 1
    fallthrough = len(case_lines) - breaks
    if len(case_lines) > breaks and fallthrough > 0:
        for path, line_no, detail in case_lines[-fallthrough:]:
            yield "java.control-flow.switch-fallthrough", path, line_no, 1, detail
    missing_default = len(switch_lines) - defaults
    if len(switch_lines) > defaults and missing_default > 0:
        for path, line_no, detail in switch_lines[-missing_default:]:
            yield "java.control-flow.switch-no-default", path, line_no, 1, detail
