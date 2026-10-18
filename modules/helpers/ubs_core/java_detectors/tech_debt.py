"""ubs_core.java_detectors.tech_debt — category 6 (bead 0xjg.8).

Port of the technical debt marker ladder (modules/ubs-java.sh 3631-3642):
case-insensitive TODO/FIXME/HACK counts summed (NOTE is counted by legacy but
excluded from the ladder); >20 switches the finding to the warning-tier
"Significant technical debt" title, >0 stays info. The tier is resolved once
from all project-wide facts and expressed as a rule-id switch (multi-rule
protocol). Source-owned directives filter findings using that selected rule.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.java_detectors._common import iter_java_files, read_lines

CATEGORY = 6

RULES = (
    ("java.logging.tech-debt", CATEGORY, "TODO/FIXME/HACK markers present", "info", ""),
    ("java.logging.tech-debt-significant", CATEGORY, "Significant technical debt", "warning", ""),
)

RULE_INFO, RULE_WARN = RULES[0][0], RULES[1][0]
THRESHOLD = 20

_MARKER_RES = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (r"TODO", r"FIXME", r"HACK")
)


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    suppressions = SourceSuppressions('java')
    hits: list[tuple[Path, int, str]] = []
    for path in iter_java_files(files):
        lines = read_lines(path)
        suppressions.index(path, '\n'.join(lines))
        for idx, line in enumerate(lines, start=1):
            if any(regex.search(line) for regex in _MARKER_RES):
                hits.append((path, idx, line.strip()[:240]))
    if not hits:
        return
    rule_id = RULE_WARN if len(hits) > THRESHOLD else RULE_INFO
    for path, line_no, detail in hits:
        if not suppressions.index(path).is_suppressed(line_no, rule_id):
            yield rule_id, path, line_no, 1, detail
