"""ubs_core.cpp_detectors.quality_markers — category 13 (bead 0xjg.9).

Port of the CATEGORY 13 marker census (modules/ubs-cpp.sh 3420-3448).
Legacy counted each marker (TODO/FIXME/HACK/XXX, case-insensitive) as its
own rg pass and SUMMED the counts — a line carrying two markers scored
twice, and the ladder resolved once on the sum:
    warning > 20  "Significant technical debt"
    info    > 10  "Moderate technical debt"
    info    > 0   "Minimal technical debt"
NOTE markers were tallied for the breakdown only (never counted).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.cpp_scan import MARKER

RULE_ID = "cpp.quality.markers"
CATEGORY = 13

_TIERS = (
    (20, "warning", "Significant technical debt"),
    (10, "info", "Moderate technical debt"),
    (0, "info", "Minimal technical debt"),
)

_MARKERS = ("TODO", "FIXME", "HACK", "XXX")


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    hits: list[tuple[Path, int, str]] = []
    seen: set[tuple[Path, int, str]] = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for marker in _MARKERS:
            regex = re.compile(re.escape(marker), re.IGNORECASE)
            for idx, line in enumerate(lines, start=1):
                if MARKER in line:
                    continue  # legacy count_lines drops marker lines
                if regex.search(line) and (path, idx, marker) not in seen:
                    seen.add((path, idx, marker))
                    hits.append((path, idx, line.strip()[:240]))
    if not hits:
        return
    total = len(hits)
    for min_count, severity, title in _TIERS:
        if total > min_count:
            for path, line_no, code in hits:
                yield path, line_no, 1, f"{title} — {code}"
            return
