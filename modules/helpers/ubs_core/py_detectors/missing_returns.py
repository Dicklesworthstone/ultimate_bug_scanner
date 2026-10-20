"""ubs_core.py_detectors.missing_returns — category 8 def-vs-return ratio (bead 0xjg.5).

Port of the legacy "Missing returns heuristic" (modules/ubs-python.sh
11383-11389): count lines matching ``^[[:space:]]*def[[:space:]]+[A-Za-z_]``
vs lines carrying the whole word ``return`` project-wide; when the def count
exceeds the return count, print ONE info finding whose count is the deficit.
The comparison needs two independent project-wide counts, which a single
Pattern (one regex, thresholds resolved from one total) cannot express — so
it is a detector.

Legacy printed no code samples; v2 anchors the deficit as records on the
first ``diff`` def lines so the sink counter still equals the legacy count
while pointing at code. Shared comment ownership and the public rule scope
apply to both counts before calculating the deficit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions

RULE_ID = "py.functions.missing-returns"
CATEGORY = 8
TITLE = "Some functions may lack return statements"
SEVERITY = "info"
DESCRIPTION = "Void intended?"

_DEF_RE = re.compile(r"^[ \t]*def[ \t]+[A-Za-z_]", re.MULTILINE)
_RETURN_RE = re.compile(r"\breturn\b")  # legacy GREP_RNW "return" (whole word)


def _line_at(text: str, pos: int) -> tuple[int, str]:
    line_no = text.count("\n", 0, pos) + 1
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return line_no, text[start:end]


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions("python")
    def_hits: list[tuple[Path, int, str]] = []
    def_count = 0
    ret_count = 0
    for path in files:
        if path.suffix.lower() not in {".py", ".pyi"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        index = suppressions.index(path, text)
        for match in _DEF_RE.finditer(text):
            line_no, line_text = _line_at(text, match.start())
            if index.is_suppressed(line_no, RULE_ID):
                continue
            def_count += 1
            def_hits.append((path, line_no, line_text.strip()[:240]))
        for line_no, line_text in enumerate(text.splitlines(), start=1):
            if index.is_suppressed(line_no, RULE_ID):
                continue
            if _RETURN_RE.search(line_text):
                ret_count += 1
    diff = def_count - ret_count
    if diff <= 0:
        return
    # File discovery order must not change which sites represent the deficit.
    def_hits.sort(key=lambda hit: (hit[0].as_posix(), hit[1]))
    for path, line_no, code in def_hits[:diff]:
        yield path, line_no, 1, code
