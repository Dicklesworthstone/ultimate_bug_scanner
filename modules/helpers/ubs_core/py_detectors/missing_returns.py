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
while pointing at code. ``count_lines`` dropped hit lines carrying
ubs:ignore from both counts; the same strip is applied here.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.functions.missing-returns"
CATEGORY = 8
TITLE = "Some functions may lack return statements"
SEVERITY = "info"
DESCRIPTION = "Void intended?"

MARKER = "ubs:ignore"

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
        for match in _DEF_RE.finditer(text):
            line_no, line_text = _line_at(text, match.start())
            if MARKER in line_text:
                continue  # count_lines strips marker lines from the count
            def_count += 1
            def_hits.append((path, line_no, line_text.strip()[:240]))
        for line_text in text.splitlines():
            if MARKER in line_text:
                continue
            if _RETURN_RE.search(line_text):
                ret_count += 1
    diff = def_count - ret_count
    if diff <= 0:
        return
    for path, line_no, code in def_hits[:diff]:
        yield path, line_no, 1, code
