"""ubs_core.cpp_detectors.perf_io — category 14 loop pipelines (bead 0xjg.9).

Ports of the CATEGORY 14 pipelines (modules/ubs-cpp.sh 3459-3469):

    rg "for|while" <files> | grep -A3  "\\+="  | grep -w  "\\+=" | count_lines
    rg "for|while" <files> | grep -A5 -E "std::cout|...printf" | grep -E "cout|cerr|printf"

The stream is the rg output itself: every for/while line, in file order.
`grep -A N` re-emits each context-window line, so a line inside K overlapping
windows is counted K times — reproduced literally. count_lines drops
`ubs:ignore` lines at the COUNTING stage (the final grep's output).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.cpp_scan import MARKER

RULES = (
    ("cpp.perf.string-concat-loops", 14,
     "String += in loops - consider reserve/ostringstream/fmt::memory_buffer", "info", ""),
    ("cpp.perf.io-in-loops", 14,
     "I/O inside loops - buffer or batch", "info", ""),
)

_LOOP_RE = re.compile(r"for|while")
_CONCAT_STAGE2_RE = re.compile(r"\+=")  # BRE "\+=" — literal +=, no word check
_CONCAT_STAGE3_RE = re.compile(r"(?<![A-Za-z0-9_])\+=(?![A-Za-z0-9_])")  # grep -w "\+="
_IO_STAGE2_RE = re.compile(r"std::cout|std::cerr|printf|fprintf|std::printf")
_IO_STAGE3_RE = re.compile(r"cout|cerr|printf")

_CONCAT_CONTEXT = 3  # grep -A3
_IO_CONTEXT = 5  # grep -A5


def _grep_a_count(stream: list[str], stage2: re.Pattern[str], stage3: re.Pattern[str],
                  context: int) -> int:
    """grep -A<context> PATTERN | grep -E PATTERN3 | count_lines semantics."""
    count = 0
    for idx, line in enumerate(stream):
        if not stage2.search(line):
            continue
        window = stream[idx:idx + context + 1]  # the line itself + N after
        for candidate in window:
            if stage3.search(candidate) and MARKER not in candidate:
                count += 1
    return count


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    streams: list[str] = []
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        streams.extend(line for line in lines if _LOOP_RE.search(line))
    concat_count = _grep_a_count(streams, _CONCAT_STAGE2_RE, _CONCAT_STAGE3_RE, _CONCAT_CONTEXT)
    if concat_count > 8:
        yield "cpp.perf.string-concat-loops", "", 0, 1, f"{concat_count} occurrences"
    io_count = _grep_a_count(streams, _IO_STAGE2_RE, _IO_STAGE3_RE, _IO_CONTEXT)
    if io_count > 5:
        yield "cpp.perf.io-in-loops", "", 0, 1, f"{io_count} occurrences"
