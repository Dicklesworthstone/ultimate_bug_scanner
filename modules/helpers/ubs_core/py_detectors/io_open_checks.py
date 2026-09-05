r"""ubs_core.py_detectors.io_open_checks — cat 16 open()/with ratio (bead 0xjg.5).

Port of the legacy "open(...) without context manager" ratio check
(modules/ubs-python.sh 11648-11656):

    open_calls=$(rg -e 'open\(' … | count_lines)
    with_calls=$(rg -e 'with[[:space:]]+[^:]*open\(' … | count_lines)
    if [ open_calls -gt 0 ] && [ with_calls -lt open_calls ]; then
      print_finding warning $((open_calls - with_calls)) \
        "open() calls missing 'with'" \
        "Wrap file handles in context managers or close them explicitly"
    else
      print_finding good "File usage appears context-managed"
    fi

Every `with … open(` line necessarily matches `open(` too, so the diff
equals exactly the set of open() lines lacking a with-prefix. The v2
record stream therefore emits one record per such line (same detail style
as the legacy code samples) and nothing at all when usage is balanced —
the good fallback is rendered upstream. `count_lines` drops lines carrying
`ubs:ignore`, so marker lines are excluded from both counts here.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_scan import MARKER

RULE_ID = "py.io.open-missing-with"
CATEGORY = 16
TITLE = "open() calls missing 'with'"
SEVERITY = "warning"
DESCRIPTION = "Wrap file handles in context managers or close them explicitly"

OPEN_RE = re.compile(r"open\(")
# legacy grep ERE `with[[:space:]]+[^:]*open\(`.
WITH_OPEN_RE = re.compile(r"with[ \t]+[^:]*open\(")


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    open_calls = 0
    with_calls = 0
    candidates: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if MARKER in line:
                continue  # count_lines drops marker lines from both counts
            if not OPEN_RE.search(line):
                continue
            open_calls += 1
            if WITH_OPEN_RE.search(line):
                with_calls += 1
            else:
                candidates.append((path, line_no, 1, line.strip()[:240]))
    if open_calls > 0 and with_calls < open_calls:
        yield from candidates
