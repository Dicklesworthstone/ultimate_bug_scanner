"""ubs_core.java_detectors.sql_concat_fallback — category 13 (bead 0xjg.8).

Port of the SQL-concatenation fallback ladder (modules/ubs-java.sh
3787-3801): the primary rg checks (the `java.sql.concat` pattern and the
`java.sql.exec-concat` require-filter pattern) run first; only when BOTH
count zero does the `java_pattern_scan sql_concat` fallback fire (looser
pattern, no identifier after the '+'). Marker semantics follow each legacy
layer: count_lines drops marker lines from the primary counts, while the
fallback heredoc never checked markers.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_scan import MARKER
from ubs_core.java_detectors._common import iter_java_files, read_lines

RULE_ID = "java.sql.concat-fallback"
CATEGORY = 13
TITLE = "SQL built via concatenation - prefer parameters"
SEVERITY = "warning"
DESCRIPTION = "Prefer PreparedStatement parameters over string concatenation"

PRIMARY_SQL_RE = re.compile(r'"(SELECT|INSERT|UPDATE|DELETE)[^"]*"[ \t]*\+[ \t]*[A-Za-z0-9_]')
PRIMARY_EXEC_RE = re.compile(r"execute(Query|Update)[ \t]*\(")
FALLBACK_RE = re.compile(r'"(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"[ \t]*\+')


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    sql_hits = 0
    exec_hits = 0
    fallback: list[tuple[Path, int, str]] = []
    for path in iter_java_files(files):
        lines = read_lines(path)
        for line in lines:
            if MARKER in line:
                continue
            if PRIMARY_SQL_RE.search(line):
                sql_hits += 1
            if PRIMARY_EXEC_RE.search(line) and "+" in line:
                exec_hits += 1
        for idx, line in enumerate(lines, start=1):
            if FALLBACK_RE.search(line):
                fallback.append((path, idx, line.strip()[:240]))
    if sql_hits > 0 or exec_hits > 0:
        return  # primary layers own the finding
    yield from fallback
