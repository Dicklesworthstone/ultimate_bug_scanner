"""ubs_core.java_detectors.equals_hashcode — category 2 (bead 0xjg.8).

Port of the per-file equals()/hashCode() pair check (modules/ubs-java.sh
3479-3485): a file declaring `boolean equals(` without any `int hashCode(`
yields one warning. The legacy loop matched .java/.kt only (not .kts), used
plain greps with no marker checks, and reported the first equals line.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_detectors._common import read_lines

RULE_ID = "java.equality.equals-no-hashcode"
CATEGORY = 2
TITLE = "equals without hashCode"
SEVERITY = "warning"
DESCRIPTION = "Objects used in HashMap/Set will misbehave"

EQUALS_RE = re.compile(r"boolean[ \t]+equals\s*\(")
HASHCODE_RE = re.compile(r"int[ \t]+hashCode\s*\(")


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {".java", ".kt"}:
            continue
        lines = read_lines(path)
        if not lines:
            continue
        eq_line = None
        has_equals = False
        has_hashcode = False
        for idx, line in enumerate(lines, start=1):
            if EQUALS_RE.search(line):
                has_equals = True
                if eq_line is None:
                    eq_line = idx
            if HASHCODE_RE.search(line):
                has_hashcode = True
        if has_equals and not has_hashcode and eq_line is not None:
            yield path, eq_line, 1, "equals(...) missing hashCode()"
