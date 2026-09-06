"""ubs_core.ruby_detectors.json_parse_no_rescue — category 9 (bead 0xjg.10).

Port of the legacy "JSON.parse without rescue" check (modules/ubs-ruby.sh
3106-3112): warn when the project-wide count of `JSON.parse(` lines exceeds
the count of JSON.parse lines that sit within the 2 lines before a `begin`
(GREP_RNW -B2 begin | grep -c JSON.parse). Only lines NOT covered by a
nearby begin are emitted as records. Current-line `ubs:ignore` markers
filter the primary count exactly like the legacy count_lines stage.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.ruby_scan import MARKER
from ubs_core.ruby_detectors._common import EXTS, read_lines, ruby_files

RULE_ID = "ruby.parsing.json-parse-no-rescue"
CATEGORY = 9
TITLE = "JSON.parse without error handling"
SEVERITY = "warning"
DESCRIPTION = "Rescue JSON::ParserError"

JSON_PARSE_RE = re.compile(r"JSON\.parse\(")
BEGIN_RE = re.compile(r"\bbegin\b")


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        parse_lines: list[int] = []
        for idx, line in enumerate(lines, 1):
            if JSON_PARSE_RE.search(line):
                if MARKER in line:
                    continue  # legacy count_lines dropped these from the count
                parse_lines.append(idx)
        if not parse_lines:
            continue
        # b: JSON.parse lines within the 2 lines before a begin (rg -B2 window).
        begins = [idx for idx, line in enumerate(lines, 1) if BEGIN_RE.search(line)]
        guarded: set[int] = set()
        for b in begins:
            for idx in parse_lines:
                if b < idx <= b + 2:
                    guarded.add(idx)
        for idx in parse_lines:
            if idx in guarded:
                continue
            yield (str(path), idx, 1, lines[idx - 1].strip()[:200])
