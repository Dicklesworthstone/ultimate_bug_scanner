"""ubs_core.java_detectors.optional_get — category 1 (bead 0xjg.8).

Port of the `java_pattern_scan optional_get` mode (modules/ubs-java.sh
615-641): Optional.get() calls on declared Optional variables plus chained
Optional.of(...)/ofNullable(...)/empty(...).get(). No marker check in legacy
(the heredoc never inspected ubs:ignore).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_detectors._common import iter_java_files, read_lines, strip_line_comments

RULE_ID = "java.null-optional.optional-get"
CATEGORY = 1
TITLE = "Optional.get() detected"
SEVERITY = "warning"
DESCRIPTION = "Prefer orElse/orElseThrow or ifPresent"

DECL_PAT = re.compile(r"\b(?:java\.util\.)?Optional(?:\s*<[^;=()]+>)?\s+([A-Za-z_][A-Za-z0-9_]*)\b")
GET_PAT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*get\s*\(")
CHAINED_PAT = re.compile(r"\b(?:java\.util\.)?Optional\s*\.\s*(?:of|ofNullable|empty)\s*\([^)]*\)\s*\.\s*get\s*\(")


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in iter_java_files(files):
        lines = read_lines(path)
        if not lines:
            continue
        optionals = set()
        for line in lines:
            stripped = line.split("//", 1)[0]
            optionals.update(DECL_PAT.findall(stripped))
        for idx, line in enumerate(lines, start=1):
            stripped = line.split("//", 1)[0]
            matched = False
            for match in GET_PAT.finditer(stripped):
                if match.group(1) in optionals:
                    matched = True
                    break
            if not matched and CHAINED_PAT.search(stripped):
                matched = True
            if matched:
                yield path, idx, 1, line.strip()[:240]
