"""ubs_core.cpp_detectors.header_hygiene — category 8 (bead 0xjg.9).

Ports of the header-guard loop and the header-scoped using-namespace check
(modules/ubs-cpp.sh 3292-3320). Rules:
- cpp.detector.header-guards: one warning per .h/.hpp/.hh/.hxx file whose
  first 50 lines lack `#pragma once` / `#ifndef` / `#if !defined`.
- cpp.headers.using-namespace-std-header: one record per matching line in
  header files only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.cpp_scan import MARKER

RULES = (
    ("cpp.detector.header-guards", 8,
     "Headers missing guard/#pragma once (heuristic)", "warning", ""),
    ("cpp.headers.using-namespace-std-header", 8,
     "using namespace std in headers is harmful", "warning", ""),
)

HEADER_SUFFIXES = {".h", ".hpp", ".hh", ".hxx"}
_GUARD_RE = re.compile(r"#pragma once|#ifndef|#if[ \t]+!defined")
_USING_STD_RE = re.compile(r"using[ \t]+namespace[ \t]+std")


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in HEADER_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        try:
            rel = str(path.resolve().relative_to(cwd))
        except ValueError:
            rel = path.name
        if not any(_GUARD_RE.search(line) for line in lines[:50]):
            yield "cpp.detector.header-guards", rel, 0, 1, rel
        for idx, line in enumerate(lines, start=1):
            if MARKER in line:
                continue
            if _USING_STD_RE.search(line):
                yield "cpp.headers.using-namespace-std-header", rel, idx, 1, line.strip()[:240]
