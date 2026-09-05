"""ubs_core.java_detectors.archive_extraction — category 4 (bead 0xjg.8).

Verbatim port of run_archive_extraction_checks (modules/ubs-java.sh
672-870): archive entry names (getName/getPath/.name/.path and aliases
assigned from them) flowing into path construction or Files.copy/move/write
sinks, unless a safe-named helper or a containment+normalization context
guards them. Requires an archive API hint in the file. Current+previous-line
ubs:ignore suppresses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_detectors._common import (
    has_ignore,
    iter_java_files,
    logical_statement_balance,
    read_lines,
    source_line,
    strip_line_comments,
)
RULE_ID = "java.security.archive-extraction"
CATEGORY = 4
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = (
    "Normalize and verify archive entry paths remain under the destination "
    "before writing files"
)

ARCHIVE_HINT_RE = re.compile(
    r'\b(?:ZipInputStream|ZipFile|ZipEntry|JarInputStream|JarFile|JarEntry|'
    r'ZipArchiveInputStream|ZipArchiveEntry|TarArchiveInputStream|TarArchiveEntry|ArchiveEntry)\b'
    r'|java\.util\.(?:zip|jar)\.|org\.apache\.commons\.compress\.archivers',
)
ENTRY_NAME_EXPR = (
    r'(?:\b[A-Za-z_][A-Za-z0-9_]*\.(?:getName|getPath)\s*\(\s*\)'
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:name|path)\b)'
)
ENTRY_NAME_RE = re.compile(ENTRY_NAME_EXPR)
ALIAS_ASSIGN_RE = re.compile(
    r'\b(?:String|var|val)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*'
    r'(?::\s*[^=]+)?=\s*' + ENTRY_NAME_EXPR
)
PATH_BUILD_RE = re.compile(
    r'\b(?:new\s+File|File|Paths\.get|Path\.of)\s*\(|'
    r'\.resolve\s*\(|'
    r'\bFiles\.(?:copy|move|write|writeString|newOutputStream|createDirectories)\s*\('
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safeDestination|safeArchivePath|safeZipEntry|safeEntryPath|'
    r'secureExtract|secureJoin|validateArchiveEntry|validateZipEntry|'
    r'withinDestination|insideDestination|assertInsideDestination)\b',
    re.IGNORECASE,
)


def context_around(lines, line_no):
    start = max(0, line_no - 8)
    end = min(len(lines), line_no + 10)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])


def has_safe_context(context):
    if SAFE_NAMED_RE.search(context):
        return True
    lower = context.lower()
    has_containment = (
        '.startswith(' in lower
        or 'getcanonicalpath(' in lower
        or 'getcanonicalfile(' in lower
        or '.relativize(' in lower
        or '.relativeto' in lower
    )
    has_normalization = '.normalize(' in lower or '.torealpath(' in lower or 'getcanonicalpath(' in lower or 'getcanonicalfile(' in lower
    return has_containment and has_normalization


def collect_aliases(lines):
    aliases = set()
    for raw in lines:
        line = strip_line_comments(raw)
        match = ALIAS_ASSIGN_RE.search(line)
        if match:
            aliases.add(match.group(1))
    return aliases


def has_entry_name(statement, aliases):
    if ENTRY_NAME_RE.search(statement):
        return True
    for alias in aliases:
        if re.search(rf'\b{re.escape(alias)}\b', statement):
            return True
    return False


def path_builds_from_entry(statement, aliases):
    if not PATH_BUILD_RE.search(statement):
        return False
    return has_entry_name(statement, aliases)


def analyze(path: Path, issues):
    text = path.read_text(encoding='utf-8', errors='ignore')
    if not ARCHIVE_HINT_RE.search(text):
        return
    lines = text.splitlines()
    aliases = collect_aliases(lines)
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement_balance(lines, idx)
        if not path_builds_from_entry(statement, aliases):
            continue
        if has_safe_context(context_around(lines, idx)):
            continue
        issues.append((path, idx, source_line(lines, idx)))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, str]] = []
    for path in iter_java_files(files):
        try:
            analyze(path, issues)
        except OSError:
            continue
    for path, line_no, detail in issues:
        yield path, line_no, 1, detail
