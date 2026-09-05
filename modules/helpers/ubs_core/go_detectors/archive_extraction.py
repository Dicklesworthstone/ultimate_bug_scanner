"""ubs_core.go_detectors.archive_extraction — category 9 security (bead 0xjg.6).

Port of run_archive_extraction_checks (modules/ubs-golang.sh 1080-1239):
for files mentioning an archive reader, flags statements that build a
filesystem path out of an archive entry's ``.Name`` (filepath/path.Join,
string concatenation, or fmt.Sprintf) and feed an os.Create/OpenFile/
WriteFile/MkdirAll/ioutil.WriteFile-style sink, unless a safe-destination
helper (safeDestination/safeExtract/secureJoin/validateArchive*/...
withinDestination, filepath.Rel/IsLocal, fs.ValidPath) appears in the
preceding 12 comment-stripped lines.

Legacy: ``print_finding critical $N "Archive extraction path traversal risk"
"Validate archive entry names with filepath.Rel/IsLocal and ensure writes
stay under the destination"``. Same-file and previous-line ``ubs:ignore``
markers suppress a hit; the v2 record count equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.archive-extraction"
CATEGORY = 9
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = "Validate or sanitize archive entry paths before writing files"
MARKER = "ubs:ignore"

ARCHIVE_HINT_RE = re.compile(r'"archive/(?:tar|zip)"|\b(?:tar\.NewReader|zip\.OpenReader|zip\.NewReader)\b')
ENTRY_NAME_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\.Name\b')
JOIN_ENTRY_RE = re.compile(r'\b(?:filepath|path)\.Join\s*\([^;\n]*\b[A-Za-z_][A-Za-z0-9_]*\.Name\b[^;\n]*\)')
CONCAT_ENTRY_RE = re.compile(r'(?:\+[^;\n]*\b[A-Za-z_][A-Za-z0-9_]*\.Name\b|\b[A-Za-z_][A-Za-z0-9_]*\.Name\b[^;\n]*\+)')
SPRINTF_ENTRY_RE = re.compile(r'\bfmt\.Sprintf\s*\([^;\n]*(?:%s|%v)[^;\n]*\b[A-Za-z_][A-Za-z0-9_]*\.Name\b[^;\n]*\)')
PATH_BUILD_RE = re.compile(r'(?::=|=|\b(?:os\.(?:Create|OpenFile|WriteFile|MkdirAll)|ioutil\.WriteFile)\s*\()')
SAFE_CONTEXT_RE = re.compile(
    r'\b(?:safeDestination|safeArchivePath|safeExtract|secureExtract|secureJoin|'
    r'validateArchive|validateArchiveMember|validateArchiveEntry|validateEntry|'
    r'withinDestination|insideDestination)\b'
    r'|filepath\.(?:Rel|IsLocal)\b'
    r'|fs\.ValidPath\b',
    re.IGNORECASE,
)


def _strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def _has_safe_context(lines, line_no):
    start = max(0, line_no - 12)
    context = '\n'.join(_strip_line_comments(line) for line in lines[start:line_no])
    return bool(SAFE_CONTEXT_RE.search(context))


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _logical_statement(lines, line_no):
    idx = line_no - 1
    statement = _strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 6:
        next_line = _strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement


def _path_builds_from_entry(line):
    if not ENTRY_NAME_RE.search(line):
        return False
    if not PATH_BUILD_RE.search(line):
        return False
    return bool(
        JOIN_ENTRY_RE.search(line)
        or CONCAT_ENTRY_RE.search(line)
        or SPRINTF_ENTRY_RE.search(line)
    )


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ARCHIVE_HINT_RE.search(text):
        return
    lines = text.splitlines()
    for idx, raw in enumerate(lines, start=1):
        if _has_ignore(lines, idx):
            continue
        line = _logical_statement(lines, idx)
        if not _path_builds_from_entry(line):
            continue
        if _has_safe_context(lines, idx):
            continue
        issues.append((path, idx, 1, _source_line(lines, idx)))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
