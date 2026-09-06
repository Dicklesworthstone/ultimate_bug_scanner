"""ubs_core.elixir_detectors.archive_extraction — category 4 security (bead 0xjg.13).

Verbatim port of run_archive_extraction_checks (modules/ubs-elixir.sh
381-620): files touching :zip/:erlar extract APIs (or Unzip/Zstream/ExArchive/
Archive) are scanned for entry-name aliases feeding Path.join/expand/
relative_to or File write sinks (or direct `cwd:`-option extracts) without a
safe-named helper or a Path.expand/relative_to + starts_with?/reject
containment context in the ±8/+10 window. Same-file and previous-line
`ubs:ignore` markers suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.elixir_detectors._common import (
    EXTS,
    elixir_files,
    has_ignore,
    read_lines,
    source_line,
    strip_line_comments,
)

RULE_ID = "ex.archive-extraction.path"
CATEGORY = 4
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate archive entry names with Path.expand/2 and reject paths "
    "outside the extraction root before writing files"
)

ARCHIVE_HINT_RE = re.compile(
    r'(?<![A-Za-z0-9_]):(?:zip|erl_tar)\.(?:extract|unzip|zip_get|foldl|open|table)\b|'
    r'\b(?:Unzip|Zstream|ExArchive|Archive)\b',
    re.IGNORECASE,
)
DIRECT_CWD_EXTRACT_RE = re.compile(
    r'(?<![A-Za-z0-9_]):(?:zip|erl_tar)\.(?:extract|unzip)\s*\([^#\n]*(?:\bcwd\s*:|\{:cwd\s*,)',
    re.IGNORECASE,
)
MEMORY_EXTRACT_RE = re.compile(r'(?<![A-Za-z0-9_]):(?:zip|erl_tar)\.(?:extract|unzip)\s*\([^#\n]*(?::memory|\[:memory)', re.IGNORECASE)
ENTRY_FN_RE = re.compile(
    r'\bfn\s+(?:\{\s*)?([A-Za-z_][A-Za-z0-9_?!]*)(?:\s*,|\s*\}|(?:\s+->))'
)
ENTRY_ALIAS_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*=\s*'
    r'(?:List\.to_string|to_string|IO\.iodata_to_binary|Path\.basename)?\s*\(?\s*'
    r'([A-Za-z_][A-Za-z0-9_?!]*)'
)
PATH_ALIAS_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*=\s*')
PATH_BUILD_RE = re.compile(
    r'\bPath\.(?:join|expand|relative_to)\s*\(|'
    r'\bFile\.(?:write!?|open!?|mkdir!?|mkdir_p!?|cp!?|rename!?|rm!?|touch!?)\s*\('
)
SINK_RE = re.compile(
    r'\bFile\.(?:write!?|open!?|mkdir!?|mkdir_p!?|cp!?|rename!?|rm!?|touch!?)\s*\('
)
ENTRY_NAME_HINT_RE = re.compile(
    r'^(?:entry_?)?(?:file_?)?(?:name|path|filename|member|entry|tar_entry|zip_entry)$',
    re.IGNORECASE,
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_archive_path|safeArchivePath|safe_extract_path|safeExtractPath|'
    r'validate_archive_entry|validateArchiveEntry|validate_zip_entry|validateZipEntry|'
    r'ensure_inside_destination|ensureInsideDestination|inside_destination\?|insideDestination\?|'
    r'assert_inside_destination|assertInsideDestination|safe_join|secure_join|secure_extract)\b',
    re.IGNORECASE,
)


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = ' do' in statement or '->' in statement or balance <= 0
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = has_end or ' do' in next_line or '->' in next_line
        lookahead += 1
    return statement


def context_around(lines, line_no):
    start = max(0, line_no - 8)
    end = min(len(lines), line_no + 10)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])


def has_safe_context(statement, context):
    if SAFE_NAMED_RE.search(statement) or SAFE_NAMED_RE.search(context):
        return True
    lower = context.lower()
    has_canonical = 'path.expand' in lower or 'path.relative_to' in lower
    has_anchor = 'string.starts_with?' in lower or 'path.relative_to' in lower
    has_reject = 'raise ' in lower or '{:error' in lower or 'throw(' in lower or 'return false' in lower
    return has_canonical and has_anchor and has_reject


def references_any(statement, names):
    return any(re.search(rf'\b{re.escape(name)}\b', statement) for name in names)


def collect_entry_aliases(lines):
    aliases = set()
    text = '\n'.join(strip_line_comments(line) for line in lines)
    if not (':memory' in text or 'zip_get' in text or 'foldl' in text or 'table' in text):
        return aliases
    for raw in lines:
        line = strip_line_comments(raw)
        match = ENTRY_FN_RE.search(line)
        if match:
            name = match.group(1)
            if ENTRY_NAME_HINT_RE.search(name):
                aliases.add(name)
        match = ENTRY_ALIAS_RE.search(line)
        if match and (match.group(2) in aliases or ENTRY_NAME_HINT_RE.search(match.group(1))):
            aliases.add(match.group(1))
    return aliases


def collect_path_aliases(lines, entry_aliases):
    aliases = set()
    for idx, _ in enumerate(lines, start=1):
        statement = logical_statement(lines, idx)
        if not PATH_BUILD_RE.search(statement):
            continue
        if not references_any(statement, entry_aliases):
            continue
        if has_safe_context(statement, context_around(lines, idx)):
            continue
        match = PATH_ALIAS_RE.search(statement)
        if match:
            aliases.add(match.group(1))
    return aliases


def scan_file_findings(path: Path) -> Iterable[tuple[int, int, str]]:
    lines = read_lines(path)
    if lines is None:
        return
    text = "\n".join(lines)
    if not ARCHIVE_HINT_RE.search(text):
        return
    entry_aliases = collect_entry_aliases(lines)
    path_aliases = collect_path_aliases(lines, entry_aliases)
    seen: set[int] = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx)
        direct_cwd_extract = bool(DIRECT_CWD_EXTRACT_RE.search(statement))
        unsafe_path_build = bool(PATH_BUILD_RE.search(statement)) and references_any(statement, entry_aliases)
        unsafe_sink = bool(SINK_RE.search(statement)) and references_any(statement, path_aliases)
        memory_extract_write_context = bool(MEMORY_EXTRACT_RE.search(text)) and unsafe_path_build
        if not (direct_cwd_extract or unsafe_path_build or unsafe_sink or memory_extract_write_context):
            continue
        if has_safe_context(statement, context_around(lines, idx)):
            continue
        if idx in seen:
            continue
        seen.add(idx)
        yield idx, 1, source_line(lines, idx)


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in elixir_files(files, EXTS):
        for line_no, col, code in scan_file_findings(path):
            yield str(path), line_no, col, code
