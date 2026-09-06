"""ubs_core.ruby_detectors.archive_extraction — category 6 security (bead 0xjg.10).

Port of run_archive_extraction_checks (modules/ubs-ruby.sh 614-810): files
that touch zip/tar/gem archive APIs are scanned for entry-name-derived path
construction (entry .name/.full_name/.path aliases feeding File.join/expand_
path/write/open, Pathname, FileUtils, #{}-interpolated separators) without a
safe-destination helper or a start_with?/canonicalization containment check
in the ±8/+10 line context. Same-file and previous-line `ubs:ignore`
markers suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.ruby_detectors._common import (
    EXTS,
    context_around,
    has_ignore,
    logical_statement,
    read_lines,
    ruby_files,
    source_line,
    strip_line_comments,
    word_regex,
)

RULE_ID = "ruby.archive-extraction.path"
CATEGORY = 6
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = (
    "Expand and verify archive entry paths remain under the destination "
    "before writing files"
)

ARCHIVE_HINT_RE = re.compile(
    r'\b(?:Zip::File|Zip::InputStream|Gem::Package::TarReader|'
    r'Minitar::Reader|Archive::Tar|Archive::Reader|Zlib::GzipReader)\b'
)
ENTRY_NAME_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\.(?:name|full_name|path)\b')
ALIAS_ASSIGN_RE = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'[A-Za-z_][A-Za-z0-9_]*\.(?:name|full_name|path)\b'
)
PATH_BUILD_RE = re.compile(
    r'\bFile\.(?:join|expand_path|write|open|binwrite)\s*\(|'
    r'\bPathname\.new\s*\(|'
    r'\bFileUtils\.(?:mkdir_p|cp|mv|touch)\s*\(|'
    r'\.extract\s*\(|'
    r'\.join\s*\(|'
    r'\+\s*(?:File::SEPARATOR|["\'][^"\']*/[^"\']*["\'])|'
    r'(?:File::SEPARATOR|["\'][^"\']*/[^"\']*["\'])\s*\+|'
    r'#\{[^}]+\}[^"\']*/|/[^"\']*#\{[^}]+\}'
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_destination|safe_archive_path|safe_zip_entry|safe_entry_path|'
    r'secure_extract|secure_join|validate_archive_entry|validate_zip_entry|'
    r'within_destination\?|inside_destination\?|assert_inside_destination)\b',
    re.IGNORECASE,
)


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
        if word_regex(alias).search(statement):
            return True
    return False


def path_builds_from_entry(statement, aliases):
    if not PATH_BUILD_RE.search(statement):
        return False
    return has_entry_name(statement, aliases)


def has_safe_context(context):
    if SAFE_NAMED_RE.search(context):
        return True
    lower = context.lower()
    has_anchor = 'start_with?' in lower or 'relative_path_from' in lower
    has_canonical = 'expand_path' in lower or 'realpath' in lower or 'cleanpath' in lower
    return has_anchor and has_canonical


def analyze(lines, issues, path_str):
    if not lines:
        return
    text = "\n".join(lines)
    if not ARCHIVE_HINT_RE.search(text):
        return
    aliases = collect_aliases(lines)
    for idx in range(1, len(lines) + 1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx)
        if not path_builds_from_entry(statement, aliases):
            continue
        if has_safe_context(context_around(lines, idx)):
            continue
        issues.append((path_str, idx, 1, source_line(lines, idx)))


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        issues: list[tuple] = []
        analyze(lines, issues, str(path))
        yield from issues
