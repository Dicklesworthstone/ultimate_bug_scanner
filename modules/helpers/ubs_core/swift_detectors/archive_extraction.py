"""swift_detectors.archive_extraction — cat 6 "Archive extraction path traversal".

Verbatim port of the archive-extraction heredoc in modules/ubs-swift.sh
(print_subheader "Archive extraction path traversal"). The legacy shell
aggregated the heredoc's `count\\tsamples` output into ONE critical finding
whose description embeds the first three samples.
"""
from __future__ import annotations

import re
from pathlib import Path

from ubs_core.swift_detectors._common import (
    SKIP_DIRS, has_ignore, iter_swift_files, logical_statement, rel,
    source_line, strip_line_comments,
)

RULE_ID = "swift.security.archive-extraction"
CATEGORY = 6
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"

archive_hint = re.compile(
    r'\b(?:Archive|ZipArchive|ZIPFoundation|ZipEntry|ArchiveEntry|Compression|Data\.decompress)\b'
)
entry_name = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\.(?:path|name|fileName|fullPath|relativePath)\b')
alias_assign = re.compile(
    r'\b(?:let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'[A-Za-z_][A-Za-z0-9_]*\.(?:path|name|fileName|fullPath|relativePath)\b'
)
path_build = re.compile(
    r'\.appendingPathComponent\s*\(|'
    r'\bURL\s*\(\s*fileURLWithPath\s*:|'
    r'\bFileManager\.default\.(?:createFile|createDirectory|moveItem|copyItem)\s*\(|'
    r'\bData\s*\([^)]*\)\.write\s*\(|'
    r'\.write\s*\(\s*to\s*:|'
    r'\.extract\s*\(|'
    r'\+\s*["\'][^"\']*/[^"\']*["\']|'
    r'["\'][^"\']*/[^"\']*["\']\s*\+|'
    r'\\\([^)]*\)[^"\']*/|/[^"\']*\\\([^)]*\)'
)
safe_named = re.compile(
    r'\b(?:safeArchiveURL|safeArchivePath|safeExtractionURL|validateArchiveEntry|'
    r'validateZipEntry|ensureInsideDestination|assertInsideDestination|isInsideDestination|'
    r'isSubpath|isDescendant)\b',
    re.IGNORECASE,
)


def _context_around(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 10)
    end = min(len(lines), line_no + 12)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])


def _has_safe_context(context: str) -> bool:
    if safe_named.search(context):
        return True
    lower = context.lower()
    has_canonical = (
        'standardizedfileurl' in lower or
        'resolvingsymlinksinpath' in lower or
        'standardizedpath' in lower
    )
    has_anchor = 'hasprefix' in lower or 'relativepath' in lower
    rejects = 'throw ' in lower or 'return false' in lower or 'guard ' in lower
    return has_canonical and has_anchor and rejects


def _collect_aliases(lines: list[str]) -> set[str]:
    aliases = set()
    for raw in lines:
        match = alias_assign.search(strip_line_comments(raw))
        if match:
            aliases.add(match.group(1))
    return aliases


def _has_entry_name(statement: str, aliases: set[str]) -> bool:
    if entry_name.search(statement):
        return True
    for alias in aliases:
        if re.search(rf'\b{re.escape(alias)}\b', statement):
            return True
    return False


def scan(ctx):
    project = ctx.project_dir
    root = project.resolve()
    base = root if root.is_dir() else root.parent
    findings = []
    for path in iter_swift_files(root, base, SKIP_DIRS):
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        if not archive_hint.search(text):
            continue
        lines = text.splitlines()
        aliases = _collect_aliases(lines)
        for line_no in range(1, len(lines) + 1):
            if has_ignore(lines, line_no):
                continue
            statement = logical_statement(lines, line_no)
            if not path_build.search(statement):
                continue
            if not _has_entry_name(statement, aliases):
                continue
            if _has_safe_context(_context_around(lines, line_no)):
                continue
            findings.append((rel(path, base), line_no, source_line(lines, line_no)))

    if not findings:
        return
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    desc = "Expand/canonicalize archive entry destinations and reject paths outside the extraction root."
    yield {
        "rule": RULE_ID,
        "category": CATEGORY,
        "path": findings[0][0],
        "line": findings[0][1],
        "severity": SEVERITY,
        "count": len(findings),
        "title": TITLE,
        "message": TITLE,
        "description": f"{desc} Examples: {samples}",
    }
