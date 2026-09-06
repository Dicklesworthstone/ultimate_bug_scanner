"""ubs_core.csharp_detectors.archive_extraction — cat 8 security (bead 0xjg.12).

Verbatim port of the ubs-csharp.sh ``run_archive_extraction_checks`` heredoc
(1412-1577): same hint/entry-name/alias/path-build/safe-context regexes, same
±10/+12 context window, same ubs:ignore placement (current + previous line).
The NUL-filelist loader is replaced by iteration over ``files``; per-file
match logic is unchanged.

Legacy emission: critical "Archive extraction path traversal risk".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.csharp_detectors._common import (
    context_around,
    has_ignore,
    logical_statement,
    relpath,
    source_line,
    strip_line_comments,
)

RULE_ID = "csharp.security.archive-extraction"
CATEGORY = 8
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = "Validate archive entry paths stay under destination"

ARCHIVE_HINT_RE = re.compile(
    r'\b(?:ZipArchive|ZipFile|ZipArchiveEntry|ZipInputStream|ZipEntry|'
    r'TarReader|TarEntry|TarArchive|SharpCompress|IArchiveEntry|SevenZipArchive)\b'
)
ENTRY_NAME_RE = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\.(?:FullName|Name|Key|FilePath)\b'
)
ALIAS_ASSIGN_RE = re.compile(
    r'\b(?:var|string|String|PathString)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'[A-Za-z_][A-Za-z0-9_]*\.(?:FullName|Name|Key|FilePath)\b'
)
PATH_BUILD_RE = re.compile(
    r'\bPath\.(?:Combine|Join|GetFullPath)\s*\(|'
    r'\bFile(?:Info|Stream)?\s*\(|'
    r'\bFile\.(?:Open|Create|CreateText|WriteAllBytes|WriteAllText|WriteAllLines|WriteAllBytesAsync|WriteAllTextAsync)\s*\(|'
    r'\bDirectory\.(?:CreateDirectory|Move)\s*\(|'
    r'\.ExtractToFile\s*\(|'
    r'\.WriteToFile\s*\(|'
    r'\.WriteToDirectory\s*\(|'
    r'\+\s*(?:Path\.DirectorySeparatorChar|Path\.AltDirectorySeparatorChar|["\'][^"\']*[\\/][^"\']*["\'])|'
    r'(?:Path\.DirectorySeparatorChar|Path\.AltDirectorySeparatorChar|["\'][^"\']*[\\/][^"\']*["\'])\s*\+|'
    r'\$\s*"[^"]*\{[^}]+\}[^"]*[\\/]|'
    r'\$\s*"[^"]*[\\/][^"]*\{[^}]+\}'
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:SafeArchivePath|GetSafeArchivePath|SafeExtractionPath|GetSafeExtractionPath|'
    r'ValidateArchiveEntry|ValidateZipEntry|ValidateTarEntry|EnsureInsideDestination|'
    r'AssertInsideDestination|IsInsideDestination|IsSubPathOf|IsPathInside)\b',
    re.IGNORECASE,
)


def has_safe_context(context):
    if SAFE_NAMED_RE.search(context):
        return True
    lower = context.lower()
    has_canonical = 'path.getfullpath' in lower or 'path.getrelativepath' in lower
    has_anchor = '.startswith' in lower or 'stringcomparison.' in lower or 'getrelativepath' in lower
    rejects_traversal = '..' in lower or 'throw ' in lower or 'return false' in lower
    return has_canonical and has_anchor and rejects_traversal


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
    return bool(PATH_BUILD_RE.search(statement) and has_entry_name(statement, aliases))


def analyze(path: Path, base_dir: Path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ARCHIVE_HINT_RE.search(text):
        return
    lines = text.splitlines()
    aliases = collect_aliases(lines)
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx)
        if not path_builds_from_entry(statement, aliases):
            continue
        if has_safe_context(context_around(lines, idx)):
            continue
        issues.append((relpath(path, base_dir), idx, source_line(lines, idx)))


def find(files: Sequence[Path], base_dir: Path | None = None) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[str, int, str]] = []
    base = base_dir if base_dir is not None else Path.cwd()
    for path in files:
        if path.suffix.lower() not in {'.cs', '.csx'}:
            continue
        analyze(path, base, issues)
    for name, line_no, code in issues:
        yield (name, line_no, 1, code)
