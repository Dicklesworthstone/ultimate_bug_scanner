"""ubs_core.cpp_detectors.archive_entry — category 7 archive extraction (bead 0xjg.9).

Verbatim port of the run_archive_extraction_checks heredoc
(modules/ubs-cpp.sh 729-976). Critical: "Archive extraction path traversal
risk". One record per unsafe construction/sink line (legacy printed one
finding with count = len(issues) and ≤5 samples).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "cpp.detector.archive-entry"
CATEGORY = 7
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = ("Normalize archive entry names and verify every destination "
               "remains under the extraction root")

SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

ARCHIVE_HINT_RE = re.compile(
    r'\b(?:archive_read|archive_entry|archive_entry_pathname|zip_(?:open|fopen|fread|get_name|stat|file)|'
    r'unz(?:Open|GoToFirstFile|GetCurrentFileInfo|OpenCurrentFile|ReadCurrentFile)|'
    r'mz_zip_|ZipArchive|QuaZip|libarchive|libzip|minizip)\b'
    r'|#\s*include\s*[<"](?:archive|archive_entry|zip|unzip|minizip|mz_zip)[^>"]*[>"]',
    re.IGNORECASE,
)
ENTRY_EXPR_RE = re.compile(
    r'\b(?:archive_entry_pathname(?:_utf8)?|zip_get_name)\s*\([^;\n)]*\)'
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:->|\.)\s*(?:name|pathname|path|filename|fileName|fullPath|m_filename|m_name)\b'
)
ALIAS_ASSIGN_RE = re.compile(
    r'\b(?:const\s+)?(?:char\s*(?:const\s*)?\*|std::string(?:_view)?|string(?:_view)?|'
    r'(?:std::)?filesystem::path|fs::path|auto(?:\s+const)?|const\s+auto)\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'(?:[^;\n]*\b(?:archive_entry_pathname(?:_utf8)?|zip_get_name)\s*\([^;\n]*\)|'
    r'[^;\n]*\b[A-Za-z_][A-Za-z0-9_]*(?:->|\.)\s*(?:name|pathname|path|filename|fileName|fullPath|m_filename|m_name)\b)'
)
OUTBUF_ARCHIVE_CALL_RE = re.compile(
    r'\b(?:unzGetCurrentFileInfo(?:64)?|mz_zip_reader_get_filename(?:_v2)?|'
    r'mz_zip_reader_file_stat|zip_stat(?:_index)?)\s*\('
)
LIKELY_ENTRY_BUFFER_RE = re.compile(
    r'^(?:entry_?)?(?:file_?)?(?:name|path)(?:_inzip|_buf|_buffer)?$|'
    r'^filename(?:_inzip|_buf|_buffer)?$|^pathbuf$|^path_buffer$|^stat$|^file_stat$',
    re.IGNORECASE,
)
PATH_ALIAS_ASSIGN_RE = re.compile(
    r'\b(?:auto(?:\s+const)?|const\s+auto|std::string(?:_view)?|string(?:_view)?|'
    r'(?:std::)?filesystem::path|fs::path)\s+([A-Za-z_][A-Za-z0-9_]*)\s*='
)
PATH_BUILD_RE = re.compile(
    r'\b(?:std::)?filesystem::path\b|'
    r'\bfs::path\b|'
    r'\b(?:std::)?(?:ofstream|fstream)\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|'
    r'\b(?:fopen|freopen|open|openat|creat|mkdir|mkdirat)\s*\(|'
    r'\b(?:std::filesystem::|filesystem::|fs::)(?:create_directories|copy_file|rename|permissions|path)\b|'
    r'\barchive_read_extract(?:2)?\s*\(|'
    r'\b(?:zip_fread|unzReadCurrentFile|mz_zip_reader_extract_to_file)\s*\(|'
    r'\s/\s|'
    r'\+\s*(?:["\'][^"\']*/[^"\']*["\']|[A-Za-z_][A-Za-z0-9_]*)|'
    r'(?:["\'][^"\']*/[^"\']*["\']|[A-Za-z_][A-Za-z0-9_]*)\s*\+'
)
SINK_RE = re.compile(
    r'\b(?:std::)?(?:ofstream|fstream)\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|'
    r'\b(?:fopen|freopen|open|openat|creat|mkdir|mkdirat)\s*\(|'
    r'\b(?:std::filesystem::|filesystem::|fs::)(?:create_directories|copy_file|rename|permissions)\b|'
    r'\barchive_read_extract(?:2)?\s*\(|'
    r'\b(?:zip_fread|unzReadCurrentFile|mz_zip_reader_extract_to_file)\s*\('
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safeArchivePath|safe_archive_path|safeExtractionPath|safe_extract_path|safeDestination|'
    r'secureExtract|secure_extract|secureJoin|secure_join|validateArchiveEntry|validate_archive_entry|'
    r'validateZipEntry|validate_zip_entry|ensureInsideDestination|ensure_inside_destination|'
    r'assertInsideDestination|assert_inside_destination|insideDestination|inside_destination|'
    r'isSubpath|is_subpath|isDescendant|is_descendant)\b',
    re.IGNORECASE,
)


def strip_line_comments(line: str) -> str:
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
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    has_end = ';' in statement or '{' in statement or '}' in statement
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line
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
    has_canonical = (
        'weakly_canonical' in lower or 'canonical(' in lower or 'lexically_normal' in lower
        or 'realpath(' in lower or 'std::filesystem::relative' in lower or 'fs::relative' in lower
    )
    has_anchor = (
        'starts_with' in lower or '.compare(' in lower or 'lexically_relative' in lower
        or 'std::filesystem::relative' in lower or 'fs::relative' in lower
        or 'relative(' in lower or 'is_subpath' in lower or 'inside_destination' in lower
    )
    has_reject = 'throw ' in lower or 'return false' in lower or 'continue;' in lower or 'return {}' in lower
    return has_canonical and has_anchor and has_reject


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def collect_entry_aliases(lines):
    aliases = set()
    for raw in lines:
        line = strip_line_comments(raw)
        match = ALIAS_ASSIGN_RE.search(line)
        if match:
            aliases.add(match.group(1))
        if OUTBUF_ARCHIVE_CALL_RE.search(line):
            for ident in re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', line):
                if LIKELY_ENTRY_BUFFER_RE.search(ident):
                    aliases.add(ident)
    return aliases


def references_name_source(statement, entry_aliases):
    if ENTRY_EXPR_RE.search(statement):
        return True
    for alias in entry_aliases:
        if re.search(rf'\b{re.escape(alias)}\b', statement):
            return True
    return False


def references_path_alias(statement, path_aliases):
    for alias in path_aliases:
        if re.search(rf'\b{re.escape(alias)}\b', statement):
            return True
    return False


def path_builds_from_entry(statement, entry_aliases):
    if not PATH_BUILD_RE.search(statement):
        return False
    return references_name_source(statement, entry_aliases)


def collect_path_aliases(lines, entry_aliases):
    aliases = set()
    for idx, _ in enumerate(lines, start=1):
        statement = logical_statement(lines, idx)
        if not path_builds_from_entry(statement, entry_aliases):
            continue
        if has_safe_context(statement, context_around(lines, idx)):
            continue
        match = PATH_ALIAS_ASSIGN_RE.search(statement)
        if match:
            aliases.add(match.group(1))
    return aliases


def analyze(path: Path, cwd: Path) -> list[tuple[str, int, str]]:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    if not ARCHIVE_HINT_RE.search(text):
        return []
    lines = text.splitlines()
    entry_aliases = collect_entry_aliases(lines)
    path_aliases = collect_path_aliases(lines, entry_aliases)
    try:
        rel = str(path.resolve().relative_to(cwd))
    except ValueError:
        rel = path.name
    seen = set()
    issues = []
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx)
        unsafe_path_build = path_builds_from_entry(statement, entry_aliases)
        unsafe_path_sink = bool(SINK_RE.search(statement)) and references_path_alias(statement, path_aliases)
        unsafe_extract = bool(re.search(r'\barchive_read_extract(?:2)?\s*\(', statement))
        if not (unsafe_path_build or unsafe_path_sink or unsafe_extract):
            continue
        if has_safe_context(statement, context_around(lines, idx)):
            continue
        key = (rel, idx)
        if key in seen:
            continue
        seen.add(key)
        issues.append((rel, idx, source_line(lines, idx)))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in EXTS:
            continue
        for rel, line_no, code in analyze(path, cwd):
            yield rel, line_no, 1, code
