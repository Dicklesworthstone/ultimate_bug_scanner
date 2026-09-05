"""ubs_core.analyzers.sec_archive_entry — archive/upload entry paths joined into
destinations (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "Archive/upload entry paths
joined into destinations": same provenance fixpoint (GH #77 — archive sources
must come from archive libraries/objects or typed entry bindings, never from
variable-name substrings), same 12-line statement window returning both the
comment-stripped statement and its raw source span, same ubs:ignore placement
rules (the marker is tested against the RAW source line and the RAW statement
span, because code_line() strips the comment that carries it).
The heredoc's os.walk over the project is replaced by iteration over
RunContext.files; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.archive-entry"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "Archive/upload entry path traversal risk"

# GH #77: archive provenance must come from archive libraries/objects, not from
# variable-name substrings. A plain `for (const entry of readdirSync(...))` is
# not an archive entry even though the binding is called "entry".
archive_lib_re = re.compile(
    r'[\'"](?:adm-zip|yauzl|yazl|unzipper|unzip-stream|jszip|node-stream-zip|'
    r'zip-lib|extract-zip|decompress|decompress-(?:zip|tar|targz|tarbz2)|'
    r'tar|node-tar|tar-stream|tar-fs|archiver|compressing)[\'"]'
)
archive_api_re = re.compile(
    r'(?:new\s+(?:AdmZip|StreamZip|JSZip|ZipFile|ZipArchive)\b|'
    r'\byauzl\s*\.\s*(?:open|fromBuffer|fromFd)\b|'
    r'\bunzipper\s*\.\s*(?:Open|Parse|Extract)\b|'
    r'\btar\s*\.\s*(?:extract|list|x|t)\b|'
    r'\bJSZip\s*\.\s*loadAsync\b|'
    r'\.\s*getEntries\s*\(|\.\s*openReadStream\s*\()'
)
# TypeScript annotations whose type name signals an archive entry/header object
# (ZipEntry, TarHeader, yauzl.Entry, ...). Dirent and other fs types must not match.
archive_type_re = re.compile(r'(?:zip|tar|unzip|archive|yauzl|entry|header)', re.IGNORECASE)
type_annotation_re = re.compile(
    r'\b(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*'
    r'(?P<type>[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*)'
)
archive_entry_event_re = re.compile(
    r'\.\s*on\s*\(\s*[\'"]entry[\'"]\s*,\s*(?:async\s*)?'
    r'(?:\(\s*(?P<parens>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<bare>[A-Za-z_$][A-Za-z0-9_$]*)\s*=>|'
    r'function\s*\(\s*(?P<func>[A-Za-z_$][A-Za-z0-9_$]*))'
)
for_of_re = re.compile(
    r'\bfor\s*(?:await\s*)?\(\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+of\s+(.+)'
)
source_property_re = re.compile(
    r'\b(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*'
    r'(?P<prop>entryName|fileName|path|name)\b'
)
assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
path_join_re = re.compile(r'\b(?:(?:path|nodePath|posix|win32)\s*\.\s*)?(?:join|resolve)\s*\(', re.IGNORECASE)
safe_re = re.compile(
    r'(?:'
    r'\bpath\s*\.\s*relative\s*\(|\bnodePath\s*\.\s*relative\s*\(|\.startsWith\s*\(|'
    r'\bpath\s*\.\s*isAbsolute\s*\(|\bnodePath\s*\.\s*isAbsolute\s*\(|'
    r'\bpath\s*\.\s*basename\s*\(|\bnodePath\s*\.\s*basename\s*\(|'
    r'isSafeArchivePath|validateArchivePath|sanitizeArchivePath|safeArchiveTarget|'
    r'stripComponents|stripPath|enclosedName|containsPath'
    r')',
    re.IGNORECASE,
)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def statement_from(lines, idx, max_lines=12):
    """Return the comment-stripped statement at idx and its raw source span.

    Inline suppressions live in comments and code_line() removes comments, so a
    trailing '// ubs:ignore' can only be seen in the raw span (GH #77). Pattern
    matching keeps using the stripped text.
    """
    parts = []
    raw_parts = []
    paren_balance = 0
    brace_balance = 0
    saw_code = False
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        raw_current = lines[line_idx]
        current = code_line(raw_current).strip()
        if not current:
            continue
        parts.append(current)
        raw_parts.append(raw_current)
        saw_code = True
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if ';' in current and paren_balance <= 0 and brace_balance <= 0:
            break
    if not saw_code:
        return "", ""
    return ' '.join(parts), '\n'.join(raw_parts)


def context_from(lines, idx):
    start = max(0, idx - 8)
    end = min(len(lines), idx + 10)
    return '\n'.join(
        clean
        for source_line in lines[start:end]
        for clean in [code_line(source_line)]
        if clean.strip()
    )


def has_archive_source(text, archive_receivers, archive_path_vars):
    for match in source_property_re.finditer(text):
        if match.group('receiver') in archive_receivers:
            return True
        if match.group('prop') == 'entryName':
            # entryName is an adm-zip archive-entry property; there is no fs analogue.
            return True
    for name in archive_path_vars:
        if re.search(rf'\b{re.escape(name)}\b', text):
            return True
    return False


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line, sample_text) per detection; logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return

    # Pass 1 (GH #77): collect archive provenance. archive_receivers holds
    # bindings that ARE archive objects/entries (typed params, archive-library
    # results, 'entry' event handler params). archive_path_vars holds bindings
    # DERIVED from an archive entry's path-ish properties.
    archive_receivers = set()
    archive_path_vars = {}
    statements = []
    for idx, line in enumerate(lines):
        statement, raw_statement = statement_from(lines, idx)
        statements.append((idx, statement, raw_statement))
        if not statement:
            continue
        for annotation in type_annotation_re.finditer(statement):
            if archive_type_re.search(annotation.group('type')):
                archive_receivers.add(annotation.group('name'))
        event = archive_entry_event_re.search(statement)
        if event:
            param = event.group('parens') or event.group('bare') or event.group('func')
            if param:
                archive_receivers.add(param)

    # Fixpoint over assignments/for-of so chains like
    # zip = new AdmZip(...) -> entry of zip.getEntries() -> name = entry.path
    # resolve regardless of declaration order.
    for _ in range(3):
        changed = False
        for idx, statement, raw_statement in statements:
            if not statement or 'ubs:ignore' in raw_statement:
                continue
            loop = for_of_re.search(statement)
            if loop:
                loop_var, iterable = loop.group(1), loop.group(2)
                if loop_var not in archive_receivers and (
                    archive_api_re.search(iterable)
                    or any(re.search(rf'\b{re.escape(name)}\b', iterable) for name in archive_receivers)
                ):
                    archive_receivers.add(loop_var)
                    changed = True
            assignment = assignment_re.search(statement)
            if not assignment:
                continue
            target, expr = assignment.group(1), assignment.group(2)
            if target not in archive_receivers and (
                archive_api_re.search(expr)
                or archive_lib_re.search(expr)
                or any(re.search(rf'\b{re.escape(name)}\b', expr) for name in sorted(archive_receivers))
            ):
                if any(
                    match.group('receiver') in archive_receivers or match.group('prop') == 'entryName'
                    for match in source_property_re.finditer(expr)
                ):
                    if target not in archive_path_vars:
                        archive_path_vars[target] = idx
                        changed = True
                else:
                    archive_receivers.add(target)
                    changed = True
        if not changed:
            break

    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        # GH #77: test the suppression marker against the raw source, since
        # code_line() has already removed the comment that carries it.
        if not stripped or 'ubs:ignore' in line:
            continue
        if not path_join_re.search(stripped):
            continue
        statement, raw_statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in raw_statement:
            continue
        if not has_archive_source(statement, archive_receivers, archive_path_vars):
            continue
        if safe_re.search(context_from(lines, idx)):
            continue
        if idx in seen_lines:
            continue
        seen_lines.add(idx)
        yield idx + 1, stripped.replace('\t', ' ')


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs relative to the scan root (cwd)
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for line, _sample in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_archive_entry_flagged(tmp_prefix: str = "ubs_core_sec_archive_entry_") -> None:
    import tempfile

    src = "\n".join([
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "type TarHeader = { name: string };",
        "export function extractEntry(header: TarHeader, destination: string, contents: Buffer): void {",
        "  const outputPath = path.join(destination, header.name);",
        "  fs.writeFileSync(outputPath, contents);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "extract.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 5, findings


def _selftest_containment_and_dirent_clean(tmp_prefix: str = "ubs_core_sec_archive_entry_clean_") -> None:
    import tempfile

    # safeArchiveTarget containment suppresses the archive sink; a Dirent walk
    # with bindings merely named entry/file must not be flagged (GH #77).
    src = "\n".join([
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "type TarHeader = { name: string };",
        "function safeArchiveTarget(destination: string, entryName: string): string {",
        "  const base = path.resolve(destination);",
        "  const target = path.resolve(base, entryName);",
        "  const relative = path.relative(base, target);",
        "  if (relative.startsWith('..') || path.isAbsolute(relative)) {",
        "    throw new Error('escaped');",
        "  }",
        "  return target;",
        "}",
        "export function extractEntry(header: TarHeader, destination: string, contents: Buffer): void {",
        "  const outputPath = safeArchiveTarget(destination, path.basename(header.name));",
        "  fs.writeFileSync(outputPath, contents);",
        "}",
        "export function walkTree(root: string): string[] {",
        "  const collected: string[] = [];",
        "  for (const entry of readdirSync(root, { withFileTypes: true })) {",
        "    const candidate = join(root, entry.name);",
        "    collected.push(candidate);",
        "  }",
        "  return collected;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "extract.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_trailing_ignore_suppresses(tmp_prefix: str = "ubs_core_sec_archive_entry_ign_") -> None:
    import tempfile

    # GH #77: a trailing ubs:ignore comment on the finding line suppresses even
    # though code_line() strips it from the statement text.
    src = "\n".join([
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "type TarHeader = { name: string };",
        "export function extractEntry(header: TarHeader, destination: string, contents: Buffer): void {",
        "  const outputPath = path.join(destination, header.name); // ubs:ignore -- validated upstream",
        "  fs.writeFileSync(outputPath, contents);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "extract.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_admzip_provenance_flagged(tmp_prefix: str = "ubs_core_sec_archive_entry_prov_") -> None:
    import tempfile

    # adm-zip require + getEntries() provenance without TS archive types stays flagged.
    src = "\n".join([
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "const AdmZip = require('adm-zip');",
        "export function extractAll(archivePath: string, destination: string): void {",
        "  const zip = new AdmZip(archivePath);",
        "  for (const entry of zip.getEntries()) {",
        "    const entryPath = entry.entryName;",
        "    const outputPath = path.join(destination, entryPath);",
        "    fs.writeFileSync(outputPath, entry.getData());",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "extract.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 8, findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_archive_entry_run_") -> None:
    import tempfile

    src = "\n".join([
        "type ZipEntry = { path: string };",
        "export function f(entry: ZipEntry, dest: string) {",
        "  const p = path.join(dest, entry.path);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "extract.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["message"] == MESSAGE, rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("archive-entry-flagged", _selftest_archive_entry_flagged),
    ("containment-and-dirent-clean", _selftest_containment_and_dirent_clean),
    ("trailing-ignore-suppresses", _selftest_trailing_ignore_suppresses),
    ("admzip-provenance-flagged", _selftest_admzip_provenance_flagged),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_archive_entry", run=run, selftests=SELF_TESTS))
