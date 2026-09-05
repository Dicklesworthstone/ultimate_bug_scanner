"""ubs_core.analyzers.sec_path_traversal — request-derived path reaches a
filesystem read/download/write sink (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "Request-derived filesystem
paths": same regexes, quote-aware code_line(), same 16-line statement window,
same taint fixpoint with upload provenance tracking, same containment-context
suppression, same ubs:ignore placement rules (the marker on the finding line,
on the line before it, or anywhere inside the collected statement text).
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

RULE = "js.security.path-traversal"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "Request-derived path reaches file read/download/write sink"

assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
destruct_assignment_re = re.compile(r'\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.*)')
source_re = re.compile(
    r'(?:'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:query|body|params|headers|cookies|files?|nextUrl|url)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\[\s*[\'"`](?:query|body|params|headers|cookies|files?|url)[\'"`]\s*\]|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:get|header)\s*\(\s*[\'"`][^\'"`]+[\'"`]\s*\)|'
    r'\b(?:headers|cookies)\s*\(\s*\)\s*\.\s*get\s*\(\s*[\'"`][^\'"`]+[\'"`]\s*\)|'
    r'\b(?:await\s+)?(?:headers|cookies)\s*\(\s*\)|'
    r'\b(?:query|body|params|headers|cookies|files|searchParams|queryParams|formData)\s*\.\s*get\s*\(|'
    r'\b(?:searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\bnew\s+URL\s*\([^)]*\)\s*\.\s*searchParams\s*\.\s*get\s*\('
    r')',
    re.IGNORECASE,
)
upload_source_re = re.compile(
    r'\b(?:req|request|ctx|context|event)\s*\.\s*files?\b|'
    r'\b(?:files|formData)\s*\.\s*get\s*\(',
    re.IGNORECASE,
)
file_name_source_re = re.compile(
    r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*(?:name|filename|originalname|path)\b',
    re.IGNORECASE,
)
safe_re = re.compile(
    r'(?:'
    r'\b(?:safeJoin|safePath|safeFile|safeFilename|safeFileName|validatePath|validateFile|validateFilename|'
    r'sanitizePath|sanitizeFile|sanitizeFilename|secureFilename|secureFileName|resolveUnderRoot|'
    r'assertInside|ensureInside|isPathInside|isSafePath|allowedFile|allowedPath)\s*\(|'
    r'\bpath\s*\.\s*basename\s*\(|\bnodePath\s*\.\s*basename\s*\(|'
    r'\.replace(?:All)?\s*\([^)]*(?:\\\\|/|\\.\\.)[^)]*\)'
    r')',
    re.IGNORECASE,
)
containment_re = re.compile(
    r'(?:'
    r'\bpath\s*\.\s*relative\s*\(|\bnodePath\s*\.\s*relative\s*\(|'
    r'\.startsWith\s*\(|\bpath\s*\.\s*isAbsolute\s*\(|\bnodePath\s*\.\s*isAbsolute\s*\(|'
    r'\brealpath\s*\(|\bfs\s*\.\s*realpath|\bcommonpath\b|\bcontainsPath\b'
    r')',
    re.IGNORECASE,
)
db_result_assignment_re = re.compile(
    r'\b(?:await\s+)?[A-Za-z_$][A-Za-z0-9_$.]*\s*\.\s*(?:query|execute|find|findOne|select)\s*\(',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'(?:'
    r'\b(?:fs|nodeFs|fsp|fsPromises)\s*(?:\.\s*promises)?\s*\.\s*'
    r'(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|open|openSync|'
    r'createReadStream|createWriteStream|stat|statSync|access|accessSync|mkdir|mkdirSync|rm|rmSync|'
    r'unlink|unlinkSync|rename|renameSync|copyFile|copyFileSync)\s*\(|'
    r'\b(?:Deno)\s*\.\s*(?:readFile|readTextFile|writeFile|writeTextFile|open|stat|mkdir|remove|rename)\s*\(|'
    r'\bBun\s*\.\s*file\s*\(|'
    r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*(?:sendFile|download|sendFileStream|file|mv|save)\s*\('
    r')',
    re.IGNORECASE,
)
candidate_re = re.compile(
    r'(?:'
    r'\b(?:fs|nodeFs|fsp|fsPromises)\s*(?:\.\s*promises)?\s*\.|'
    r'\bDeno\s*\.|\bBun\s*\.\s*file\s*\(|'
    r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*(?:sendFile|download|sendFileStream|file|mv|save)\s*\(|'
    r'createReadStream|createWriteStream'
    r')',
    re.IGNORECASE,
)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    result = []
    quote = ""
    escaped = False
    idx = 0
    while idx < len(source_line):
        ch = source_line[idx]
        nxt = source_line[idx + 1] if idx + 1 < len(source_line) else ""
        if quote:
            result.append(ch)
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = ""
            idx += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            result.append(ch)
            idx += 1
            continue
        if ch == '/' and nxt == '/':
            break
        if ch == '/' and nxt == '*':
            idx += 2
            while idx + 1 < len(source_line) and not (source_line[idx] == '*' and source_line[idx + 1] == '/'):
                idx += 1
            idx += 2
            continue
        result.append(ch)
        idx += 1
    return ''.join(result)


def statement_from(lines, idx, max_lines=16):
    parts = []
    paren_balance = 0
    brace_balance = 0
    saw_code = False
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = code_line(lines[line_idx]).strip()
        if not current:
            continue
        parts.append(current)
        saw_code = True
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if ';' in current and paren_balance <= 0 and brace_balance <= 0:
            break
    return ' '.join(parts) if saw_code else ""


def split_top_level_args(args_text):
    args = []
    current = []
    depth = 0
    quote = ""
    escaped = False
    for ch in args_text:
        current.append(ch)
        if quote:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            current.pop()
            args.append(''.join(current).strip())
            current = []
    tail = ''.join(current).strip()
    if tail:
        args.append(tail)
    return args


def extract_call_args(text, open_pos):
    depth = 1
    quote = ""
    escaped = False
    start = open_pos
    for pos in range(start, len(text)):
        ch = text[pos]
        if quote:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[start:pos]
    return text[start:]


def destructured_targets(body):
    targets = []
    for part in split_top_level_args(body):
        part = part.strip()
        if not part or part.startswith('...'):
            continue
        if ':' in part:
            local = part.rsplit(':', 1)[-1].strip()
        else:
            local = part
        local = local.split('=')[0].strip()
        if re.match(r'^[A-Za-z_$][A-Za-z0-9_$]*$', local):
            targets.append(local)
    return targets


def context_before(lines, idx, max_lines=14):
    start = max(0, idx - max_lines)
    return '\n'.join(
        clean
        for source_line in lines[start:idx + 1]
        for clean in [code_line(source_line)]
        if clean.strip()
    )


def names_in(text, tainted_vars):
    return [name for name in tainted_vars if re.search(rf'\b{re.escape(name)}\b', text)]


def has_safe_context(text, lines, idx, refs):
    if safe_re.search(text):
        return True
    context = context_before(lines, idx)
    if not containment_re.search(context):
        return False
    return not refs or any(re.search(rf'\b{re.escape(name)}\b', context) for name in refs)


def collect_tainted_vars(lines):
    assignments = []
    upload_vars = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        statement = statement_from(lines, idx)
        if not statement:
            continue
        match = destruct_assignment_re.search(stripped)
        if match:
            targets = destructured_targets(match.group(1))
            expr = match.group(2)
        else:
            match = assignment_re.search(stripped)
            if not match:
                continue
            targets = [match.group(1)]
            expr = match.group(2)
        if not targets or db_result_assignment_re.search(statement):
            continue
        assignments.append((idx, targets, statement or expr))

    tainted = {}
    for _ in range(6):
        changed = False
        for idx, targets, expr in assignments:
            if safe_re.search(expr):
                for target in targets:
                    tainted.pop(target, None)
                    upload_vars.discard(target)
                continue
            refs = names_in(expr, tainted)
            upload_refs = [name for name in refs if name in upload_vars]
            direct_source = source_re.search(expr)
            file_name_source = file_name_source_re.search(expr) and refs
            if not (direct_source or refs or file_name_source):
                continue
            for target in targets:
                if target not in tainted:
                    tainted[target] = idx
                    changed = True
                if upload_source_re.search(expr) or upload_refs or file_name_source:
                    upload_vars.add(target)
        if not changed:
            break
    return tainted


def sink_arg_text(statement):
    match = sink_re.search(statement)
    if not match:
        return ""
    return extract_call_args(statement, match.end())


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line, sample_text) per detection; logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    tainted_vars = collect_tainted_vars(lines)
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]) or not candidate_re.search(stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement or not sink_re.search(statement):
            continue
        args_text = sink_arg_text(statement)
        if not args_text:
            continue
        refs = names_in(args_text, tainted_vars)
        direct = source_re.search(args_text)
        if not direct and not refs:
            continue
        if has_safe_context(args_text, lines, idx, refs):
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


def _selftest_traversal_sink_flagged(tmp_prefix: str = "ubs_core_sec_path_traversal_") -> None:
    import tempfile

    src = "\n".join([
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "const UPLOAD_ROOT = '/srv/uploads';",
        "export function expressDownload(req, res) {",
        "  const requested = req.query.file;",
        "  res.sendFile(path.join(UPLOAD_ROOT, requested ?? ''));",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "files.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 6, findings


def _selftest_containment_clean(tmp_prefix: str = "ubs_core_sec_path_traversal_clean_") -> None:
    import tempfile

    # basename sanitization and resolve/relative containment both suppress.
    src = "\n".join([
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "const UPLOAD_ROOT = path.resolve('/srv/uploads');",
        "function validatePath(rawName?: string): string {",
        "  const target = path.resolve(UPLOAD_ROOT, rawName ?? '');",
        "  const relative = path.relative(UPLOAD_ROOT, target);",
        "  if (relative.startsWith('..') || path.isAbsolute(relative)) {",
        "    throw new Error('escaped');",
        "  }",
        "  return target;",
        "}",
        "export function rawRead(req: any) {",
        "  return fs.readFileSync(validatePath(req.params.name));",
        "}",
        "export function uploadedSave(req: any) {",
        "  const target = path.join(UPLOAD_ROOT, path.basename(req.file.originalname));",
        "  return fs.writeFileSync(target, 'x');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "files.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_marker_suppression(tmp_prefix: str = "ubs_core_sec_path_traversal_ign_") -> None:
    import tempfile

    # Legacy placement rules: marker on the finding line or the line before it.
    for marker in ("res.download(path.join(ROOT, req.query.f)); // ubs:ignore",
                   "// ubs:ignore",
                   "res.download(path.join(ROOT, req.query.f));"):
        src = "\n".join([
            "export function dl(req, res) {",
            marker,
            "}",
            "",
        ])
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "files.ts"
            target.write_text(src, encoding="utf-8")
            findings = list(scan_file_findings(target))
        expected = [] if 'ubs:ignore' in marker else [2]
        assert [line for line, _ in findings] == expected, (marker, findings)


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_path_traversal_run_") -> None:
    import tempfile

    src = "fs.readFileSync(req.query.file);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "files.js"
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
    ("traversal-sink-flagged", _selftest_traversal_sink_flagged),
    ("containment-clean", _selftest_containment_clean),
    ("ignore-marker-suppression", _selftest_ignore_marker_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_path_traversal", run=run, selftests=SELF_TESTS))
