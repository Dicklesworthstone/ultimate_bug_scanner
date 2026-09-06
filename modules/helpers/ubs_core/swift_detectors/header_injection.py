"""swift_detectors.header_injection — cat 6 "Request-derived response headers".

Verbatim port of the run_request_response_header_checks heredoc in
modules/ubs-swift.sh (no ubs_core analyzer existed for it before this bead).
The legacy shell aggregated the heredoc's `count\\tsamples` output into ONE
critical finding whose description embeds the first three samples.
"""
from __future__ import annotations

import re
from pathlib import Path

from ubs_core.swift_detectors._common import (
    SKIP_DIRS, has_ignore, iter_swift_files, logical_statement, rel,
    source_line, strip_line_comments,
)

RULE_ID = "swift.taint.header-injection"
CATEGORY = 6
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
PATH_LIMIT = 4

name_re = r'[A-Za-z_][A-Za-z0-9_]*'
assign_re = re.compile(rf'\b(?:let|var)\s+({name_re})\s*(?::[^=]+)?=\s*(.+)')
request_source = re.compile(
    r'\b(?:req|request)\s*\.\s*(?:query|parameters|params)\s*(?:\[[^\]]+\]|\.\s*get\s*\([^)]*\))|'
    r'\b(?:req|request)\s*\.\s*headers\s*(?:\[[^\]]+\]|\.\s*first\s*\([^)]*\)|\.\s*get\s*\([^)]*\))|'
    r'\b(?:req|request)\s*\.\s*cookies\s*(?:\[[^\]]+\]|\.\s*get\s*\([^)]*\))|'
    r'\b(?:req|request)\s*\.\s*(?:url|uri)\s*(?:\.\s*(?:string|absoluteString|description|host|path|query))?\b|'
    r'\b(?:req|request)\s*\.\s*content\s*\.\s*get\s*\([^)]*\bat\s*:\s*["\'][^"\']*(?:header|trace|name|filename|file|token|tenant|id|value|download|export)[^"\']*["\']',
    re.IGNORECASE,
)
request_collection_source = re.compile(
    r'\b(?:req|request)\s*\.\s*(?:query|parameters|params|headers|cookies)\b(?:\s*\[[^\]]+\]|\s*\.\s*(?:get|first)\s*\([^)]*\))?',
    re.IGNORECASE,
)
content_source = re.compile(r'\b(?:req|request)\s*\.\s*content\b')
headerish_name = re.compile(r'(header|trace|name|file|filename|token|tenant|id|value|download|export|disposition)', re.IGNORECASE)
safe_named = re.compile(
    r'\b(?:safeHeader(?:Value)?|safeResponseHeader(?:Value)?|sanitizeHeader(?:Value)?|'
    r'sanitizedHeader(?:Value)?|cleanHeader(?:Value)?|encodeHeader(?:Value)?|'
    r'encodedHeader(?:Value)?|encodedFilename|safeFilenameForHeader|'
    r'safeContentDispositionFilename|stripCRLF|removeCRLF|withoutCRLF|rejectCRLF|'
    r'validHeaderValue|isHeaderValueSafe|headerSafe)\b',
    re.IGNORECASE,
)
encoding_re = re.compile(
    r'\.addingPercentEncoding\s*\(|'
    r'\bCharacterSet\.(?:urlPathAllowed|urlQueryAllowed|alphanumerics)\b',
    re.IGNORECASE,
)
strip_re = re.compile(
    r'\.replacingOccurrences\s*\(\s*of\s*:\s*["\']\\[rn]["\']|'
    r'\.filter\s*\{[^}]*\\[rn][^}]*\}|'
    r'\.split\s*\([^)]*whereSeparator',
    re.IGNORECASE,
)
crlf_check_re = re.compile(
    r'\\r|\\n|newlines|newline|CharacterSet\.newlines|'
    r'\.contains\s*\(\s*["\']\\[rn]["\']\s*\)|'
    r'\.rangeOfCharacter\s*\(\s*from\s*:\s*\.newlines',
    re.IGNORECASE,
)
reject_re = re.compile(r'\b(?:throw|return(?:\s+(?:nil|false))?|abort|preconditionFailure)\b')
sink_re = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\.headers\s*\[\s*["\'][^"\']+["\']\s*\]\s*=|'
    r'\bheaders\s*\[\s*["\'][^"\']+["\']\s*\]\s*=|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\.headers\s*\.\s*(?:add|replaceOrAdd|set)\s*\(|'
    r'\bheaders\s*\.\s*(?:add|replaceOrAdd|set)\s*\(|'
    r'\bResponse\s*\([^)]*\bheaders\s*:|'
    r'\bHTTPHeaders\s*\(\s*\[',
    re.IGNORECASE,
)
location_sink_re = re.compile(
    r'\[\s*["\']Location["\']\s*\]\s*=|'
    r'\(\s*["\']Location["\']\s*,|'
    r'["\']Location["\']\s*:|'
    r'\bname\s*:\s*\.?\s*location\b|'
    r'\bname\s*:\s*["\']Location["\']',
    re.IGNORECASE,
)


def identifier_search_text(expr: str) -> str:
    """Mask string literals but surface interpolation contents (heredoc)."""
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escape:
                escape = False
                i += 1
                continue
            if ch == '\\':
                if i + 1 < len(expr) and expr[i + 1] == '(':
                    depth = 1
                    j = i + 2
                    interpolation = []
                    while j < len(expr) and depth > 0:
                        current = expr[j]
                        if current == '(':
                            depth += 1
                        elif current == ')':
                            depth -= 1
                            if depth == 0:
                                break
                        interpolation.append(current)
                        j += 1
                    out.append(' ')
                    out.append(''.join(interpolation))
                    out.append(' ')
                    i = j + 1
                    continue
                escape = True
                i += 1
                continue
            if ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def is_safe_expression(statement: str) -> bool:
    return bool(safe_named.search(statement) or encoding_re.search(statement) or strip_re.search(statement))


def has_source(statement: str, target_name: str = '') -> bool:
    if request_source.search(statement):
        return True
    if target_name and headerish_name.search(target_name) and request_collection_source.search(statement):
        return True
    return bool(target_name and headerish_name.search(target_name) and content_source.search(statement))


def refs_in_expr(expr: str, tainted: dict) -> list:
    refs = []
    code_text = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\s*:', ' ', identifier_search_text(expr))
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', code_text):
            refs.append(name)
    return refs


def has_non_location_header_sink(statement: str) -> bool:
    keys = []
    keys.extend(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\.headers\s*\[\s*["\']([^"\']+)["\']\s*\]\s*=', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\bheaders\s*\[\s*["\']([^"\']+)["\']\s*\]\s*=', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\(\s*["\']([^"\']+)["\']\s*,', statement))
    keys.extend(re.findall(r'["\']([^"\']+)["\']\s*:', statement))
    keys.extend(re.findall(r'\bname\s*:\s*["\']([^"\']+)["\']', statement, re.IGNORECASE))
    if re.search(r'\bname\s*:\s*\.?\s*location\b', statement, re.IGNORECASE):
        keys.append('Location')
    if keys:
        return any(key.lower() != 'location' for key in keys)
    return not location_sink_re.search(statement)


def taint_from_expr(expr: str, tainted: dict, target_name: str = ''):
    if is_safe_expression(expr):
        return None
    direct = has_source(expr, target_name)
    if direct:
        source = request_source.search(expr)
        return {'path': [(source.group(0) if source else target_name or 'request content').strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_crlf_reject_context(lines: list[str], line_no: int, refs: list) -> bool:
    if not refs:
        return False
    start = max(0, line_no - 18)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no]]
    for ref in refs:
        ref_lines = [
            line for line in context_lines
            if re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line))
        ]
        if not ref_lines:
            continue
        if any(is_safe_expression(line) for line in ref_lines):
            return True
        for pos, line in enumerate(context_lines):
            if not re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line)):
                continue
            if not crlf_check_re.search(line):
                continue
            reject_window = '\n'.join(context_lines[pos:pos + 5])
            if reject_re.search(reject_window):
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
        if not (re.search(r'\b(?:req|request)\b', text) and sink_re.search(text)):
            continue

        lines = text.splitlines()
        tainted = {}
        seen = set()
        for line_no in range(1, len(lines) + 1):
            if has_ignore(lines, line_no):
                continue
            statement = logical_statement(lines, line_no, dotted_continuation=True).strip()
            if not statement:
                continue
            if re.match(r'^\s*func\b', statement):
                tainted.clear()

            assignment = assign_re.search(statement)
            if assignment:
                variable, rhs = assignment.group(1), assignment.group(2)
                taint = taint_from_expr(rhs, tainted, variable)
                if taint:
                    tainted[variable] = taint
                elif variable in tainted and is_safe_expression(rhs):
                    tainted.pop(variable, None)

            if not sink_re.search(statement) or not has_non_location_header_sink(statement):
                continue
            if is_safe_expression(statement):
                continue
            direct = has_source(statement)
            refs = refs_in_expr(statement, tainted)
            if not direct and not refs:
                continue
            if has_crlf_reject_context(lines, line_no, refs):
                continue
            key = (rel(path, base), line_no)
            if key in seen:
                continue
            seen.add(key)
            if direct:
                source = request_source.search(statement)
                path_desc = f"{(source.group(0) if source else 'request source').strip()} -> response header"
            else:
                ref = refs[0]
                seq = list(tainted.get(ref, {}).get('path', [ref]))
                if len(seq) >= PATH_LIMIT:
                    seq = seq[-(PATH_LIMIT - 1):]
                seq.append('response header')
                path_desc = ' -> '.join(seq)
            findings.append((rel(path, base), line_no, f"{source_line(lines, line_no)} [{path_desc}]"))

    if not findings:
        return
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    desc = "Reject or strip CR/LF before writing request data to response headers; encode Content-Disposition filenames or use a header-safe helper."
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
