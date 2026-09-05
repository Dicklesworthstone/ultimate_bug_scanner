"""Shared java/kotlin line-scanning scaffolding for the heredoc detector ports.

Every helper here is a verbatim copy of the identically named function inside
the legacy `python3 - "$PROJECT_DIR" <<'PY'` heredocs (modules/ubs-java.sh
672-2374), so each detector behaves exactly like the heredoc it replaces.
Detectors iterate the module's file list instead of re-walking the tree.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

SKIP_DIRS = {'.git', '.gradle', '.mvn', 'build', 'target', 'out', 'node_modules', '.cache'}
EXTS = ('.java', '.kt', '.kts')


def iter_java_files(files: Sequence[Path]) -> Iterable[Path]:
    for path in files:
        if path.suffix.lower() in EXTS:
            yield path


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return []


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
        if ch == '/' and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == '/':
                break
            if nxt == '*':
                end = line.find('*/', i + 2)
                if end == -1:
                    break
                i = end + 2
                continue
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
    stripped = statement.strip()
    has_kotlin_line_end = balance <= 0 and bool(
        re.match(r'(?:val|var|return|throw)\b', stripped) or
        (re.match(r'[A-Za-z_][A-Za-z0-9_]*\s*=', stripped) is not None)
    )
    has_end = ';' in statement or '{' in statement or '}' in statement or has_kotlin_line_end
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        has_kotlin_line_end = balance <= 0 and bool(
            re.match(r'(?:val|var|return|throw)\b', next_line) or
            (re.match(r'[A-Za-z_][A-Za-z0-9_]*\s*=', next_line) is not None)
        )
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line or has_kotlin_line_end
        lookahead += 1
    return statement


def logical_statement_balance(lines, line_no):
    """Archive-extraction heredoc variant (ubs-java.sh 778-788): joins while
    parens stay unbalanced, with no Kotlin line-end heuristic."""
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


# ── Request-taint engine shared by the header-injection / SSRF ports ───────

def annotated_sources(text, ANNOTATED_PARAM_RE):
    sources = {}
    for match in ANNOTATED_PARAM_RE.finditer(text):
        name = match.group(1)
        sources[name] = {'path': [f'@request {name}']}
    return sources


def is_safe_expr(expr, SAFE_EXPR_RE):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def taint_from_expr(expr, tainted, SOURCE_RE, SAFE_EXPR_RE, path_limit=4):
    if is_safe_expr(expr, SAFE_EXPR_RE):
        return None
    direct = SOURCE_RE.search(expr)
    if direct:
        return {'path': [direct.group(0).strip('(')]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= path_limit:
        path = path[-(path_limit - 1):]
    path.append(ref)
    return {'path': path}


def taint_path_desc(direct, refs, tainted, sink_label, path_limit=4):
    if direct:
        return f"{direct.group(0).strip('(')} -> {sink_label}"
    ref = refs[0]
    seq = list(tainted.get(ref, {}).get('path', [ref]))
    if len(seq) >= path_limit:
        seq = seq[-(path_limit - 1):]
    seq.append(sink_label)
    return ' -> '.join(seq)
