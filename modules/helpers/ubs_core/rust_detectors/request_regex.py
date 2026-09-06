"""ubs_core.rust_detectors.request_regex — request-controlled regex-pattern taint (bead 0xjg.7).

Port of rust_request_regex_matches (modules/ubs-rust.sh 4161-4431).

The legacy heredoc consumed UBS_RUST_FILE_LIST (GH #70) or rglob'd the tree;
`find(files)` instead iterates the orchestrator's already-filtered file list in
order. The legacy code never called .resolve() on list entries, so neither does
this port; the local skip_dirs set is kept for documentation only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

RULE_ID = "rust.security.request-regex"
CATEGORY = 8
TITLE = "Request-controlled regex pattern reaches regex engine"
SEVERITY = "warning"
DESCRIPTION = (
    "Escape pattern fragments with regex::escape or validate against an "
    "allow-list before Regex::new/RegexSet::new"
)

skip_dirs = {".git", "target", ".cargo", "node_modules"}  # documentation-only (see module docstring)

source_re = re.compile(
    r'\b(?:params|query|form|body|json|payload|data|input)\s*\.\s*get\s*\('
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|param|query|path|match_info)\s*\('
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\('
    r'|\bPath\s*\('
    r'|\b(?:std::)?env::args(?:_os)?\s*\(',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\b(?:(?:regex::)?Regex|(?:regex::)?RegexBuilder|(?:regex::)?RegexSet)\s*::\s*new\s*\(',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
path_extractor_re = re.compile(r'\bPath\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*:\s*Path\b')
safe_re = re.compile(
    r'\b(?:regex::)?escape\s*\('
    r'|\b(?:escape_regex|escape_regexp|sanitize_regex|sanitize_regexp|safe_regex|safe_regexp|'
    r'validate_regex|validate_regexp|allowed_regex|allowed_regexp|is_safe_regex|is_allowed_regex)[A-Za-z0-9_]*\s*\('
    r'|\b(?:ALLOWED|Allowed|allowed)[A-Za-z0-9_]*\.(?:contains|iter)\s*\(',
    re.IGNORECASE,
)
PATH_LIMIT = 5

def rust_files(files):
    """Legacy rust_files(): consume the orchestrator's authoritative filtered
    file list (--exclude / --strict-gitignore / --exclude-tests) instead of
    re-walking the tree with a local skip list. The legacy listing path kept
    .rs entries only and never resolved them."""
    for entry in files:
        if entry.suffix == ".rs":
            yield entry

def strip_line_comments(line: str) -> str:
    out = []
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if raw_hashes is not None:
            out.append(ch)
            if ch == '"' and line.startswith("#" * raw_hashes, i + 1):
                out.extend("#" * raw_hashes)
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "r":
            j = i + 1
            while j < len(line) and line[j] == "#":
                j += 1
            if j < len(line) and line[j] == '"':
                raw_hashes = j - i - 1
                out.extend(line[i : j + 1])
                i = j + 1
                continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)

def mask_literals(expr: str):
    chars = list(expr)
    quote = ""
    escape = False
    for i, ch in enumerate(chars):
        if quote:
            chars[i] = " "
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            continue
        if ch in ('"', "'"):
            chars[i] = " "
            quote = ch
    return "".join(chars)

def logical_statement(lines, line_no, max_lines=12):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count("(") - statement.count(")")
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + max_lines:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        balance += nxt.count("(") - nxt.count(")")
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and "ubs:ignore" in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and "ubs:ignore" in lines[idx - 1]
    )

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""

def refs_in_expr(expr: str, tainted):
    haystack = mask_literals(expr)
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', haystack)]

def taint_from_expr(expr: str, tainted):
    if safe_re.search(expr):
        return None
    direct = source_re.search(expr)
    if direct:
        return {"path": [direct.group(0).strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get("path", [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {"path": path}

def path_extractor_taints(statement: str):
    return {
        match.group("name"): {"path": [f"Path({match.group('name')}) extractor"]}
        for match in path_extractor_re.finditer(statement)
    }

def sink_arg(statement: str):
    match = sink_re.search(statement)
    if not match:
        return ""
    start = match.end()
    depth = 1
    quote = ""
    escape = False
    for pos in range(start, len(statement)):
        ch = statement[pos]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return statement[start:pos].strip()
        elif ch == "," and depth == 1:
            return statement[start:pos].strip()
    return ""

def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not (source_re.search(text) and sink_re.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for line_no, _ in enumerate(lines, start=1):
        if has_ignore(lines, line_no):
            continue
        raw_line = strip_line_comments(lines[line_no - 1]).strip()
        if not raw_line:
            continue
        statement = logical_statement(lines, line_no).strip()
        if not statement:
            continue
        if re.match(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+\b', raw_line):
            tainted.clear()
            tainted.update(path_extractor_taints(statement))
            continue
        assign = assign_re.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif safe_re.search(rhs):
                tainted.pop(name, None)
        if not sink_re.search(statement):
            continue
        arg = sink_arg(statement)
        if not arg or safe_re.search(arg):
            continue
        direct = source_re.search(arg)
        refs = refs_in_expr(arg, tainted)
        if not direct and not refs:
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = [direct.group(0).strip()]
        else:
            ref = refs[0]
            path_desc = list(tainted.get(ref, {}).get("path", [ref]))
        if len(path_desc) >= PATH_LIMIT:
            path_desc = path_desc[-(PATH_LIMIT - 1):]
        path_desc.append("regex engine")
        issues.append((path, line_no, f"{source_line(lines, line_no)}  [{' -> '.join(path_desc)}]"))


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy deduped finding, in legacy order."""
    issues = []
    for rust_file in rust_files(files):
        analyze(rust_file, issues)
    for path, line_no, code in issues:
        yield path, line_no, 1, code


if __name__ == "__main__":
    import sys
    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
