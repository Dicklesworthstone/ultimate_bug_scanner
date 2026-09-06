"""ubs_core.rust_detectors.sql_injection — interpolated SQL execution taint (bead 0xjg.7).

Port of rust_sql_injection_matches (modules/ubs-rust.sh 3737-4119).

The legacy heredoc consumed UBS_RUST_FILE_LIST (GH #70) or rglob'd the tree;
`find(files)` instead iterates the orchestrator's already-filtered file list in
order. The legacy code never called .resolve() on list entries, so neither does
this port; the local skip_dirs set is kept for documentation only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

RULE_ID = "rust.security.sql-injection"
CATEGORY = 8
TITLE = "Interpolated SQL reaches execution sink"
SEVERITY = "critical"
DESCRIPTION = (
    "Use sqlx query macros, .bind(), rusqlite params!, diesel DSL/bind(), or "
    "other parameterized placeholders instead of format!/concat SQL"
)

skip_dirs = {".git", "target", ".cargo", "node_modules"}  # documentation-only (see module docstring)
path_limit = 5

source_re = re.compile(
    r'\b(?:params|query|form|body|json|payload|data|input)\s*\.\s*get\s*\('
    r'|\b(?:params|query|form|body|json|payload|data|input)\s*\.\s*'
    r'(?:user|username|email|name|status|tenant|account|id|role|filter|search|sort|limit|offset|where|order|table|column)\b'
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|param|query|path|match_info)\s*\('
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\('
    r'|\bPath\s*\('
    r'|\b(?:std::)?env::args(?:_os)?\s*\(',
    re.IGNORECASE,
)
sql_keyword_re = re.compile(
    r'\b(?:SELECT|INSERT|UPDATE|DELETE|UPSERT|REPLACE|WITH|CREATE|ALTER|DROP)\b',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\b(?:sqlx::query(?:_as|_scalar|_unchecked|_as_unchecked)?|'
    r'diesel::sql_query|sea_orm::Statement::from_sql_and_values|'
    r'tokio_postgres::Client::query|postgres::Client::query)\s*(?:!|\()'
    r'|\b(?:conn|connection|db|database|client|pool|tx|transaction|stmt)\s*\.\s*'
    r'(?:execute|execute_batch|batch_execute|query|query_one|query_opt|query_row|query_map|prepare|prepare_cached|raw_query|execute_raw|query_raw)\s*\('
    r'|\b(?:execute_sql|raw_query|query_raw|execute_raw)\s*\(',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
push_re = re.compile(
    r'\b(?P<recv>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:push_str|push|write_str)\s*\((?P<arg>.+)\)'
)
query_macro_re = re.compile(
    r'\bsqlx::query(?:_as|_scalar)?!\s*\(|\bquery(?:_as|_scalar)?!\s*\(',
    re.IGNORECASE,
)
path_extractor_re = re.compile(
    r'\bPath\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*:\s*Path\b'
)
parameterized_re = re.compile(
    r'\.(?:bind|push_bind)\s*\(|\bparams!\s*\[|\bnamed_params!\s*\{|\bbind\s*::\s*<',
    re.IGNORECASE,
)
construction_re = re.compile(
    r'\bformat!\s*\(|\bwrite!\s*\(|\bformat_args!\s*\(|\+|\.push_str\s*\(|\.push\s*\(',
    re.IGNORECASE,
)


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


def without_string_literals(text: str) -> str:
    chars = list(text)
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if raw_hashes is not None:
            chars[i] = " "
            if ch == '"' and text.startswith("#" * raw_hashes, i + 1):
                for pos in range(i, i + raw_hashes + 1):
                    if pos < len(chars):
                        chars[pos] = " "
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            chars[i] = " "
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
            while j < len(chars) and chars[j] == "#":
                j += 1
            if j < len(chars) and chars[j] == '"':
                for pos in range(i, j + 1):
                    chars[pos] = " "
                raw_hashes = j - i - 1
                i = j + 1
                continue
        if ch in ('"', "'"):
            chars[i] = " "
            quote = ch
        i += 1
    return "".join(chars)


def logical_statement(lines, line_no, max_lines=16):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren = statement.count("(") - statement.count(")")
    brace = statement.count("{") - statement.count("}")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (paren > 0 or brace > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + max_lines:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        paren += nxt.count("(") - nxt.count(")")
        brace += nxt.count("{") - nxt.count("}")
        has_end = has_end or ";" in nxt or "{" in nxt or "}" in nxt
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


def refs_in_expr(expr: str, table):
    searchable = without_string_literals(expr)
    refs = []
    for name in table:
        if re.search(rf'\b{re.escape(name)}\b', searchable) or re.search(
            rf'\{{\s*{re.escape(name)}\s*(?::|[}}])', expr
        ):
            refs.append(name)
    return refs


def taint_from_expr(expr: str, tainted):
    direct = source_re.search(expr)
    if direct:
        return {"path": [direct.group(0).strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get("path", [ref]))
    if len(path) >= path_limit:
        path = path[-(path_limit - 1):]
    path.append(ref)
    return {"path": path}


def is_sql_text(expr: str) -> bool:
    return bool(sql_keyword_re.search(expr))


def is_constructed_sql(expr: str, tainted) -> bool:
    if not is_sql_text(expr):
        return False
    if not (source_re.search(expr) or refs_in_expr(expr, tainted)):
        return False
    if construction_re.search(expr):
        return True
    return bool(re.search(r'\{\s*[A-Za-z_][A-Za-z0-9_]*\s*(?::|[}])', expr))


def mark_dirty(lhs: str, expr: str, tainted, dirty_sql, sql_vars):
    if is_sql_text(expr):
        sql_vars.add(lhs)
    else:
        sql_vars.discard(lhs)
    if is_constructed_sql(expr, tainted):
        refs = refs_in_expr(expr, tainted)
        if refs:
            ref = refs[0]
            path = list(tainted.get(ref, {}).get("path", [ref]))
        else:
            direct = source_re.search(expr)
            path = [direct.group(0).strip()] if direct else [lhs]
        if len(path) >= path_limit:
            path = path[-(path_limit - 1):]
        path.append(lhs)
        dirty_sql[lhs] = {"path": path}
    elif lhs in dirty_sql and parameterized_re.search(expr):
        dirty_sql.pop(lhs, None)
    elif lhs in dirty_sql and not is_sql_text(expr):
        dirty_sql.pop(lhs, None)


def tainted_path_for_expr(expr: str, tainted, dirty_sql):
    dirty_refs = refs_in_expr(expr, dirty_sql)
    if dirty_refs:
        ref = dirty_refs[0]
        return list(dirty_sql.get(ref, {}).get("path", [ref]))
    if is_constructed_sql(expr, tainted):
        refs = refs_in_expr(expr, tainted)
        if refs:
            ref = refs[0]
            return list(tainted.get(ref, {}).get("path", [ref]))
        direct = source_re.search(expr)
        if direct:
            return [direct.group(0).strip()]
    return []


def sink_is_compile_time_checked(statement: str) -> bool:
    return bool(query_macro_re.search(statement))


def path_extractor_taints(statement: str):
    return {
        match.group("name"): {"path": [f"Path({match.group('name')}) extractor"]}
        for match in path_extractor_re.finditer(statement)
    }


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not (source_re.search(text) and sql_keyword_re.search(text) and sink_re.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    dirty_sql = {}
    sql_vars = set()
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
            dirty_sql.clear()
            sql_vars.clear()
            tainted.update(path_extractor_taints(statement))
            continue

        assign = assign_re.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and not refs_in_expr(rhs, tainted):
                tainted.pop(name, None)
            mark_dirty(name, rhs, tainted, dirty_sql, sql_vars)

        push = push_re.search(statement)
        if push:
            recv = push.group("recv")
            arg = push.group("arg")
            if recv in sql_vars and (source_re.search(arg) or refs_in_expr(arg, tainted)):
                refs = refs_in_expr(arg, tainted)
                if refs:
                    ref = refs[0]
                    path_desc = list(tainted.get(ref, {}).get("path", [ref]))
                else:
                    direct = source_re.search(arg)
                    path_desc = [direct.group(0).strip()] if direct else [recv]
                if len(path_desc) >= path_limit:
                    path_desc = path_desc[-(path_limit - 1):]
                path_desc.append(recv)
                dirty_sql[recv] = {"path": path_desc}

        if not sink_re.search(statement):
            continue
        if sink_is_compile_time_checked(statement):
            continue
        if parameterized_re.search(statement) and not refs_in_expr(statement, dirty_sql) and not is_constructed_sql(statement, tainted):
            continue
        path_desc = tainted_path_for_expr(statement, tainted, dirty_sql)
        if not path_desc:
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        if len(path_desc) >= path_limit:
            path_desc = path_desc[-(path_limit - 1):]
        path_desc.append("SQL execution")
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
