"""ubs_core.rust_detectors.sql_injection — interpolated SQL execution taint (bead 0xjg.7).

Port of rust_sql_injection_matches (modules/ubs-rust.sh 3737-4119).

The legacy heredoc consumed UBS_RUST_FILE_LIST (GH #70) or rglob'd the tree;
`find(files)` instead iterates the orchestrator's already-filtered file list in
order. The legacy code never called .resolve() on list entries, so neither does
this port; the local skip_dirs set is kept for documentation only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.suppression import has_suppression_marker

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
    # Rust's request extractor constructor is case-sensitive: a filesystem
    # receiver's `.path()` method does not introduce request-derived taint.
    r'|(?-i:\bPath)\s*\('
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


def has_ignore(lines, line_no, rule=None):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and has_suppression_marker(lines[idx], rule)
    ) or (
        0 <= idx - 1 < len(lines) and has_suppression_marker(lines[idx - 1], rule)
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def refs_in_expr(expr: str, table):
    searchable = without_string_literals(expr)
    names = set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', searchable))
    names.update(re.findall(r'\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::|})', expr))
    return [name for name in table if name in names]


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



@dataclass(frozen=True)
class FunctionSummary:
    """Finite local-call summary: parameter influence only, never runtime values."""

    return_taint: frozenset[int] = frozenset()
    return_sql: frozenset[int] = frozenset()
    sink_params: frozenset[int] = frozenset()


@dataclass(frozen=True)
class FunctionRegion:
    name: str
    params: tuple[str, ...]
    body: str


def _matching_delimiter(code: str, opening: int, left: str = "(", right: str = ")"):
    depth = 0
    for pos in range(opening, len(code)):
        char = code[pos]
        if char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return pos
    return None


def _split_top_level(blob: str):
    """Split comma-separated Rust syntax without entering nested delimiters."""
    masked = without_string_literals(blob)
    parts = []
    start = 0
    stack = []
    closing = {")": "(", "]": "[", "}": "{"}
    for pos, char in enumerate(masked):
        if char in "([{":
            stack.append(char)
        elif char in closing:
            if stack and stack[-1] == closing[char]:
                stack.pop()
        elif char == "," and not stack:
            parts.append(blob[start:pos])
            start = pos + 1
    parts.append(blob[start:])
    return parts


def _parameter_names(blob: str):
    names = []
    for part in _split_top_level(blob):
        raw = part.strip()
        if not raw or re.fullmatch(r"(?:&\s*)?(?:mut\s+)?self", raw):
            continue
        left = raw.split(":", 1)[0]
        tokens = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", left)
        tokens = [token for token in tokens if token not in {"mut", "ref", "self"}]
        if tokens:
            names.append(tokens[-1])
    return tuple(names)


def _function_regions(text: str):
    """Index ordinary local functions with balanced signature/body delimiters."""
    code = strip_comments_and_strings(text, "rust")
    regions = []
    for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        opening = code.find("(", match.start())
        if opening < 0:
            continue
        close = _matching_delimiter(code, opening)
        if close is None:
            continue
        body = close + 1
        while body < len(code) and code[body].isspace():
            body += 1
        # Skip return types / where clauses while respecting nested type syntax.
        while body < len(code) and code[body] != "{":
            if code[body] == ";":
                break
            body += 1
        if body >= len(code) or code[body] != "{":
            continue
        end = _matching_delimiter(code, body, "{", "}")
        if end is None:
            continue
        regions.append(FunctionRegion(
            match.group(1),
            _parameter_names(text[opening + 1:close]),
            text[body + 1:end],
        ))
    return regions


def _named_calls(expr: str, names):
    """Yield exact free-function calls; method/qualified calls stay opaque."""
    if not names:
        return
    masked = without_string_literals(expr)
    group = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    for match in re.finditer(rf"(?<![\w:.])(?P<name>{group})\s*\(", masked):
        opening = masked.find("(", match.start())
        close = _matching_delimiter(masked, opening)
        if close is None:
            continue
        yield match.group("name"), _split_top_level(expr[opening + 1:close])


def _origin_indexes(path_desc):
    found = set()
    for step in path_desc or ():
        match = re.fullmatch(r"param:(\d+)", step)
        if match:
            found.add(int(match.group(1)))
    return found


def _value_path(expr: str, tainted, dirty_sql, summaries=None, depth=0):
    dirty_refs = refs_in_expr(expr, dirty_sql)
    if dirty_refs:
        return list(dirty_sql[dirty_refs[0]].get("path", [dirty_refs[0]]))
    taint = taint_from_expr(expr, tainted)
    if taint:
        return list(taint.get("path", ()))
    if summaries and depth < 4:
        call_taint, call_sql = _call_effect(expr, summaries, tainted, dirty_sql, depth + 1)
        return call_sql or call_taint
    return []


def _call_effect(expr: str, summaries, tainted, dirty_sql, depth=0):
    """Return (taint path, dirty-SQL path) for known local helper calls."""
    for name, arguments in _named_calls(expr, summaries):
        summary = summaries[name]
        taint_path = []
        sql_path = []
        for index in sorted(summary.return_taint):
            if index < len(arguments):
                taint_path = _value_path(arguments[index], tainted, dirty_sql, summaries, depth)
                if taint_path:
                    break
        for index in sorted(summary.return_sql):
            if index < len(arguments):
                sql_path = _value_path(arguments[index], tainted, dirty_sql, summaries, depth)
                if sql_path:
                    break
        if taint_path or sql_path:
            step = f"{name}()"
            if taint_path:
                taint_path = [*taint_path[-(path_limit - 1):], step]
            if sql_path:
                sql_path = [*sql_path[-(path_limit - 1):], step]
            return taint_path, sql_path
    return [], []


def _sink_argument(statement: str):
    match = sink_re.search(statement)
    if not match:
        return None
    masked = without_string_literals(statement)
    opening = masked.find("(", match.start())
    if opening < 0:
        return None
    close = _matching_delimiter(masked, opening)
    if close is None:
        return None
    arguments = _split_top_level(statement[opening + 1:close])
    return arguments[0].strip() if arguments else None


def _summary_sink_paths(statement: str, summaries, tainted, dirty_sql):
    paths = []
    for name, arguments in _named_calls(statement, summaries):
        summary = summaries[name]
        for index in sorted(summary.sink_params):
            if index >= len(arguments):
                continue
            path_desc = _value_path(arguments[index], tainted, dirty_sql, summaries)
            if path_desc:
                paths.append([*path_desc[-(path_limit - 1):], f"{name}() SQL execution"])
    return paths


def _derive_function_summary(region: FunctionRegion, summaries):
    tainted = {
        name: {"path": [f"param:{index}"]}
        for index, name in enumerate(region.params)
    }
    dirty_sql = {}
    sql_vars = set()
    return_taint = set()
    return_sql = set()
    sink_params = set()
    lines = region.body.splitlines()

    def record_return(expr):
        call_taint, call_sql = _call_effect(expr, summaries, tainted, dirty_sql)
        path_desc = call_taint or _value_path(expr, tainted, {}, summaries)
        return_taint.update(_origin_indexes(path_desc))
        sql_desc = call_sql or tainted_path_for_expr(expr, tainted, dirty_sql)
        return_sql.update(_origin_indexes(sql_desc))

    for line_no in range(1, len(lines) + 1):
        raw_line = strip_line_comments(lines[line_no - 1]).strip()
        if not raw_line:
            continue
        statement = logical_statement(lines, line_no).strip()
        if not statement:
            continue

        assign = assign_re.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            call_taint, call_sql = _call_effect(rhs, summaries, tainted, dirty_sql)
            taint = {"path": call_taint} if call_taint else taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and not refs_in_expr(rhs, tainted):
                tainted.pop(name, None)
            mark_dirty(name, rhs, tainted, dirty_sql, sql_vars)
            if call_sql:
                dirty_sql[name] = {"path": call_sql}

        push = push_re.search(statement)
        if push:
            recv = push.group("recv")
            arg = push.group("arg")
            path_desc = _value_path(arg, tainted, dirty_sql, summaries)
            if recv in sql_vars and path_desc:
                dirty_sql[recv] = {"path": [*path_desc[-(path_limit - 1):], recv]}

        argument = _sink_argument(statement)
        if argument is not None and not sink_is_compile_time_checked(statement):
            sink_params.update(_origin_indexes(_value_path(argument, tainted, dirty_sql, summaries)))

        for name, arguments in _named_calls(statement, summaries):
            summary = summaries[name]
            for index in summary.sink_params:
                if index < len(arguments):
                    sink_params.update(_origin_indexes(
                        _value_path(arguments[index], tainted, dirty_sql, summaries)
                    ))

        returned = re.match(r"^\s*return\b(.*?);?\s*$", statement, re.DOTALL)
        if returned:
            record_return(returned.group(1).strip())

    # Rust tail expressions are common for query-builder helpers.
    for raw in reversed(lines):
        tail = strip_line_comments(raw).strip()
        if not tail:
            continue
        if not tail.endswith(";") and not re.match(
                r"^(?:let|if|else|for|while|loop|match|return|break|continue)\b", tail):
            record_return(tail)
        break

    return FunctionSummary(frozenset(return_taint), frozenset(return_sql), frozenset(sink_params))


def _function_summaries(text: str):
    """Least fixed point over finite parameter-effect summaries."""
    regions = _function_regions(text)
    summaries = {region.name: FunctionSummary() for region in regions}
    if len(summaries) != len(regions):
        # Ambiguous local names cannot be resolved without Rust namespace/type
        # analysis. Leave them opaque rather than guessing by leaf spelling.
        counts = {}
        for region in regions:
            counts[region.name] = counts.get(region.name, 0) + 1
        summaries = {name: summary for name, summary in summaries.items() if counts[name] == 1}
        regions = [region for region in regions if counts[region.name] == 1]

    while True:
        changed = False
        for region in regions:
            previous = summaries[region.name]
            derived = _derive_function_summary(region, summaries)
            merged = FunctionSummary(
                previous.return_taint | derived.return_taint,
                previous.return_sql | derived.return_sql,
                previous.sink_params | derived.sink_params,
            )
            if merged != previous:
                summaries[region.name] = merged
                changed = True
        if not changed:
            return summaries


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not (source_re.search(text) and sql_keyword_re.search(text) and sink_re.search(text)):
        return
    lines = text.splitlines()
    summaries = _function_summaries(text)
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
            call_taint, call_sql = _call_effect(rhs, summaries, tainted, dirty_sql)
            taint = {"path": call_taint} if call_taint else taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and not refs_in_expr(rhs, tainted):
                tainted.pop(name, None)
            mark_dirty(name, rhs, tainted, dirty_sql, sql_vars)
            if call_sql:
                dirty_sql[name] = {"path": call_sql}

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

        for path_desc in _summary_sink_paths(statement, summaries, tainted, dirty_sql):
            if has_ignore(lines, line_no, RULE_ID):
                continue
            key = (path, line_no)
            if key in seen:
                continue
            seen.add(key)
            issues.append((path, line_no, f"{source_line(lines, line_no)}  [{' -> '.join(path_desc)}]"))

        if not sink_re.search(statement):
            continue
        if sink_is_compile_time_checked(statement):
            continue
        if parameterized_re.search(statement) and not refs_in_expr(statement, dirty_sql) and not is_constructed_sql(statement, tainted):
            continue
        path_desc = tainted_path_for_expr(statement, tainted, dirty_sql)
        if not path_desc:
            continue
        if has_ignore(lines, line_no, RULE_ID):
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
