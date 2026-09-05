"""ubs_core.analyzers.sec_sql_injection — request-derived SQL construction
reaching execution sinks (bead A4-js security wave, bead 0xjg.4).

Verbatim port of the legacy ubs-js.sh ``js_sql_injection_matches`` function
including its suppression helpers: same source/sink/keyword/safe-template
regexes, same 18-line statement window, same taint propagation (destructuring,
route-param signatures, assignment kill rules), same parameterized/Prisma
tagged-template suppression, same ``ubs:ignore`` placement rules (line above,
same line, and anywhere inside the collected statement). The heredoc's
os.walk over the project is replaced by iteration over ``RunContext.files``;
per-file match logic is unchanged.

Legacy emission: print_finding "critical" / "Interpolated SQL reaches
execution sink". The legacy title rides in the message so the contract-v2
text renderer surfaces it verbatim (rule ids are not in
js_rules.SUMMARY_MAP).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.sql-injection"
CATEGORY_ID = "js.security"
SEVERITY = "critical"
TITLE = "Interpolated SQL reaches execution sink"
REMEDIATION = ("Use parameterized queries, Prisma safe tagged templates, bind/replacements, "
               "or query-builder where clauses instead of raw string construction")

source_re = re.compile(
    r'\b(?:req|request|ctx|context|event)\.(?:body|query|params|headers|cookies)\b'
    r'|\b(?:req|request|ctx|context)\.(?:get|header|param|query)\s*\('
    r"|\b(?:context\.)?params\s*(?:\.\s*(?:id|slug|user|username|email|name|status|tenant|account|role|filter|search|sort|limit|offset|where|order|table|column)\b|\[\s*['\"](?:id|slug|user|username|email|name|status|tenant|account|role|filter|search|sort|limit|offset|where|order|table|column)['\"]\s*\])"
    r'|\b(?:searchParams|URLSearchParams)\.(?:get|getAll|entries)\s*\('
    r'|\b(?:request|req)\.url\b'
    r'|\b(?:new\s+URL|URLSearchParams)\s*\([^)]*(?:req|request|event)\b',
    re.IGNORECASE,
)
sql_keyword_re = re.compile(r'\b(?:SELECT|INSERT|UPDATE|DELETE|UPSERT|MERGE|WITH)\b', re.IGNORECASE)
sql_sink_re = re.compile(
    r'\.\s*(?:query|execute|raw|'
    r'\$queryRawUnsafe|\$executeRawUnsafe|queryRawUnsafe|executeRawUnsafe|'
    r'\$queryRaw|\$executeRaw|queryRaw|executeRaw)\s*(?:\(|`)',
    re.IGNORECASE,
)
unsafe_sink_re = re.compile(r'\$?(?:queryRawUnsafe|executeRawUnsafe)\s*\(', re.IGNORECASE)
assign_re = re.compile(r'^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(.+)$')
simple_assign_re = re.compile(r'^\s*([A-Za-z_$][\w$]*)\s*=\s*(?![=>=])(.+)$')
destructure_re = re.compile(r'^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$')
route_params_object_re = re.compile(r'^\s*\(?\s*(?:await\s+)?(?:context\.)?params\s*\)?\s*$', re.IGNORECASE)
safe_sql_re = re.compile(
    r'\b(?:sql|Prisma\.sql)\s*`|'
    r'\$queryRaw\s*`|\$executeRaw\s*`|'
    r'\b(?:query|execute|raw)\s*\(\s*["`][\s\S]*?(?:\$[0-9]+|\?|:[A-Za-z_][\w$]*)[\s\S]*?,\s*(?:\[[\s\S]*?\]|\{[\s\S]*?\b(?:replacements|bind)\b)|'
    r'\bsequelize\.query\s*\([\s\S]*?,\s*\{[\s\S]*?\b(?:replacements|bind)\b|'
    r'\b(?:knex|db|pool|connection|client)\.[A-Za-z_$][\w$]*\s*\([\s\S]*?\)\s*\.\s*(?:where|andWhere|orWhere)\s*\(',
    re.IGNORECASE,
)
safe_tagged_template_re = re.compile(
    r'\b(?:sql|Prisma\.sql)\s*`|\$queryRaw\s*`|\$executeRaw\s*`',
    re.IGNORECASE,
)


def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ''
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
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and nxt == '/':
            break
        if ch == '/' and nxt == '*':
            end = line.find('*/', i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def statement_from(lines: list[str], index: int, max_lines: int = 18) -> str:
    parts = []
    paren = brace = bracket = 0
    for offset in range(index, min(len(lines), index + max_lines)):
        current = strip_line_comments(lines[offset]).strip()
        if not current:
            continue
        parts.append(current)
        paren += current.count('(') - current.count(')')
        brace += current.count('{') - current.count('}')
        bracket += current.count('[') - current.count(']')
        if offset > index and paren <= 0 and brace <= 0 and bracket <= 0:
            break
        if ';' in current and paren <= 0 and brace <= 0 and bracket <= 0:
            break
    return ' '.join(parts)


def has_ignore(lines: list[str], index: int) -> bool:
    return (
        0 <= index < len(lines) and 'ubs:ignore' in lines[index]
    ) or (
        0 <= index - 1 < len(lines) and 'ubs:ignore' in lines[index - 1]
    )


def split_destructure_parts(blob: str) -> list[str]:
    parts = []
    start = 0
    depth = 0
    quote = ''
    escape = False
    for idx, ch in enumerate(blob):
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch in '({[':
            depth += 1
            continue
        if ch in ')}]' and depth > 0:
            depth -= 1
            continue
        if ch == ',' and depth == 0:
            parts.append(blob[start:idx].strip())
            start = idx + 1
    tail = blob[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def names_from_destructure(blob: str) -> list[str]:
    names = []
    for part in split_destructure_parts(blob):
        token = part.strip().split('=')[0].strip()
        if ':' in token:
            token = token.split(':', 1)[1].strip()
            if token.startswith('{') and token.endswith('}'):
                names.extend(names_from_destructure(token[1:-1]))
                continue
        if token.startswith('...'):
            token = token[3:].strip()
        if re.match(r'^[A-Za-z_$][\w$]*$', token):
            names.append(token)
    return names


def route_param_names_from_signature(statement: str) -> list[str]:
    if 'params' not in statement or ('function' not in statement and '=>' not in statement):
        return []
    names = []
    for match in re.finditer(r'\bparams\s*:\s*\{([^{}]+)\}', statement):
        names.extend(names_from_destructure(match.group(1)))
    return names


def rhs_expression(expr: str) -> str:
    return expr.strip().rstrip(';').strip()


def mask_literals_for_refs(expr: str) -> str:
    out = []
    quote = ''
    escape = False
    template_expr_depth = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        nxt = expr[i + 1] if i + 1 < len(expr) else ''
        if quote:
            if quote == '`' and ch == '$' and nxt == '{':
                out.append(' ')
                out.append(' ')
                i += 2
                quote = ''
                template_expr_depth = 1
                continue
            out.append(' ')
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if template_expr_depth:
            out.append(ch)
            if ch in ('"', "'", '`'):
                quote = ch
            elif ch == '{':
                template_expr_depth += 1
            elif ch == '}':
                template_expr_depth -= 1
                if template_expr_depth == 0:
                    quote = '`'
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(' ')
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def refs(expr: str, names: set[str]) -> list[str]:
    haystack = mask_literals_for_refs(expr)
    return [name for name in names if re.search(rf'(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])', haystack)]


def has_untrusted(expr: str, tainted: set[str]) -> bool:
    return bool(source_re.search(expr) or refs(expr, tainted))


def dynamic_sql(expr: str) -> bool:
    return bool('${' in expr or re.search(r'(?:\+|\.concat\s*\(|\.join\s*\()', expr))


def safe_parameterized(statement: str) -> bool:
    if unsafe_sink_re.search(statement):
        return False
    return bool(safe_sql_re.search(statement))


def only_safe_tagged_templates(statement: str) -> bool:
    return bool(safe_tagged_template_re.search(statement)) and not sql_sink_re.search(
        safe_tagged_template_re.sub('', statement)
    )


def source_line(lines: list[str], index: int) -> str:
    if 0 <= index < len(lines):
        return lines[index].strip().replace('\t', ' ')
    return ''


def scan_file_findings(path: Path) -> Iterator[tuple[int, str, str]]:
    """Yield (line_number, sample_text, reason) per detection; heredoc-identical."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    text = '\n'.join(lines)
    if not (sql_sink_re.search(text) or sql_keyword_re.search(text)):
        return
    tainted: set[str] = set()
    tainted_sql: set[str] = set()
    seen: set[tuple[str, int, str]] = set()
    for idx, raw in enumerate(lines):
        stripped = strip_line_comments(raw).strip()
        if not stripped or has_ignore(lines, idx):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        tainted.update(route_param_names_from_signature(statement))

        destruct = destructure_re.match(statement)
        if destruct:
            destruct_source = rhs_expression(destruct.group(2))
        if destruct and (source_re.search(destruct_source) or route_params_object_re.match(destruct_source)):
            tainted.update(names_from_destructure(destruct.group(1)))

        assign = assign_re.match(statement) or simple_assign_re.match(statement)
        if assign:
            name, rhs = assign.groups()
            if source_re.search(rhs) or route_params_object_re.match(rhs_expression(rhs)) or refs(rhs, tainted):
                tainted.add(name)
            elif name in tainted and not refs(rhs, tainted):
                tainted.discard(name)
            if sql_keyword_re.search(rhs) and dynamic_sql(rhs) and has_untrusted(rhs, tainted):
                tainted_sql.add(name)
            elif name in tainted_sql and not refs(rhs, tainted_sql):
                tainted_sql.discard(name)

        if not sql_sink_re.search(stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        if not sql_sink_re.search(statement):
            continue
        if only_safe_tagged_templates(statement):
            continue

        sql_var_refs = refs(statement, tainted_sql)
        untrusted = has_untrusted(statement, tainted)
        dynamic = dynamic_sql(statement)
        unsafe = bool(unsafe_sink_re.search(statement))
        has_inline_sql = bool(sql_keyword_re.search(statement))
        if safe_parameterized(statement) and not (
            sql_var_refs or (has_inline_sql and dynamic and untrusted)
        ):
            continue
        if not (
            sql_var_refs
            or (has_inline_sql and dynamic and untrusted)
            or (unsafe and (untrusted or sql_var_refs or (has_inline_sql and dynamic)))
        ):
            continue

        reason = 'request-derived SQL reaches raw execution'
        if unsafe:
            reason = 'request-derived SQL reaches Prisma raw unsafe execution'
        elif sql_var_refs:
            reason = f"request-derived SQL variable {sql_var_refs[0]} reaches execution"
        key = (str(path), idx + 1, reason)
        if key in seen:
            continue
        seen.add(key)
        yield idx + 1, f"{source_line(lines, idx)}  [{reason}]", reason


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
        for line, sample, _reason in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": f"{TITLE}: {sample}",
                "remediation": REMEDIATION,
            }


def _selftest_interpolated_sql_sink(tmp_prefix: str = "ubs_core_sec_sql_") -> None:
    import tempfile

    src = "\n".join([
        "async function listUsers(params: { tenant: string }) {",
        "  const tenant = params.tenant;",
        "  const rows = await db.query(`SELECT * FROM users WHERE tenant = '${tenant}'`);",
        "  return rows;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "users.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, sample, reason = findings[0]
    assert line == 3, findings
    assert reason == "request-derived SQL reaches raw execution", findings
    assert "WHERE tenant" in sample, findings


def _selftest_prisma_unsafe(tmp_prefix: str = "ubs_core_sec_sql_prisma_") -> None:
    import tempfile

    src = "\n".join([
        "export async function lookup(email: string) {",
        "  const rows = await prisma.$queryRawUnsafe(",
        "    'SELECT * FROM accounts WHERE owner = $1', email",
        "  );",
        "  return rows;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "accounts.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, _sample, reason = findings[0]
    assert line == 2, findings
    assert reason == "request-derived SQL reaches Prisma raw unsafe execution", findings


def _selftest_parameterized_clean(tmp_prefix: str = "ubs_core_sec_sql_clean_") -> None:
    import tempfile

    # $1 placeholder + replacements object and a safe tagged template stay clean
    src = "\n".join([
        "export async function list(slug: string) {",
        "  const rows = await db.query('SELECT * FROM tenants WHERE slug = $1', [slug]);",
        "  const safe = await prisma.$queryRaw`SELECT * FROM accounts WHERE slug = ${slug}`;",
        "  return { rows, safe };",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_sql_ign_") -> None:
    import tempfile

    # line-above placement suppresses; same-line placement suppresses
    src = "\n".join([
        "export async function list(slug: string) {",
        "  // ubs:ignore",
        "  const rows = await db.query(`SELECT * FROM tenants WHERE slug = '${slug}'`);",
        "  const rest = await db.query(`SELECT * FROM accounts WHERE slug = '${slug}'`); // ubs:ignore",
        "  return { rows, rest };",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ign.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_sql_run_") -> None:
    import tempfile

    src = (
        "export async function list(slug: string) {\n"
        "  return db.query(`SELECT * FROM tenants WHERE slug = '${slug}'`);\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "run.ts"
        target.write_text(src, encoding="utf-8")
        records = list(run(RunContext(lang="javascript", files=[target])))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "critical", rec
        assert rec["line"] == 2, rec
        assert TITLE in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("interpolated-sql-sink", _selftest_interpolated_sql_sink),
    ("prisma-unsafe", _selftest_prisma_unsafe),
    ("parameterized-clean", _selftest_parameterized_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_sql_injection", run=run, selftests=SELF_TESTS))
