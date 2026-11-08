"""ubs_core.analyzers.sec_sql_injection — request-derived SQL construction
reaching execution sinks (bead A4-js security wave, bead 0xjg.4).

Verbatim port of the legacy ubs-js.sh ``js_sql_injection_matches`` function
with the same source/sink/keyword/safe-template regexes, same 18-line statement
window, same taint propagation (destructuring,
route-param signatures, assignment kill rules), same parameterized/Prisma
tagged-template suppression. Marker suppression uses shared lexical statement
ownership and exact rule scopes without erasing annotated source or validation
facts. The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``;
per-file match logic is retained. Proven Drizzle SQL object calls may additionally
use the shared bounded engine to distinguish bound chunks from raw SQL text.

Legacy emission: print_finding "critical" / "Interpolated SQL reaches
execution sink". The legacy title rides in the message so the contract-v2
text renderer surfaces it verbatim (rule ids are not in
js_rules.SUMMARY_MAP).
"""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.lexer import javascript_lexical_views

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}

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
    return statement_window(lines, index, max_lines)[0]


def statement_window(lines: list[str], index: int, max_lines: int = 18) -> tuple[str, int]:
    """Return the legacy statement text and its exclusive physical-line end."""
    parts = []
    paren = brace = bracket = 0
    end = index
    for offset in range(index, min(len(lines), index + max_lines)):
        current = strip_line_comments(lines[offset]).strip()
        if not current:
            continue
        parts.append(current)
        end = offset + 1
        paren += current.count('(') - current.count(')')
        brace += current.count('{') - current.count('}')
        bracket += current.count('[') - current.count(']')
        if offset > index and paren <= 0 and brace <= 0 and bracket <= 0:
            break
        if ';' in current and paren <= 0 and brace <= 0 and bracket <= 0:
            break
    return ' '.join(parts), end


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


def permits_drizzle_bindings(text: str) -> bool:
    """Conservative file-level prerequisite for the Drizzle execution shape.

    Raw fragments, aliases and local rebinding make lexical proof insufficient.
    Keep those files on the existing detection path rather than treating every
    function named ``sql`` as a parameterizing provider.
    """
    source, code = javascript_lexical_views(text)
    imports = re.finditer(
        r'\bimport\s*\{([^}]+)\}\s*from\s*([\'"])drizzle-orm\2', source
    )
    imported = any(
        code[match.start():match.start() + 6] == 'import'
        and 'sql' in (name.strip() for name in match.group(1).split(','))
        for match in imports
    )
    if not imported:
        return False
    # SQL/SQLChunk constructors can insert raw fragments, including through an
    # aliased import. Their presence requires richer value provenance.
    if any(re.search(r'\b(?:SQL|StringChunk)\b', match.group(1))
           for match in re.finditer(r'\bimport\s*\{([^}]+)\}\s*from\s*([\'"])drizzle-orm\2', source)):
        return False
    uncertain = re.compile(
        r'\.\s*raw\b|\b(?:sql|Prisma)\s*\['
        r'|\b(?:queryRawUnsafe|executeRawUnsafe)\b'
        r'|\b(?:const|let|var|function|class)\s+sql\b'
        r'|\bsql\s*=(?!=)|=\s*sql\s*(?:[;,)]|$)'
        r'|\b(?:const|let|var)\s*\{[^}]*\bsql\b'
        r'|\bfunction\b[^()]*\([^)]*\bsql\b'
        r'|\([^()]*\bsql\b[^()]*\)\s*(?::[^=]*)?=>'
        r'|(?:\(|,)\s*sql\s*(?=[:,)=])|\bcatch\s*\([^)]*\bsql\b'
        r'|\bnew\s+(?:SQL|StringChunk)\b'
    )
    return not uncertain.search(code)


def only_bound_drizzle_execution(statement: str) -> bool:
    """Every execution sink must receive one complete ``sql`...` `` value.

    The shared lexical view retains interpolation expressions and substitutes
    balanced parentheses for template boundaries. It prevents SQL-looking text
    in strings/comments from establishing a safe tag and keeps nested execution
    sinks visible. An incomplete bounded statement never establishes safety.
    """
    source, code = javascript_lexical_views(statement)
    templates: dict[int, int] = {}
    for match in re.finditer(r'(?<![\w$.])sql\s*`', source):
        opening = match.end() - 1
        if code[match.start():opening].strip() != 'sql' or code[opening] != '(':
            continue
        depth = 0
        for offset in range(opening, len(code)):
            if code[offset] == '(':
                depth += 1
            elif code[offset] == ')':
                depth -= 1
                if depth == 0:
                    # A call may return an unsafe SQL wrapper rather than a
                    # bound scalar. Do not claim safety for opaque builders.
                    if (source[offset] == '`'
                            and not re.search(r'(?:[\w$]|\])\s*\(', code[opening + 1:offset])):
                        templates[match.start()] = offset + 1
                    break
    if not templates:
        return False
    found = False
    for sink in sql_sink_re.finditer(source):
        # Ignore sink-shaped literal text, while keeping real nested calls.
        if code[sink.start():sink.end() - 1] != source[sink.start():sink.end() - 1]:
            continue
        found = True
        if not re.fullmatch(r'\.\s*(?:query|execute)\s*\(', sink.group(), re.I):
            return False
        argument = sink.end()
        while argument < len(code) and code[argument].isspace():
            argument += 1
        end = templates.get(argument)
        if end is None:
            return False
        while end < len(code) and code[end].isspace():
            end += 1
        if end == len(code) or code[end] != ')':
            return False
    return found


def source_line(lines: list[str], index: int) -> str:
    if 0 <= index < len(lines):
        return lines[index].strip().replace('\t', ' ')
    return ''


def proven_drizzle_lines(path: Path, text: str) -> set[int]:
    """Prove every SQL effect in each complete legacy statement window.

    A genuine raw factory can be an ignored separator or argument inside a
    proven composition. A nested execution is a separate effect and requires
    its own proof, including when both calls share a physical source line.
    """
    if 'drizzle-orm' not in text:
        return set()
    from ubs_core.analyzers.taint_js import drizzle_sql_call_proofs
    proofs = sorted(drizzle_sql_call_proofs(path, text), key=lambda item: (item[0], -item[1]))
    if not proofs:
        return set()
    source, code = javascript_lexical_views(text)
    line_starts, offset = [], 0
    for line in text.splitlines(keepends=True):
        line_starts.append(offset)
        offset += len(line)
    observations, unproven_executions, stack, cursor = [], [], [], 0
    for match in sql_sink_re.finditer(source):
        if code[match.start():match.end() - 1] != source[match.start():match.end() - 1]:
            continue
        while cursor < len(proofs) and proofs[cursor][0] <= match.start():
            proof = proofs[cursor]
            cursor += 1
            while stack and stack[-1][1] <= proof[0]:
                stack.pop()
            if stack and proof[1] > stack[-1][1]:
                return set()  # intersecting, non-nested spans cannot certify ownership
            stack.append(proof)
        while stack and stack[-1][1] <= match.start():
            stack.pop()
        certificate = None
        if stack and match.end() <= stack[-1][1]:
            _start, _end, role, own_safe = stack[-1]
            if role == 'execute':
                if own_safe:
                    certificate = stack[-1]
                else:
                    unproven_executions.append(match.start())
            elif role == 'factory':
                certificate = next((proof for proof in reversed(stack) if proof[3]), None)
            else:
                unproven_executions.append(match.start())
        else:
            unproven_executions.append(match.start())
        line = bisect_right(line_starts, match.start())
        observations.append((line, certificate))
    statuses = {}
    for line, certificate in observations:
        # Query-value safety does not excuse execution effects inside an
        # ignored argument or chunk, including effects on another source line.
        safe = certificate is not None and (
            bisect_left(unproven_executions, certificate[1])
            == bisect_left(unproven_executions, certificate[0]))
        statuses[line] = statuses.get(line, True) and safe
    lines = text.splitlines()
    result = set()
    for line, safe in statuses.items():
        if not safe:
            continue
        _statement, end = statement_window(lines, line - 1)
        # The legacy detector can attribute an ASI-separated sibling call to
        # the preceding line. Certify that exact bounded window, not just the
        # call that supplied its SQL keyword or its opening parenthesis.
        if all(statuses.get(number, True) for number in range(line, end + 1)):
            result.add(line)
    return result


def scan_file_findings(path: Path) -> Iterator[tuple[int, str, str]]:
    """Yield (line_number, sample_text, reason) per detection; heredoc-identical."""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    original_text = text
    lines = text.splitlines()
    source_index = SourceSuppressions('javascript').index(path, text)
    text = '\n'.join(lines)
    if not (sql_sink_re.search(text) or sql_keyword_re.search(text)):
        return
    drizzle_bindings = permits_drizzle_bindings(text)
    drizzle_proofs = None
    tainted: set[str] = set()
    tainted_sql: set[str] = set()
    seen: set[tuple[str, int, str]] = set()
    for idx, raw in enumerate(lines):
        stripped = strip_line_comments(raw).strip()
        if not stripped:
            continue
        statement = statement_from(lines, idx)
        if not statement:
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
        if not statement:
            continue
        if not sql_sink_re.search(statement):
            continue
        if only_safe_tagged_templates(statement):
            continue
        if drizzle_bindings and only_bound_drizzle_execution(statement):
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
        if drizzle_proofs is None:
            drizzle_proofs = proven_drizzle_lines(path, original_text)
        if idx + 1 in drizzle_proofs:
            continue

        reason = 'request-derived SQL reaches raw execution'
        if unsafe:
            reason = 'request-derived SQL reaches Prisma raw unsafe execution'
        elif sql_var_refs:
            reason = f"request-derived SQL variable {sql_var_refs[0]} reaches execution"
        key = (str(path), idx + 1, reason)
        if key in seen or source_index.is_suppressed(idx + 1, RULE):
            continue
        seen.add(key)
        yield idx + 1, f"{source_line(lines, idx)}  [{reason}]", reason


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        rel = path.resolve()
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
    # legacy-faithful: the declaring line self-references its tainted SQL
    # variable, so the reason names the variable (verified vs extracted
    # heredoc — see test-suite/artifacts/a4-sec-sql-injection/parity.txt)
    assert reason == "request-derived SQL variable rows reaches execution", findings
    assert "WHERE tenant" in sample, findings


def _selftest_prisma_unsafe(tmp_prefix: str = "ubs_core_sec_sql_prisma_") -> None:
    import tempfile

    # request-derived input reaching $queryRawUnsafe (legacy-verified:
    # flags line 3 with the Prisma raw unsafe reason)
    src = "\n".join([
        "export async function lookup(req: Request, prisma: PrismaLike) {",
        "  const status = req.body.status;",
        "  return prisma.$queryRawUnsafe(`SELECT * FROM invoices WHERE status = '${status}'`);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "accounts.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, _sample, reason = findings[0]
    assert line == 3, findings
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

    # lines 4-5 carry a genuinely request-derived variable (legacy-verified:
    # flagged as SQL-variable reasons without markers, clean with them —
    # line-above and same-line placements both suppress)
    src = "\n".join([
        "export async function list(req: Request) {",
        "  const slug = new URL(req.url).searchParams.get('slug');",
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

    # request-derived fragment interpolated into the sink (legacy-verified:
    # exactly one record at line 3, "raw execution" reason)
    src = (
        "export async function list(req: Request) {\n"
        "  const slug = new URL(req.url).searchParams.get('slug');\n"
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
        assert rec["line"] == 3, rec
        assert TITLE in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("interpolated-sql-sink", _selftest_interpolated_sql_sink),
    ("prisma-unsafe", _selftest_prisma_unsafe),
    ("parameterized-clean", _selftest_parameterized_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_sql_injection", run=run, selftests=SELF_TESTS))
