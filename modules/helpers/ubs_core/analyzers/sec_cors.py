"""ubs_core.analyzers.sec_cors — credentialed wildcard/reflected CORS (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "CORS credentials with permissive
origins" (``cors_credentials_report``): same candidate gate, same 18-line
context window, same wildcard/reflected-origin + credentials-true conjunction,
same 3-line coalescing rule, same ``ubs:ignore`` placement rules (trigger line,
line above, or anywhere inside the collected context).
The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.cors"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = ("Credentialed wildcard/reflected CORS: Use an explicit trusted origin allowlist and emit "
           "Vary: Origin when Access-Control-Allow-Credentials is true")

origin_wildcard_re = re.compile(
    r'(?:'
    r'\borigin\s*:\s*(?:[\'"]\*[\'"]|\[\s*[\'"]\*[\'"]\s*\])|'
    r'[\'"]Access-Control-Allow-Origin[\'"]\s*[:,]\s*[\'"]\*[\'"]|'
    r'\.(?:setHeader|header|set)\s*\(\s*[\'"]Access-Control-Allow-Origin[\'"]\s*,\s*[\'"]\*[\'"]'
    r')',
    re.IGNORECASE,
)
origin_reflection_re = re.compile(
    r'(?:'
    r'\borigin\s*:\s*true\b|'
    r'\borigin\s*:\s*(?:req|request)\s*\.\s*headers\s*\.\s*origin\b|'
    r'[\'"]Access-Control-Allow-Origin[\'"]\s*[:,]\s*(?:req|request)\s*\.\s*headers\s*\.\s*origin\b|'
    r'\.(?:setHeader|header|set)\s*\(\s*[\'"]Access-Control-Allow-Origin[\'"]\s*,\s*(?:req|request)\s*\.\s*headers\s*\.\s*origin\b'
    r')',
    re.IGNORECASE,
)
credentials_true_re = re.compile(
    r'(?:'
    r'\bcredentials\s*:\s*true\b|'
    r'[\'"]Access-Control-Allow-Credentials[\'"]\s*[:,]\s*(?:true|[\'"]true[\'"])|'
    r'\.(?:setHeader|header|set)\s*\(\s*[\'"]Access-Control-Allow-Credentials[\'"]\s*,\s*(?:true|[\'"]true[\'"])'
    r')',
    re.IGNORECASE,
)
candidate_re = re.compile(
    r'cors\s*\(|Access-Control-Allow-Origin|\borigin\s*:\s*(?:true|[\'"]\*[\'"]|\[\s*[\'"]\*[\'"])',
    re.IGNORECASE,
)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def context_from(lines, idx, max_lines=18):
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
        ends_statement = current.endswith(';') or current.endswith('});') or current.endswith('}));') or current.endswith('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0 and ends_statement:
            break
    return ' '.join(parts) if saw_code else ""


def scan_file_findings(path: Path) -> Iterator[int]:
    """Yield 1-based line numbers per detection; match logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    seen_lines = set()
    last_issue_idx = -100
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]) or not candidate_re.search(stripped):
            continue
        context = context_from(lines, idx)
        if not context or 'ubs:ignore' in context or not credentials_true_re.search(context):
            continue
        if not (origin_wildcard_re.search(context) or origin_reflection_re.search(context)):
            continue
        if idx in seen_lines or idx - last_issue_idx <= 3:
            continue
        seen_lines.add(idx)
        last_issue_idx = idx
        yield idx + 1


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
        for line in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_wildcard_credentialed_flagged(tmp_prefix: str = "ubs_core_sec_cors_") -> None:
    import tempfile

    src = "\n".join([
        "import cors from 'cors';",
        "import express from 'express';",
        "",
        "const app = express();",
        "",
        "app.use(cors({",
        "  origin: '*',",
        "  credentials: true,",
        "}));",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "app.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [6], findings


def _selftest_reflected_origin_flagged(tmp_prefix: str = "ubs_core_sec_cors_refl_") -> None:
    import tempfile

    src = "\n".join([
        "export function reflectAnyOrigin(req, res) {",
        "  res.header('Access-Control-Allow-Origin', req.headers.origin);",
        "  res.header('Access-Control-Allow-Credentials', 'true');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "handler.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [2], findings


def _selftest_allowlist_clean(tmp_prefix: str = "ubs_core_sec_cors_clean_") -> None:
    import tempfile

    # Explicit allowlist origins and wildcard WITHOUT credentials stay clean.
    allowlisted = "\n".join([
        "import cors from 'cors';",
        "",
        "const allowedOrigins = ['https://app.example.com'];",
        "",
        "app.use(cors({",
        "  origin: allowedOrigins,",
        "  credentials: true,",
        "}));",
        "",
    ])
    public_no_creds = "\n".join([
        "app.use(cors({ origin: '*' }));",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        good = Path(tmp) / "good.ts"
        good.write_text(allowlisted, encoding="utf-8")
        pub = Path(tmp) / "public.ts"
        pub.write_text(public_no_creds, encoding="utf-8")
        assert list(scan_file_findings(good)) == [], "allowlisted origins must stay clean"
        assert list(scan_file_findings(pub)) == [], "public wildcard without credentials stays clean"


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_cors_ign_") -> None:
    import tempfile

    # ubs:ignore on the line itself and anywhere inside the collected context.
    same_line = "\n".join([
        "app.use(cors({ // ubs:ignore",
        "  origin: '*',",
        "  credentials: true,",
        "}));",
        "",
    ])
    in_context = "\n".join([
        "app.use(cors({",
        "  origin: '*',",
        "  credentials: true, // ubs:ignore",
        "}));",
        "",
    ])
    above = "\n".join([
        "// ubs:ignore",
        "app.use(cors({ origin: '*', credentials: true }));",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        for name, body in (("same.ts", same_line), ("ctx.ts", in_context), ("above.ts", above)):
            target = Path(tmp) / name
            target.write_text(body, encoding="utf-8")
            findings = list(scan_file_findings(target))
            assert findings == [], (name, findings)


def _selftest_coalescing_and_run_shape(tmp_prefix: str = "ubs_core_sec_cors_run_") -> None:
    import tempfile

    # Findings within 3 lines coalesce (heredoc rule); run() records carry the rule.
    src = "\n".join([
        "res.setHeader('Access-Control-Allow-Origin', '*');",
        "res.setHeader('Access-Control-Allow-Credentials', 'true');",
        "res.setHeader('Access-Control-Allow-Origin', '*');",
        "res.setHeader('Access-Control-Allow-Credentials', 'true');",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "resp.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [1], findings
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 1, rec
        assert "Credentialed wildcard/reflected CORS" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("wildcard-credentialed-flagged", _selftest_wildcard_credentialed_flagged),
    ("reflected-origin-flagged", _selftest_reflected_origin_flagged),
    ("allowlist-clean", _selftest_allowlist_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("coalescing-and-run-shape", _selftest_coalescing_and_run_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_cors", run=run, selftests=SELF_TESTS))
