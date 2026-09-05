"""ubs_core.analyzers.sec_request_body — unbounded request body parsing
(bead A4-js security wave, bead 0xjg.4).

Verbatim port of the legacy ubs-js.sh ``js_unbounded_request_body_matches``
function including its suppression helpers: same body-consumer regex
(json/text/arrayBuffer/formData/blob over req/request/nextRequest/event.request
/ctx.request/context.request), same size-guard/allowlist suppressions resolved
inside the ±(45/16)-line function context, same ``ubs:ignore`` placement rules
(any of the three lines ending at the match line). The heredoc's os.walk over
the project is replaced by iteration over ``RunContext.files``; per-file match
logic is unchanged.

Legacy emission: print_finding "warning" / "Request body parsed without
explicit size guard". The legacy title rides in the message so the
contract-v2 text renderer surfaces it verbatim (rule ids are not in
js_rules.SUMMARY_MAP).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.request-body"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
TITLE = "Request body parsed without explicit size guard"
REMEDIATION = ("Check Content-Length or enforce framework/body-parser limits before "
               "request.json(), request.text(), request.arrayBuffer(), request.formData(), "
               "or equivalent body consumers")

body_call_re = re.compile(
    r'\b(?P<receiver>(?:req|request|nextRequest|event\.request|ctx\.request|context\.request))'
    r'\s*\.\s*(?P<method>json|text|arrayBuffer|formData|blob)\s*\(',
    re.IGNORECASE,
)
safe_re = re.compile(
    r'\b(?:content-length|Content-Length|headers\.get\s*\(\s*[\'"]content-length[\'"]|'
    r'bodySizeLimit|sizeLimit|maxBodySize|maxRequestBody|maxPayload|maxBytes|'
    r'bytes\.parse|raw-body[^;\n]*limit|'
    r'createUploadthing|unstable_parseMultipartFormData)\b'
)
guard_re = re.compile(r'\b(?:if|throw|return|NextResponse\.json|Response\.json)\b')


def strip_line_comments(line: str) -> str:
    quote = ''
    escaped = False
    for idx, ch in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '/' and idx + 1 < len(line) and line[idx + 1] == '/':
            return line[:idx]
    return line


def has_ignore(lines: list[str], idx: int) -> bool:
    start = max(0, idx - 2)
    return any('ubs:ignore' in lines[pos] for pos in range(start, idx + 1))


def source_line(lines: list[str], idx: int) -> str:
    return lines[idx].strip().replace('\t', ' ')


def function_context(lines: list[str], idx: int) -> str:
    start = idx
    while start > 0 and idx - start < 45:
        stripped = strip_line_comments(lines[start]).strip()
        if re.search(r'\b(?:export\s+)?(?:async\s+)?function\b|=>\s*\{|app\.(?:post|put|patch|use)\s*\(|router\.(?:post|put|patch|use)\s*\(', stripped):
            break
        start -= 1
    end = idx
    while end + 1 < len(lines) and end - idx < 16:
        end += 1
    return '\n'.join(lines[start:end + 1])


def guarded(context: str) -> bool:
    if not safe_re.search(context):
        return False
    return bool(guard_re.search(context) or re.search(r'\blimit\s*:', context))


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line_number, sample_text) per detection; heredoc-identical."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    seen: set[tuple[str, int]] = set()
    for idx, raw in enumerate(lines):
        if has_ignore(lines, idx):
            continue
        stripped = strip_line_comments(raw).strip()
        if not stripped or not body_call_re.search(stripped):
            continue
        if 'ubs:ignore' in stripped:
            continue
        context = function_context(lines, idx)
        if guarded(context):
            continue
        key = (str(path), idx + 1)
        if key in seen:
            continue
        seen.add(key)
        yield idx + 1, source_line(lines, idx)


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
        for line, sample in scan_file_findings(path):
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


def _selftest_unbounded_json(tmp_prefix: str = "ubs_core_sec_body_") -> None:
    import tempfile

    src = "\n".join([
        "export async function POST(request: Request) {",
        "  const payload = await request.json();",
        "  return Response.json(payload);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "route.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, sample = findings[0]
    assert line == 2, findings
    assert "request.json()" in sample, findings


def _selftest_event_formdata(tmp_prefix: str = "ubs_core_sec_body_fd_") -> None:
    import tempfile

    src = "\n".join([
        "export async function action({ request }: { request: Request }) {",
        "  const form = await event.request.formData();",
        "  return { ok: true };",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "action.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, sample = findings[0]
    assert line == 2, findings
    assert "event.request.formData()" in sample, findings


def _selftest_content_length_guarded(tmp_prefix: str = "ubs_core_sec_body_clean_") -> None:
    import tempfile

    # Content-Length check + throw before parsing keeps the handler clean
    src = "\n".join([
        "export async function POST(request: Request) {",
        "  const length = Number(request.headers.get('content-length'));",
        "  if (length > 1_000_000) {",
        "    throw new Response('Payload too large', { status: 413 });",
        "  }",
        "  const payload = await request.json();",
        "  return Response.json(payload);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "route.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_body_ign_") -> None:
    import tempfile

    # heredoc window: any ubs:ignore on idx-2..idx suppresses
    src = "\n".join([
        "export async function POST(request: Request) {",
        "  // ubs:ignore",
        "  const payload = await request.json();",
        "  return Response.json(payload);",
        "}",
        "export async function PUT(request: Request) {",
        "  const payload = await request.json(); // ubs:ignore",
        "  return Response.json(payload);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "route.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_body_run_") -> None:
    import tempfile

    src = "export async function POST(req: Request) {\n  return (await req.text()).length;\n}\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "route.js"
        target.write_text(src, encoding="utf-8")
        records = list(run(RunContext(lang="javascript", files=[target])))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 2, rec
        assert TITLE in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("unbounded-json", _selftest_unbounded_json),
    ("event-formdata", _selftest_event_formdata),
    ("content-length-guarded", _selftest_content_length_guarded),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_request_body", run=run, selftests=SELF_TESTS))
