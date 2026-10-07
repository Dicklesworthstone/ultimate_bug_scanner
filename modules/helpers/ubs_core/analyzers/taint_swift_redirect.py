"""Swift redirect policy over the shared scoped request-flow frontend."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from .taint_swift_traversal import flow_findings, iter_swift_files, rel, source_line


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, int, str]]:
    """Render count/sample output from structured, sink-specific flow facts."""
    lines = text.splitlines()
    findings = []
    for finding in flow_findings(path, text, 'redirect'):
        route = finding['extras']['taint_path']
        source = next((step['label'] for step in route if step['kind'] == 'source'), 'request source')
        line = finding['line']
        findings.append((rel(path, base), line, f"{source_line(lines, line)} [{source} -> redirect]"))
    return findings


def collect_findings(root: Path) -> list[tuple[str, int, str]]:
    root = Path(root).resolve()
    base = root if root.is_dir() else root.parent
    findings: list[tuple[str, int, str]] = []
    for path in iter_swift_files(root, base):
        text = path.read_text(encoding='utf-8', errors='replace')
        findings.extend(scan_text(path, text, base))
    return findings


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("usage: taint_swift_redirect.py <project_dir>", file=sys.stderr)
        return 2
    findings = collect_findings(Path(sys.argv[1]).resolve())
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    print(f"{len(findings)}\t{samples}")
    return 0


_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix != '.swift':
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        yield from flow_findings(path, text, 'redirect')


def _selftest_detects_query_redirect() -> None:
    code = (
        "func queryRedirect(req: Request) -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    return req.redirect(to: target)\n"
        "}\n"
    )
    findings = scan_text(Path("F.swift"), code, Path("."))
    assert len(findings) == 1, findings
    assert findings[0][1] == 3, findings
    assert findings[0][2].endswith("[req.query[\"returnUrl\"] -> redirect]"), findings


def _selftest_validation_context_suppression() -> None:
    code = (
        "func localOnly(req: Request) throws -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    guard let url = URL(string: target), url.scheme == \"https\", url.host == \"app.example.com\" else {\n"
        "        throw Abort(.badRequest)\n"
        "    }\n"
        "    return req.redirect(to: url.absoluteString)\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_unproven_allowlist_remains_unsafe() -> None:
    code = (
        "func localOnly(req: Request) throws -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    guard let url = URL(string: target), let host = url.host, allowedHosts.contains(host) else {\n"
        "        throw Abort(.badRequest)\n"
        "    }\n"
        "    return req.redirect(to: target)\n"
        "}\n"
    )
    findings = scan_text(Path("F.swift"), code, Path("."))
    assert len(findings) == 1 and findings[0][1] == 6, findings


def _selftest_ubs_ignore_suppression() -> None:
    code = (
        "func queryRedirect(req: Request) -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    return req.redirect(to: target) // ubs:ignore\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_run(tmp_prefix: str = "ubs_core_taint_swift_redirect_") -> None:
    import tempfile

    code = (
        "func queryRedirect(req: Request) -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    return req.redirect(to: target)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "F.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.taint.request_open_redirect", findings
    assert findings[0]["line"] == 3, findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_query_redirect", _selftest_detects_query_redirect),
    ("validation_context_suppression", _selftest_validation_context_suppression),
    ("unproven_allowlist_remains_unsafe", _selftest_unproven_allowlist_remains_unsafe),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("run_finds_redirect", _selftest_run),
)

register(Analyzer(layer="taint", lang="swift", name="taint_swift_redirect", run=run, selftests=SELF_TESTS))
