"""Elixir redirect policy over the shared scoped request-flow engine.

Retains the public rule and legacy report dialect, with exact-value URL
validation and structured source/call/sink evidence. Helper names, neighboring
checks, atoms, comments and strings are never validation evidence.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.analyzers.taint_elixir_traversal import flow_findings

ROOT: Path = Path()
BASE_DIR: Path = Path()



SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def scan_file_findings(path: Path):
    for line, col, code, _extras in flow_findings(path, 'redirect'):
        yield line, col, code


def analyze(path, issues):
    """Heredoc aggregation: collect one (relpath, line, code) tuple per finding."""
    for idx, _col, code in scan_file_findings(path):
        issues.append((relpath(path), idx, code))


def main(argv=None) -> int:
    """Byte-parity entrypoint: same behavior as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    global ROOT, BASE_DIR
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:5]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        resolved = path.resolve()
        for line_no, col, code, extras in flow_findings(path, 'redirect'):
            yield {
                "rule": "elixir.taint.open_redirect",
                "path": str(resolved),
                "line": line_no,
                "col": col,
                "layer": "taint",
                "lang": "elixir",
                "severity": "critical",
                "message": f"{_MESSAGE} ({code})",
                "extras": extras,
            }


def _selftest_direct_redirect(tmp_prefix: str = "ubs_core_taint_elixir_redir_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "redirect_to.ex"
        target.write_text(
            "def redirect_to(conn, params) do\n"
            "  target = params[\"url\"]\n"
            "  redirect(conn, external: target)\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "elixir.taint.open_redirect", findings
    assert findings[0]["line"] == 3, findings
    assert findings[0]["col"] == 3, findings
    assert findings[0]["severity"] == "critical", findings
    assert "params[ -> redirect" in findings[0]["message"], findings


def _selftest_local_path_validation_suppression(tmp_prefix: str = "ubs_core_taint_elixir_redir_local_") -> None:
    import tempfile

    code = (
        "def redirect_to(conn, params) do\n"
        "  target = params[\"url\"]\n"
        "  unless String.starts_with?(target, \"/\") and not String.starts_with?(target, \"//\") and not String.contains?(target, [\"\\\\\", \"\\n\", \"\\r\", \"\\t\"]) do\n"
        "    raise \"untrusted redirect\"\n"
        "  end\n"
        "  redirect(conn, external: target)\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe_redirect.ex"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert findings == [], findings


def _selftest_ignore_comment_suppression(tmp_prefix: str = "ubs_core_taint_elixir_redir_ign_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ex"
        target.write_text(
            "# ubs:ignore\n"
            "target = params[\"url\"]\n"
            "redirect(conn, external: target)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    # Suppressing the assignment must not erase the value at a later sink.
    assert len(findings) == 1 and findings[0]["line"] == 3, findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_elixir_redir_main_") -> None:
    import tempfile
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "redirect_to.ex"
        target.write_text(
            "def redirect_to(conn, params) do\n"
            "  target = params[\"url\"]\n"
            "  redirect(conn, external: target)\n"
            "end\n",
            encoding="utf-8",
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main(["x", tmp])
        assert rc == 0
        out = buffer.getvalue()
    assert out == (
        "__COUNT__\t1\n"
        "__SAMPLE__\tredirect_to.ex\t3\tredirect(conn, external: target)  [params[ -> redirect]\n"
    ), repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_redirect", _selftest_direct_redirect),
    ("local_path_validation_suppression", _selftest_local_path_validation_suppression),
    ("ignore_comment_suppression", _selftest_ignore_comment_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="elixir", name="taint_elixir_redirect", run=run, selftests=SELF_TESTS))
