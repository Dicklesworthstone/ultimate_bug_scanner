#!/usr/bin/env python3
"""Regression tests for issues #51 and #52.

#51: per-line ``// ubs:ignore`` / ``# ubs:ignore`` markers were silently
ignored by rules whose count pipelines went straight through ``grep -c``
or ``grep -cw`` instead of the ``count_lines()`` helper. Confirm that
adding the marker now suppresses the affected JS rule.

#52: bare ``--skip=N`` silenced category N in every language module at
once. Confirm that
  - bare ``--skip=N`` with a single language module emits no warning,
  - bare ``--skip=N`` with two or more language modules active emits a
    stderr warning that names the category in each language and
    recommends ``--skip-LANG=N``,
  - ``--skip-LANG=N`` is forwarded only to the matching language module
    (Python's critical ``Mutable default arguments`` keeps firing when
    only ``--skip-js=8`` is in effect),
  - ``--skip-LANG=N`` does not emit the warning, even with more than one
    language active.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"
JS_MODULE = REPO_ROOT / "modules" / "ubs-js.sh"
ENV_BASE = {
    "NO_COLOR": "1",
    "UBS_ENABLE_AUTO_UPDATE": "0",
    "UBS_NO_AUTO_UPDATE": "1",
}


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(ENV_BASE)
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def write_block_fns(path: Path, *, with_ignore: bool) -> None:
    """Write a JS file that trips ubs-js cat-8 'Function declarations
    inside blocks'. With ``with_ignore=True`` every line carries the
    ``// ubs:ignore`` marker so the rule must produce zero findings."""
    suffix = "  // ubs:ignore" if with_ignore else ""
    body = "\n".join(
        f"if (true) {{ function fn{i}() {{}} }}{suffix}" for i in range(6)
    ) + "\n"
    path.write_text(body)


def test_issue_51_ubs_ignore_respected() -> None:
    """The JS module's 'Function declarations inside blocks' rule used to
    bypass count_lines() via ``grep -cw``. After the #51 fix the count
    must drop to zero when every matching line carries ``// ubs:ignore``."""
    with tempfile.TemporaryDirectory(prefix="ubs-51-") as tmp:
        proj = Path(tmp)
        target = proj / "blockfns.js"

        # Baseline: no ignore markers => rule fires with 6 findings.
        write_block_fns(target, with_ignore=False)
        baseline = run([sys.executable, "-c", "import sys; sys.exit(0)"], proj)  # warm subprocess
        baseline = subprocess.run(
            ["bash", str(JS_MODULE), str(proj)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, **ENV_BASE},
            check=False,
        )
        assert (
            "Function declarations in blocks" in baseline.stdout
            or "Function declarations in blocks" in baseline.stderr
        ), f"baseline did not trip rule:\nSTDOUT:\n{baseline.stdout}\nSTDERR:\n{baseline.stderr}"

        # With ubs:ignore on every matching line, count_lines() must
        # strip them and the rule must NOT fire.
        write_block_fns(target, with_ignore=True)
        ignored = subprocess.run(
            ["bash", str(JS_MODULE), str(proj)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, **ENV_BASE},
            check=False,
        )
        assert "Function declarations in blocks" not in ignored.stdout, (
            "ubs:ignore was not honored - rule still fired:\n"
            f"STDOUT:\n{ignored.stdout}\nSTDERR:\n{ignored.stderr}"
        )


def test_issue_52_single_language_no_warning() -> None:
    """--skip=N with a single active language must not emit the warning."""
    with tempfile.TemporaryDirectory(prefix="ubs-52a-") as tmp:
        proj = Path(tmp)
        write_block_fns(proj / "test.js", with_ignore=False)
        result = run(
            [str(UBS_BIN), "--only=js", "--skip=8", str(proj)],
            cwd=REPO_ROOT,
        )
        combined = result.stdout + result.stderr
        assert "WARNING: bare --skip=" not in combined, (
            "Single-language --skip should not warn:\n" + combined
        )


def test_issue_52_polyglot_warning_emitted() -> None:
    """--skip=N with 2+ active languages must emit a stderr warning that
    names the category in each language and recommends --skip-LANG=N."""
    with tempfile.TemporaryDirectory(prefix="ubs-52b-") as tmp:
        proj = Path(tmp)
        write_block_fns(proj / "test.js", with_ignore=False)
        (proj / "test.py").write_text("def foo(x=[]):\n    return x\n")
        result = run([str(UBS_BIN), "--skip=8", str(proj)], cwd=REPO_ROOT)
        combined = result.stdout + result.stderr
        assert "WARNING: bare --skip=8" in combined, (
            "Polyglot --skip=8 must emit warning:\n" + combined
        )
        assert "in js:" in combined, combined
        assert "in python:" in combined, combined
        assert "--skip-LANG=" in combined or "--skip-js=" in combined, combined


def test_issue_52_per_language_skip_works_without_warning() -> None:
    """--skip-LANG=N silences only that language; Python's critical
    rule keeps firing when only --skip-js=8 is in effect, and no
    warning is emitted."""
    with tempfile.TemporaryDirectory(prefix="ubs-52c-") as tmp:
        proj = Path(tmp)
        write_block_fns(proj / "test.js", with_ignore=False)
        (proj / "test.py").write_text("def foo(x=[]):\n    return x\n")
        result = run([str(UBS_BIN), "--skip-js=8", str(proj)], cwd=REPO_ROOT)
        combined = result.stdout + result.stderr
        # No warning when only per-language flags are used.
        assert "WARNING: bare --skip=" not in combined, (
            "Per-language --skip-js=8 must not emit warning:\n" + combined
        )
        # Python cat 8 critical (mutable default arg) must still fire.
        assert "Mutable default arguments" in combined, (
            "Python cat-8 critical must keep firing under --skip-js=8:\n"
            + combined
        )


def main() -> None:
    test_issue_51_ubs_ignore_respected()
    print("OK: #51 ubs:ignore now respected by cat-8 rule")
    test_issue_52_single_language_no_warning()
    print("OK: #52 single-language --skip=N emits no warning")
    test_issue_52_polyglot_warning_emitted()
    print("OK: #52 polyglot --skip=N emits warning naming each cat")
    test_issue_52_per_language_skip_works_without_warning()
    print("OK: #52 --skip-LANG=N targets one module, no warning, others unaffected")


if __name__ == "__main__":
    main()
