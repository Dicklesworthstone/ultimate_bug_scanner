#!/usr/bin/env python3
"""ubs accepts any Python >= 3.9 (python_is_3 in ubs), so every ubs_core helper
must import there. macOS still ships /usr/bin/python3 = 3.9: a 3.10-only runtime
construct (e.g. a `X | Y` type alias, which `from __future__ import annotations`
does not defer) makes every Python scan fail with an environment error.

Two checks: every helper parses with the 3.9 grammar (runs everywhere), and every
ubs_core module imports under a real Python < 3.10 when one is installed.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "modules" / "helpers"
UBS = REPO_ROOT / "ubs"
PY_FIXTURES = REPO_ROOT / "test-suite" / "python"

# Reaches code paths a bare import does not: the bisect predecessor proof in
# py_detectors/index_arithmetic walks every binding in scope, and read
# ast.MatchAs at call time (AttributeError on 3.9, so the whole Python module
# reported MODULE_INVALID_JSON).
BISECT_LOOKUP = """
from bisect import bisect_right


def lookup(position):
    offsets = [0, 10, 20]
    cursor = bisect_right(offsets, position)
    return offsets[cursor - 1]


def neighbour(xs, i):
    return xs[i + 1]
"""
FLOOR = (3, 9)

IMPORT_ALL = r"""
import importlib, pathlib, sys, traceback
bad = []
for p in sorted(pathlib.Path('ubs_core').rglob('*.py')):
    if '__pycache__' in p.parts or p.stem == '__main__':
        continue
    parts = p.with_suffix('').parts
    mod = '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)
    try:
        importlib.import_module(mod)
    except Exception as exc:
        tb = traceback.extract_tb(exc.__traceback__)[-1]
        bad.append(f'{mod}: {type(exc).__name__}: {exc} ({tb.filename}:{tb.lineno})')
print('\n'.join(bad))
sys.exit(1 if bad else 0)
"""


def old_python() -> str | None:
    """A Python interpreter at the supported floor (>= 3.9, < 3.10), if any."""
    for cand in ("python3.9", "/usr/bin/python3"):
        exe = shutil.which(cand) or (cand if Path(cand).is_file() else None)
        if not exe:
            continue
        try:
            out = subprocess.run(
                [exe, "-c", "import sys; print(*sys.version_info[:2])"],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        try:
            ver = tuple(int(x) for x in out.stdout.split())
        except ValueError:
            continue
        if out.returncode == 0 and FLOOR <= ver < (3, 10):
            return exe
    return None


class HelperPythonFloor(unittest.TestCase):
    def test_helpers_parse_with_python_39_grammar(self) -> None:
        failures = []
        for path in sorted(HELPERS.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            try:
                ast.parse(path.read_text(encoding="utf-8"), str(path), feature_version=FLOOR)
            except SyntaxError as exc:
                failures.append(f"{path.relative_to(REPO_ROOT)}:{exc.lineno}: {exc.msg}")
        self.assertEqual(failures, [])

    def test_ubs_core_imports_on_python_39(self) -> None:
        exe = old_python()
        if exe is None:
            self.skipTest("no Python 3.9 interpreter installed")
        proc = subprocess.run(
            [exe, "-B", "-c", IMPORT_ALL], cwd=HELPERS,
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_python_scan_runs_on_python_39(self) -> None:
        """The real entry path: `ubs --only=python` with python3 = 3.9 on PATH."""
        exe = old_python()
        if exe is None:
            self.skipTest("no Python 3.9 interpreter installed")
        with tempfile.TemporaryDirectory(prefix="ubs_py39_") as tmp:
            shim = Path(tmp) / "bin"
            shim.mkdir()
            (shim / "python3").symlink_to(exe)
            project = Path(tmp) / "project"
            shutil.copytree(PY_FIXTURES, project, ignore=shutil.ignore_patterns("__pycache__"))
            (project / "bisect_lookup.py").write_text(textwrap.dedent(BISECT_LOOKUP), encoding="utf-8")
            env = os.environ.copy()
            env.update({
                "PATH": f"{shim}{os.pathsep}{env.get('PATH', '')}",
                "NO_COLOR": "1", "UBS_NO_AUTO_UPDATE": "1", "UBS_SKIP_SIZE_CHECK": "1",
            })
            # Fixed argv built from the fixture paths above.
            proc = subprocess.run(  # ubs:ignore[python.taint.command]
                [str(UBS), "--only=python", "--format=json", str(project)],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=600, check=False,
            )
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            self.fail(f"not JSON (exit {proc.returncode}): {proc.stdout[-2000:]}{proc.stderr[-2000:]}")
        self.assertEqual(report.get("failed_modules"), [], proc.stderr[-4000:])
        self.assertEqual(report.get("status"), "ok", proc.stderr[-4000:])


if __name__ == "__main__":
    unittest.main()
