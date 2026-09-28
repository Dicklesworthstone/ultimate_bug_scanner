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
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "modules" / "helpers"
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


if __name__ == "__main__":
    unittest.main()
