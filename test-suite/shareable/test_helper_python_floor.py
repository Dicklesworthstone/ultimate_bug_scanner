#!/usr/bin/env python3
"""Exercise the shipped helper floor, not the development environment's Python.

The grammar check runs everywhere. CI must install real Python 3.9 and set
UBS_REQUIRE_PYTHON39=1; a missing floor interpreter is then a failure, not a
skip. The current-runtime checks also run on newer Python to retain slots and
exercise the same interpreter-selection, doctor and scan contract there.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "modules" / "helpers"
UBS = REPO_ROOT / "ubs"
PY_FIXTURES = REPO_ROOT / "test-suite" / "python"
FLOOR = (3, 9)

# Reaches the bisect predecessor proof, where an unguarded ast.MatchAs once
# raised AttributeError on 3.9 despite successful imports.
BISECT_LOOKUP = """
from bisect import bisect_right


def lookup(position):
    offsets = [0, 10, 20]
    cursor = bisect_right(offsets, position)
    return offsets[cursor - 1]


def neighbour(xs, i):
    return xs[i + 1]
"""

# Compile *and execute imports*: grammar alone accepts runtime type aliases
# and dataclass keyword arguments that fail on an older interpreter.
IMPORT_ALL = r"""
import importlib, json, pathlib, sys, traceback
bad = []
paths = sorted(pathlib.Path('.').rglob('*.py'))
assert paths, 'no shipped helpers discovered'
compiled = imported = 0
for p in paths:
    if '__pycache__' in p.parts:
        continue
    try:
        compile(p.read_bytes(), str(p), 'exec')
        compiled += 1
        if p.stem == '__main__':
            continue  # CLI entry points are exercised by the real scans below.
        parts = p.with_suffix('').parts
        mod = '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)
        importlib.import_module(mod)
        imported += 1
    except Exception as exc:
        tb = traceback.extract_tb(exc.__traceback__)[-1]
        bad.append(f'{p}: {type(exc).__name__}: {exc} ({tb.filename}:{tb.lineno})')
print(json.dumps({'python': sys.version, 'compiled': compiled, 'imported': imported,
                  'failures': bad}, indent=2))
sys.exit(1 if bad else 0)
"""

DATACLASS_CONTRACT = r"""
from copy import deepcopy
from dataclasses import fields, replace
import sys
from ubs_core.analyzers.taint_js import _Statement, _HeapOutput
statement = _Statement('block', 1, 7)
assert statement == _Statement('block', 1, 7)
assert statement.body == statement.alternate == statement.catch_names == ()
assert statement.extra is None and statement.catch_range is None
assert replace(statement, end=9).end == 9 and statement.end == 7
assert deepcopy(statement) == statement
statement.end = 8
assert statement.end == 8
output = _HeapOutput({'a': {'value': 1}}, {'a'}, {'a': 1})
copy = deepcopy(output)
assert copy == output and copy.heap is not output.heap
copy.heap['a']['value'] = 2
assert output.heap['a']['value'] == 1
assert replace(output, weak_refs=set()).weak_refs == set()
for value in (statement, output):
    slotted = sys.version_info >= (3, 10)
    assert hasattr(type(value), '__slots__') == slotted
    assert hasattr(value, '__dict__') != slotted
    if slotted:
        assert tuple(type(value).__slots__) == tuple(f.name for f in fields(value))
print('dataclass defaults, equality, mutation, replace, deepcopy and slots: OK')
"""


def old_python() -> str | None:
    """Find real 3.9; an explicitly required/misconfigured runtime must fail."""
    explicit = os.environ.get("UBS_TEST_PYTHON39")
    candidates = (explicit,) if explicit else (sys.executable, "python3.9", "/usr/bin/python3")
    for cand in candidates:
        exe = shutil.which(cand) or (cand if Path(cand).is_file() else None)
        if not exe:
            continue
        try:
            # The caller deliberately selects a trusted test interpreter;
            # fixture contents never influence this executable or fixed argv.
            out = subprocess.run(  # ubs:ignore[python.taint.command,py.security.command-injection] trusted test interpreter
                [exe, "-c", "import sys; print(*sys.version_info[:2])"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            ver = tuple(int(x) for x in out.stdout.split())
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        if out.returncode == 0 and ver == FLOOR:
            return exe
    if explicit or os.environ.get("UBS_REQUIRE_PYTHON39") == "1":
        raise RuntimeError("a real Python 3.9 is required; set UBS_TEST_PYTHON39 to its executable")
    return None


def clean_env(scratch: Path) -> dict:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("UBS_") and key not in ("PYTHONPATH", "PYTHONHOME")}
    env.update({
        "HOME": str(scratch), "XDG_CACHE_HOME": str(scratch / "cache"),
        "XDG_CONFIG_HOME": str(scratch / "config"), "NO_COLOR": "1",
        "UBS_NO_AUTO_UPDATE": "1", "UBS_SKIP_SIZE_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


class HelperPythonFloor(unittest.TestCase):
    def test_helpers_parse_with_python_39_grammar(self) -> None:
        failures = []
        paths = sorted(HELPERS.rglob("*.py"))
        self.assertTrue(paths, "no shipped helpers discovered")
        for path in paths:
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
        proc = subprocess.run(  # ubs:ignore[python.taint.command] trusted version-checked test interpreter
            [exe, "-B", "-S", "-c", IMPORT_ALL], cwd=HELPERS,
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        print(proc.stdout, flush=True)

    def test_python_scan_runs_on_python_39(self) -> None:
        """Keep the broad Python fixture scan, including call-time AST APIs."""
        exe = old_python()
        if exe is None:
            self.skipTest("no Python 3.9 interpreter installed")
        with tempfile.TemporaryDirectory(prefix="ubs_py39_") as tmp:
            scratch = Path(tmp)
            shim = scratch / "bin"
            shim.mkdir()
            (shim / "python3").symlink_to(exe)
            project = scratch / "project"
            shutil.copytree(PY_FIXTURES, project, ignore=shutil.ignore_patterns("__pycache__"))
            (project / "bisect_lookup.py").write_text(textwrap.dedent(BISECT_LOOKUP), encoding="utf-8")
            env = clean_env(scratch)
            env["PATH"] = f"{shim}{os.pathsep}{env.get('PATH', '')}"
            proc = subprocess.run(  # ubs:ignore[python.taint.command] fixed fixture argv
                [str(UBS), "--only=python", "--format=json", str(project)],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=600, check=False,
            )
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            self.fail(f"not JSON (exit {proc.returncode}): {proc.stdout[-2000:]}{proc.stderr[-2000:]}")
        self.assertIn(proc.returncode, (0, 1), proc.stderr[-4000:])
        self.assertEqual(report.get("failed_modules"), [], proc.stderr[-4000:])
        self.assertEqual(report.get("status"), "ok", proc.stderr[-4000:])
        self.assertGreater(report["totals"]["critical"], 0, report)


class HelperCurrentRuntime(unittest.TestCase):
    def test_expected_interpreter_is_really_running(self) -> None:
        self.assertGreaterEqual(sys.version_info[:2], FLOOR)
        expected = os.environ.get("UBS_TEST_EXPECT_PYTHON")
        if expected:
            self.assertEqual("%d.%d" % sys.version_info[:2], expected)
        print(f"runtime executable: {sys.executable}; version: {sys.version}", flush=True)

    def test_all_helpers_compile_and_import_without_site_packages(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-B", "-S", "-c", IMPORT_ALL], cwd=HELPERS,
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        print(proc.stdout, flush=True)

    def test_taint_dataclass_behavior(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-B", "-S", "-c", DATACLASS_CONTRACT], cwd=HELPERS,
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def check_doctor_and_scans(self, override: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_runtime_") as tmp:
            scratch = Path(tmp)
            shim = scratch / "bin"
            shim.mkdir()
            selected = shim / ("selected-python" if override else "python3")
            selected.symlink_to(sys.executable)
            env = clean_env(scratch)
            env["PATH"] = f"{shim}{os.pathsep}{env.get('PATH', '')}"
            if override:
                env["UBS_PYTHON"] = str(selected)
                # A broken PATH python3 proves UBS_PYTHON wins, rather than a
                # newer system interpreter accidentally making the scan pass.
                decoy = shim / "python3"
                decoy.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                decoy.chmod(0o755)
            doctor = subprocess.run(
                [str(UBS), "doctor"], cwd=tmp, env=env,
                capture_output=True, text=True, timeout=180, check=False,
            )
            detail = doctor.stdout + doctor.stderr
            self.assertEqual(doctor.returncode, 0, detail)
            shim_note = " (via a per-run python3 shim)" if override else ""
            self.assertIn(f"python: ready {selected}{shim_note} Python {sys.version.split()[0]}", detail)
            if override:
                self.assertIn("python3 comes from UBS_PYTHON", detail)
            else:
                self.assertNotIn("python3 comes from UBS_PYTHON", detail)
            for language, filename, clean, buggy in (
                ("python", "sample.py", "VALUE = 42\n", "eval(input())\n"),
                ("js", "sample.js", "export const answer = 42;\n",
                 "const box = {}; box.html = req.query.html; res.send(box.html);\n"),
            ):
                for dirty, source in ((False, clean), (True, buggy)):
                    with self.subTest(override=override, language=language, dirty=dirty):
                        project = scratch / f"{language}-{'buggy' if dirty else 'clean'}"
                        project.mkdir()
                        (project / filename).write_text(source, encoding="utf-8")
                        proc = subprocess.run(  # ubs:ignore[python.taint.command] fixed fixture argv
                            [str(UBS), f"--only={language}", "--format=json", "--ci", str(project)],
                            cwd=tmp, env=env, capture_output=True, text=True, timeout=300, check=False,
                        )
                        detail = proc.stdout + proc.stderr
                        self.assertEqual(proc.returncode, 1 if dirty else 0, detail[-6000:])
                        self.assertNotIn("Traceback (most recent call last)", detail)
                        try:
                            report = json.loads(proc.stdout)
                        except ValueError:
                            self.fail(f"scanner did not emit JSON: {detail[-6000:]}")
                        self.assertEqual(report.get("status"), "ok", report)
                        self.assertEqual(report.get("failed_modules"), [], report)
                        if dirty:
                            self.assertGreater(report["totals"]["critical"], 0, report)
                        else:
                            self.assertEqual(report["totals"]["critical"], 0, report)

    def test_path_interpreter_doctor_and_real_scans_agree(self) -> None:
        self.check_doctor_and_scans(override=False)

    def test_explicit_interpreter_doctor_and_real_scans_agree(self) -> None:
        self.check_doctor_and_scans(override=True)


if __name__ == "__main__":
    unittest.main()
