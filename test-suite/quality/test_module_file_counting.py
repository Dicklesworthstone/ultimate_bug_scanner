#!/usr/bin/env python3
"""Regression tests for the NUL-delimited file counter used by shell modules.

Issue #81: safe_count_files() counted the NUL separators emitted by
``find -print0`` with awk's ``gsub(/\\0/, "")``. busybox awk terminates strings
at the first NUL, so that expression resolves to 0 and the scan reported zero
scanned files - which aborts the manifest case before it reaches any finding
assertion. The counter must not depend on awk's NUL handling at all.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULES_WITH_COUNTER = ("modules/ubs-elixir.sh", "modules/ubs-ruby.sh")


def extract_safe_count_files(module_path: Path) -> str:
    for line in module_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("safe_count_files()"):
            return line
    raise AssertionError(f"safe_count_files() definition not found in {module_path}")


class SafeCountFilesTest(unittest.TestCase):
    def test_counts_nul_delimited_paths_without_awk(self) -> None:
        """The counter must survive an awk that cannot report NUL bytes.

        Stubbing awk out entirely is a stricter stand-in for busybox awk: if the
        count still depends on awk in any way the assertion below fails, exactly
        as it did before the fix.
        """
        stub_dir = Path(tempfile.mkdtemp(prefix="ubs-awk-stub-"))
        try:
            stub = stub_dir / "awk"
            stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"

            for rel in MODULES_WITH_COUNTER:
                with self.subTest(module=rel):
                    definition = extract_safe_count_files(REPO_ROOT / rel)
                    script = f"{definition}\nsafe_count_files\n"
                    result = subprocess.run(
                        ["bash", "-c", script],
                        input=b"one.ex\0two.ex\0three.ex\0",
                        capture_output=True,
                        env=env,
                        check=False,
                    )
                    self.assertEqual(
                        result.stdout.decode("utf-8", "replace").strip(),
                        "3",
                        f"{rel}: safe_count_files must count NUL-delimited paths "
                        f"without awk (stderr: {result.stderr!r})",
                    )
        finally:
            shutil.rmtree(stub_dir, ignore_errors=True)

    def test_counts_zero_for_empty_input(self) -> None:
        for rel in MODULES_WITH_COUNTER:
            with self.subTest(module=rel):
                definition = extract_safe_count_files(REPO_ROOT / rel)
                result = subprocess.run(
                    ["bash", "-c", f"{definition}\nsafe_count_files\n"],
                    input=b"",
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.stdout.decode("utf-8", "replace").strip(), "0")


if __name__ == "__main__":
    unittest.main()
