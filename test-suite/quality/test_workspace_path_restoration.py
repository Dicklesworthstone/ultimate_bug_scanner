#!/usr/bin/env python3
"""Findings from a multi-file scan name the files the user passed.

`ubs a.py b.py` scans a shadow workspace under TMPDIR and rewrites workspace
paths back to the originals. When TMPDIR sits behind a symlink (macOS: /var
and /tmp point into /private), modules that resolve paths name the workspace
by its real path; rewriting only the unresolved spelling produced
/private/private/... for every finding. A symlinked TMPDIR reproduces that on
any platform.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class WorkspacePathRestorationTests(unittest.TestCase):
    def test_multi_file_findings_survive_a_symlinked_tmpdir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-ws-paths-") as tmp:
            base = Path(tmp).resolve()
            real_tmp = base / "real-tmp"
            real_tmp.mkdir()
            linked_tmp = base / "linked-tmp"
            linked_tmp.symlink_to(real_tmp, target_is_directory=True)
            project = base / "project"
            project.mkdir()
            files = [project / "a.py", project / "b.py"]
            for path in files:
                path.write_text("value = eval(input())\n", encoding="utf-8")
            env = {**os.environ, "TMPDIR": str(linked_tmp), "UBS_NO_AUTO_UPDATE": "1",
                   "UBS_NO_CACHE": "1", "NO_COLOR": "1"}
            result = subprocess.run(
                [str(ROOT / "ubs"), *map(str, files), "--only=python", "--format=json", "--ci"],
                cwd=project, capture_output=True, text=True, env=env, timeout=300,
            )
            self.assertIn(result.returncode, (0, 1), result.stderr)
            report = json.loads(result.stdout)
            reported = {finding["file"] for finding in report.get("findings", [])}
            self.assertTrue(reported, result.stdout)
            self.assertLessEqual(reported, {str(path) for path in files}, reported)
            for scanner in report["scanners"]:
                for finding in scanner["findings"]:
                    location = finding.get("path") or finding.get("file")
                    if location:
                        self.assertTrue(Path(location).is_file(), finding)


if __name__ == "__main__":
    unittest.main()
