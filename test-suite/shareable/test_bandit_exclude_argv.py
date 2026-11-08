#!/usr/bin/env python3
"""Regression test for issue #203.

The Python module built bandit's ``-x`` exclusion by expanding every
``.ubsignore`` glob into one path per matched file and passing the
comma-joined list as a single ``execve`` argument. Once that argument crossed
Linux's ``MAX_ARG_STRLEN`` (128 KiB) the launch failed ``E2BIG`` before bandit
started, and the whole scan was reported ``partial -- python: error`` (exit 2),
so a project with a broad ``.ubsignore`` (e.g. ``artifacts/**`` over a large
generated tree) produced no Python result at all.

The fix passes bandit one ``-x`` entry per pattern -- the directory for a
``dir/**`` / ``dir/*`` pattern (bandit's ``-x`` excludes a directory
recursively), otherwise the glob itself -- so the argument stays small while
the exclusion still holds.

This drives the real ``ubs`` meta-runner (focr's ``ubs .`` flow, which reads
``.ubsignore``) on a project whose ignore glob matches well over 128 KiB of
paths, and asserts both sides of the fix:

  (i)  the Python module completes -- no ``Argument list too long``, no
       ``python: error`` partial, exit code is not 2, and bandit actually ran;
  (ii) a bandit-flaggable file placed *inside* the excluded ``artifacts/`` is
       NOT reported (the exclusion still works), while an identical file
       *outside* it IS reported (the scan really ran).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"
ENV_BASE = {
    "NO_COLOR": "1",
    "UBS_ENABLE_AUTO_UPDATE": "0",
    "UBS_NO_AUTO_UPDATE": "1",
}
# The slow part is a cold bandit run via uv; 600s fires on a hang, not a busy
# host, and UBS_TEST_CHILD_TIMEOUT raises it further.
CHILD_TIMEOUT_SECONDS = int(os.environ.get("UBS_TEST_CHILD_TIMEOUT", "600"))

# Enough long-named files that the comma-joined absolute paths of a naive
# per-file ``-x`` expansion exceed MAX_ARG_STRLEN (128 KiB) by a wide margin
# (~2500 * ~120 bytes ~= 300 KiB); the pre-fix code failed E2BIG here.
FILLER_COUNT = 2500
FILLER_STEM = "generated_padding_file_with_a_deliberately_long_name_"

# subprocess.call(..., shell=True): bandit B602, and py.security.shell-true.
FLAGGABLE = (
    "import subprocess\n\n\n"
    "def run():\n"
    '    subprocess.call("ls -la", shell=True)\n'
)


class BanditExcludeArgvTest(unittest.TestCase):
    def test_large_ubsignore_glob_does_not_overflow_bandit_argv(self) -> None:
        if shutil.which("uv") is None:
            self.skipTest("uv is required to run the python module's bandit stage")

        proj = Path(tempfile.mkdtemp(prefix="ubs-203-"))
        try:
            (proj / "app.py").write_text(FLAGGABLE, encoding="utf-8")
            artifacts = proj / "artifacts"
            artifacts.mkdir()
            (artifacts / "secret_sink.py").write_text(FLAGGABLE, encoding="utf-8")
            for i in range(FILLER_COUNT):
                (artifacts / f"{FILLER_STEM}{i}.py").write_text("", encoding="utf-8")
            (proj / ".ubsignore").write_text("artifacts/**\n", encoding="utf-8")

            proc = subprocess.run(
                [str(UBS_BIN), "--only=python", str(proj)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, **ENV_BASE},
                check=False,
                timeout=CHILD_TIMEOUT_SECONDS,
            )
            out = proc.stdout + proc.stderr

            # (i) the module must not overflow bandit's argv and must complete.
            self.assertNotIn(
                "Argument list too long", out,
                msg=f"bandit -x argv overflowed MAX_ARG_STRLEN (E2BIG).\n{out}",
            )
            self.assertNotIn(
                "python: error", out,
                msg=f"python module reported a partial/error run.\n{out}",
            )
            self.assertNotIn(
                "Bandit did not complete", out,
                msg=f"bandit failed to launch (the #203 symptom).\n{out}",
            )
            self.assertNotEqual(
                proc.returncode, 2,
                msg=f"exit 2 = partial scan; not every language was scanned.\n{out}",
            )
            # bandit actually executed (not merely skipped as unavailable).
            self.assertTrue(
                ("Bandit scan completed" in out) or ("bandit.readthedocs.io" in out),
                msg=f"bandit stage did not run to completion.\n{out}",
            )

            # (ii) the flaggable file OUTSIDE artifacts/ is reported ...
            self.assertIn(
                "app.py", out,
                msg=f"the file outside the exclusion was not scanned/reported.\n{out}",
            )
            # ... and the one INSIDE the excluded artifacts/ is not.
            self.assertNotIn(
                "secret_sink.py", out,
                msg=f"a file inside the excluded artifacts/ was reported; the "
                    f"exclusion regressed.\n{out}",
            )
        finally:
            shutil.rmtree(proj, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
