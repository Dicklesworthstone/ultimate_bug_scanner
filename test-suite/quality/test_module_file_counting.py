#!/usr/bin/env python3
"""Regression tests for shell file admission and NUL-delimited file counting.

Issue #81: safe_count_files() counted the NUL separators emitted by
``find -print0`` with awk's ``gsub(/\\0/, "")``. busybox awk terminates strings
at the first NUL, so that expression resolves to 0 and the scan reported zero
scanned files - which aborts the manifest case before it reaches any finding
assertion. The counter must not depend on awk's NUL handling at all.
"""
from __future__ import annotations

import json
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
                    result = subprocess.run(  # ubs:ignore[py.security.command-injection] Fixed repo module definition; no external input.
                        ["bash", "-c", script],
                        input=b"one.ex\0two.ex\0three.ex\0",
                        capture_output=True,
                        env=env,
                        check=False,
                        timeout=30,
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
                result = subprocess.run(  # ubs:ignore[py.security.command-injection] Fixed repo module definition; no external input.
                    ["bash", "-c", f"{definition}\nsafe_count_files\n"],
                    input=b"",
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.stdout.decode("utf-8", "replace").strip(), "0")


class ExtensionlessShellAdmissionTest(unittest.TestCase):
    def _check_extensionless_shell_admission(self, *, mode: str) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-shell-admission-") as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            shell_scripts = {
                "env-bash": "#!/usr/bin/env bash",
                "env-sh": "#!/usr/bin/env sh",
                "env-split-bash": "#!/usr/bin/env -S bash -e",
                "direct-bash": "#!/bin/bash",
            }
            contents = {
                name: shebang + '\ncommand="${1:-}"\neval "$command"\n'
                for name, shebang in shell_scripts.items()
            }
            contents.update({
                "python-script": '#!/usr/bin/env python3\nprint("hello")\n',
                "ordinary-text": 'Shell documentation example:\neval "$command"\n',
                # The interpreter is Python; /bash is only an argument. Its
                # string literal must not be treated as executable shell code.
                "misleading-argument": (
                    '#!/usr/bin/env python3 /bash\n'
                    'example = """\neval "$command"\n"""\n'
                ),
            })
            for name, content in contents.items():
                path = project / name
                path.write_text(content, encoding="utf-8")
                path.chmod(0o755)

            if mode != "directory":
                (project / "unrequested-script").write_text(
                    '#!/usr/bin/env bash\ncommand="${1:-}"\neval "$command"\n',
                    encoding="utf-8",
                )
            if mode == "files":
                # Explicit paths must remain admitted even when a project
                # ignore pattern would omit them from a directory scan.
                (project / ".ubsignore").write_text("env-bash\n", encoding="utf-8")
                targets = [str(project / name) for name in contents]
            elif mode == "staged":
                for command in (
                    ["git", "init", "--initial-branch=main", str(project)],
                    ["git", "-C", str(project), "add", "--", *contents],
                ):
                    setup = subprocess.run(
                        command, cwd=project, capture_output=True, text=True,
                        check=False, timeout=30,
                    )
                    self.assertEqual(
                        setup.returncode, 0,
                        f"{command!r}\nstdout:\n{setup.stdout}\nstderr:\n{setup.stderr}",
                    )
                targets = ["--staged", str(project)]
            else:
                targets = [str(project)]
            result = subprocess.run(
                ["bash", str(REPO_ROOT / "ubs"), "--only=bash", "--format=json",
                 "--ci", "--no-cache", "--no-auto-update", *targets],
                cwd=project,
                env={**os.environ, "NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"},
                capture_output=True,
                text=True,
                check=False,
                timeout=180,
            )
            context = (f"mode={mode}, exit={result.returncode}\n"
                       f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
            self.assertEqual(result.returncode, 1, context)
            try:
                document = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AssertionError(f"Scanner stdout is not JSON: {exc}\n{context}") from exc

            self.assertEqual(document["status"], "ok", context)
            self.assertFalse(document.get("failed_modules"), context)
            self.assertEqual(document["totals"]["files"], 4, context)
            self.assertEqual(len(document["scanners"]), 1, context)
            scanner = document["scanners"][0]
            self.assertEqual(scanner["language"], "bash", context)
            self.assertEqual(scanner["files"], 4, context)

            self.assertIn("findings", document, context)
            findings = document["findings"]
            self.assertTrue(
                all(Path(finding["file"]).name in shell_scripts for finding in findings),
                context,
            )
            eval_locations = []
            for finding in findings:
                if finding["rule_id"] != "bash.security.eval_variable":
                    continue
                source = Path(finding["file"])
                if not source.is_absolute():
                    source = project / source
                eval_locations.append((source.resolve(), finding["line"]))
            self.assertCountEqual(
                eval_locations,
                [((project / name).resolve(), 3) for name in shell_scripts],
                context,
            )

    def test_directory_scan_admits_extensionless_shell_interpreters(self) -> None:
        self._check_extensionless_shell_admission(mode="directory")

    def test_explicit_file_scan_admits_extensionless_shell_interpreters(self) -> None:
        self._check_extensionless_shell_admission(mode="files")

    def test_staged_scan_admits_only_selected_extensionless_shell_scripts(self) -> None:
        self._check_extensionless_shell_admission(mode="staged")


if __name__ == "__main__":
    unittest.main()
