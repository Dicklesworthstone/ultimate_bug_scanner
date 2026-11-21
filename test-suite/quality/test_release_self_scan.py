#!/usr/bin/env python3
"""Release self-scan must fail closed before any version, commit or tag changes.

The release script and self-scan validator are real. Scanner behavior is
controlled so release failures can be exercised without running the entire
multi-language suite or publishing anything. Candidate integration cases also
use the real candidate validator and checksum tools against real Git trees.
"""
from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_self_scan", ROOT / "scripts/check_self_scan.py")
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def clean_report() -> dict:
    # Shape emitted by merge_json_scanners in the production meta-runner.
    return {
        "project": ".", "status": "ok", "failed_modules": [],
        "scanners": [
            {"language": "python", "status": "ok", "files": 3,
             "critical": 0, "warning": 0, "info": 12},
            {"language": "bash", "status": "ok", "files": 2,
             "critical": 0, "warning": 0, "info": 7},
        ],
        "totals": {"files": 5, "critical": 0, "warning": 0, "info": 19},
    }


class ReportTests(unittest.TestCase):
    def test_complete_report_allows_informational_findings(self):
        self.assertEqual(GATE.validate_report(clean_report()), 5)

    def test_rejects_missing_and_incomplete_execution_evidence(self):
        for key in ("status", "failed_modules", "scanners", "totals"):
            report = clean_report()
            del report[key]
            with self.subTest(missing=key), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)
        for status in ("partial", "error", "skipped", "timeout", None):
            for level in ("aggregate", "scanner"):
                report = clean_report()
                target = report if level == "aggregate" else report["scanners"][0]
                target["status"] = status
                with self.subTest(status=status, level=level), self.assertRaises(GATE.SelfScanError):
                    GATE.validate_report(report)
        report = clean_report()
        del report["scanners"][0]["status"]
        with self.assertRaises(GATE.SelfScanError):
            GATE.validate_report(report)

    def test_rejects_failures_even_with_zero_counts_and_ok_status(self):
        for failures in (None, {}, ["python"], [{"language": "python", "status": "partial"}]):
            report = clean_report()
            report["failed_modules"] = failures
            with self.subTest(failures=failures), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)

    def test_rejects_bad_count_types_and_inconsistent_totals(self):
        for key in ("files", "critical", "warning"):
            for value in (True, False, -1, "0", None, 0.0):
                for level in ("totals", "scanner"):
                    report = clean_report()
                    target = report["totals"] if level == "totals" else report["scanners"][0]
                    target[key] = value
                    with self.subTest(key=key, value=value, level=level), self.assertRaises(GATE.SelfScanError):
                        GATE.validate_report(report)
            report = clean_report()
            report["totals"][key] += 1
            with self.subTest(mismatch=key), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)

    def test_rejects_warnings_and_criticals_in_either_accounting_layer(self):
        for key in ("critical", "warning"):
            report = clean_report()
            report["scanners"][0][key] = 1
            with self.subTest(hidden=key), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)
            report["totals"][key] = 1
            with self.subTest(finding=key), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)

    def test_rejects_empty_duplicate_and_malformed_scanners(self):
        for scanners in ([], {}, [None], [{"language": []}],
                         [clean_report()["scanners"][0]] * 2):
            report = clean_report()
            report["scanners"] = scanners
            with self.subTest(scanners=scanners), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)
        for report in (None, [], "ok"):
            with self.subTest(report=report), self.assertRaises(GATE.SelfScanError):
                GATE.validate_report(report)
        report = clean_report()
        report["totals"]["files"] = 0
        for scanner in report["scanners"]:
            scanner["files"] = 0
        with self.assertRaisesRegex(GATE.SelfScanError, "did not scan"):
            GATE.validate_report(report)


class RunnerFailureTests(unittest.TestCase):
    def test_timeout_is_a_release_failure(self):
        error = subprocess.TimeoutExpired(["ubs"], GATE.SELF_SCAN_TIMEOUT_SECONDS)
        with mock.patch.object(GATE.subprocess, "run", side_effect=error), \
                contextlib.redirect_stderr(io.StringIO()) as diagnostic:
            self.assertEqual(GATE.main(), 1)
        self.assertIn("release budget", diagnostic.getvalue())

    def test_missing_scanner_is_a_release_failure(self):
        with mock.patch.object(GATE.subprocess, "run", side_effect=FileNotFoundError("ubs")), \
                contextlib.redirect_stderr(io.StringIO()) as diagnostic:
            self.assertEqual(GATE.main(), 1)
        self.assertIn("could not run self-scan", diagnostic.getvalue())


SCANNER = '''#!/usr/bin/env bash
UBS_VERSION="1.0.0"
if [[ "${1:-}" == --version ]]; then
    echo "UBS v$UBS_VERSION"
    exit 0
fi
exec python3 - "$@" <<'STUB'
import json, os, sys
from pathlib import Path
record = {"argv": sys.argv[1:], "cwd": os.getcwd(), "env": {
    key: os.environ.get(key) for key in (
        "UBS_ALLOW_PARTIAL", "UBS_ALLOW_NO_SCAN", "UBS_NO_AUTO_UPDATE",
        "UBS_ENABLE_AUTO_UPDATE", "UBS_NO_CACHE",
    )
}}
Path(os.environ["CALL_RECORD"]).write_text(json.dumps(record), encoding="utf-8")
sys.stdout.buffer.write(Path(os.environ["SCAN_REPORT"]).read_bytes())
sys.stderr.write("scanner diagnostic retained\\n")
if os.environ.get("MODEL_PARTIAL_EXIT") == "1":
    raise SystemExit(0 if os.environ.get("UBS_ALLOW_PARTIAL") == "1" else 2)
raise SystemExit(int(os.environ.get("SCAN_EXIT", "0")))
STUB
'''


class ReleaseFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ubs-release-gate-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "checkout with spaces"
        (self.repo / "scripts").mkdir(parents=True)
        for name in ("cut-release.sh", "check_self_scan.py"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        (self.repo / "ubs").write_text(SCANNER, encoding="utf-8")
        (self.repo / "ubs").chmod(0o755)
        for name, text in {
            "VERSION": "1.0.0\n", "README.md": "badge/version-1.0.0-blue.svg\n",
            "CHANGELOG.md": "# Changelog\n\n## [Unreleased]\n\nA detector repair.\n",
            "SHA256SUMS": "fixture\n", "install.sh": "#!/usr/bin/env bash\ntrue\n",
        }.items():
            (self.repo / name).write_text(text, encoding="utf-8")
        for name in ("update_checksums.sh", "update_sha256sums.sh",
                     "verify_checksums.sh", "verify_sha256sums.sh"):
            (self.repo / "scripts" / name).write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        self.report_path = self.base / "report.json"
        self.record_path = self.base / "invocation.json"
        self.report_path.write_text(json.dumps(clean_report()), encoding="utf-8")
        self.env = os.environ.copy()
        for key in list(self.env):
            if key.startswith("GIT_"):
                self.env.pop(key)
        self.env.update({
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0", "PYTHONDONTWRITEBYTECODE": "1",
            "UBS_ALLOW_PARTIAL": "1", "UBS_ALLOW_NO_SCAN": "1",
            "UBS_NO_AUTO_UPDATE": "0", "UBS_ENABLE_AUTO_UPDATE": "1", "UBS_NO_CACHE": "0",
            "SCAN_REPORT": str(self.report_path), "CALL_RECORD": str(self.record_path),
            "TMPDIR": str(self.base), "SCAN_EXIT": "0", "MODEL_PARTIAL_EXIT": "0",
        })
        self.prepare_candidate()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "UBS gate test")
        self.git("config", "user.email", "ubs-test@example.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "tag.gpgSign", "false")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.head = self.git("rev-parse", "HEAD")
        self.originals = {p: (self.repo / p).read_bytes()
                          for p in self.git("ls-files").splitlines()}

    def prepare_candidate(self):
        # These cases isolate the JSON self-scan contract. The separate
        # CandidateReleaseTests below exercise the actual candidate validator.
        (self.repo / "scripts/build_release_candidate.py").write_text(
            "raise SystemExit(0)\n", encoding="utf-8",
        )

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, env=self.env, text=True, stderr=subprocess.PIPE,
            timeout=30,
        ).strip()

    def release(self, *args, version="1.0.1"):
        return subprocess.run(
            ["bash", str(self.repo / "scripts/cut-release.sh"), version, *args],
            cwd=self.base, env=self.env, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=30,
        )

    def unchanged(self):
        self.assertEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self.git("tag", "--list"), "")
        self.assertEqual(self.git("status", "--porcelain"), "")
        for path, data in self.originals.items():
            self.assertEqual((self.repo / path).read_bytes(), data, path)


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "requires Git and Bash")
class ReleaseTests(ReleaseFixture, unittest.TestCase):
    def test_unsupported_prerelease_versions_are_rejected_before_scan_or_mutation(self):
        # The generation protocol only accepts numeric X.Y.Z versions. A
        # successful self-scan must not let the cutter create an uninstallable
        # release, including when only preparing or previewing the candidate.
        for version in ("1.0.1-rc1", "1.0.1-beta.2", "1.0.1+build.7"):
            for mode in ("--dry-run", "--no-commit", "--yes"):
                with self.subTest(version=version, mode=mode):
                    proc = self.release(mode, "--allow-dirty", version=version)
                    self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                    self.assertIn(b"version", proc.stderr)
                    self.assertFalse(self.record_path.exists(), "self-scan ran for an unsupported version")
                    self.unchanged()

    def test_success_runs_strict_scan_then_creates_real_local_commit_and_tag(self):
        proc = self.release("--yes")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self.git("tag", "--list"), "v1.0.1")
        self.assertEqual(self.git("cat-file", "-t", "v1.0.1"), "tag")
        self.assertEqual((self.repo / "VERSION").read_text(), "1.0.1\n")
        try:
            record = json.loads(self.record_path.read_text())
        except json.JSONDecodeError as error:
            self.fail(f"Invalid scanner invocation record: {error}")
        self.assertEqual(record["argv"], [".", "--ci", "--fail-on-warning", "--format=json"])
        self.assertEqual(Path(record["cwd"]).resolve(), self.repo.resolve())
        self.assertEqual(record["env"], {
            "UBS_ALLOW_PARTIAL": "0", "UBS_ALLOW_NO_SCAN": "0",
            "UBS_NO_AUTO_UPDATE": "1", "UBS_ENABLE_AUTO_UPDATE": "0", "UBS_NO_CACHE": "1",
        })

    def test_partial_overrides_cannot_pass_even_with_yes_allow_dirty(self):
        report = clean_report()
        report["status"] = "partial"
        report["failed_modules"] = [{"language": "python", "status": "partial"}]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        for model_exit in ("0", "1"):
            self.env["MODEL_PARTIAL_EXIT"] = model_exit
            with self.subTest(model_exit=model_exit):
                proc = self.release("--yes", "--allow-dirty")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(b"self-scan rejected", proc.stderr)
                self.unchanged()

    def test_nonzero_exit_with_clean_json_is_not_a_pass(self):
        for code in ("1", "2", "3", "7"):
            self.env["SCAN_EXIT"] = code
            with self.subTest(code=code):
                proc = self.release("--yes")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(f"scanner exited {code}".encode(), proc.stderr)
                self.unchanged()

    def test_no_scan_and_malformed_reports_preserve_tree_and_diagnostics(self):
        empty = clean_report()
        empty["scanners"] = []
        empty["totals"]["files"] = 0
        for data in (b"", b"not JSON", b"[]", b"\xff",
                     b'{"status":"partial","status":"ok"}',
                     b'{"status":NaN}', json.dumps(empty).encode()):
            self.report_path.write_bytes(data)
            with self.subTest(data=data):
                proc = self.release("--yes")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(b"self-scan rejected", proc.stderr)
                self.assertIn(b"scanner diagnostic retained", proc.stderr)
                self.unchanged()

    def test_scanner_failure_or_findings_cannot_hide_behind_clean_totals(self):
        partial = clean_report()
        partial["scanners"][0]["status"] = "partial"
        warning = clean_report()
        warning["scanners"][0]["warning"] = 1
        for report in (partial, warning):
            self.report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.subTest(report=report):
                proc = self.release("--yes")
                self.assertNotEqual(proc.returncode, 0)
                self.unchanged()

    def test_dry_run_still_requires_complete_scan_and_never_mutates(self):
        proc = self.release("--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertTrue(self.record_path.is_file())
        self.unchanged()
        report = clean_report()
        report["status"] = "partial"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        proc = self.release("--dry-run")
        self.assertNotEqual(proc.returncode, 0)
        self.unchanged()

    def test_no_commit_mode_does_not_bypass_gate(self):
        self.report_path.write_text("{}", encoding="utf-8")
        proc = self.release("--no-commit")
        self.assertNotEqual(proc.returncode, 0)
        self.unchanged()


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "requires Git and Bash")
class CandidateReleaseTests(ReleaseFixture, unittest.TestCase):
    """The real cutter must authenticate the tree that it will actually tag."""

    def prepare_candidate(self):
        for name in ("build_release_candidate.py", "release_generation.py",
                     "update_checksums.py", "update_checksums.sh", "update_sha256sums.sh",
                     "verify_checksums.sh", "verify_sha256sums.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        shutil.copy2(ROOT / "minisign.pub", self.repo / "minisign.pub")
        key = (self.repo / "minisign.pub").read_text().splitlines()[1]
        zero = "0" * 64
        files = {
            "ubs-daemon": "#!/usr/bin/env python3\nprint('fixture service')\n",
            "scripts/verify.sh": "#!/usr/bin/env bash\nexit 0\n",
            ".claude/hooks/git_safety_guard.py": "# Inert release payload fixture.\n",
            "install.sh": '#!/usr/bin/env bash\nMINISIGN_PUBKEY="${UBS_MINISIGN_PUBKEY:-'
                          + key + '}"\n',
            "modules/contract.json": '{}\n',
            "modules/helpers/ubs_core/sample.py": 'VALUE = "original helper"\n',
            "modules/lib/ubs-common.sh": "#!/usr/bin/env bash\n"
                "declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(\n"
                f"  ['contract.json']='{zero}'\n)\n",
            "modules/ubs-bash.sh": '#!/usr/bin/env bash\n'
                f'UBS_LIB_CHECKSUM="{zero}"\n',
            "scripts/new-module.sh": '#!/usr/bin/env bash\n'
                f'UBS_LIB_CHECKSUM="{zero}"\n',
        }
        for relative, content in files.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        declarations = (
            'UBS_VERSION="1.0.0"\nUBS_RELEASE_GENERATIONS=1\n'
            f'UBS_RELEASE_PUBKEY="{key}"\nUBS_DAEMON_SHA256="{zero}"\n'
            "declare -A MODULE_CHECKSUMS=(\n"
            f"  [bash]='{zero}'\n)\n"
            "declare -A HELPER_CHECKSUMS=(\n"
            f"  ['contract.json']='{zero}'\n)\n"
            'HELPER_ASSETS=(\n  "contract.json"\n)\nALL_LANGS=(bash)\n'
            "generation_helper() {\ncat <<'PYRELEASEGENERATION'\n"
            + (self.repo / "scripts/release_generation.py").read_text()
            + "PYRELEASEGENERATION\n}\n"
        )
        (self.repo / "ubs").write_text(
            SCANNER.replace('UBS_VERSION="1.0.0"\n', declarations, 1), encoding="utf-8",
        )
        self.refresh_checksums()

    def refresh_checksums(self):
        result = subprocess.run(
            [sys.executable, str(self.repo / "scripts/update_checksums.py")],
            cwd=self.repo, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def source_bytes(self):
        paths = self.git("ls-files", "--cached", "--others", "--exclude-standard").splitlines()
        return {name: (self.repo / name).read_bytes() for name in paths}

    def assert_no_release(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self.git("tag", "--list"), "")
        self.assertIn(b"release candidate rejected", result.stderr)

    def check_tag(self):
        self.assertEqual(self.git("tag", "--list"), "v1.0.1")
        self.assertEqual(self.git("cat-file", "-t", "v1.0.1"), "tag")
        self.assertEqual(self.git("rev-parse", "v1.0.1^{commit}"), self.git("rev-parse", "HEAD"))
        # Reconstruct only the committed bytes in a fresh directory. This
        # independent cold-source check cannot borrow an unstaged payload.
        tagged = self.base / "tagged source"
        tagged.mkdir()
        for relative in self.git("ls-tree", "-r", "--name-only", "v1.0.1").splitlines():
            destination = tagged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(subprocess.check_output(
                ["git", "show", "v1.0.1:" + relative], cwd=self.repo,
                env=self.env, stderr=subprocess.PIPE, timeout=30,
            ))
        result = subprocess.run(
            [sys.executable, str(tagged / "scripts/build_release_candidate.py"),
             "--version", "1.0.1", "--output", str(self.base / "tagged candidate")],
            cwd=self.base, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git("status", "--porcelain"), "")

    def assert_generation_rejected(self, mode):
        runner = self.repo / "ubs"
        runner.write_text(runner.read_text().replace("UBS_RELEASE_GENERATIONS=1\n", "", 1))
        self.refresh_checksums()
        before, status = self.source_bytes(), self.git("status", "--porcelain")
        result = self.release(mode, "--allow-dirty")
        self.assert_no_release(result)
        self.assertIn(b"UBS_RELEASE_GENERATIONS", result.stderr)
        self.assertFalse(self.record_path.exists(), "self-scan ran before candidate rejection")
        self.assertEqual(self.source_bytes(), before)
        self.assertEqual(self.git("status", "--porcelain"), status)

    def test_missing_generation_is_rejected_before_scan_or_mutation(self):
        self.assert_generation_rejected("--yes")

    def test_dry_run_requires_generation_compatible_runner(self):
        self.assert_generation_rejected("--dry-run")

    def test_prepare_mode_requires_generation_compatible_runner(self):
        self.assert_generation_rejected("--no-commit")

    def test_clean_complete_tree_can_be_committed_and_tagged(self):
        result = self.release("--yes")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.record_path.exists())
        self.check_tag()

    def assert_unstaged_release_input_is_rejected(self, relative):
        path = self.repo / relative
        changed = path.read_bytes() + b"\n# changed release input\n"
        path.write_bytes(changed)
        self.refresh_checksums()
        result = self.release("--yes", "--allow-dirty")
        self.assert_no_release(result)
        self.assertTrue(self.record_path.exists(), "working candidate should pass preflight")
        self.assertEqual(path.read_bytes(), changed, "rejection must retain the user's source edit")
        self.assertEqual((self.repo / "VERSION").read_text(), "1.0.1\n")

    def test_unstaged_module_cannot_be_tagged_with_its_new_checksum(self):
        self.assert_unstaged_release_input_is_rejected("modules/ubs-bash.sh")

    def test_unstaged_helper_cannot_be_tagged_with_its_new_checksum(self):
        self.assert_unstaged_release_input_is_rejected("modules/helpers/ubs_core/sample.py")

    def test_unstaged_installer_cannot_be_tagged_with_its_new_checksum(self):
        self.assert_unstaged_release_input_is_rejected("install.sh")

    def test_unstaged_verifier_cannot_differ_from_the_qualified_payload(self):
        self.assert_unstaged_release_input_is_rejected("scripts/verify.sh")

    def test_unstaged_guard_cannot_differ_from_the_qualified_payload(self):
        self.assert_unstaged_release_input_is_rejected(".claude/hooks/git_safety_guard.py")

    def test_untracked_pinned_helper_cannot_be_absent_from_release_tree(self):
        relative = "modules/helpers/ubs_core/new_helper.py"
        path = self.repo / relative
        path.write_text('VALUE = "new untracked dependency"\n', encoding="utf-8")
        self.refresh_checksums()
        # Stage all updated tracked pins, leaving only the new payload out.
        # A working-tree-only check and git diff --quiet both miss this case.
        self.git("add", "-u")
        self.assertEqual(self.git("ls-files", "--", relative), "")
        result = self.release("--yes", "--allow-dirty")
        self.assert_no_release(result)
        self.assertIn(b"new_helper.py", result.stderr)
        self.assertTrue(path.is_file(), "rejection must preserve the untracked helper")
        self.assertEqual(self.git("ls-files", "--", relative), "")

    def test_complete_staged_runtime_changes_can_be_tagged(self):
        helper = self.repo / "modules/helpers/ubs_core/sample.py"
        helper.write_text('VALUE = "reviewed helper revision"\n', encoding="utf-8")
        installer = self.repo / "install.sh"
        installer.write_bytes(installer.read_bytes() + b"\n# reviewed installer revision\n")
        self.refresh_checksums()
        self.git("add", "modules", "scripts/new-module.sh", "install.sh", "ubs", "SHA256SUMS")
        result = self.release("--yes", "--allow-dirty")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git("show", "v1.0.1:modules/helpers/ubs_core/sample.py"),
                         'VALUE = "reviewed helper revision"')
        self.check_tag()

    def test_commit_hook_cannot_tag_a_tree_changed_after_validation(self):
        hook = self.repo / ".git/hooks/pre-commit"
        hook.write_text(
            "#!/usr/bin/env bash\nset -e\n"
            "printf '%s\\n' '# changed after candidate validation' >> install.sh\n"
            "git add -- install.sh\n", encoding="utf-8",
        )
        hook.chmod(0o755)
        result = self.release("--yes")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self.git("tag", "--list"), "")
        self.assertIn(b"tree", result.stderr.lower())
        self.assertIn("changed after candidate validation", (self.repo / "install.sh").read_text())

    def test_replace_ref_cannot_hide_a_malformed_committed_tree(self):
        # A replacement changes local Git reads, but the original commit's
        # bytes are still what a pushed release tag distributes. Preserve a
        # good commit object, then use it to disguise a changed release tree.
        before = self.repo / ".git/hooks/pre-commit"
        before.write_text(
            "#!/usr/bin/env bash\nset -e\n"
            'qualified_tree="$(git write-tree)"\n'
            'git commit-tree "$qualified_tree" -m "qualified temporary candidate" '
            '> .git/ubs-qualified-commit\n'
            "printf '%s\\n' '# raw release payload changed' >> install.sh\n"
            "git add -- install.sh\n", encoding="utf-8",
        )
        after = self.repo / ".git/hooks/post-commit"
        after.write_text(
            "#!/usr/bin/env bash\nset -e\n"
            'git replace "$(git rev-parse HEAD)" "$(cat .git/ubs-qualified-commit)"\n',
            encoding="utf-8",
        )
        before.chmod(0o755)
        after.chmod(0o755)
        result = self.release("--yes")
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertNotEqual(self.git("--no-replace-objects", "rev-parse", "HEAD^{tree}"),
                            self.git("rev-parse", "HEAD^{tree}"))
        self.assertIn("raw release payload changed",
                      self.git("--no-replace-objects", "show", "HEAD:install.sh"))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git("tag", "--list"), "")
        self.assertIn(b"tree", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
