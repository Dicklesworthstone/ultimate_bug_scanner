#!/usr/bin/env python3
"""Release self-scan must fail closed before any version, commit or tag changes.

The release script and validator are real. The scanner and downstream checksum
steps are controlled fixtures so analyzer failures can be exercised without
running the multi-language suite or publishing a release.
"""
from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import shutil
import subprocess
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


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "requires Git and Bash")
class ReleaseTests(unittest.TestCase):
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

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, env=self.env, text=True, stderr=subprocess.PIPE,
        ).strip()

    def release(self, *args):
        return subprocess.run(
            ["bash", str(self.repo / "scripts/cut-release.sh"), "1.0.1", *args],
            cwd=self.base, env=self.env, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=30,
        )

    def unchanged(self):
        self.assertEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self.git("tag", "--list"), "")
        self.assertEqual(self.git("status", "--porcelain"), "")
        for path, data in self.originals.items():
            self.assertEqual((self.repo / path).read_bytes(), data, path)

    def test_success_runs_strict_scan_then_creates_real_local_commit_and_tag(self):
        proc = self.release("--yes")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self.git("tag", "--list"), "v1.0.1")
        self.assertEqual(self.git("cat-file", "-t", "v1.0.1"), "tag")
        self.assertEqual((self.repo / "VERSION").read_text(), "1.0.1\n")
        record = json.loads(self.record_path.read_text())
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


if __name__ == "__main__":
    unittest.main()
