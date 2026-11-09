#!/usr/bin/env python3
"""Issue #128: optional analyzers must not turn coverage failures into passes."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core import bash_scan, external_tools, findings_merge


def diagnostic(**changes: object) -> dict:
    result = {"file": "sample.sh", "line": 3, "column": 1, "code": 2086,
              "level": "warning", "message": "Double quote to prevent splitting"}
    result.update(changes)
    return result


def audit_dependency(**changes: object) -> dict:
    """The published pip-audit JSON schema, with fixed advisory service data."""
    result = {"name": "example-package", "version": "1.0", "vulns": [
        {"id": "PYSEC-2026-123", "fix_versions": ["1.1"], "aliases": ["CVE-2026-12345"]},
    ]}
    result.update(changes)
    return result


class PipAuditResults(unittest.TestCase):
    def parse(self, doc=None, *, raw=None):
        sink, errors = io.StringIO(), []
        counts = external_tools.parse_pip_audit_report(
            json.dumps(doc) if raw is None else raw, Path("requirements.txt"), sink, errors,
        )
        return counts, [json.loads(line) for line in sink.getvalue().splitlines()], errors

    def normalized_scan(self, root, name, dependencies, *, baseline=""):
        """Exercise the real sink, canonical ledger and new-only filter."""
        manifest = root / "requirements.txt"
        manifest.write_text("# resolved dependencies\n" + "".join(
            f"{row['name']}=={row['version']}\n" for row in dependencies))
        run = root / name
        run.mkdir()
        errors = []
        with (run / "python.findings.json").open("w", encoding="utf-8") as sink:
            counts = external_tools.parse_pip_audit_report(
                json.dumps({"dependencies": dependencies, "fixes": []}), manifest, sink, errors)
        self.assertFalse(errors)
        severities = {"critical": counts["vulnerabilities"], "warning": 0, "info": 0}
        report = run / "combined.json"
        report.write_text(json.dumps({
            "status": "ok", "totals": severities,
            "scanners": [{"language": "python", "status": "ok", **severities}],
        }), encoding="utf-8")
        with patch.dict(os.environ, {"UBS_KEEP_TEMP": "1"}):
            findings_merge.merge(run, report, project_dir=root,
                                 baseline_path=baseline, new_only=bool(baseline))
        return report, json.loads(report.read_text(encoding="utf-8")), counts

    def identity_workspace(self):
        artifacts = ROOT / "test-suite/artifacts"
        artifacts.mkdir(exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="pip-audit-identity-", dir=artifacts))

    def test_new_only_keeps_another_package_with_the_same_advisory(self):
        root = self.identity_workspace()
        old = audit_dependency(name="first-package")
        new = audit_dependency(name="different-package")
        baseline, previous, _counts = self.normalized_scan(root, "baseline", [old])
        self.assertEqual(previous["totals"]["critical"], 1)
        for index, dependencies in enumerate(([new], [old, new], [new, old])):
            with self.subTest(dependencies=dependencies):
                _report, current, counts = self.normalized_scan(
                    root, f"current-{index}", dependencies, baseline=baseline)
                self.assertEqual(counts["vulnerabilities"], len(dependencies))
                self.assertEqual(current["totals"]["critical"], 1)
                self.assertEqual([row["extras"]["package"] for row in current["findings"]],
                                 ["different-package"])

    def test_package_name_aliases_deduplicate_and_preserve_baseline_identity(self):
        root = self.identity_workspace()
        baseline, previous, _counts = self.normalized_scan(
            root, "baseline", [audit_dependency(name="Example.Package")])
        aliases = [audit_dependency(name=name, version="1.0.1")
                   for name in ("example-package", "example_package", "EXAMPLE...Package")]
        _report, all_findings, counts = self.normalized_scan(root, "unfiltered", aliases)
        self.assertEqual(counts["vulnerabilities"], 1)
        self.assertEqual(len(all_findings["findings"]), 1)
        self.assertEqual(all_findings["findings"][0]["fingerprint"],
                         previous["findings"][0]["fingerprint"])
        _report, current, _counts = self.normalized_scan(root, "current", aliases, baseline=baseline)
        self.assertEqual(current["totals"]["critical"], 0)
        self.assertEqual(current["findings"], [])

    def test_advisory_becomes_project_finding_with_remediation(self):
        counts, rows, errors = self.parse({"dependencies": [audit_dependency()], "fixes": []})
        self.assertEqual(counts, {"dependencies": 1, "vulnerabilities": 1, "skipped": 0})
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["rule"], rows[0]["severity"], rows[0]["path"], rows[0]["line"]),
                         ("py.pip-audit.PYSEC-2026-123.example-package", "critical", "requirements.txt", 1))
        self.assertEqual(rows[0]["extras"], {
            "tool": "pip-audit", "scope": "project", "package": "example-package", "version": "1.0",
            "advisory": "PYSEC-2026-123", "fix_versions": ["1.1"], "aliases": ["CVE-2026-12345"],
        })
        self.assertIn("fixed in 1.1", rows[0]["message"])

    def test_clean_inventory_and_empty_inventory_are_distinguishable(self):
        for dependencies, expected in (([], 0), ([audit_dependency(vulns=[])], 1)):
            with self.subTest(dependencies=dependencies):
                counts, rows, errors = self.parse({"dependencies": dependencies, "fixes": []})
                self.assertEqual(counts, {"dependencies": expected, "vulnerabilities": 0, "skipped": 0})
                self.assertFalse(rows or errors)

    def test_skipped_and_malformed_dependencies_keep_valid_advisories(self):
        for bad in (None, {}, {"name": "unresolved", "skip_reason": "no distribution metadata"},
                    audit_dependency(vulns=None), audit_dependency(version=1)):
            with self.subTest(bad=bad):
                counts, rows, errors = self.parse({"dependencies": [bad, audit_dependency()], "fixes": []})
                self.assertTrue(errors)
                self.assertEqual(counts["vulnerabilities"], 1)
                self.assertEqual([row["rule"] for row in rows], ["py.pip-audit.PYSEC-2026-123.example-package"])

    def test_malformed_advisory_does_not_erase_other_advisories(self):
        good = audit_dependency()["vulns"][0]
        for bad in (None, {}, {**good, "fix_versions": None}, {**good, "aliases": [1]},
                    {**good, "id": "bad/id"}):
            with self.subTest(bad=bad):
                counts, rows, errors = self.parse({"dependencies": [audit_dependency(vulns=[bad, good])]})
                self.assertTrue(errors)
                self.assertEqual(counts["vulnerabilities"], 1)
                self.assertEqual(len(rows), 1)

    def test_truncation_preserves_complete_dependency_prefix(self):
        raw = '{"dependencies":[' + json.dumps(audit_dependency()) + ',{"name":'
        counts, rows, errors = self.parse(raw=raw)
        self.assertEqual(counts["vulnerabilities"], 1)
        self.assertEqual(len(rows), 1)
        self.assertIn("incomplete report", errors[0])

    def test_missing_duplicate_and_invalid_documents_are_incomplete(self):
        for raw in ("", "[]", "null", "{}", '{"dependencies":null}',
                    '{"dependencies":[],"dependencies":[]}', '{"dependencies":[]}junk'):
            with self.subTest(raw=raw):
                _counts, rows, errors = self.parse(raw=raw)
                self.assertFalse(rows)
                self.assertTrue(errors)


class ShellCheckResults(unittest.TestCase):
    def invoke(self, result: subprocess.CompletedProcess | Exception,
               *, skip: set[int] | None = None, installed: bool = True,
               files: list[Path] | None = None, reported: set | None = None):
        sink, errors = io.StringIO(), []
        with patch.object(bash_scan.shutil, "which", return_value="/bin/shellcheck" if installed else None), \
             patch.object(bash_scan.subprocess, "run") as run:
            if isinstance(result, Exception):
                run.side_effect = result
            else:
                run.return_value = result
            counts = bash_scan.scan_shellcheck(
                files or [Path("sample.sh")], sink, skip or set(), reported or set(), errors=errors,
            )
        return counts, [json.loads(line) for line in sink.getvalue().splitlines()], errors, run

    def result(self, code: int = 0, data: object = None, *, raw: str | None = None):
        return subprocess.CompletedProcess(["shellcheck"], code,
                                           json.dumps([] if data is None else data) if raw is None else raw,
                                           "analyzer diagnostic on stderr\n")

    def test_absent_and_explicitly_skipped_are_complete(self):
        for options in ({"installed": False}, {"skip": {6}}):
            with self.subTest(options=options):
                counts, rows, errors, run = self.invoke(self.result(), **options)
                self.assertEqual(sum(counts.values()), 0)
                self.assertFalse(rows or errors)
                run.assert_not_called()

    def test_success_empty_array_is_clean(self):
        _, rows, errors, run = self.invoke(self.result())
        self.assertFalse(rows or errors)
        self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_findings_exit_one_is_not_analyzer_failure(self):
        counts, rows, errors, _ = self.invoke(self.result(1, [diagnostic()]))
        self.assertEqual(counts["warning"], 1)
        self.assertEqual(rows[0]["rule"], "bash.shellcheck.SC2086")
        self.assertFalse(errors)

    def test_ignored_diagnostic_does_not_turn_exit_one_into_failure(self):
        _, rows, errors, _ = self.invoke(self.result(1, [diagnostic(code=2034)]))
        self.assertFalse(rows or errors)

    def test_independent_shellcheck_finding_survives_native_warning(self):
        native = ("sample.sh", 3, "bash.robustness.cd_without_exit")
        counts, rows, errors, _ = self.invoke(
            self.result(1, [diagnostic()]), reported={native},
        )
        self.assertEqual(counts["warning"], 1)
        self.assertEqual([row["rule"] for row in rows], ["bash.shellcheck.SC2086"])
        self.assertFalse(errors)

    def test_same_shellcheck_rule_is_not_reported_twice(self):
        _, rows, errors, _ = self.invoke(
            self.result(1, [diagnostic()]),
            reported={("sample.sh", 3, "bash.shellcheck.SC2086")},
        )
        self.assertFalse(rows or errors)

    def test_processing_usage_timeout_and_signal_exits_are_partial(self):
        for code in (2, 3, 4, 124, 127, -9):
            with self.subTest(code=code):
                counts, rows, errors, _ = self.invoke(self.result(code, [diagnostic()]))
                self.assertEqual(counts["warning"], 1)
                self.assertEqual(len(rows), 1)
                self.assertIn(f"shellcheck exited {code}", errors[0])
                self.assertIn("diagnostic on stderr", errors[0])

    def test_launch_and_timeout_errors_are_partial(self):
        for exc, expected in ((OSError("cannot execute"), "could not be launched"),
                              (subprocess.TimeoutExpired(["shellcheck"], 120), "timed out")):
            with self.subTest(exc=exc):
                _, rows, errors, _ = self.invoke(exc)
                self.assertFalse(rows)
                self.assertIn(expected, errors[0])

    def test_empty_truncated_and_non_array_json_are_partial(self):
        for raw in ("", "[", "null", "{}", '"oops"', "false"):
            with self.subTest(raw=raw):
                _, rows, errors, _ = self.invoke(self.result(raw=raw))
                self.assertFalse(rows)
                self.assertTrue(errors)

    def test_malformed_rows_preserve_valid_rows(self):
        for bad in (None, 4, [], {}, diagnostic(line="three"), diagnostic(line=True),
                    diagnostic(column=0), diagnostic(code="SC2086"), diagnostic(file=None),
                    diagnostic(message=[]), diagnostic(level="unknown")):
            with self.subTest(bad=bad):
                counts, rows, errors, _ = self.invoke(self.result(0, [bad, diagnostic()]))
                self.assertEqual(counts["warning"], 1)
                self.assertEqual(len(rows), 1)
                self.assertIn("malformed diagnostic", errors[0])

    def test_failure_does_not_prevent_later_batches(self):
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="shellcheck-small-batches-", dir=artifacts))
        files = [scratch / f"sample-{i}.sh" for i in range(51)]
        for path in files:
            path.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        sink, errors = io.StringIO(), []
        with patch.object(bash_scan.shutil, "which", return_value="/bin/shellcheck"), \
             patch.object(bash_scan.subprocess, "run", side_effect=[OSError("failed batch"), self.result(1, [diagnostic()])]) as run:
            counts = bash_scan.scan_shellcheck(files, sink, set(), set(), errors)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(counts["warning"], 1)
        self.assertIn("failed batch", errors[0])


SHELLCHECK_STUB = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ["SHELLCHECK_CALLS"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
mode = os.environ.get("SHELLCHECK_MODE", "clean")
if mode == "malformed":
    print("not JSON")
    sys.exit(0)
rows = []
if mode in ("findings", "partial-findings"):
    rows = [{"file": sys.argv[-1], "line": 3, "column": 1, "code": 2086,
             "level": "warning", "message": "sentinel ShellCheck finding"}]
print(json.dumps(rows))
if mode in ("failure", "partial-findings"):
    print("sentinel could not process a file", file=sys.stderr)
    sys.exit(2)
sys.exit(1 if rows else 0)
'''


class ShellCheckIntegration(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs-optional-analyzer-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.source = self.project / "sample.sh"
        self.source.write_text('#!/bin/bash\neval "$command"\necho "$HOME"\n', encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.stub = self.bin / "shellcheck"
        self.stub.write_text(SHELLCHECK_STUB, encoding="utf-8")
        self.stub.chmod(0o755)
        self.calls = self.root / "calls.jsonl"
        self.env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                    "HOME": str(self.root), "XDG_CACHE_HOME": str(self.root / "cache"),
                    "XDG_DATA_HOME": str(self.root / "data"), "NO_COLOR": "1", "CI": "1",
                    "UBS_CACHE_DIR": str(self.root / "cache"), "UBS_NO_CACHE": "0",
                    "UBS_ENABLE_AUTO_UPDATE": "0", "UBS_NO_AUTO_UPDATE": "1",
                    "UBS_TEST_FORCE_NO_AST_GREP": "1", "PYTHONDONTWRITEBYTECODE": "1",
                    "SHELLCHECK_CALLS": str(self.calls)}

    def scan(self, mode: str, fmt: str = "json", *, meta: bool = False, args: tuple = ()):
        binary = ROOT / "ubs" if meta else ROOT / "modules/ubs-bash.sh"
        cmd = [str(binary), str(self.project), f"--format={fmt}", *args]
        if meta:
            cmd.append("--only=bash")
        return subprocess.run(cmd, cwd=self.root, env={**self.env, "SHELLCHECK_MODE": mode},
                              capture_output=True, text=True, timeout=60, check=False)

    def document(self, proc):
        try:
            return json.loads(proc.stdout)
        except ValueError:
            self.fail(proc.stdout + proc.stderr)

    def test_module_partial_keeps_native_and_external_findings(self):
        proc = self.scan("partial-findings")
        doc = self.document(proc)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
        self.assertIn("shellcheck", doc["message"])
        self.assertGreater(doc["critical"], 0)
        self.assertIn("bash.shellcheck.SC2086", {r.get("rule") for r in doc["findings"]})

    def test_valid_findings_are_not_partial(self):
        proc = self.scan("findings")
        doc = self.document(proc)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)  # native eval is critical
        self.assertEqual(doc["status"], "ok")
        self.assertNotIn("module_error", doc)

    def test_warm_cache_retries_external_layer_and_recovers(self):
        for mode, status, code in (("clean", "ok", 1), ("failure", "partial", 2),
                                   ("malformed", "partial", 2), ("findings", "ok", 1)):
            with self.subTest(mode=mode):
                proc = self.scan(mode)
                doc = self.document(proc)
                self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
                self.assertEqual(doc["status"], status)
                if mode != "clean":
                    self.assertGreater(doc["extras"]["profile"]["cache_hits"], 0)
        self.assertEqual(len(self.calls.read_text().splitlines()), 4)
        proc = self.scan("clean")
        doc = self.document(proc)
        self.assertNotIn("bash.shellcheck.SC2086", {r.get("rule") for r in doc["findings"]})

    def test_skip_does_not_launch_external_tool(self):
        for args in (("--no-shellcheck",), ("--skip=6",)):
            with self.subTest(args=args):
                proc = self.scan("failure", args=args)
                self.assertEqual(self.document(proc)["status"], "ok")
        self.assertFalse(self.calls.exists())

    def test_text_never_labels_failed_shellcheck_clean(self):
        proc = self.scan("failure", "text")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("Partial: [ANALYZER_ERROR] shellcheck", proc.stdout)
        self.assertIn("Not evaluated: ShellCheck did not complete", proc.stdout)

    def test_module_sarif_reports_failed_invocation_with_findings(self):
        proc = self.scan("failure", "sarif")
        doc = self.document(proc)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        run = doc["runs"][0]
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertTrue(run["results"])

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg"), "meta-runner requires jq/rg")
    def test_production_meta_runner_preserves_partial_evidence(self):
        for fmt in ("json", "sarif", "text"):
            with self.subTest(fmt=fmt):
                proc = self.scan("partial-findings", fmt, meta=True)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                if fmt == "json":
                    doc = self.document(proc)
                    self.assertIn(doc["status"], ("partial", "error"))
                    self.assertTrue(doc["failed_modules"])
                    self.assertGreater(doc["totals"]["critical"], 0)
                    self.assertEqual([s["language"] for s in doc["scanners"]], ["bash"])
                elif fmt == "sarif":
                    doc = self.document(proc)
                    self.assertTrue(any(run.get("results") for run in doc["runs"]))
                    self.assertTrue(any(not inv["executionSuccessful"]
                                        for run in doc["runs"] for inv in run.get("invocations", [])))
                else:
                    self.assertIn("shellcheck", proc.stdout + proc.stderr)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg"), "meta-runner requires jq/rg")
    def test_contract_snapshot_and_exports_never_become_scanners(self):
        report = self.root / "report.json"
        proc = self.scan("clean", meta=True, args=(f"--report-json={report}",))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        for doc in (self.document(proc), json.loads(report.read_text())):
            self.assertEqual([s["language"] for s in doc["scanners"]], ["bash"])
            self.assertEqual(doc["totals"]["critical"], 1)
            self.assertNotIn("contract_version", doc["scanners"][0])

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg"), "meta-runner requires jq/rg")
    def test_multilanguage_failure_keeps_healthy_scanner(self):
        (self.project / "clean.py").write_text("answer = 42\n", encoding="utf-8")
        proc = subprocess.run(
            [str(ROOT / "ubs"), str(self.project), "--only=python,bash", "--format=json"],
            cwd=self.root, env={**self.env, "SHELLCHECK_MODE": "partial-findings"},
            capture_output=True, text=True, timeout=60, check=False,
        )
        doc = self.document(proc)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(doc["status"], "partial")
        self.assertEqual({s["language"] for s in doc["scanners"]}, {"bash", "python"})
        self.assertEqual([s["language"] for s in doc["failed_modules"]], ["bash"])
        self.assertGreater(doc["totals"]["critical"], 0)


@unittest.skipUnless(shutil.which("jq"), "aggregation requires jq")
class ScannerMergeResults(unittest.TestCase):
    def test_only_selected_summaries_are_merged_on_every_call(self):
        text = (ROOT / "ubs").read_text(encoding="utf-8")
        start = text.index("merge_json_scanners(){")
        function = text[start:text.index("\n}\n", start) + 3]
        for languages in (("bash",), ("bash", "python")):
            with self.subTest(languages=languages), tempfile.TemporaryDirectory(prefix="ubs-merge-") as tmp:
                root = Path(tmp)
                for lang in languages:
                    (root / f"{lang}.json").write_text(json.dumps({
                        "language": lang, "files": 1, "critical": 1, "warning": 0,
                        "info": 0, "status": "ok", "findings": [],
                    }))
                # Both authentic internal metadata and a scanner-looking file
                # are irrelevant unless a selected module owns that basename.
                (root / "detection-contract.json").write_text('{"modules":{}}')
                (root / "unselected.json").write_text('{"language":"rogue","critical":999}')
                script = '''set -euo pipefail
TMPDIR_RUN="$1"; SOURCE_PROJECT_DIR="$1"; shift
langs=("$@")
need_cmd(){ command -v "$1" >/dev/null; }
ensure_git_metadata(){ :; }
date_iso(){ printf '%s' '2026-01-01T00:00:00Z'; }
add_json_permalinks(){ printf '%s\\n' "$1"; }
say(){ printf '%s\\n' "$*" >&2; }
''' + function + '''
merge_json_scanners > "$TMPDIR_RUN/first.out"
cp "$TMPDIR_RUN/first.out" "$TMPDIR_RUN/combined.json"
merge_json_scanners > "$TMPDIR_RUN/second.out"
cmp "$TMPDIR_RUN/first.out" "$TMPDIR_RUN/second.out"
cat "$TMPDIR_RUN/second.out"
'''
                proc = subprocess.run(["bash", "-c", script, "ubs-merge", tmp, *languages],  # ubs:ignore[py.security.command-injection] Runs repository-owned code; fixture data stays in positional argv.
                                      capture_output=True, text=True, check=False, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                doc = json.loads(proc.stdout)
                self.assertEqual([s["language"] for s in doc["scanners"]], list(languages))
                self.assertEqual(doc["totals"]["critical"], len(languages))


@unittest.skipUnless(os.name == "posix", "Python module requires a POSIX shell")
class PythonOptionalIntegration(unittest.TestCase):
    """Real module and processes; injected tools pin external report contracts."""

    def setUp(self):
        artifacts = ROOT / "test-suite/artifacts"
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="python-optional-", dir=artifacts))
        self.project = self.root / "project"
        self.project.mkdir()
        self.source = self.project / "sample.py"
        self.source.write_text('import os\nhandle = open("data", encoding="utf-8")\n')
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Omit user tool directories so the direct route cannot accidentally
        # provision an audit through an installed uv. Use the test interpreter.
        (self.bin / "python3").symlink_to(sys.executable)
        self.calls = self.root / "calls.jsonl"
        self.pids = self.root / "pids.json"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("UBS_", "UV_", "XDG_"))}
        self.env.update(PATH=f"{self.bin}:/usr/bin:/bin", NO_COLOR="1", CI="1",
                        PYTHONDONTWRITEBYTECODE="1", ENABLE_UV_TOOLS="1",
                        UBS_CACHE_DIR=str(self.root / "cache"), UBS_NO_AUTO_UPDATE="1",
                        UBS_TEST_FORCE_NO_AST_GREP="1", UV_TIMEOUT="10",
                        AUDIT_CALLS=str(self.calls), AUDIT_PIDS=str(self.pids))

    def failure_tool(self, tool, *, uv=False):
        # An executable with a recorded PID and real descendants verifies
        # cancellation without pretending to provide successful audit results.
        if tool == "pip-audit":
            (self.project / "requirements.txt").write_text("urllib3==1.26.0\n")
        script = f"#!{sys.executable}\n" + r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
with open(os.environ["AUDIT_CALLS"], "a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
mode = os.environ.get("AUDIT_MODE", "empty")
if mode in ("output", "stall"):
    print('[{"message":"audit evidence before failure"}]', flush=True)
    print("audit stderr before failure", file=sys.stderr, flush=True)
if mode == "stall":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    Path(os.environ["AUDIT_PIDS"]).write_text(json.dumps([os.getpid(), child.pid]))
    time.sleep(120)
sys.exit(int(os.environ.get("AUDIT_EXIT", "2")))
'''
        target = self.bin / ("uv" if uv else tool)
        target.write_text(script)
        target.chmod(0o755)

    def command(self, tool, *, format="text"):
        return [str(ROOT / "modules/ubs-python.sh"), str(self.project),
                f"--format={format}", f"--uv-tools={tool}",
                f"--summary-json={self.root / 'summary.json'}"]

    def scan(self, tool, *, format="text", **env):
        proc = subprocess.run(self.command(tool, format=format), cwd=self.root,
                              env={**self.env, **env}, capture_output=True,
                              text=True, timeout=60, check=False)
        (self.root / "stdout.txt").write_text(proc.stdout)
        (self.root / "stderr.txt").write_text(proc.stderr)
        return proc, json.loads((self.root / "summary.json").read_text())

    def assert_partial(self, proc, summary, tool):
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(summary["status"], "partial", summary)
        self.assertEqual(summary["module_error"], "ANALYZER_ERROR", summary)
        self.assertIn(tool, summary["message"])
        self.assertIn("analysis incomplete", proc.stderr)
        self.assertNotIn("Ruff clean", proc.stdout)
        # The external error must not replace independently observed findings.
        self.assertIn("python.lifecycle.file_handle",
                      {row["rule"] for row in summary["findings"]})
        self.assertIn("sample.py", proc.stdout)
        self.assertIn("coverage is incomplete", proc.stdout)

    def test_empty_abnormal_output_is_partial_for_all_default_tools(self):
        for tool in ("ruff", "bandit", "pip-audit"):
            self.failure_tool(tool)
            for code in ((0, 2) if tool == "ruff" else (1, 2)):
                with self.subTest(tool=tool, code=code):
                    proc, summary = self.scan(tool, AUDIT_EXIT=str(code))
                    self.assert_partial(proc, summary, tool)
        self.assertEqual(len(self.calls.read_text().splitlines()), 6)
        self.assertGreater(summary["extras"]["profile"]["cache_hits"], 0)

    def audit_tool(self, dependencies, *, code=0, uv=False):
        """A transport fixture, not a substitute for dependency-resolution proof."""
        (self.root / "audit.json").write_text(json.dumps({"dependencies": dependencies, "fixes": []}))
        script = f"#!{sys.executable}\n" + r'''
import json, os, sys
from pathlib import Path
with open(os.environ["AUDIT_CALLS"], "a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
sys.stdout.write(Path(os.environ["AUDIT_CALLS"]).with_name("audit.json").read_text())
sys.exit(CODE)
'''.replace("CODE", str(code))
        target = self.bin / ("uv" if uv else "pip-audit")
        target.write_text(script)
        target.chmod(0o755)

    def test_pyproject_uses_project_resolution_and_all_formats_keep_advisories(self):
        self.source.write_text("answer = 42\n")
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "example"\nversion = "1.0"\ndependencies = ["example-package==1.0"]\n')
        self.audit_tool([audit_dependency()], code=1)
        for format in ("text", "json", "sarif"):
            with self.subTest(format=format):
                proc, summary = self.scan("pip-audit", format=format)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(summary["status"], "ok", summary)
                self.assertEqual(summary["critical"], 1)
                self.assertEqual(summary["extras"]["external_tools"][0]["dependencies"], 1)
                self.assertEqual([r["rule"] for r in summary["findings"]], ["py.pip-audit.PYSEC-2026-123.example-package"])
                if format == "json":
                    self.assertEqual(json.loads(proc.stdout), summary)
                elif format == "sarif":
                    results = json.loads(proc.stdout)["runs"][0]["results"]
                    self.assertEqual([r["ruleId"] for r in results], ["py.pip-audit.PYSEC-2026-123.example-package"])
                    self.assertTrue(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("pyproject.toml"))
                else:
                    self.assertIn("example-package 1.0: PYSEC-2026-123 (fixed in 1.1)", proc.stdout)
                    critical_lines = [line for line in proc.stdout.splitlines()
                                      if line.startswith("Critical issues:")]
                    self.assertTrue(critical_lines)
                    self.assertEqual(set(critical_lines), {"Critical issues: 1"})
        for line in self.calls.read_text().splitlines():
            argv = json.loads(line)
            self.assertNotIn("--path", argv)
            self.assertEqual(argv[-1], str(self.project))
            self.assertIn("--format=json", argv)

    def test_requirements_precede_pyproject_and_audits_are_not_source_cached(self):
        self.source.write_text("answer = 42\n")
        (self.project / "requirements.txt").write_text("example-package==1.0\n")
        (self.project / "pyproject.toml").write_text('[project]\ndynamic = ["dependencies"]\n')
        self.audit_tool([audit_dependency(vulns=[])], uv=True)
        clean, summary = self.scan("pip-audit", format="json")
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        self.assertEqual(summary["critical"], 0)
        self.audit_tool([audit_dependency()], code=1, uv=True)
        vulnerable, summary = self.scan("pip-audit", format="json")
        self.assertEqual(vulnerable.returncode, 1, vulnerable.stdout + vulnerable.stderr)
        self.assertEqual(summary["critical"], 1)
        self.assertGreater(summary["extras"]["profile"]["cache_hits"], 0)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 2)
        for argv in calls:
            self.assertEqual(argv[:4], ["tool", "run", "--quiet", "pip-audit"])
            self.assertEqual(argv[-2:], ["-r", str(self.project / "requirements.txt")])
            self.assertNotIn("--path", argv)

    def test_no_manifest_is_explicit_skip_and_never_audits_tool_environment(self):
        self.audit_tool([])
        proc, summary = self.scan("pip-audit", format="json")
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        self.assertFalse(self.calls.exists())
        outcome = summary["extras"]["external_tools"][0]
        self.assertEqual(outcome["status"], "skipped")
        self.assertIn("no requirements.txt or pyproject.toml", outcome["reason"])

    def test_dynamic_pyproject_dependencies_are_partial_instead_of_empty_audit(self):
        (self.project / "pyproject.toml").write_text('[project]\ndynamic = ["dependencies"]\n')
        self.audit_tool([])
        proc, summary = self.scan("pip-audit")
        self.assert_partial(proc, summary, "pip-audit")
        self.assertFalse(self.calls.exists())
        self.assertIn("dynamic project dependencies", proc.stdout)
        self.assertTrue(any("dynamic project dependencies" in row["message"]
                            for row in summary["analysis_errors"]))

    def test_explicit_empty_runtime_dependencies_do_not_provision_an_audit(self):
        (self.project / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        self.audit_tool([], uv=True)
        proc, summary = self.scan("pip-audit", format="json")
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        self.assertEqual(summary["status"], "ok", summary)
        self.assertFalse(self.calls.exists())
        outcome = summary["extras"]["external_tools"][0]
        self.assertEqual(outcome["dependencies"], 0)
        self.assertEqual(outcome["reason"], "pyproject.toml declares no runtime dependencies")

    def test_skipped_packages_keep_advisories_but_make_the_scan_partial(self):
        (self.project / "requirements.txt").write_text("example-package==1.0\n")
        self.audit_tool([audit_dependency(), {"name": "private-package", "skip_reason": "not on PyPI"}], code=1)
        proc, summary = self.scan("pip-audit")
        self.assert_partial(proc, summary, "pip-audit")
        self.assertIn("py.pip-audit.PYSEC-2026-123.example-package", {row["rule"] for row in summary["findings"]})
        outcome = summary["extras"]["external_tools"][0]
        self.assertEqual((outcome["status"], outcome["dependencies"], outcome["skipped"]), ("partial", 1, 1))

    def test_exit_one_without_advisories_is_an_execution_failure(self):
        (self.project / "requirements.txt").write_text("example-package==1.0\n")
        self.audit_tool([audit_dependency(vulns=[])], code=1)
        proc, summary = self.scan("pip-audit")
        self.assert_partial(proc, summary, "pip-audit")
        self.assertIn("exit 1 contradicts 0 valid advisory findings", proc.stdout)

    def test_uv_without_companion_preserves_both_streams_and_native_findings(self):
        self.failure_tool("ruff", uv=True)
        self.assertFalse((self.bin / "uvx").exists())
        proc, summary = self.scan("ruff", AUDIT_MODE="output")
        self.assert_partial(proc, summary, "ruff")
        self.assertIn("audit evidence before failure", proc.stdout)
        self.assertIn("audit stderr before failure", proc.stdout)
        argv = json.loads(self.calls.read_text().splitlines()[0])
        self.assertEqual(argv[:5], ["tool", "run", "--quiet", "ruff", "check"])
        self.assertIn("--no-fix", argv)

    @staticmethod
    def running(pid):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return False
        return state not in ("Z", "X")

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "Linux process cleanup evidence")
    def test_tool_deadline_stops_descendants_and_keeps_earlier_evidence(self):
        self.failure_tool("pip-audit", uv=True)
        proc, summary = self.scan("pip-audit", AUDIT_MODE="stall", UV_TIMEOUT="1")
        self.assert_partial(proc, summary, "pip-audit")
        self.assertIn("timed out after 1s", proc.stdout)
        self.assertIn("audit evidence before failure", proc.stdout)
        self.assertIn("audit stderr before failure", proc.stdout)
        for pid in json.loads(self.pids.read_text()):
            self.assertFalse(self.running(pid), f"audit process {pid} survived its deadline")

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "Linux process cleanup evidence")
    def test_module_cancellation_stops_isolated_audit_descendants(self):
        self.failure_tool("pip-audit", uv=True)
        with (self.root / "cancel.stdout").open("w") as out, \
                (self.root / "cancel.stderr").open("w") as err:
            proc = subprocess.Popen(self.command("pip-audit"), cwd=self.root,
                                    env={**self.env, "AUDIT_MODE": "stall", "UV_TIMEOUT": "60"},
                                    stdout=out, stderr=err, start_new_session=True)
            pids = []
            try:
                deadline = time.monotonic() + 30
                while not self.pids.exists() and proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(self.pids.exists(), "audit child never started")
                pids = json.loads(self.pids.read_text())
                self.assertTrue(all(self.running(pid) for pid in pids))
                # The analyzer really is isolated from the module's group.
                self.assertNotEqual(os.getpgid(pids[0]), proc.pid)
                os.killpg(proc.pid, signal.SIGTERM)
                self.assertNotEqual(proc.wait(timeout=5), 0)
                deadline = time.monotonic() + 3
                while any(self.running(pid) for pid in pids) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertFalse(any(self.running(pid) for pid in pids), pids)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                for pid in pids:
                    if self.running(pid):
                        os.kill(pid, signal.SIGKILL)

    @unittest.skipUnless(shutil.which("ruff"), "requires an installed real Ruff")
    def test_real_ruff_keeps_findings_and_recovers_after_failed_audit(self):
        self.failure_tool("ruff", uv=True)
        failed, summary = self.scan("ruff")
        self.assert_partial(failed, summary, "ruff")
        # Use a separate PATH without uv, so the next pass runs genuine Ruff.
        direct = self.root / "direct"
        direct.mkdir()
        (direct / "python3").symlink_to(sys.executable)
        (direct / "ruff").symlink_to(shutil.which("ruff"))
        proc, summary = self.scan("ruff", PATH=f"{direct}:/usr/bin:/bin")
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        self.assertEqual(summary["status"], "ok", summary)
        self.assertNotIn("module_error", summary)
        self.assertGreater(summary["extras"]["profile"]["cache_hits"], 0)
        self.assertIn('"code": "F401"', proc.stdout)
        self.assertIn("Ruff emitted findings", proc.stdout)
        self.assertNotIn("analysis incomplete", proc.stderr)

    def test_retention_skips_inapplicable_dependency_audits_without_launching_tools(self):
        self.source.write_text("answer = 42\n")
        self.audit_tool([], uv=True)
        scratch = self.root / "retained"
        scratch.mkdir()
        for scope in ("no-manifest", "empty-runtime", "selected-file"):
            with self.subTest(scope=scope):
                if scope == "empty-runtime":
                    (self.project / "pyproject.toml").write_text('[project]\ndependencies = []\n')
                elif scope == "selected-file":
                    # A manifest next to the selected file must not widen a
                    # targeted scan into a project dependency audit.
                    (self.project / "pyproject.toml").write_text(
                        '[project]\ndependencies = ["example-package==1.0"]\n')
                    self.project = self.source
                proc, summary = self.scan("pip-audit", format="json", UBS_KEEP_TEMP="1", TMPDIR=str(scratch))
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(summary["status"], "ok", summary)
                self.assertFalse(self.calls.exists(), "a skipped audit launched an external tool")
                outcome = summary["extras"]["external_tools"][0]
                self.assertEqual(outcome["status"], "skipped", outcome)
                self.assertFalse(summary.get("analysis_errors"))
                self.assertNotIn("cannot retain", proc.stderr)

    def test_retention_refuses_required_dependency_audit_before_launch(self):
        self.source.write_text("answer = 42\n")
        self.audit_tool([audit_dependency()], code=1, uv=True)
        scratch = self.root / "retained"
        scratch.mkdir()
        for manifest in ("pyproject.toml", "requirements.txt"):
            with self.subTest(manifest=manifest):
                (self.project / manifest).write_text(
                    '[project]\ndependencies = ["example-package==1.0"]\n'
                    if manifest == "pyproject.toml" else "example-package==1.0\n")
                proc, summary = self.scan("pip-audit", format="json", UBS_KEEP_TEMP="1", TMPDIR=str(scratch))
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertEqual(summary["status"], "partial", summary)
                self.assertEqual(summary["module_error"], "ANALYZER_ERROR", summary)
                self.assertFalse(self.calls.exists(), "retention mode launched an external tool")
                self.assertEqual(summary["extras"]["external_tools"][0]["status"], "partial")
                self.assertTrue(any("cannot retain external analyzer scratch" in row["message"]
                                    for row in summary["analysis_errors"]))
                self.assertIn("UBS_KEEP_TEMP=1", proc.stderr)


if __name__ == "__main__":
    unittest.main()
