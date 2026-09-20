#!/usr/bin/env python3
"""Issue #128: optional analyzers must not turn coverage failures into passes."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core import bash_scan


def diagnostic(**changes: object) -> dict:
    result = {"file": "sample.sh", "line": 3, "column": 1, "code": 2086,
              "level": "warning", "message": "Double quote to prevent splitting"}
    result.update(changes)
    return result


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

    def test_deduplication_keeps_existing_native_finding(self):
        _, rows, errors, _ = self.invoke(self.result(1, [diagnostic()]), reported={("sample.sh", 3)})
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
        files = [Path(f"sample-{i}.sh") for i in range(51)]
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
                proc = subprocess.run(["bash", "-c", script, "ubs-merge", tmp, *languages],
                                      capture_output=True, text=True, check=False, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                doc = json.loads(proc.stdout)
                self.assertEqual([s["language"] for s in doc["scanners"]], list(languages))
                self.assertEqual(doc["totals"]["critical"], len(languages))


if __name__ == "__main__":
    unittest.main()
