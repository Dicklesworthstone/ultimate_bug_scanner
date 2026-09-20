#!/usr/bin/env python3
"""Issue #128: optional Ruby coverage must survive every report/cache path."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core.external_tools import RubyFindings, ToolOutput, run_command, scan_ruby_tools


def rubocop_doc(path: str = "sample.rb") -> dict:
    return {"files": [{"path": path, "offenses": [{
        "cop_name": "Lint/Syntax", "severity": "error", "message": "syntax error",
        "location": {"start_line": 2, "start_column": 1},
    }]}]}


def brakeman_doc(path: str = "sample.rb") -> dict:
    return {"warnings": [{"warning_code": 1, "message": "SQL injection",
                          "confidence": "High", "file": path, "line": 2}], "errors": []}


def audit_doc() -> dict:
    return {"results": [{"type": "unpatched_gem", "gem": {"name": "example", "version": "1.0"},
                         "advisory": {"id": "CVE-2099-0001", "title": "Example vulnerability"}}]}


def reek_doc(path: str = "sample.rb") -> list:
    return [{"source": path, "smell_type": "UnusedParameters", "lines": [2], "message": "unused argument"}]


class RubyToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-ruby-tools-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "sample.rb"
        self.source.write_text('value = 1\nputs value\n', encoding="utf-8")
        (self.root / "config").mkdir()
        (self.root / "config/application.rb").write_text("# Rails application fixture\n")
        (self.root / "Gemfile.lock").write_text("GEM\n  specs:\n    example (1.0)\n")
        self.sink = io.StringIO()

    def scan(self, tool: str, stdout: str, rc: int = 0) -> tuple[list, list, list]:
        errors = []
        with patch("ubs_core.external_tools.shutil.which", return_value="/tool"), \
             patch("ubs_core.external_tools.run_command", return_value=ToolOutput(rc, stdout, "tool diagnostic")):
            outcomes = scan_ruby_tools([self.source], self.sink, str(self.root), tool, 1, errors)
        return [json.loads(line) for line in self.sink.getvalue().splitlines()], errors, outcomes

    def test_documented_findings_exits_are_complete(self) -> None:
        fixtures = [("rubocop", rubocop_doc(), 1), ("brakeman", brakeman_doc(), 3),
                    ("bundler-audit", audit_doc(), 1), ("reek", reek_doc(), 2)]
        for tool, doc, rc in fixtures:
            with self.subTest(tool=tool):
                self.sink = io.StringIO()
                records, errors, outcomes = self.scan(tool, json.dumps(doc), rc)
                self.assertEqual(errors, [])
                self.assertEqual(outcomes, [{"tool": tool, "status": "ok"}])
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["extras"]["tool"], tool)

    def test_empty_json_is_complete_but_empty_bytes_are_partial(self) -> None:
        for tool, doc in [("rubocop", {"files": []}), ("brakeman", {"warnings": [], "errors": []}),
                          ("bundler-audit", {"results": []}), ("reek", [])]:
            with self.subTest(tool=tool):
                self.assertFalse(self.scan(tool, json.dumps(doc))[1])
                for raw in ("", "{", "null", '"broken"', "{}", "[42]"):
                    self.assertTrue(self.scan(tool, raw)[1], (tool, raw))

    def test_failures_preserve_valid_records(self) -> None:
        for tool, doc, rc in [("rubocop", rubocop_doc(), 2), ("brakeman", brakeman_doc(), 7),
                              ("bundler-audit", audit_doc(), 42), ("reek", reek_doc(), 1)]:
            with self.subTest(tool=tool):
                self.sink = io.StringIO()
                records, errors, outcomes = self.scan(tool, json.dumps(doc), rc)
                self.assertEqual(len(records), 1)
                self.assertIn(tool, errors[0])
                self.assertEqual(outcomes[0]["status"], "partial")

    def test_brakeman_embedded_errors_even_with_exit_zero(self) -> None:
        doc = brakeman_doc()
        doc["errors"] = [{"error": "could not parse model"}]
        records, errors, _ = self.scan("brakeman", json.dumps(doc))
        self.assertEqual(len(records), 1)
        self.assertIn("could not parse model", ";".join(errors))

    def test_bad_rows_do_not_discard_good_rows(self) -> None:
        doc = rubocop_doc()
        doc["files"][0]["offenses"].insert(0, {"cop_name": "incomplete"})
        records, errors, _ = self.scan("rubocop", json.dumps(doc), 1)
        self.assertEqual(len(records), 1)
        self.assertTrue(errors)
        doc = audit_doc()
        doc["results"].insert(0, {"type": "unknown"})
        self.sink = io.StringIO()
        records, errors, _ = self.scan("bundler-audit", json.dumps(doc), 1)
        self.assertEqual(len(records), 1)
        self.assertTrue(errors)

    def test_audit_error_exit_with_empty_results_is_not_clean(self) -> None:
        self.assertTrue(self.scan("bundler-audit", '{"results":[]}', 1)[1])

    def test_absent_and_inapplicable_tools_are_skipped(self) -> None:
        errors = []
        with patch("ubs_core.external_tools.shutil.which", return_value=None), \
             patch("ubs_core.external_tools.run_command") as launch:
            outcomes = scan_ruby_tools([self.source], self.sink, str(self.root),
                                      "rubocop,brakeman,bundler-audit,reek,fasterer", 1, errors)
            launch.assert_not_called()
        self.assertFalse(errors)
        self.assertTrue(all(out["status"] == "skipped" for out in outcomes))
        with patch("ubs_core.external_tools.run_command") as launch:
            scan_ruby_tools([], self.sink, str(self.root), "rubocop", 1, errors)
            launch.assert_not_called()

    def test_selected_file_scope_and_suppression(self) -> None:
        self.assertEqual(self.scan("rubocop", json.dumps(rubocop_doc("unselected.rb")), 1)[:2], ([], []))
        self.source.write_text("value = 1\nputs value # ubs:ignore[rb.rubocop.Lint-Syntax]\n")
        self.assertEqual(self.scan("rubocop", json.dumps(rubocop_doc()), 1)[:2], ([], []))

    def test_dependency_findings_have_explicit_project_scope(self) -> None:
        records, errors, _ = self.scan("bundler-audit", json.dumps(audit_doc()), 1)
        self.assertFalse(errors)
        self.assertEqual(records[0]["path"], str(self.root / "Gemfile.lock"))
        self.assertEqual(records[0]["extras"]["scope"], "project")

    def test_fasterer_parse_failure_is_partial_and_keeps_findings(self) -> None:
        raw = "sample.rb:2 Use faster operation.\n1 file inspected, 1 offense detected, 1 unparsable file found\n"
        records, errors, _ = self.scan("fasterer", raw, 1)
        self.assertEqual(len(records), 1)
        self.assertTrue(any("could not be parsed" in error for error in errors))

    def test_fasterer_clean_and_bad_output(self) -> None:
        self.assertFalse(self.scan("fasterer", "1 file inspected, 0 offenses detected\n")[1])
        self.assertTrue(self.scan("fasterer", "No such file or directory\n")[1])

    def test_all_selected_files_passed_without_shell_interpolation(self) -> None:
        odd = self.root / "quoted ' file\nname.rb"
        odd.write_text("value = 1\n")
        errors = []
        with patch("ubs_core.external_tools.shutil.which", return_value="/rubocop"), \
             patch("ubs_core.external_tools.run_command", return_value=ToolOutput(0, '{"files":[]}', "")) as launch:
            scan_ruby_tools([self.source, odd], self.sink, str(self.root), "rubocop,rubocop", 1, errors)
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(launch.call_args.args[1][-2:], [str(self.source), str(odd)])
            self.assertEqual(launch.call_args.args[2], self.root)

    def test_bundle_resolution_distinguishes_absence_and_failure(self) -> None:
        (self.root / "Gemfile").write_text('source "https://rubygems.org"\n')
        for result, expected in [(ToolOutput(0, '{"rubocop":false}', ""), "skipped"),
                                 (ToolOutput(1, "", "missing dependency"), "partial")]:
            with self.subTest(expected=expected):
                errors = []
                with patch("ubs_core.external_tools.shutil.which", return_value="/bundle"), \
                     patch("ubs_core.external_tools.run_command", return_value=result) as launch:
                    outcomes = scan_ruby_tools([self.source], self.sink, str(self.root), "rubocop", 1, errors)
                    self.assertEqual(outcomes[0]["status"], expected)
                    self.assertEqual(launch.call_count, 1)
                    self.assertEqual(launch.call_args.kwargs["env"]["BUNDLE_GEMFILE"], str(self.root / "Gemfile"))

    def test_bundle_exec_runs_in_target_not_caller(self) -> None:
        (self.root / "Gemfile").write_text("# bundle fixture\n")
        errors = []
        results = [ToolOutput(0, '{"rubocop":true}', ""), ToolOutput(0, '{"files":[]}', "")]
        with patch("ubs_core.external_tools.shutil.which", return_value="/bundle"), \
             patch("ubs_core.external_tools.run_command", side_effect=results) as launch:
            scan_ruby_tools([self.source], self.sink, str(self.root), "rubocop", 1, errors)
            self.assertEqual(launch.call_args.args[1][:3], ["/bundle", "exec", "rubocop"])
            self.assertEqual(launch.call_args.args[2], self.root)
        self.assertFalse(errors)

    def test_timeout_and_launch_errors(self) -> None:
        errors = []
        result = run_command("rubocop", ["/nonexistent-ubs-test-tool"], self.root, 1, errors)
        self.assertIsNone(result)
        self.assertIn("could not launch", errors[0])
        errors = []
        result = run_command("rubocop", [sys.executable, "-c", "import time; time.sleep(5)"],
                             self.root, 0.05, errors)
        self.assertIsNotNone(result)
        self.assertTrue(any("timed out" in error for error in errors))
        for timeout in (0, -1, float("nan"), float("inf")):
            errors = []
            self.assertIsNone(run_command("test", ["anything"], self.root, timeout, errors))
            self.assertTrue(errors)


class RubyIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-ruby-integration-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.project = self.base / "project with spaces"
        self.project.mkdir()
        self.source = self.project / "sample.rb"
        self.source.write_text('value = 1\nputs value\n')
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.config = self.base / "tool.json"
        self.log = self.base / "calls.jsonl"
        script = f'''#!{sys.executable}
import json, os, pathlib, sys, time
cfg = json.loads(pathlib.Path(os.environ["RUBY_TOOL_CONFIG"]).read_text())
with open(os.environ["RUBY_TOOL_LOG"], "a") as out:
    out.write(json.dumps({{"tool": pathlib.Path(sys.argv[0]).name, "args": sys.argv[1:], "cwd": os.getcwd()}}) + "\\n")
time.sleep(cfg.get("sleep", 0))
print(cfg.get("raw", json.dumps(cfg.get("doc", {{"files": []}}))))
sys.exit(cfg.get("exit", 0))
'''
        for tool in ("rubocop", "brakeman", "bundle-audit", "reek", "fasterer"):
            (self.bin / tool).write_text(script)
            (self.bin / tool).chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ.get('PATH', '')}",
                        RUBY_TOOL_CONFIG=str(self.config), RUBY_TOOL_LOG=str(self.log),
                        UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0", CI="1", NO_COLOR="1",
                        UBS_TEST_FORCE_NO_AST_GREP="1", RB_TOOLS="rubocop", RB_TIMEOUT="2",
                        UBS_CACHE_DIR=str(self.base / "cache"), PYTHONDONTWRITEBYTECODE="1")
        self.env.pop("UBS_NO_CACHE", None)
        self.env.pop("UBS_VERIFIED_ASSET_DIR", None)
        self.env.pop("UBS_ALLOW_UNVERIFIED_HELPERS", None)
        self.configure(rubocop_doc(), 1)

    def configure(self, doc: object = None, rc: int = 0, **kwargs) -> None:
        self.config.write_text(json.dumps({"doc": doc, "exit": rc, **kwargs}))

    def run_scan(self, fmt: str = "json", *extra: str, meta: bool = False, tool: str = "rubocop"):
        cmd = [str(ROOT / "ubs"), "--only=ruby"] if meta else ["bash", str(ROOT / "modules/ubs-ruby.sh")]
        return subprocess.run([*cmd, str(self.project), "--ci", f"--format={fmt}", *extra],
                              cwd=self.base, env=dict(self.env, RB_TOOLS=tool), capture_output=True,
                              text=True, timeout=45, check=False)

    def assert_scan(self, result, rc: int):
        self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_module_and_meta_report_same_external_findings(self) -> None:
        for meta in (False, True):
            with self.subTest(meta=meta):
                doc = self.assert_scan(self.run_scan(meta=meta), 1)
                scanner = doc["scanners"][0] if meta else doc
                self.assertEqual(scanner["status"], "ok")
                self.assertTrue(any(r.get("rule", r.get("rule_id", "")).startswith("rb.rubocop.")
                                    for r in scanner["findings"]))

    def test_partial_json_sarif_and_text_keep_native_evidence(self) -> None:
        self.source.write_text('value = 1\nputs value\neval(params[:input])\n')
        self.configure(rubocop_doc(), 2)
        for fmt in ("json", "sarif", "text"):
            with self.subTest(fmt=fmt):
                proc = self.run_scan(fmt)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                if fmt == "json":
                    doc = json.loads(proc.stdout)
                    self.assertEqual(doc["status"], "partial")
                    self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
                    self.assertTrue(any(r["rule"].startswith("rb.rubocop.") for r in doc["findings"]))
                    self.assertTrue(any(not r["rule"].startswith("rb.rubocop.") for r in doc["findings"]))
                elif fmt == "sarif":
                    doc = json.loads(proc.stdout)
                    self.assertTrue(any(not inv["executionSuccessful"] for run in doc["runs"] for inv in run["invocations"]))
                    self.assertTrue(any(r["ruleId"].startswith("rb.rubocop.") for run in doc["runs"] for r in run["results"]))
                else:
                    self.assertIn("Partial: [ANALYZER_ERROR]", proc.stdout)
                    self.assertIn("rb.rubocop.", proc.stdout)

    def test_each_default_security_tool_reaches_machine_reports(self) -> None:
        (self.project / "config").mkdir()
        (self.project / "config/application.rb").write_text("# application\n")
        (self.project / "Gemfile.lock").write_text("GEM\n  specs:\n    example (1.0)\n")
        for tool, doc, rc in [("brakeman", brakeman_doc(), 3), ("bundler-audit", audit_doc(), 1)]:
            with self.subTest(tool=tool):
                self.configure(doc, rc)
                result = self.assert_scan(self.run_scan(tool=tool), 1)
                self.assertTrue(any(r["rule"].startswith(f"rb.{tool}.") for r in result["findings"]))
                self.configure(raw="network or database failed", rc=1)
                self.assertEqual(self.assert_scan(self.run_scan(tool=tool), 2)["status"], "partial")

    def test_warm_cache_does_not_hide_failure_or_stale_vulnerabilities(self) -> None:
        first = self.assert_scan(self.run_scan(), 1)
        self.configure(raw="broken output", rc=2)
        second = self.assert_scan(self.run_scan(), 2)
        self.assertEqual(second["status"], "partial")
        self.configure({"files": []}, 0)
        third = self.assert_scan(self.run_scan(), 0)
        self.assertEqual(third["status"], "ok")
        self.assertFalse(any(r["rule"].startswith("rb.rubocop.") for r in third["findings"]))
        self.assertEqual(len(self.log.read_text().splitlines()), 3)
        self.assertGreater(third["extras"]["profile"]["cache_hits"], 0)

    def test_disable_and_category_skip_do_not_launch(self) -> None:
        for arg in ("--no-bundler", "--skip=19", "--only=1"):
            with self.subTest(arg=arg):
                self.assert_scan(self.run_scan("json", arg), 0)
                self.assertFalse(self.log.exists())

    def test_warning_finding_obeys_ubs_severity_policy(self) -> None:
        doc = rubocop_doc()
        doc["files"][0]["offenses"][0]["severity"] = "warning"
        self.configure(doc, 1)
        self.assert_scan(self.run_scan(), 0)
        self.assert_scan(self.run_scan("json", "--fail-on-warning"), 1)

    def test_subprocess_timeout_is_partial(self) -> None:
        self.env["RB_TIMEOUT"] = "0.05"
        self.configure({"files": []}, 0, sleep=1)
        doc = self.assert_scan(self.run_scan(), 2)
        self.assertIn("timed out", doc["message"])

    def test_machine_scan_runs_in_target_cwd_and_respects_files_from(self) -> None:
        unselected = self.project / "other.rb"
        unselected.write_text("value = 1\n")
        paths = self.base / "files.nul"
        paths.write_bytes(os.fsencode(self.source) + b"\0")
        self.configure(rubocop_doc("other.rb"), 1)
        result = self.assert_scan(self.run_scan("json", f"--files-from={paths}"), 0)
        self.assertFalse(result["findings"])
        call = json.loads(self.log.read_text().splitlines()[0])
        self.assertEqual(call["cwd"], str(self.project))
        self.assertIn(str(self.source), call["args"])
        self.assertNotIn(str(unselected), call["args"])


if __name__ == "__main__":
    unittest.main()
