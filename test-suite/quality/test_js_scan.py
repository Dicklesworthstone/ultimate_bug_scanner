#!/usr/bin/env python3
"""Unit tests for ubs_core.js_scan — contract-v2 pattern layer (bead 0xjg.4)."""
from __future__ import annotations

import json
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

import re  # noqa: E402

from ubs_core.js_scan import (  # noqa: E402
    Pattern,
    _record_category,
    iter_matches,
    load_patterns,
    resolve_severity,
    scan_patterns,
)


def _pat(**overrides) -> Pattern:
    fields = dict(
        category=11,
        rule_id="js.debug.debugger",
        title="debugger statements",
        regex=re.compile(r"\bdebugger\b"),
        thresholds=((0, "critical"),),
    )
    fields.update(overrides)
    return Pattern(**fields)


class ThresholdTests(unittest.TestCase):
    def test_ladder_first_match_wins(self) -> None:
        p = _pat(thresholds=((50, "warning"), (20, "info")))
        self.assertEqual(resolve_severity(p, 51), "warning")
        self.assertEqual(resolve_severity(p, 21), "info")
        self.assertIsNone(resolve_severity(p, 20))  # exclusive: 20 is not > 20

    def test_exact_counts_are_exclusive(self) -> None:
        p = _pat(thresholds=((15, "warning"), (0, "info")))
        self.assertEqual(resolve_severity(p, 16), "warning")
        self.assertEqual(resolve_severity(p, 15), "info")


class MatchTests(unittest.TestCase):
    def test_marker_lines_excluded(self) -> None:
        p = _pat()
        text = "debugger;\ndebugger;  # ubs:ignore\n"
        hits = list(iter_matches(p, text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 1)

    def test_exclude_regex_drops_lines(self) -> None:
        p = _pat(
            regex=re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*!"),
            exclude_regex=re.compile(r"!=|!=="),
        )
        text = "a!.b;\nif (x !== y) { z!; }\n"
        hits = list(iter_matches(p, text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 1)


class ScanTests(unittest.TestCase):
    def test_counters_and_sink_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-jsv2-") as tmp:
            src = Path(tmp) / "s.js"
            src.write_text("debugger;\n// TODO: x\n// FIXME: y\n", encoding="utf-8")
            sink_path = Path(tmp) / "sink.ndjson"
            patterns = [
                _pat(),
                _pat(
                    category=14,
                    rule_id="js.markers.todo-family",
                    title="Technical debt markers",
                    regex=re.compile(r"TODO|FIXME"),
                    thresholds=((0, "info"),),
                ),
            ]
            with sink_path.open("w", encoding="utf-8") as sink:
                counters = scan_patterns(patterns, [src], sink, skip=set())
            self.assertEqual(counters, {"critical": 1, "warning": 0, "info": 2})
            records = [json.loads(line) for line in sink_path.read_text().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["rule"], "js.debug.debugger")
            self.assertEqual(records[0]["severity"], "critical")
            self.assertTrue(all(r["category_id"] for r in records))

    def test_skip_category_silences_patterns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-jsv2-") as tmp:
            src = Path(tmp) / "s.js"
            src.write_text("debugger;\n", encoding="utf-8")
            sink_path = Path(tmp) / "sink.ndjson"
            with sink_path.open("w", encoding="utf-8") as sink:
                counters = scan_patterns([_pat()], [src], sink, skip={11})
            self.assertEqual(counters["critical"], 0)
            self.assertEqual(sink_path.read_text(), "")


class ExemplarPatternsTests(unittest.TestCase):
    def test_exemplar_module_loads(self) -> None:
        patterns = load_patterns()
        rules = {p.rule_id for p in patterns}
        self.assertIn("js.debug.debugger", rules)
        self.assertIn("js.markers.todo-family", rules)
        self.assertIn("js.typescript.non-null-assertion", rules)


@unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep required")
class CustomPolicyIntegrationTests(unittest.TestCase):
    """Requested policies must reach the real analyzer, report and exit gate."""

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="js-policy-", dir=artifacts)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.rules = self.root / "team's policies"
        self.rules.mkdir()
        self.source = self.project / "sample.js"
        self.source.write_text("policyProbe();\n")

    def policy(self, name="policy.yml", rule_id="org.must-not-call", language="javascript"):
        path = self.rules / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f'id: "{rule_id}"\nlanguage: {language}\nseverity: error\n'
            'message: Project policy violation\nrule:\n  pattern: policyProbe()\n'
        )
        return path

    def scan(self, *args, meta=False, env=None):
        command = REPO_ROOT / ("ubs" if meta else "modules/ubs-js.sh")
        return subprocess.run(
            [str(command), "--format=json", "--no-color", f"--rules={self.rules}",
             *args, str(self.project)], cwd=self.root,
            env={**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1",
                 "UBS_SKIP_TYPE_NARROWING": "1", **(env or {})},
            capture_output=True, text=True, timeout=45,
        )

    def assert_policy(self, result, rule_id="org.must-not-call"):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn(rule_id, result.stdout)
        return report

    def test_error_policy_is_critical_without_fail_on_warning(self):
        self.policy()
        report = self.assert_policy(self.scan())
        self.assertGreater(report["critical"], 0)

    def test_nested_yaml_policy_reaches_meta_runner(self):
        self.policy("nested/custom.yaml")
        self.assert_policy(self.scan(meta=True))

    def test_custom_policy_is_not_downgraded_by_builtin_async_calibration(self):
        self.policy(rule_id="js.async.await-no-try")
        self.assert_policy(self.scan(), "js.async.await-no-try")

    def test_custom_policy_does_not_inherit_builtin_listener_filter(self):
        self.policy(rule_id="js.resource.listener-no-remove")
        self.assert_policy(self.scan(), "js.resource.listener-no-remove")

    def test_custom_filename_cannot_be_overwritten_by_builtin(self):
        self.policy("parseInt-no-radix.yml")
        self.assert_policy(self.scan())

    def test_multiple_documents_and_quoted_ids_are_all_counted(self):
        path = self.policy()
        path.write_text(path.read_text() + '\n---\n' +
                        path.read_text().replace('org.must-not-call', 'org.second-policy'))
        report = self.assert_policy(self.scan())
        self.assertIn("org.second-policy", json.dumps(report))

    def test_typescript_and_tsx_keep_the_authored_grammar(self):
        self.source.write_text("const value = 1;\n")
        for suffix, language in (("ts", "typescript"), ("tsx", "tsx")):
            with self.subTest(language=language):
                self.policy(f"{suffix}.yaml", f"org.{suffix}", language)
                (self.project / f"sample.{suffix}").write_text("policyProbe();\n")
                self.assert_policy(self.scan(), f"org.{suffix}")

    def test_invalid_policy_never_becomes_success(self):
        self.policy().write_text("id: broken\nlanguage: javascript\nrule: [\n")
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_empty_policy_never_becomes_success(self):
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("rules", result.stderr.lower())

    def test_missing_policy_never_becomes_success(self):
        self.rules = self.root / "missing-policy"
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_policy_not_filtered_by_native_token_prefilter(self):
        self.policy().write_text('id: org.loop\nlanguage: javascript\nseverity: error\n'
                                 'rule:\n  kind: while_statement\n')
        self.source.write_text("while (ready) { tick(); }\n")
        self.assert_policy(self.scan(), "org.loop")

    def test_list_and_dump_include_nested_yaml_without_flattening(self):
        self.policy("nested/custom.yaml")
        dump = self.root / "team's dump"
        result = self.scan("--list-rules", f"--dump-rules={dump}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("org.must-not-call", result.stdout)
        self.assertTrue((dump / "rules/custom/nested/custom.yaml").is_file())
        self.assertTrue((dump / "sgconfig-custom.yml").is_file())

    def test_custom_cache_is_invalidated_when_policy_changes(self):
        path = self.policy("nested/custom.yaml")
        path.write_text(path.read_text().replace("policyProbe()", "notCalled()"))
        env = {"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(self.root / "cache")}
        first = self.scan(env=env)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.policy("nested/custom.yaml")
        self.assert_policy(self.scan(env=env))

    def broken_analyzer(self):
        binary = self.root / "ast-grep"
        state = self.root / "analyzer-state"
        state.write_text("broken")
        binary.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\nfrom pathlib import Path\n"
            "if '--version' in sys.argv:\n    print('ast-grep 0.45.3'); sys.exit(0)\n"
            "if '-c' not in sys.argv:\n    sys.exit(0)\n"
            "config = sys.argv[sys.argv.index('-c') + 1]\n"
            "if not config.endswith('sgconfig-custom.yml'):\n    sys.exit(0)\n"
            "print(json.dumps({'ruleId': 'org.must-not-call', 'file': sys.argv[-1],\n"
            "    'range': {'start': {'line': 0, 'column': 0}}, 'severity': 'error',\n"
            "    'message': 'Retained policy finding'}))\n"
            f"if Path({str(state)!r}).read_text() == 'broken':\n    print('{{invalid-json')\n"
        )
        binary.chmod(0o755)
        return binary, state

    def test_partial_findings_reach_every_meta_renderer(self):
        self.policy()
        binary, _ = self.broken_analyzer()
        for fmt in ("json", "jsonl", "sarif", "text"):
            with self.subTest(format=fmt):
                result = self.scan(f"--format={fmt}", meta=True,
                                   env={"UBS_AST_GREP_BIN": str(binary),
                                        "PATH": str(binary.parent) + os.pathsep + os.environ["PATH"]})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("org.must-not-call", result.stdout)
                if fmt == "json":
                    self.assertEqual(json.loads(result.stdout)["status"], "partial")
                elif fmt == "jsonl":
                    records = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(records[-1]["status"], "partial")
                elif fmt == "sarif":
                    runs = json.loads(result.stdout)["runs"]
                    self.assertTrue(any(inv.get("executionSuccessful") is False
                                        for run in runs for inv in run.get("invocations", [])))
                else:
                    self.assertIn("Partial: [ANALYZER_ERROR]", result.stdout)
                    self.assertNotIn("good:", result.stdout)

    def test_failed_analysis_is_retried_and_can_recover_with_cache_enabled(self):
        self.policy()
        binary, state = self.broken_analyzer()
        env = {"UBS_AST_GREP_BIN": str(binary), "UBS_NO_CACHE": "0",
               "UBS_CACHE_DIR": str(self.root / "cache")}
        for _ in range(2):
            result = self.scan(env=env)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "partial")
        state.write_text("healthy")
        self.assert_policy(self.scan(env=env))

    @unittest.skipUnless(os.name == "posix" and Path("/proc").exists(), "Linux process-group check")
    def test_meta_deadline_stops_isolated_analyzer(self):
        import signal
        import time
        self.policy()
        binary = self.root / "ast-grep"
        pid_file = self.root / "analyzer.pid"
        binary.write_text(
            f"#!{sys.executable}\n"
            "import os, sys, time\nfrom pathlib import Path\n"
            "if '--version' in sys.argv:\n    print('ast-grep 0.45.3'); sys.exit(0)\n"
            "if '-c' not in sys.argv:\n    sys.exit(0)\n"
            f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
            "time.sleep(30)\n"
        )
        binary.chmod(0o755)
        try:
            result = self.scan(meta=True, env={
                "PATH": str(binary.parent) + os.pathsep + os.environ["PATH"],
                "UBS_MODULE_TIMEOUT": "4", "UBS_MODULE_TIMEOUT_GRACE": "1",
            })
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("MODULE_TIMEOUT", result.stdout + result.stderr)
            self.assertTrue(pid_file.is_file(), result.stdout + result.stderr)
            state = Path(f"/proc/{int(pid_file.read_text())}/stat")
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    child_state = state.read_text().split()[2]
                except FileNotFoundError:
                    break
                if child_state == "Z":
                    break
                self.assertLess(time.monotonic(), deadline, "analyzer survived the module deadline")
                time.sleep(0.01)
        finally:
            if pid_file.is_file():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


class AstCompletenessTests(unittest.TestCase):
    """Broken analyzer output must retain evidence and fail the coverage gate."""

    def setUp(self):
        from ubs_core import js_ast
        self.ast = js_ast
        self.tmp = tempfile.TemporaryDirectory(prefix="js-ast-boundary-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "sgconfig-custom.yml"
        self.config.write_text("ruleDirs: []\n")
        self.source = self.root / "sample.js"
        self.source.write_text("policyProbe();\n")
        self.match = {
            "ruleId": "org.critical-policy", "file": str(self.source),
            "range": {"start": {"line": 0, "column": 0}},
            "severity": "error", "message": "Policy violation",
        }

    def invoke(self, stdout, returncode=0, **kwargs):
        from ubs_core.external_tools import ToolOutput
        sink, errors = io.StringIO(), []
        with mock.patch.object(self.ast, "run_command", return_value=ToolOutput(returncode, stdout, "")):
            counts = self.ast.scan_config(
                self.config, [self.source], sink, "custom", errors=errors, **kwargs,
            )
        records = [json.loads(line) for line in sink.getvalue().splitlines()]
        return counts, records, errors

    def test_invalid_json_keeps_valid_diagnostics(self):
        counts, records, errors = self.invoke("{broken\n" + json.dumps(self.match) + '\n{"truncated":')
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(records[0]["line"], 1)
        self.assertIn("2 malformed diagnostic(s)", errors[0])

    def test_invalid_record_shapes_never_crash_or_look_clean(self):
        invalid = [None, [], 1, "diagnostic", {}, {**self.match, "ruleId": []},
                   {**self.match, "file": 42}, {**self.match, "file": "a\0.js"},
                   {**self.match, "range": None}, {**self.match, "range": {"start": []}},
                   {**self.match, "severity": "fatal-typo"}, {**self.match, "message": {}}]
        for record in invalid:
            with self.subTest(record=record):
                counts, rows, errors = self.invoke(json.dumps(record) + "\n" + json.dumps(self.match))
                self.assertEqual(counts["critical"], 1)
                self.assertEqual(len(rows), 1)
                self.assertTrue(errors)

    def test_invalid_positions_are_not_invented_as_line_one(self):
        for field in ("line", "column"):
            for value in (None, -1, True, 1.5, "1", [], {}):
                with self.subTest(field=field, value=value):
                    start = {"line": 0, "column": 0, field: value}
                    record = {**self.match, "range": {"start": start}}
                    counts, rows, errors = self.invoke(json.dumps(record))
                    self.assertEqual(sum(counts.values()), 0)
                    self.assertFalse(rows)
                    self.assertTrue(errors)

    def test_error_exit_without_evidence_is_partial(self):
        counts, rows, errors = self.invoke("", returncode=1)
        self.assertFalse(rows)
        self.assertEqual(sum(counts.values()), 0)
        self.assertIn("without valid diagnostics", errors[0])

    def test_successful_empty_stream_is_complete(self):
        _, rows, errors = self.invoke(" \n\n")
        self.assertFalse(rows or errors)

    def test_filtered_valid_diagnostic_does_not_become_analyzer_error(self):
        _, rows, errors = self.invoke(json.dumps(self.match), returncode=1, count_only=set())
        self.assertFalse(rows or errors)

    def test_abnormal_exit_keeps_findings(self):
        counts, rows, errors = self.invoke(json.dumps(self.match), returncode=2)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(len(rows), 1)
        self.assertIn("exited 2", errors[0])

    def test_many_malformed_records_have_bounded_diagnostics(self):
        _, _, errors = self.invoke("not-json\n" * 10000)
        self.assertEqual(len(errors), 1)
        self.assertIn("10000 malformed", errors[0])
        self.assertLess(len(errors[0]), 400)

    def test_missing_config_is_not_a_clean_scan(self):
        sink, errors = io.StringIO(), []
        self.ast.scan_config(self.root / "absent.yml", [self.source], sink, "custom", errors=errors)
        self.assertTrue(errors)
        self.assertEqual(sink.getvalue(), "")

    def test_missing_rule_pack_is_not_a_clean_scan(self):
        errors = []
        self.ast.scan_all(self.root / "absent", [self.source], io.StringIO(), errors=errors)
        self.assertTrue(errors)

    def test_missing_grammar_is_partial_even_with_other_configs_present(self):
        errors = []
        from ubs_core.external_tools import ToolOutput
        with mock.patch.object(self.ast, "run_command", return_value=ToolOutput(0, "", "")):
            self.ast.scan_all(self.root, [self.source], io.StringIO(), errors=errors)
        self.assertEqual(len(errors), 3)
        self.assertTrue(any("typescript" in error for error in errors))

    def test_empty_selection_does_not_require_config(self):
        errors = []
        self.ast.scan_config(self.root / "absent.yml", [], io.StringIO(), "custom", errors=errors)
        self.assertFalse(errors)

    def test_partial_output_sets_summary_exit_and_refuses_cache(self):
        from ubs_core import js_scan
        from ubs_core.cache import ScanCache
        from ubs_core.external_tools import ToolOutput
        selected = self.root / "files.list"
        selected.write_bytes(os.fsencode(self.source) + b"\0")
        report = self.root / "report.json"
        result = ToolOutput(0, json.dumps(self.match) + "\ninvalid-json\n", "")
        for grammar in ("javascript", "typescript", "tsx"):
            (self.root / f"sgconfig-{grammar}.yml").write_text("ruleDirs: []\n")
        def analyzer(tool, *args, **kwargs):
            return result if "custom" in tool else ToolOutput(0, "", "")
        with mock.patch.object(self.ast, "run_command", side_effect=analyzer), \
                mock.patch.object(ScanCache, "store_scanned_files") as store, \
                mock.patch.dict(os.environ, {"UBS_CACHE_DIR": str(self.root / "cache"), "UBS_NO_CACHE": "0"}):
            code = js_scan.main([
                "--files-from", str(selected), "--sink", str(self.root / "findings.jsonl"),
                "--json-out", str(report), "--project-dir", str(self.root),
                "--ast-rule-dir", str(self.root),
            ])
        self.assertEqual(code, 2)
        doc = json.loads(report.read_text())
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
        self.assertEqual(doc["critical"], 1)
        self.assertIn("org.critical-policy", report.read_text())
        store.assert_not_called()

    def real_analyzer(self, body):
        binary = self.root / "ast-grep"
        binary.write_text(f"#!{sys.executable}\n" + body)
        binary.chmod(0o755)
        sink, errors = io.StringIO(), []
        with mock.patch.dict(os.environ, {"UBS_AST_GREP_BIN": str(binary)}):
            counts = self.ast.scan_config(self.config, [self.source], sink, "custom", errors=errors)
        return counts, [json.loads(line) for line in sink.getvalue().splitlines()], errors

    def test_invalid_utf8_marks_partial_without_losing_valid_prefix(self):
        payload = (json.dumps(self.match) + "\n").encode() + b"\xff\n"
        counts, rows, errors = self.real_analyzer(f"import sys\nsys.stdout.buffer.write({payload!r})\n")
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(any("UTF-8" in error for error in errors), errors)

    def test_output_limit_is_partial_and_preserves_complete_prefix(self):
        from ubs_core import external_tools
        prefix = json.dumps(self.match) + "\n"
        with mock.patch.object(external_tools, "OUTPUT_LIMIT", len(prefix.encode()) + 10):
            counts, rows, errors = self.real_analyzer(
                f"import sys\nsys.stdout.write({prefix!r} + 'x' * 10000)\n"
            )
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(any("output exceeds" in error for error in errors), errors)

    def test_timeout_preserves_flushed_findings(self):
        with mock.patch.object(self.ast, "_TIMEOUT", 1.0):
            counts, rows, errors = self.real_analyzer(
                f"import sys, time\nprint({json.dumps(self.match)!r}, flush=True)\ntime.sleep(30)\n"
            )
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(any("timed out" in error for error in errors), errors)

    @unittest.skipUnless(os.name == "posix" and Path("/proc").exists(), "Linux process-group check")
    def test_timeout_stops_analyzer_descendants(self):
        import signal
        import time
        pid_file = self.root / "child.pid"
        try:
            with mock.patch.object(self.ast, "_TIMEOUT", 1.0):
                _, _, errors = self.real_analyzer(
                    "import subprocess, sys, time\nfrom pathlib import Path\n"
                    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                    f"Path({str(pid_file)!r}).write_text(str(child.pid))\n"
                    f"print({json.dumps(self.match)!r}, flush=True)\ntime.sleep(30)\n"
                )
            self.assertTrue(any("timed out" in error for error in errors), errors)
            self.assertTrue(pid_file.is_file())
            child_pid = int(pid_file.read_text())
            state = Path(f"/proc/{child_pid}/stat")
            # Waiting for the direct child does not wait for its descendants.
            # Give group SIGKILL delivery a bounded grace period, but fail if
            # the descendant remains alive (its own sleep lasts 30 seconds).
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    child_state = state.read_text().split()[2]
                except FileNotFoundError:
                    break
                if child_state == "Z":
                    break
                self.assertLess(time.monotonic(), deadline, "analyzer child is still running")
                time.sleep(0.01)
        finally:
            # Do not leave a live test child behind if the assertion regresses.
            if pid_file.is_file():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_missing_binary_is_partial(self):
        errors = []
        with mock.patch.dict(os.environ, {"UBS_AST_GREP_BIN": str(self.root / "absent")}):
            self.ast.scan_config(self.config, [self.source], io.StringIO(), "custom", errors=errors)
        self.assertTrue(any("could not launch" in error for error in errors), errors)

    @unittest.skipUnless(os.name == "posix", "POSIX signal handlers")
    def test_execution_restores_signal_handlers(self):
        import signal
        signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        before = {sig: signal.getsignal(sig) for sig in signals}
        self.real_analyzer("pass\n")
        self.assertEqual({sig: signal.getsignal(sig) for sig in signals}, before)
        with mock.patch.object(self.ast, "_TIMEOUT", 0.2):
            self.real_analyzer("import time\ntime.sleep(30)\n")
        self.assertEqual({sig: signal.getsignal(sig) for sig in signals}, before)

    @unittest.skipUnless(os.name == "posix", "POSIX signal handlers")
    def test_execution_respects_explicit_signal_policy(self):
        import signal
        previous = signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            self.real_analyzer("pass\n")
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGTERM, previous)

    def test_process_runner_can_be_called_from_worker_thread(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            counts, rows, errors = executor.submit(self.real_analyzer, "pass\n").result(timeout=5)
        self.assertFalse(rows or errors)
        self.assertEqual(sum(counts.values()), 0)


class MaskRegexTests(unittest.TestCase):
    """Pattern.mask_regex blanks an idiom before the search without moving
    line numbers or hiding the rest of the line."""

    def test_masked_span_is_invisible_but_the_rest_of_the_line_counts(self) -> None:
        p = _pat(
            regex=re.compile(r"\bdebugger\b"),
            mask_regex=re.compile(r"debugger\s*;\s*//\s*allowed"),
        )
        text = "\n".join([
            "debugger; // allowed",
            "debugger; // allowed  debugger;",
            "debugger;",
        ])
        hits = list(iter_matches(p, text))
        self.assertEqual([line for line, _ in hits], [2, 3])
        # Reported text is the original source, not the masked copy.
        self.assertEqual(hits[0][1], "debugger; // allowed  debugger;")


class LooseEqualityNullishTests(unittest.TestCase):
    """GH #137: `x == null` / `x != undefined` is the deliberate nullish idiom
    (ESLint eqeqeq "smart" exempts it); every other loose comparison on the
    same line must still count."""

    def setUp(self) -> None:
        patterns = [p for p in load_patterns() if p.rule_id == "js.type-coercion.loose-equality"]
        self.assertEqual(len(patterns), 1)
        self.pattern = patterns[0]

    def hits(self, text: str) -> list[int]:
        return [line for line, _ in iter_matches(self.pattern, text)]

    def test_nullish_comparisons_are_exempt(self) -> None:
        src = "\n".join([
            "if (value == null) {",
            "const unknown = summary?.costUsd == null;",
            "meta.agentUsed != null && meta.originalModel != null",
            "if (leaders.get(key) == null) {}",
            "if (x == undefined) {}",
            "if (null == x) {}",
            "if (undefined != x) {}",
            "x==null",
        ])
        self.assertEqual(self.hits(src), [])

    def test_other_loose_comparisons_still_report(self) -> None:
        src = "\n".join([
            "if (x == 'x') {}",              # 1
            "if (x == null && y == 5) {}",   # 2: the nullish half is masked, y == 5 is not
            "if (x == nullable) {}",         # 3: not the literal null
            "if (x == undefinedValue) {}",   # 4
            "x==5",                          # 5
            "if (typeof x == 'string') {}",  # 6
            "if (a === null) {}",            # strict: never reported
            "if (a <= null) {}",             # relational: never reported
        ])
        self.assertEqual(self.hits(src), [1, 2, 3, 4, 5, 6])


class AnalyzerCategoryTests(unittest.TestCase):
    """GH #134: analyzer findings must resolve to the category number that
    --skip and the text renderer use, whatever prefix their rule id carries."""

    def test_ctcompare_maps_to_security(self) -> None:
        self.assertEqual(_record_category({"rule": "javascript.ctcompare.unsafe_secret_compare"}), 7)

    def test_explicit_category_id_is_honoured(self) -> None:
        self.assertEqual(_record_category({"rule": "javascript.something.new",
                                           "category_id": "js.type-coercion"}), 4)
        self.assertEqual(_record_category({"rule": "javascript.something.new",
                                           "category_id": "js.security"}), 7)

    def test_unknown_rule_without_category_stays_unmapped(self) -> None:
        self.assertIsNone(_record_category({"rule": "javascript.something.new"}))
        self.assertIsNone(_record_category({"rule": "javascript.something.new",
                                            "category_id": "js.not-a-category"}))


class MetaRunnerRegressionTests(unittest.TestCase):
    """End-to-end through the meta-runner, the way the reports were filed."""

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="js-issue-", dir=artifacts)
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()

    def scan(self, *args):
        result = subprocess.run(
            [str(REPO_ROOT / "ubs"), "--format=json", "--no-color", "--ci", "--only=js",
             *args, str(self.project)], cwd=self.tmp.name,
            env={**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1",
                 "UBS_SKIP_TYPE_NARROWING": "1"},
            capture_output=True, text=True, timeout=120,
        )
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        report = json.loads(result.stdout)
        rules = sorted(f["rule"] for s in report["scanners"] for f in s.get("findings", []))
        return report, rules

    def test_gh134_skip_category_reaches_ctcompare_findings(self) -> None:
        (self.project / "a.ts").write_text(
            "export function nonceReplayCheck(sessionNonce: string, expectedNonce: string): boolean {\n"
            "  return sessionNonce === expectedNonce;\n}\n"
        )
        report, rules = self.scan()
        self.assertIn("javascript.ctcompare.unsafe_secret_compare", rules)
        self.assertEqual(report["totals"]["critical"], 1, report)
        report, rules = self.scan("--skip=js.security")
        self.assertEqual(rules, [], report)
        self.assertEqual(report["totals"]["critical"], 0, report)

    def test_gh137_nullish_check_is_not_a_loose_equality_finding(self) -> None:
        (self.project / "nullish.ts").write_text(
            "export function label(value: string | null | undefined): string {\n"
            "  if (value == null) {\n    return \"unknown\";\n  }\n"
            "  const unknown = value != null;\n"
            "  return value;\n}\n"
        )
        report, rules = self.scan()
        self.assertNotIn("js.type-coercion.loose-equality", rules, report)
        (self.project / "loose.ts").write_text(
            "export function isX(value: string): boolean {\n  return value == \"x\";\n}\n"
        )
        report, rules = self.scan()
        self.assertIn("js.type-coercion.loose-equality", rules, report)
        loose = [f for s in report["scanners"] for f in s.get("findings", [])
                 if f["rule"] == "js.type-coercion.loose-equality"]
        self.assertEqual([(Path(f["path"]).name, f["line"]) for f in loose], [("loose.ts", 2)])



if __name__ == "__main__":
    unittest.main()
