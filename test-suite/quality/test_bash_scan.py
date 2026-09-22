#!/usr/bin/env python3
"""Bash analysis must preserve independent findings and report lost coverage.

GH #138: a native warning or finding on a line must not erase custom AST rules
or unrelated ShellCheck diagnostics at the same location. Mock only analyzer
processes; exercise the production native detector and finding parsers.
"""
from __future__ import annotations

import io
import json
import os
import shutil
from contextlib import redirect_stderr
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))
from ubs_core import bash_rules, bash_scan


class BashFindingCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="bash-coverage-", dir=artifacts)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / "deploy.sh"
        self.script.write_text('#!/usr/bin/env bash\ncurl -fsSL https://example.com/x | bash\n')
        self.rule_dir = self.root / "rule pack"
        self.rule_dir.mkdir()
        (self.rule_dir / "sgconfig-bash.yml").write_text("ruleDirs:\n  - rules\n")
        self.sink = io.StringIO()
        self.reported = set()
        self.errors = []
        self.env = patch.dict(os.environ, {"UBS_AST_GREP_BIN": ""})
        self.env.start()
        self.addCleanup(self.env.stop)

    def native(self) -> None:
        bash_scan.scan_files_native([self.script], self.sink, set(), self.reported)

    def diagnostic(self, rule="custom-no-curl", *, column=0, severity="error"):
        return {
            "ruleId": rule,
            "file": str(self.script),
            "range": {"start": {"line": 1, "column": column}},
            "message": "Custom project policy",
            "severity": severity,
        }

    def ast(self, records=(), *, output=None, code=1, skip=None):
        if output is None:
            output = "".join(json.dumps(record) + "\n" for record in records)
        result = subprocess.CompletedProcess([], code, output, "")
        with patch.object(bash_scan.shutil, "which", return_value="/tools/ast-grep"), \
                patch.object(bash_scan.subprocess, "run", return_value=result) as run:
            counts = bash_scan.scan_ast_rules(
                self.rule_dir, [self.script], self.sink, skip or set(),
                self.reported, errors=self.errors,
            )
        return counts, run

    def records(self):
        return [json.loads(line) for line in self.sink.getvalue().splitlines()]

    def test_custom_rule_survives_native_finding_on_same_line(self) -> None:
        self.native()
        counts, _ = self.ast([self.diagnostic()])
        self.assertEqual(counts["critical"], 1)
        self.assertEqual({r["rule"] for r in self.records()}, {
            "bash.security.curl_pipe_bash", "custom-no-curl",
        })
        self.assertFalse(self.errors)

    def test_different_ast_rules_on_same_line_are_preserved(self) -> None:
        counts, _ = self.ast([self.diagnostic("custom-a"), self.diagnostic("custom-b")])
        self.assertEqual(counts["critical"], 2)
        self.assertEqual([r["rule"] for r in self.records()], ["custom-a", "custom-b"])

    def test_same_rule_at_distinct_columns_is_preserved(self) -> None:
        self.ast([self.diagnostic(column=0), self.diagnostic(column=30)])
        self.assertEqual([r["col"] for r in self.records()], [1, 31])

    def test_known_equivalent_native_ast_finding_is_not_duplicated(self) -> None:
        self.script.write_text('#!/usr/bin/env bash\neval "$command"\n')
        self.native()
        self.ast([self.diagnostic("bash.security.eval-variable")])
        self.assertEqual([r["rule"] for r in self.records()], ["bash.security.eval_variable"])

    def test_unrelated_builtin_ast_rule_survives_native_warning(self) -> None:
        self.script.write_text('#!/usr/bin/env bash\nread user; test "$a" -a "$b"\n')
        self.native()
        self.ast([self.diagnostic("bash.syntax.test-compound", severity="warning")])
        self.assertIn("bash.syntax.test-compound", {r["rule"] for r in self.records()})

    def test_shellcheck_finding_survives_unrelated_native_warning(self) -> None:
        self.script.write_text('#!/usr/bin/env bash\ncd $target\n')
        self.native()
        output = [{"file": str(self.script), "line": 2, "column": 4,
                   "code": 2086, "level": "warning", "message": "Quote this expansion"}]
        result = subprocess.CompletedProcess([], 1, json.dumps(output), "")
        with patch.object(bash_scan.shutil, "which", return_value="/tools/shellcheck"), \
                patch.object(bash_scan.subprocess, "run", return_value=result):
            counts = bash_scan.scan_shellcheck(
                [self.script], self.sink, set(), self.reported, errors=self.errors,
            )
        self.assertEqual(counts["warning"], 1)
        self.assertEqual({r["rule"] for r in self.records()}, {
            "bash.robustness.cd_without_exit", "bash.shellcheck.SC2086",
        })

    def test_malformed_json_preserves_valid_records_and_reports_error(self) -> None:
        good = json.dumps(self.diagnostic())
        self.ast(output=good + '\n{"truncated":\n' + good + "\n")
        self.assertTrue(self.errors)
        self.assertIn("malformed", self.errors[0])
        self.assertEqual(len(self.records()), 2)

    def test_malformed_record_shapes_are_not_silent_or_fatal(self) -> None:
        malformed = [None, [], 42, "bad", {}, {"ruleId": "x"},
                     {**self.diagnostic(), "range": None},
                     {**self.diagnostic(), "range": {"start": []}},
                     {**self.diagnostic(), "file": []},
                     {**self.diagnostic(), "ruleId": []},
                     {**self.diagnostic(), "message": {}},
                     {**self.diagnostic(), "severity": []}]
        for value in malformed:
            with self.subTest(value=value):
                self.errors.clear()
                counts, _ = self.ast([value, self.diagnostic()])
                self.assertEqual(counts["critical"], 1)
                self.assertTrue(self.errors)

    def test_invalid_positions_do_not_become_invented_line_one_findings(self) -> None:
        for position in ({}, {"line": "1", "column": 0},
                         {"line": True, "column": 0}, {"line": -1, "column": 0},
                         {"line": 0, "column": -1}, {"line": 0, "column": "x"}):
            with self.subTest(position=position):
                self.errors.clear()
                counts, _ = self.ast([{**self.diagnostic(), "range": {"start": position}}])
                self.assertEqual(sum(counts.values()), 0)
                self.assertTrue(self.errors)

    def test_missing_requested_ast_config_reports_incomplete_coverage(self) -> None:
        with patch.object(bash_scan.shutil, "which", return_value="/tools/ast-grep"):
            counts = bash_scan.scan_ast_rules(
                self.root / "missing", [self.script], self.sink, set(),
                self.reported, errors=self.errors,
            )
        self.assertEqual(sum(counts.values()), 0)
        self.assertTrue(self.errors)
        self.assertIn("sgconfig-bash.yml", self.errors[0])

    def test_missing_requested_ast_binary_reports_incomplete_coverage(self) -> None:
        with patch.object(bash_scan.shutil, "which", return_value=None):
            counts = bash_scan.scan_ast_rules(
                self.rule_dir, [self.script], self.sink, set(),
                self.reported, errors=self.errors,
            )
        self.assertEqual(sum(counts.values()), 0)
        self.assertTrue(self.errors)
        self.assertIn("unavailable", self.errors[0])

    def test_verified_ast_binary_override_is_honored(self) -> None:
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": "/verified tools/sg"}):
            _, run = self.ast([self.diagnostic()])
        self.assertEqual(run.call_args.args[0][0], "/verified tools/sg")

    def test_analyzer_failure_keeps_completed_diagnostics(self) -> None:
        counts, _ = self.ast([self.diagnostic()], code=2)
        self.assertEqual(counts["critical"], 1)
        self.assertTrue(self.errors)
        self.assertIn("exited 2", self.errors[0])

    def test_empty_successful_ast_output_is_not_an_error(self) -> None:
        counts, _ = self.ast(output="", code=0)
        self.assertEqual(sum(counts.values()), 0)
        self.assertFalse(self.errors)

    def test_category_skips_still_apply(self) -> None:
        counts, _ = self.ast([self.diagnostic("custom-security-rule")], skip={3})
        self.assertEqual(sum(counts.values()), 0)
        self.assertFalse(self.records())
        self.assertFalse(self.errors)

    def run_main(self, output, *, warm=None):
        """Exercise the real status/sink orchestration with controlled cache IO."""
        class Capture(io.StringIO):
            @property
            def by_file(self):
                records = {}
                for line in self.getvalue().splitlines():
                    record = json.loads(line)
                    records.setdefault(record["path"], []).append(record)
                return records

            def get_for_file(self, path):
                return self.by_file.get(str(path), [])

        cache = Mock()
        cache.partition_files.return_value = (warm or {}, [] if warm else [self.script])
        cache.stats = {"hits": int(bool(warm)), "misses": int(not warm), "hit_rate": int(bool(warm))}
        prefilter = SimpleNamespace(
            is_bypass=True, ast_files=[self.script], files_considered=1,
            files_after_prefilter=1, prefilter_ms=0, to_dict=lambda: {},
        )
        modules = {
            "ubs_core.cache": SimpleNamespace(ScanCache=Mock(return_value=cache), CapturingSink=Capture),
            "ubs_core.prefilter": SimpleNamespace(
                build_prefilter_index=Mock(return_value=None),
                run_prefilter=Mock(return_value=prefilter),
                PrefilterResult=Mock(return_value=prefilter),
            ),
        }
        file_list = self.root / "files"
        file_list.write_bytes(os.fsencode(self.script) + b"\0")
        summary = self.root / "summary.json"
        env = {"UBS_AST_GREP_BIN": "", "UBS_PREFILTER_FILE": "", "UBS_CACHE_FILE": "", "UBS_PROFILE": "0"}
        result = subprocess.CompletedProcess([], 1, output, "")
        with patch.dict(sys.modules, modules), patch.dict(os.environ, env), \
                patch.object(bash_scan.shutil, "which", return_value="/tools/analyzer"), \
                patch.object(bash_scan.subprocess, "run", return_value=result), \
                redirect_stderr(io.StringIO()):
            args = ["--files-from", str(file_list), "--sink", str(self.root / "findings"),
                    "--json-out", str(summary), "--project-dir", str(self.root),
                    "--ast-rule-dir", str(self.rule_dir)]
            if warm is None:
                args.append("--no-shellcheck")
            code = bash_scan.main(args)
        return code, json.loads(summary.read_text()), cache

    def test_malformed_ast_output_marks_summary_partial_and_is_not_cached(self) -> None:
        code, summary, cache = self.run_main(json.dumps(self.diagnostic()) + '\n{"truncated":\n')
        self.assertEqual(code, 2)
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["module_error"], "ANALYZER_ERROR")
        self.assertIn("malformed", summary["message"])
        self.assertEqual(summary["critical"], 2)
        self.assertEqual({r["rule"] for r in summary["findings"]}, {
            "bash.security.curl_pipe_bash", "custom-no-curl",
        })
        cache.store_scanned_files.assert_not_called()

    def test_valid_native_and_custom_findings_are_both_in_summary(self) -> None:
        code, summary, cache = self.run_main(json.dumps(self.diagnostic()) + "\n")
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["critical"], 2)
        cache.store_scanned_files.assert_called_once()

    def test_warm_cache_does_not_hide_new_shellcheck_critical(self) -> None:
        native = {"rule": "bash.robustness.cd_without_exit", "path": str(self.script),
                  "line": 2, "col": 1, "category_id": "bash.robustness",
                  "severity": "warning", "message": "cd without exit"}
        diagnostic = {"file": str(self.script), "line": 2, "column": 4,
                      "code": 1072, "level": "error", "message": "Syntax error"}
        code, summary, cache = self.run_main(json.dumps([diagnostic]), warm={self.script: [native]})
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["warning"], 1)
        self.assertIn("bash.shellcheck.SC1072", {r["rule"] for r in summary["findings"]})
        cache.store_scanned_files.assert_not_called()


class BashRulePackTest(unittest.TestCase):
    """Exercise the real generator and wrapper; stub only scan/bootstrap IO."""

    def setUp(self) -> None:
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="bash-rules-", dir=artifacts)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.rules = self.root / "team's rules"
        self.rules.mkdir()
        self.policy = "id: custom-no-curl\nlanguage: bash\nrule:\n  pattern: curl $$$A\nseverity: error\n"
        (self.rules / "policy.yaml").write_text(self.policy, encoding="utf-8")
        self.script = self.root / "deploy.sh"
        self.script.write_text("#!/usr/bin/env bash\nprintf '%s\\n' safe\n")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.ast = self.tools / "ast-grep"
        self.ast.write_text("#!/bin/sh\nexit 0\n")
        self.ast.chmod(0o755)

    def wrapper(self, *args, env_extra=None):
        # Start after the shared-library bootstrap. Its IO functions are
        # unrelated to rule generation and covered by test_ubs_common.py.
        # The actual parser, generator calls, error handling and argument
        # handoff all run unchanged. No real AST/ShellCheck process runs here.
        source = (ROOT / "modules" / "ubs-bash.sh").read_text(encoding="utf-8")
        source = source[source.index('VERSION="0.1.0"'):]
        bootstrap = r'''
set -Eeuo pipefail
ubs_validate_format(){ :; }
ubs_resolve_helpers_dir(){ printf -v "$1" '%s' "$TEST_HELPERS"; }
python3(){
  if [[ "${1:-}" == -m && "${2:-}" == ubs_core.bash_scan ]]; then
    printf '%s\0' "$@" > "$TEST_CALL"
    local previous="" argument ast_dir=""
    for argument in "$@"; do
      if [[ "$previous" == --ast-rule-dir ]]; then ast_dir="$argument"; fi
      if [[ "$previous" == --json-out || "$previous" == --text-out ]]; then
        printf '{}\n' > "$argument"
      fi
      previous="$argument"
    done
    if [[ -n "$ast_dir" && -f "$ast_dir/rules/user_policy.yaml" ]]; then
      cat "$ast_dir/rules/user_policy.yaml" > "$TEST_POLICY"
    fi
    return 0
  fi
  command "$TEST_PYTHON" "$@"
}
'''
        env = os.environ.copy()
        env.update({
            "TEST_HELPERS": str(ROOT / "modules" / "helpers"),
            "TEST_PYTHON": sys.executable,
            "TEST_CALL": str(self.root / "scan-call"),
            "TEST_POLICY": str(self.root / "copied-policy"),
            "PATH": str(self.tools) + os.pathsep + env.get("PATH", ""),
            "TMPDIR": str(self.root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "UBS_AST_GREP_BIN": "",
            "UBS_TEST_FORCE_NO_AST_GREP": "0",
        })
        env.update(env_extra or {})
        return subprocess.run(
            ["bash", "-c", bootstrap + source, "ubs-bash", str(self.script), *args],
            env=env, cwd=self.root, capture_output=True, text=True,
            timeout=15, check=False,
        )

    def test_missing_custom_directory_is_rejected_by_generator(self) -> None:
        destination = self.root / "generated"
        with self.assertRaises((OSError, ValueError)):
            bash_rules.generate(destination, self.root / "absent")
        self.assertFalse((destination / "sgconfig-bash.yml").exists())

    def test_empty_custom_directory_is_not_a_loaded_policy(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(ValueError):
            bash_rules.generate(self.root / "generated", empty)

    def test_generator_reports_loaded_files_on_stderr(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            manifest = bash_rules.generate(self.root / "generated", self.rules)
        self.assertIn("custom-no-curl", manifest)
        self.assertIn("1 custom rule file", stderr.getvalue())
        self.assertEqual(
            (self.root / "generated/rules/user_policy.yaml").read_text(), self.policy,
        )

    def test_invalid_utf8_policy_is_not_silently_repaired(self) -> None:
        (self.rules / "invalid.yml").write_bytes(b"id: bad\nmessage: \xff\n")
        with self.assertRaises(UnicodeError):
            bash_rules.generate(self.root / "generated", self.rules)

    def test_quoted_directory_reaches_the_scanner(self) -> None:
        result = self.wrapper("--format=json", f"--rules={self.rules}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "scan-call").exists())
        self.assertTrue((self.root / "copied-policy").exists(), result.stderr)
        self.assertEqual((self.root / "copied-policy").read_text(), self.policy)

    def test_quoted_dump_directory_is_populated(self) -> None:
        destination = self.root / "team's dump"
        result = self.wrapper(f"--rules={self.rules}", f"--dump-rules={destination}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / "rules/user_policy.yaml").is_file(), result.stderr)

    def test_missing_directory_fails_before_scan(self) -> None:
        result = self.wrapper(f"--rules={self.root / 'absent'}")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--rules", result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    def test_empty_rules_argument_fails_before_scan(self) -> None:
        result = self.wrapper("--rules=")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    def test_missing_rules_argument_names_the_option(self) -> None:
        result = self.wrapper("--rules")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--rules", result.stderr)

    def test_empty_policy_pack_fails_before_scan(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        result = self.wrapper(f"--rules={empty}")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("rule", result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_nonregular_policy_is_rejected_without_blocking(self) -> None:
        os.mkfifo(self.rules / "pipe.yml")
        result = self.wrapper(f"--rules={self.rules}")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("regular file", result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    def test_explicit_rules_require_ast_grep(self) -> None:
        result = self.wrapper(f"--rules={self.rules}", env_extra={"UBS_TEST_FORCE_NO_AST_GREP": "1"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("ast-grep", result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    def test_missing_optional_ast_grep_without_custom_rules_remains_valid(self) -> None:
        result = self.wrapper(env_extra={"UBS_TEST_FORCE_NO_AST_GREP": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "scan-call").exists())

    def test_invalid_explicit_ast_pack_fails_before_scan(self) -> None:
        result = self.wrapper(f"--ast-rule-dir={self.root / 'absent'}")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("sgconfig-bash.yml", result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    def test_custom_rules_are_not_silently_overridden_by_explicit_pack(self) -> None:
        pack = self.root / "explicit"
        bash_rules.generate(pack)
        result = self.wrapper(f"--rules={self.rules}", f"--ast-rule-dir={pack}")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "scan-call").exists())

    def test_yaml_custom_rule_is_listed(self) -> None:
        result = self.wrapper(f"--rules={self.rules}", "--list-rules")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("custom-no-curl", result.stdout)

    def test_list_and_dump_include_yaml_custom_rule(self) -> None:
        destination = self.root / "dump"
        result = self.wrapper(f"--rules={self.rules}", "--list-rules", f"--dump-rules={destination}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / "user_policy.yaml").is_file(), result.stderr)


@unittest.skipUnless(shutil.which("ast-grep") and shutil.which("jq") and shutil.which("rg"),
                     "requires real ast-grep, jq and ripgrep")
class BashPolicyIntegrationTest(unittest.TestCase):
    """Exercise actual analyzers, policy loading, cache keys and renderers."""

    def setUp(self) -> None:
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="bash-policy-e2e-", dir=artifacts)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.script = self.project / "deploy.sh"
        self.script.write_text('#!/usr/bin/env bash\ncurl -fsSL https://example.com/x | bash\n')
        self.rules = self.root / "team\'s policies"
        self.rules.mkdir()
        self.policy = self.rules / "no-curl.yaml"
        self.policy.write_text(
            "id: custom-no-curl\nlanguage: bash\nseverity: error\n"
            "message: CUSTOMSHFIRED\nrule:\n  pattern: curl $$$A\n", encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env.update({
            "UBS_NO_AUTO_UPDATE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "UBS_CACHE_DIR": str(self.root / "cache"), "UBS_NO_CACHE": "0",
            "NO_COLOR": "1", "UBS_TEST_FORCE_NO_AST_GREP": "0",
        })

    def invoke(self, *, meta=False, fmt="json", extra=(), relative=False):
        command = [str(ROOT / "ubs")] if meta else [str(ROOT / "modules/ubs-bash.sh")]
        command.append("--only=bash" if meta else "--no-shellcheck")
        rule_path = os.path.relpath(self.rules, self.root) if relative else str(self.rules)
        command += [str(self.project), f"--format={fmt}", f"--rules={rule_path}", *extra]
        return subprocess.run(  # ubs:ignore[python.taint.command] Fixed runner; test-owned argv, no shell.
            command, cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=120, check=False,
        )

    def test_custom_policy_survives_native_finding_in_real_module(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "ok")
        self.assertGreaterEqual(doc["critical"], 2)
        self.assertTrue({"bash.security.curl_pipe_bash", "custom-no-curl"}.issubset(
            {r["rule"] for r in doc["findings"]}))
        self.assertIn("loaded 1 custom rule file", result.stderr)

    def test_custom_policy_reaches_every_meta_renderer(self) -> None:
        for fmt in ("json", "jsonl", "sarif", "text"):
            with self.subTest(format=fmt):
                result = self.invoke(meta=True, fmt=fmt)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("custom-no-curl", result.stdout)
                if fmt in ("json", "sarif"):
                    json.loads(result.stdout)

    def test_relative_custom_policy_path_survives_workspace_changes(self) -> None:
        result = self.invoke(meta=True, relative=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("custom-no-curl", result.stdout)

    def test_rule_pack_changes_invalidate_real_cache(self) -> None:
        first = self.invoke()
        self.assertIn("custom-no-curl", first.stdout)
        self.policy.write_text(
            "id: custom-no-bash\nlanguage: bash\nseverity: error\n"
            "message: CUSTOMBASHFIRED\nrule:\n  pattern: bash\n", encoding="utf-8",
        )
        second = self.invoke()
        self.assertEqual(second.returncode, 1, second.stdout + second.stderr)
        rules = {r["rule"] for r in json.loads(second.stdout)["findings"]}
        self.assertIn("custom-no-bash", rules)
        self.assertNotIn("custom-no-curl", rules)

    def test_invalid_yaml_is_partial_and_keeps_native_finding(self) -> None:
        self.policy.write_text("id: broken\nlanguage: bash\nrule: [\n", encoding="utf-8")
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
        self.assertIn("bash.security.curl_pipe_bash", {r["rule"] for r in doc["findings"]})

    def test_missing_policy_directory_never_becomes_success(self) -> None:
        self.rules = self.root / "absent"
        for meta in (False, True):
            with self.subTest(meta=meta):
                result = self.invoke(meta=meta)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("rules", (result.stdout + result.stderr).lower())

    @unittest.skipUnless(shutil.which("shellcheck"), "requires real ShellCheck")
    def test_real_shellcheck_diagnostic_is_not_hidden_by_native_warning(self) -> None:
        self.script.write_text('#!/usr/bin/env bash\ncd $target\n', encoding="utf-8")
        result = subprocess.run(
            [str(ROOT / "modules/ubs-bash.sh"), str(self.project), "--format=json"],
            cwd=self.root, env=self.env, capture_output=True, text=True,
            timeout=120, check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "ok")
        self.assertTrue({"bash.robustness.cd_without_exit", "bash.shellcheck.SC2086"}.issubset(
            {r["rule"] for r in doc["findings"]}))

    def test_meta_rejects_invalid_policy_before_detection_in_every_language(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        contract = json.loads((ROOT / "modules/contract.json").read_text())
        for lang in contract["modules"]:
            for value, reason in (("", "invalid-rules-directory"),
                                  (str(self.root / "absent"), "invalid-rules-directory"),
                                  (str(empty), "empty-rules-directory")):
                with self.subTest(lang=lang, value=value):
                    result = subprocess.run(
                        [str(ROOT / "ubs"), str(empty), f"--rules={value}",
                         f"--only={lang}", "--format=json"],
                        cwd=self.root, env=self.env, capture_output=True,
                        text=True, timeout=30, check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(json.loads(result.stdout)["reason"], reason)

    def test_elixir_custom_rules_are_forwarded_by_meta_runner(self) -> None:
        project = self.root / "elixir-project"
        project.mkdir()
        (project / "app.ex").write_text('IO.puts("hello")\n', encoding="utf-8")
        rules = self.root / "elixir-rules"
        rules.mkdir()
        (rules / "policy.yml").write_text(
            "id: custom-elixir-policy\nlanguage: elixir\nseverity: error\n"
            "message: CUSTOMELIXIRFIRED\nrule:\n  pattern: IO.puts($$$A)\n", encoding="utf-8",
        )
        result = subprocess.run(
            [str(ROOT / "ubs"), str(project), "--only=elixir", "--format=json", f"--rules={rules}"],
            cwd=self.root, env=self.env, capture_output=True, text=True,
            timeout=120, check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("custom-elixir-policy", result.stdout)
        self.assertGreater(json.loads(result.stdout)["totals"]["critical"], 0)


if __name__ == "__main__":
    unittest.main()
