#!/usr/bin/env python3
"""Repository scan settings: independent real-runner and policy regressions.

Fixtures, commands, source identities and complete child streams are retained
under test-suite/artifacts/scan-config. The service checks use its real scanner
and byte observer without opening a Unix socket. No analyzer is replaced.
"""
from __future__ import annotations

from collections import Counter
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[2]
UBS = ROOT / "ubs"
ARTIFACTS = ROOT / "test-suite" / "artifacts" / "scan-config"
PYTHON_SOURCE = "value = input()\neval(value)\n"  # ubs:ignore[python.taint.eval] Scanned fixture; never executed.
SAFE_SOURCE = 'literal = "eval(input())"\n# eval(input())\nvalue = 7\n'
WARNING_SOURCE = "from math import *\n"
EVAL_RULES = ("py.security.eval-exec-usage", "py.eval-exec", "python.taint.eval")
WARNING_RULES = ("py.variables.wildcard-import", "py.wildcard-import")

loader = importlib.machinery.SourceFileLoader("ubs_daemon_scan_config", str(ROOT / "ubs-daemon"))
spec = importlib.util.spec_from_loader(loader.name, loader)
daemon = importlib.util.module_from_spec(spec)
loader.exec_module(daemon)


class ScanConfigFixture:
    def setUp(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=ARTIFACTS))
        self.project = self.work / "project"
        self.project.mkdir()
        (self.work / "home").mkdir()
        self.inputs = set()
        self.calls = 0
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("UBS_", "GIT_", "XDG_", "TOON_"))
            and key not in {"JOBS", "ENABLE_UV_TOOLS"}
        }
        self.env.update(
            UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0", UBS_NO_CACHE="1",
            ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
            HOME=str(self.work / "home"),
            XDG_CONFIG_HOME=str(self.work / "settings"),
            XDG_CACHE_HOME=str(self.work / "cache"), UBS_CACHE_DIR=str(self.work / "scan-cache"),
        )
        self.git("init", "-q", "-b", "main")

    def write(self, name, text, *, root=None):
        path = (root or self.project) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.inputs.add(path)
        return path

    def config(self, value, *, root=None, name=".ubs.json"):
        return self.write(name, json.dumps(value) + "\n", root=root)

    def git(self, *args, cwd=None):
        directory = cwd or self.project
        return subprocess.run(  # ubs:ignore[python.taint.command] Fixed fixture operations; no shell.
            ["git", "-c", f"core.hooksPath={directory / '.git' / 'ubs-empty-hooks'}",
             "-c", "user.name=UBS configuration tests", "-c", "user.email=ubs-test@example.invalid",
             *args], cwd=directory, env=self.env, capture_output=True, text=True,
            timeout=30, check=True,
        )

    def record(self, name, command, result, elapsed, *, environment=None, cwd=None):
        self.calls += 1
        prefix = self.work / f"{self.calls:03d}-{name}"
        prefix.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
        prefix.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
        identities = {}
        for path in sorted(self.inputs):
            if path.exists() and stat.S_ISREG(path.stat().st_mode):
                identities[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        receipt = {
            "case": self.id(), "command": command, "cwd": str(cwd or self.project),
            "exit_code": result.returncode, "seconds": round(elapsed, 4),
            "source_sha256": identities,
            "ubs_sha256": hashlib.sha256(UBS.read_bytes()).hexdigest(),
            "daemon_sha256": hashlib.sha256((ROOT / "ubs-daemon").read_bytes()).hexdigest(),
            "python": sys.version,
            "tools": {tool: shutil.which(tool) for tool in ("bash", "python3", "git", "jq", "rg", "ast-grep")},
            "environment": {
                key: value for key, value in (environment or self.env).items()
                if key.startswith(("UBS_", "XDG_"))
                or key in {"ENABLE_UV_TOOLS", "TMPDIR", "TMP", "TEMP", "PYTHONDONTWRITEBYTECODE"}
            },
        }
        prefix.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        return result

    def run_ubs(self, *args, cwd=None, environment=None, name="scan", timeout=120):
        env = dict(self.env)
        for key, value in (environment or {}).items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        command = [str(UBS), "--ci", "--no-color", "--format=json", "--jobs=1", *map(str, args)]
        start = time.monotonic()
        try:
            result = subprocess.run(  # ubs:ignore[python.taint.command] Real scanner with test-owned argv; no shell.
                command, cwd=cwd or self.project, env=env, capture_output=True,
                text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
            stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
            result = subprocess.CompletedProcess(command, -1, stdout, stderr + f"\nTimed out after {timeout}s\n")
            self.record(name, command, result, time.monotonic() - start, environment=env, cwd=cwd)
            self.fail(f"Scanner exceeded {timeout}s; complete streams: {self.work}")
        return self.record(name, command, result, time.monotonic() - start, environment=env, cwd=cwd)

    def document(self, result):
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"Invalid JSON, exit {result.returncode}: {exc}\n{result.stderr}\nArtifacts: {self.work}")

    def findings(self, document):
        def relative(raw):
            path = Path(raw)
            if not path.is_absolute():
                path = self.project / path
            return path.resolve().relative_to(self.project.resolve()).as_posix()
        return Counter(
            (item["rule_id"], relative(item["file"]), item["line"], item["severity"])
            for item in document["findings"]
        )

    def expect_eval(self, result, names, *, rules=EVAL_RULES, files=None):
        document = self.document(result)
        self.assertEqual(result.returncode, 1, (result.stderr, self.work))
        self.assertEqual(document["status"], "ok", (document, self.work))
        self.assertEqual(document["totals"], {
            "files": len(names) if files is None else files,
            "critical": len(names) * len(rules), "warning": 0, "info": 0,
        }, self.work)
        expected = Counter((rule, name, 2, "critical") for name in names for rule in rules)
        self.assertEqual(self.findings(document), expected, self.work)
        return document

    def expect_warnings(self, result, code):
        document = self.document(result)
        self.assertEqual(result.returncode, code, (result.stderr, self.work))
        self.assertEqual(document["status"], "ok", document)
        self.assertEqual(document["totals"], {"files": 1, "critical": 0, "warning": 2, "info": 0})
        self.assertEqual(self.findings(document), Counter((rule, "app.py", 1, "warning") for rule in WARNING_RULES))
        return document


@unittest.skipUnless(all(shutil.which(tool) for tool in ("bash", "git", "jq", "rg", "ast-grep")),
                     "real scan configuration cases require bash, git, jq, ripgrep and ast-grep")
class RepositoryScanConfigTests(ScanConfigFixture, unittest.TestCase):
    def test_absent_empty_and_disabled_config_preserve_defaults_and_ignores(self):
        self.write("app.py", PYTHON_SOURCE)
        self.write("safe.py", SAFE_SOURCE)
        self.write("ignored.py", PYTHON_SOURCE)
        self.write("node_modules/generated.py", PYTHON_SOURCE)
        self.write(".ubsignore", "ignored.py\n")
        baseline = self.expect_eval(self.run_ubs("."), ["app.py"], files=2)
        self.config({})
        empty = self.expect_eval(self.run_ubs("."), ["app.py"], files=2)
        self.assertEqual(self.findings(empty), self.findings(baseline))
        self.write(".ubs.json", "this is intentionally not JSON\n")
        self.expect_eval(self.run_ubs("--no-config", "."), ["app.py"], files=2)

    def test_discovered_settings_match_equivalent_explicit_flags(self):
        self.write("kept.py", PYTHON_SOURCE)
        self.write("ignored/skipped.py", PYTHON_SOURCE)
        self.write("other.js", "const answer = 42;\n")
        self.config({"version": 1, "only": ["python"], "exclude": ["ignored/**"]})
        configured = self.expect_eval(self.run_ubs("."), ["kept.py"])
        explicit = self.expect_eval(self.run_ubs("--no-config", "--only=python", "--exclude=ignored/**", "."), ["kept.py"])
        self.assertEqual(self.findings(configured), self.findings(explicit))

    def test_language_exclusion_and_aliases_use_real_language_selection(self):
        self.write("app.py", PYTHON_SOURCE)
        self.write("other.js", "const answer = 42;\n")
        self.config({"exclude_langs": ["ts"]})
        self.expect_eval(self.run_ubs("."), ["app.py"])
        self.config({"only": ["py"], "skip_by_lang": {"py": [7]}})
        self.expect_eval(self.run_ubs("."), ["app.py"], rules=("py.eval-exec",))

    def test_explicit_language_and_repeated_excludes_replace_project_fields(self):
        for name in ("first.py", "second.py", "third.py"):
            self.write(name, PYTHON_SOURCE)
        self.write("other.js", "const answer = 42;\n")
        self.config({"only": ["js"], "exclude": ["first.py"]})
        self.expect_eval(self.run_ubs("--only=python", "--exclude=second.py", "--exclude", "third.py", "."), ["first.py"])
        self.expect_eval(self.run_ubs("--only=python", "--exclude=", "."), ["first.py", "second.py", "third.py"])

    def test_skip_precedence_is_project_then_environment_then_cli(self):
        self.write("app.py", PYTHON_SOURCE)
        self.config({"skip": ["python.security"]})
        self.expect_eval(self.run_ubs("."), ["app.py"], rules=("py.eval-exec",))
        self.expect_eval(self.run_ubs(".", environment={"UBS_SKIP_CATEGORIES": "13"}), ["app.py"])
        self.expect_eval(self.run_ubs("--skip=7", ".", environment={"UBS_SKIP_CATEGORIES": "13"}),
                         ["app.py"], rules=("py.eval-exec",))
        self.expect_eval(self.run_ubs("--skip=", ".", environment={"UBS_SKIP_CATEGORIES": "7"}), ["app.py"])

    def test_per_language_override_replaces_config_after_alias_normalization(self):
        self.write("app.py", PYTHON_SOURCE)
        self.config({"skip_by_lang": {"py": [7]}})
        self.expect_eval(self.run_ubs("--skip-python=13", "."), ["app.py"])
        self.expect_eval(self.run_ubs("--skip-py=7", "--skip-python=13", "."),
                         ["app.py"], rules=("py.eval-exec",))

    def test_profile_precedence_recomputes_warning_gate(self):
        self.write("app.py", WARNING_SOURCE)
        self.expect_warnings(self.run_ubs("."), 0)
        self.config({"profile": "strict"})
        self.expect_warnings(self.run_ubs("."), 1)
        self.expect_warnings(self.run_ubs(".", environment={"UBS_PROFILE": "loose"}), 0)
        self.expect_warnings(self.run_ubs("--profile=strict", ".", environment={"UBS_PROFILE": "loose"}), 1)
        self.config({"profile": "loose"})
        self.expect_warnings(self.run_ubs(".", environment={"UBS_PROFILE": "strict"}), 1)

    def test_numeric_timing_environment_preserves_project_profile_and_cli_overrides(self):
        self.write("app.py", WARNING_SOURCE)
        self.config({"profile": "strict"})
        cases = (
            ("strict-with-timing", (), "1", 1, True),
            ("explicit-loose-with-timing", ("--profile=loose",), "1", 0, True),
            ("explicit-strict-with-timing", ("--profile=strict",), "1", 1, True),
            ("strict-with-timing-disabled", (), "0", 1, False),
        )
        for name, flags, timing, code, has_timing in cases:
            with self.subTest(case=name):
                document = self.expect_warnings(
                    self.run_ubs(*flags, ".", environment={"UBS_PROFILE": timing}, name=name), code)
                if has_timing:
                    self.assertIsInstance(document.get("profile"), dict, (document, self.work))
                    for phase in ("total_ms", "list_ms", "fanout_ms", "merge_ms"):
                        self.assertIsInstance(document["profile"][phase], int)
                        self.assertGreaterEqual(document["profile"][phase], 0)
                    self.assertEqual(document["profile"]["files_considered"], 1)
                else:
                    self.assertNotIn("profile", document)

    def test_explicit_warning_gate_overrides_false_project_setting(self):
        self.write("app.py", WARNING_SOURCE)
        self.config({"fail_on_warning": False})
        self.expect_warnings(self.run_ubs("."), 0)
        self.expect_warnings(self.run_ubs("--fail-on-warning", "."), 1)

    def test_category_selection_matches_existing_cli_semantics(self):
        self.write("app.py", PYTHON_SOURCE)
        self.config({"only": ["python"], "category": "resource-lifecycle"})
        configured = self.expect_eval(self.run_ubs("."), ["app.py"], rules=("py.eval-exec",))
        control = self.expect_eval(self.run_ubs("--no-config", "--only=python", "--category=resource-lifecycle", "."),
                                   ["app.py"], rules=("py.eval-exec",))
        self.assertEqual(self.findings(configured), self.findings(control))

    def make_rule(self, directory, rule_id, *, severity="error"):
        self.write("marker.yml", f"id: {rule_id}\nlanguage: python\nseverity: {severity}\n"
                   "message: project policy marker\nrule:\n  pattern: mark_me($$$)\n", root=directory)
        return directory

    def expect_custom(self, result, ids):
        document = self.document(result)
        self.assertEqual(result.returncode, 1, (result.stderr, self.work))
        self.assertEqual(document["status"], "ok", document)
        self.assertEqual(document["totals"], {"files": 1, "critical": len(ids), "warning": 0, "info": 0})
        self.assertEqual(self.findings(document), Counter((rule, "app.py", 1, "critical") for rule in ids))
        return document

    def test_explicit_config_anchors_rule_paths_to_its_own_directory(self):
        self.write("app.py", "mark_me()\n")
        policies = self.work / "policies with spaces"
        rules = self.make_rule(policies / "rules", "custom.project-marker")
        config = self.config({"rules": ["rules"]}, root=policies, name="chosen.json")
        self.expect_custom(self.run_ubs("--config", os.path.relpath(config, self.project), "app.py"), ["custom.project-marker"])
        self.expect_custom(self.run_ubs("--no-config", f"--rules={rules}", "app.py"), ["custom.project-marker"])

    def test_rule_directory_precedence_replaces_lower_layers(self):
        self.write("app.py", "mark_me()\n")
        project_rules = self.make_rule(self.project / "rules", "custom.project-marker")
        env_rules = self.make_rule(self.work / "env-rules", "custom.environment-marker")
        cli_rules = self.make_rule(self.work / "cli-rules", "custom.command-marker")
        self.config({"rules": [str(project_rules)]})
        self.expect_custom(self.run_ubs("app.py", environment={"UBS_RULES": str(env_rules)}), ["custom.environment-marker"])
        self.expect_custom(self.run_ubs(f"--rules={cli_rules}", "app.py", environment={"UBS_RULES": str(env_rules)}),
                           ["custom.command-marker"])
        self.config({"rules": []})
        cleared = self.run_ubs("app.py")
        self.assertEqual(cleared.returncode, 0, cleared.stderr)
        self.assertEqual(self.document(cleared)["totals"], {"files": 1, "critical": 0, "warning": 0, "info": 0})

    def test_root_config_is_selected_from_a_single_file_not_the_invocation_cwd(self):
        source = self.write("nested/with space.py", PYTHON_SOURCE)
        self.write("outside-target.py", PYTHON_SOURCE)
        self.config({"skip": [7]})
        self.config({"unknown_nested_decoy": True}, root=source.parent)
        other = self.work / "other-project"
        other.mkdir()
        self.git("init", "-q", "-b", "main", cwd=other)
        self.config({"only": ["js"]}, root=other)
        self.expect_eval(self.run_ubs(source, cwd=other), ["nested/with space.py"], rules=("py.eval-exec",))

    def test_root_anchored_config_excludes_keep_their_repository_meaning(self):
        self.write("nested/kept.py", PYTHON_SOURCE)
        ignored = self.write("nested/ignored.py", PYTHON_SOURCE)
        self.write("outside-target.py", PYTHON_SOURCE)
        self.config({"exclude": ["/nested/ignored.py"]})
        self.expect_eval(self.run_ubs("nested"), ["nested/kept.py"])
        self.expect_eval(self.run_ubs(".", cwd=self.project / "nested"), ["nested/kept.py"])
        # The existing named-file contract wins over ignore patterns. Reading
        # repository policy must preserve that explicit selection guarantee.
        self.expect_eval(self.run_ubs(ignored), ["nested/ignored.py"])

    def test_multiple_explicit_targets_and_files_use_invocation_repository_config(self):
        self.write("nested/a.py", PYTHON_SOURCE)
        self.write("nested/b.py", PYTHON_SOURCE)
        self.write("unselected.py", PYTHON_SOURCE)
        self.config({"skip": [7]})
        for args in (("a.py", "b.py"), ("--files=a.py,b.py",)):
            with self.subTest(args=args):
                self.expect_eval(self.run_ubs(*args, cwd=self.project / "nested"),
                                 ["nested/a.py", "nested/b.py"], rules=("py.eval-exec",))

    def test_non_git_selection_does_not_inherit_ambient_parent_configuration(self):
        external = Path(tempfile.mkdtemp(prefix="ubs-config-nongit-"))
        self.config({"profile": "strict"}, root=external)
        selected = external / "selected"
        selected.mkdir()
        self.write("app.py", WARNING_SOURCE, root=selected)
        original = self.project
        self.project = selected
        try:
            self.expect_warnings(self.run_ubs(selected), 0)
            self.config({"profile": "strict"})
            self.expect_warnings(self.run_ubs(selected), 1)
        finally:
            self.project = original

    def test_staged_and_diff_use_root_settings_without_changing_source_selection(self):
        self.write("a.py", "value = 1\n")
        self.write("ignored.py", "value = 1\n")
        self.write("nested/selected.py", "value = 1\n")
        nested = self.project / "nested"
        self.git("add", "a.py", "ignored.py", "nested/selected.py")
        self.git("commit", "-qm", "fixture base")
        self.write("a.py", PYTHON_SOURCE)
        self.write("ignored.py", PYTHON_SOURCE)
        self.git("add", "a.py", "ignored.py")
        self.write("a.py", "value = 1\n")
        self.write("untracked.py", PYTHON_SOURCE)
        self.config({"only": ["python"], "exclude": ["ignored.py"], "skip": [7]})
        self.expect_eval(self.run_ubs("--staged", "..", cwd=nested), ["a.py"], rules=("py.eval-exec",))
        self.write("nested/selected.py", PYTHON_SOURCE)
        self.git("add", "nested/selected.py")
        self.write("nested/selected.py", "value = 1\n")
        self.expect_eval(self.run_ubs("--staged", cwd=nested), ["nested/selected.py"], rules=("py.eval-exec",))
        self.write("a.py", PYTHON_SOURCE)
        self.expect_eval(self.run_ubs("--diff", "..", cwd=nested), ["a.py"], rules=("py.eval-exec",))
        self.write("nested/selected.py", PYTHON_SOURCE)
        self.expect_eval(self.run_ubs("--diff", cwd=nested), ["nested/selected.py"], rules=("py.eval-exec",))

    def test_non_git_nested_selection_uses_the_same_policy_anchor_as_watch(self):
        original = self.project
        self.project = Path(tempfile.mkdtemp(prefix="ubs-config-nested-"))
        try:
            self.write("nested/a.py", PYTHON_SOURCE)
            self.write("nested/b.py", PYTHON_SOURCE)
            self.config({"skip": [7]})
            self.config({"skip": []}, root=self.project / "nested")
            self.expect_eval(self.run_ubs("nested/a.py"), ["nested/a.py"])
            self.expect_eval(self.run_ubs("nested"), ["nested/a.py", "nested/b.py"])
            self.expect_eval(self.run_ubs("nested/a.py", "nested/b.py"),
                             ["nested/a.py", "nested/b.py"], rules=("py.eval-exec",))
            self.assertEqual(daemon.watch_config_path(self.project, ["nested/a.py"]), "nested/.ubs.json")
            self.assertEqual(daemon.watch_config_path(self.project, ["nested"]), "nested/.ubs.json")
            self.assertEqual(daemon.watch_config_path(self.project, ["nested/a.py", "nested/b.py"]), ".ubs.json")
            source = self.project / "nested/a.py"
            (source.parent / "alias.py").symlink_to(source)
            for names in (["nested/a.py", "nested/a.py"], ["nested/a.py", "nested/alias.py"]):
                request = {"paths": names, "format": "json"}
                selected, _ = daemon.validate_scan(self.project, request)
                self.assertEqual(selected, [source.resolve()])
                self.assertEqual(daemon.watch_config_path(self.project, names), "nested/.ubs.json")
            self.expect_eval(self.run_ubs(*selected), ["nested/a.py"])
        finally:
            self.project = original

    def test_json_and_sarif_configured_findings_have_exact_same_public_locations(self):
        self.write("app.py", PYTHON_SOURCE)
        self.write("ignored.py", PYTHON_SOURCE)
        self.config({"exclude": ["ignored.py"]})
        expected = self.expect_eval(self.run_ubs("."), ["app.py"])
        result = self.run_ubs("--format=sarif", ".")
        self.assertEqual(result.returncode, 1, result.stderr)
        sarif = self.document(result)
        findings = Counter()
        for run in sarif["runs"]:
            if run["tool"]["driver"]["name"].endswith("-ast"):
                continue
            for item in run["results"]:
                location = item["locations"][0]["physicalLocation"]
                raw = unquote(urlparse(location["artifactLocation"]["uri"]).path)
                path = Path(raw)
                if not path.is_absolute():
                    path = self.project / path
                findings[(item["ruleId"], path.resolve().relative_to(self.project).as_posix(),
                          location["region"]["startLine"], "critical" if item["level"] == "error" else item["level"])] += 1
        self.assertEqual(findings, self.findings(expected))

    def test_configuration_edit_invalidates_warm_cache_and_matches_cold_scan(self):
        self.write("app.py", PYTHON_SOURCE)
        config = self.config({"skip": [7]})
        env = {"UBS_NO_CACHE": None, "UBS_PROFILE": "1"}
        cold = self.expect_eval(self.run_ubs("app.py", environment=env), ["app.py"], rules=("py.eval-exec",))
        warm = self.expect_eval(self.run_ubs("app.py", environment=env), ["app.py"], rules=("py.eval-exec",))
        self.assertEqual((cold["profile"]["cache_hits"], warm["profile"]["cache_hits"]), (0, 1))
        stamp = config.stat()
        self.config({"skip": []})
        os.utime(config, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        changed = self.expect_eval(self.run_ubs("app.py", environment=env), ["app.py"])
        self.assertEqual(changed["profile"]["cache_hits"], 0)
        self.assertEqual(changed["profile"]["cache_misses"], 1)
        warm_again = self.expect_eval(self.run_ubs("app.py", environment=env), ["app.py"])
        self.assertEqual(warm_again["profile"]["cache_hits"], 1)
        uncached = self.expect_eval(self.run_ubs("--no-cache", "app.py", environment=env), ["app.py"])
        self.assertEqual(self.findings(changed), self.findings(uncached))

    def test_real_service_cache_observes_config_edits_and_never_reuses_config_errors(self):
        # A nested Git checkout intentionally disables whole-report reuse.
        # Use a tiny external source tree and keep all receipts in self.work.
        original = self.project
        self.project = Path(tempfile.mkdtemp(prefix="ubs-config-service-"))
        self.write("app.py", PYTHON_SOURCE)
        self.env.pop("UBS_NO_CACHE", None)
        try:
            with patch.dict(os.environ, self.env, clear=True):
                service = daemon.ScanService(self.project, UBS, 120, 8 * 1024 * 1024)
                request = {"protocol": 1, "op": "scan", "root": str(self.project), "paths": ["app.py"],
                           "environment": daemon.environment_key(), "scanner": str(UBS), "format": "json"}

                def scan(name):
                    before = time.monotonic()
                    response = service.handle(request)
                    result = subprocess.CompletedProcess(["ScanService.handle", "app.py"], response["exit_code"],
                                                         response["stdout"], response["stderr"])
                    self.record(name, result.args, result, time.monotonic() - before)
                    return response, result

                first, report = scan("service-cold")
                self.assertFalse(first["cached"])
                self.expect_eval(report, ["app.py"])
                warm, report = scan("service-warm")
                self.assertTrue(warm["cached"], warm)
                self.expect_eval(report, ["app.py"])
                self.config({"skip": [7]})
                changed, report = scan("service-config-created")
                self.assertFalse(changed["cached"])
                self.expect_eval(report, ["app.py"], rules=("py.eval-exec",))
                warm, report = scan("service-config-warm")
                self.assertTrue(warm["cached"], warm)
                self.expect_eval(report, ["app.py"], rules=("py.eval-exec",))
                self.write(".ubs.json", "malformed config\n")
                for name in ("service-config-error", "service-config-error-again"):
                    failed, report = scan(name)
                    self.assertFalse(failed["cached"])
                    self.assertEqual(report.returncode, 2, report.stderr)
                self.config({"skip": []})
                repaired, report = scan("service-config-repaired")
                self.assertFalse(repaired["cached"])
                self.expect_eval(report, ["app.py"])
                with patch.dict(os.environ, {"UBS_SKIP_CATEGORIES": "7"}):
                    other_environment = daemon.environment_key()
                self.assertNotEqual(other_environment, request["environment"])
                mismatch = service.handle(dict(request, environment=other_environment))
                self.assertIn("unavailable", mismatch)
                with self.assertRaisesRegex(daemon.ServiceError, "Unknown scan request fields"):
                    service.handle(dict(request, config="../external.json"))
        finally:
            self.project = original

    def test_real_service_never_reuses_reports_with_external_custom_rules(self):
        original = self.project
        self.project = Path(tempfile.mkdtemp(prefix="ubs-config-rule-cache-"))
        source = self.write("app.py", "mark_me()\n")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        try:
            for origin in ("config", "environment"):
                with self.subTest(origin=origin):
                    rules = self.work / (origin + "-rules")
                    rule = self.write("marker.yml", "id: custom.external-marker\nlanguage: python\n"
                                      "severity: error\nmessage: shared policy marker\nrule:\n"
                                      "  pattern: never_called($$$)\n", root=rules)
                    config = self.config({"rules": [str(rules)] if origin == "config" else []})
                    config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
                    env = dict(self.env)
                    if origin == "environment":
                        env["UBS_RULES"] = str(rules)
                    with patch.dict(os.environ, env, clear=True):
                        service = daemon.ScanService(self.project, UBS, 120, 8 * 1024 * 1024)
                        request = {"protocol": 1, "op": "scan", "root": str(self.project), "paths": ["app.py"],
                                   "environment": daemon.environment_key(), "scanner": str(UBS), "format": "json"}

                        def scan(name):
                            before = time.monotonic()
                            response = service.handle(request)
                            result = subprocess.CompletedProcess(["ScanService.handle", "app.py"], response["exit_code"],
                                                                 response["stdout"], response["stderr"])
                            self.record(origin + "-" + name, result.args, result, time.monotonic() - before,
                                        environment=env)
                            return response, result

                        first, report = scan("rule-cold")
                        self.assertEqual(report.returncode, 0, report.stderr)
                        self.assertEqual(self.document(report)["totals"],
                                         {"files": 1, "critical": 0, "warning": 0, "info": 0})
                        warm, report = scan("rule-repeat")
                        self.assertEqual(report.returncode, 0, report.stderr)
                        self.assertEqual(self.document(report).get("findings", []), [])
                        rule.write_text("id: custom.external-marker\nlanguage: python\n"
                                        "severity: error\nmessage: shared policy marker\nrule:\n"
                                        "  pattern: mark_me($$$)\n", encoding="utf-8")
                        changed, report = scan("external-rule-edited")
                        cold = self.run_ubs("app.py", name=origin + "-cold-cli-after-rule-edit",
                                            environment={"UBS_RULES": env.get("UBS_RULES")})
                        expected = Counter({("custom.external-marker", "app.py", 1, "critical"): 1})
                        for result in (report, cold):
                            document = self.document(result)
                            self.assertEqual(result.returncode, 1, (result.stderr, self.work))
                            self.assertEqual(document["status"], "ok", document)
                            self.assertEqual(document["totals"],
                                             {"files": 1, "critical": 1, "warning": 0, "info": 0})
                            self.assertEqual(self.findings(document), expected)
                        self.assertFalse(any(response["cached"] for response in (first, warm, changed)))
                        self.assertEqual(len(service.cache), 0)
                        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)
                        self.assertEqual(hashlib.sha256(config.read_bytes()).hexdigest(), config_hash)
        finally:
            self.project = original

    def test_malformed_unknown_and_wrong_typed_settings_fail_before_output_truncation(self):
        self.write("app.py", PYTHON_SOURCE)
        output = self.write("existing-report.txt", "previous report must survive\n", root=self.work)
        invalid = (
            "{", "[]", "null", '{"version":true}', '{"version":1.0}', '{"version":2}',
            '{"unknown":true}', '{"only":["python"],"only":["js"]}',
            '{"only":"python"}', '{"only":["not-a-language"]}', '{"only":[true]}',
            '{"exclude":[null]}', '{"exclude":["line\\nseparator"]}',
            '{"exclude_langs":false}', '{"profile":"experimental"}',
            '{"fail_on_warning":"false"}', '{"category":"security"}',
            '{"skip":[0]}', '{"skip":[-1]}', '{"skip":[true]}', '{"skip":[1.5]}',
            '{"skip":["python.not-a-category"]}', '{"skip_by_lang":{"py":["python.security"]}}',
            '{"skip_by_lang":{"python":[7],"python":[13]}}', '{"skip_by_lang":{"unknown":[7]}}',
            '{"rules":"rules"}', '{"rules":[false]}',
        )
        for index, raw in enumerate(invalid):
            with self.subTest(raw=raw):
                config = self.write(".ubs.json", raw)
                result = self.run_ubs(f"--output={output}", ".", name=f"invalid-{index}", timeout=10)
                self.assertEqual(result.returncode, 2, (raw, result.stderr, self.work))
                self.assertIn(config.name, result.stderr, (raw, result.stderr))
                self.assertEqual(output.read_text(), "previous report must survive\n")

    def test_missing_nonregular_oversized_and_invalid_utf8_explicit_config_are_errors(self):
        self.write("app.py", PYTHON_SOURCE)
        missing = self.work / "absent.json"
        directory = self.work / "directory.json"
        directory.mkdir()
        oversized = self.write("large.json", " " * (256 * 1024 + 1), root=self.work)
        utf8 = self.work / "invalid-utf8.json"
        utf8.write_bytes(b"\xff")
        self.inputs.add(utf8)
        many = self.config({"exclude": [f"path-{index}" for index in range(257)]}, root=self.work, name="many.json")
        cases = [missing, directory, oversized, utf8, many]
        if hasattr(os, "mkfifo"):
            fifo = self.work / "pipe.json"
            os.mkfifo(fifo)
            cases.append(fifo)
        for path in cases:
            with self.subTest(path=path.name):
                result = self.run_ubs(f"--config={path}", "app.py", timeout=10, name=path.stem)
                self.assertEqual(result.returncode, 2, (path, result.stderr, self.work))
                self.assertIn(path.name, result.stderr)

    def test_explicit_config_and_no_config_conflict_in_both_orders(self):
        self.write("app.py", PYTHON_SOURCE)
        config = self.config({})
        for args in ((f"--config={config}", "--no-config"), ("--no-config", f"--config={config}")):
            with self.subTest(args=args):
                result = self.run_ubs(*args, "app.py")
                self.assertEqual(result.returncode, 2, (result.stderr, self.work))
                self.assertIn("config", result.stderr.lower())

    def test_config_strings_are_data_and_do_not_execute_shell_text(self):
        self.write("app.py", PYTHON_SOURCE)
        marker = self.work / "shell-must-not-run"
        self.config({"exclude": [f"$(touch {marker})", "`false`"]})
        self.expect_eval(self.run_ubs("."), ["app.py"])
        self.assertFalse(marker.exists())

    def test_machine_schema_and_robot_docs_are_available_without_loading_project_policy(self):
        self.write(".ubs.json", "malformed repository config\n")
        for name, args in (("schema", ["--schema=config"]), ("robot", ["robot-docs", "config"])):
            command = [str(UBS), *args]
            start = time.monotonic()
            result = subprocess.run(command, cwd=self.project, env=self.env, capture_output=True,
                                    text=True, timeout=10, check=False)
            self.record(name, command, result, time.monotonic() - start)
            self.assertEqual(result.returncode, 0, result.stderr)
            document = self.document(result)
            if name == "schema":
                self.assertEqual(document["type"], "object")
                self.assertFalse(document["additionalProperties"])
                self.assertTrue({"only", "exclude", "profile", "rules", "skip_by_lang"} <= set(document["properties"]))
            else:
                self.assertIn(".ubs.json", result.stdout)
                self.assertIn("--config", result.stdout)


class ScanConfigSnapshotTests(ScanConfigFixture, unittest.TestCase):
    def test_custom_rule_policy_reuse_and_environment_precedence(self):
        original = self.project
        self.project = Path(tempfile.mkdtemp(prefix="ubs-config-snapshot-"))
        self.write("app.py", "value = 1\n")
        rules = self.work / "shared-rules"
        self.write("marker.yml", "id: custom.marker\nlanguage: python\nrule:\n  pattern: mark_me($$$)\n", root=rules)
        try:
            with patch.dict(os.environ, self.env, clear=True):
                self.assertIsNotNone(daemon.snapshot(self.project, UBS))
                for policy in ({"skip": [7]}, {"rules": []}):
                    self.config(policy)
                    self.assertIsNotNone(daemon.snapshot(self.project, UBS), policy)
                self.config({"rules": [str(rules)]})
                self.assertIsNone(daemon.snapshot(self.project, UBS))
                for cleared in ("", ":"):
                    with patch.dict(os.environ, {"UBS_RULES": cleared}):
                        self.assertIsNotNone(daemon.snapshot(self.project, UBS), cleared)
                self.config({"rules": []})
                with patch.dict(os.environ, {"UBS_RULES": str(rules)}):
                    self.assertIsNone(daemon.snapshot(self.project, UBS))
                for malformed in ("{", "[]", '{"rules":[],"rules":[]}', '{"rules":NaN}',
                                  '{"rules":null}', " " * (256 * 1024 + 1)):
                    self.write(".ubs.json", malformed)
                    with patch.dict(os.environ, {"UBS_RULES": ""}):
                        self.assertIsNone(daemon.snapshot(self.project, UBS), malformed[:100])
        finally:
            self.project = original


class ScanConfigWatchTests(ScanConfigFixture, unittest.TestCase):
    def test_nested_file_watch_rediscovers_policy_after_git_root_creation(self):
        original = self.project
        self.project = Path(tempfile.mkdtemp(prefix="ubs-config-nested-watch-"))
        try:
            source = self.write("nested/app.py", "value = 1\n")
            self.config({"skip": [7]})
            nested = source.parent
            config = nested / ".ubs.json"
            request = {"protocol": 1, "op": "scan", "root": str(self.project), "paths": ["nested/app.py"],
                       "environment": daemon.environment_key(), "scanner": str(UBS), "format": "json"}
            transitions = iter((
                lambda: self.config({"skip": [7]}, root=nested),
                lambda: self.config({"skip": []}, root=nested),
                lambda: config.rename(self.work / "saved-nested-policy.json"),
                lambda: self.git("init", "-q", "-b", "main"),
                lambda: self.config({"skip": []}),
            ))
            original_observer = daemon.WatchObserver

            class AdvancingObserver(original_observer):
                def wait(self, seconds):
                    try:
                        change = next(transitions)
                    except StopIteration:
                        raise daemon.ServiceError("fixture observations complete")
                    change()

            output = io.StringIO()
            start = time.monotonic()
            with patch.object(daemon, "request_service", return_value={"root": str(self.project), "status": "ready"}) as transport, \
                    patch.object(daemon, "WatchObserver", AdvancingObserver), contextlib.redirect_stdout(output):
                code = daemon.watch(self.project, request, 30, 0.01, 60)
            result = subprocess.CompletedProcess(["ubs-daemon.watch", "nested/app.py"], code, output.getvalue(), "")
            self.record("nested-watch-policy", result.args, result, time.monotonic() - start)
            self.assertEqual(code, 2)
            transport.assert_called_once()
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            changes = [event for event in events if event["event"] == "changed"]
            self.assertEqual([event["generation"] for event in changes], [1, 2, 3, 4, 5, 6], events)
            self.assertEqual([event["watch_inputs"] for event in changes],
                             [["nested/.ubs.json"]] * 4 + [[".ubs.json"]] * 2)
            self.assertTrue(all(event["paths"] == ["nested/app.py"] for event in changes))
            self.assertEqual(source.read_text(), "value = 1\n")
            self.assertFalse(any(event["event"] in {"scanning", "invalid"} for event in events))
            self.assertIn("fixture observations complete", events[-1]["stderr"])
        finally:
            self.project = original

    def test_watch_refuses_policy_outside_the_served_subdirectory(self):
        source = self.write("nested/app.py", "value = 1\n")
        self.config({"skip": [7]})
        served = source.parent
        for selection, names in (("files", ["app.py"]), ("directory", ["."])):
            with self.subTest(selection=selection):
                request = {"protocol": 1, "op": "scan", "root": str(served), "paths": names,
                           "selection": selection, "environment": daemon.environment_key(),
                           "scanner": str(UBS), "format": "json"}
                output = io.StringIO()
                start = time.monotonic()
                with patch.object(daemon, "request_service", return_value={"root": str(served), "status": "ready"}) as transport, \
                        patch.object(daemon.WatchObserver, "wait", side_effect=daemon.ServiceError("fixture stop")) as wait, \
                        contextlib.redirect_stdout(output):
                    code = daemon.watch(served, request, 30, 0.01, 60)
                result = subprocess.CompletedProcess(["ubs-daemon.watch", selection], code, output.getvalue(), "")
                self.record("outside-policy-" + selection, result.args, result, time.monotonic() - start, cwd=served)
                self.assertEqual(code, 2)
                transport.assert_called_once()
                events = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(events[-1]["event"], "error", events)
                self.assertIn("outside the served repository", events[-1]["stderr"])
                self.assertIn("Git worktree root", events[-1]["stderr"])
                self.assertIn(str(self.project), events[-1]["stderr"])
                wait.assert_not_called()

    def test_automatic_config_preserves_explicit_dependency_bound_and_scope_checks(self):
        self.write("app.py", "value = 1\n")
        dependencies = tuple(f"optional-policy-{index}" for index in range(256))
        before, errors = daemon.watch_inputs(self.project, ["app.py"], dependencies=dependencies,
                                              scan_config=".ubs.json")
        self.assertEqual(errors, [])
        self.config({"skip": [7]})
        after, errors = daemon.watch_inputs(self.project, ["app.py"], dependencies=dependencies,
                                             scan_config=".ubs.json")
        self.assertEqual(errors, [])
        self.assertNotEqual(before, after)
        with self.assertRaisesRegex(daemon.ServiceError, "256"):
            daemon.watch_inputs(self.project, ["app.py"], dependencies=(*dependencies, "one-too-many"),
                                scan_config=".ubs.json")
        config = self.project / ".ubs.json"
        config.rename(self.work / "saved-policy.json")
        outside = self.write("external-policy.json", "{}\n", root=self.work)
        config.symlink_to(outside)
        _, errors = daemon.watch_inputs(self.project, ["app.py"], scan_config=".ubs.json")
        self.assertTrue(any("outside the served repository" in error for error in errors), errors)

    def test_file_watch_observes_config_creation_edit_removal_and_explicit_dependencies(self):
        source = self.write("app.py", "value = 1\n")
        dependency = self.write("policy-data.txt", "old\n")
        config = self.project / ".ubs.json"
        request = {"protocol": 1, "op": "scan", "root": str(self.project), "paths": ["app.py"],
                   "environment": daemon.environment_key(), "scanner": str(UBS), "format": "json"}
        transitions = iter((
            lambda: self.config({"skip": [7]}),
            lambda: self.config({"skip": []}),
            lambda: config.rename(self.work / "removed-policy.json"),
            lambda: dependency.write_text("changed\n", encoding="utf-8"),
        ))
        original_observer = daemon.WatchObserver

        class AdvancingObserver(original_observer):
            def wait(self, seconds):
                try:
                    change = next(transitions)
                except StopIteration:
                    raise daemon.ServiceError("fixture observations complete")
                change()

        output = io.StringIO()
        start = time.monotonic()
        # Only the initial service-ready exchange is a transport double. The
        # real watcher and descriptor reader inspect every fixture transition;
        # a long debounce prevents a scanner request in this policy-only test.
        with patch.object(daemon, "request_service", return_value={"root": str(self.project), "status": "ready"}) as transport, \
                patch.object(daemon, "WatchObserver", AdvancingObserver), contextlib.redirect_stdout(output):
            code = daemon.watch(self.project, request, 30, 0.01, 60, dependencies=("policy-data.txt",))
        result = subprocess.CompletedProcess(["ubs-daemon.watch", "app.py"], code, output.getvalue(), "")
        self.record("watch-policy", result.args, result, time.monotonic() - start)
        self.assertEqual(code, 2)
        transport.assert_called_once()
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        changes = [event for event in events if event["event"] == "changed"]
        self.assertEqual([event["generation"] for event in changes], [1, 2, 3, 4, 5], events)
        self.assertTrue(all(previous["source_fingerprint"] != current["source_fingerprint"]
                            for previous, current in zip(changes, changes[1:])))
        # Removing the config restores the same byte policy as initial absence.
        self.assertEqual(changes[0]["source_fingerprint"], changes[3]["source_fingerprint"])
        self.assertTrue(all(set(event["watch_inputs"]) == {".ubs.json", "policy-data.txt"} for event in changes))
        self.assertTrue(all(event["paths"] == ["app.py"] for event in changes))
        self.assertEqual(source.read_text(), "value = 1\n")
        self.assertFalse(any(event["event"] == "scanning" for event in events))
        self.assertEqual(events[-1]["event"], "error")
        self.assertIn("fixture observations complete", events[-1]["stderr"])


if __name__ == "__main__":
    unittest.main()
