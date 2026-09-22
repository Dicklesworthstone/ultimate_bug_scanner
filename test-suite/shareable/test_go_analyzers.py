#!/usr/bin/env python3
"""Go optional tools must provide fresh findings and truthful coverage (#128)."""
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

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "modules/helpers"))
from ubs_core import external_tools as tools

MODULE = "example.invalid/sample"
OSV = "GO-2026-0001"


def stream(*messages: dict) -> str:
    return "\n".join(json.dumps(m, indent=2) for m in messages)


def config() -> dict:
    return {"config": {"protocol_version": "v1.0.0", "scan_level": "symbol"}}


def finding(level: str = "symbol", source: str = "main.go") -> dict:
    frame = {"module": "example.invalid/dependency", "version": "v1.0.0"}
    if level != "module":
        frame["package"] = "example.invalid/dependency/pkg"
    trace = [frame]
    if level == "symbol":
        frame["function"] = "Dangerous"
        trace.append({"module": MODULE, "function": "main", "position": {
            "filename": source, "line": 3, "column": 2}})
    return {"finding": {"osv": OSV, "fixed_version": "v1.2.3", "trace": trace}}


class Adapters(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-go-adapter-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "go.mod").write_text(f"module {MODULE}\n\ngo 1.23\n")
        self.file = self.root / "main.go"
        self.file.write_text("package main\nfunc main() {\n println(1)\n}\n")
        self.sink, self.errors = io.StringIO(), []
        self.parser = tools.GoFindings([self.file], self.root, self.sink)

    def rows(self) -> list[dict]:
        return [json.loads(s) for s in self.sink.getvalue().splitlines()]

    def vet_doc(self, file: str = "main.go") -> dict:
        return {MODULE: {"printf": [{"posn": f"{file}:3:2", "message": "invalid format argument"}]}}

    def test_vet_json_findings_and_package_headings(self) -> None:
        self.parser.vet("# sample\n# [sample]\n" + stream(self.vet_doc(), {}), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(self.rows()[0]["rule"], "go.vet.printf")
        self.assertEqual(self.rows()[0]["severity"], "warning")

    def test_vet_error_object_is_incomplete_even_with_zero_exit(self) -> None:
        self.parser.vet(stream(self.vet_doc(), {"other": {"printf": {"error": "type checking failed"}}}), self.errors)
        self.assertIn("type checking failed", ";".join(self.errors))
        self.assertEqual(len(self.rows()), 1)

    def test_vet_empty_malformed_and_wrong_shape_are_not_clean(self) -> None:
        for output in ("", "panic: analyzer crashed", "[]", '{"pkg":[]}', '{"pkg":{"a":null}}'):
            with self.subTest(output=output):
                errors = []
                self.parser.vet(output, errors)
                self.assertTrue(errors)

    def test_vet_preserves_valid_rows_before_malformed_rows_and_tail(self) -> None:
        doc = self.vet_doc()
        doc[MODULE]["printf"] += [None, {"posn": "bad", "message": "bad"}]
        self.parser.vet(stream(doc) + '\n{"unfinished":', self.errors)
        self.assertEqual(len(self.rows()), 1)
        self.assertGreaterEqual(len(self.errors), 3)

    def test_vet_deduplicates_test_variants_and_rejects_unselected(self) -> None:
        self.parser.vet(stream(self.vet_doc(), self.vet_doc(), self.vet_doc("excluded.go")), self.errors)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.errors, [])

    def test_vet_statement_suppression_is_respected(self) -> None:
        self.file.write_text("package main\nfunc main() {\n println(1) // ubs:ignore[go.vet.printf]\n}\n")
        self.parser.vet(stream(self.vet_doc()), self.errors)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.errors, [])

    def test_vulnerability_stream_uses_strongest_evidence_and_retains_fix(self) -> None:
        self.parser.govulncheck(stream(config(), finding("module"), finding("package"), finding(), finding(),
                                      {"osv": {"id": OSV, "summary": "Unsafe input"}}), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.rows()), 1)
        row = self.rows()[0]
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["path"], str(self.file))
        self.assertEqual(row["extras"]["fixed_version"], "v1.2.3")
        self.assertEqual(row["extras"]["reachability"], "symbol")

    def test_unused_vulnerable_dependency_is_info_not_critical(self) -> None:
        self.parser.govulncheck(stream(config(), finding("module"), finding("package")), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["severity"], "info")
        self.assertEqual(self.rows()[0]["extras"]["scope"], "project")
        self.assertEqual(self.rows()[0]["extras"]["reachability"], "package")

    def test_osv_messages_alone_are_not_vulnerabilities(self) -> None:
        self.parser.govulncheck(stream(config(), {"osv": {"id": OSV}}, {"SBOM": {}}), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(self.rows(), [])

    def test_vulnerability_requires_valid_protocol_and_report(self) -> None:
        for output in ("", "{}", "null", stream(finding()), stream({"config": {"protocol_version": "v2"}}),
                       stream(config(), {"finding": {"osv": OSV, "trace": []}}), stream(config(), {"finding": None})):
            with self.subTest(output=output):
                errors = []
                self.parser.govulncheck(output, errors)
                self.assertTrue(errors)

    def test_vulnerability_truncated_tail_preserves_evidence(self) -> None:
        self.parser.govulncheck(stream(config(), finding()) + '\n{"finding":', self.errors)
        self.assertTrue(self.errors)
        self.assertEqual(self.rows()[0]["severity"], "critical")

    def test_unselected_callsite_is_not_readmitted(self) -> None:
        self.parser.govulncheck(stream(config(), finding(source="excluded.go")), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(self.rows(), [])

    def test_dependency_filename_is_not_attributed_to_local_source(self) -> None:
        row = finding()
        row["finding"]["trace"] = [row["finding"]["trace"][0]]
        row["finding"]["trace"][0]["position"] = {"filename": "main.go", "line": 3, "column": 1}
        self.parser.govulncheck(stream(config(), row), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(self.rows()[0]["path"], str(self.root / "go.mod"))
        self.assertEqual(self.rows()[0]["extras"]["scope"], "project")

    def test_missing_tools_are_optional(self) -> None:
        with patch.object(tools.shutil, "which", return_value=None), patch.object(tools, "run_command") as run:
            outcomes = tools.scan_go_tools([self.file], self.sink, str(self.root), "./...", 1, self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual({o["status"] for o in outcomes}, {"skipped"})
        run.assert_not_called()

    def test_package_patterns_are_argv_not_shell_code(self) -> None:
        calls = []
        def run(tool, argv, root, timeout, errors, **kwargs):
            calls.append(argv)
            return tools.ToolOutput(0, "{}" if tool == "go vet" else stream(config()), "")
        with patch.object(tools.shutil, "which", side_effect=lambda t: None if t == "gofmt" else t), patch.object(tools, "run_command", side_effect=run):
            tools.scan_go_tools([self.file], self.sink, str(self.root), './a "./space dir" "$(touch owned)"', 1, self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(calls[0][-3:], ["./a", "./space dir", "$(touch owned)"])
        self.assertFalse((self.root / "owned").exists())

    def test_tool_options_cannot_be_smuggled_in_as_package_patterns(self) -> None:
        with patch.object(tools, "run_command") as run:
            tools.scan_go_tools([self.file], self.sink, str(self.root), "-fix ./...", 1, self.errors)
        self.assertTrue(self.errors)
        run.assert_not_called()

    def test_selected_nested_modules_use_their_own_root(self) -> None:
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "go.mod").write_text("module example.invalid/nested\n")
        other = nested / "other.go"
        other.write_text("package nested\n")
        with patch.object(tools.shutil, "which", return_value=None):
            outcomes = tools.scan_go_tools([self.file, other], self.sink, str(self.root), "./...", 1, self.errors)
        self.assertEqual({o["root"] for o in outcomes}, {str(self.root), str(nested)})

    def test_merged_stderr_keeps_more_than_diagnostic_preview_limit(self) -> None:
        result = tools.run_command("go vet", [sys.executable, "-c", "import sys;sys.stderr.write('x'*12000)"],
                                   self.root, 5, self.errors, merge_stderr=True)
        self.assertEqual(self.errors, [])
        self.assertEqual(len(result.stdout), 12000)

    def test_real_process_timeout_is_incomplete(self) -> None:
        tools.run_command("go vet", [sys.executable, "-c", "import time;time.sleep(30)"],
                          self.root, 0.05, self.errors, merge_stderr=True)
        self.assertIn("timed out", ";".join(self.errors))


STUB = r'''#!PYTHON
import json, os, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
if name == "ast-grep":
    if "--version" in sys.argv: print("ast-grep 0.41.0")
    elif "--json=stream" not in sys.argv: print("[]")
    raise SystemExit(0)
if name == "go" and "run" in sys.argv:
    raise SystemExit(0)
key = {"go":"vet", "gofmt":"gofmt", "govulncheck":"vuln"}[name]
with open(os.environ["GO_TEST_LOG"], "a") as log:
    log.write(json.dumps({"tool":key,"cwd":os.getcwd(),"args":sys.argv[1:]}) + "\n")
mode = os.environ.get("GO_TEST_" + key.upper(), "clean")
if mode == "timeout":
    time.sleep(30)
if mode == "malformed":
    print('{"broken":', file=sys.stderr if name == "go" else sys.stdout)
    raise SystemExit(0)
if name == "gofmt":
    if mode == "finding": print(sys.argv[-1])
elif name == "go":
    rows = [{"posn":str(Path.cwd()/"main.go")+":3:2", "message":"stub vet finding"}] if mode in ("finding","error") else []
    print("# sample\n# [sample]", file=sys.stderr)
    print(json.dumps({"example.invalid/sample":{"printf":rows}}), file=sys.stderr)
else:
    print(json.dumps({"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}))
    if mode in ("finding","error"):
        print(json.dumps({"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[
            {"module":"example.invalid/dep","version":"v1.0.0","package":"example.invalid/dep","function":"Bad"},
            {"module":"example.invalid/sample","function":"main","position":{"filename":"main.go","line":3,"column":2}}
        ]}}))
raise SystemExit(1 if mode == "error" else 0)
'''


class Integration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-go-tools-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "project with spaces"
        self.root.mkdir()
        (self.root / "go.mod").write_text(f"module {MODULE}\n\ngo 1.23\n")
        self.file = self.root / "main.go"
        self.file.write_text("package main\nfunc main() {\n println(1)\n}\n")
        self.bin = self.base / "bin"
        self.bin.mkdir()
        for tool in ("go", "gofmt", "govulncheck", "ast-grep"):
            executable = self.bin / tool
            executable.write_text(STUB.replace("#!PYTHON", "#!" + sys.executable))
            executable.chmod(0o755)
        self.log = self.base / "calls.jsonl"
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ.get("PATH", ""),
                        NO_COLOR="1", CI="1", UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                        UBS_CACHE_DIR=str(self.base / "cache"), XDG_DATA_HOME=str(self.base / "data"),
                        PYTHONDONTWRITEBYTECODE="1", GO_TEST_LOG=str(self.log))
        self.env.pop("UBS_NO_CACHE", None)
        self.env.pop("UBS_VERIFIED_ASSET_DIR", None)
        self.env.pop("UBS_ALLOW_UNVERIFIED_HELPERS", None)

    def scan(self, *args: str, meta: bool = False, **modes: str):
        env = dict(self.env, **{"GO_TEST_"+k.upper():v for k,v in modes.items()})
        command = [str(REPO / "ubs"), "--only=golang", "--skip-golang=17"] if meta else [
            "bash", str(REPO / "modules/ubs-golang.sh"), "--skip=17"]
        return subprocess.run([*command, "--ci", *args, str(self.root)], cwd=self.base,
                              env=env, capture_output=True, text=True, timeout=60)

    def test_module_findings_enter_json_sink_and_exit_policy(self) -> None:
        sidecar = self.base / "findings.jsonl"
        result = self.scan("--go-tools", "--format=json", f"--report-json={sidecar}", vet="finding", vuln="finding", gofmt="finding")
        self.assertEqual(result.returncode, 1, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "ok")
        wanted = {"go.vet.printf", "go.govulncheck."+OSV, "go.gofmt.format"}
        self.assertTrue(wanted <= {f["rule"] for f in doc["findings"]})
        self.assertTrue(wanted <= {json.loads(s)["rule"] for s in sidecar.read_text().splitlines()})
        self.assertEqual({json.loads(s)["cwd"] for s in self.log.read_text().splitlines()}, {str(self.root)})

    def test_vet_failure_preserves_findings_and_marks_partial(self) -> None:
        result = self.scan("--go-tools", "--format=json", vet="error", vuln="finding")
        self.assertEqual(result.returncode, 2, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
        self.assertIn("go vet", doc["message"])
        self.assertTrue({"go.vet.printf", "go.govulncheck."+OSV} <= {f["rule"] for f in doc["findings"]})

    def test_warm_cache_retries_and_recovers_optional_tools(self) -> None:
        first = self.scan("--go-tools", "--format=json", vet="finding")
        second = self.scan("--go-tools", "--format=json", vet="error")
        third = self.scan("--go-tools", "--format=json")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 2, second.stderr)
        self.assertEqual(third.returncode, 0, third.stderr)
        doc = json.loads(third.stdout)
        self.assertEqual(doc["status"], "ok")
        self.assertGreater(doc["extras"]["profile"]["cache_hits"], 0)
        self.assertNotIn("go.vet.printf", {f["rule"] for f in doc["findings"]})
        self.assertEqual(sum(json.loads(s)["tool"] == "vet" for s in self.log.read_text().splitlines()), 3)

    def test_default_and_category_skip_do_not_run_tools(self) -> None:
        for args in (("--format=json",), ("--format=json", "--go-tools", "--skip=17,18")):
            result = self.scan(*args, vet="error")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())

    def test_text_does_not_claim_failed_tools_are_disabled(self) -> None:
        result = self.scan("--go-tools", "--format=text", vet="error")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Partial: [ANALYZER_ERROR]", result.stdout)
        self.assertIn("go vet: partial", result.stdout)
        self.assertNotIn("Go tools disabled", result.stdout)

    def test_sarif_keeps_failed_invocation_and_findings(self) -> None:
        result = self.scan("--go-tools", "--format=sarif", vet="error", vuln="finding")
        self.assertEqual(result.returncode, 2, result.stderr)
        doc = json.loads(result.stdout)
        self.assertTrue(any(r["results"] for r in doc["runs"]))
        self.assertTrue(any(not i["executionSuccessful"] for r in doc["runs"] for i in r["invocations"]))

    def test_meta_runner_routes_go_options_and_preserves_partial_results(self) -> None:
        result = self.scan("--go-tools", "--go-timeout=5", '--test-pkgs=./...', "--format=json", meta=True, vuln="error")
        self.assertEqual(result.returncode, 2, result.stderr)
        doc = json.loads(result.stdout)
        # Usable partial evidence remains partial even without another healthy
        # module. The nonzero coverage gate and the analyzer error still apply.
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["failed_modules"][0]["status"], "partial")
        self.assertEqual(doc["scanners"][0]["status"], "partial")
        self.assertEqual(doc["failed_modules"][0]["module_error"], "ANALYZER_ERROR")
        self.assertTrue(any(f["rule_id"] == "go.govulncheck."+OSV for f in doc["findings"]))

    def test_meta_mixed_language_options_only_reach_go(self) -> None:
        (self.root / "bad.sh").write_text('#!/bin/bash\neval "$INPUT"\n')
        result = self.scan("--only=golang,bash", "--go-tools", "--go-timeout=5", "--format=json",
                           meta=True, vet="error")
        self.assertEqual(result.returncode, 2, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "partial")
        bash = next(s for s in doc["scanners"] if s["language"] == "bash")
        self.assertEqual(bash["status"], "ok")
        self.assertGreater(bash["critical"], 0)

    def test_warning_policy_includes_vet(self) -> None:
        result = self.scan("--go-tools", "--format=json", "--fail-on-warning", vet="finding")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "ok")

    def test_timeout_still_runs_other_tools(self) -> None:
        # Only the deliberately sleeping tool must exceed the budget, leaving
        # enough time for the real interpreter to start on loaded CI workers.
        result = self.scan("--go-tools", "--go-timeout=5", "--format=json", vet="timeout")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("timed out", json.loads(result.stdout)["message"])
        self.assertEqual({json.loads(s)["tool"] for s in self.log.read_text().splitlines()}, {"gofmt", "vet", "vuln"})
        outcomes = {t["tool"]: t["status"] for t in json.loads(result.stdout)["extras"]["external_tools"]}
        self.assertEqual(outcomes, {"gofmt": "ok", "go vet": "partial", "govulncheck": "ok"})


@unittest.skipUnless(shutil.which("go") and shutil.which("gofmt"), "Go toolchain not available")
class RealGoTools(unittest.TestCase):
    setUp = Adapters.setUp
    rows = Adapters.rows
    # A real, offline standard-library package guards the actual vet JSON/exit
    # contract; stub-only tests cannot prove we chose the right protocol.
    def test_real_vet_json_finding_and_gofmt_are_read_only(self) -> None:
        self.file.write_text('package main\nimport "fmt"\nfunc main(){fmt.Printf("%d", "wrong")}\n')
        before = self.file.read_bytes()
        which = shutil.which
        with patch.object(tools.shutil, "which", side_effect=lambda t: None if t == "govulncheck" else which(t)), \
             patch.dict(os.environ, {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off", "GOFLAGS": ""}):
            result = tools.scan_go_tools([self.file], self.sink, str(self.root), "./...", 30, self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(self.file.read_bytes(), before)
        self.assertTrue({"go.vet.printf", "go.gofmt.format"} <= {f["rule"] for f in self.rows()})
        self.assertEqual(result[1]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
