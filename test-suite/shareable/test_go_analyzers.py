#!/usr/bin/env python3
"""Go optional tools must provide fresh findings and truthful coverage (#128)."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit
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


class ChunkedReader:
    """Expose short binary reads and reject a whole-report read."""
    def __init__(self, source, chunk: int):
        self.source, self.chunk = source, chunk

    def read(self, size: int = -1):
        if not 0 < size <= 64 * 1024:
            raise AssertionError("native report reads must use bounded chunks")
        return self.source.read(min(size, self.chunk))


class Adapters(unittest.TestCase):
    def setUp(self) -> None:
        artifacts = REPO / "test-suite/artifacts/go-analyzers"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-go-adapter-", dir=artifacts)
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

    def test_vet_stream_retains_prefix_inside_unfinished_package(self) -> None:
        row = self.vet_doc()[MODULE]["printf"][0]
        prefix = ('{"' + MODULE + '":{"printf":[' + json.dumps(row)).encode()
        for tail in (b',{"posn":', b',]', b']', b']}} trailing failure',
                     b',{"posn":"main.go:4:1","message":"\xff"}]}}',
                     b',{"posn":"main.go:4:1","message":"bad","extra":NaN}]}}'):
            with self.subTest(tail=tail):
                sink, errors = io.StringIO(), []
                tools.GoFindings([self.file], self.root, sink).vet(io.BytesIO(prefix + tail), errors)
                self.assertEqual(len(sink.getvalue().splitlines()), 1)
                self.assertTrue(errors)

    def test_vet_stream_handles_fragmented_utf8_keys_strings_and_containers(self) -> None:
        file = self.root / "source-µ-\u2028.go"
        file.write_bytes(self.file.read_bytes())
        message = 'Quotes " and \\ escapes, {brackets} [arrays], unicode µ and \n newlines'
        doc = {MODULE: {"printf": [{"posn": f"{file}:3:2", "message": message,
                                    "fixes": [{"edits": [1, True, None, {"text": "]}"}]}]}]}}
        payload = ("# module\n# [module]\ngo: downloading example.invalid/dependency v1.0.0\n" +
                   json.dumps(doc, ensure_ascii=False) + "\n{}\n").encode()
        for chunk in (1, 2, 7, 64 * 1024):
            with self.subTest(chunk=chunk):
                sink, errors = io.StringIO(), []
                tools.GoFindings([file], self.root, sink).vet(ChunkedReader(io.BytesIO(payload), chunk), errors)
                self.assertEqual(errors, [])
                rows = [json.loads(line) for line in io.StringIO(sink.getvalue())]
                self.assertEqual([(row["path"], row["line"], row["col"], row["message"])
                                  for row in rows], [(str(file), 3, 2, message)])

    def test_vet_bounds_individual_values_and_depth_without_losing_prefix(self) -> None:
        row = json.dumps(self.vet_doc()[MODULE]["printf"][0])
        prefix = '{"' + MODULE + '":{"printf":[' + row + ','
        for tail, limit, message in (
            (json.dumps({"message": "x" * 300}), 256, "JSON value exceeds 256 bytes"),
            ("[" * 130 + "0" + "]" * 130, 4096, "JSON value nesting exceeds 128"),
        ):
            with self.subTest(message=message), patch.object(tools, "OUTPUT_RECORD_LIMIT", limit):
                sink, errors = io.StringIO(), []
                tools.GoFindings([self.file], self.root, sink).vet(
                    ChunkedReader(io.BytesIO((prefix + tail + ']}}').encode()), 7), errors)
                self.assertEqual(len(sink.getvalue().splitlines()), 1)
                self.assertIn(message, ";".join(errors))

    def test_vet_bounds_error_detail_but_checks_every_row(self) -> None:
        doc = self.vet_doc()
        doc[MODULE]["printf"] += [None] * 2000
        self.parser.vet(io.BytesIO(stream(doc).encode()), self.errors)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(len(self.errors), 5)
        self.assertIn("1996 additional report error(s)", self.errors[-1])

    def test_vet_read_error_preserves_accepted_diagnostics(self) -> None:
        prefix = ('{"' + MODULE + '":{"printf":[' +
                  json.dumps(self.vet_doc()[MODULE]["printf"][0]) + ',').encode()
        class BrokenReader:
            def __init__(self):
                self.started = False

            def read(self, size):
                if self.started:
                    raise OSError("captured output read failed")
                self.started = True
                return prefix

        self.parser.vet(BrokenReader(), self.errors)
        self.assertEqual(len(self.rows()), 1)
        self.assertIn("captured output read failed", ";".join(self.errors))

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

    def test_vulnerability_stream_has_no_total_output_ceiling(self) -> None:
        # Real protocol messages, generated on disk; progress does not become
        # a finding or require retention until the final symbol evidence.
        with tempfile.TemporaryFile(dir=self.root) as output:
            output.write((stream(config()) + "\n").encode())
            progress = (stream({"progress": {"message": "x" * 20_000}}) + "\n").encode()
            for _ in range(900):
                output.write(progress)
            output.write((stream(finding("module"), finding(source="excluded.go"),
                                 finding(), {"osv": {"id": OSV, "summary": "Late advisory"}}) + "\n").encode())
            self.assertGreater(output.tell(), tools.OUTPUT_LIMIT)
            output.seek(0)
            self.parser.govulncheck(ChunkedReader(output, 1024), self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["extras"]["reachability"], "symbol")
        self.assertIn("Late advisory", self.rows()[0]["message"])
        self.assertEqual(self.rows()[0]["path"], str(self.file))

    def test_vulnerability_stream_checks_invalid_utf8_size_depth_and_tail(self) -> None:
        prefix = (stream(config(), finding()) + "\n").encode()
        for tail, limit in ((b'{"progress":{"message":"\xff"}}', 4096),
                            (b'{"progress":{"message":"' + b"x" * 5000 + b'"}}', 4096),
                            (b'{"progress":' + b"[" * 130 + b"0" + b"]" * 130 + b"}", 4096)):
            with self.subTest(tail=tail[:50]), patch.object(tools, "OUTPUT_RECORD_LIMIT", limit):
                sink, errors = io.StringIO(), []
                tools.GoFindings([self.file], self.root, sink).govulncheck(
                    ChunkedReader(io.BytesIO(prefix + tail), 7), errors)
                self.assertTrue(errors)
                self.assertEqual(json.loads(sink.getvalue())["severity"], "critical")

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
        @contextmanager
        def run(tool, argv, root, timeout, errors, **kwargs):
            calls.append(argv)
            with io.BytesIO(("{}" if tool == "go vet" else stream(config())).encode()) as output:
                yield tools.ToolStreamOutput(0, output, "")
        with patch.object(tools.shutil, "which", side_effect=lambda t: None if t == "gofmt" else t), patch.object(tools, "run_command_stream", side_effect=run):
            tools.scan_go_tools([self.file], self.sink, str(self.root), './a "./space dir" "$(touch owned)"', 1, self.errors)
        self.assertEqual(self.errors, [])
        self.assertEqual(calls[0][-3:], ["./a", "./space dir", "$(touch owned)"])
        self.assertFalse((self.root / "owned").exists())

    def test_tool_options_cannot_be_smuggled_in_as_package_patterns(self) -> None:
        with patch.object(tools, "run_command_stream") as run:
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

    def test_timeout_keeps_diagnostics_inside_unfinished_native_package(self) -> None:
        prefix = '{"' + MODULE + '":{"printf":[' + json.dumps(self.vet_doc()[MODULE]["printf"][0]) + ','
        code = "import sys,time;sys.stderr.write(" + repr(prefix) + ");sys.stderr.flush();time.sleep(30)"
        with tools.run_command_stream("go vet", [sys.executable, "-c", code],
                                      self.root, 2, self.errors, merge_stderr=True) as output:
            self.assertIsNotNone(output)
            self.assertNotEqual(output.returncode, 0)
            self.parser.vet(output.stdout, self.errors)
            self.assertEqual(len(self.rows()), 1)
        self.assertTrue(output.stdout.closed)
        self.assertIn("timed out", ";".join(self.errors))
        self.assertIn("JSON", ";".join(self.errors))


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
    rows = [{"posn":str(Path.cwd()/"main.go")+":3:2", "message":"stub vet finding"}] if mode in ("finding","error","truncated") else []
    print("# sample\n# [sample]", file=sys.stderr)
    if mode == "truncated":
        print('{"example.invalid/sample":{"printf":[' + json.dumps(rows[0]) + ',', file=sys.stderr)
    else:
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
        artifacts = REPO / "test-suite/artifacts/go-analyzers"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-go-tools-", dir=artifacts)
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

    def test_truncated_vet_package_keeps_findings_and_failed_coverage(self) -> None:
        result = self.scan("--go-tools", "--format=json", vet="truncated")
        self.assertEqual(result.returncode, 2, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
        rows = [row for row in doc["findings"] if row["rule"] == "go.vet.printf"]
        self.assertEqual([(row["path"], row["line"], row["col"]) for row in rows],
                         [(str(self.file), 3, 2)])
        self.assertIn("JSON", doc["message"])

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


class DefaultNilDereference(unittest.TestCase):
    """The precise nil rule participates in ordinary reports and policy.

    No optional-analyzer flag or tool stub enables this rule. The same source
    contains nil-proven dereferences, safe control flow, a nil-safe method and
    an inline-suppressed dereference so both admission and precision matter.
    """

    RULE = "go.narrowing.nil_dereference"
    SOURCE = textwrap.dedent('''\
        package sample

        type Node struct { Value int }

        func nilField() int {
            var pointer *Node
            return pointer.Value // nil-field
        }
        func nilValue() int {
            var pointer *int
            return *pointer // nil-value
        }
        func notice() {}
        func fallsThrough(pointer *Node) int {
            if pointer == nil { notice() }
            return pointer.Value // fallthrough-field
        }
        func returningGuard(pointer *Node) int {
            if pointer == nil { return 0 }
            return pointer.Value
        }
        func repaired() int {
            var pointer *Node
            if pointer == nil { pointer = &Node{Value: 1} }
            return pointer.Value
        }
        func (pointer *Node) OrZero() int {
            if pointer == nil { return 0 }
            return pointer.Value
        }
        func nilSafeMethod() int {
            var pointer *Node
            return pointer.OrZero()
        }
        func suppressed() int {
            var pointer *Node
            return pointer.Value // ubs:ignore[go.narrowing.nil_dereference]
        }
    ''')

    def setUp(self) -> None:
        artifacts = REPO / "test-suite/artifacts/go-nil-public"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=artifacts))
        self.root = self.base / "project"
        self.root.mkdir()
        self.file = self.root / "main.go"
        self.file.write_text(self.SOURCE, encoding="utf-8")
        self.sequence = 0
        self.env = dict(os.environ, NO_COLOR="1", CI="1", UBS_NO_AUTO_UPDATE="1",
                        UBS_ENABLE_AUTO_UPDATE="0", UBS_NO_CACHE="0", PYTHONDONTWRITEBYTECODE="1",
                        XDG_DATA_HOME=str(self.base / "data"), GOTOOLCHAIN="local",
                        GOPROXY="off", GOSUMDB="off", GOWORK="off", GOFLAGS="")
        for key in ("UBS_VERIFIED_ASSET_DIR", "UBS_ALLOW_UNVERIFIED_HELPERS", "UBS_SKIP_TYPE_NARROWING"):
            self.env.pop(key, None)

    def expected_sites(self):
        sites = []
        for marker, token in (("nil-field", "pointer.Value"), ("nil-value", "*pointer"),
                              ("fallthrough-field", "pointer.Value")):
            matches = [(number, line) for number, line in enumerate(self.SOURCE.splitlines(), 1)
                       if line.endswith("// " + marker)]
            self.assertEqual(len(matches), 1, marker)
            number, line = matches[0]
            sites.append((str(self.file), number, line.index(token) + 1, "warning", "golang.defer-nil"))
        return sorted(sites)

    def scan(self, endpoint: str, output: str, *options: str):
        self.sequence += 1
        artifacts = self.base / f"{self.sequence:02}-{endpoint}-{output}"
        artifacts.mkdir()
        command = (["bash", str(REPO / "ubs"), "--only=golang", "--no-config"]
                   if endpoint == "runner" else ["bash", str(REPO / "modules/ubs-golang.sh")])
        command += ["--ci", f"--format={output}", *options, str(self.root)]
        environment = dict(self.env, UBS_CACHE_DIR=str(self.base / ("cache-" + endpoint)))
        started = time.monotonic()
        result = subprocess.run(command, cwd=self.base, env=environment, capture_output=True,
                                text=True, timeout=120)
        (artifacts / "source.go").write_text(self.file.read_text(), encoding="utf-8")
        (artifacts / "stdout.txt").write_text(result.stdout, encoding="utf-8")
        (artifacts / "stderr.txt").write_text(result.stderr, encoding="utf-8")
        identity = {}
        for name in ("ubs", "modules/ubs-golang.sh", "modules/helpers/ubs_core/go_scan.py",
                     "modules/helpers/ubs_core/analyzers/narrowing_go.py"):
            identity[name] = hashlib.sha256((REPO / name).read_bytes()).hexdigest()
        (artifacts / "receipt.json").write_text(json.dumps({
            "command": command, "cwd": str(self.base), "exit_code": result.returncode,
            "elapsed_seconds": time.monotonic() - started, "source_sha256":
            hashlib.sha256(self.file.read_bytes()).hexdigest(), "assets": identity,
            "environment": {key: environment[key] for key in (
                "UBS_NO_CACHE", "UBS_CACHE_DIR", "UBS_NO_AUTO_UPDATE", "GOTOOLCHAIN")},
        }, indent=2) + "\n", encoding="utf-8")
        try:
            document = json.loads(result.stdout)
        except ValueError:
            self.fail(f"Invalid {output} report: {result.stdout}\n{result.stderr}")
        return result, document

    def assert_report(self, result, document, output, expected, *, exit_code=0):
        self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
        rows = []
        if output == "json":
            self.assertEqual(document["status"], "ok", document)
            counts = document.get("totals", document)
            self.assertEqual(counts["critical"], 0, counts)
            self.assertEqual(counts["warning"], len(expected), counts)
            for finding in document["findings"]:
                if finding.get("rule_id", finding.get("rule")) == self.RULE:
                    rows.append((finding.get("file", finding.get("path")), finding["line"],
                                 finding["col"], finding["severity"], finding["category_id"]))
        else:
            for run in document["runs"]:
                self.assertTrue(all(item.get("executionSuccessful", True)
                                    for item in run.get("invocations", [])), run)
                for finding in run.get("results", []):
                    if finding["ruleId"] == self.RULE:
                        self.assertEqual(len(finding["locations"]), 1, finding)
                        location = finding["locations"][0]["physicalLocation"]
                        uri = location["artifactLocation"]["uri"]
                        path = Path(unquote(urlsplit(uri).path))
                        if not path.is_absolute():
                            path = self.root / path
                        rows.append((str(path), location["region"]["startLine"],
                                     location["region"]["startColumn"], finding["level"],
                                     finding["properties"]["category_id"]))
        self.assertEqual(sorted(rows), expected, document)

    def test_default_reports_include_only_proven_nil_dereferences(self):
        expected = self.expected_sites()
        for endpoint in ("module", "runner"):
            for output in ("json", "sarif"):
                with self.subTest(endpoint=endpoint, output=output):
                    result, document = self.scan(endpoint, output)
                    self.assert_report(result, document, output, expected)
            result, document = self.scan(endpoint, "json", "--fail-on-warning")
            self.assert_report(result, document, "json", expected, exit_code=1)

    def test_category_skip_and_source_repair_invalidate_cached_nil_findings(self):
        expected = self.expected_sites()
        for endpoint in ("module", "runner"):
            with self.subTest(endpoint=endpoint):
                self.file.write_text(self.SOURCE, encoding="utf-8")
                for warm in (False, True):
                    result, document = self.scan(endpoint, "json")
                    self.assert_report(result, document, "json", expected)
                    scanner = (next(row for row in document["scanners"] if row["language"] == "golang")
                               if endpoint == "runner" else document)
                    profile = scanner["extras"]["profile"]
                    self.assertEqual(profile["cache_hits"], int(warm), profile)
                skip = "--skip-golang=20" if endpoint == "runner" else "--skip=20"
                result, document = self.scan(endpoint, "json", skip)
                self.assert_report(result, document, "json", [])
                repaired = self.SOURCE.replace("var pointer *Node", "pointer := &Node{Value: 1}")
                repaired = repaired.replace("var pointer *int", "value := 1\n    pointer := &value")
                repaired = repaired.replace("if pointer == nil { notice() }", "if pointer == nil { return 0 }")
                self.file.write_text(repaired, encoding="utf-8")
                result, document = self.scan(endpoint, "json")
                self.assert_report(result, document, "json", [])


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

    OFFLINE_GO = {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off", "GOFLAGS": ""}

    def native_printf_column(self, statement: str) -> int:
        """Ask this Go toolchain which column its printf check reports.

        Go releases differ: older vet anchors the diagnostic at the call,
        newer vet at the offending format directive. A one-diagnostic
        package outside the scanned tree pins the expectation to the
        toolchain under test instead of to one release.
        """
        artifacts = REPO / "test-suite/artifacts/go-analyzers"
        probe = tempfile.TemporaryDirectory(prefix="ubs-go-vet-probe-", dir=artifacts)
        self.addCleanup(probe.cleanup)
        root = Path(probe.name)
        (root / "go.mod").write_text("module example.invalid/probe\n\ngo 1.23\n")
        (root / "probe.go").write_text('package main\n\nimport "fmt"\n\nfunc main() {\n' + statement + '}\n')
        result = subprocess.run(["go", "vet", "-json", "./..."], cwd=root, capture_output=True,
                                text=True, timeout=120, env=dict(os.environ, **self.OFFLINE_GO))
        report = "\n".join(line for line in (result.stdout + result.stderr).splitlines()
                           if not line.startswith("#"))
        rows = json.loads(report)["example.invalid/probe"]["printf"]
        self.assertEqual(len(rows), 1, report)
        position = rows[0]["posn"].rsplit(":", 2)
        self.assertEqual((Path(position[0]).name, position[1]), ("probe.go", "6"), report)
        return int(position[2])

    def test_real_vet_keeps_every_diagnostic_beyond_sixteen_megabytes(self) -> None:
        # A real offline vet run, with 13,000 distinct source sites in one
        # package. Long but valid arguments grow the report past the former
        # aggregate cap without storing a giant fixture in the repository.
        column = self.native_printf_column('\tfmt.Printf("%d", "x")\n')
        files, expected = [], set()
        for number in range(13):
            path = self.root / f"part{number:02}.go"
            body = '\tfmt.Printf("%d", "' + "x" * 1200 + '")\n'
            path.write_text('package main\n\nimport "fmt"\n\n' +
                            f"func Check{number}() {{\n" + body * 1000 + '}\n')
            files.append(path)
            expected.update((str(path), line, column) for line in range(6, 1006))
        hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
        captured = {}
        capture, which = tools.run_command_stream, shutil.which

        @contextmanager
        def observe(*args, **kwargs):
            with capture(*args, **kwargs) as output:
                if args[0] == "go vet" and output is not None:
                    position = output.stdout.tell()
                    captured["size"] = output.stdout.seek(0, io.SEEK_END)
                    captured["exit"] = output.returncode
                    output.stdout.seek(position)
                yield output

        with patch.object(tools.shutil, "which", side_effect=lambda t: None if t == "govulncheck" else which(t)), \
             patch.object(tools, "run_command_stream", side_effect=observe), \
             patch.dict(os.environ, {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off", "GOFLAGS": ""}):
            outcomes = tools.scan_go_tools(files, self.sink, str(self.root), "./...", 120, self.errors)
        self.assertEqual(captured["exit"], 0)
        self.assertGreater(captured["size"], 16 * 1024 * 1024)
        self.assertEqual(self.errors, [])
        self.assertEqual(next(row["status"] for row in outcomes if row["tool"] == "go vet"), "ok")
        rows = [row for row in self.rows() if row["rule"] == "go.vet.printf"]
        self.assertEqual(len(rows), 13000)
        self.assertEqual({(row["path"], row["line"], row["col"]) for row in rows}, expected)
        self.assertTrue(all(row["severity"] == "warning" and "fmt.Printf format %d" in row["message"]
                            for row in rows))
        self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}, hashes)


@unittest.skipUnless(shutil.which("go"), "Go toolchain not available")
class LifecycleLocations(unittest.TestCase):
    """Category 17 findings name the leaking file and line, like their neighbours.

    The resource-lifecycle helper reports `<root-relative name>:<line>`. That
    token used to become the finding's file with line 0 (and `.:<line>` for a
    single-file target), so JSON, SARIF and editors pointed at no real file.
    Each leak below also discards an error, so `go.error-handling.blank-discards`
    marks the same line through the ordinary path handling.
    """
    LEAK = 'package main\n\nimport "os"\n\nfunc leak{n}() {{\n\n\tfh, _ := os.Open("in")\n\t_ = fh\n}}\n'
    NAMES = ("plain.go", "dir with space/spaced.go") + (
        ("odd:name.go", "odd\tname.go", "odd\nname.go", "odd\rname.go", "odd name.go")
        if os.name != "nt" else ())

    def setUp(self) -> None:
        artifacts = REPO / "test-suite/artifacts/go-analyzers"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-go-lifecycle-", dir=artifacts)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "project"
        for number, name in enumerate(self.NAMES):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.LEAK.format(n=number), encoding="utf-8")
        self.env = dict(os.environ, NO_COLOR="1", CI="1", UBS_NO_AUTO_UPDATE="1",
                        UBS_ENABLE_AUTO_UPDATE="0", PYTHONDONTWRITEBYTECODE="1",
                        UBS_CACHE_DIR=str(Path(self.tmp.name) / "cache"),
                        XDG_DATA_HOME=str(Path(self.tmp.name) / "data"),
                        GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOWORK="off", GOFLAGS="")
        for name in ("UBS_VERIFIED_ASSET_DIR", "UBS_ALLOW_UNVERIFIED_HELPERS"):
            self.env.pop(name, None)

    def scan(self, target: Path, fmt: str) -> dict:
        result = subprocess.run(
            [str(REPO / "ubs"), "--ci", "--no-config", "--only=golang", f"--format={fmt}", str(target)],
            cwd=self.tmp.name, env=self.env, capture_output=True, text=True, timeout=180)
        self.assertIn(result.returncode, (0, 1), result.stderr + result.stdout)
        return json.loads(result.stdout)

    def json_sites(self, report: dict, rule: str) -> set:
        self.assertEqual(report["status"], "ok", report.get("failed_modules"))
        return {(f["file"], f["line"]) for f in report["findings"] if f["rule_id"] == rule}

    def test_directory_scan_reports_each_leak_at_its_file_and_line(self) -> None:
        report = self.scan(self.root, "json")
        leaks = self.json_sites(report, "go.lifecycle.file_handle")
        self.assertEqual(leaks, self.json_sites(report, "go.error-handling.blank-discards"))
        self.assertEqual(leaks, {(str(self.root / name), 7) for name in self.NAMES})

    def test_single_file_scan_names_the_file_not_the_root(self) -> None:
        target = self.root / self.NAMES[0]
        report = self.scan(target, "json")
        leaks = self.json_sites(report, "go.lifecycle.file_handle")
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks, self.json_sites(report, "go.error-handling.blank-discards"))
        self.assertEqual({line for _, line in leaks}, {7})

    def test_single_file_message_and_text_name_the_file_not_the_root(self) -> None:
        # The helper names a single-file target "." (relative to itself). That
        # token must not reach the finding's message or the text report.
        target = self.root / self.NAMES[0]
        report = self.scan(target, "json")
        messages = [f["message"] for f in report["findings"] if f["rule_id"] == "go.lifecycle.file_handle"]
        self.assertEqual(len(messages), 1)
        self.assertIn(f"[{self.NAMES[0]}:7]", messages[0])
        text = subprocess.run(
            [str(REPO / "ubs"), "--ci", "--no-config", "--only=golang", "--format=text", str(target)],
            cwd=self.tmp.name, env=self.env, capture_output=True, text=True, timeout=180)
        self.assertIn(text.returncode, (0, 1), text.stderr + text.stdout)
        self.assertIn(f"{self.NAMES[0]}:7", text.stdout)
        self.assertNotIn(".:7", text.stdout)

    def test_sarif_locations_match_the_ordinary_go_findings(self) -> None:
        report = self.scan(self.root, "sarif")
        sites = {}
        for run in report["runs"]:
            for result in run.get("results", []):
                for location in result["locations"]:
                    physical = location["physicalLocation"]
                    sites.setdefault(result["ruleId"], set()).add(
                        (physical["artifactLocation"]["uri"], physical["region"]["startLine"]))
        leaks = sites.get("go.lifecycle.file_handle", set())
        self.assertEqual(len(leaks), len(self.NAMES))
        self.assertEqual(leaks, sites.get("go.error-handling.blank-discards"))
        self.assertEqual({line for _, line in leaks}, {7})


if __name__ == "__main__":
    unittest.main()
