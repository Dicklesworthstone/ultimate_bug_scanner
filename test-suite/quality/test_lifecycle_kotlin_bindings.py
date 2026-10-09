"""Independent Kotlin resource-identity oracle for mj1j.17 / mj1j.18.

The expected obligations follow the public APIs rather than an implementation:
https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.io/use.html
https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/Closeable.html
https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/FileInputStream.html
https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/Files.html

Kotlin use closes its receiver on normal and exceptional exits, and returns the
block's result. Returning that receiver therefore exports a closed resource.
Closing Java Closeable twice is permitted; no double-close finding is expected.
Files.lines/walk streams own resources even after a terminal stream operation.
IO operations can throw before a later unprotected close. Cases are compiled
separately from analysis and never execute their file/network operations.

Set UBS_KOTLIN_RESOURCE_E2E=1 for actual module/meta-runner integration probes.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
import uuid
from unittest.mock import patch

import test_kotlin_native_semantics as native

ROOT = native.ROOT
kotlin_scan = native.kotlin_scan
UNCLOSED = "kotlin.resource.unclosed"
CLOSED = "kotlin.resource.use-after-close"
ESCAPE = "kotlin.resource.escape-from-use"
RULES = {UNCLOSED, CLOSED, ESCAPE}
ONLY_RESOURCE = set(range(1, 23)) - {19}


@dataclass(frozen=True)
class Case:
    name: str
    code: str

    @property
    def source(self):
        return textwrap.dedent(self.code).strip("\n") + "\n"

    @property
    def expected(self):
        markers = {"unclosed": UNCLOSED, "closed": CLOSED, "escape": ESCAPE}
        return sorted((rule, number) for number, line in enumerate(self.source.splitlines(), 1)
                      for marker, rule in markers.items() if "// expect:" + marker in line)


CASES = (
    Case("file_input_unclosed", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
        }
        '''),
    Case("file_input_closed", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin")
            stream.close()
        }
        '''),
    Case("file_output_unclosed", '''
        import java.io.FileOutputStream
        fun f() {
            val stream = FileOutputStream("output.bin") // expect:unclosed
        }
        '''),
    Case("file_reader_unclosed", '''
        import java.io.FileReader
        fun f() {
            val reader = FileReader("input.txt") // expect:unclosed
        }
        '''),
    Case("file_writer_unclosed", '''
        import java.io.FileWriter
        fun f() {
            val writer = FileWriter("output.txt") // expect:unclosed
        }
        '''),
    Case("random_access_unclosed", '''
        import java.io.RandomAccessFile
        fun f() {
            val file = RandomAccessFile("input.bin", "r") // expect:unclosed
        }
        '''),
    Case("files_input_unclosed", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path) {
            val stream = Files.newInputStream(path) // expect:unclosed
        }
        '''),
    Case("files_output_unclosed", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path) {
            val stream = Files.newOutputStream(path) // expect:unclosed
        }
        '''),
    Case("files_reader_unclosed", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path) {
            val reader = Files.newBufferedReader(path) // expect:unclosed
        }
        '''),
    Case("files_writer_unclosed", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path) {
            val writer = Files.newBufferedWriter(path) // expect:unclosed
        }
        '''),
    Case("files_lines_terminal_does_not_close", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path): Long {
            val lines = Files.lines(path) // expect:unclosed
            return lines.count()
        }
        '''),
    Case("files_lines_use_closes", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path): Long {
            return Files.lines(path).use { lines -> lines.count() }
        }
        '''),
    Case("files_walk_unclosed", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path) {
            val entries = Files.walk(path) // expect:unclosed
        }
        '''),
    Case("files_walk_use_closes", '''
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path): Long = Files.walk(path).use { it.count() }
        '''),
    Case("socket_unclosed", '''
        import java.net.Socket
        fun f() {
            val socket = Socket("localhost", 8080) // expect:unclosed
        }
        '''),
    Case("server_socket_closed_twice", '''
        import java.net.ServerSocket
        fun f() {
            val socket = ServerSocket(0)
            socket.close()
            socket.close()
        }
        '''),
    Case("kotlin_file_extension_unclosed", '''
        import java.io.File
        fun f() {
            val stream = File("input.bin").inputStream() // expect:unclosed
        }
        '''),
    Case("kotlin_file_extension_use", '''
        import java.io.File
        fun f(): String = File("input.txt").bufferedReader().use { it.readLine() }
        '''),
    Case("alias_closes_selected_handle", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin")
            val copy = stream
            copy.close()
        }
        '''),
    Case("unrelated_close_leaves_obligation", '''
        import java.io.FileInputStream
        import java.io.InputStream
        fun f(other: InputStream) {
            val stream = FileInputStream("input.bin") // expect:unclosed
            other.close()
        }
        '''),
    Case("rebind_loses_original_handle", '''
        import java.io.FileInputStream
        fun f() {
            var stream = FileInputStream("first.bin") // expect:unclosed
            stream = FileInputStream("second.bin")
            stream.close()
        }
        '''),
    Case("alias_survives_rebind", '''
        import java.io.FileInputStream
        fun f() {
            var stream = FileInputStream("first.bin")
            val copy = stream
            try {
                stream = FileInputStream("second.bin")
                stream.close()
            } finally { copy.close() }
        }
        '''),
    Case("one_branch_close_leaks", '''
        import java.io.FileInputStream
        fun f(close: Boolean) {
            val stream = FileInputStream("input.bin") // expect:unclosed
            if (close) stream.close()
        }
        '''),
    Case("both_branches_close", '''
        import java.io.FileInputStream
        fun f(close: Boolean) {
            val stream = FileInputStream("input.bin")
            if (close) stream.close() else stream.close()
        }
        '''),
    Case("early_return_leaks", '''
        import java.io.FileInputStream
        fun f(stop: Boolean) {
            val stream = FileInputStream("input.bin") // expect:unclosed
            if (stop) return
            stream.close()
        }
        '''),
    Case("explicit_throw_leaks", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            throw IllegalStateException("stop")
        }
        '''),
    Case("finally_closes_on_return_and_throw", '''
        import java.io.FileInputStream
        fun f(stop: Boolean) {
            val stream = FileInputStream("input.bin")
            try {
                if (stop) return
                throw IllegalStateException("stop")
            } finally { stream.close() }
        }
        '''),
    Case("io_failure_bypasses_later_close", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            stream.read()
            stream.close()
        }
        '''),
    Case("finally_closes_on_io_failure", '''
        import java.io.FileInputStream
        fun f(): Int {
            val stream = FileInputStream("input.bin")
            try { return stream.read() } finally { stream.close() }
        }
        '''),
    Case("use_named_parameter", '''
        import java.io.FileInputStream
        fun f(): Int = FileInputStream("input.bin").use { stream -> stream.read() }
        '''),
    Case("use_nonlocal_return", '''
        import java.io.FileInputStream
        fun f(): Int {
            FileInputStream("input.bin").use { return it.read() }
        }
        '''),
    Case("use_labeled_return", '''
        import java.io.FileInputStream
        fun f(stop: Boolean): Int {
            return FileInputStream("input.bin").use { stream ->
                if (stop) return@use 0
                stream.read()
            }
        }
        '''),
    Case("use_exception_closes", '''
        import java.io.FileInputStream
        fun f() {
            FileInputStream("input.bin").use { throw IllegalStateException("stop") }
        }
        '''),
    Case("return_transfers_live_handle", '''
        import java.io.FileInputStream
        fun f(): FileInputStream {
            val stream = FileInputStream("input.bin")
            return stream
        }
        '''),
    Case("return_alias_transfers_live_handle", '''
        import java.io.FileInputStream
        fun f(): FileInputStream {
            val stream = FileInputStream("input.bin")
            val copy = (stream)
            return copy
        }
        '''),
    Case("return_receiver_from_use_is_closed", '''
        import java.io.FileInputStream
        fun f(): FileInputStream {
            return FileInputStream("input.bin").use {
                it // expect:escape
            }
        }
        '''),
    Case("read_after_explicit_close", '''
        import java.io.FileInputStream
        fun f(): Int {
            val stream = FileInputStream("input.bin")
            stream.close()
            return stream.read() // expect:closed
        }
        '''),
    Case("alias_reads_closed_resource", '''
        import java.io.FileInputStream
        fun f(): Int {
            val stream = FileInputStream("input.bin")
            val copy = stream
            stream.close()
            return copy.read() // expect:closed
        }
        '''),
    Case("read_after_use_closed_receiver", '''
        import java.io.FileInputStream
        fun f(): Int {
            val stream = FileInputStream("input.bin")
            stream.use { it.read() }
            return stream.read() // expect:closed
        }
        '''),
    Case("double_close_is_valid", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin")
            stream.close()
            stream.close()
        }
        '''),
    Case("separate_function_close_does_not_discharge", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
        }
        fun g(stream: FileInputStream) { stream.close() }
        '''),
    Case("inner_parameter_close_is_unrelated", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            fun cleanup(stream: FileInputStream) { stream.close() }
        }
        '''),
    Case("constructor_import_alias", '''
        import java.io.FileInputStream as Source
        fun f() {
            val stream = Source("input.bin") // expect:unclosed
        }
        '''),
    Case("fully_qualified_constructor", '''
        fun f() {
            val stream = java.io.FileInputStream("input.bin") // expect:unclosed
        }
        '''),
    Case("local_type_shadows_constructor", '''
        class FileInputStream(val name: String)
        fun f() { val stream = FileInputStream("no-resource") }
        '''),
    Case("local_factory_shadows_import", '''
        import java.io.FileInputStream
        fun f() {
            fun FileInputStream(name: String): String = name
            val stream = FileInputStream("no-resource")
        }
        '''),
    Case("builtin_use_import_alias", '''
        import java.io.FileInputStream
        import kotlin.io.use as managed
        fun f(): Int = FileInputStream("input.bin").managed { it.read() }
        '''),
    Case("custom_use_does_not_close", '''
        import java.io.FileInputStream
        fun FileInputStream.use(block: (FileInputStream) -> Unit) { block(this) }
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            stream.use { println("visited") }
        }
        '''),
    Case("lexical_decoys_do_not_acquire", '''
        fun f() {
            val example = """FileInputStream("input.bin").read()"""
            // val stream = java.io.FileInputStream("input.bin")
            /* val other = java.io.FileOutputStream("output.bin") */
            println(example)
        }
        '''),
    Case("all_selected_factories_close_with_use", '''
        import java.io.File
        import java.io.FileOutputStream
        import java.io.FileReader
        import java.io.FileWriter
        import java.io.RandomAccessFile
        import java.nio.file.Files
        import java.nio.file.Path
        fun f(path: Path) {
            FileOutputStream("output.bin").use { it.write(1) }
            FileReader("input.txt").use { it.read() }
            FileWriter("output.txt").use { it.write("ok") }
            RandomAccessFile("input.bin", "r").use { it.read() }
            Files.newInputStream(path).use { it.read() }
            Files.newOutputStream(path).use { it.write(1) }
            Files.newBufferedReader(path).use { it.readLine() }
            Files.newBufferedWriter(path).use { it.write("ok") }
            File("output.txt").writer().use { it.write("ok") }
            File("output.bin").outputStream().use { it.write(1) }
        }
        '''),
    Case("static_factory_import_alias", '''
        import java.nio.file.Files.newInputStream as openInput
        import java.nio.file.Path
        fun f(path: Path) {
            val stream = openInput(path) // expect:unclosed
        }
        '''),
    Case("files_object_shadow_is_not_java_factory", '''
        object Files { fun newInputStream(path: String): String = path }
        fun f() { val stream = Files.newInputStream("no-resource") }
        '''),
    Case("write_after_close", '''
        import java.io.FileOutputStream
        fun f() {
            val stream = FileOutputStream("output.bin")
            stream.close()
            stream.write(1) // expect:closed
        }
        '''),
    Case("read_open_handle_with_finally_is_safe", '''
        import java.io.FileInputStream
        fun f(): Int {
            val stream = FileInputStream("input.bin")
            try { return stream.read() } finally { stream.close() }
        }
        '''),
    Case("conditional_close_can_reach_invalid_read", '''
        import java.io.FileInputStream
        fun f(close: Boolean): Int {
            val stream = FileInputStream("input.bin")
            try {
                if (close) stream.close()
                return stream.read() // expect:closed
            } finally { stream.close() }
        }
        '''),
    Case("closed_alias_does_not_close_new_binding", '''
        import java.io.FileInputStream
        fun f(): Int {
            var stream = FileInputStream("first.bin")
            val old = stream
            old.close()
            stream = FileInputStream("second.bin")
            try { return stream.read() } finally { stream.close() }
        }
        '''),
    Case("outer_use_does_not_own_inner_acquisition", '''
        import java.io.FileInputStream
        fun f() {
            FileInputStream("first.bin").use {
                val inner = FileInputStream("second.bin") // expect:unclosed
            }
        }
        '''),
    Case("nested_use_closes_both_handles", '''
        import java.io.FileInputStream
        fun f() {
            FileInputStream("first.bin").use {
                FileInputStream("second.bin").use { inner -> inner.read() }
            }
        }
        '''),
    Case("println_is_not_ownership_transfer", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            println(stream)
        }
        '''),
    Case("unrelated_callback_before_acquisition", '''
        import java.io.FileInputStream
        fun f(action: () -> Unit) {
            action()
            FileInputStream("input.bin").use { it.read() }
        }
        '''),
    Case("catch_runtime_exception_parent_closes", '''
        import java.io.FileInputStream
        fun f() {
            val stream = FileInputStream("input.bin")
            try { throw IllegalStateException("stop") }
            catch (problem: RuntimeException) { stream.close() }
        }
        '''),
    Case("catch_unrelated_io_does_not_close_runtime", '''
        import java.io.FileInputStream
        import java.io.IOException
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            try { throw IllegalStateException("stop") }
            catch (problem: IOException) { stream.close() }
        }
        '''),
    Case("catch_explicit_io_closes", '''
        import java.io.FileInputStream
        import java.io.IOException
        fun f() {
            val stream = FileInputStream("input.bin")
            try { throw IOException("stop") }
            catch (problem: IOException) { stream.close() }
        }
        '''),
    Case("catch_unrelated_runtime_does_not_close_io", '''
        import java.io.FileInputStream
        import java.io.IOException
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
            try { throw IOException("stop") }
            catch (problem: RuntimeException) { stream.close() }
        }
        '''),
    Case("use_returns_closed_resource_callback", '''
        import java.io.FileInputStream
        fun f(): () -> Int = FileInputStream("input.bin").use { stream ->
            { stream.read() } // expect:escape
        }
        '''),
    Case("use_returns_unrelated_callback", '''
        import java.io.FileInputStream
        fun f(): () -> Int = FileInputStream("input.bin").use { stream ->
            { 1 }
        }
        '''),
    Case("unrelated_recursion_does_not_poison_managed_resource", '''
        import java.io.FileInputStream
        fun sum(n: Int): Int = if (n <= 0) 0 else sum(n - 1) + n
        fun f(): Int = FileInputStream("input.bin").use { it.read() }
        '''),
    Case("unrelated_recursion_does_not_hide_unclosed_resource", '''
        import java.io.FileInputStream
        fun sum(n: Int): Int = if (n <= 0) 0 else sum(n - 1) + n
        fun f() {
            val stream = FileInputStream("input.bin") // expect:unclosed
        }
        '''),
    Case("third_iteration_resource_is_unclosed", '''
        import java.io.FileInputStream
        fun f() {
            var i = 0
            while (i < 3) {
                val stream = FileInputStream("input.bin") // expect:unclosed
                i++
                if (i < 3) stream.close()
            }
        }
        '''),
    Case("all_loop_iterations_close_selected_resource", '''
        import java.io.FileInputStream
        fun f() {
            var i = 0
            while (i < 3) {
                val stream = FileInputStream("input.bin")
                i++
                stream.close()
            }
        }
        '''),
)
BY_NAME = {case.name: case for case in CASES}

UNSUPPORTED_CASES = (
    Case("unknown_resource_argument", '''
        import java.io.FileInputStream
        fun f(action: (FileInputStream) -> Unit) {
            val stream = FileInputStream("input.bin")
            action(stream)
        }
        '''),
    Case("unknown_callback_captures_resource", '''
        import java.io.FileInputStream
        fun f(action: (() -> Unit) -> Unit) {
            val stream = FileInputStream("input.bin")
            action { stream.close() }
        }
        '''),
    Case("unknown_heap_ownership", '''
        import java.io.FileInputStream
        fun f(handles: MutableMap<String, FileInputStream>) {
            val stream = FileInputStream("input.bin")
            handles["selected"] = stream
        }
        '''),
)
MALFORMED = Case("malformed_resource_body", '''
    import java.io.FileInputStream
    fun f() {
        val stream = FileInputStream("input.bin")
    ''')


class LoggedResourceCase(native.LoggedKotlinCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / "test-suite/artifacts/kotlin-resource-bindings" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifacts.mkdir(parents=True)
        paths = (Path(__file__), ROOT / "modules/helpers/ubs_core/kotlin_scan.py",
                 ROOT / "modules/helpers/ubs_core/analyzers/lifecycle_kotlin.py")
        identity = {"python": sys.version, "executable": sys.executable,
                    "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=30).strip(),
                    "sources": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in paths if path.is_file()}}
        (cls.artifacts / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
        print(f"[{cls.__name__}] artifacts: {cls.artifacts}", flush=True)

    def assert_records(self, case, records):
        actual = sorted((record["rule"], record["line"]) for record in records
                        if record["rule"].startswith("kotlin.resource."))
        self.assertEqual(actual, case.expected, (case.source, records))
        for record in records:
            if record["rule"].startswith("kotlin.resource."):
                self.assertIn(record["rule"], RULES, record)
                self.assertEqual(record["severity"], "warning", record)
                self.assertEqual(record["category_id"], "kotlin.resource-lifecycle", record)
                self.assertGreater(record["col"], 0, record)
                self.assertEqual(Path(record["path"]).name, "Input.kt", record)


class KotlinResourceAnalyzerTests(LoggedResourceCase):
    def test_selected_resource_bindings_and_exit_paths(self):
        for case in CASES:
            with self.subTest(case=case.name):
                directory, source = self.fixture(case)
                sink, stdout, stderr = io.StringIO(), io.StringIO(), io.StringIO()
                started = time.monotonic()
                status, error, records = "FAIL", None, []
                print(f"[{case.name}] RUN", flush=True)
                try:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        kotlin_scan.scan_analyzers([source], sink, ONLY_RESOURCE)
                    records = [json.loads(line) for line in sink.getvalue().splitlines() if line]
                    self.assert_records(case, records)
                    status = "PASS"
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    (directory / "stdout.log").write_text(stdout.getvalue(), encoding="utf-8")
                    (directory / "stderr.log").write_text(stderr.getvalue(), encoding="utf-8")
                    (directory / "result.json").write_text(json.dumps({
                        "case": case.name, "expected": case.expected, "status": status,
                        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "elapsed": time.monotonic() - started, "error": error, "findings": records,
                    }, indent=2) + "\n", encoding="utf-8")
                    print(f"[{case.name}] {status} ({time.monotonic() - started:.3f}s)", flush=True)

    def test_selected_unknown_shapes_and_budgets_are_incomplete(self):
        cases = [(case, {}) for case in (*UNSUPPORTED_CASES, MALFORMED)]
        cases.append((BY_NAME["file_input_unclosed"], {"UBS_KOTLIN_MAX_TOKENS": "5"}))
        for case, environment in cases:
            with self.subTest(case=case.name, environment=environment):
                directory, source = self.fixture(case, "-incomplete")
                sink, stdout, stderr = io.StringIO(), io.StringIO(), io.StringIO()
                errors = []
                started = time.monotonic()
                with patch.dict(os.environ, environment):
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        kotlin_scan.scan_analyzers([source], sink, ONLY_RESOURCE, errors=errors)
                (directory / "stdout.log").write_text(stdout.getvalue(), encoding="utf-8")
                (directory / "stderr.log").write_text(stderr.getvalue(), encoding="utf-8")
                (directory / "result.json").write_text(json.dumps({
                    "case": case.name, "expected": "incomplete", "errors": errors,
                    "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "elapsed": time.monotonic() - started, "environment": environment,
                    "sink": sink.getvalue(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertTrue(errors, (case.name, "selected unsupported work must not certify a clean scan", sink.getvalue()))

    def test_disabled_resource_category_does_not_parse_selected_syntax(self):
        _, source = self.fixture(MALFORMED, "-disabled")
        sink, errors = io.StringIO(), []
        kotlin_scan.scan_analyzers([source], sink, set(range(1, 23)), errors=errors)
        self.assertEqual(errors, [])
        self.assertEqual(sink.getvalue(), "")


PUBLIC_UNSAFE = Case("public_obligations", '''
    import java.io.FileInputStream
    fun leaked() {
        val stream = FileInputStream("input.bin") // expect:unclosed
    }
    fun closed(): Int {
        val stream = FileInputStream("input.bin")
        stream.close()
        return stream.read() // expect:closed
    }
    fun escaped(): FileInputStream {
        return FileInputStream("input.bin").use {
            it // expect:escape
        }
    }
    ''')
PUBLIC_SAFE = Case("public_managed", '''
    import java.io.FileInputStream
    fun closed() {
        val stream = FileInputStream("input.bin")
        stream.close()
    }
    fun managed(): Int = FileInputStream("input.bin").use { it.read() }
    fun transferred(): FileInputStream = FileInputStream("input.bin")
    ''')


@unittest.skipUnless(os.environ.get("UBS_KOTLIN_RESOURCE_E2E") == "1", "set UBS_KOTLIN_RESOURCE_E2E=1 for actual resource CLI scans")
class KotlinResourceCliTests(LoggedResourceCase):
    scan = native.KotlinNativeCliTests.scan
    meta_records = staticmethod(native.KotlinNativeCliTests.meta_records)

    def assert_sarif(self, case, payload):
        actual = []
        for run in payload["runs"]:
            for record in run["results"]:
                if record["ruleId"].startswith("kotlin.resource."):
                    self.assertEqual(record["level"], "warning", record)
                    location = record["locations"][0]["physicalLocation"]
                    self.assertTrue(location["artifactLocation"]["uri"].endswith("Input.kt"), record)
                    actual.append((record["ruleId"], location["region"]["startLine"]))
        self.assertEqual(sorted(actual), case.expected, payload)

    def test_public_json_sarif_and_exact_totals(self):
        for case in (PUBLIC_UNSAFE, PUBLIC_SAFE):
            for meta in (False, True):
                for fmt in ("json", "sarif"):
                    with self.subTest(case=case.name, meta=meta, format=fmt):
                        result, payload = self.scan(case, meta=meta, fmt=fmt)
                        self.assertEqual(result.returncode, 1 if case.expected else 0, (result.stdout, result.stderr))
                        if fmt == "sarif":
                            self.assert_sarif(case, payload)
                        else:
                            records = self.meta_records(payload) if meta else payload["findings"]
                            self.assert_records(case, records)
                            totals = payload["totals"] if meta else payload
                            self.assertEqual(totals["critical"], 0, payload)
                            self.assertEqual(totals["warning"], len(case.expected), payload)
                            if not meta:
                                self.assertEqual(payload["status"], "ok", payload)
                                self.assertEqual(payload["files"], 1, payload)

    def test_scoped_suppression_and_profiles(self):
        unsafe = BY_NAME["file_input_unclosed"]
        suppressed = Case("resource_suppressed", unsafe.source.replace("// expect:unclosed", "// ubs:ignore[" + UNCLOSED + "]"))
        wrong = Case("resource_wrong_suppression", unsafe.source.replace("// expect:unclosed", "// ubs:ignore[" + CLOSED + "] // expect:unclosed"))
        for case in (suppressed, wrong):
            with self.subTest(case=case.name):
                result, payload = self.scan(case, meta=True)
                self.assertEqual(result.returncode, 1 if case.expected else 0, (result.stdout, result.stderr))
                self.assert_records(case, self.meta_records(payload))
        for profile, exit_code in ((None, 0), ("strict", 1), ("loose", 0)):
            with self.subTest(profile=profile):
                flags = ("--profile=" + profile,) if profile else ()
                result, payload = self.scan(unsafe, meta=True, flags=flags, fail_on_warning=False,
                                            suffix="-profile-" + (profile or "default"))
                self.assertEqual(result.returncode, exit_code, (result.stdout, result.stderr))
                self.assert_records(unsafe, self.meta_records(payload))

    def test_cache_source_and_category_context(self):
        unsafe = BY_NAME["file_input_unclosed"]
        environment = {"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(self.artifacts / "shared-cache")}
        for iteration in range(2):
            result, payload = self.scan(unsafe, env_updates=environment, suffix="-cached")
            self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
            self.assert_records(unsafe, payload["findings"])
            if iteration:
                self.assertEqual(payload["extras"]["profile"]["cache_hits"], 1, payload)
        safe = Case(unsafe.name, BY_NAME["file_input_closed"].source)
        result, payload = self.scan(safe, env_updates=environment, suffix="-cached")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_records(safe, payload["findings"])
        self.assertEqual(payload["extras"]["profile"]["cache_misses"], 1, payload)
        result, payload = self.scan(unsafe, flags=("--skip=19",), env_updates=environment, suffix="-cached")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(payload["findings"], [], payload)
        result, payload = self.scan(unsafe, env_updates=environment, suffix="-cached")
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assert_records(unsafe, payload["findings"])

    def test_selected_unknown_budget_and_syntax_failures_are_publicly_partial(self):
        only_resource = ("--skip=" + ",".join(map(str, sorted(ONLY_RESOURCE))),)
        cases = ((UNSUPPORTED_CASES[0], {}), (MALFORMED, {}),
                 (BY_NAME["file_input_unclosed"], {"UBS_KOTLIN_MAX_TOKENS": "5"}))
        for case, environment in cases:
            with self.subTest(case=case.name, environment=environment):
                result, payload = self.scan(case, flags=only_resource, env_updates=environment, suffix="-partial")
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                self.assertEqual(payload["status"], "partial", payload)
                self.assertEqual(payload["module_error"], "ANALYZER_ERROR", payload)
                self.assertIn("lifecycle_kotlin", result.stderr, result.stderr)

    def test_nul_selection_and_ignored_sibling(self):
        directory = self.artifacts / "selection"
        inputs = directory / "sources"
        inputs.mkdir(parents=True)
        selected = inputs / "Input.kt"
        ignored = inputs / "Ignored.kt"
        selected.write_text(PUBLIC_SAFE.source, encoding="utf-8")
        ignored.write_text(PUBLIC_UNSAFE.source, encoding="utf-8")
        selection = directory / "selected-files.nul"
        selection.write_bytes(os.fsencode(selected) + b"\0")
        temporary = directory / "temporary"
        temporary.mkdir()
        environment = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_NO_CACHE="1", PYTHONDONTWRITEBYTECODE="1",
                           TMPDIR=str(temporary), XDG_CACHE_HOME=str(directory / "cache"))
        commands = (
            ["bash", str(ROOT / "modules/ubs-kotlin.sh"), "--ci", "--format=json", "--fail-on-warning",
             "--files-from=" + str(selection), str(inputs)],
            [str(ROOT / "ubs"), "--only=kotlin", "--ci", "--format=json", "--fail-on-warning",
             "--exclude=Ignored.kt", str(inputs)],
        )
        for index, command in enumerate(commands):
            with self.subTest(command=command):
                started = time.monotonic()
                result = subprocess.run(command, cwd=directory, env=environment, text=True, capture_output=True, timeout=120)  # ubs:ignore[py.security.command-injection] - trusted repo runner and fixed fixture argv, with shell=False.
                prefix = directory / ("selection-" + str(index))
                prefix.with_suffix(".stdout.log").write_text(result.stdout, encoding="utf-8")
                prefix.with_suffix(".stderr.log").write_text(result.stderr, encoding="utf-8")
                prefix.with_suffix(".command.json").write_text(json.dumps({
                    "command": command, "elapsed": time.monotonic() - started, "returncode": result.returncode,
                    "sources": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (selected, ignored)},
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                try:
                    payload = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(("Invalid scanner JSON", str(exc), command, result.stdout, result.stderr))
                if index == 0:
                    self.assertEqual(payload["files"], 1, payload)
                    self.assertEqual(payload["findings"], [], payload)
                else:
                    self.assertEqual(payload["totals"]["warning"], 0, payload)
                    self.assert_records(PUBLIC_SAFE, self.meta_records(payload))


if __name__ == "__main__":
    unittest.main(verbosity=2)
