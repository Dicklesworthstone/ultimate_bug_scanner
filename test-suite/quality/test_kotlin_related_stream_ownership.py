"""Independent API-contract oracle for socket streams and gzip ownership.

Socket input/output streams close their socket, including sibling stream aliases:
https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/Socket.html
Gzip construction performs I/O and can fail before use owns the wrapper:
https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/zip/GZIPInputStream.html
https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/zip/GZIPOutputStream.html
The gzip finish operation writes the trailer but does not close the backing stream.

Only the existing resource finding contract is asserted. The fixtures do not run
network or file operations. Set UBS_KOTLIN_RESOURCE_E2E=1 for real CLI scans.
"""
from __future__ import annotations

import os
import unittest

import test_lifecycle_kotlin_bindings as resources

Case = resources.Case

SOCKET_CASES = (
    Case("socket_stream_outer_use_covers_getter_failure", '''
        import java.net.Socket
        fun f() {
            Socket("localhost", 8080).use { socket ->
                socket.getInputStream().use { input -> input.read() }
            }
        }
        '''),
    Case("socket_stream_inner_use_misses_getter_failure", '''
        import java.net.Socket
        fun f() {
            val socket = Socket("localhost", 8080) // expect:unclosed
            socket.getInputStream().use { input -> input.read() }
        }
        '''),
    Case("socket_stream_finally_covers_getter_failure", '''
        import java.net.Socket
        fun f() {
            val socket = Socket("localhost", 8080)
            try {
                socket.getOutputStream().use { output -> output.write(1) }
            } finally {
                socket.close()
            }
        }
        '''),
    Case("closing_input_closes_output_alias", '''
        import java.net.Socket
        fun f() {
            Socket("localhost", 8080).use { socket ->
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                input.close()
                output.write(1) // expect:closed
            }
        }
        '''),
    Case("closing_socket_closes_input_alias", '''
        import java.net.Socket
        fun f() {
            Socket("localhost", 8080).use { socket ->
                val input = socket.getInputStream()
                socket.close()
                input.read() // expect:closed
            }
        }
        '''),
    Case("socket_stream_returned_from_use_is_closed", '''
        import java.io.InputStream
        import java.net.Socket
        fun f(): InputStream = Socket("localhost", 8080).use { socket ->
            socket.getInputStream() // expect:escape
        }
        '''),
    Case("socket_stream_helper_keeps_alias_identity", '''
        import java.io.InputStream
        import java.net.Socket as NetworkSocket
        fun input(socket: NetworkSocket): InputStream = socket.getInputStream()
        fun f() {
            NetworkSocket("localhost", 8080).use { socket ->
                val stream = input(socket)
                stream.close()
                socket.getOutputStream() // expect:closed
            }
        }
        '''),
    Case("socket_stream_member_wins_over_extension", '''
        import java.io.FileInputStream
        import java.io.InputStream
        import java.net.Socket
        fun Socket.getInputStream(): InputStream = FileInputStream("other.bin")
        fun f() {
            Socket("localhost", 8080).use { socket ->
                socket.getInputStream().close()
                socket.getOutputStream() // expect:closed
            }
        }
        '''),
    Case("separate_socket_binding_remains_open", '''
        import java.net.Socket
        fun f() {
            Socket("localhost", 8080).use { first ->
                Socket("localhost", 8081).use { second ->
                    first.getOutputStream().close()
                    second.getInputStream().use { input -> input.read() }
                }
            }
        }
        '''),
)

COMPRESSION_CASES = (
    Case("gzip_native_write_wins_over_closing_extension", '''
        import java.io.OutputStream
        import java.util.zip.GZIPOutputStream
        fun GZIPOutputStream.write(value: Int) { this.close() }
        fun f(raw: OutputStream) {
            val gzip = GZIPOutputStream(raw) // expect:unclosed
            gzip.write(1)
        }
        '''),
    Case("gzip_native_read_wins_over_closing_extension", '''
        import java.io.InputStream
        import java.util.zip.GZIPInputStream
        fun GZIPInputStream.read(): Int { this.close(); return -1 }
        fun f(raw: InputStream) {
            val gzip = GZIPInputStream(raw) // expect:unclosed
            gzip.read()
        }
        '''),
    Case("gzip_native_flush_wins_over_closing_extension", '''
        import java.io.OutputStream
        import java.util.zip.GZIPOutputStream
        fun GZIPOutputStream.flush() { this.close() }
        fun f(raw: OutputStream) {
            val gzip = GZIPOutputStream(raw) // expect:unclosed
            gzip.flush()
        }
        '''),
    Case("gzip_input_inner_use_misses_header_failure", '''
        import java.io.FileInputStream
        import java.util.zip.GZIPInputStream
        fun f() {
            GZIPInputStream(FileInputStream("input.gz")).use { it.read() } // expect:unclosed
        }
        '''),
    Case("gzip_output_inner_use_misses_header_failure", '''
        import java.io.FileOutputStream
        import java.util.zip.GZIPOutputStream
        fun f() {
            GZIPOutputStream(FileOutputStream("output.gz")).use { it.write(1) } // expect:unclosed
        }
        '''),
    Case("gzip_input_outer_use_covers_header_failure", '''
        import java.io.FileInputStream
        import java.util.zip.GZIPInputStream
        fun f() {
            FileInputStream("input.gz").use { raw ->
                GZIPInputStream(raw).use { it.read() }
            }
        }
        '''),
    Case("gzip_output_outer_use_covers_header_failure", '''
        import java.io.FileOutputStream
        import java.util.zip.GZIPOutputStream
        fun f() {
            FileOutputStream("output.gz").use { raw ->
                GZIPOutputStream(raw, true).use { it.write(1) }
            }
        }
        '''),
    Case("gzip_io_catch_closes_constructor_and_read_failure", '''
        import java.io.FileInputStream
        import java.io.IOException
        import java.util.zip.GZIPInputStream
        fun f() {
            val raw = FileInputStream("input.gz")
            try {
                GZIPInputStream(raw).use { it.read() }
            } catch (failure: IOException) {
                raw.close()
            }
        }
        '''),
    Case("gzip_format_catch_does_not_cover_all_io_failure", '''
        import java.io.FileInputStream
        import java.util.zip.GZIPInputStream
        import java.util.zip.ZipException
        fun f() {
            val raw = FileInputStream("input.gz") // expect:unclosed
            try {
                GZIPInputStream(raw).use { it.read() }
            } catch (failure: ZipException) {
                raw.close()
            }
        }
        '''),
    Case("gzip_finish_does_not_discharge_backing_obligation", '''
        import java.io.FileOutputStream
        import java.io.IOException
        import java.util.zip.GZIPOutputStream
        fun f() {
            val raw = FileOutputStream("output.gz") // expect:unclosed
            val gzip = try {
                GZIPOutputStream(raw)
            } catch (failure: IOException) {
                raw.close()
                return
            }
            gzip.finish()
        }
        '''),
    Case("gzip_finish_preserves_live_backing_stream", '''
        import java.io.FileOutputStream
        import java.util.zip.GZIPOutputStream
        fun f() {
            FileOutputStream("output.gz").use { raw ->
                GZIPOutputStream(raw).use { gzip ->
                    gzip.finish()
                    raw.write(1)
                }
            }
        }
        '''),
    Case("gzip_close_reaches_backing_alias", '''
        import java.io.FileInputStream
        import java.util.zip.GZIPInputStream
        fun f() {
            FileInputStream("input.gz").use { raw ->
                val gzip = GZIPInputStream(raw)
                gzip.close()
                raw.read() // expect:closed
            }
        }
        '''),
    Case("gzip_size_failure_is_not_an_io_failure", '''
        import java.io.FileInputStream
        import java.io.IOException
        import java.util.zip.GZIPInputStream
        fun f() {
            val raw = FileInputStream("input.gz") // expect:unclosed
            try {
                GZIPInputStream(raw, 0).use { it.read() }
            } catch (failure: IOException) {
                raw.close()
            }
        }
        '''),
    Case("gzip_native_to_string_wins_over_closing_extension", '''
        import java.io.OutputStream
        import java.util.zip.GZIPOutputStream
        fun GZIPOutputStream.toString(): String { this.close(); return "closed" }
        fun f(raw: OutputStream) {
            val gzip = GZIPOutputStream(raw) // expect:unclosed
            gzip.toString()
        }
        '''),
    Case("gzip_native_hash_code_wins_over_closing_extension", '''
        import java.io.OutputStream
        import java.util.zip.GZIPOutputStream
        fun GZIPOutputStream.hashCode(): Int { this.close(); return 0 }
        fun f(raw: OutputStream) {
            val gzip = GZIPOutputStream(raw) // expect:unclosed
            gzip.hashCode()
        }
        '''),
    Case("gzip_native_equals_wins_over_closing_extension", '''
        import java.io.OutputStream
        import java.util.zip.GZIPOutputStream
        fun GZIPOutputStream.equals(other: Any?): Boolean { this.close(); return true }
        fun f(raw: OutputStream) {
            val gzip = GZIPOutputStream(raw) // expect:unclosed
            gzip.equals(null)
        }
        '''),
    Case("gzip_different_arity_metadata_extension_can_close", '''
        import java.io.OutputStream
        import java.util.zip.GZIPOutputStream
        fun GZIPOutputStream.toString(close: Boolean): String { this.close(); return "closed" }
        fun f(raw: OutputStream) {
            val gzip = GZIPOutputStream(raw)
            gzip.toString(true)
        }
        '''),
)


class KotlinRelatedStreamAnalyzerTests(resources.LoggedResourceCase):
    check_cases = resources.KotlinResourceAnalyzerTests.check_cases

    def test_socket_stream_shared_close_and_getter_failures(self):
        self.check_cases(SOCKET_CASES)

    def test_compression_construction_and_backing_ownership(self):
        self.check_cases(COMPRESSION_CASES)


@unittest.skipUnless(os.environ.get("UBS_KOTLIN_RESOURCE_E2E") == "1",
                     "set UBS_KOTLIN_RESOURCE_E2E=1 for actual resource CLI scans")
class KotlinRelatedStreamCliTests(resources.LoggedResourceCase):
    scan = resources.KotlinResourceCliTests.scan
    meta_records = staticmethod(resources.KotlinResourceCliTests.meta_records)
    assert_sarif = resources.KotlinResourceCliTests.assert_sarif

    def test_public_socket_and_compression_json_sarif(self):
        selected = {
            "gzip_native_write_wins_over_closing_extension",
            "gzip_input_inner_use_misses_header_failure",
            "gzip_native_to_string_wins_over_closing_extension",
            "gzip_native_hash_code_wins_over_closing_extension",
            "gzip_native_equals_wins_over_closing_extension",
            "gzip_different_arity_metadata_extension_can_close",
        }
        cases = (SOCKET_CASES[0], SOCKET_CASES[3],
                 *(case for case in COMPRESSION_CASES if case.name in selected))
        self.assertEqual(len(cases), 8)
        for case in cases:
            for meta in (False, True):
                for fmt in ("json", "sarif"):
                    with self.subTest(case=case.name, meta=meta, format=fmt):
                        result, payload = self.scan(case, meta=meta, fmt=fmt)
                        self.assertEqual(result.returncode, 1 if case.expected else 0,
                                         (result.stdout, result.stderr))
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

    def test_borrowed_backing_aliases_are_publicly_incomplete(self):
        names = {"borrowed_file_read_after_gzip_close", "borrowed_file_rewrapped_after_gzip_use"}
        cases = [case for case in resources.UNSUPPORTED_CASES if case.name in names]
        self.assertEqual(len(cases), 2)
        for case in cases:
            for meta in (False, True):
                for fmt in ("json", "sarif"):
                    with self.subTest(case=case.name, meta=meta, format=fmt):
                        result, payload = self.scan(case, meta=meta, fmt=fmt)
                        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                        if fmt == "sarif":
                            invocations = [invocation for run in payload["runs"]
                                           for invocation in run.get("invocations", [])]
                            self.assertTrue(any(invocation.get("executionSuccessful") is False
                                                for invocation in invocations), payload)
                            self.assertIn("incomplete", str(invocations).lower())
                        else:
                            scanners = payload["scanners"] if meta else [payload]
                            self.assertTrue(any(scanner.get("status") == "partial"
                                                and scanner.get("module_error") == "ANALYZER_ERROR"
                                                for scanner in scanners), payload)


if __name__ == "__main__":
    unittest.main()
