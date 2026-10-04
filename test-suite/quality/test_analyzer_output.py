"""Complete-result publication for serial and parallel shared-core analyzers."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "modules" / "helpers"
sys.path.insert(0, str(HELPERS))
from ubs_core import cli


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        temporary = tempfile.TemporaryDirectory(prefix="ubs-output-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "report.ndjson"
        self.output.write_bytes(b'{"previous": true}\n')
        self.record = {"rule": "test.rule", "path": "source.py", "line": 1, "message": "é😀\nsecond line"}

    def tearDown(self):
        print(f"[{self.id()}] FINISHED ({time.monotonic() - self.started:.3f}s)", flush=True)

    def broken(self):
        yield self.record
        raise RuntimeError("late analyzer failure")

    def test_failed_analyzer_preserves_existing_report_bytes_and_inode(self):
        before = self.output.read_bytes(), self.output.stat().st_ino
        with self.assertRaisesRegex(RuntimeError, "late analyzer failure"):
            cli._write_ndjson(self.broken(), str(self.output))
        self.assertEqual((self.output.read_bytes(), self.output.stat().st_ino), before)
        self.assertEqual(list(self.root.iterdir()), [self.output])

    def test_failed_analyzer_does_not_emit_a_stdout_prefix(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaisesRegex(RuntimeError, "late analyzer failure"):
            cli._write_ndjson(self.broken(), "-")
        self.assertEqual(stdout.getvalue(), "")

    def test_encoding_error_after_valid_record_preserves_both_destinations(self):
        for invalid in ({"value": object()}, {"value": float("nan")}, {"value": "\ud800"}):
            for target in ("-", str(self.output)):
                with self.subTest(target=target, invalid=repr(invalid)):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout), self.assertRaises((TypeError, ValueError, UnicodeError)):
                        cli._write_ndjson(iter([self.record, invalid]), target)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(self.output.read_bytes(), b'{"previous": true}\n')
                    self.assertEqual(list(self.root.iterdir()), [self.output])

    def test_result_is_not_published_until_iterator_has_finished(self):
        stdout = io.StringIO()
        def findings():
            for _ in range(5):
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(self.output.read_bytes(), b'{"previous": true}\n')
                yield self.record
        with contextlib.redirect_stdout(stdout):
            count = cli._write_ndjson(findings(), "-")
        self.assertEqual(count, 5)
        self.assertEqual([json.loads(line) for line in stdout.getvalue().splitlines()], [self.record] * 5)
        stdout = io.StringIO()
        count = cli._write_ndjson(findings(), str(self.output))
        self.assertEqual(count, 5)
        self.assertEqual([json.loads(line) for line in self.output.read_text().splitlines()], [self.record] * 5)

    def test_empty_success_replaces_old_report_and_creates_missing_report(self):
        for path in (self.output, self.root / "new.ndjson"):
            self.assertEqual(cli._write_ndjson(iter(()), str(path)), 0)
            self.assertEqual(path.read_bytes(), b"")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_complete_file_is_atomically_replaced_in_same_directory(self):
        replace = os.replace
        observed = []
        def publication(source, target):
            observed.append((Path(source), Path(target)))
            self.assertEqual(Path(source).parent.parent, self.root)
            self.assertEqual(self.output.read_bytes(), b'{"previous": true}\n')
            self.assertEqual(json.loads(Path(source).read_text()), self.record)
            return replace(source, target)
        with patch.object(cli.os, "replace", side_effect=publication):
            self.assertEqual(cli._write_ndjson(iter([self.record]), str(self.output)), 1)
        self.assertEqual(len(observed), 1)
        self.assertEqual(json.loads(self.output.read_text()), self.record)
        self.assertEqual(list(self.root.iterdir()), [self.output])

    def test_failed_atomic_replace_leaves_previous_report_and_cleans_staging(self):
        with patch.object(cli.os, "replace", side_effect=OSError("rename failed")), self.assertRaises(OSError):
            cli._write_ndjson(iter([self.record]), str(self.output))
        self.assertEqual(self.output.read_bytes(), b'{"previous": true}\n')
        self.assertEqual(list(self.root.iterdir()), [self.output])

    def test_output_symlink_cannot_overwrite_an_unrelated_target(self):
        link = self.root / "link"
        link.symlink_to(self.output)
        with self.assertRaisesRegex(ValueError, "regular file"):
            cli._write_ndjson(iter([self.record]), str(link))
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.output.read_bytes(), b'{"previous": true}\n')

    def test_special_output_is_rejected_without_opening_or_replacing_it(self):
        pipe = self.root / "fifo"
        os.mkfifo(pipe)
        with self.assertRaisesRegex(ValueError, "regular file"):
            cli._write_ndjson(iter([self.record]), str(pipe))
        self.assertTrue(__import__('stat').S_ISFIFO(pipe.lstat().st_mode))

    def test_lazy_input_is_not_truncated_before_analysis(self):
        # Output can share an input pathname without truncating its bytes
        # before a lazy analyzer has had the opportunity to consume them.
        def findings():
            yield {"observed": self.output.read_text()}
        cli._write_ndjson(findings(), str(self.output))
        self.assertEqual(json.loads(self.output.read_text()), {"observed": '{"previous": true}\n'})

    def test_writer_does_not_keep_the_entire_report_in_memory(self):
        staged = tempfile.TemporaryFile
        copy = cli.shutil.copyfileobj
        calls = []
        def copy_chunks(source, target, length):
            calls.append(length)
            return copy(source, target, length)
        class Sink:
            def __init__(self):
                self.bytes = 0
                self.largest = 0
            def write(self, text):
                self.bytes += len(text)
                self.largest = max(self.largest, len(text))
                return len(text)
            def flush(self):
                pass
        sink = Sink()
        with patch.object(cli.tempfile, "TemporaryFile", wraps=staged) as spool, \
             patch.object(cli.shutil, "copyfileobj", side_effect=copy_chunks), contextlib.redirect_stdout(sink):
            count = cli._write_ndjson(({"text": "x" * 4096} for _ in range(1024)), "-")
        self.assertEqual(count, 1024)
        self.assertGreater(sink.bytes, 4 * 1024 * 1024)
        self.assertLessEqual(sink.largest, 65536)
        self.assertEqual(calls, [65536])
        spool.assert_called_once()

    def test_stdout_transfer_error_is_reported_not_swallowed(self):
        class Broken:
            def write(self, data):
                raise BrokenPipeError("reader closed")
            def flush(self):
                pass
        with contextlib.redirect_stdout(Broken()), self.assertRaises(BrokenPipeError):
            cli._write_ndjson(iter([self.record]), "-")

    def test_real_cli_analyzer_failure_is_exit_two_with_no_partial_result(self):
        # Deliberately failing registry analyzers exercise error handling,
        # not detector accuracy. The CLI and process boundaries are real.
        program = r'''
import sys
from ubs_core import analyzers, cli, registry

def first(ctx):
    yield {'rule':'test.partial','path':'a.py','line':1}
def later(ctx):
    raise RuntimeError('worker exploded')
registry._REGISTRY = {('guards','python'): [
    registry.Analyzer('guards','python','first',first),
    registry.Analyzer('guards','python','later',later)]}
raise SystemExit(cli.main(['guards','--lang','python','--files-from',sys.argv[1],
                          '--out',sys.argv[2],'--jobs',sys.argv[3]]))
'''
        selection = self.root / "files.nul"
        selection.write_bytes(b"a.py\0")
        for jobs in (1, 2, 8):
            for target in ("-", str(self.output)):
                with self.subTest(jobs=jobs, target=target):
                    result = subprocess.run([sys.executable, "-c", program, str(selection), target, str(jobs)],
                        env=dict(os.environ, PYTHONPATH=str(HELPERS), PYTHONDONTWRITEBYTECODE="1"),
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "", result.stdout)
                    self.assertIn("RuntimeError: worker exploded", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(self.output.read_bytes(), b'{"previous": true}\n')

    def test_actual_python_taint_cli_report_is_unchanged_by_staging(self):
        source = self.root / "a.py"
        source.write_text("eval(input())\n")
        selection = self.root / "files.nul"
        selection.write_bytes(os.fsencode(source) + b"\0")
        command = [sys.executable, "-m", "ubs_core", "taint", "--lang", "python", "--files-from", str(selection)]
        environment = dict(os.environ, PYTHONPATH=str(HELPERS), PYTHONDONTWRITEBYTECODE="1")
        direct = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=10)
        saved = subprocess.run(command + ["--out", str(self.output), "--jobs", "2"],
                               env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual((direct.returncode, saved.returncode), (0, 0), direct.stderr + saved.stderr)
        self.assertEqual(saved.stdout, "")
        self.assertEqual(self.output.read_text(), direct.stdout)
        self.assertEqual([r['rule'] for r in map(json.loads, direct.stdout.splitlines())], ['python.taint.eval'])


if __name__ == "__main__":
    unittest.main()
