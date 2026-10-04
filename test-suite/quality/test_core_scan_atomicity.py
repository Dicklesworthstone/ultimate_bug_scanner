"""Fail-closed worker execution and transactional core finding publication."""
from __future__ import annotations

from collections import Counter
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core import analyzers, cli, shards  # noqa: F401


class LoggedTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(case is self or getattr(case, 'test_case', None) is self
                     for case, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic()-started:.3f}s)', flush=True)
        return result


class WorkerAtomicityTests(LoggedTests):
    def test_completion_order_cannot_reorder_source_shards(self):
        third_running = threading.Event()
        fourth_done = threading.Event()

        def process(paths):
            if paths[0] == Path('first'):
                self.assertTrue(third_running.wait(2))
            elif paths[0] == Path('third'):
                third_running.set()
                self.assertTrue(fourth_done.wait(2))
            elif paths[0] == Path('fourth'):
                fourth_done.set()
            return [str(path) for path in paths]

        paths = ['first', 'second', 'third', 'fourth']
        self.assertEqual(shards.run_work_stealing(paths, process, 2, 1), paths)

    def test_worker_baseexception_is_an_error_not_missing_findings(self):
        for error in (SystemExit(0), KeyboardInterrupt(), GeneratorExit()):
            with self.subTest(error=type(error).__name__):
                def process(paths):
                    if paths[0] == Path('bad'):
                        raise error
                    return ['finding']
                with self.assertRaises(RuntimeError) as raised:
                    shards.run_work_stealing(['good', 'bad'], process, 2, 1)
                self.assertIs(raised.exception.__cause__, error)

    def test_generator_failure_is_not_a_successful_partial_shard(self):
        problem = ValueError('incomplete analysis')
        def process(paths):
            yield 'partial finding'
            raise problem
        for jobs in (1, 2):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError) as raised:
                shards.run_work_stealing(['one', 'two'], process, jobs, 1)
            self.assertIs(raised.exception, problem)

    def test_worker_launch_failure_joins_already_started_worker(self):
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        start = threading.Thread.start
        attempts = 0

        def start_or_fail(thread):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                self.assertTrue(entered.wait(2))
                release.set()
                raise RuntimeError('cannot start worker')
            return start(thread)

        def process(paths):
            entered.set()
            self.assertTrue(release.wait(2))
            finished.set()
            return paths

        with patch.object(threading.Thread, 'start', start_or_fail), \
                self.assertRaisesRegex(RuntimeError, 'cannot start worker'):
            shards.run_work_stealing(['first', 'second'], process, 2, 1)
        self.assertTrue(finished.is_set())

    def test_failure_stops_unstarted_work_and_joins_running_callbacks(self):
        both_running = threading.Barrier(2)
        release = threading.Event()
        started = []
        finished = threading.Event()
        failure = ValueError('scanner failed')
        state = threading.local()

        def process(paths):
            name = str(paths[0])
            started.append(name)
            if name in ('first', 'bad'):
                both_running.wait(2)
            if name == 'bad':
                state.failed = True
                raise failure
            if name == 'first':
                self.assertTrue(release.wait(2))
                finished.set()
            return [name]

        original_done = shards.ShardQueue.task_done
        # The failing shard must record failure before acknowledging its task.
        # Release the still-running peer precisely at that boundary, so this
        # control does not depend on sleep duration or thread scheduling.
        def task_done(queue):
            original_done(queue)
            if getattr(state, 'failed', False):
                release.set()

        with patch.object(shards.ShardQueue, 'task_done', task_done), self.assertRaises(ValueError):
            shards.run_work_stealing(['first', 'bad', 'never-1', 'never-2'], process, 2, 1)
        self.assertTrue(finished.is_set())
        self.assertNotIn('never-1', started)
        self.assertNotIn('never-2', started)

    def test_duplicate_paths_and_per_shard_record_order_are_retained(self):
        paths = ['same', 'same', 'other', 'last']
        expected = [value for path in paths for value in (path + ':a', path + ':b')]
        actual = shards.run_work_stealing(paths,
                    lambda selected: (value for path in selected for value in (str(path)+':a', str(path)+':b')), 4, 1)
        self.assertEqual(actual, expected)
        self.assertEqual(Counter(actual), Counter(expected))

    def test_fast_worker_steals_later_shards_while_first_is_blocked(self):
        finished_later = threading.Event()
        visits = []
        def process(paths):
            name = str(paths[0])
            if name == 'first':
                self.assertTrue(finished_later.wait(2))
            visits.append(name)
            if name == 'last':
                finished_later.set()
            return [name]
        selected = ['first', 'second', 'third', 'last']
        self.assertEqual(shards.run_work_stealing(selected, process, 2, 1), selected)
        self.assertEqual(visits[-1], 'first')


class PublicationTests(LoggedTests):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ubs-atomic-report-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'findings.ndjson'
        self.previous = b'previous valid report\n'
        self.output.write_bytes(self.previous)
        self.finding = {'rule': 'test.rule', 'path': 'a.py', 'line': 1, 'message': 'Unicode é😀'}

    def broken(self, error):
        yield self.finding
        raise error

    def test_late_analysis_error_preserves_existing_report(self):
        with self.assertRaises(ValueError):
            cli._write_ndjson(self.broken(ValueError('late analysis error')), str(self.output))
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(set(self.root.iterdir()), {self.output})

    def test_late_analysis_error_publishes_nothing_to_stdout(self):
        with contextlib.redirect_stdout(io.StringIO()) as stream, self.assertRaises(ValueError):
            cli._write_ndjson(self.broken(ValueError('late analysis error')), '-')
        self.assertEqual(stream.getvalue(), '')

    def test_cancelled_analysis_preserves_report_and_removes_stage(self):
        with self.assertRaises(KeyboardInterrupt):
            cli._write_ndjson(self.broken(KeyboardInterrupt()), str(self.output))
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(set(self.root.iterdir()), {self.output})

    def test_analyzer_systemexit_zero_is_not_clean_cli_completion(self):
        for layer, jobs in ((layer, jobs) for layer in ('guards', 'taint', 'scan') for jobs in (1, 2)):
            with self.subTest(layer=layer, jobs=jobs):
                selected = self.root / 'files.nul'
                selected.write_bytes(b'one.py\0two.py\0')
                with patch.object(cli, 'run_layer', side_effect=lambda *_, **kw: self.broken(SystemExit(0))), \
                        patch.object(cli, 'run_scan', side_effect=lambda *_, **kw: self.broken(SystemExit(0))), \
                        contextlib.redirect_stdout(io.StringIO()) as output, \
                        contextlib.redirect_stderr(io.StringIO()) as errors:
                    result = cli.main([layer, '--lang', 'python', '--files-from', str(selected),
                                       '--jobs', str(jobs)])
                self.assertEqual(result, 2, (output.getvalue(), errors.getvalue()))
                self.assertEqual(output.getvalue(), '')
                self.assertTrue(errors.getvalue())

    def test_invalid_json_value_does_not_replace_valid_report(self):
        for value in (float('nan'), object(), '\ud800'):
            with self.subTest(value=repr(value)), self.assertRaises((ValueError, TypeError)):
                cli._write_ndjson([self.finding, {'invalid': value}], str(self.output))
            self.assertEqual(self.output.read_bytes(), self.previous)

    def test_cli_error_keeps_previous_report_and_error_stream_separate(self):
        selected = self.root / 'files.nul'
        selected.write_bytes(b'one.py\0two.py\0')
        for jobs in (1, 2):
            with self.subTest(jobs=jobs), \
                    patch.object(cli, 'run_layer', side_effect=lambda *_, **kw: self.broken(ValueError('failed analyzer'))), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                code = cli.main(['guards', '--lang', 'python', '--files-from', str(selected),
                                 '--jobs', str(jobs), '--out', str(self.output)])
                self.assertEqual(code, 2)
                self.assertEqual(output.getvalue(), '')
                self.assertIn('failed analyzer', errors.getvalue())
                self.assertEqual(self.output.read_bytes(), self.previous)

    def test_unknown_language_scan_cannot_publish_empty_success(self):
        selected = self.root / 'files.nul'
        selected.write_bytes(b'source.py\0')
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit) as raised:
            cli.main(['scan', '--lang', 'unsupported-language', '--files-from', str(selected),
                      '--out', str(self.output)])
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('no analyzers registered', errors.getvalue())
        self.assertEqual(self.output.read_bytes(), self.previous)

    def test_successful_file_and_stdout_dialects_match_exactly(self):
        records = [self.finding, dict(self.finding, line=2)]
        expected = ''.join(json.dumps(record, ensure_ascii=False) + '\n' for record in records)
        self.assertEqual(cli._write_ndjson(iter(records), str(self.output)), 2)
        self.assertEqual(self.output.read_text(), expected)
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(cli._write_ndjson(iter(records), '-'), 2)
        self.assertEqual(stream.getvalue(), expected)
        self.assertEqual(set(self.root.iterdir()), {self.output})

    def test_empty_success_replaces_report_with_empty_file(self):
        self.assertEqual(cli._write_ndjson(iter(()), str(self.output)), 0)
        self.assertEqual(self.output.read_bytes(), b'')

    def test_destination_remains_old_until_generator_is_exhausted(self):
        def records():
            for _ in range(3):
                self.assertEqual(self.output.read_bytes(), self.previous)
                yield self.finding
            self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(cli._write_ndjson(records(), str(self.output)), 3)
        self.assertNotEqual(self.output.read_bytes(), self.previous)

    def test_failed_atomic_replace_preserves_prior_report(self):
        with patch('os.replace', side_effect=OSError('publish failed')), self.assertRaises(OSError):
            cli._write_ndjson([self.finding], str(self.output))
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(set(self.root.iterdir()), {self.output})

    def test_failed_first_report_does_not_leave_a_partial_file(self):
        destination = self.root / 'new.ndjson'
        with self.assertRaises(ValueError):
            cli._write_ndjson(self.broken(ValueError('not complete')), str(destination))
        self.assertFalse(destination.exists())
        self.assertEqual(set(self.root.iterdir()), {self.output})

    def test_publication_memory_does_not_scale_with_report_size(self):
        record = dict(self.finding, message='x' * 4096)
        tracemalloc.start()
        try:
            self.assertEqual(cli._write_ndjson((record for _ in range(4000)), str(self.output)), 4000)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertGreater(self.output.stat().st_size, 16_000_000)
        self.assertLess(peak, 2_000_000, peak)


if __name__ == '__main__':
    unittest.main()
