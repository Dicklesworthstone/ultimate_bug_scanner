"""C6: bounded parallel finding streams, with ordered and fail-closed delivery."""
from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import json
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
from ubs_core import analyzers, cli, registry  # noqa: F401


class StreamingTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(case is self or getattr(case, 'test_case', None) is self
                     for case, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic()-started:.3f}s)', flush=True)
        return result

    def setUp(self):
        self.ctx = registry.RunContext('python', files=[Path('first.py'), Path('second.py')])
        temporary = tempfile.TemporaryDirectory(prefix='ubs-stream-test-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    @staticmethod
    def finding(number=1, message='finding', rule='test.stream'):
        return {'rule': rule, 'path': 'source.py', 'line': number, 'message': message}

    def analyzer(self, name, run, **options):
        return registry.Analyzer('guards', 'python', name, run, **options)

    def select(self, *values):
        context = patch.dict(registry._REGISTRY, {('guards', 'python'): list(values)}, clear=True)
        context.start()
        self.addCleanup(context.stop)

    def test_first_finding_is_available_before_analyzer_finishes(self):
        release = threading.Event()
        finished = threading.Event()
        def analyze(ctx):
            try:
                yield self.finding()
                if not release.wait(2):
                    raise AssertionError('Consumer cannot see the first finding until producer exhaustion')
                yield self.finding(2)
            finally:
                finished.set()
        self.select(self.analyzer('stream', analyze))
        findings = registry.run_layer('guards', self.ctx, jobs=2)
        try:
            self.assertEqual(next(findings)['line'], 1)
            self.assertFalse(finished.is_set())
            release.set()
            self.assertEqual([item['line'] for item in findings], [2])
        finally:
            release.set()
            findings.close()
        self.assertTrue(finished.is_set())

    def test_fast_later_producer_is_backpressured_not_fully_buffered(self):
        blocked = threading.Event()
        completed = threading.Event()
        produced = []
        queue_type = registry.queue.Queue
        class ObservedQueue(queue_type):
            def put(self, value, *args, **kwargs):
                if self.full():
                    blocked.set()
                return super().put(value, *args, **kwargs)
        def later(ctx):
            try:
                for number in range(1, 4001):
                    produced.append(number)
                    yield self.finding(number)
            finally:
                completed.set()
        self.select(self.analyzer('first', lambda ctx: [self.finding()]), self.analyzer('later', later))
        with patch.object(registry.queue, 'Queue', ObservedQueue):
            findings = registry.run_layer('guards', self.ctx, jobs=2)
            try:
                next(findings)
                self.assertTrue(blocked.wait(2), 'Later task did not encounter bounded backpressure')
                self.assertLessEqual(len(produced), registry.MAX_BUFFERED_FINDINGS + 1)
                self.assertFalse(completed.is_set())
            finally:
                findings.close()
        self.assertTrue(completed.is_set())

    def test_faster_later_results_keep_registration_and_record_order(self):
        second_completed = threading.Event()
        def first(ctx):
            self.assertTrue(second_completed.wait(2))
            yield self.finding(1, rule='first')
            yield self.finding(2, rule='first')
        def second(ctx):
            yield self.finding(3, rule='second')
            second_completed.set()
        self.select(self.analyzer('first', first), self.analyzer('second', second))
        result = list(registry.run_layer('guards', self.ctx, jobs=2))
        self.assertEqual([(r['rule'], r['line']) for r in result], [('first', 1), ('first', 2), ('second', 3)])

    def test_empty_stream_and_project_record_do_not_lose_completion(self):
        self.ctx.files = []
        self.select(self.analyzer('empty', lambda ctx: []),
                    self.analyzer('project', lambda ctx: [self.finding()]))
        self.assertEqual(list(registry.run_scan(self.ctx, jobs=3)), list(registry.run_scan(self.ctx, jobs=1)))

    def test_single_record_queue_preserves_all_file_shards(self):
        self.ctx.files = [Path(f'{index}.py') for index in range(24)]
        def local(ctx):
            for path in ctx.files:
                for line in range(1, 11):
                    yield dict(self.finding(line), path=str(path))
        self.select(self.analyzer('local', local, file_independent=True))
        baseline = list(registry.run_scan(self.ctx))
        with patch.object(registry, 'MAX_BUFFERED_FINDINGS', 1):
            for jobs in (2, 4, 8):
                self.assertEqual(list(registry.run_scan(self.ctx, jobs=jobs)), baseline)

    def test_normalized_extra_fields_are_identical_in_serial_and_parallel(self):
        def analyze(ctx):
            for line in range(1, 101):
                yield dict(self.finding(line, 'é😀'), evidence={'values': ['one', line]}, col=4)
        self.select(self.analyzer('stream', analyze))
        self.assertEqual(list(registry.run_scan(self.ctx, jobs=4)), list(registry.run_scan(self.ctx)))

    def test_late_failure_preserves_prior_file_and_emits_no_stdout_prefix(self):
        def analyze(ctx):
            for line in range(1, 301):
                yield self.finding(line)
            raise ValueError('late analysis failure')
        self.select(self.analyzer('failing', analyze))
        output = self.directory / 'report.ndjson'
        output.write_text('previous report')
        for target in (str(output), '-'):
            with self.subTest(target=target), contextlib.redirect_stdout(io.StringIO()) as stream, \
                    self.assertRaisesRegex(ValueError, 'late analysis failure'):
                cli._write_ndjson(registry.run_scan(self.ctx, jobs=2), target)
            self.assertEqual(stream.getvalue(), '')
            self.assertEqual(output.read_text(), 'previous report')
            self.assertEqual(set(self.directory.iterdir()), {output})

    def test_later_failure_releases_blocked_producer_and_closes_generator(self):
        blocked = threading.Event()
        closed = threading.Event()
        problem = ValueError('later producer failed')
        queue_type = registry.queue.Queue
        class ObservedQueue(queue_type):
            def put(self, value, *args, **kwargs):
                if self.full():
                    blocked.set()
                return super().put(value, *args, **kwargs)
        def first(ctx):
            try:
                for line in range(1, 50001):
                    yield self.finding(line)
            finally:
                closed.set()
        def later(ctx):
            self.assertTrue(blocked.wait(2))
            raise problem
        self.select(self.analyzer('first', first), self.analyzer('later', later))
        # Hold the ordered consumer at its first yield, allowing the first
        # producer to hit backpressure before the later task fails.
        with patch.object(registry.queue, 'Queue', ObservedQueue):
            findings = registry.run_scan(self.ctx, jobs=2)
            try:
                with self.assertRaises(ValueError) as raised:
                    for finding in findings:
                        if finding['line'] == 1:
                            self.assertTrue(blocked.wait(2))
                self.assertIs(raised.exception, problem)
            finally:
                findings.close()
        self.assertTrue(closed.is_set())

    def test_consumer_close_releases_queued_producers_without_launching_more(self):
        both_started = threading.Barrier(2)
        opened = []
        closed = []
        def make(index):
            def analyze(ctx):
                opened.append(index)
                try:
                    both_started.wait(2)
                    for line in range(1, 10001):
                        yield self.finding(line)
                finally:
                    closed.append(index)
            return self.analyzer(str(index), analyze)
        self.select(*(make(index) for index in range(10)))
        findings = registry.run_scan(self.ctx, jobs=2)
        self.assertEqual(next(findings)['line'], 1)
        findings.close()
        self.assertEqual(sorted(opened), [0, 1])
        self.assertEqual(sorted(closed), [0, 1])

    def test_failed_submission_releases_and_joins_the_first_producer(self):
        first_started = threading.Event()
        closed = threading.Event()
        class FailedExecutor(ThreadPoolExecutor):
            attempts = 0
            def submit(self, *args, **kwargs):
                self.attempts += 1
                if self.attempts == 2:
                    if not first_started.wait(2):
                        raise AssertionError('First worker did not start')
                    raise RuntimeError('cannot submit worker')
                return super().submit(*args, **kwargs)
        def first(ctx):
            try:
                first_started.set()
                for line in range(1, 10001):
                    yield self.finding(line)
            finally:
                closed.set()
        self.select(self.analyzer('first', first), self.analyzer('second', first))
        with patch.object(registry, 'ThreadPoolExecutor', FailedExecutor), \
                self.assertRaisesRegex(RuntimeError, 'cannot submit worker'):
            list(registry.run_scan(self.ctx, jobs=2))
        self.assertTrue(closed.is_set())

    def test_generator_cleanup_failure_is_not_an_empty_success(self):
        def broken(ctx):
            try:
                yield self.finding()
            finally:
                raise ValueError('cleanup failed')
        self.select(self.analyzer('cleanup', broken))
        with self.assertRaisesRegex(ValueError, 'cleanup failed'):
            list(registry.run_scan(self.ctx, jobs=2))

    def test_worker_systemexit_zero_cannot_publish_a_successful_report(self):
        def broken(ctx):
            yield self.finding()
            raise SystemExit(0)
        self.select(self.analyzer('exit', broken))
        listing = self.directory / 'files.nul'
        listing.write_bytes(b'first.py\0second.py\0')
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
            code = cli.main(['guards', '--lang', 'python', '--files-from', str(listing), '--jobs', '2'])
        self.assertEqual(code, 2, errors.getvalue())
        self.assertEqual(output.getvalue(), '')
        self.assertIn('before', errors.getvalue())

    def test_cli_encoding_error_closes_the_retained_upstream_generator(self):
        closed = threading.Event()
        held = []
        def analyze(ctx):
            try:
                for line in range(1, 10001):
                    yield dict(self.finding(line), unserializable=object())
            finally:
                closed.set()
        self.select(self.analyzer('encoding', analyze))
        listing = self.directory / 'files.nul'
        listing.write_bytes(b'first.py\0second.py\0')
        destination = self.directory / 'report.ndjson'
        destination.write_text('previous report')
        def retain(layer, ctx, **options):
            stream = registry.run_layer(layer, ctx, **options)
            held.append(stream)  # Do not depend on refcount/GC to stop workers.
            return stream
        try:
            with patch.object(cli, 'run_layer', side_effect=retain), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                code = cli.main(['guards', '--lang', 'python', '--files-from', str(listing),
                                 '--jobs', '2', '--out', str(destination)])
            self.assertEqual(code, 2, errors.getvalue())
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(destination.read_text(), 'previous report')
            self.assertTrue(closed.is_set(), 'CLI failure returned with a blocked upstream worker')
        finally:
            for stream in held:
                stream.close()

    def test_findings_memory_is_bounded_while_large_report_is_written(self):
        def analyze(ctx):
            for line in range(1, 2501):
                # Unique allocated payloads, not 2,500 references to one string.
                yield self.finding(line, f'{line}:' + 'x' * 4096)
        self.select(self.analyzer('first', analyze), self.analyzer('second', analyze))
        destination = self.directory / 'large.ndjson'
        tracemalloc.start()
        try:
            count = cli._write_ndjson(registry.run_scan(self.ctx, jobs=2), str(destination))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(count, 5000)
        self.assertGreater(destination.stat().st_size, 20_000_000)
        self.assertLess(peak, 3_000_000, peak)
        with destination.open() as stream:
            lines = [json.loads(line)['line'] for line in stream]
        self.assertEqual(lines, list(range(1, 2501)) * 2)
        print('STREAMING_MEMORY_PEAK', peak, 'REPORT_BYTES', destination.stat().st_size, flush=True)


if __name__ == '__main__':
    unittest.main()
