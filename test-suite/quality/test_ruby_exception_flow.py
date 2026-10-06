"""Independent Ruby exception-flow acceptance, with real public CLI controls.

Ruby's rescue/else/ensure completion rules determine which value reaches a
sink. These cases specify those rules independently of the analyzer graph.
See https://docs.ruby-lang.org/en/3.4/syntax/exceptions_rdoc.html.
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import taint_ruby_traversal, taint_ruby_url
from ubs_core.registry import RunContext

URL = 'ruby.taint.outbound_url'
PATH = 'ruby.taint.path_traversal'
RULES = {URL, PATH}
URL_CHECK = "uri.scheme == 'https' && ['api.example.com'].include?(uri.host)"


@dataclass(frozen=True)
class Case:
    name: str
    rule: str
    code: str
    lines: tuple[int, ...]

    @property
    def source(self):
        return textwrap.dedent(self.code).strip('\n') + '\n'


CASES = (
    Case('directory_open_in_ensure_keeps_basename_request_unsafe', PATH, '''
        begin
          leaf = File.basename(params[:file])
        ensure
          Dir.open(File.join('/srv/files', leaf))
        end''', (4,)),
    Case('send_file_in_ensure_accepts_fixed_basename_leaf', PATH, '''
        begin
          leaf = File.basename(params[:file])
        ensure
          send_file File.join('/srv/files', leaf)
        end''', ()),
    Case('rescue_reaches_request_path', PATH, '''
        begin
          raise 'failed'
        rescue
          File.read(params[:file])
        end''', (4,)),
    Case('rescue_constant_path_is_clean', PATH, '''
        def read_document(params)
          begin
            raise 'failed'
          rescue
            File.read('/srv/files/health.txt')
          end
        end''', ()),
    Case('exception_message_reaches_url', URL, '''
        begin
          raise params[:url]
        rescue => error
          Net::HTTP.get(URI.parse(error.message))
        end''', (4,)),
    Case('exception_message_reaches_path', PATH, '''
        begin
          raise params[:file]
        rescue => error
          File.read(error.message)
        end''', (4,)),
    Case('explicit_exception_class_carries_message', URL, '''
        begin
          raise ArgumentError, params[:url]
        rescue ArgumentError => error
          Net::HTTP.get(URI.parse(error.message))
        end''', (4,)),
    Case('first_matching_typed_rescue_excludes_later_handler', URL, '''
        target = params[:url]
        begin
          raise ArgumentError, 'failed'
        rescue ArgumentError
          target = 'https://api.example.com/health'
        rescue StandardError
          Net::HTTP.get(URI.parse(target))
        end''', ()),
    Case('unmatched_typed_rescue_does_not_handle_exception', URL, '''
        begin
          raise ArgumentError, params[:url]
        rescue IOError => error
          Net::HTTP.get(URI.parse(error.message))
        end''', ()),
    Case('exception_constructor_carries_message', PATH, '''
        begin
          raise StandardError.new(params[:file])
        rescue StandardError => error
          File.read(error.message)
        end''', (4,)),
    Case('swallowed_url_rejection_is_not_validation', URL, f'''
        uri = URI.parse(params[:url])
        begin
          raise 'blocked' unless {URL_CHECK}
        rescue
          puts 'ignored'
        end
        Net::HTTP.get(uri)''', (7,)),
    Case('guarded_helper_rescue_returns_fixed_url', URL, f'''
        def checked_url(raw)
          uri = URI.parse(raw)
          raise 'blocked' unless {URL_CHECK}
          uri
        rescue
          URI.parse('https://api.example.com/health')
        end
        Net::HTTP.get(checked_url(params[:url]))''', ()),
    Case('guarded_helper_rescue_returns_unchecked_url', URL, f'''
        def checked_url(raw)
          uri = URI.parse(raw)
          raise 'blocked' unless {URL_CHECK}
          uri
        rescue
          URI.parse(raw)
        end
        Net::HTTP.get(checked_url(params[:url]))''', (8,)),
    Case('ensure_sink_runs_before_return', PATH, '''
        def read_document(params)
          begin
            return 'finished'
          ensure
            File.read(params[:file])
          end
        end''', (5,)),
    Case('ensure_sink_runs_before_uncaught_raise', PATH, '''
        def read_document(params)
          begin
            raise 'failed'
          ensure
            File.read(params[:file])
          end
        end''', (5,)),
    Case('ensure_expression_does_not_replace_unsafe_return_value', URL, '''
        def target_url(raw)
          begin
            raw
          ensure
            'https://api.example.com/health'
          end
        end
        Net::HTTP.get(URI.parse(target_url(params[:url])))''', (8,)),
    Case('ensure_expression_does_not_replace_fixed_return_value', URL, '''
        def target_url(raw)
          begin
            'https://api.example.com/health'
          ensure
            raw
          end
        end
        Net::HTTP.get(URI.parse(target_url(params[:url])))''', ()),
    Case('ensure_explicit_return_can_replace_unsafe_value', URL, '''
        def target_url(raw)
          begin
            return raw
          ensure
            return 'https://api.example.com/health'
          end
        end
        Net::HTTP.get(URI.parse(target_url(params[:url])))''', ()),
    Case('ensure_explicit_return_can_replace_fixed_value', URL, '''
        def target_url(raw)
          begin
            return 'https://api.example.com/health'
          ensure
            return raw
          end
        end
        Net::HTTP.get(URI.parse(target_url(params[:url])))''', (8,)),
    Case('nested_ensures_both_run_on_return', PATH, '''
        def read_document(params)
          begin
            begin
              return 'finished'
            ensure
              File.read(params[:first])
            end
          ensure
            File.read(params[:second])
          end
        end''', (6, 9)),
    Case('ensure_runs_when_rescue_reraises', PATH, '''
        begin
          raise 'failed'
        rescue
          raise
        ensure
          File.read(params[:file])
        end''', (6,)),
    Case('ensure_preserves_pending_exception_across_inner_rescue', PATH, '''
        begin
          begin
            raise params[:file]
          ensure
            begin
              raise 'inner'
            rescue
              nil
            end
          end
        rescue => error
          File.read(error.message)
        end''', (12,)),
    Case('completed_rescue_does_not_leave_exception_active', PATH, '''
        begin
          raise params[:file]
        rescue
          nil
        end
        begin
          raise
        rescue => error
          File.read(error.message)
        end''', ()),
    Case('unknown_exception_class_is_not_assumed_runtime_error', PATH, '''
        class FatalRequest < Exception
        end
        begin
          raise FatalRequest, params[:file]
        rescue RuntimeError
          nil
        rescue FatalRequest => error
          File.read(error.message)
        end''', (8,)),
    Case('unknown_call_can_reach_rescue_with_existing_binding', URL, '''
        target = params[:url]
        begin
          risky_operation
        rescue
          Net::HTTP.get(URI.parse(target))
        end''', (5,)),
    Case('else_is_not_entered_after_rescue', URL, '''
        target = params[:url]
        begin
          raise 'failed'
        rescue
          puts 'handled'
        else
          Net::HTTP.get(URI.parse(target))
        end''', ()),
    Case('else_normal_path_reaches_sink', URL, '''
        target = params[:url]
        begin
          risky_operation
        rescue
          puts 'handled'
        else
          Net::HTTP.get(URI.parse(target))
        end''', (7,)),
    Case('else_and_rescue_both_replace_request_value', URL, '''
        target = params[:url]
        begin
          risky_operation
        rescue
          target = 'https://api.example.com/recovered'
        else
          target = 'https://api.example.com/health'
        end
        Net::HTTP.get(URI.parse(target))''', ()),
    Case('implicit_method_rescue_binds_message', URL, '''
        def fetch(params)
          raise params[:url]
        rescue => error
          Net::HTTP.get(URI.parse(error.message))
        end''', (4,)),
    Case('implicit_method_ensure_runs_on_return', PATH, '''
        def read_document(params)
          return 'finished'
        ensure
          File.read(params[:file])
        end''', (4,)),
    Case('rescued_exception_does_not_leak_between_methods', PATH, '''
        def remember(params)
          raise params[:file]
        rescue => error
          error.message
        end
        def health
          error = '/srv/files/health.txt'
          File.read(error)
        end''', ()),
    Case('retry_preserves_rebound_request_value', URL, '''
        target = 'https://api.example.com/health'
        attempt = 0
        begin
          Net::HTTP.get(URI.parse(target))
          raise 'retry' if attempt == 0
        rescue
          target = params[:url]
          attempt = 1
          retry
        end''', (4,)),
    Case('retry_with_fixed_sink_is_clean', PATH, '''
        def read_document(params)
          begin
            risky_operation
            File.read('/srv/files/health.txt')
          rescue
            retry
          end
        end''', ()),
    Case('bare_reraise_keeps_message_for_outer_rescue', PATH, '''
        begin
          begin
            raise params[:file]
          rescue => inner
            raise
          end
        rescue => outer
          File.read(outer.message)
        end''', (8,)),
    Case('raise_argument_preserves_helper_exception', PATH, '''
        def message
          raise params[:file]
        end
        def handler
          begin
            raise message()
          rescue => error
            File.read(error.message)
          end
        end''', (8,)),
    Case('selected_helper_raises_message_to_callers_rescue', URL, '''
        def reject(value)
          raise value
        end
        begin
          reject(params[:url])
        rescue => error
          Net::HTTP.get(URI.parse(error.message))
        end''', (7,)),
    Case('ensure_rebinding_does_not_rewrite_evaluated_return', URL, '''
        def target_url(raw)
          begin
            return raw
          ensure
            raw = 'https://api.example.com/health'
          end
        end
        Net::HTTP.get(URI.parse(target_url(params[:url])))''', (8,)),
    Case('ensure_mutation_invalidates_returned_url_proof', URL, f'''
        def target_url(raw, host)
          uri = URI.parse(raw)
          raise 'blocked' unless {URL_CHECK}
          begin
            return uri
          ensure
            uri.host = host
          end
        end
        Net::HTTP.get(target_url(params[:url], params[:host]))''', (10,)),
)
BY_NAME = {case.name: case for case in CASES}


class LoggedCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ROOT / 'test-suite/artifacts/ruby-exception-flow' / (cls.__name__ + '-' + uuid.uuid4().hex[:12])
        cls.artifact.mkdir(parents=True)
        paths = (ROOT / 'modules/helpers/ubs_core/analyzers/taint_ruby_traversal.py',
                 ROOT / 'modules/helpers/ubs_core/analyzers/taint_ruby_url.py',
                 ROOT / 'modules/helpers/ubs_core/taint_flow.py')
        (cls.artifact / 'identity.json').write_text(json.dumps({
            'python': sys.version, 'executable': sys.executable,
            'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'helpers': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
        }, indent=2) + '\n')

    def setUp(self):
        self.started = time.monotonic()
        self.failure_count = len(self._outcome.result.failures) + len(self._outcome.result.errors)
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        failures = len(self._outcome.result.failures) + len(self._outcome.result.errors)
        print(f'[{self.id()}] {"FAIL" if failures > self.failure_count else "PASS"} '
              f'({time.monotonic() - self.started:.3f}s)', flush=True)

    def observe(self, case):
        directory = self.artifact / case.name
        directory.mkdir(exist_ok=True)
        target = directory / 'input.rb'
        target.write_text(case.source, encoding='utf-8')
        stdout, stderr, records, error = io.StringIO(), io.StringIO(), [], None
        start = time.monotonic()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                for analyzer in (taint_ruby_url, taint_ruby_traversal):
                    records.extend(analyzer.run(RunContext(lang='ruby', files=[target])))
        except Exception as exc:
            error = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            (directory / 'stdout.log').write_text(stdout.getvalue())
            (directory / 'stderr.log').write_text(stderr.getvalue())
            (directory / 'result.json').write_text(json.dumps({
                'case': case.name, 'expected': [(case.rule, line) for line in case.lines],
                'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                'elapsed': time.monotonic() - start, 'error': error, 'findings': records,
            }, indent=2) + '\n')
        return records


class RubyExceptionSemanticTests(LoggedCase):
    def check_case(self, case):
        findings = self.observe(case)
        self.assertEqual(sorted((row['rule'], row['line']) for row in findings),
                         [(case.rule, line) for line in case.lines], (case.source, findings))
        for finding in findings:
            self.assertEqual(finding['severity'], 'critical', finding)
            self.assertEqual(Path(finding['path']).name, 'input.rb', finding)
            self.assertGreater(finding['col'], 0, finding)

    def test_exception_message_retains_original_request_evidence(self):
        findings = self.observe(BY_NAME['exception_message_reaches_url'])
        self.assertEqual(len(findings), 1, findings)
        trace = findings[0].get('extras', {}).get('taint_path', [])
        self.assertTrue(any(step.get('kind') == 'source' and step.get('line') == 2 for step in trace), findings)
        self.assertTrue(any(step.get('kind') == 'sink' and step.get('line') == 4 for step in trace), findings)

    def test_retry_outside_rescue_is_an_explicit_parse_error(self):
        invalid = Case('invalid_retry', URL, 'target = params[:url]\nretry\nNet::HTTP.get(URI.parse(target))', ())
        with self.assertRaisesRegex(ValueError, '(?i)retry|incomplete|syntax'):
            self.observe(invalid)


def semantic_test(case):
    def test(self):
        self.check_case(case)
    return test


for _case in CASES:
    setattr(RubyExceptionSemanticTests, 'test_' + _case.name, semantic_test(_case))


@unittest.skipUnless(os.environ.get('UBS_RUBY_TAINT_E2E') == '1', 'set UBS_RUBY_TAINT_E2E=1 for actual CLI scans')
class RubyExceptionPublicTests(LoggedCase):
    def test_exception_semantics_reach_json_and_sarif(self):
        names = ('exception_message_reaches_url', 'exception_message_reaches_path',
                 'swallowed_url_rejection_is_not_validation', 'guarded_helper_rescue_returns_fixed_url',
                 'ensure_sink_runs_before_return', 'ensure_expression_does_not_replace_fixed_return_value',
                 'ensure_explicit_return_can_replace_fixed_value', 'nested_ensures_both_run_on_return',
                 'else_and_rescue_both_replace_request_value', 'implicit_method_rescue_binds_message',
                 'retry_preserves_rebound_request_value', 'selected_helper_raises_message_to_callers_rescue',
                 'raise_argument_preserves_helper_exception',
                 'ensure_preserves_pending_exception_across_inner_rescue',
                 'completed_rescue_does_not_leave_exception_active',
                 'unknown_exception_class_is_not_assumed_runtime_error',
                 'directory_open_in_ensure_keeps_basename_request_unsafe',
                 'send_file_in_ensure_accepts_fixed_basename_leaf')
        for name in names:
            case = BY_NAME[name]
            directory = self.artifact / name
            directory.mkdir()
            target = directory / 'selected exception source.rb'
            target.write_text(case.source)
            for fmt in ('json', 'sarif'):
                with self.subTest(case=name, format=fmt):
                    command = [str(ROOT / 'ubs'), '--only=ruby', '--ci', '--format=' + fmt, str(target)]
                    env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
                           'CI': '1', 'NO_COLOR': '1', 'UBS_CACHE_DIR': str(self.artifact / 'cache')}
                    start = time.monotonic()
                    result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=180)
                    (directory / (fmt + '.stdout.log')).write_text(result.stdout)
                    (directory / (fmt + '.stderr.log')).write_text(result.stderr)
                    (directory / (fmt + '.identity.json')).write_text(json.dumps({
                        'command': command, 'exit': result.returncode, 'elapsed': time.monotonic() - start,
                        'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                    }, indent=2) + '\n')
                    self.assertEqual(result.returncode, int(bool(case.lines)), (result.stdout, result.stderr))
                    payload = json.loads(result.stdout)
                    if fmt == 'json':
                        self.assertEqual(payload['status'], 'ok', payload)
                        self.assertEqual(payload['failed_modules'], [], payload)
                        self.assertEqual(payload['totals']['files'], 1, payload)
                        self.assertEqual(payload['totals']['critical'], len(case.lines), payload)
                        findings = [(row['rule_id'], row['line']) for row in payload['findings'] if row['rule_id'] in RULES]
                    else:
                        findings = [(row['ruleId'], row['locations'][0]['physicalLocation']['region']['startLine'])
                                    for run in payload['runs'] for row in run.get('results', []) if row['ruleId'] in RULES]
                    self.assertEqual(sorted(findings), [(case.rule, line) for line in case.lines], payload)
                    print('RUBY_EXCEPTION_PUBLIC', name, fmt, 'PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
