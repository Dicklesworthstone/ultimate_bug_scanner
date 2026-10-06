"""Independent Ruby URL/path flow oracle (mj1j.5), authored before the engine.

These fixtures describe Ruby value flow and concrete API arguments. Names such
as safe_url confer no trust. Expected locations identify actual sink calls,
including sinks reached through selected local helpers. The public companion
uses the real UBS executable; enable it with UBS_RUBY_TAINT_E2E=1.
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
HELPERS = ROOT / 'modules/helpers'
sys.path.insert(0, str(HELPERS))
from ubs_core.analyzers import taint_ruby_traversal, taint_ruby_url
from ubs_core.registry import RunContext

URL = 'ruby.taint.outbound_url'
PATH = 'ruby.taint.path_traversal'
TARGET_RULES = {URL, PATH}
URL_CHECK = "uri.scheme == 'https' && ['api.example.com'].include?(uri.host)"
PATH_CHECK = 'target.start_with?(base + File::SEPARATOR) || target == base'


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
    Case('url_direct', URL, 'Net::HTTP.get(URI.parse(params[:url]))', (1,)),
    Case('url_safe_named_identity', URL, '''
        def safe_url(value)
          value
        end
        Net::HTTP.get(URI.parse(safe_url(params[:url])))''', (4,)),
    Case('url_alpha_renamed_identity', URL, '''
        def identity(value)
          value
        end
        Net::HTTP.get(URI.parse(identity(params[:url])))''', (4,)),
    Case('url_literal_overwrite', URL, '''
        target = params[:url]
        target = 'https://api.example.com/health'
        Net::HTTP.get(URI.parse(target))''', ()),
    Case('url_literal_control', URL, "Net::HTTP.get(URI.parse('https://api.example.com/health'))", ()),
    Case('url_overwrite_only_protects_later_sink', URL, '''
        target = params[:url]
        Net::HTTP.get(URI.parse(target))
        target = 'https://api.example.com/health'
        Net::HTTP.get(URI.parse(target))''', (2,)),
    Case('url_uri_parsing_is_not_validation', URL, '''
        uri = URI.parse(params[:url])
        Net::HTTP.get(uri)''', (2,)),
    Case('url_join_can_replace_the_authority', URL,
         "Net::HTTP.get(URI.join('https://api.example.com/', params[:url]))", (1,)),
    Case('url_local_constant_return', URL, '''
        def target_url(raw)
          'https://api.example.com/health'
        end
        Net::HTTP.get(URI.parse(target_url(params[:url])))''', ()),
    Case('url_local_sink_summary', URL, '''
        def dispatch(target)
          Net::HTTP.get(URI.parse(target))
        end
        dispatch(params[:url])''', (2,)),
    Case('url_request_default_in_handler_is_an_entry_source', URL, '''
        def dispatch(target = params[:url])
          Net::HTTP.get(URI.parse(target))
        end''', (2,)),
    Case('url_guard_exact_uri', URL, f'''
        uri = URI.parse(params[:url])
        raise 'blocked' unless {URL_CHECK}
        Net::HTTP.get(uri)''', ()),
    Case('url_guard_scheme_alone', URL, '''
        uri = URI.parse(params[:url])
        raise 'blocked' unless uri.scheme == 'https'
        Net::HTTP.get(uri)''', (3,)),
    Case('url_guard_host_alone', URL, '''
        uri = URI.parse(params[:url])
        raise 'blocked' unless ['api.example.com'].include?(uri.host)
        Net::HTTP.get(uri)''', (3,)),
    Case('url_guard_on_unrelated_value', URL, '''
        target = params[:url]
        uri = URI.parse('https://api.example.com/')
        raise 'blocked' unless uri.scheme == 'https' && ['api.example.com'].include?(uri.host)
        Net::HTTP.get(URI.parse(target))''', (4,)),
    Case('url_logging_is_not_rejection', URL, f'''
        uri = URI.parse(params[:url])
        puts 'blocked' unless {URL_CHECK}
        Net::HTTP.get(uri)''', (3,)),
    Case('url_guard_rebind_invalidates_proof', URL, f'''
        uri = URI.parse(params[:url])
        raise 'blocked' unless {URL_CHECK}
        uri = URI.parse(params[:other_url])
        Net::HTTP.get(uri)''', (4,)),
    Case('url_guard_host_mutation_invalidates_proof', URL, f'''
        uri = URI.parse(params[:url])
        raise 'blocked' unless {URL_CHECK}
        uri.host = params[:host]
        Net::HTTP.get(uri)''', (4,)),
    Case('url_allowlist_push_invalidates_host_proof', URL, '''
        allowed = ['api.example.com']
        allowed.push(params[:host])
        uri = URI.parse(params[:url])
        raise 'blocked' unless uri.scheme == 'https' && allowed.include?(uri.host)
        Net::HTTP.get(uri)''', (5,)),
    Case('url_allowlist_shovel_invalidates_host_proof', URL, '''
        allowed = ['api.example.com']
        allowed << params[:host]
        uri = URI.parse(params[:url])
        raise 'blocked' unless uri.scheme == 'https' && allowed.include?(uri.host)
        Net::HTTP.get(uri)''', (5,)),
    Case('url_allowlist_alias_mutation_invalidates_host_proof', URL, '''
        allowed = ['api.example.com']
        alias_list = allowed
        alias_list.push(params[:host])
        uri = URI.parse(params[:url])
        raise 'blocked' unless uri.scheme == 'https' && allowed.include?(uri.host)
        Net::HTTP.get(uri)''', (6,)),
    Case('url_merge_mutation_invalidates_guard', URL, f'''
        uri = URI.parse(params[:url])
        raise 'blocked' unless {URL_CHECK}
        uri.merge!(params[:other_url])
        Net::HTTP.get(uri)''', (4,)),
    Case('url_alias_host_assignment_invalidates_original_guard', URL, f'''
        uri = URI.parse(params[:url])
        raise 'blocked' unless {URL_CHECK}
        alias_uri = uri
        alias_uri.host = params[:host]
        Net::HTTP.get(uri)''', (5,)),
    Case('url_helper_with_actual_guard', URL, f'''
        def checked_url(raw)
          uri = URI.parse(raw)
          raise 'blocked' unless {URL_CHECK}
          uri
        end
        Net::HTTP.get(checked_url(params[:url]))''', ()),
    Case('url_unimplemented_validator_is_not_proof', URL, '''
        target = validate_url(params[:url])
        Net::HTTP.get(URI.parse(target))''', (2,)),
    Case('url_same_name_different_method_scope', URL, '''
        def remember(params)
          target = params[:url]
        end
        def health
          target = 'https://api.example.com/health'
          Net::HTTP.get(URI.parse(target))
        end''', ()),
    Case('url_uncalled_parameter_sink_has_no_source', URL, '''
        def remember(params)
          target = params[:url]
        end
        def unused(target)
          Net::HTTP.get(URI.parse(target))
        end''', ()),
    Case('url_same_class_constant_helper', URL, '''
        class Handler
          def target_url(value)
            'https://api.example.com/health'
          end
          def handle(params)
            Net::HTTP.get(URI.parse(target_url(params[:url])))
          end
        end''', ()),
    Case('url_different_class_helper_does_not_sanitize', URL, '''
        class Safe
          def target_url(value)
            'https://api.example.com/health'
          end
        end
        class Handler
          def handle(params)
            Net::HTTP.get(URI.parse(target_url(params[:url])))
          end
        end''', (8,)),
    Case('url_singleton_helper_does_not_replace_instance_method', URL, '''
        class Handler
          def self.target_url(value)
            'https://api.example.com/health'
          end
          def handle(params)
            Net::HTTP.get(URI.parse(target_url(params[:url])))
          end
        end''', (6,)),
    Case('url_unknown_receiver_does_not_select_local_helper', URL, '''
        def target_url(value)
          'https://api.example.com/health'
        end
        Net::HTTP.get(URI.parse(provider.target_url(params[:url])))''', (4,)),
    Case('url_relative_definition_does_not_sanitize_root_receiver', URL, '''
        module Tools
          class Helper
          end
          def Helper.target_url(value)
            'https://api.example.com/health'
          end
        end
        Net::HTTP.get(URI.parse(Helper.target_url(params[:url])))''', (8,)),
    Case('url_relative_definition_matches_qualified_receiver', URL, '''
        module Tools
          class Helper
          end
          def Helper.target_url(value)
            'https://api.example.com/health'
          end
        end
        Net::HTTP.get(URI.parse(Tools::Helper.target_url(params[:url])))''', ()),
    Case('url_branch_join_keeps_unsafe_path', URL, '''
        target = params[:url]
        if healthy
          target = 'https://api.example.com/health'
        end
        Net::HTTP.get(URI.parse(target))''', (5,)),
    Case('url_both_branches_overwrite', URL, '''
        target = params[:url]
        if healthy
          target = 'https://api.example.com/health'
        else
          target = 'https://api.example.com/status'
        end
        Net::HTTP.get(URI.parse(target))''', ()),
    Case('url_zero_iteration_loop_keeps_entry_value', URL, '''
        target = params[:url]
        while ready
          target = 'https://api.example.com/health'
        end
        Net::HTTP.get(URI.parse(target))''', (5,)),
    Case('url_loop_backedge_reaches_earlier_sink', URL, '''
        target = 'https://api.example.com/health'
        while ready
          Net::HTTP.get(URI.parse(target))
          target = params[:url]
        end''', (3,)),
    Case('url_multiline_sink_location', URL, '''
        target = params[:url]
        Net::HTTP.get(
          URI.parse(
            target
          )
        )''', (2,)),
    Case('url_block_parameter_shadows_outer_binding', URL, '''
        target = 'https://api.example.com/health'
        [params[:url]].each do |target|
          Net::HTTP.get(URI.parse(target))
        end
        Net::HTTP.get(URI.parse(target))''', (3,)),
    Case('url_block_write_reaches_outer_existing_local', URL, '''
        target = 'https://api.example.com/health'
        [1].each do |number|
          target = params[:url]
        end
        Net::HTTP.get(URI.parse(target))''', (5,)),
    Case('url_selected_alias_keeps_helper_meaning', URL, '''
        def identity(value)
          value
        end
        alias safe_url identity
        Net::HTTP.get(URI.parse(safe_url(params[:url])))''', (5,)),
    Case('url_redefined_helper_is_not_a_sanitizer', URL, '''
        def safe_url(value)
          'https://api.example.com/health'
        end
        def safe_url(value)
          value
        end
        Net::HTTP.get(URI.parse(safe_url(params[:url])))''', (7,)),
    Case('url_single_quoted_code_is_inert', URL, "text = 'Net::HTTP.get(URI.parse(params[:url]))'\nputs text", ()),
    Case('url_percent_quoted_code_is_inert', URL, 'text = %q{Net::HTTP.get(URI.parse(params[:url]))}\nputs text', ()),
    Case('url_heredoc_code_is_inert', URL, '''
        text = <<~TEXT
        Net::HTTP.get(URI.parse(params[:url]))
        TEXT
        puts text''', ()),
    Case('url_interpolated_request_host_is_unsafe', URL,
         'Net::HTTP.get(URI.parse("https://#{params[:host]}/status"))', (1,)),
    Case('url_safe_spelling_in_string_is_not_validation', URL, '''
        target = params[:url]
        message = 'safe_url(target)'
        Net::HTTP.get(URI.parse(target))''', (3,)),
    Case('url_comment_code_is_inert', URL, '# Net::HTTP.get(URI.parse(params[:url]))', ()),
    Case('url_source_suppression_does_not_erase_flow', URL, '''
        target = params[:url] # ubs:ignore[ruby.taint.outbound_url]

        Net::HTTP.get(URI.parse(target))''', (3,)),
    Case('url_sink_suppression_is_rule_specific', URL,
         'Net::HTTP.get(URI.parse(params[:url])) # ubs:ignore[ruby.taint.path_traversal]', (1,)),
    Case('url_sink_suppression_matching_rule', URL,
         'Net::HTTP.get(URI.parse(params[:url])) # ubs:ignore[ruby.taint.outbound_url]', ()),
    Case('url_sink_suppression_bare_marker', URL,
         'Net::HTTP.get(URI.parse(params[:url])) # ubs:ignore', ()),
    Case('url_bare_source_suppression_does_not_erase_flow', URL, '''
        target = params[:url] # ubs:ignore

        Net::HTTP.get(URI.parse(target))''', (3,)),
    Case('path_direct', PATH, 'File.read(params[:file])', (1,)),
    Case('path_safe_named_identity', PATH, '''
        def safe_path(value)
          value
        end
        File.read(safe_path(params[:file]))''', (4,)),
    Case('path_literal_overwrite', PATH, '''
        target = params[:file]
        target = '/srv/app/files/health.txt'
        File.read(target)''', ()),
    Case('path_literal_control', PATH, "File.read('/srv/app/files/health.txt')", ()),
    Case('path_expansion_alone_is_not_containment', PATH, '''
        target = File.expand_path(params[:file], '/srv/app/files')
        File.read(target)''', (2,)),
    Case('path_prefix_without_separator_allows_sibling', PATH, '''
        base = '/srv/app/files'
        target = File.expand_path(params[:file], base)
        raise 'blocked' unless target.start_with?(base)
        File.read(target)''', (4,)),
    Case('path_real_containment_of_sink_value', PATH, f'''
        base = File.expand_path('/srv/app/files')
        target = File.expand_path(params[:file], base)
        raise 'blocked' unless {PATH_CHECK}
        File.read(target)''', ()),
    Case('path_raw_prefix_does_not_remove_dot_segments', PATH, '''
        target = params[:file]
        raise 'blocked' unless target.start_with?('/srv/app/files/')
        File.read(target)''', (3,)),
    Case('path_guard_on_unrelated_value', PATH, '''
        target = params[:file]
        other = File.expand_path('health.txt', '/srv/app/files')
        raise 'blocked' unless other.start_with?('/srv/app/files/')
        File.read(target)''', (4,)),
    Case('path_checks_expanded_value_but_uses_raw_value', PATH, f'''
        base = File.expand_path('/srv/app/files')
        raw = params[:file]
        target = File.expand_path(raw, base)
        raise 'blocked' unless {PATH_CHECK}
        File.read(raw)''', (5,)),
    Case('path_rebind_invalidates_containment', PATH, f'''
        base = File.expand_path('/srv/app/files')
        target = File.expand_path(params[:file], base)
        raise 'blocked' unless {PATH_CHECK}
        target = params[:other_file]
        File.read(target)''', (5,)),
    Case('path_concat_invalidates_containment', PATH, f'''
        base = File.expand_path('/srv/app/files')
        target = File.expand_path(params[:file], base)
        raise 'blocked' unless {PATH_CHECK}
        target.concat('/../../etc/passwd')
        File.read(target)''', (5,)),
    Case('path_alias_concat_invalidates_containment', PATH, f'''
        base = File.expand_path('/srv/app/files')
        target = File.expand_path(params[:file], base)
        raise 'blocked' unless {PATH_CHECK}
        alias_path = target
        alias_path.concat('/../../etc/passwd')
        File.read(target)''', (6,)),
    Case('path_helper_with_actual_containment', PATH, f'''
        def contained_path(raw)
          base = File.expand_path('/srv/app/files')
          target = File.expand_path(raw, base)
          raise 'blocked' unless {PATH_CHECK}
          target
        end
        File.read(contained_path(params[:file]))''', ()),
    Case('path_basename_of_other_value_is_not_validation', PATH, '''
        target = params[:file]
        other = File.basename('health.txt')
        File.read(target)''', (3,)),
    Case('path_validated_basename_under_constant_root', PATH, '''
        name = File.basename(params[:file])
        raise 'blocked' if ['.', '..'].include?(name)
        File.read(File.join('/srv/app/files', name))''', ()),
    Case('path_write_content_is_not_a_path_argument', PATH,
         "File.write('/srv/app/files/health.txt', params[:file])", ()),
    Case('path_rename_destination_is_a_path_argument', PATH,
         "File.rename('/srv/app/files/health.txt', params[:file])", (1,)),
    # File.basename retains '.'/'..'. These are scanner inputs only; the
    # destructive operation is never executed by this test suite.
    Case('path_basename_dotdot_is_not_safe_for_directory_deletion', PATH,
         "FileUtils.rm_rf(File.join('/srv/app/files', File.basename(params[:file])))", (1,)),
    Case('path_basename_dot_rejection_protects_directory_deletion', PATH, '''
        name = File.basename(params[:file])
        raise 'blocked' if ['.', '..'].include?(name)
        FileUtils.rm_rf(File.join('/srv/app/files', name))''', ()),
    Case('path_basename_with_child_component_can_escape', PATH,
         "File.read(File.join('/srv/app/files', File.basename(params[:file]), 'secrets.txt'))", (1,)),
    Case('path_basename_with_concatenated_child_can_escape', PATH, '''
        name = File.basename(params[:file]) + '/secrets.txt'
        File.read(File.join('/srv/app/files', name))''', (2,)),
    Case('path_chmod_path_is_second_argument', PATH, 'File.chmod(0600, params[:file])', (1,)),
    Case('path_local_sink_summary', PATH, '''
        def read_document(target)
          File.read(target)
        end
        read_document(params[:file])''', (2,)),
    Case('path_branch_join_keeps_unsafe_path', PATH, '''
        target = params[:file]
        if healthy
          target = '/srv/app/files/health.txt'
        end
        File.read(target)''', (5,)),
    Case('path_same_name_different_method_scope', PATH, '''
        def remember(params)
          target = params[:file]
        end
        def health
          target = '/srv/app/files/health.txt'
          File.read(target)
        end''', ()),
    Case('path_quoted_code_is_inert', PATH, "text = 'File.read(params[:file])'\nputs text", ()),
    Case('path_source_suppression_does_not_erase_flow', PATH, '''
        target = params[:file] # ubs:ignore[ruby.taint.path_traversal]

        File.read(target)''', (3,)),
)
BY_NAME = {case.name: case for case in CASES}


class LoggedCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ROOT / 'test-suite/artifacts/ruby-taint-dataflow' / (cls.__name__ + '-' + uuid.uuid4().hex[:12])
        cls.artifact.mkdir(parents=True)
        identity = {'python': sys.version, 'executable': sys.executable,
                    'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    'helpers': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in sorted((HELPERS / 'ubs_core').rglob('*ruby*.py'))}}
        (cls.artifact / 'source-identity.json').write_text(json.dumps(identity, indent=2) + '\n')

    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.failures_before = len(result.errors) + len(result.failures)
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.errors) + len(result.failures) > self.failures_before
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic() - self.started:.3f}s)', flush=True)

    def observe(self, case):
        directory = self.artifact / case.name
        directory.mkdir(exist_ok=True)
        target = directory / 'input.rb'
        target.write_text(case.source, encoding='utf-8')
        stdout, stderr = io.StringIO(), io.StringIO()
        started = time.monotonic()
        records = []
        error = None
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
                'case': case.name, 'expected_rule': case.rule, 'expected_lines': case.lines,
                'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                'elapsed': time.monotonic() - started, 'error': error, 'findings': records,
            }, indent=2) + '\n')
        return target, records


class RubySemanticTests(LoggedCase):
    def check_case(self, case):
        target, records = self.observe(case)
        actual = sorted((record['rule'], record['line']) for record in records)
        expected = sorted((case.rule, line) for line in case.lines)
        self.assertEqual(actual, expected, (case.source, records))
        for record in records:
            self.assertEqual(record['severity'], 'critical', record)
            self.assertEqual(Path(record['path']).name, target.name, record)
            self.assertGreater(record['col'], 0, record)
            self.assertIn('params', record['message'], record)

    def test_ruby_binding_forms_preserve_sink_flow_or_report_incomplete(self):
        supported = (
            Case('parser_parallel_second', URL, '''
                unused, target = 'fixed', params[:url]
                Net::HTTP.get(URI.parse(target))''', (2,)),
            Case('parser_parallel_clean_second', URL, '''
                unused, target = params[:url], 'https://api.example.com/'
                Net::HTTP.get(URI.parse(target))''', ()),
            Case('parser_chained_assignment', URL, '''
                unused = target = params[:url]
                Net::HTTP.get(URI.parse(target))''', (2,)),
            Case('parser_default_argument', URL, '''
                def fetch(target, mode = 'get')
                  Net::HTTP.get(URI.parse(target))
                end
                fetch(params[:url])''', (2,)),
            Case('parser_keyword_order', URL, '''
                def fetch(other:, target:)
                  Net::HTTP.get(URI.parse(target))
                end
                fetch(target: params[:url], other: 'fixed')''', (2,)),
            Case('parser_keyword_clean_target', URL, '''
                def fetch(other:, target:)
                  Net::HTTP.get(URI.parse(target))
                end
                fetch(target: 'https://api.example.com/', other: params[:url])''', ()),
            Case('parser_brace_block_assignment', URL, '''
                target = 'https://api.example.com/'
                [1].each { |i| target = params[:url] }
                Net::HTTP.get(URI.parse(target))''', (3,)),
            Case('parser_singleton_class', URL, '''
                class Fetcher
                  class << self
                    def fetch(target)
                      Net::HTTP.get(URI.parse(target))
                    end
                  end
                end
                Fetcher.fetch(params[:url])''', (4,)),
            Case('parser_aliased_sink', URL, 'def fetch(target)\n  Net::HTTP.get(URI.parse(target))\nend\nalias dispatch fetch\ndispatch(params[:url])', (2,)),
        )
        for case in supported:
            with self.subTest(case=case.name):
                self.check_case(case)
        bounded = (
            Case('parser_rest_parameter', URL, 'def fetch(*targets)\n  Net::HTTP.get(URI.parse(targets[0]))\nend\nfetch(params[:url])', (2,)),
            Case('parser_lambda_sink', URL, 'fetch = ->(target) { Net::HTTP.get(URI.parse(target)) }\nfetch.call(params[:url])', (1,)),
            Case('parser_instance_sink', URL, 'class Fetcher\n def fetch(target)\n  Net::HTTP.get(URI.parse(target))\n end\nend\nFetcher.new.fetch(params[:url])', (3,)),
        )
        for case in bounded:
            with self.subTest(case=case.name):
                try:
                    self.check_case(case)
                except ValueError as exc:
                    self.assertIn('incomplete', str(exc).lower())

    def test_binding_preserving_alpha_rename_has_identical_security_result(self):
        safe = BY_NAME['url_safe_named_identity']
        renamed = BY_NAME['url_alpha_renamed_identity']
        self.assertEqual(safe.source.replace('safe_url', 'identity'), renamed.source)
        _, first = self.observe(safe)
        _, second = self.observe(renamed)
        for findings in (first, second):
            self.assertEqual([(row['rule'], row['line']) for row in findings], [(URL, 4)], findings)

    def test_malformed_selected_ruby_is_an_error(self):
        malformed = Case('malformed', URL, 'def fetch(params)\n  Net::HTTP.get(URI.parse(params[:url]))', ())
        with self.assertRaisesRegex(ValueError, 'incomplete|unclosed|unterminated|Ruby|ruby|parse'):
            self.observe(malformed)

    def test_local_summary_retains_structured_source_and_sink_evidence(self):
        _, findings = self.observe(BY_NAME['url_local_sink_summary'])
        self.assertEqual(len(findings), 1, findings)
        extras = findings[0].get('extras', {})
        trace = extras.get('taint_path', [])
        self.assertTrue(any(step.get('kind') == 'source' and step.get('line') == 4 for step in trace), findings)
        self.assertTrue(any(step.get('kind') == 'sink' and step.get('line') == 2 for step in trace), findings)
        self.assertEqual(extras.get('source_count'), 1, findings)

    def test_helper_mutation_cannot_retain_a_callers_validation_proof(self):
        case = Case('url_helper_argument_mutation', URL, f'''
            def corrupt(uri, host)
              uri.host = host
            end
            uri = URI.parse(params[:url])
            raise 'blocked' unless {URL_CHECK}
            corrupt(uri, params[:host])
            Net::HTTP.get(uri)''', (7,))
        # Heap effects may be rejected as explicitly incomplete while this
        # frontend is scoped to local values; a successful clean answer is wrong.
        try:
            _, findings = self.observe(case)
        except ValueError as exc:
            self.assertIn('incomplete', str(exc).lower())
        else:
            self.assertEqual([(row['rule'], row['line']) for row in findings], [(URL, 7)], findings)

    def test_unresolved_selected_local_sink_forms_cannot_be_silently_clean(self):
        cases = (
            Case('url_default_argument_sink', URL, '''
                def dispatch(target, mode = :get)
                  Net::HTTP.get(URI.parse(target))
                end
                dispatch(params[:url])''', (2,)),
            Case('url_singleton_block_sink', URL, '''
                module Client
                  class << self
                    def dispatch(target)
                      Net::HTTP.get(URI.parse(target))
                    end
                  end
                end
                Client.dispatch(params[:url])''', (4,)),
            Case('url_lambda_sink', URL, '''
                dispatch = ->(target) { Net::HTTP.get(URI.parse(target)) }
                dispatch.call(params[:url])''', (1,)),
        )
        for case in cases:
            with self.subTest(case=case.name):
                try:
                    _, findings = self.observe(case)
                except ValueError as exc:
                    self.assertIn('incomplete', str(exc).lower())
                else:
                    self.assertEqual([(row['rule'], row['line']) for row in findings],
                                     [(URL, line) for line in case.lines], findings)


def semantic_test(case):
    def test(self):
        self.check_case(case)
    return test


for _case in CASES:
    setattr(RubySemanticTests, 'test_' + _case.name, semantic_test(_case))


@unittest.skipUnless(os.environ.get('UBS_RUBY_TAINT_E2E') == '1', 'set UBS_RUBY_TAINT_E2E=1 for actual CLI scans')
class RubyPublicTests(LoggedCase):
    def scan(self, directory, target, fmt='json', extra=()):
        directory.mkdir(parents=True, exist_ok=True)
        command = [str(ROOT / 'ubs'), '--only=ruby', '--ci', '--format=' + fmt, *extra, str(target)]
        env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
               'CI': '1', 'NO_COLOR': '1', 'UBS_CACHE_DIR': str(self.artifact / 'cache'),
               'PYTHONDONTWRITEBYTECODE': '1'}
        started = time.monotonic()
        # Artifact directories vary per attempt; the actual project/cwd must
        # stay fixed to exercise a real cache replay in the same scan context.
        execution_cwd = target.parent if target.is_file() else target
        result = subprocess.run(command, cwd=execution_cwd, env=env, text=True, capture_output=True, timeout=180)
        (directory / 'stdout.log').write_text(result.stdout)
        (directory / 'stderr.log').write_text(result.stderr)
        (directory / 'identity.json').write_text(json.dumps({
            'command': command, 'cwd': str(execution_cwd), 'elapsed': time.monotonic() - started,
            'exit': result.returncode, 'format': fmt,
            'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None,
            'path': env.get('PATH'),
        }, indent=2) + '\n')
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            self.fail((command, result.returncode, result.stdout, result.stderr))
        return result, payload

    def assert_findings(self, result, payload, case, fmt, selected):
        self.assertEqual(result.returncode, int(bool(case.lines)), (result.stdout, result.stderr))
        if fmt == 'json':
            self.assertEqual(payload['status'], 'ok', payload)
            self.assertEqual(payload['failed_modules'], [], payload)
            self.assertEqual(payload['totals']['files'], 1, payload)
            self.assertEqual(payload['totals']['critical'], len(case.lines), payload)
            records = payload['findings']
            target = [(r['rule_id'], r['line']) for r in records if r['rule_id'] in TARGET_RULES]
            paths = [r['file'] for r in records if r['rule_id'] in TARGET_RULES]
        else:
            records = [r for run in payload['runs'] for r in run.get('results', [])]
            target = [(r['ruleId'], r['locations'][0]['physicalLocation']['region']['startLine'])
                      for r in records if r['ruleId'] in TARGET_RULES]
            paths = [r['locations'][0]['physicalLocation']['artifactLocation']['uri']
                     for r in records if r['ruleId'] in TARGET_RULES]
        self.assertEqual(sorted(target), [(case.rule, line) for line in case.lines], (payload, result.stderr))
        for path in paths:
            from urllib.parse import unquote
            self.assertEqual(Path(unquote(path)).name, selected.name, payload)

    def test_selected_file_json_and_sarif_semantic_controls(self):
        names = ('url_direct', 'url_safe_named_identity', 'url_alpha_renamed_identity',
                 'url_literal_overwrite', 'url_local_sink_summary', 'url_guard_exact_uri',
                 'url_guard_on_unrelated_value', 'url_guard_rebind_invalidates_proof',
                 'url_percent_quoted_code_is_inert', 'url_source_suppression_does_not_erase_flow',
                 'path_direct', 'path_safe_named_identity', 'path_literal_overwrite',
                 'path_real_containment_of_sink_value', 'path_prefix_without_separator_allows_sibling',
                 'path_checks_expanded_value_but_uses_raw_value', 'path_write_content_is_not_a_path_argument')
        for name in names:
            case = BY_NAME[name]
            directory = self.artifact / name
            directory.mkdir(exist_ok=True)
            target = directory / 'selected source.rb'
            target.write_text(case.source)
            # A sibling source is intentionally unsafe and must not enter a selected-file scan.
            (directory / 'unselected.rb').write_text('File.read(params[:file])\n')
            for fmt in ('json', 'sarif'):
                with self.subTest(case=name, format=fmt):
                    result, payload = self.scan(directory / fmt, target, fmt)
                    self.assert_findings(result, payload, case, fmt, target)
                    print('RUBY_TAINT_PUBLIC', name, fmt, 'PASS', flush=True)

    def test_warm_cache_and_same_file_helper_edit_invalidate_answers(self):
        directory = self.artifact / 'cache-edit'
        directory.mkdir()
        target = directory / 'handler.rb'
        unsafe = BY_NAME['url_safe_named_identity']
        safe = Case('same_binding_constant_return', URL,
                    unsafe.source.replace('  value\n', "  'https://api.example.com/health'\n"), ())
        for index, case in enumerate((unsafe, unsafe, safe, safe)):
            if index in (0, 2):
                target.write_text(case.source)
            result, payload = self.scan(directory / str(index), target)
            self.assert_findings(result, payload, case, 'json', target)
            profile = payload['scanners'][0]['extras']['profile']
            self.assertEqual(profile['cache_hits'], int(index in (1, 3)), payload)

    def test_malformed_source_remains_partial_on_repeated_scans(self):
        directory = self.artifact / 'malformed-public'
        directory.mkdir()
        target = directory / 'handler.rb'
        target.write_text('def fetch(params)\n  Net::HTTP.get(URI.parse(params[:url]))\n')
        for attempt in range(2):
            result, payload = self.scan(directory / str(attempt), target)
            self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
            self.assertEqual(payload['status'], 'partial', payload)
            self.assertTrue(any(row.get('language') == 'ruby' and row.get('module_error') == 'ANALYZER_ERROR'
                                for row in payload.get('failed_modules', [])), payload)


if __name__ == '__main__':
    unittest.main()
