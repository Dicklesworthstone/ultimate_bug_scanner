"""Elixir clause/tuple validation and immutable-value proof regressions.

The initial independent oracle lives in test_swift_elixir_request_flow.py.
These additional source programs exercise the newly supported control forms
and prove that validation does not cross a value, scope, or sink boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import subprocess
import sys
import textwrap
import time
import unittest
import uuid
from pathlib import Path

import test_swift_elixir_request_flow as oracle
from test_swift_elixir_request_flow import (
    Case, LoggedCase, ELIXIR_LOCAL, ROOT,
)
from ubs_core.analyzers.taint_elixir_traversal import ElixirEngine
from ubs_core.taint_flow import AnalysisLimit, Budget


CASES = (
    Case('elixir', 'path', 'interpolation_keeps_renamed_request_source', '''
        def handle(connection) do
          target = ~s(#{connection.params["file"]})
          File.read!(target)
        end''', (3,)),
    Case('elixir', 'redirect', 'atom_and_string_map_keys_are_distinct', '''
        def handle(conn, params) do
          options = %{"next" => params["next"], next: "/home"}
          redirect(conn, external: Map.get(options, "next"))
        end''', (3,)),
    Case('elixir', 'redirect', 'atom_map_key_clean_control', '''
        def handle(conn, params) do
          options = %{"next" => params["next"], next: "/home"}
          redirect(conn, external: Map.get(options, :next))
        end''', ()),
    Case('elixir', 'redirect', 'dynamic_map_key_preserves_possible_value', '''
        def handle(conn, params) do
          options = %{params["key"] => params["next"]}
          redirect(conn, external: Map.get(options, "next"))
        end''', (3,)),
    Case('elixir', 'redirect', 'atom_map_pattern_does_not_match_string_key', '''
        defmodule Handler do
          defp pick(%{next: _}, _raw), do: "/"
          defp pick(_, raw), do: raw
          def handle(conn, params) do
            redirect(conn, external: pick(%{"next" => "safe"}, params["next"]))
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'struct_identity_selects_fallback', '''
        defmodule A do
          defstruct [:safe]
        end
        defmodule B do
          defstruct [:other]
        end
        defmodule Handler do
          defp pick(%A{}, _raw), do: "/"
          defp pick(_, raw), do: raw
          def handle(conn, params) do
            redirect(conn, external: pick(%B{}, params["next"]))
          end
        end''', (11,)),
    Case('elixir', 'redirect', 'matching_struct_clean_control', '''
        defmodule A do
          defstruct [:safe]
        end
        defmodule Handler do
          defp pick(%A{}, _raw), do: "/"
          defp pick(_, raw), do: raw
          def handle(conn, params) do
            redirect(conn, external: pick(%A{}, params["next"]))
          end
        end''', ()),
    Case('elixir', 'redirect', 'repeated_pattern_variable_requires_equality', '''
        defmodule Handler do
          defp pick({same, same}, _raw), do: "/"
          defp pick(_, raw), do: raw
          def handle(conn, params) do
            redirect(conn, external: pick({"a", "b"}, params["next"]))
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'repeated_pattern_variable_equal_control', '''
        defmodule Handler do
          defp pick({same, same}, _raw), do: "/"
          defp pick(_, raw), do: raw
          def handle(conn, params) do
            redirect(conn, external: pick({"a", "a"}, params["next"]))
          end
        end''', ()),
    Case('elixir', 'redirect', 'missing_map_key_reaches_fallback_clause', '''
        defmodule Handler do
          defp pick(%{"safe" => _}, _value), do: "/"
          defp pick(_, value), do: value
          def handle(conn, params) do
            redirect(conn, external: pick(%{}, params["next"]))
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'unknown_request_key_preserves_failure_clause', '''
        defmodule Handler do
          defp pick(%{"safe" => _}, _value), do: "/"
          defp pick(_, value), do: value
          def handle(conn, params) do
            redirect(conn, external: pick(params, params["next"]))
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'shadowed_string_predicate_is_not_proof', f'''
        defmodule PretendString do
          def starts_with?(_value, prefix), do: prefix == "/"
          def contains?(_value, _characters), do: false
        end
        defmodule Handler do
          alias PretendString, as: String
          def handle(conn, params) do
            target = params["next"]
            if {ELIXIR_LOCAL} do
              redirect(conn, external: target)
            end
          end
        end''', (10,)),
    Case('elixir', 'redirect', 'known_map_fetch_selects_only_success', '''
        def handle(conn, params) do
          target = case Map.fetch(%{"next" => "/home"}, "next") do
            {:ok, accepted} -> accepted
            :error -> params["next"]
          end
          redirect(conn, external: target)
        end''', ()),
    Case('elixir', 'redirect', 'renamed_request_arguments', '''
        def handle(connection, arguments) do
          redirect(connection, external: arguments["next"])
        end''', (2,)),
    Case('elixir', 'redirect', 'renamed_connection_alias', '''
        def handle(connection) do
          request = connection
          redirect(connection, external: request.params["next"])
        end''', (3,)),
    Case('elixir', 'redirect', 'cond_selected_raw_result', '''
        def handle(conn, params) do
          target = cond do
            false -> "/home"
            true -> params["next"]
          end
          redirect(conn, external: target)
        end''', (6,)),
    Case('elixir', 'redirect', 'cond_first_truthy_clause', '''
        def handle(conn, params) do
          target = cond do
            true -> "/home"
            true -> params["next"]
          end
          redirect(conn, external: target)
        end''', ()),
    Case('elixir', 'redirect', 'with_tuple_flow', '''
        def handle(conn, params) do
          with {:ok, target} <- Map.fetch(params, "next") do
            redirect(conn, external: target)
          else
            :error -> redirect(conn, external: "/home")
          end
        end''', (3,)),
    Case('elixir', 'redirect', 'with_boolean_validator', f'''
        def handle(conn, params) do
          with {{:ok, target}} <- Map.fetch(params, "next"),
               true <- {ELIXIR_LOCAL} do
            redirect(conn, external: target)
          else
            _ -> redirect(conn, external: "/home")
          end
        end''', ()),
    Case('elixir', 'redirect', 'selected_validator_tuple', f'''
        defmodule Handler do
          defp validate(target) do
            if {ELIXIR_LOCAL} do
              {{:ok, target}}
            else
              {{:error, :unsafe}}
            end
          end
          def handle(conn, params) do
            with {{:ok, target}} <- validate(params["next"]) do
              redirect(conn, external: target)
            else
              _ -> redirect(conn, external: "/home")
            end
          end
        end''', ()),
    Case('elixir', 'redirect', 'safe_atom_is_not_validation', '''
        defmodule Handler do
          defp validate(target), do: {:ok, target}
          def handle(conn, params) do
            with {:ok, target} <- validate(params["next"]) do
              redirect(conn, external: target)
            end
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'proof_rebinding', f'''
        def handle(conn, params) do
          target = params["next"]
          unless {ELIXIR_LOCAL} do
            raise "blocked"
          end
          target = params["replacement"]
          redirect(conn, external: target)
        end''', (7,)),
    Case('elixir', 'redirect', 'immutable_alias_keeps_proof', f'''
        def handle(conn, params) do
          target = params["next"]
          unless {ELIXIR_LOCAL} do
            raise "blocked"
          end
          accepted = target
          target = params["replacement"]
          redirect(conn, external: accepted)
        end''', ()),
    Case('elixir', 'redirect', 'transform_invalidates_proof', f'''
        def handle(conn, params) do
          target = params["next"]
          unless {ELIXIR_LOCAL} do
            raise "blocked"
          end
          redirect(conn, external: String.trim(target))
        end''', (6,)),
    Case('elixir', 'redirect', 'ignored_error_does_not_terminate', '''
        def handle(conn, params) do
          target = params["next"]
          if target == "blocked" do
            {:error, :unsafe}
          end
          redirect(conn, external: target)
        end''', (6,)),
    Case('elixir', 'redirect', 'halt_does_not_return_from_function', '''
        def handle(conn, params) do
          target = params["next"]
          unless String.starts_with?(target, "/") do
            halt(conn)
          end
          redirect(conn, external: target)
        end''', (6,)),
    Case('elixir', 'redirect', 'scope_isolation', '''
        def first(conn, params) do
          target = params["next"]
          target
        end
        def second(conn, target) do
          redirect(conn, external: target)
        end''', ()),
    Case('elixir', 'redirect', 'keyword_helper_selected_safe', '''
        defmodule Handler do
          defp choose(value, opts) do
            if opts[:safe], do: "/home", else: value
          end
          def handle(conn, params) do
            redirect(conn, external: choose(params["next"], safe: true, audit: false))
          end
        end''', ()),
    Case('elixir', 'redirect', 'keyword_helper_selected_unsafe', '''
        defmodule Handler do
          defp choose(value, opts) do
            if opts[:safe], do: "/home", else: value
          end
          def handle(conn, params) do
            redirect(conn, external: choose(params["next"], safe: false, audit: true))
          end
        end''', (6,)),
    Case('elixir', 'redirect', 'default_argument_helper', r'''
        defmodule Handler do
          defp choose(value, mode \\ :raw) do
            case mode do
              :raw -> value
              :safe -> "/home"
            end
          end
          def handle(conn, params) do
            redirect(conn, external: choose(params["next"]))
          end
        end''', (9,)),
    Case('elixir', 'redirect', 'lowercase_sigil_interpolation', '''
        def handle(conn, params) do
          target = ~s(#{params["next"]})
          redirect(conn, external: target)
        end''', (3,)),
    Case('elixir', 'redirect', 'uppercase_sigil_no_interpolation', '''
        def handle(conn, params) do
          target = ~S(#{params["next"]})
          redirect(conn, external: target)
        end''', ()),
    Case('elixir', 'redirect', 'map_destructured_parameter', '''
        def handle(conn, %{"next" => target}) do
          redirect(conn, external: target)
        end''', (2,)),
    Case('elixir', 'redirect', 'module_alias_selects_real_helper', '''
        defmodule Helpers do
          def identity(value), do: value
        end
        defmodule Handler do
          alias Helpers, as: Safe
          def handle(conn, params) do
            redirect(conn, external: Safe.identity(params["next"]))
          end
        end''', (7,)),
    Case('elixir', 'path', 'write_content_is_not_a_path', '''
        def handle(_conn, params) do
          File.write!("/srv/files/report", params["body"])
        end''', ()),
    Case('elixir', 'path', 'copy_destination_is_a_path', '''
        def handle(_conn, params) do
          File.cp!("/srv/files/report", params["destination"])
        end''', (2,)),
    Case('elixir', 'path', 'download_binary_is_not_a_path', '''
        def handle(conn, params) do
          send_download(conn, {:binary, params["body"]})
        end''', ()),
    Case('elixir', 'path', 'download_file_tuple_is_a_path', '''
        def handle(conn, params) do
          send_download(conn, {:file, params["file"]})
        end''', (2,)),
    Case('elixir', 'path', 'basename_directory_sink_unsafe', '''
        def handle(_conn, params) do
          name = Path.basename(params["file"])
          File.ls!(Path.join("/srv/files", name))
        end''', (3,)),
    Case('elixir', 'path', 'basename_file_sink_clean', '''
        def handle(_conn, params) do
          name = Path.basename(params["file"])
          File.read!(Path.join("/srv/files", name))
        end''', ()),
    Case('elixir', 'path', 'raw_prefix_is_not_containment', '''
        def handle(_conn, params) do
          target = params["file"]
          if String.starts_with?(target, "/srv/files/") do
            File.read!(target)
          end
        end''', (4,)),
    Case('elixir', 'path', 'prefix_missing_separator', '''
        def handle(_conn, params) do
          target = Path.expand(params["file"])
          if String.starts_with?(target, "/srv/files") do
            File.read!(target)
          end
        end''', (4,)),
    Case('elixir', 'path', 'redirect_proof_cannot_protect_file', f'''
        def handle(_conn, params) do
          target = params["file"]
          if {ELIXIR_LOCAL} do
            File.read!(target)
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'file_proof_cannot_protect_redirect', '''
        def handle(conn, params) do
          target = Path.expand(params["next"])
          if String.starts_with?(target, "/srv/files/") do
            redirect(conn, external: target)
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'weak_uri_guard_and_reserialization', '''
        def handle(conn, params) do
          target = params["next"]
          uri = URI.parse(target)
          if uri.scheme == "https" and uri.host == "app.example.com" do
            redirect(conn, external: URI.to_string(uri))
          end
        end''', (5,)),
)


class ElixirScopedFlowTests(LoggedCase):
    def test_scoped_annotation_aliases_remain_sink_specific(self):
        for case in annotation_cases():
            with self.subTest(case=case.name):
                findings = self.observe(case)
                self.assertEqual(sorted((row['rule'], row['line']) for row in findings),
                                 [(case.rule, line) for line in case.lines], findings)

    def test_direct_identity_callback_preserves_request_source(self):
        """This unchanged former boundary is now supported callback coverage."""
        from ubs_core.analyzers.taint_elixir_redirect import run
        from ubs_core.registry import RunContext
        source = 'def handle(conn, params) do\nf = fn value -> value end\nredirect(conn, external: f.(params["next"]))\nend'
        path = self.artifact / 'direct_identity_callback.ex'
        path.write_text(source, encoding='utf-8')
        findings = list(run(RunContext(lang='elixir', files=[path])))
        self.assertEqual([(row['rule'], row['line'], row['col']) for row in findings],
                         [('elixir.taint.open_redirect', 3, 1)], findings)
        self.assertEqual(findings[0]['severity'], 'critical')
        trace = findings[0]['extras']['taint_path']
        self.assertEqual((trace[0]['kind'], trace[-1]['kind']), ('source', 'sink'))
        self.assertEqual((trace[0]['line'], trace[-1]['line'], trace[-1]['col']), (3, 3, 1))

    def test_explicit_boundaries_and_budget(self):
        sources = (
            'def handle(conn, params) do\nredirect(conn, external: params["next"])',
            'def handle(conn, params) do\nmodule = params["module"]\nmodule.forward(conn)\nend',
            'def handle(conn, params) do\nredirect(conn, external: apply(Safe, :validate, [params["next"]]))\nend',
            'defmodule Handler do\nuse CustomMacros\ndef handle(conn, params), do: redirect(conn, external: params["next"])\nend',
            'def handle(conn, params) do\nredirect(conn, external: Unknown.validate(params["next"]))\nend',
            'defmodule Handler do\nimport Fake, only: [raise: 1]\ndef handle(conn, params) do\nraise(params["next"])\nredirect(conn, external: params["next"])\nend\nend',
            'def handle(conn, params) do\nput_resp_header(conn, params["header"], params["next"])\nend',
        )
        for index, source in enumerate(sources):
            with self.subTest(boundary=index):
                with self.assertRaisesRegex(ValueError, 'incomplete|Expected|Unsupported'):
                    ElixirEngine(self.artifact / 'boundary.ex', source, 'redirect').analyze()
        with self.assertRaises(AnalysisLimit):
            ElixirEngine(self.artifact / 'budget.ex', CASES[0].source, 'redirect', Budget(3)).analyze()

    def test_original_fixture_sites_and_clean_controls(self):
        for policy, filename, expected in (
            ('redirect', 'buggy/open_redirect.ex', [7, 16, 21, 26, 33, 39]),
            ('path', 'buggy/path_traversal.ex', [7, 12, 17, 22, 28]),
            ('redirect', 'clean/open_redirect.ex', []),
            ('path', 'clean/path_traversal.ex', []),
        ):
            with self.subTest(policy=policy, fixture=filename):
                path = ROOT / 'test-suite/elixir' / filename
                findings = ElixirEngine(path, path.read_text(encoding='utf-8'), policy).analyze()
                self.assertEqual(sorted(line for line, _ in findings), expected)


def annotation_cases():
    for kind, sink, canonical, legacy, unrelated in (
        ('path', 'File.read!(target)', 'elixir.taint.request_path_traversal',
         'ex.request-path-traversal', 'ex.request-open-redirect'),
        ('redirect', 'redirect(conn, external: target)', 'elixir.taint.open_redirect',
         'ex.request-open-redirect', 'ex.request-path-traversal'),
    ):
        for label, marker, placement, expected in (
            ('canonical_sink', canonical, 'sink', ()),
            ('legacy_sink', legacy, 'sink', ()),
            ('other_sink_alias', unrelated, 'sink', (3,)),
            ('unrelated_sink_rule', 'unrelated.rule', 'sink', (3,)),
            ('canonical_source', canonical, 'source', (3,)),
            ('legacy_source', legacy, 'source', (3,)),
        ):
            source_marker = ' # ubs:ignore[' + marker + ']' if placement == 'source' else ''
            sink_marker = ' # ubs:ignore[' + marker + ']' if placement == 'sink' else ''
            yield Case('elixir', kind, kind + '_' + label,
                       'def handle(conn, params) do\n'
                       '  target = params["value"]' + source_marker + '\n'
                       '  ' + sink + sink_marker + '\nend', expected)


def semantic_test(case):
    def test(self):
        findings = self.observe(case)
        self.assertEqual(sorted((row['rule'], row['line']) for row in findings),
                         [(case.rule, line) for line in case.lines], findings)
        for finding in findings:
            self.assertEqual(finding['severity'], 'critical')
            path = finding['extras']['taint_path']
            self.assertEqual(path[-1]['kind'], 'sink')
            self.assertEqual(path[-1]['line'], finding['line'])
    return test


for _case in CASES:
    setattr(ElixirScopedFlowTests, 'test_' + _case.name, semantic_test(_case))


@unittest.skipUnless(os.environ.get('UBS_ELIXIR_FLOW_E2E') == '1',
                     'set UBS_ELIXIR_FLOW_E2E=1 for actual CLI scans')
class ElixirScopedPublicTests(LoggedCase):
    scan = oracle.ScopedRequestPublicTests.scan
    assert_result = oracle.ScopedRequestPublicTests.assert_result

    def test_scoped_annotation_aliases_through_json_and_sarif(self):
        for case in annotation_cases():
            if case.name.endswith(('canonical_sink', 'canonical_source', 'unrelated_sink_rule')):
                continue
            for fmt in ('json', 'sarif'):
                with self.subTest(case=case.name, format=fmt):
                    result, payload, target = self.scan(case, fmt, ('--no-cache',))
                    self.assert_result(case, fmt, result, payload, target)
                    print('ELIXIR_SCOPED_ANNOTATION_PUBLIC', case.name, fmt, 'PASS', flush=True)

    def test_control_forms_through_json_and_sarif(self):
        names = {'with_tuple_flow', 'with_boolean_validator', 'selected_validator_tuple',
                 'safe_atom_is_not_validation', 'proof_rebinding', 'immutable_alias_keeps_proof',
                 'transform_invalidates_proof', 'lowercase_sigil_interpolation',
                 'uppercase_sigil_no_interpolation', 'write_content_is_not_a_path',
                 'download_file_tuple_is_a_path', 'basename_directory_sink_unsafe',
                 'basename_file_sink_clean', 'weak_uri_guard_and_reserialization',
                 'missing_map_key_reaches_fallback_clause', 'repeated_pattern_variable_requires_equality',
                 'atom_and_string_map_keys_are_distinct', 'atom_map_key_clean_control',
                 'dynamic_map_key_preserves_possible_value', 'atom_map_pattern_does_not_match_string_key',
                 'struct_identity_selects_fallback', 'matching_struct_clean_control'}
        for case in CASES:
            if case.name not in names:
                continue
            for fmt in ('json', 'sarif'):
                with self.subTest(case=case.name, format=fmt):
                    result, payload, target = self.scan(case, fmt, ('--no-cache',))
                    self.assert_result(case, fmt, result, payload, target)
                    print('ELIXIR_SCOPED_PUBLIC', case.name, fmt, 'PASS', flush=True)

    def test_dynamic_header_name_is_explicitly_partial(self):
        case = Case('elixir', 'redirect', 'dynamic_header', '''
            def handle(conn, params) do
              put_resp_header(conn, params["header"], params["next"])
            end''', ())
        for fmt in ('json', 'sarif'):
            with self.subTest(format=fmt):
                result, payload, _target = self.scan(case, fmt, ('--no-cache',))
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                if fmt == 'json':
                    self.assertEqual(payload['status'], 'partial', payload)
                    self.assertTrue(payload['failed_modules'], payload)
                self.assertIn('response-header name', result.stderr)


# Independent mj1j.19 lifecycle oracle. These programs describe the documented
# API contracts, not the old project-wide subtraction of open/close counts:
# https://hexdocs.pm/elixir/File.html#open/3
# https://hexdocs.pm/elixir/Port.html#close/1
# https://hexdocs.pm/elixir/Task.html#yield/2
# https://hexdocs.pm/elixir/Task.Supervisor.html#start_child/3
LIFECYCLE_SCAN_ROOT = ROOT
LIFECYCLE_RULES = {
    'file': 'ex.io.file-open-unmatched',
    'port': 'ex.io.port-open-unmatched',
    'task': 'ex.otp.task-async-unawaited',
}
LIFECYCLE_SKIP = '1,2,4,5,6,7,9,10,11,12,13,14,15,16'


@dataclass(frozen=True)
class ElixirLifecycleCase:
    name: str
    body: str

    @property
    def source(self):
        body = textwrap.dedent(self.body).strip('\n')
        return 'defmodule LifecycleProbe do\n' + textwrap.indent(body, '  ') + '\nend\n'

    @property
    def expected(self):
        expected = []
        for number, line in enumerate(self.source.splitlines(), 1):
            if '# LEAK:' not in line:
                continue
            kind = line.split('# LEAK:', 1)[1].strip()
            prefix = {'file': 'File.open', 'port': 'Port.open', 'task': 'Task.'}[kind]
            expected.append((LIFECYCLE_RULES[kind], number, line.index(prefix) + 1))
        return sorted(expected)


ELIXIR_LIFECYCLE_CASES = (
    ElixirLifecycleCase('file_single_discarded', '''
        def run do
          io = File.open!("one.txt") # LEAK:file
          IO.read(io, :eof)
          :ok
        end'''),
    ElixirLifecycleCase('file_actual_second_allocation', '''
        def run do
          first = File.open!("first.txt")
          second = File.open!("second.txt") # LEAK:file
          File.close(first)
          :ok
        end'''),
    ElixirLifecycleCase('file_both_allocations_closed', '''
        def run do
          first = File.open!("first.txt")
          second = File.open!("second.txt")
          File.close(first)
          File.close(second)
          :ok
        end'''),
    ElixirLifecycleCase('file_open_tuple_binding_leaks', '''
        def run do
          {:ok, io} = File.open("one.txt", [:read]) # LEAK:file
          IO.read(io, :eof)
          :ok
        end'''),
    ElixirLifecycleCase('file_open_tuple_binding_closed', '''
        def run do
          {:ok, io} = File.open("one.txt", [:read])
          File.close(io)
        end'''),
    ElixirLifecycleCase('file_alias_closes_original_after_rebind', '''
        def run do
          io = File.open!("first.txt")
          saved = io
          io = File.open!("second.txt") # LEAK:file
          File.close(saved)
          :ok
        end'''),
    ElixirLifecycleCase('file_rebind_leaves_original_open', '''
        def run do
          io = File.open!("first.txt") # LEAK:file
          saved = io
          io = File.open!("second.txt")
          File.close(io)
          :ok
        end'''),
    ElixirLifecycleCase('file_conditional_close_is_not_guaranteed', '''
        def run(enabled) do
          io = File.open!("one.txt") # LEAK:file
          if enabled do
            File.close(io)
          end
          :ok
        end'''),
    ElixirLifecycleCase('file_both_branches_close', '''
        def run(enabled) do
          io = File.open!("one.txt")
          if enabled do
            File.close(io)
          else
            File.close(io)
          end
          :ok
        end'''),
    ElixirLifecycleCase('file_branch_binding_does_not_replace_outer', '''
        def run(enabled) do
          io = File.open!("outer.txt")
          if enabled do
            io = File.open!("inner.txt")
            File.close(io)
          end
          File.close(io)
        end'''),
    ElixirLifecycleCase('file_outer_cleanup_cannot_close_branch_allocation', '''
        def run(enabled) do
          io = File.open!("outer.txt")
          if enabled do
            io = File.open!("inner.txt") # LEAK:file
            :ok
          end
          File.close(io)
        end'''),
    ElixirLifecycleCase('file_other_function_cannot_discharge', '''
        def run do
          io = File.open!("one.txt") # LEAK:file
          :ok
        end
        def close_unrelated(io) do
          File.close(io)
        end'''),
    ElixirLifecycleCase('file_uncalled_callback_cannot_discharge', '''
        def run do
          io = File.open!("one.txt") # LEAK:file
          finish = fn -> File.close(io) end
          :ok
        end'''),
    ElixirLifecycleCase('file_callback_open_automatically_closes', '''
        def run do
          File.open("one.txt", fn io ->
            IO.read(io, :eof)
          end)
          :ok
        end'''),
    ElixirLifecycleCase('file_bang_callback_with_modes_closes', '''
        def run do
          File.open!("one.txt", [:read], fn io ->
            IO.read(io, :eof)
          end)
          :ok
        end'''),
    ElixirLifecycleCase('file_callback_does_not_own_extra_open', '''
        def run do
          File.open("one.txt", fn io ->
            extra = File.open!("two.txt") # LEAK:file
            IO.read(io, :eof)
            :ok
          end)
          :ok
        end'''),
    ElixirLifecycleCase('file_try_after_guarantees_cleanup', '''
        def run do
          io = File.open!("one.txt")
          try do
            IO.read(io, :eof)
          after
            File.close(io)
          end
        end'''),
    ElixirLifecycleCase('file_try_after_wrong_receiver', '''
        def run do
          first = File.open!("first.txt")
          second = File.open!("second.txt") # LEAK:file
          try do
            :ok
          after
            File.close(first)
          end
          :ok
        end'''),
    ElixirLifecycleCase('file_close_error_can_skip_other_cleanup', '''
        def run do
          first = File.open!("first.txt")
          second = File.open!("second.txt") # LEAK:file
          if File.close(first) == :ok do
            File.close(second)
          end
          :ok
        end'''),
    ElixirLifecycleCase('file_close_result_arms_both_close_other_handle', '''
        def run do
          first = File.open!("first.txt")
          second = File.open!("second.txt")
          case File.close(first) do
            :ok -> File.close(second)
            {:error, _reason} -> File.close(second)
          end
          :ok
        end'''),
    ElixirLifecycleCase('file_return_transfers_handle', '''
        def acquire do
          io = File.open!("one.txt")
          io
        end'''),
    ElixirLifecycleCase('file_return_transfers_result_tuple', '''
        def acquire do
          File.open("one.txt")
        end'''),
    ElixirLifecycleCase('file_success_case_closes_acquired_handle', '''
        def run do
          case File.open("one.txt") do
            {:ok, io} -> File.close(io)
            {:error, _reason} -> :ok
          end
        end'''),
    ElixirLifecycleCase('file_success_case_discards_acquired_handle', '''
        def run do
          case File.open("one.txt") do # LEAK:file
            {:ok, io} -> IO.read(io, :eof)
            {:error, _reason} -> :ok
          end
          :ok
        end'''),
    ElixirLifecycleCase('lexical_decoys_are_not_allocations', '''
        def run do
          text = "Task.async File.open Port.open"
          # Task.async(fn -> :ok end)
          # File.open!("never.txt")
          # Port.open({:spawn_executable, "/bin/cat"}, [])
          text
        end'''),
    ElixirLifecycleCase('file_rule_suppression_is_allocation_specific', '''
        def run do
          first = File.open!("first.txt") # ubs:ignore[ex.io.file-open-unmatched]
          second = File.open!("second.txt") # LEAK:file
          :ok
        end'''),
    ElixirLifecycleCase('unrelated_rule_suppression_keeps_file_obligation', '''
        def run do
          io = File.open!("one.txt") # ubs:ignore[ex.otp.task-async-unawaited] # LEAK:file
          :ok
        end'''),
    ElixirLifecycleCase('port_actual_second_allocation', '''
        def run do
          first = Port.open({:spawn_executable, "/bin/cat"}, [])
          second = Port.open({:spawn_executable, "/bin/cat"}, []) # LEAK:port
          Port.close(first)
          :ok
        end'''),
    ElixirLifecycleCase('port_both_allocations_closed', '''
        def run do
          first = Port.open({:spawn_executable, "/bin/cat"}, [])
          second = Port.open({:spawn_executable, "/bin/cat"}, [])
          Port.close(first)
          Port.close(second)
        end'''),
    ElixirLifecycleCase('port_alias_after_rebinding', '''
        def run do
          port = Port.open({:spawn_executable, "/bin/cat"}, [])
          saved = port
          port = Port.open({:spawn_executable, "/bin/cat"}, []) # LEAK:port
          Port.close(saved)
          :ok
        end'''),
    ElixirLifecycleCase('port_conditional_close_is_not_guaranteed', '''
        def run(enabled) do
          port = Port.open({:spawn_executable, "/bin/cat"}, []) # LEAK:port
          if enabled do
            Port.close(port)
          end
          :ok
        end'''),
    ElixirLifecycleCase('port_both_branches_close', '''
        def run(enabled) do
          port = Port.open({:spawn_executable, "/bin/cat"}, [])
          if enabled do
            Port.close(port)
          else
            Port.close(port)
          end
          :ok
        end'''),
    ElixirLifecycleCase('port_return_transfers_handle', '''
        def acquire do
          Port.open({:spawn_executable, "/bin/cat"}, [])
        end'''),
    ElixirLifecycleCase('port_other_function_cannot_discharge', '''
        def run do
          port = Port.open({:spawn_executable, "/bin/cat"}, []) # LEAK:port
          :ok
        end
        def close_unrelated(port) do
          Port.close(port)
        end'''),
    ElixirLifecycleCase('port_close_is_true_not_ok_atom', '''
        def run do
          io = File.open!("one.txt") # LEAK:file
          port = Port.open({:spawn_executable, "/bin/cat"}, [])
          if Port.close(port) == :ok do
            File.close(io)
          end
          :ok
        end'''),
    ElixirLifecycleCase('port_close_true_branch_runs', '''
        def run do
          io = File.open!("one.txt")
          port = Port.open({:spawn_executable, "/bin/cat"}, [])
          if Port.close(port) == true do
            File.close(io)
          end
          :ok
        end'''),
    ElixirLifecycleCase('task_actual_second_allocation', '''
        def run do
          first = Task.async(fn -> :one end)
          second = Task.async(fn -> :two end) # LEAK:task
          Task.await(first)
          :ok
        end'''),
    ElixirLifecycleCase('task_both_allocations_awaited', '''
        def run do
          first = Task.async(fn -> :one end)
          second = Task.async(fn -> :two end)
          Task.await(first)
          Task.await(second)
        end'''),
    ElixirLifecycleCase('task_alias_after_rebinding', '''
        def run do
          task = Task.async(fn -> :one end)
          saved = task
          task = Task.async(fn -> :two end) # LEAK:task
          Task.await(saved)
          :ok
        end'''),
    ElixirLifecycleCase('task_conditional_await_is_not_guaranteed', '''
        def run(enabled) do
          task = Task.async(fn -> :ok end) # LEAK:task
          if enabled do
            Task.await(task)
          end
          :ok
        end'''),
    ElixirLifecycleCase('task_both_branches_observe', '''
        def run(enabled) do
          task = Task.async(fn -> :ok end)
          if enabled do
            Task.await(task)
          else
            Task.shutdown(task)
          end
          :ok
        end'''),
    ElixirLifecycleCase('task_yield_timeout_keeps_obligation', '''
        def run do
          task = Task.async(fn -> :ok end) # LEAK:task
          Task.yield(task, 0)
          :ok
        end'''),
    ElixirLifecycleCase('task_yield_infinity_observes_reply', '''
        def run do
          task = Task.async(fn -> :ok end)
          Task.yield(task, :infinity)
          :ok
        end'''),
    ElixirLifecycleCase('task_yield_or_shutdown_observes_every_outcome', '''
        def run do
          task = Task.async(fn -> :ok end)
          Task.yield(task, 0) || Task.shutdown(task)
        end'''),
    ElixirLifecycleCase('task_yield_wrong_fallback_cannot_discharge', '''
        def run do
          task = Task.async(fn -> :one end) # LEAK:task
          other = Task.async(fn -> :two end) # LEAK:task
          Task.yield(task, 0) || Task.shutdown(other)
          :ok
        end'''),
    ElixirLifecycleCase('task_case_yield_nil_shutdown_is_complete', '''
        def run do
          task = Task.Supervisor.async_nolink(Workers, fn -> :ok end)
          case Task.yield(task, 0) do
            {:ok, result} -> result
            {:exit, _reason} -> :stopped
            nil -> Task.shutdown(task)
          end
        end'''),
    ElixirLifecycleCase('task_case_yield_nil_without_shutdown_leaks', '''
        def run do
          task = Task.Supervisor.async_nolink(Workers, fn -> :ok end) # LEAK:task
          case Task.yield(task, 0) do
            {:ok, result} -> result
            {:exit, _reason} -> :stopped
            nil -> :ok
          end
        end'''),
    ElixirLifecycleCase('task_supervised_async_requires_observation', '''
        def run do
          task = Task.Supervisor.async(Workers, fn -> :ok end) # LEAK:task
          :ok
        end'''),
    ElixirLifecycleCase('task_supervised_async_awaited', '''
        def run do
          task = Task.Supervisor.async(Workers, fn -> :ok end)
          Task.await(task)
        end'''),
    ElixirLifecycleCase('task_supervised_start_child_has_no_await_obligation', '''
        def run do
          Task.Supervisor.start_child(Workers, fn -> :ok end)
          :ok
        end'''),
    ElixirLifecycleCase('task_start_has_no_await_obligation', '''
        def run do
          Task.start(fn -> :ok end)
          :ok
        end'''),
    ElixirLifecycleCase('task_ignore_explicitly_releases_obligation', '''
        def run do
          task = Task.async(fn -> :ok end)
          Task.ignore(task)
          :ok
        end'''),
    ElixirLifecycleCase('task_ignore_exit_outcome_keeps_branch_reachable', '''
        def run do
          task = Task.Supervisor.async_nolink(Workers, fn -> exit(:failed) end)
          case Task.ignore(task) do
            {:exit, _reason} ->
              io = File.open!("exit.txt") # LEAK:file
              :ok
            {:ok, _result} -> :ok
            nil -> :ok
          end
        end'''),
    ElixirLifecycleCase('task_callback_does_not_capture_unreferenced_file', '''
        def run do
          io = File.open!("one.txt")
          task = Task.async(fn -> :ok end)
          File.close(io)
          Task.await(task)
        end'''),
    ElixirLifecycleCase('task_worker_exit_closes_its_ordinary_file', '''
        def run do
          task = Task.async(fn ->
            io = File.open!("one.txt")
            IO.read(io, :eof)
          end)
          Task.await(task)
        end'''),
    ElixirLifecycleCase('task_supervised_worker_exit_closes_its_port', '''
        def run do
          Task.Supervisor.start_child(Workers, fn ->
            port = Port.open({:spawn_executable, "/bin/cat"}, [])
            Port.command(port, "hello")
          end)
          :ok
        end'''),
    ElixirLifecycleCase('task_return_transfers_to_caller', '''
        def acquire do
          Task.async(fn -> :ok end)
        end'''),
    ElixirLifecycleCase('task_other_function_cannot_discharge', '''
        def run do
          task = Task.async(fn -> :ok end) # LEAK:task
          :ok
        end
        def await_unrelated(task) do
          Task.await(task)
        end'''),
    ElixirLifecycleCase('task_uncalled_callback_cannot_discharge', '''
        def run do
          task = Task.async(fn -> :ok end) # LEAK:task
          finish = fn -> Task.await(task) end
          :ok
        end'''),
    ElixirLifecycleCase('saved_callback_execution', '''
        def run do
          io = File.open!("one.txt")
          finish = fn -> File.close(io) end
          finish.()
        end'''),
)


ELIXIR_LIFECYCLE_INCOMPLETE = (
    ElixirLifecycleCase('delayed_write_close_can_leave_file_open', '''
        def run do
          io = File.open!("output.txt", [:write, :delayed_write])
          File.close(io)
        end'''),
    ElixirLifecycleCase('resource_used_across_task_process', '''
        def run do
          io = File.open!("one.txt")
          task = Task.async(fn -> IO.read(io, :eof) end)
          File.close(io)
          Task.await(task)
        end'''),
    ElixirLifecycleCase('dynamic_cleanup_execution', '''
        def run do
          io = File.open!("one.txt")
          apply(File, :close, [io])
        end'''),
    ElixirLifecycleCase('unmodeled_collection_callback_ownership', '''
        def run(paths) do
          files = Enum.map(paths, fn path -> File.open!(path) end)
          Enum.each(files, &File.close/1)
        end'''),
    ElixirLifecycleCase('macro_can_change_resource_control_flow', '''
        use UnknownResourceMacros
        def run do
          io = File.open!("one.txt")
          release_later(io)
        end'''),
)


class ElixirLifecycleTests(unittest.TestCase):
    """Run the actual scanner; no substitute analyzer implements the oracle."""

    def setUp(self):
        self.artifact = ROOT / 'test-suite/artifacts/oct8-elixir-probe' / (
            self.id().split('.')[-1] + '-' + uuid.uuid4().hex)
        self.artifact.mkdir(parents=True)
        self.scan_root = LIFECYCLE_SCAN_ROOT
        sources = [self.scan_root / 'modules/ubs-elixir.sh',
                   self.scan_root / 'modules/lib/ubs-common.sh',
                   *sorted((self.scan_root / 'modules/helpers/ubs_core').rglob('*.py'))]
        self.tool_hashes = {str(path.relative_to(self.scan_root)):
                            hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}

    def source_file(self, case):
        directory = self.artifact / case.name
        directory.mkdir(exist_ok=True)
        target = directory / 'selected source.ex'
        if not target.exists():
            target.write_text(case.source, encoding='utf-8')
        self.assertEqual(target.read_text(encoding='utf-8'), case.source)
        return directory, target

    def execute(self, case, mode='python', extra=(), **options):
        directory, target = self.source_file(case)
        evidence = directory / (mode + '-' + options.get('attempt', 'scan'))
        evidence.mkdir()
        environment = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_ENABLE_AUTO_UPDATE='0',
                           ENABLE_UV_TOOLS='0', PYTHONDONTWRITEBYTECODE='1',
                           UBS_ALLOW_UNVERIFIED_HELPERS='0',
                           UBS_NO_CACHE='0' if options.get('cached') else '1',
                           UBS_CACHE_DIR=str(directory / 'cache'), TMPDIR=str(evidence))
        if mode == 'python':
            file_list = evidence / 'files.list0'
            file_list.write_bytes(os.fsencode(target) + b'\0')
            report = evidence / 'report.json'
            command = [sys.executable, '-B', '-m', 'ubs_core.elixir_scan',
                       '--files-from', str(file_list), '--sink', str(evidence / 'findings.jsonl'),
                       '--project-dir', str(directory), '--json-out', str(report),
                       '--skip', LIFECYCLE_SKIP, '--fail-on-warning', *extra]
            environment['PYTHONPATH'] = str(self.scan_root / 'modules/helpers')
        else:
            command = [str(self.scan_root / 'modules/ubs-elixir.sh'), '--ci', '--no-color',
                       '--only=3,8', '--fail-on-warning', '--format=' + mode,
                       *extra, str(directory if options.get('directory_input') else target)]
        started = time.monotonic()
        timed_out = False
        try:
            result = subprocess.run(command, cwd=directory, env=environment, text=True,
                                    capture_output=True, timeout=120)
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout, stderr = error.stdout or '', error.stderr or ''
            if isinstance(stdout, bytes):
                stdout = stdout.decode('utf-8', errors='replace')
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8', errors='replace')
            result = subprocess.CompletedProcess(command, 124, stdout, stderr)
        (evidence / 'stdout.log').write_text(result.stdout, encoding='utf-8')
        (evidence / 'stderr.log').write_text(result.stderr, encoding='utf-8')
        (evidence / 'identity.json').write_text(json.dumps({
            'command': command, 'cwd': str(directory), 'exit': result.returncode,
            'timed_out': timed_out,
            'elapsed': time.monotonic() - started, 'python': sys.version,
            'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'tool_sha256': self.tool_hashes,
            'environment': {key: environment.get(key) for key in (
                'PATH', 'PYTHONPATH', 'TMPDIR', 'UBS_NO_CACHE', 'UBS_CACHE_DIR',
                'UBS_NO_AUTO_UPDATE', 'UBS_ALLOW_UNVERIFIED_HELPERS',
                'UBS_TEST_FORCE_NO_AST_GREP', 'ENABLE_UV_TOOLS')},
        }, indent=2), encoding='utf-8')
        context = (command, result.returncode, result.stdout, result.stderr)
        self.assertFalse(timed_out, context)
        try:
            payload = json.loads(report.read_text(encoding='utf-8') if mode == 'python' else result.stdout)
        except (OSError, ValueError):
            self.fail(context)
        return result, payload, target

    def assert_complete(self, case, mode, result, payload, target, *, expected=None):
        context = (case.name, result.returncode, result.stdout, result.stderr, payload)
        expected = case.expected if expected is None else expected
        self.assertEqual(result.returncode, int(bool(expected)), context)
        if mode in {'python', 'json'}:
            self.assertEqual(payload['status'], 'ok', context)
            self.assertEqual((payload['files'], payload['critical'], payload['warning'], payload['info']),
                             (1, 0, len(expected), 0), context)
            records = payload['findings']
            actual = sorted((row['rule'], row['line'], row['col']) for row in records)
            self.assertTrue(all(row['severity'] == 'warning' and Path(row['path']) == target
                                and not row['suppressed'] for row in records), context)
        else:
            records = [row for run in payload['runs'] for row in run.get('results', [])]
            actual = sorted((row['ruleId'],
                             row['locations'][0]['physicalLocation']['region']['startLine'],
                             row['locations'][0]['physicalLocation']['region']['startColumn'])
                            for row in records)
            self.assertTrue(all(row['level'] == 'warning' for row in records), context)
            from urllib.parse import unquote
            self.assertTrue(all(Path(unquote(row['locations'][0]['physicalLocation']
                                             ['artifactLocation']['uri'])) == target for row in records), context)
            invocations = [item for run in payload['runs'] for item in run.get('invocations', [])]
            # Successful module SARIF may omit the optional invocations array;
            # the real process exit and complete result set are checked above.
            for invocation in invocations:
                self.assertIs(invocation['executionSuccessful'], True, context)
                self.assertEqual(invocation['exitCode'], int(bool(expected)), context)
        self.assertEqual(actual, expected, context)

    def assert_incomplete(self, mode, result, payload):
        context = (result.returncode, result.stdout, result.stderr, payload)
        self.assertEqual(result.returncode, 2, context)
        if mode in {'python', 'json'}:
            self.assertEqual(payload['status'], 'partial', context)
            self.assertEqual(payload['module_error'], 'ANALYZER_ERROR', context)
            self.assertIn('incomplete', payload['message'].lower(), context)
        else:
            invocations = [item for run in payload['runs'] for item in run.get('invocations', [])]
            self.assertTrue(invocations, context)
            for invocation in invocations:
                self.assertIs(invocation['executionSuccessful'], False, context)
                self.assertEqual(invocation['exitCode'], 2, context)

    def test_binding_specific_lifecycle_semantics(self):
        for case in ELIXIR_LIFECYCLE_CASES:
            with self.subTest(case=case.name):
                result, payload, target = self.execute(case)
                self.assert_complete(case, 'python', result, payload, target)
                print('ELIXIR_LIFECYCLE_SEMANTIC', case.name, 'PASS', flush=True)

    def test_unsupported_ownership_is_explicitly_incomplete(self):
        for case in ELIXIR_LIFECYCLE_INCOMPLETE:
            with self.subTest(case=case.name):
                result, payload, _ = self.execute(case)
                self.assert_incomplete('python', result, payload)

    @unittest.skipUnless(os.environ.get('UBS_ELIXIR_LIFECYCLE_E2E') == '1',
                         'set UBS_ELIXIR_LIFECYCLE_E2E=1 for actual module JSON/SARIF scans')
    def test_binding_specific_lifecycle_public_json_and_sarif(self):
        for case in ELIXIR_LIFECYCLE_CASES:
            for mode in ('json', 'sarif'):
                with self.subTest(case=case.name, format=mode):
                    result, payload, target = self.execute(case, mode)
                    self.assert_complete(case, mode, result, payload, target)
                    print('ELIXIR_LIFECYCLE_PUBLIC', case.name, mode, 'PASS', flush=True)

    @unittest.skipUnless(os.environ.get('UBS_ELIXIR_LIFECYCLE_E2E') == '1',
                         'set UBS_ELIXIR_LIFECYCLE_E2E=1 for actual incomplete module scans')
    def test_unsupported_ownership_is_incomplete_in_public_reports(self):
        for case in ELIXIR_LIFECYCLE_INCOMPLETE:
            for mode in ('json', 'sarif'):
                with self.subTest(case=case.name, format=mode):
                    result, payload, _ = self.execute(case, mode)
                    self.assert_incomplete(mode, result, payload)

    @unittest.skipUnless(os.environ.get('UBS_ELIXIR_LIFECYCLE_E2E') == '1',
                         'set UBS_ELIXIR_LIFECYCLE_E2E=1 for actual selection/category scans')
    def test_selected_files_excludes_and_category_filters(self):
        for name, category in (('file_actual_second_allocation', '8'),
                               ('task_actual_second_allocation', '3')):
            case = next(item for item in ELIXIR_LIFECYCLE_CASES if item.name == name)
            directory, _ = self.source_file(case)
            sibling = directory / 'unselected.ex'
            sibling.write_text('defmodule Other do\n  def run do\n'
                               '    Port.open({:spawn_executable, "/bin/cat"}, [])\n'
                               '    :ok\n  end\nend\n', encoding='utf-8')
            for mode in ('json', 'sarif'):
                for attempt, extra, directory_input in (
                    ('selected-file', (), False),
                    ('excluded-sibling', ('--exclude=unselected.ex',), True),
                    ('skip-category', ('--skip=' + category,), False),
                ):
                    with self.subTest(case=name, format=mode, selection=attempt):
                        result, payload, target = self.execute(
                            case, mode, extra, attempt=attempt, directory_input=directory_input)
                        self.assert_complete(case, mode, result, payload, target,
                                             expected=[] if attempt == 'skip-category' else None)

    def test_warm_cache_preserves_obligations_and_category_context(self):
        case = next(item for item in ELIXIR_LIFECYCLE_CASES
                    if item.name == 'file_actual_second_allocation')
        for attempt, extra, expected, expected_hits in (
            ('cold', (), case.expected, 0),
            ('warm', (), case.expected, 1),
            ('category-excluded', ('--skip', LIFECYCLE_SKIP + ',8'), [], 0),
            ('category-excluded-warm', ('--skip', LIFECYCLE_SKIP + ',8'), [], 1),
            ('restored-category', (), case.expected, 1),
        ):
            with self.subTest(attempt=attempt):
                result, payload, target = self.execute(case, extra=extra, attempt=attempt, cached=True)
                self.assert_complete(case, 'python', result, payload, target, expected=expected)
                self.assertEqual(payload['extras']['profile']['cache_hits'], expected_hits, payload)
