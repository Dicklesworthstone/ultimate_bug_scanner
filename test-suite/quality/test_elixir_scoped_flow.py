"""Elixir clause/tuple validation and immutable-value proof regressions.

The initial independent oracle lives in test_swift_elixir_request_flow.py.
These additional source programs exercise the newly supported control forms
and prove that validation does not cross a value, scope, or sink boundary.
"""
from __future__ import annotations

import os
import unittest
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

    def test_explicit_boundaries_and_budget(self):
        sources = (
            'def handle(conn, params) do\nredirect(conn, external: params["next"])',
            'def handle(conn, params) do\nmodule = params["module"]\nmodule.forward(conn)\nend',
            'def handle(conn, params) do\nredirect(conn, external: apply(Safe, :validate, [params["next"]]))\nend',
            'defmodule Handler do\nuse CustomMacros\ndef handle(conn, params), do: redirect(conn, external: params["next"])\nend',
            'def handle(conn, params) do\nredirect(conn, external: Unknown.validate(params["next"]))\nend',
            'def handle(conn, params) do\nf = fn value -> value end\nredirect(conn, external: f.(params["next"]))\nend',
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
