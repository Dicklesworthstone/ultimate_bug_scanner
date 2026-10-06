"""C# D6 regressions against the real analyzer, without scanner doubles.

UBS_CSHARP_TEST_ANALYZER selects an older source file for before/after probes.
Only DataflowDetectionTests use that hook; engine/CLI tests test the checkout.
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.registry import RunContext
from ubs_core.analyzers import taint_csharp_redirect as redirect
from ubs_core.taint_flow import (AnalysisLimit, Budget, CLEAN, Step, Trace,
                                advance, join, join_states, solve)

if os.environ.get('UBS_CSHARP_TEST_ANALYZER'):
    spec = importlib.util.spec_from_file_location('ubs_csharp_dataflow_under_test', os.environ['UBS_CSHARP_TEST_ANALYZER'])
    cs = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = cs
    spec.loader.exec_module(cs)
else:
    from ubs_core.analyzers import taint_csharp_request as cs
RULE = 'csharp.taint.request_traversal'


class LatticeTests(unittest.TestCase):
    def test_join_laws_and_deterministic_shortest_evidence(self):
        a = frozenset({Trace('source', ('a.cs', 1))})
        b = frozenset({Trace('source', ('b.cs', 2))})
        c = frozenset({Trace('parameter', (10, 0))})
        for x, y, z in itertools.product((CLEAN, a, b, c, join(a, b)), repeat=3):
            self.assertEqual(join(x, x), x)
            self.assertEqual(join(x, y), join(y, x))
            self.assertEqual(join(join(x, y), z), join(x, join(y, z)))
        long = advance(advance(a, Step('a.cs', 1, 1, 'call', 'a')), Step('a.cs', 2, 1, 'call', 'b'))
        short = advance(a, Step('a.cs', 1, 1, 'call', 'a'))
        for order in ((long, short), (short, long)):
            self.assertEqual(next(iter(join(*order))).evidence, next(iter(short)).evidence)

    def test_cyclic_cfg_converges_and_reaches_a_long_chain(self):
        source = frozenset({Trace('source', ('a.cs', 0))})
        edges = {i: (i + 1,) for i in range(200)}
        edges[200] = (0,)
        def transfer(node, state):
            if node == 0:
                state['x0'] = source
            else:
                state['x' + str(node)] = state.get('x' + str(node - 1), CLEAN)
            return state
        inputs = solve(0, {}, edges, transfer, Budget())
        self.assertEqual(inputs[200]['x199'], source)

    def test_strong_kill_is_not_undone_by_the_old_output(self):
        source = frozenset({Trace('source', ('a.cs', 0))})
        def transfer(node, state):
            if node == 0:
                state['p'] = source
            elif node == 1:
                state.pop('p', None)
            return state
        result = solve(0, {}, {0: (1,), 1: (2,), 2: ()}, transfer, Budget())
        self.assertNotIn('p', result[2])

    def test_empty_state_is_reachable_and_dead_nodes_are_not(self):
        result = solve(0, {}, {0: (1,), 1: (), 2: ()}, lambda _, state: state, Budget())
        self.assertEqual(result, {0: {}, 1: {}})

    def test_budget_exhaustion_is_an_error_not_partial_success(self):
        with self.assertRaisesRegex(AnalysisLimit, 'incomplete'):
            solve(0, {}, {0: (1,), 1: ()}, lambda _, state: state, Budget(1))


class DataflowDetectionTests(unittest.TestCase):
    def scan(self, code):
        with tempfile.TemporaryDirectory(prefix='ubs-csharp-flow-test-') as tmp:
            source = Path(tmp) / 'fixture.cs'
            source.write_text(textwrap.dedent(code), encoding='utf-8')
            return list(cs.run(RunContext(lang='csharp', files=[source])))

    def bad(self, code, count=1):
        findings = self.scan(code)
        self.assertEqual(len(findings), count, findings)
        self.assertTrue(all(f['rule'] == RULE and f['severity'] == 'critical' for f in findings), findings)
        return findings

    def clean(self, code):
        self.assertEqual(self.scan(code), [])

    def test_existing_buggy_fixture_retains_all_five_flows(self):
        source = ROOT / 'test-suite/csharp/security/RequestPathTraversalBuggy.cs'
        findings = list(cs.run(RunContext(lang='csharp', files=[source])))
        self.assertEqual({f['line'] for f in findings}, {13, 19, 26, 33, 40})

    def test_existing_clean_fixture_remains_clean(self):
        source = ROOT / 'test-suite/csharp/security/RequestPathTraversalClean.cs'
        self.assertEqual(list(cs.run(RunContext(lang='csharp', files=[source]))), [])

    def test_helper_sink_tracks_actual_parameter_and_named_arguments(self):
        self.bad('''
            class C {
                void Save(string path, string contents) { File.WriteAllText(path, contents); }
                void Handler() { Save(contents: "data", path: Request.Query["path"]); }
            }
        ''')

    def test_helper_source_return_flows_into_caller(self):
        self.bad('''
            class C {
                string Source() { return Request.Query["path"]; }
                void Handler() { File.Delete(Source()); }
            }
        ''')

    def test_nested_helper_returns_and_expression_bodies(self):
        self.bad('''
            class C {
                string A(string value) => B(value);
                string B(string value) { return Path.Combine("/srv", value); }
                void Handler() { File.OpenRead(A(Request.Query["path"])); }
            }
        ''')

    def test_helper_constant_return_is_not_tainted_by_its_argument(self):
        self.clean('''
            class C {
                string Fixed(string value) { return "/fixed.txt"; }
                void Handler() { File.ReadAllText(Fixed(Request.Query["path"])); }
            }
        ''')

    def test_same_named_parameter_in_unrelated_method_is_not_tainted(self):
        self.clean('''
            class C {
                void A() { var path = Request.Query["path"]; }
                void B(string path) { File.ReadAllText(path); }
                void Handler() { B("/fixed.txt"); }
            }
        ''')

    def test_same_method_name_in_unrelated_types_is_not_resolved(self):
        self.clean('''
            class A { string Map(string p) => "/fixed.txt";
                void H() { File.Delete(Map(Request.Query["p"])); } }
            class B { string Map(string p) => p; }
        ''')

    def test_same_file_static_type_qualified_helper(self):
        self.bad('''
            class Storage { public static void Read(string p) { File.ReadAllText(p); } }
            class Controller { void H() { Storage.Read(Request.Query["p"]); } }
        ''')

    def test_clean_caller_does_not_infect_or_erase_tainted_caller(self):
        self.bad('''
            class C {
                string Map(string p) => p;
                void Good() { File.ReadAllText(Map("/safe")); }
                void Bad() { File.ReadAllText(Map(Request.Query["p"])); }
            }
        ''')

    def test_safe_helper_body_is_used_not_its_name(self):
        self.bad('''
            class C {
                string SafePath(string p) => p;
                void H() { File.Delete(SafePath(Request.Query["p"])); }
            }
        ''')

    def test_real_basename_helper_sanitizes_the_return_only(self):
        self.clean('''
            class C {
                string Component(string p) => Path.GetFileName(p);
                void H() { File.Delete(Path.Combine("/srv", Component(Request.Query["p"]))); }
            }
        ''')

    def test_sanitizer_does_not_hide_other_arguments_or_later_inputs(self):
        self.bad('''
            var first = Request.Query["first"];
            var second = Request.Query["second"];
            File.Delete(Path.GetFileName(first) + second);
        ''')

    def test_string_literal_reassignment_strongly_kills_taint(self):
        self.clean('var p = Request.Query["p"]; p = "/fixed"; File.Delete(p);')

    def test_clean_assignments_on_both_branches_kill_taint(self):
        self.clean('var p = Request.Query["p"]; if (ok) { p = "/a"; } else { p = "/b"; } File.Delete(p);')

    def test_clean_assignment_on_one_branch_does_not_erase_the_other(self):
        self.bad('var p = Request.Query["p"]; if (ok) { p = "/a"; } File.Delete(p);')

    def test_source_on_either_branch_is_joined(self):
        self.bad('var p = "/a"; if (ok) { p = Request.Query["p"]; } else { p = "/b"; } File.Delete(p);')

    def test_loop_carried_flow_reaches_sink_before_assignment(self):
        self.bad('''
            var a = "/a"; var b = "/b";
            while (next) { File.ReadAllText(a); a = b; b = Request.Query["p"]; }
        ''')

    def test_loop_exit_joins_zero_and_many_iterations(self):
        self.bad('var p = Request.Query["p"]; while (next) { p = "/safe"; } File.Delete(p);')

    def test_unconditional_return_and_break_do_not_run_later_statements(self):
        self.clean('''
            class C { void H() {
                var p = Request.Query["p"];
                while (true) { break; File.Delete(p); }
                return; File.Delete(p);
            } }
        ''')

    def test_continue_preserves_loop_carried_assignment(self):
        self.bad('''
            var p = "/safe";
            while (next) { File.Delete(p); p = Request.Query["p"]; continue; p = "/safe"; }
        ''')

    def test_do_loop_executes_once_before_false_condition(self):
        self.bad('var p = "/safe"; do { p = Request.Query["p"]; } while (false); File.Delete(p);')

    def test_do_false_does_not_invent_a_second_iteration(self):
        self.clean('var p = "/safe"; do { File.Delete(p); p = Request.Query["p"]; } while (false);')

    def test_generic_helper_instantiation_uses_its_summary(self):
        self.bad('class C { void Read<T>(string p) { File.Delete(p); } void H() { Read<int>(Request.Query["p"]); } }')

    def test_generic_helper_as_argument_does_not_split_type_parameters(self):
        self.bad('class C { string Map<A,B>(string p) => p; void H() { File.Delete(Map<int,string>(Request.Query["p"])); } }')

    def test_multiple_declarators_share_scope_and_update_sequentially(self):
        self.bad('string a="/safe", b=Request.Query["p"], c=b; File.Delete(c);')

    def test_tainted_condition_does_not_taint_fixed_branch_results(self):
        self.clean('class C { string Pick(string p) => p.Length > 1 ? "/safe" : "/fallback"; void H() { File.Delete(Pick(Request.Query["p"])); } }')

    def test_finally_sink_runs_on_return_and_throw(self):
        for completion in ('return;', 'throw new Exception();'):
            with self.subTest(completion=completion):
                self.bad('class C { void H() { var p=Request.Query["p"]; try { ' + completion +
                         ' } finally { File.Delete(p); } } }')

    def test_finally_sees_values_assigned_before_abrupt_exit(self):
        self.bad('class C { void H() { var p="/safe"; try { p=Request.Query["p"]; return; } finally { File.Delete(p); } } }')

    def test_finally_on_break_leaving_try_does_not_run_following_body(self):
        self.bad('var p=Request.Query["p"]; while (true) { try { break; } finally { File.Delete(p); } p="/safe"; }')

    def test_catch_sees_taint_written_before_throw(self):
        self.bad('var p="/safe"; try { p=Request.Query["p"]; throw new Exception(); } catch (Exception e) { File.Delete(p); }')

    def test_literal_false_branch_does_not_create_a_source(self):
        self.clean('var p = "/safe"; if (false) { p = Request.Query["p"]; } File.Delete(p);')

    def test_switch_arms_join_instead_of_sequentially_erasing(self):
        self.bad('''
            var p = "/safe";
            switch (which) { case 1: p = Request.Query["p"]; break; default: p = "/safe"; break; }
            File.Delete(p);
        ''')

    def test_recursion_and_mutual_recursion_terminate(self):
        self.bad('''
            class C {
                string A(string p) { if (done) return p; return B(p); }
                string B(string p) => A(p);
                void H() { File.Delete(B(Request.Query["p"])); }
            }
        ''')

    def test_helper_with_only_parameter_and_no_tainted_call_is_clean(self):
        self.clean('class C { void H(string p) { File.Delete(p); } void Other() { var ignored = Request.Query["p"]; } }')

    def test_async_file_read_and_write_are_path_sinks(self):
        self.bad('''
            class C { async Task H() {
                var p = Request.Query["p"];
                await File.ReadAllTextAsync(p);
                await File.WriteAllBytesAsync(p, data);
            } }
        ''', count=2)

    def test_request_controlled_file_contents_are_not_paths(self):
        self.clean('File.WriteAllText("/fixed.txt", Request.Form["body"]);')

    def test_named_async_contents_and_token_are_not_paths(self):
        self.clean('await File.WriteAllTextAsync(contents: Request.Form["body"], path: "/fixed.txt");')

    def test_copy_destination_and_backup_paths_are_sinks(self):
        self.bad('''
            File.Copy("/safe", Request.Query["destination"]);
            File.Replace("/safe", "/safe2", Request.Query["backup"]);
        ''', count=2)

    def test_request_collection_get_and_tostring_are_sources(self):
        self.bad('var p = Request.Query.ToString(); File.Delete(p);')

    def test_typed_request_parameter_with_nonstandard_name(self):
        self.bad('class C { void H(HttpRequest incoming) { File.Delete(incoming.Query["p"]); } }')

    def test_try_get_value_taints_output_but_not_boolean_result(self):
        self.bad('Request.Headers.TryGetValue("X-Path", out var p); File.Delete(p);')

    def test_comments_normal_verbatim_raw_and_char_literals_are_inert(self):
        self.clean(r'''
            var documentation = "Request.Query File.Delete(p)";
            var verbatim = @"Request.Query[""p""]; File.Delete(p);";
            var raw = """Request.Query["p"]; File.Delete(p);""";
            var c = '"';
            // Request.Query["p"]; File.Delete(p);
            /* Request.Query["p"]; File.Delete(p); */
            File.Delete("/fixed");
        ''')

    def test_interpolated_string_preserves_executable_input(self):
        self.bad('var p = Request.Query["p"]; File.Delete($"/srv/{p}");')

    def test_verbatim_interpolation_and_nested_strings(self):
        self.bad('File.Delete($@"/srv/{Request.Query["p"]}");')

    def test_raw_interpolation_uses_dollar_arity(self):
        self.bad('var p = Request.Query["p"]; File.Delete($$"""literal {brace}/{{p}}""");')

    def test_interpolated_escaped_braces_are_not_executed(self):
        self.clean('var p = Request.Query["p"]; File.Delete($"/safe/{{p}}");')

    def test_inert_string_cannot_supply_a_suppression_marker(self):
        self.bad('var p = Request.Query["p"]; var s = "ubs:ignore"; File.Delete(p);')

    def test_ignored_sink_does_not_sanitize_the_source(self):
        self.bad('''
            var p = Request.Query["p"];
            File.Delete(p); // ubs:ignore[csharp.taint.request_traversal]
            File.ReadAllText(p);
        ''')

    def test_rule_scoped_marker_does_not_suppress_a_different_rule(self):
        self.bad('var p = Request.Query["p"]; File.Delete(p); // ubs:ignore[csharp.other]')

    def test_unrelated_basename_operation_does_not_sanitize_path(self):
        self.bad('var p = Request.Query["p"]; var other = Path.GetFileName("/safe"); File.Delete(p);')

    def test_prefix_without_separator_is_not_a_containment_proof(self):
        self.bad('''
            var root = "/srv/uploads";
            var p = Path.GetFullPath(Request.Query["p"]);
            if (!p.StartsWith(root, StringComparison.Ordinal)) { return; }
            File.Delete(p);
        ''')
        self.assertTrue('/srv/uploads-evil/secret'.startswith('/srv/uploads'))

    def test_prefix_without_canonicalization_is_not_a_containment_proof(self):
        self.bad('''
            var root = "/srv/uploads"; var p = Request.Query["p"];
            if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { return; }
            File.Delete(p);
        ''')

    def test_containment_requires_unsafe_branch_to_exit(self):
        self.bad('''
            var root = "/srv/uploads"; var p = Path.GetFullPath(Request.Query["p"]);
            if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { Log(p); }
            File.Delete(p);
        ''')

    def test_canonical_containment_guard_discharges_only_safe_branch(self):
        self.clean('''
            var root = "/srv/uploads"; var p = Path.GetFullPath(Request.Query["p"]);
            if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { return; }
            File.Delete(p);
        ''')

    def test_new_value_after_guard_is_not_sanitized(self):
        self.bad('''
            var root = "/srv/uploads"; var p = Path.GetFullPath(Request.Query["p"]);
            if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { return; }
            p = Request.Query["other"]; File.Delete(p);
        ''')

    def test_controlled_root_cannot_certify_an_arbitrary_controlled_path(self):
        self.bad('''
            var root = Path.GetFullPath(Request.Query["root"]);
            var p = Path.GetFullPath(Request.Query["p"]);
            if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { return; }
            File.Delete(p);
        ''')

    def test_helper_transformation_cannot_restore_canonical_tag(self):
        self.bad('''
            class C {
                string Append(string p) => p + "/../secret";
                void H() {
                    var root = "/srv/uploads";
                    var p = Append(Path.GetFullPath(Request.Query["p"]));
                    if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { return; }
                    File.Delete(p);
                }
            }
        ''')

    def test_user_defined_path_class_is_not_a_builtin_sanitizer(self):
        self.bad('''
            class Path { public static string GetFileName(string p) => p; }
            class C { void H() { File.Delete(Path.GetFileName(Request.Query["p"])); } }
        ''')

    def test_helper_effect_provenance_names_source_call_and_sink(self):
        findings = self.bad('''
            class C {
                void Read(string p) { File.ReadAllText(p); }
                void H() { Read(Request.Query["p"]); }
            }
        ''')
        kinds = [step['kind'] for step in findings[0]['extras']['taint_path']]
        self.assertIn('source', kinds)
        self.assertIn('call', kinds)
        self.assertIn('sink', kinds)
        self.assertEqual(findings[0]['extras']['source_count'], 1)

    def test_overloads_with_different_arities_do_not_share_parameters(self):
        self.clean('''
            class C {
                string Map(string p) => "/fixed";
                string Map(string p, string q) => p;
                void H() { File.Delete(Map(Request.Query["p"])); }
            }
        ''')

    def test_disabled_rule_does_not_read_source(self):
        context = RunContext(lang='csharp', files=[Path('/absent.cs')], profile={'disabled_rules': [RULE]})
        self.assertEqual(list(cs.run(context)), [])


class ByReferenceTests(unittest.TestCase):
    scan = DataflowDetectionTests.scan
    bad = DataflowDetectionTests.bad
    clean = DataflowDetectionTests.clean

    def test_out_parameter_carries_request_source_into_caller(self):
        self.bad('class C { void Source(out string p) { p=Request.Query["p"]; } void H() { Source(out var path); File.Delete(path); } }')

    def test_parameter_to_out_summary_uses_the_actual_input(self):
        self.bad('class C { void Copy(string raw, out string p) { p=raw; } void H() { Copy(Request.Query["p"], out var path); File.Delete(path); } }')

    def test_named_output_arguments_bind_by_parameter(self):
        self.bad('class C { void Copy(string raw, out string p) { p=raw; } void H() { Copy(p: out var path, raw: Request.Query["p"]); File.Delete(path); } }')

    def test_ref_parameter_can_introduce_a_new_request_source(self):
        self.bad('class C { void Source(ref string p) { p=Request.Query["p"]; } void H() { var path="/safe"; Source(ref path); File.Delete(path); } }')

    def test_ref_identity_preserves_the_callers_taint(self):
        self.bad('class C { void Keep(ref string p) { Log(p); } void H() { var path=Request.Query["p"]; Keep(ref path); File.Delete(path); } }')

    def test_ref_constant_assignment_kills_old_taint(self):
        self.clean('class C { void Clear(ref string p) { p="/fixed"; } void H() { var path=Request.Query["p"]; Clear(ref path); File.Delete(path); } }')

    def test_out_constant_assignment_kills_old_taint(self):
        self.clean('class C { void Clear(out string p) { p="/fixed"; } void H() { var path=Request.Query["p"]; Clear(out path); File.Delete(path); } }')

    def test_out_basename_is_a_transformation_not_a_global_sanitizer(self):
        self.bad('class C { void Name(string raw, out string p) { p=Path.GetFileName(raw); } void H() { var raw=Request.Query["p"]; Name(raw, out var safe); File.Delete(safe); File.Delete(raw); } }')

    def test_nested_output_helpers_propagate_writes(self):
        self.bad('class C { void A(string x, out string p) { B(x, out p); } void B(string x, out string p) { p=x; } void H() { A(Request.Query["p"], out var p); File.Delete(p); } }')

    def test_ref_conditional_write_joins_both_exits(self):
        self.bad('class C { void Change(ref string p) { if (ok) p=Request.Query["p"]; } void H() { var p="/safe"; Change(ref p); File.Delete(p); } }')

    def test_ref_conditional_clean_does_not_erase_untouched_branch(self):
        self.bad('class C { void Change(ref string p) { if (ok) p="/safe"; } void H() { var p=Request.Query["p"]; Change(ref p); File.Delete(p); } }')

    def test_outputs_are_taken_after_finally_on_return(self):
        self.bad('class C { void Source(out string p) { p="/safe"; try { return; } finally { p=Request.Query["p"]; } } void H() { Source(out var p); File.Delete(p); } }')

    def test_finally_can_clear_a_reference_before_returning(self):
        self.clean('class C { void Clear(ref string p) { try { return; } finally { p="/safe"; } } void H() { var p=Request.Query["p"]; Clear(ref p); File.Delete(p); } }')

    def test_aliased_ref_parameters_share_storage_inside_the_helper(self):
        self.bad('class C { void Use(ref string p, ref string q) { p=Request.Query["p"]; File.Delete(q); } void H() { var path="/safe"; Use(ref path, ref path); } }')

    def test_nonaliased_ref_parameters_do_not_share_storage(self):
        self.clean('class C { void Use(ref string p, ref string q) { p=Request.Query["p"]; File.Delete(q); } void H() { var a="/safe"; var b="/safe"; Use(ref a, ref b); } }')

    def test_alias_context_does_not_pollute_a_distinct_call(self):
        self.bad('class C { void Use(ref string p, ref string q) { p=Request.Query["p"]; File.Delete(q); } void H() { var a="/safe"; var b="/safe"; Use(ref a, ref a); Use(ref a, ref b); } }')

    def test_second_aliased_assignment_overwrites_the_first(self):
        self.clean('class C { void Change(ref string p, ref string q) { p=Request.Query["p"]; q="/safe"; } void H() { var path="/safe"; Change(ref path, ref path); File.Delete(path); } }')

    def test_in_parameter_observes_writes_through_an_alias(self):
        self.bad('class C { void Use(ref string p, in string q) { p=Request.Query["p"]; File.Delete(q); } void H() { var path="/safe"; Use(ref path, in path); } }')

    def test_by_value_parameter_does_not_alias_reference_storage(self):
        self.clean('class C { void Use(ref string p, string q) { p=Request.Query["p"]; File.Delete(q); } void H() { var path="/safe"; Use(ref path, path); } }')

    def test_out_and_ref_alias_share_updates_inside_the_helper(self):
        self.bad('class C { void Use(out string p, ref string q) { p=Request.Query["p"]; File.Delete(q); } void H() { var path="/safe"; Use(out path, ref path); } }')

    def test_distinct_outputs_are_applied_to_the_right_variables(self):
        self.bad('class C { void Split(string raw, out string a, out string b) { a=raw; b="/safe"; } void H() { Split(Request.Query["p"], out var first, out var second); File.Delete(first); File.Delete(second); } }')

    def test_unresolved_helper_cannot_hide_parameter_to_out_flow(self):
        self.bad('External.Copy(Request.Query["p"], out var path); File.Delete(path);')

    def test_unresolved_ref_call_does_not_assert_sanitization(self):
        self.bad('var path=Request.Query["p"]; External.Clear(ref path); File.Delete(path);')

    def test_output_evidence_survives_substitution(self):
        findings = self.bad('class C { void Copy(string raw, out string p) { p=raw; } void H() { Copy(Request.Query["p"], out var path); File.Delete(path); } }')
        self.assertIn('output', [step['kind'] for step in findings[0]['extras']['taint_path']])

    def test_output_summaries_converge_through_mutual_recursion(self):
        self.bad('class C { void A(string raw, out string p) { if (done) { p=raw; return; } B(raw,out p); } void B(string raw, out string p) { A(raw,out p); } void H() { B(Request.Query["p"],out var p); File.Delete(p); } }')


class RedirectDataflowTests(unittest.TestCase):
    def scan(self, code):
        with tempfile.TemporaryDirectory(prefix='ubs-csharp-redirect-') as tmp:
            path = Path(tmp) / 'app.cs'
            path.write_text(textwrap.dedent(code), encoding='utf-8')
            return list(redirect.run(RunContext(lang='csharp', files=[path])))

    def check(self, code, count=1):
        findings = self.scan(code)
        self.assertEqual(len(findings), count, findings)
        self.assertTrue(all(f['rule'] == redirect.RULE and f['severity'] == 'critical' for f in findings), findings)
        return findings

    def test_existing_buggy_fixture_covers_every_redirect_sink(self):
        source = ROOT / 'test-suite/csharp/security/OpenRedirectBuggy.cs'
        findings = list(redirect.run(RunContext(lang='csharp', files=[source])))
        self.assertEqual({f['line'] for f in findings}, {10, 16, 22, 28, 34})

    def test_existing_clean_fixture_uses_real_local_and_host_validation(self):
        source = ROOT / 'test-suite/csharp/security/OpenRedirectClean.cs'
        self.assertEqual(list(redirect.run(RunContext(lang='csharp', files=[source]))), [])

    def test_original_clean_fixture_weak_prefix_is_an_unsafe_helper(self):
        # Retain the original predicate as positive coverage. A /\ prefix is
        # accepted here but normalized by browsers into an external authority.
        self.check('''
            class C {
                private static string SafeRedirectTarget(string raw)
                {
                    if (raw.StartsWith("/", StringComparison.Ordinal) && !raw.StartsWith("//", StringComparison.Ordinal))
                    {
                        return raw;
                    }
                    throw new Exception();
                }
                void H() { Response.Redirect(SafeRedirectTarget(Request.Query["x"])); }
            }
        ''')

    def test_browser_url_oracle_disproves_original_local_prefix_guard(self):
        node = shutil.which('node')
        if node is None:
            self.skipTest('Node URL runtime unavailable; detector regression runs independently')
        result = subprocess.run([node, '-e', r'''
            const raw = '/\\attacker.example/login';
            process.stdout.write(JSON.stringify({
                accepted: raw.startsWith('/') && !raw.startsWith('//'),
                destination: new URL(raw, 'https://app.example.com').href
            }));
        '''], capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(json.loads(result.stdout), {'accepted': True, 'destination': 'https://attacker.example/login'})

    def test_helpers_propagate_only_actual_url_arguments(self):
        findings = self.check('''
            class C {
                void Send(string target, string description) { Response.Redirect(target); }
                void Bad() { Send(description: "data", target: Request.Query["x"]); }
                void Good() { Send(description: Request.Query["x"], target: "/safe"); }
            }
        ''')
        kinds = {step['kind'] for step in findings[0]['extras']['taint_path']}
        self.assertTrue({'source', 'call', 'sink'} <= kinds)

    def test_source_returns_and_ref_out_effects_reach_caller(self):
        self.check('''
            class C {
                string Source() => Request.Query["x"];
                void Copy(string input, out string target) { target = input; }
                void H() { Copy(Source(), out var destination); Results.Redirect(destination); }
            }
        ''')

    def test_helper_constant_return_and_ref_overwrite_are_clean(self):
        self.check('''
            class C {
                string Fixed(string input) => "/safe";
                void Clear(ref string input) { input = "/safe"; }
                void H() {
                    var target = Request.Query["x"];
                    Response.Redirect(Fixed(target));
                    Clear(ref target);
                    Response.Redirect(target);
                }
            }
        ''', 0)

    def test_same_named_locals_in_other_methods_do_not_share_taint(self):
        self.check('''
            class C {
                void A() { var target = Request.Query["x"]; }
                void B(string target) { Response.Redirect(target); }
                void Good() { B("/safe"); }
            }
        ''', 0)

    def test_reassignment_and_branch_join_use_current_values(self):
        for change, count in [('target = "/safe";', 0),
                              ('if (ok) target = "/safe"; else target = "/other";', 0),
                              ('if (ok) target = "/safe";', 1)]:
            with self.subTest(change=change):
                self.check('var target=Request.Query["x"]; ' + change + ' Response.Redirect(target);', count)

    def test_loop_carried_flow_and_recursive_helpers_converge(self):
        self.check('''
            class C {
                string A(string p) { if (done) return p; return B(p); }
                string B(string p) => A(p);
                void H() {
                    var target = "/safe";
                    while (next) { Response.Redirect(target); target = B(Request.Query["x"]); }
                }
            }
        ''')

    def test_guard_only_refines_its_success_branch(self):
        for guard in ('if (!Url.IsLocalUrl(target)) { return; }',
                      'if (!Url.IsLocalUrl(target)) { throw new Exception(); }'):
            with self.subTest(guard=guard):
                self.check('var target=Request.Query["x"]; ' + guard + ' Response.Redirect(target);', 0)
        self.check('''
            var target = Request.Query["x"];
            if (Url.IsLocalUrl(target)) { Response.Redirect(target); }
            else { Response.Redirect(target); }
        ''')

    def test_ignored_nondominating_or_overwritten_guards_do_not_sanitize(self):
        cases = (
            'Url.IsLocalUrl(target);',
            'var valid = Url.IsLocalUrl(target);',
            'if (!Url.IsLocalUrl(target)) { Log(target); }',
            'if (ok) { if (!Url.IsLocalUrl(target)) return; }',
            'if (!Url.IsLocalUrl(target)) return; target=Request.Query["other"];',
            'var other="/safe"; if (!Url.IsLocalUrl(other)) return;',
            'if (Url.IsLocalUrl(target)) return;',
        )
        for code in cases:
            with self.subTest(code=code):
                self.check('var target=Request.Query["x"]; ' + code + ' Response.Redirect(target);')

    def test_validation_inside_real_helper_uses_summary(self):
        self.check('''
            class C {
                string Validate(string target) {
                    if (!Url.IsLocalUrl(target)) throw new Exception();
                    return target;
                }
                void H() { Response.Redirect(Validate(Request.Query["x"])); }
            }
        ''', 0)

    def test_safe_names_and_shadowed_validators_are_not_proofs(self):
        for helper in ('SafeRedirectTarget', 'ValidatedRedirectUrl', 'SanitizeRedirect'):
            with self.subTest(helper=helper):
                self.check('class C { string ' + helper + '(string p) => p; void H() { Response.Redirect(' + helper + '(Request.Query["x"])); } }')
                self.check('Response.Redirect(External.' + helper + '(Request.Query["x"]));')
        self.check('''
            class Url { public static bool IsLocalUrl(string p) => true; }
            class C { void H() { var target=Request.Query["x"]; if(!Url.IsLocalUrl(target)) return; Response.Redirect(target); } }
        ''')

    def test_official_static_validator_and_import_alias(self):
        self.check('''
            using Redirects = Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult;
            var target = Request.Query["x"];
            if (!Redirects.IsLocalUrl(target)) return;
            Response.Redirect(target);
        ''', 0)

    def test_file_path_and_encoding_sanitizers_are_not_url_validation(self):
        for call in ('Path.GetFileName', 'Path.GetFullPath', 'HttpUtility.UrlEncode', 'WebUtility.HtmlEncode'):
            with self.subTest(call=call):
                self.check('Response.Redirect(' + call + '(Request.Query["x"]));')

    def test_typed_request_sources_and_try_get_value_outputs(self):
        self.check('''
            class C { void H(HttpRequest incoming) {
                incoming.Headers.TryGetValue("X", out var target);
                Response.Redirect(target.ToString());
                Response.Redirect(incoming.Host.Value);
            } }
        ''', 2)

    def test_location_writes_and_named_arguments_track_only_header_value(self):
        self.check('''
            var target = Request.Query["x"];
            Response.Headers["lOcAtIoN"] = target;
            Response.Headers.Location = target;
            Response.Headers.Append(value: target, key: "Location");
            Response.Headers.Add("Location", target);
            Response.Headers["X-Other"] = target;
            Response.Headers.Append("X-Other", target);
            Response.Redirect(location: "/safe", permanent: Request.Query["permanent"]);
        ''', 4)

    def test_local_redirect_is_a_safe_sink_but_does_not_clean_shared_input(self):
        self.check('''
            var target = Request.Query["x"];
            LocalRedirect(target);
            Results.LocalRedirect(target);
            Response.Redirect(target);
        ''')

    def test_literals_and_comments_are_inert_but_interpolations_execute(self):
        self.check(r'''
            var documentation = "Request.Query[\"x\"]; Response.Redirect(target);";
            /* var target=Request.Query["x"]; Response.Redirect(target); */
            Response.Redirect("/fixed");
        ''', 0)
        self.check('Response.Redirect($"{Request.Query["x"]}");')

    def test_rule_scoped_suppression_does_not_sanitize_source(self):
        self.check('''
            var target = Request.Query["x"];
            Response.Redirect(target); // ubs:ignore[csharp.taint.open_redirect]
            Response.Redirect(target); // ubs:ignore[csharp.taint.request_traversal]
        ''')

    def test_disabled_rule_does_not_read_source_and_invalid_source_fails(self):
        ctx = RunContext(lang='csharp', files=[Path('/absent.cs')], profile={'disabled_rules': [redirect.RULE]})
        self.assertEqual(list(redirect.run(ctx)), [])
        with self.assertRaises(ValueError):
            self.scan('var target=Request.Query["x]; Response.Redirect(target);')

    def test_absolute_https_exact_host_guard_validates_only_parsed_uri(self):
        prefix = 'var raw=Request.Query["x"]; if(!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps||uri.Host!="app.example.com") return; '
        self.check(prefix + 'Response.Redirect(uri.ToString());', 0)
        self.check(prefix + 'Response.Redirect(raw);')
        self.check(prefix + 'uri = new Uri(Request.Query["other"]); Response.Redirect(uri.ToString());')

    def test_allowlist_requires_same_uri_exact_host_and_rejecting_branch(self):
        for guard in (
            '!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps||uri.Host!=Request.Query["host"]',
            '!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps||!uri.Host.EndsWith("example.com")',
            '!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||other.Scheme!=Uri.UriSchemeHttps||uri.Host!="app.example.com"',
            '!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps||other.Host!="app.example.com"',
        ):
            with self.subTest(guard=guard):
                self.check('var raw=Request.Query["x"]; if (' + guard + ') return; Response.Redirect(uri.ToString());')
        self.check('var raw=Request.Query["x"]; if(!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps||uri.Host!="app.example.com") Log(raw); Response.Redirect(uri.ToString());')

    def test_private_constant_host_set_is_not_trusted_after_mutation_or_escape(self):
        template = '''
            class C {
                private static readonly HashSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase) { "app.example.com", "login.example.com" };
                string Validate(string raw) {
                    if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
                        uri.Scheme != Uri.UriSchemeHttps || !Hosts.Contains(uri.Host)) throw new Exception();
                    return uri.ToString();
                }
                void H() { MUTATE; Response.Redirect(Validate(Request.Query["x"])); }
            }
        '''
        self.check(template.replace('MUTATE', 'Log("safe")'), 0)
        for mutation in ('Hosts.Add(Request.Query["host"])', 'External.Change(Hosts)', 'var alias=Hosts'):
            with self.subTest(mutation=mutation):
                self.check(template.replace('MUTATE', mutation))
        # A collection initializer does not imply BCL HashSet semantics.
        shadow = '''class HashSet<T> : List<T> {
            public HashSet(IEqualityComparer<T> comparer) { }
            public new bool Contains(T item) => true;
        }\n'''
        self.check(shadow + template.replace('MUTATE', 'Log("safe")'))
        self.check('using StringComparer = UnsafeComparer;\n' + template.replace('MUTATE', 'Log("safe")'))


class AnalysisBoundaryTests(unittest.TestCase):
    def test_actual_helper_evidence_survives_combined_json_and_sarif(self):
        import io
        from ubs_core.csharp_scan import run_analyzers
        from ubs_core.findings_merge import merge, to_sarif
        with tempfile.TemporaryDirectory(prefix='ubs-csharp-evidence-') as tmp:
            root = Path(tmp)
            source = root / 'app.cs'
            source.write_text('class C { void Read(string p) { File.Delete(p); } void H() { Read(Request.Query["p"]); } }')
            sink = io.StringIO()
            run_analyzers([source], sink, set(), root)
            (root / 'csharp.findings.json').write_text(sink.getvalue())
            combined = root / 'combined.json'
            combined.write_text(json.dumps({'status': 'ok', 'scanners': [{'language': 'csharp', 'files': 1}]}))
            merge(root, combined, project_dir=root)
            report = json.loads(combined.read_text())
            finding = next(f for f in report['findings'] if f['rule_id'] == RULE)
            evidence = finding['extras']['taint_path']
            self.assertIn('source', [step['kind'] for step in evidence])
            self.assertIn('call', [step['kind'] for step in evidence])
            sarif = to_sarif(report)
            result = next(f for run in sarif['runs'] for f in run['results'] if f['ruleId'] == RULE)
            locations = result['codeFlows'][0]['threadFlows'][0]['locations']
            self.assertEqual(len(locations), len(evidence))
            self.assertEqual(result['properties']['extras'], finding['extras'])
            for original, location in zip(evidence, locations):
                physical = location['location']['physicalLocation']
                self.assertEqual(physical['artifactLocation']['uri'], original['path'])
                self.assertEqual(physical['region']['startLine'], original['line'])
                self.assertEqual(physical['region']['startColumn'], original['col'])

    def test_invalid_evidence_coordinates_are_not_fabricated(self):
        from ubs_core.findings_merge import to_sarif
        finding = {'rule_id': RULE, 'file': 'a.cs', 'line': 1, 'severity': 'critical',
                   'extras': {'taint_path': [{'path': 'a.cs', 'line': True, 'col': 1, 'kind': 'source', 'label': 'bad'}]}}
        with self.assertRaisesRegex(ValueError, 'invalid evidence'):
            to_sarif({'language': 'csharp', 'findings': [finding]})

    def test_evidence_step_bound_is_explicit(self):
        from ubs_core.findings_merge import to_sarif
        finding = {'rule_id': RULE, 'file': 'a.cs', 'line': 1, 'severity': 'critical',
                   'extras': {'taint_path': [{} for _ in range(65)]}}
        with self.assertRaisesRegex(ValueError, 'at most 64'):
            to_sarif({'language': 'csharp', 'findings': [finding]})

    def test_provenance_survives_the_real_csharp_scan_sink(self):
        import io
        from ubs_core.csharp_scan import run_analyzers
        with tempfile.TemporaryDirectory(prefix='ubs-csharp-native-') as tmp:
            path = Path(tmp) / 'app.cs'
            path.write_text('class C { void Read(string p) { File.Delete(p); } void H() { Read(Request.Query["p"]); } }')
            sink = io.StringIO()
            run_analyzers([path], sink, set(), path.parent)
            findings = [json.loads(line) for line in sink.getvalue().splitlines()]
            records = [finding for finding in findings if finding['rule'] == RULE]
            self.assertEqual(len(records), 1, findings)
            self.assertIn('taint_path', records[0]['extras'])

    def test_failed_analysis_is_explicit_and_excluded_categories_do_not_run(self):
        import io
        from ubs_core.csharp_scan import run_analyzers
        with tempfile.TemporaryDirectory(prefix='ubs-csharp-native-') as tmp:
            path = Path(tmp) / 'app.cs'
            path.write_text('var p=Request.Query["p];')
            errors = []
            run_analyzers([path], io.StringIO(), set(), path.parent, errors=errors)
            self.assertTrue(any('taint_csharp_request' in error for error in errors), errors)
            errors = []
            run_analyzers([path], io.StringIO(), {8}, path.parent, errors=errors)
            self.assertFalse(any('taint_csharp_request' in error for error in errors), errors)
            self.assertFalse(any('taint_csharp_redirect' in error for error in errors), errors)

    def test_budget_is_not_reported_as_clean(self):
        flow = cs.CSharpFlow(Path('test.cs'), 'var p=Request.Query["p"]; File.Delete(p);')
        flow.budget = Budget(0)
        with self.assertRaises(AnalysisLimit):
            list(flow.analyze())

    def test_unterminated_string_and_unbalanced_input_are_not_clean(self):
        for code in ('var p=Request.Query["p];', 'void A( { Request.Query["p"];'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                cs.CSharpFlow(Path('test.cs'), code)

    def test_helpers_do_not_walk_unselected_sources(self):
        with tempfile.TemporaryDirectory(prefix='ubs-csharp-selection-') as tmp:
            root = Path(tmp)
            good, bad = root / 'good.cs', root / 'bad.cs'
            good.write_text('File.Delete("/fixed");')
            bad.write_text('File.Delete(Request.Query["p"]);')
            self.assertEqual(list(cs.run(RunContext(lang='csharp', files=[good]))), [])


class RedirectPublicReportTests(unittest.TestCase):
    def test_real_module_json_and_sarif_preserve_helper_evidence(self):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='csharp-redirect-e2e-', dir=artifacts))
        source = root / 'app.cs'
        source.write_text('''class C {
    void Send(string target) { Response.Redirect(target); }
    void Handler() { Send(Request.Query["next"]); }
}
''', encoding='utf-8')
        filelist = root / 'inputs'
        filelist.write_bytes(os.fsencode(source) + b'\0')
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', UBS_NO_CACHE='1',
                   UBS_NO_AUTO_UPDATE='1', NO_COLOR='1')
        evidence = None
        for phase in ('tainted', 'clean'):
            for format_name in ('json', 'sarif'):
                case = f'csharp-redirect-{phase}-{format_name}'
                started = time.monotonic()
                print(f'[{case}] RUN', flush=True)
                command = [str(ROOT / 'modules/ubs-csharp.sh'), '--ci', '--only=8',
                           '--no-dotnet', '--no-color', f'--format={format_name}',
                           '--files-from', str(filelist), str(root)]
                result = subprocess.run(command, cwd=root, env=env, capture_output=True,
                                        text=True, timeout=90)
                (root / f'{case}.stdout.json').write_text(result.stdout, encoding='utf-8')
                (root / f'{case}.stderr.log').write_text(result.stderr, encoding='utf-8')
                context = f'{command!r}\nexit={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}'
                expected = int(phase == 'tainted')
                self.assertEqual(result.returncode, expected, context)
                doc = json.loads(result.stdout)
                if format_name == 'json':
                    self.assertEqual(doc['status'], 'ok', context)
                    self.assertEqual(doc['critical'], expected, context)
                    records = [finding for finding in doc['findings'] if finding['rule'] == redirect.RULE]
                    self.assertEqual(len(records), expected, context)
                    if records:
                        self.assertEqual(records[0]['line'], 2, context)
                        evidence = records[0]['extras']['taint_path']
                        self.assertTrue({'source', 'call', 'sink'} <= {step['kind'] for step in evidence}, context)
                else:
                    records = [finding for run in doc['runs'] for finding in run.get('results', [])
                               if finding['ruleId'] == redirect.RULE]
                    self.assertEqual(len(records), expected, context)
                    if records:
                        self.assertEqual(records[0]['properties']['extras']['taint_path'], evidence, context)
                        flow = records[0]['codeFlows'][0]['threadFlows'][0]['locations']
                        self.assertEqual(len(flow), len(evidence), context)
                        self.assertEqual(records[0]['locations'][0]['physicalLocation']['region']['startLine'], 2, context)
                print(f'[{case}] PASS ({time.monotonic() - started:.3f}s)', flush=True)
            source.write_text('''class C {
    void Send(string target) { if (!Url.IsLocalUrl(target)) return; Response.Redirect(target); }
    void Handler() { Send(Request.Query["next"]); }
}
''', encoding='utf-8')


if __name__ == '__main__':
    unittest.main(verbosity=2)
