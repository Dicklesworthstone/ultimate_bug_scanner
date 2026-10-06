"""Production Rust redirect dataflow: unsafe flows paired with safe controls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.rust_detectors import open_redirect
from ubs_core.rust_detectors.redirect_flow import Origin, Source, join
from ubs_core.taint_flow import AnalysisLimit

RULE = 'rust.security.open-redirect'
SOURCE = 'params.get("next")'
LOCAL_GUARD = r'''target.starts_with('/') && !target.starts_with("//") && !target.contains('\\') && !target.chars().any(char::is_control)'''


class SourceCase(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.failures_before = len(result.failures) + len(result.errors)
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.failures) + len(result.errors) > self.failures_before
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic() - self.started:.3f}s)', flush=True)

    def scan(self, code):
        code = textwrap.dedent(code).lstrip('\n')
        with tempfile.TemporaryDirectory(prefix='ubs-rust-redirect-') as tmp:
            path = Path(tmp) / 'handler.rs'
            path.write_text(code, encoding='utf-8')
            return list(open_redirect.find([path]))

    def body(self, code):
        return self.scan('fn handler(params: Params, flag: bool) -> Redirect {\n' + textwrap.dedent(code) + '\n}')

    def count(self, code, expected=1):
        got = self.body(code)
        self.assertEqual(len(got), expected, (code, got))
        return got


class SourceTests(SourceCase):
    def test_direct_request_and_field_sources(self):
        for value in (SOURCE, 'query.next', 'payload.return_url', 'req.uri()',
                      'req.headers().get("x-redirect-url")', 'std::env::var("HTTP_HOST")'):
            with self.subTest(value=value):
                self.count(f'let target = {value}; Redirect::to(&target)')

    def test_no_file_wide_local_leak(self):
        self.assertEqual(self.scan(f'''
            fn read(params: Params) {{ let target = {SOURCE}; }}
            fn unused(target: &str) -> Redirect {{ Redirect::to(target) }}
        '''), [])

    def test_safe_reassignment_kills_taint(self):
        self.count(f'let mut target={SOURCE}; target="/safe"; Redirect::to(target)', 0)

    def test_later_assignment_does_not_taint_earlier_sink(self):
        self.count(f'let mut target="/safe"; Redirect::to(target); target={SOURCE};', 0)

    def test_semicolon_and_multiline_statement_boundaries(self):
        self.count('''
            let target = params
                .get("next"); let fixed = "/safe";
            Redirect::to(
                target
            );
            Redirect::to(fixed);
        ''')

    def test_assignment_with_type_and_lifetime(self):
        self.count(f"let target: &'static str = {SOURCE}; Redirect::to(target)")

    def test_branch_clean_write_cannot_erase_other_reaching_definition(self):
        self.count(f'let mut target={SOURCE}; if flag {{ target="/safe"; }} Redirect::to(target)')

    def test_both_branch_orders_join(self):
        for left, right in [(SOURCE, '"/safe"'), ('"/safe"', SOURCE)]:
            with self.subTest(left=left):
                self.count(f'let target; if flag {{ target={left}; }} else {{ target={right}; }} Redirect::to(target)')

    def test_both_branches_clean(self):
        self.count(f'let mut target={SOURCE}; if flag {{ target="/a"; }} else {{ target="/b"; }} Redirect::to(target)', 0)

    def test_if_expression_result(self):
        self.count(f'let target=if flag {{ {SOURCE} }} else {{ "/safe" }}; Redirect::to(target)')

    def test_else_if_branch_result(self):
        self.count(f'let target=if a {{ "/a" }} else if b {{ {SOURCE} }} else {{ "/b" }}; Redirect::to(target)')

    def test_early_return_excludes_dead_sink(self):
        self.count(f'let target={SOURCE}; return Redirect::to("/safe"); Redirect::to(target);', 0)

    def test_returning_branch_does_not_taint_continuation(self):
        self.count(f'let mut target="/safe"; if flag {{ target={SOURCE}; return Redirect::to("/safe"); }} Redirect::to(target)', 0)

    def test_unreachable_literal_branch_is_not_scanned(self):
        self.count(f'if false {{ Redirect::to({SOURCE}); }} Redirect::to("/safe")', 0)

    def test_nested_block_shadow_does_not_overwrite_outer_taint(self):
        self.count(f'let target={SOURCE}; {{ let target="/safe"; Redirect::to(target); }} Redirect::to(target)')

    def test_inner_taint_does_not_escape_shadow(self):
        self.count(f'let target="/safe"; {{ let target={SOURCE}; }} Redirect::to(target)', 0)

    def test_inner_assignment_to_outer_binding_escapes(self):
        self.count(f'let mut target="/safe"; {{ target={SOURCE}; }} Redirect::to(target)')

    def test_zero_iteration_loop_keeps_entry_taint(self):
        self.count(f'let mut target={SOURCE}; while flag {{ target="/safe"; }} Redirect::to(target)')

    def test_loop_backedge_reaches_earlier_sink(self):
        self.count(f'let mut target="/safe"; while flag {{ Redirect::to(target); target={SOURCE}; }}')

    def test_continue_state_reaches_next_iteration(self):
        self.count(f'let mut target="/safe"; while flag {{ Redirect::to(target); target={SOURCE}; continue; target="/safe"; }}')

    def test_break_value_carries_loop_expression_result(self):
        self.count(f'let target=loop {{ break {SOURCE}; }}; Redirect::to(target)')

    def test_break_state_reaches_after_loop(self):
        self.count(f'let mut target="/safe"; loop {{ target={SOURCE}; break; }} Redirect::to(target)')

    def test_infinite_loop_does_not_reach_following_sink(self):
        self.count(f'let target={SOURCE}; loop {{ }} Redirect::to(target)', 0)

    def test_local_guard_must_reject_network_paths(self):
        self.count(f'let target={SOURCE}; if target.starts_with("/") {{ Redirect::to(target); }}')

    def test_negated_local_guard_protects_only_valid_continuation(self):
        self.count(f'''let target={SOURCE}; if !({LOCAL_GUARD}) {{ return Err("blocked"); }} Redirect::to(target)''', 0)

    def test_old_local_guard_does_not_reject_browser_network_paths(self):
        self.count(f'''let target={SOURCE}; if !(target.starts_with('/') && !target.starts_with("//")) {{ return Err("blocked"); }} Redirect::to(target)''')

    def test_backslash_rejection_alone_does_not_reject_stripped_controls(self):
        guard = r'''target.starts_with('/') && !target.starts_with("//") && !target.contains('\\')'''
        self.count(f'let target={SOURCE}; if !({guard}) {{ return; }} Redirect::to(target);')

    def test_local_guard_explicitly_rejects_each_url_control(self):
        guard = r'''target.starts_with('/') && !target.starts_with("//") && !target.contains("\\") && !target.contains('\t') && !target.contains('\r') && !target.contains('\n')'''
        self.count(f'let target={SOURCE}; if !({guard}) {{ return; }} Redirect::to(target);', 0)

    def test_safe_local_helper_is_proven_from_body(self):
        guard = LOCAL_GUARD.replace('target', 'raw')
        self.count(f'''fn safe_redirect_url(raw: &str) -> &str {{ if {guard} {{ raw }} else {{ "/" }} }}
            let target=safe_redirect_url({SOURCE}); Redirect::to(target);''', 0)

    def test_reversed_local_guard_operands(self):
        guard = r'''!target.chars().any(char::is_control) && !target.contains('\\') && !target.starts_with("//") && target.starts_with('/')'''
        self.count(f'''let target={SOURCE}; if {guard} {{ Redirect::to(target); }}''', 0)

    def test_guard_does_not_protect_sibling_or_post_join_path(self):
        self.count(f'''let target={SOURCE}; if {LOCAL_GUARD} {{ }} Redirect::to(target)''')

    def test_logging_rejection_does_not_validate(self):
        self.count(f'''let target={SOURCE}; if !({LOCAL_GUARD}) {{ log("invalid"); }} Redirect::to(target)''')

    def test_unrelated_value_validation_cannot_suppress(self):
        self.count(f'let target={SOURCE}; if !is_allowed_redirect_host(&other) {{ return Err("blocked"); }} Redirect::to(target)')

    def test_named_external_predicate_is_not_validation_evidence(self):
        for helper in ('is_allowed_redirect_host', 'is_local_redirect', 'isLocalRedirect'):
            with self.subTest(helper=helper):
                self.count(f'let target={SOURCE}; if !{helper}(&target) {{ return Err("blocked"); }} Redirect::to(target)')

    def test_url_validation_requires_the_original_parsed_value(self):
        checks = '''let hosts=["example.com"];
            if parsed.scheme() != "https" { return; }
            if !hosts.contains(&parsed.host_str().unwrap_or_default()) { return; }
            Redirect::to(target);'''
        for expression, expected in (
            ('Url::parse(target)?', 0),
            ('Url::parse(target).map_err(|_| "invalid")?', 0),
            ('Url::parse(target).expect("valid")', 0),
            ('Url::parse(other)?', 1),
            ('Url::parse(target).unwrap_or_else(|_| Url::parse("https://example.com").unwrap())', 1),
            ('Url::parse(target).unwrap().join("https://example.com").unwrap()', 1),
            ('Url::parse(target).map_err(|_| "invalid")?.join("https://example.com").unwrap()', 1),
        ):
            with self.subTest(expression=expression):
                self.count(f'let target={SOURCE}; let parsed={expression}; {checks}', expected)

    def test_reassignment_breaks_parsed_value_authority(self):
        self.count(f'''let mut target={SOURCE}; let parsed=Url::parse(target)?;
            target={SOURCE}; let hosts=["example.com"];
            if parsed.scheme() != "https" {{ return; }}
            if !hosts.contains(&parsed.host_str().unwrap_or_default()) {{ return; }}
            Redirect::to(target);''')

    def test_reassignment_revokes_validation(self):
        self.count(f'let mut target={SOURCE}; if !({LOCAL_GUARD}) {{ return Err("blocked"); }} target={SOURCE}; Redirect::to(target)')

    def test_local_predicate_name_is_not_authority(self):
        got = self.scan(f'''
            fn is_allowed_redirect_host(target: &str) -> bool {{ true }}
            fn handler(params: Params) {{
                let target={SOURCE};
                if !is_allowed_redirect_host(&target) {{ return; }}
                Redirect::to(target);
            }}
        ''')
        self.assertEqual(len(got), 1, got)

    def test_external_safe_helper_name_cannot_clean_its_result(self):
        self.count(f'let raw={SOURCE}; let target=safe_redirect_url(raw); Redirect::to(target)')
        self.count(f'let raw={SOURCE}; safe_redirect_url(raw); Redirect::to(raw)')

    def test_sanitized_sibling_cannot_hide_raw_operand(self):
        self.count(f'let raw={SOURCE}; Redirect::to(format!("{{}}{{}}", safe_redirect_url(raw), raw))')

    def test_sanitizer_spelling_in_literal_or_comment_is_inert(self):
        self.count(f'let target={SOURCE}; let comment="safe_redirect_url(target)"; Redirect::to(target)')
        self.count(f'let target={SOURCE}; /* safe_redirect_url(target) */ Redirect::to(target)')

    def test_comments_raw_strings_and_lifetimes_do_not_create_scopes(self):
        self.count(f'''let target={SOURCE}; let example=r###"fn bad() {{ Redirect::to(target) }}"###;
            /* {{ /* fn nested() {{ */ }} */
            Redirect::to(target)
        ''')

    def test_inert_source_and_sink_text_never_become_findings(self):
        self.count('let sample=r#"params.get("next"); Redirect::to(target)"#;', 0)

    def test_tainted_name_inside_literal_is_not_a_reference(self):
        self.count(f'let target={SOURCE}; Redirect::to("/target")', 0)

    def test_format_implicit_capture(self):
        self.count(f'let target={SOURCE}; Redirect::to(&format!("{{target}}"))')
        self.count(f'let target={SOURCE}; Redirect::to(&format!("{{{{target}}}}"))', 0)

    def test_header_value_is_the_sink_not_arbitrary_arguments(self):
        self.count(f'let target={SOURCE}; response.header("Location", target)')
        self.count(f'let target={SOURCE}; response.header("X-Trace", target)', 0)
        self.count(f'let target={SOURCE}; response.header(target, "Location")', 0)

    def test_tuple_header_and_constant_name(self):
        self.count(f'let target={SOURCE}; response.insert_header(("Location", target))')
        self.count(f'let target={SOURCE}; headers.insert(http::header::LOCATION, target)')

    def test_non_header_insert_and_bare_temporary_are_not_sinks(self):
        self.count(f'let target={SOURCE}; cache.insert(LOCATION, target); temporary(target); Redirect::to("/safe")', 0)

    def test_suppressing_source_line_does_not_erase_dataflow(self):
        self.count(f'let target={SOURCE}; // ubs:ignore\nRedirect::to(target)')

    def test_rule_specific_suppression_and_unrelated_marker(self):
        self.count(f'let target={SOURCE};\nRedirect::to(target); // ubs:ignore[{RULE}]', 0)
        self.count(f'let target={SOURCE};\nRedirect::to(target); // ubs:ignore[rust.other]')

    def test_standalone_suppression_on_multiline_sink(self):
        self.count(f'let target={SOURCE};\n// ubs:ignore[{RULE}]\nRedirect::to(\n target\n);', 0)

    def test_existing_fixtures(self):
        clean = list(open_redirect.find([ROOT / 'test-suite/rust/clean/open_redirect.rs']))
        buggy = list(open_redirect.find([ROOT / 'test-suite/rust/buggy/open_redirect.rs']))
        self.assertEqual(clean, [])
        self.assertEqual([row[1] for row in buggy], [56, 65, 74, 79, 84])
        self.assertTrue(all('\n' not in row[3] for row in buggy), buggy)


class SummaryTests(SourceCase):
    def test_forward_and_backward_helper_definitions(self):
        helper = 'fn dispatch(target: &str) -> Redirect { Redirect::to(target) }\n'
        caller = f'fn handler(params: Params) -> Redirect {{ dispatch({SOURCE}) }}\n'
        for code in (helper + caller, caller + helper):
            with self.subTest(code=code):
                got = self.scan(code)
                self.assertEqual(len(got), 1, got)
                self.assertIn('dispatch', got[0][3])
                self.assertIn('params.get("next") -> redirect', got[0][3])

    def test_helper_constant_argument_is_clean(self):
        self.assertEqual(self.scan(f'''
            fn dispatch(target: &str) -> Redirect {{ Redirect::to(target) }}
            fn handler(params: Params) {{ let raw={SOURCE}; dispatch("/safe"); }}
        '''), [])

    def test_local_constant_return_is_not_opaque_argument_echo(self):
        self.count(f'fn fixed(raw: &str) -> &str {{ "/safe" }} let raw={SOURCE}; Redirect::to(fixed(raw))', 0)

    def test_local_passthrough_and_source_return(self):
        self.count(f'fn identity(raw: &str) -> &str {{ raw }} Redirect::to(identity({SOURCE}))')
        self.count(f'fn read(params: Params) -> &str {{ {SOURCE} }} Redirect::to(read(params))')

    def test_explicit_and_conditional_returns(self):
        self.count(f'fn choose(raw: &str, flag: bool) -> &str {{ if flag {{ return raw; }} "/safe" }} Redirect::to(choose({SOURCE}, flag))')

    def test_argument_positions_are_not_interchangeable(self):
        self.count(f'fn first(a: &str, b: &str) -> &str {{ a }} Redirect::to(first("/safe", {SOURCE}))', 0)
        self.count(f'fn first(a: &str, b: &str) -> &str {{ a }} Redirect::to(first({SOURCE}, "/safe"))')

    def test_generic_and_destructured_parameters(self):
        self.count(f"fn first<'a, T>(a: &'a str, _: Vec<T>) -> &'a str {{ a }} Redirect::to(first({SOURCE}, vec![]))")
        self.count(f'fn first((a, b): (&str, &str)) -> &str {{ a }} Redirect::to(first(({SOURCE}, "/safe")))')

    def test_call_chain_and_recursive_summary_converge(self):
        got = self.scan(f'''
            fn a(value: &str, flag: bool) -> &str {{ if flag {{ b(value, false) }} else {{ value }} }}
            fn b(value: &str, flag: bool) -> &str {{ a(value, flag) }}
            fn dispatch(value: &str) -> Redirect {{ Redirect::to(b(value, true)) }}
            fn handler(params: Params) -> Redirect {{ dispatch({SOURCE}) }}
        ''')
        self.assertEqual(len(got), 1, got)

    def test_recursive_constant_control(self):
        self.count(f'fn recur(value: &str, flag: bool) -> &str {{ if flag {{ recur(value, false) }} else {{ "/safe" }} }} Redirect::to(recur({SOURCE}, flag))', 0)

    def test_sink_summary_is_at_helper_location_and_deduplicated(self):
        got = self.scan(f'''
            fn dispatch(target: &str) -> Redirect {{
                Redirect::to(target)
            }}
            fn handler(params: Params) {{
                dispatch({SOURCE});
                dispatch({SOURCE});
            }}
        ''')
        self.assertEqual([row[1] for row in got], [2], got)

    def test_local_sanitizer_spelling_does_not_override_unsafe_body(self):
        self.count(f'fn safe_redirect_url(raw: &str) -> &str {{ raw }} Redirect::to(safe_redirect_url({SOURCE}))')

    def test_local_redirect_spelling_does_not_override_safe_body(self):
        self.count(f'fn redirect(raw: &str) -> Redirect {{ Redirect::to("/safe") }} redirect({SOURCE});', 0)

    def test_nested_function_is_not_a_closure(self):
        self.count(f'let target={SOURCE}; fn unused() {{ Redirect::to(target); }}', 0)

    def test_same_named_module_functions_are_not_mixed(self):
        got = self.scan(f'''
            mod first {{ fn dispatch(x: &str) -> Redirect {{ Redirect::to(x) }} }}
            mod second {{
                fn dispatch(x: &str) -> &str {{ "/safe" }}
                fn handler(params: Params) {{ Redirect::to(dispatch({SOURCE})); }}
            }}
        ''')
        self.assertEqual(got, [])

    def test_same_named_impl_methods_are_not_free_function_summaries(self):
        self.count(f'impl Example {{ fn dispatch(x: &str) {{ Redirect::to(x); }} }} dispatch({SOURCE});', 0)

    def test_opaque_external_call_keeps_return_taint(self):
        self.count(f'Redirect::to(external::transform({SOURCE}))')

    def test_nonreturning_helper_prevents_unreachable_sink(self):
        self.count(f'fn stop() {{ panic!("stopped"); }} let target={SOURCE}; stop(); Redirect::to(target);', 0)

    def test_unused_closure_is_not_executed(self):
        self.count(f'let target={SOURCE}; let callback=|| {{ Redirect::to(target) }};', 0)

    def test_lattice_laws(self):
        a = frozenset({Origin('source', 1, 'one')})
        b = frozenset({Origin('parameter', 0)})
        c = frozenset({Origin('source', 2, 'two')})
        self.assertEqual(join(a, a), a)
        self.assertEqual(join(a, b), join(b, a))
        self.assertEqual(join(join(a, b), c), join(a, join(b, c)))

    def test_discarded_block_and_branch_are_not_function_returns(self):
        for body in ('{ raw };', 'if flag { raw } else { raw };'):
            with self.subTest(body=body):
                self.count(f'fn unit(raw: &str, flag: bool) {{ {body} }} Redirect::to(unit({SOURCE}, flag))', 0)

    def test_comment_between_source_receiver_and_method(self):
        self.count('Redirect::to(params /* request collection */ .get("next"))')

    def test_multiline_location_header_is_not_discarded_by_prefilter(self):
        self.count(f'let target={SOURCE};\nresponse.header(\n"Location",\ntarget\n)')

    def test_delimiter_and_budget_failures_are_not_clean_results(self):
        with self.assertRaisesRegex(AnalysisLimit, 'incomplete'):
            Source(f'fn f() {{ Redirect::to({SOURCE}); }}', max_steps=0).solve()
        for code in ('fn f() { (] }', 'fn f() {', '}', '(' * 129 + ')' * 129):
            with self.subTest(code=code), self.assertRaises((ValueError, AnalysisLimit)):
                Source(code).solve()

    def test_work_budget_is_shared_across_summary_and_loop_iterations(self):
        code = f'fn f(params: Params, flag: bool) {{ let mut x="/"; while flag {{ Redirect::to(x); x={SOURCE}; }} }}'
        with self.assertRaises(AnalysisLimit):
            Source(code, max_steps=25).solve()
        self.assertEqual(len(Source(code).solve()), 1)

    def test_registry_and_production_share_flow_and_rule_scoped_suppression(self):
        from ubs_core.analyzers import taint_rust
        from ubs_core.registry import RunContext
        with tempfile.TemporaryDirectory(prefix='ubs-rust-registry-') as tmp:
            path = Path(tmp) / 'handler.rs'
            path.write_text(f'fn dispatch(x: &str) {{ Redirect::to(x); }}\nfn handler() {{ dispatch({SOURCE}); }}\n', encoding='utf-8')
            records = list(taint_rust.run(RunContext(lang='rust', files=[path])))
            self.assertEqual([r['line'] for r in records], [1], records)
            self.assertEqual(records[0]['rule'], 'rust.taint.open_redirect')
            path.write_text(f'fn handler() {{\nRedirect::to({SOURCE}); // ubs:ignore[rust.taint.open_redirect]\n}}\n', encoding='utf-8')
            self.assertEqual(list(taint_rust.run(RunContext(lang='rust', files=[path]))), [])
            self.assertEqual(len(list(open_redirect.find([path]))), 1)

    def test_unreadable_selected_file_is_an_error(self):
        with tempfile.TemporaryDirectory(prefix='ubs-rust-missing-') as tmp:
            with self.assertRaisesRegex(OSError, 'Cannot read Rust redirect input'):
                list(open_redirect.find([Path(tmp) / 'missing.rs']))

    def test_completed_file_findings_survive_a_later_file_error(self):
        with tempfile.TemporaryDirectory(prefix='ubs-rust-partial-files-') as tmp:
            path = Path(tmp) / 'unsafe.rs'
            path.write_text(f'fn handler() {{ Redirect::to({SOURCE}); }}\n', encoding='utf-8')
            findings = open_redirect.find([path, Path(tmp) / 'missing.rs'])
            self.assertEqual(next(findings)[:3], (path, 1, 1))
            with self.assertRaisesRegex(OSError, 'Cannot read Rust redirect input'):
                next(findings)


class QualifiedHelperTests(SourceCase):
    def test_module_helper_summary_preserves_sink_and_source_locations(self):
        helper = 'mod handlers {\n pub fn send(target: &str) {\n  Redirect::to(target);\n }\n}\n'
        caller = f'fn handler(params: Params) {{ handlers::send({SOURCE}); handlers::send("/"); }}\n'
        for code in (helper + caller, caller + helper):
            with self.subTest(code=code):
                got = self.scan(code)
                site = code.index('Redirect::to')
                self.assertEqual([row[1] for row in got], [code[:site].count('\n') + 1], got)
                self.assertIn('Redirect::to(target)', got[0][3])
                self.assertIn('params.get("next") -> redirect', got[0][3])
                self.assertEqual(Source(code).solve(), {
                    site: frozenset({Origin('source', code.index(SOURCE), SOURCE)})})

    def test_module_constant_return_and_passthrough_are_distinct(self):
        for returned, expected in (('"/safe"', 0), ('raw', 1)):
            with self.subTest(returned=returned):
                self.count(f'mod helpers {{pub fn target(raw: &str) -> &str {{{returned}}}}} '
                           f'Redirect::to(helpers::target({SOURCE}));', expected)

    def test_module_helper_can_prove_a_guarded_return(self):
        guard = LOCAL_GUARD.replace('target', 'raw')
        self.count(f'mod helpers {{pub fn target(raw: &str) -> &str {{'
                   f'if {guard} {{raw}} else {{"/"}}}}}} '
                   f'Redirect::to(helpers::target({SOURCE}));', 0)

    def test_associated_helpers_and_self_across_separate_impls(self):
        definitions = 'struct Handler {}\nimpl Handler {fn send(x: &str) {Redirect::to(x);}}\n'
        for call in (f'fn handler(params: Params) {{Handler::send({SOURCE});}}',
                     f'impl Handler {{fn handler(params: Params) {{Self::send({SOURCE});}}}}'):
            for code in (definitions + call, call + definitions):
                with self.subTest(code=code):
                    self.assertEqual(len(self.scan(code)), 1)

    def test_associated_constant_return_and_passthrough_are_distinct(self):
        for returned, expected in (('"/safe"', 0), ('raw', 1)):
            with self.subTest(returned=returned):
                self.count(f'struct Handler {{}} impl Handler {{fn target(raw: &str) -> &str {{{returned}}}}} '
                           f'Redirect::to(Handler::target({SOURCE}));', expected)

    def test_module_and_type_value_bindings_do_not_shadow_namespaces(self):
        self.count(f'mod handlers {{pub fn send(x: &str) {{Redirect::to(x);}}}} '
                   f'let handlers=8; handlers::send({SOURCE});')
        self.count(f'struct Handler {{}} impl Handler {{fn send(x: &str) {{Redirect::to(x);}}}} '
                   f'let Handler=7; Handler::send({SOURCE});')

    def test_sibling_modules_and_same_named_types_never_mix(self):
        for selected, expected in (('safe', 0), ('unsafe_handlers', 1)):
            code = f'''mod safe {{
                pub struct Handler {{}}
                impl Handler {{pub fn send(x: &str) {{Redirect::to("/");}}}}
            }}
            mod unsafe_handlers {{
                pub struct Handler {{}}
                impl Handler {{pub fn send(x: &str) {{Redirect::to(x);}}}}
            }}
            fn handler(params: Params) {{{selected}::Handler::send({SOURCE});}}'''
            with self.subTest(selected=selected):
                got = self.scan(code)
                self.assertEqual(len(got), expected, got)
                if expected:
                    self.assertEqual(got[0][1], 7)

    def test_module_qualification_does_not_fall_back_to_a_free_namesake(self):
        self.count(f'fn send(x: &str) {{Redirect::to(x);}} external::send({SOURCE});', 0)
        self.count(f'mod empty {{}} fn send(x: &str) {{Redirect::to(x);}} empty::send({SOURCE});', 0)
        self.count(f'fn fixed(x: &str) -> &str {{"/"}} Redirect::to(external::fixed({SOURCE}));')

    def test_self_qualification_ignores_block_local_function_names(self):
        for module_value, local_value, expected in (('x', '"/"', 1), ('"/"', 'x', 0)):
            with self.subTest(module_value=module_value):
                got = self.scan(f'''fn send(x: &str) {{Redirect::to({module_value});}}
                    fn handler(params: Params) {{
                        fn send(x: &str) {{Redirect::to({local_value});}}
                        self::send({SOURCE});
                    }}''')
                self.assertEqual(len(got), expected, got)

    def test_self_and_super_follow_inline_module_ancestry(self):
        got = self.scan(f'''mod outer {{
            fn send(x: &str) {{Redirect::to(x);}}
            mod middle {{mod inner {{
                fn handler(params: Params) {{{{super::super::send({SOURCE});}}}}
            }}}}
            fn local(params: Params) {{self::send({SOURCE});}}
        }}''')
        self.assertEqual([row[1] for row in got], [2], got)

    def test_crate_and_extern_roots_are_not_inferred_from_a_selected_file(self):
        for path in ('crate::helpers', '::helpers', 'super::helpers'):
            with self.subTest(path=path):
                self.count(f'mod helpers {{pub fn fixed(x: &str) -> &str {{"/"}}}} '
                           f'Redirect::to({path}::fixed({SOURCE}));')

    def test_opaque_path_arguments_still_execute_known_sinks(self):
        for path in ('external::dispatch', 'crate::dispatch', '::dispatch',
                     'external::Type::<u8, u16>::dispatch'):
            with self.subTest(path=path):
                self.count(f'{path}(Redirect::to({SOURCE}));')

    def test_block_local_module_shadows_only_its_lexical_region(self):
        code = f'''mod helpers {{pub fn target(x: &str) -> &str {{x}}}}
            fn handler(params: Params) {{
                {{mod helpers {{pub fn target(x: &str) -> &str {{"/"}}}}
                    Redirect::to(helpers::target({SOURCE}));}}
                Redirect::to(helpers::target({SOURCE}));
            }}'''
        got = self.scan(code)
        self.assertEqual([row[1] for row in got], [5], got)

    def test_imported_modules_and_type_aliases_are_opaque_even_after_the_call(self):
        for declaration, prefix in (('use external::helpers;', 'helpers'),
                                    ('use external::{nested::{self as helpers}};', 'helpers'),
                                    ('use external::Handler;', 'Handler'),
                                    ('type Handler = external::Other;', 'Handler')):
            code = f'''mod helpers {{pub fn fixed(x: &str) -> &str {{"/"}}}}
                struct Handler {{}}
                impl Handler {{fn fixed(x: &str) -> &str {{"/"}}}}
                fn handler(params: Params) {{
                    Redirect::to({prefix}::fixed({SOURCE}));
                    {declaration}
                }}'''
            with self.subTest(declaration=declaration):
                self.assertEqual(len(self.scan(code)), 1)

    def test_grouped_and_glob_imports_block_outer_free_helpers(self):
        for declaration in ('use external::fixed;', 'use external::{nested::{fixed}};',
                            'use external::{nested::*};'):
            with self.subTest(declaration=declaration):
                got = self.scan(f'''fn fixed(x: &str) -> &str {{"/"}}
                    fn handler(params: Params) {{Redirect::to(fixed({SOURCE})); {declaration}}}''')
                self.assertEqual(len(got), 1, got)

    def test_glob_imports_do_not_hide_explicit_local_declarations(self):
        self.count(f'use external::*; mod helpers {{pub fn fixed(x: &str) -> &str {{"/"}}}} '
                   f'Redirect::to(helpers::fixed({SOURCE}));', 0)

    def test_generic_type_parameters_shadow_nominal_types(self):
        got = self.scan(f'''struct Handler {{}}
            impl Handler {{fn fixed(x: &str) -> &str {{"/"}}}}
            fn handler<Handler: ExternalTrait>(params: Params) {{
                Redirect::to(Handler::fixed({SOURCE}));
            }}''')
        self.assertEqual(len(got), 1, got)

    def test_const_parameters_and_lifetimes_do_not_shadow_nominal_types(self):
        for generics in ('const Handler: usize', "'Handler"):
            with self.subTest(generics=generics):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{fn send(x: &str) {{Redirect::to(x);}}}}
                    fn handler<{generics}>(params: Params) {{Handler::send({SOURCE});}}''')
                self.assertEqual(len(got), 1, got)

    def test_generic_owner_and_ufcs_paths_never_rebind_the_trailing_leaf(self):
        for path in ('external::Type::<u8>::fixed', 'external::Type :: <u8> :: fixed',
                     '<Type as Trait>::fixed', '<Type<u8> as Trait>::fixed',
                     'external::Type::<Vec<u8>>::fixed::<u16>',
                     'external::Type::<u8, u16>::fixed',
                     'external::Type::<Result<u8, E>>::fixed',
                     'external::Type::<fn() -> Result<u8, E>>::fixed',
                     '<Type<u8, u16> as Trait>::fixed'):
            with self.subTest(path=path):
                self.count(f'fn fixed(x: &str) -> &str {{"/"}} Redirect::to({path}({SOURCE}));')
                self.count(f'fn fixed(x: &str) {{Redirect::to(x);}} {path}({SOURCE});', 0)

    def test_generic_arguments_on_a_known_function_preserve_its_summary(self):
        for returned, expected in (('x', 1), ('"/"', 0)):
            for arguments in ('::<u8>', ':: <u8>', '::/*comment*/<u8>', '::<Result<u8, E>>'):
                with self.subTest(returned=returned, arguments=arguments):
                    self.count(f'mod helpers {{pub fn target<T>(x: &str) -> &str {{{returned}}}}} '
                               f'Redirect::to(helpers::target{arguments}({SOURCE}));', expected)

    def test_comparison_operators_do_not_merge_call_arguments(self):
        self.count(f'fn choose(flag: bool, x: &str) -> &str {{x}} '
                   f'Redirect::to(choose(flag < 3, {SOURCE}));')
        self.count(f'fn choose(x: &str, flag: bool) -> &str {{x}} '
                   f'Redirect::to(choose({SOURCE}, flag > 3));')

    def test_unclosed_generic_lookahead_consumes_the_shared_work_budget(self):
        source = Source('<' + 'UnknownType ' * 100, max_steps=100)
        self.assertGreater(source.budget.remaining, 0)
        with self.assertRaisesRegex(AnalysisLimit, 'work limit.*incomplete'):
            source.path(0, len(source.code))

    def test_ambiguous_comparison_lookahead_is_bounded_without_timing(self):
        comparisons = ', '.join(['x < y'] * 250)
        code = f'fn handler(params: Params) {{let flags=[{comparisons}]; Redirect::to({SOURCE});}}'
        with self.assertRaisesRegex(AnalysisLimit, 'work limit.*incomplete'):
            Source(code, max_steps=20_000).solve()
        self.assertEqual(len(Source(code).solve()), 1)

    def test_small_comparisons_and_unambiguous_less_equal_remain_supported(self):
        for comparisons in ('x < y, y < z, x < z', ', '.join(['x <= y'] * 250)):
            with self.subTest(comparisons=comparisons):
                code = f'fn handler(params: Params) {{let flags=[{comparisons}]; Redirect::to({SOURCE});}}'
                self.assertEqual(len(Source(code, max_steps=20_000).solve()), 1)

    def test_trait_impl_methods_are_not_selected_as_inherent_methods(self):
        got = self.scan(f'''struct Handler {{}}
            trait External {{fn fixed(x: &str) -> &str;}}
            impl External for Handler {{fn fixed(x: &str) -> &str {{"/"}}}}
            fn handler(params: Params) {{Redirect::to(Handler::fixed({SOURCE}));}}''')
        self.assertEqual(len(got), 1, got)

    def test_inherent_method_is_not_confused_with_trait_namesake(self):
        got = self.scan(f'''struct Handler {{}}
            trait External {{fn send(x: &str);}}
            impl External for Handler {{fn send(x: &str) {{Redirect::to("/");}}}}
            impl Handler {{fn send(x: &str) {{Redirect::to(x);}}}}
            fn handler(params: Params) {{Handler::send({SOURCE});}}''')
        self.assertEqual([row[1] for row in got], [4], got)

    def test_ambiguous_associated_methods_and_specializations_are_opaque(self):
        for definitions, path in (
            ('struct Handler {} impl Handler {fn fixed(x: &str) -> &str {"/"}} '
             'impl Handler {fn fixed(x: &str) -> &str {x}}', 'Handler::fixed'),
            ('struct Handler<T> {value: T} impl Handler<u8> {fn fixed(x: &str) -> &str {"/"}}',
             'Handler::<u8>::fixed'),
        ):
            with self.subTest(definitions=definitions):
                self.count(definitions + f'Redirect::to({path}({SOURCE}));')

    def test_dynamic_method_dispatch_remains_opaque(self):
        self.count(f'fn fixed(x: &str) -> &str {{"/"}} Redirect::to(service.fixed({SOURCE}));')

    def test_impl_trait_function_signatures_are_not_type_boundaries(self):
        for parameter, returned in (('Params', 'impl IntoResponse'), ('impl RequestParams', 'Redirect'),
                                    ('impl RequestParams', 'impl IntoResponse')):
            with self.subTest(parameter=parameter, returned=returned):
                got = self.scan(f'''fn send(x: &str) {{Redirect::to(x);}}
                    fn handler(params: {parameter}) -> {returned} {{send({SOURCE});}}''')
                self.assertEqual(len(got), 1, got)

    def test_bare_helpers_in_impl_methods_resolve_in_the_enclosing_module(self):
        for header in ('impl Handler', 'impl External for Handler'):
            for free, associated, expected in (('x', '"/"', 1), ('"/"', 'x', 0)):
                with self.subTest(header=header, free=free):
                    got = self.scan(f'''fn send(x: &str) {{Redirect::to({free});}}
                        struct Handler {{}}
                        {header} {{
                            fn send(x: &str) {{Redirect::to({associated});}}
                            fn handler(params: Params) {{send({SOURCE});}}
                        }}''')
                    self.assertEqual(len(got), expected, got)

    def test_framework_static_sink_contract_survives_local_stand_ins(self):
        self.count(f'struct Redirect {{}} impl Redirect {{fn to(x: &str) -> Self {{Redirect {{}}}}}} '
                   f'Redirect::to({SOURCE});')

    def test_private_qualified_inherent_target_cannot_hide_a_visible_trait(self):
        for visibility, expected in (('', 1), ('pub ', 0), ('pub(crate) ', 1), ('pub(super) ', 1)):
            with self.subTest(visibility=visibility):
                code = f'''struct Handler {{}}
                    mod child {{impl super::Handler {{{visibility}fn target(&self, x: &'static str) -> &'static str {{"/safe"}}}}}}
                    trait Fallback {{fn target(&self, x: &'static str) -> &'static str;}}
                    impl Fallback for Handler {{fn target(&self, x: &'static str) -> &'static str {{x}}}}
                    fn handler(params: Params) {{
                        let receiver=Handler {{}}; Redirect::to(Handler::target(&receiver, {SOURCE}));
                    }}'''
                got = self.scan(code)
                self.assertEqual(len(got), expected, got)
                if expected:
                    self.assertEqual(got[0][1], 6)

    def test_private_qualified_methods_are_visible_to_descendant_modules(self):
        for returned, expected in (('"/"', 0), ('x', 1)):
            with self.subTest(returned=returned):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{fn target(&self, x: &'static str) -> &'static str {{{returned}}}}}
                    mod child {{fn handler(params: Params) {{
                        let receiver=super::Handler {{}};
                        Redirect::to(super::Handler::target(&receiver, {SOURCE}));
                    }}}}''')
                self.assertEqual(len(got), expected, got)

    def test_sibling_module_private_methods_remain_opaque_but_public_methods_resolve(self):
        for visibility, expected in (('', 1), ('pub ', 0)):
            with self.subTest(visibility=visibility):
                got = self.scan(f'''struct Handler {{}}
                    mod first {{impl super::Handler {{{visibility}fn target(&self, x: &'static str) -> &'static str {{"/"}}}}}}
                    trait Fallback {{fn target(&self, x: &'static str) -> &'static str;}}
                    impl Fallback for Handler {{fn target(&self, x: &'static str) -> &'static str {{x}}}}
                    mod second {{use super::Fallback; fn handler(params: Params) {{
                        let receiver=super::Handler {{}};
                        Redirect::to(super::Handler::target(&receiver, {SOURCE}));
                    }}}}''')
                self.assertEqual(len(got), expected, got)

    def test_unrelated_pub_tokens_do_not_export_a_private_method(self):
        for prefix in ('pub fn unrelated() {}', 'pub const ENABLED: bool = true;',
                       '#[doc = "pub"]', '// pub\n', 'pub(crate) fn unrelated() {}',
                       'const TEXT: &str = "pub";'):
            with self.subTest(prefix=prefix):
                got = self.scan(f'''struct Handler {{}}
                    mod child {{impl super::Handler {{
                        {prefix}
                        fn target(&self, x: &'static str) -> &'static str {{"/"}}
                    }}}}
                    trait Fallback {{fn target(&self, x: &'static str) -> &'static str;}}
                    impl Fallback for Handler {{fn target(&self, x: &'static str) -> &'static str {{x}}}}
                    fn handler(params: Params) {{Redirect::to(Handler::target(&Handler {{}}, {SOURCE}));}}''')
                self.assertEqual(len(got), 1, got)

    def test_visibility_modifier_lookbehind_consumes_the_shared_work_budget(self):
        code = 'pub' + ' ' * 1024 + 'fn helper() {}'
        with self.assertRaisesRegex(AnalysisLimit, 'work limit.*incomplete'):
            Source(code, max_steps=100)
        self.assertEqual(Source(code, max_steps=2000).solve(), {})


class ReceiverHelperTests(SourceCase):
    def test_direct_self_sink_requires_matching_receiver_forms(self):
        for caller, helper in (('&self', '&self'), ('&mut self', '&mut self'),
                               ('self', 'self'), ('mut self', 'self'), ('self', 'mut self')):
            with self.subTest(caller=caller, helper=helper):
                code = f'''struct Handler {{}}
                    impl Handler {{
                        fn send({helper}, target: &str) {{Redirect::to(target);}}
                        fn route({caller}, params: Params) {{self.send({SOURCE});}}
                    }}'''
                got = self.scan(code)
                self.assertEqual([row[1] for row in got], [3], got)
                self.assertIn('params.get("next") -> redirect', got[0][3])

    def test_self_constant_return_and_passthrough_are_distinct(self):
        for receiver in ('&self', '&mut self', 'self'):
            for returned, expected in (('"/"', 0), ('raw', 1)):
                with self.subTest(receiver=receiver, returned=returned):
                    got = self.scan(f'''struct Handler {{}}
                        impl Handler {{
                            fn target({receiver}, raw: &str) -> &str {{{returned}}}
                            fn route({receiver}, params: Params) {{Redirect::to(self.target({SOURCE}));}}
                        }}''')
                    self.assertEqual(len(got), expected, got)

    def test_implicit_self_does_not_shift_explicit_argument_positions(self):
        for first, second, expected in (('"/"', SOURCE, 0), (SOURCE, '"/"', 1)):
            with self.subTest(first=first):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{
                        fn first(&self, a: &str, b: &str) -> &str {{a}}
                        fn route(&self, params: Params) {{Redirect::to(self.first({first}, {second}));}}
                    }}''')
                self.assertEqual(len(got), expected, got)

    def test_receiver_fact_survives_a_known_method_return(self):
        code = f'''struct Handler {{target: String}}
            impl Handler {{
                fn target(&self) -> String {{self.target.clone()}}
                fn route(&self) {{Redirect::to(self.target());}}
            }}
            fn handler(params: Params) {{
                let receiver=Handler {{target: {SOURCE}}};
                Handler::route(&receiver);
            }}'''
        got = self.scan(code)
        self.assertEqual([row[1] for row in got], [4], got)

    def test_separate_impls_and_declaration_order_preserve_self_owner(self):
        helper = 'impl Handler {fn send(&self, x: &str) {Redirect::to(x);}}\n'
        route = f'impl Handler {{fn route(&self, params: Params) {{self.send({SOURCE});}}}}\n'
        for definitions in (helper + route, route + helper):
            with self.subTest(definitions=definitions):
                self.assertEqual(len(self.scan('struct Handler {}\n' + definitions)), 1)

    def test_unrelated_owners_with_the_same_method_name_never_mix(self):
        for selected, expected in (('Safe', 0), ('Unsafe', 1)):
            code = f'''struct Safe {{}}
                struct Unsafe {{}}
                impl Safe {{fn send(&self, x: &str) {{Redirect::to("/");}}}}
                impl Unsafe {{fn send(&self, x: &str) {{Redirect::to(x);}}}}
                impl {selected} {{fn route(&self, params: Params) {{self.send({SOURCE});}}}}'''
            with self.subTest(selected=selected):
                got = self.scan(code)
                self.assertEqual(len(got), expected, got)
                if expected:
                    self.assertEqual(got[0][1], 4)

    def test_matching_inherent_receiver_wins_over_trait_namesakes(self):
        for inherent, trait, expected in (('"/"', 'x', 0), ('x', '"/"', 1)):
            with self.subTest(inherent=inherent):
                got = self.scan(f'''struct Handler {{}}
                    trait External {{fn target(&self, x: &str) -> &str;}}
                    impl External for Handler {{fn target(&self, x: &str) -> &str {{{trait}}}}}
                    impl Handler {{
                        fn target(&self, x: &str) -> &str {{{inherent}}}
                        fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}
                    }}''')
                self.assertEqual(len(got), expected, got)

    def test_trait_for_reference_does_not_override_matching_inherent_receiver(self):
        got = self.scan(f'''struct Handler {{}}
            trait External {{fn target(self, x: &str) -> &str;}}
            impl External for &Handler {{fn target(self, x: &str) -> &str {{x}}}}
            impl Handler {{
                fn target(&self, x: &str) -> &str {{"/"}}
                fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}
            }}''')
        self.assertEqual(got, [])

    def test_mismatched_receiver_forms_may_select_a_trait_and_remain_opaque(self):
        # rustc selects the trait for these valid receiver-form mismatches.
        for caller, inherent in (('&self', '&mut self'), ('self', '&self'), ('&mut self', '&self')):
            with self.subTest(caller=caller, inherent=inherent):
                got = self.scan(f'''struct Handler {{}}
                    trait External {{fn target({caller}, x: &str) -> &str;}}
                    impl External for Handler {{fn target({caller}, x: &str) -> &str {{x}}}}
                    impl Handler {{
                        fn target({inherent}, x: &str) -> &str {{"/"}}
                        fn route({caller}, params: Params) {{Redirect::to(self.target({SOURCE}));}}
                    }}''')
                self.assertEqual(len(got), 1, got)

    def test_private_child_impl_does_not_override_visible_trait_dispatch(self):
        # The private inherent method is inaccessible from route's module;
        # rustc selects the visible trait method with the same receiver form.
        got = self.scan(f'''struct Handler {{}}
            mod helpers {{impl super::Handler {{fn target(&self, x: &'static str) -> &'static str {{"/"}}}}}}
            trait External {{fn target(&self, x: &'static str) -> &'static str;}}
            impl External for Handler {{fn target(&self, x: &'static str) -> &'static str {{x}}}}
            impl Handler {{fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}}}''')
        self.assertEqual(len(got), 1, got)

    def test_typed_receivers_remain_opaque(self):
        for caller, helper in (('self: &Self', '&self'), ('&self', 'self: &Self'),
                               ('self: Box<Self>', '&self')):
            with self.subTest(caller=caller, helper=helper):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{
                        fn target({helper}, x: &str) -> &str {{"/"}}
                        fn route({caller}, params: Params) {{Redirect::to(self.target({SOURCE}));}}
                    }}''')
                self.assertEqual(len(got), 1, got)

    def test_generic_methods_and_callers_remain_opaque(self):
        for helper, caller, call in (('<T>', '', 'self.target::<u8>'), ('', '<T>', 'self.target')):
            with self.subTest(helper=helper, caller=caller):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{
                        fn target{helper}(&self, x: &str) -> &str {{"/"}}
                        fn route{caller}(&self, params: Params) {{Redirect::to({call}({SOURCE}));}}
                    }}''')
                self.assertEqual(len(got), 1, got)

    def test_generic_impls_and_default_generic_types_remain_opaque(self):
        for declaration, implementation in (('struct Handler<T> {value: T}', 'impl<T> Handler<T>'),
                                             ('struct Handler<T=u8> {value: T}', 'impl Handler')):
            with self.subTest(declaration=declaration):
                got = self.scan(f'''{declaration}
                    {implementation} {{
                        fn target(&self, x: &str) -> &str {{"/"}}
                        fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}
                    }}''')
                self.assertEqual(len(got), 1, got)

    def test_self_in_a_trait_impl_remains_opaque(self):
        got = self.scan(f'''struct Handler {{}}
            impl Handler {{fn target(&self, x: &str) -> &str {{"/"}}}}
            trait External {{fn route(&self, params: Params);}}
            impl External for Handler {{fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}}}''')
        self.assertEqual(len(got), 1, got)

    def test_aliases_fields_chains_and_other_receivers_remain_opaque(self):
        for expression in ('other.target', 'alias.target', 'self.other.target', '(*self).target'):
            with self.subTest(expression=expression):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{
                        fn target(&self, x: &str) -> &str {{"/"}}
                        fn route(&self, other: External, params: Params) {{
                            let alias=self;
                            Redirect::to({expression}({SOURCE}));
                        }}
                    }}''')
                self.assertEqual(len(got), 1, got)

    def test_local_function_does_not_inherit_an_enclosing_receiver(self):
        got = self.scan(f'''struct Handler {{}}
            impl Handler {{
                fn target(&self, x: &str) -> &str {{"/"}}
                fn route(&self, params: Params) {{
                    fn inner(handler: &Handler, params: Params) {{Redirect::to(handler.target({SOURCE}));}}
                    inner(self, params);
                }}
            }}''')
        self.assertEqual([row[1] for row in got], [5], got)

    def test_local_header_method_body_wins_over_name_based_sink_catalog(self):
        for destination, expected in (('"/"', 0), ('target', 1)):
            with self.subTest(destination=destination):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{
                        fn header(&self, key: &str, target: &str) {{Redirect::to({destination});}}
                        fn route(&self, params: Params) {{self.header("Location", {SOURCE});}}
                    }}''')
                self.assertEqual(len(got), expected, got)
                if expected:
                    self.assertEqual(got[0][1], 3)

    def test_self_source_or_sink_spellings_do_not_override_a_known_body(self):
        for method in ('get', 'redirect'):
            with self.subTest(method=method):
                got = self.scan(f'''struct Handler {{}}
                    impl Handler {{
                        fn {method}(&self, raw: &str) -> &str {{"/"}}
                        fn route(&self, params: Params) {{Redirect::to(self.{method}({SOURCE}));}}
                    }}''')
                self.assertEqual(got, [])


class PatternFlowTests(SourceCase):
    def test_match_binding_reaches_sink(self):
        self.count(f'match {SOURCE} {{ Some(target) => Redirect::to(target), None => Redirect::to("/") }}')

    def test_match_clean_arms_do_not_return_subject_taint(self):
        self.count(f'let target=match {SOURCE} {{ Some(_) => "/one", None => "/two" }}; Redirect::to(target);', 0)

    def test_match_result_and_local_function_summary(self):
        self.count(f'fn choose(raw: &str) -> &str {{ match Some(raw) {{ Some(value) => value, None => "/" }} }} Redirect::to(choose({SOURCE}));')

    def test_match_arm_assignments_join_instead_of_overwriting(self):
        for arms in (f'true => {{ target={SOURCE}; }}, false => {{ target="/"; }}',
                     f'true => {{ target="/"; }}, false => {{ target={SOURCE}; }}'):
            with self.subTest(arms=arms):
                self.count(f'let mut target="/"; match flag {{ {arms} }} Redirect::to(target);')

    def test_match_all_arm_clean_writes_kill_entry_taint(self):
        self.count(f'let mut target={SOURCE}; match flag {{ true => {{target="/a";}}, false => {{target="/b";}} }} Redirect::to(target);', 0)

    def test_match_early_return_does_not_reach_continuation(self):
        self.count(f'let mut target="/"; match flag {{ true => {{target={SOURCE}; return;}}, false => {{}} }} Redirect::to(target);', 0)

    def test_match_divergent_expression_arms_are_function_exits(self):
        self.count(f'match flag {{ true => return Redirect::to({SOURCE}), false => return Redirect::to("/") }} Redirect::to({SOURCE});')

    def test_match_block_arms_allow_omitted_commas(self):
        self.count(f'match {SOURCE} {{ Some(target) => {{ Redirect::to(target); }} None => {{}} }}')

    def test_match_nested_expression_and_arm_results(self):
        self.count(f'let target=match flag {{ true => match {SOURCE} {{ Some(x) => x, None => "/" }}, false => "/" }}; Redirect::to(target);')

    def test_match_captures_are_scoped_and_shadow_outer_binding(self):
        self.count(f'let target={SOURCE}; match Some("/") {{ Some(target) => {{Redirect::to(target);}}, None => {{}} }} Redirect::to(target);')
        self.count(f'let target="/"; match {SOURCE} {{ Some(target) => {{}}, None => {{}} }} Redirect::to(target);', 0)

    def test_match_guard_checks_only_its_own_arm(self):
        self.count(f'match {SOURCE} {{ Some(target) if {LOCAL_GUARD} => Redirect::to(target), Some(other) => Redirect::to(other), None => Redirect::to("/") }}')

    def test_match_false_guard_does_not_execute_body(self):
        self.count(f'match {SOURCE} {{ Some(target) if false => Redirect::to(target), _ => Redirect::to("/") }}', 0)

    def test_match_guard_itself_can_contain_sink(self):
        self.count(f'match {SOURCE} {{ Some(target) if allow(Redirect::to(target)) => {{}}, _ => {{}} }}')

    def test_match_wildcard_prevents_unreachable_arms(self):
        self.count(f'match {SOURCE} {{ _ => "/", Some(target) => Redirect::to(target) }}', 0)

    def test_match_literal_patterns_do_not_create_sources(self):
        self.count('match "params.get(\\\"next\\\")" { "other" => Redirect::to("/"), _ => Redirect::to("/") }', 0)

    def test_match_or_and_struct_patterns_bind_values(self):
        for pattern in ('Some(target) | Other(target)', 'Payload { next: target, .. }',
                        'Payload { target, .. }', 'Some(ref target)', 'target @ Some(_)'):
            with self.subTest(pattern=pattern):
                self.count(f'match {SOURCE} {{ {pattern} => Redirect::to(target), _ => {{}} }}')

    def test_if_let_propagates_value_to_capture(self):
        self.count(f'if let Some(target) = {SOURCE} {{ Redirect::to(target); }}')

    def test_if_let_capture_does_not_leak_to_else_or_after(self):
        self.count(f'let target="/"; if let Some(target)={SOURCE} {{}} else {{Redirect::to(target);}} Redirect::to(target);', 0)

    def test_if_let_success_does_not_destroy_outer_binding(self):
        self.count(f'let target={SOURCE}; if let Some(target)=Some("/") {{Redirect::to(target);}} Redirect::to(target);')

    def test_if_let_expression_result(self):
        self.count(f'let target=if let Some(value)={SOURCE} {{value}} else {{"/"}}; Redirect::to(target);')

    def test_if_let_chain_shares_bindings_then_restores_them(self):
        self.count(f'if let Some(target)={SOURCE} && {LOCAL_GUARD} {{ Redirect::to(target); }}', 0)
        self.count(f'if let Some(first)={SOURCE} && let Some(target)=Some(first) {{Redirect::to(target);}}')

    def test_if_let_struct_pattern_is_not_mistaken_for_body(self):
        self.count(f'if let Payload {{next: target, ..}}={SOURCE} {{ Redirect::to(target); }}')

    def test_while_let_capture_is_loop_local(self):
        self.count(f'let target="/"; while let Some(target)={SOURCE} {{Redirect::to(target); break;}} Redirect::to(target);')

    def test_while_let_backedge_carries_taint_and_restores_capture(self):
        self.count(f'let mut next="/"; while let Some(target)=Some(next) {{Redirect::to(target); next={SOURCE};}}')

    def test_while_let_false_chain_does_not_execute_body(self):
        self.count(f'while let Some(target)={SOURCE} && false {{ Redirect::to(target); }}', 0)

    def test_match_break_and_continue_transfer_loop_state(self):
        self.count(f'let mut target="/"; loop {{match flag {{true => {{target={SOURCE}; break;}}, false => break}}}} Redirect::to(target);')
        self.count(f'let mut target="/"; while flag {{ Redirect::to(target); match flag {{true => {{target={SOURCE}; continue;}}, false => break}} }}')

    def test_match_break_expression_value(self):
        self.count(f'let target=loop {{match flag {{true => break {SOURCE}, false => break "/"}}}}; Redirect::to(target);')

    def test_let_else_success_binds_surviving_value(self):
        self.count(f'let Some(target)={SOURCE} else {{return;}}; Redirect::to(target);')

    def test_let_else_failure_uses_outer_binding(self):
        self.count(f'let target={SOURCE}; let Some(target)=Some("/") else {{Redirect::to(target); return;}}; Redirect::to(target);')

    def test_let_else_divergent_failure_does_not_kill_success(self):
        for diverge in ('return', 'panic!("missing")', 'loop {}'):
            with self.subTest(diverge=diverge):
                self.count(f'let Some(target)={SOURCE} else {{{diverge};}}; Redirect::to(target);')

    def test_let_else_failure_can_continue_loop(self):
        self.count(f'while flag {{let Some(target)={SOURCE} else {{continue;}}; Redirect::to(target);}}')

    def test_match_guard_let_bindings_reach_arm_not_next_arm(self):
        self.count(f'let target="/"; match flag {{true if let Some(target)={SOURCE} => Redirect::to(target), _ => Redirect::to(target)}}')

    def test_for_destructuring_binds_iterator_values(self):
        self.count(f'for (key, target) in {SOURCE} {{Redirect::to(target);}}')

    def test_binding_capitalization_is_not_a_sanitizer(self):
        self.count(f'let Target={SOURCE}; Redirect::to(Target);')
        self.count(f'if let Some(Target)={SOURCE} {{Redirect::to(Target);}}')
        self.count(f'fn dispatch(Target: &str) {{Redirect::to(Target);}} dispatch({SOURCE});')

    def test_match_none_result_is_not_a_capture(self):
        self.count(f'let target=match {SOURCE} {{Some(_) => None, None => None}}; Redirect::to(target);', 0)

    def test_match_arm_locations_and_clean_siblings_are_distinct(self):
        code = f'''fn handler(params: Params) {{
            let target="/";
            match {SOURCE} {{
                Some(target) if {LOCAL_GUARD} => {{
                    Redirect::to(target);
                }}
                Some(other) => {{
                    Redirect::to(other);
                }}
                None => {{
                    Redirect::to(target);
                }}
            }}
            Redirect::to(target);
        }}'''
        self.assertEqual([row[1] for row in self.scan(code)], [8])

    def test_if_let_failure_after_guard_restores_outer_capture(self):
        code = f'''fn handler(params: Params) {{
            let target="/";
            if let Some(target)={SOURCE} && flag {{
                Redirect::to(target);
            }} else {{
                Redirect::to(target);
            }}
            Redirect::to(target);
        }}'''
        self.assertEqual([row[1] for row in self.scan(code)], [4])

    def test_pattern_matching_retains_parameter_positions(self):
        code = 'fn pick(safe: &str, raw: &str) -> &str { match Some(safe) { Some(value) => value, None => "/" } }'
        self.count(code + f'Redirect::to(pick("/", {SOURCE}));', 0)
        self.count(code + f'Redirect::to(pick({SOURCE}, "/"));')

    def test_pattern_work_budget_fails_explicitly(self):
        code = f'fn handler() {{match {SOURCE} {{Some(target) => Redirect::to(target), _ => {{}}}}}}'
        with self.assertRaises(AnalysisLimit):
            Source(code, max_steps=35).solve()

    def test_pattern_summary_is_declaration_order_independent(self):
        source = f'fn source(params: Params) -> Option<String> {{{SOURCE}}}'
        consumer = 'fn consumer(value: Option<String>) {if let Some(target)=value {Redirect::to(target);}}'
        entry = 'fn handler(params: Params) {consumer(source(params));}'
        for definitions in ((source, consumer, entry), (entry, consumer, source), (consumer, entry, source)):
            with self.subTest(definitions=definitions):
                self.assertEqual(len(self.scan('\n'.join(definitions))), 1)

    def test_malformed_match_and_nondiverging_let_else_are_errors(self):
        for text in (f'match {SOURCE} {{Some(x) Redirect::to(x)}}',
                     f'let Some(target)={SOURCE} else {{log("missing");}}; Redirect::to(target);'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'incomplete'):
                self.scan(text)


@unittest.skipUnless(os.environ.get('UBS_RUST_REDIRECT_E2E') == '1', 'set UBS_RUST_REDIRECT_E2E=1 for real CLI scans')
class RealScannerTests(SourceCase):
    def test_json_sarif_and_selected_file_contract(self):
        artifact = ROOT / 'test-suite/artifacts/rust-redirect-dataflow'
        artifact.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ubs-rust-redirect-e2e-') as tmp:
            tmp = Path(tmp)
            project = tmp / 'project with spaces'
            project.mkdir()
            dangerous = project / 'unsafe.rs'
            dangerous.write_text(f'fn dispatch(x: &str) {{ Redirect::to(x); }}\nfn handler(params: Params) {{ dispatch({SOURCE}); }}\n', encoding='utf-8')
            safe = project / 'safe.rs'
            safe.write_text('fn handler() { Redirect::to("/safe"); }\n', encoding='utf-8')
            cases = [('unsafe', dangerous, True), ('safe', safe, False)]
            expected_lines = {'unsafe': 1}
            patterns = (
                ('match', f'match {SOURCE} {{Some(target) => Redirect::to(target), _ => Redirect::to("/")}}', True),
                ('if-let', f'if let Some(target)={SOURCE} {{Redirect::to(target);}}', True),
                ('let-else', f'let Some(target)={SOURCE} else {{return;}}; Redirect::to(target);', True),
                ('match-clean', f'let target=match {SOURCE} {{Some(_) => "/one", None => "/two"}}; Redirect::to(target);', False),
                ('local-guard-incomplete', f'let target={SOURCE}; if !(target.starts_with("/") && !target.starts_with("//")) {{return;}} Redirect::to(target);', True),
                ('local-guard-strong', f'let target={SOURCE}; if !({LOCAL_GUARD}) {{return;}} Redirect::to(target);', False),
                ('external-custom-predicate', f'let target={SOURCE}; if !is_local_redirect(target) {{return;}} Redirect::to(target);', True),
                ('external-safe-helper', f'Redirect::to(safe_redirect_url({SOURCE}));', True),
            )
            for name, body, expected in patterns:
                target = project / (name + '.rs')
                target.write_text('fn handler(params: Params) {\n' + body + '\n}\n', encoding='utf-8')
                cases.append((name, target, expected))
                if expected:
                    expected_lines[name] = 2
            qualified = (
                ('module-helper', 'mod helpers {\n pub fn send(x: &str) {\n  Redirect::to(x);\n }\n}\n'
                 f'fn handler(params: Params) {{helpers::send({SOURCE});}}', 3),
                ('module-constant', 'mod helpers {pub fn fixed(x: &str) -> &str {"/"}}\n'
                 f'fn handler(params: Params) {{Redirect::to(helpers::fixed({SOURCE}));}}', None),
                ('associated-helper', 'struct Handler {}\nimpl Handler {\n fn send(x: &str) {Redirect::to(x);}\n}\n'
                 f'fn handler(params: Params) {{Handler::send({SOURCE});}}', 3),
                ('self-helper', 'struct Handler {}\nimpl Handler {\n fn send(x: &str) {Redirect::to(x);}\n}\n'
                 f'impl Handler {{fn handler(params: Params) {{Self::send({SOURCE});}}}}', 3),
                ('module-collision-clean', 'mod first {pub fn send(x: &str) {Redirect::to(x);}}\n'
                 'mod second {pub fn send(x: &str) {Redirect::to("/");}}\n'
                 f'fn handler(params: Params) {{second::send({SOURCE});}}', None),
                ('import-after-call', 'mod helpers {pub fn fixed(x: &str) -> &str {"/"}}\n'
                 'fn handler(params: Params) {\n'
                 f' Redirect::to(helpers::fixed({SOURCE}));\n use external::helpers;\n}}', 3),
                ('type-alias-after-call', 'struct Handler {}\n'
                 'impl Handler {fn fixed(x: &str) -> &str {"/"}}\n'
                 'fn handler(params: Params) {\n'
                 f' Redirect::to(Handler::fixed({SOURCE}));\n type Handler = external::Other;\n}}', 4),
                ('generic-type-shadow', 'struct Handler {}\n'
                 'impl Handler {fn fixed(x: &str) -> &str {"/"}}\n'
                 'fn handler<Handler: ExternalTrait>(params: Params) {\n'
                 f' Redirect::to(Handler::fixed({SOURCE}));\n}}', 4),
                ('qualified-generic-opaque', 'fn fixed(x: &str) -> &str {"/"}\n'
                 f'fn handler(params: Params) {{Redirect::to(external::Type::<Result<u8, E>>::fixed({SOURCE}));}}', 2),
                ('impl-trait-handler', 'fn send(x: &str) {Redirect::to(x);}\n'
                 f'fn handler(params: impl RequestParams) -> impl IntoResponse {{send({SOURCE});}}', 1),
                ('impl-free-helper', 'fn send(x: &str) {Redirect::to(x);}\nstruct Handler {}\n'
                 f'impl Handler {{fn handler(params: Params) {{send({SOURCE});}}}}', 1),
                ('self-receiver-helper', 'struct Handler {}\nimpl Handler {\n'
                 ' fn send(&self, x: &str) {Redirect::to(x);}\n'
                 f' fn route(&self, params: Params) {{self.send({SOURCE});}}\n}}', 3),
                ('self-receiver-constant', 'struct Handler {}\nimpl Handler {\n'
                 ' fn target(&self, x: &str) -> &str {"/"}\n'
                 f' fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}\n}}', None),
                ('self-receiver-owner-clean', 'struct Safe {}\nstruct Unsafe {}\n'
                 'impl Unsafe {fn send(&self, x: &str) {Redirect::to(x);}}\n'
                 'impl Safe {fn send(&self, x: &str) {Redirect::to("/");}}\n'
                 f'impl Safe {{fn route(&self, params: Params) {{self.send({SOURCE});}}}}', None),
                ('self-receiver-trait-fallback', 'struct Handler {}\n'
                 'trait External {fn target(&self, x: &str) -> &str;}\n'
                 'impl External for Handler {fn target(&self, x: &str) -> &str {x}}\n'
                 'impl Handler {\n fn target(&mut self, x: &str) -> &str {"/"}\n'
                 f' fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}\n}}', 6),
                ('self-receiver-private-fallback', 'struct Handler {}\n'
                 'mod hidden {impl super::Handler {fn target(&self, x: &str) -> &str {"/"}}}\n'
                 'trait External {fn target(&self, x: &str) -> &str;}\n'
                 'impl External for Handler {fn target(&self, x: &str) -> &str {x}}\n'
                 f'impl Handler {{fn route(&self, params: Params) {{Redirect::to(self.target({SOURCE}));}}}}', 5),
                ('self-receiver-header-clean', 'struct Handler {}\nimpl Handler {\n'
                 ' fn header(&self, key: &str, x: &str) {Redirect::to("/");}\n'
                 f' fn route(&self, params: Params) {{self.header("Location", {SOURCE});}}\n}}', None),
                ('self-receiver-header-helper', 'struct Handler {}\nimpl Handler {\n'
                 ' fn header(&self, key: &str, x: &str) {Redirect::to(x);}\n'
                 f' fn route(&self, params: Params) {{self.header("Location", {SOURCE});}}\n}}', 3),
                ('qualified-private-trait-fallback', 'struct Handler {}\n'
                 'mod hidden {impl super::Handler {fn target(&self, x: &\'static str) -> &\'static str {"/"}}}\n'
                 'trait Fallback {fn target(&self, x: &\'static str) -> &\'static str;}\n'
                 'impl Fallback for Handler {fn target(&self, x: &\'static str) -> &\'static str {x}}\n'
                 f'fn handler(params: Params) {{Redirect::to(Handler::target(&Handler {{}}, {SOURCE}));}}', 5),
                ('qualified-public-inherent-clean', 'struct Handler {}\n'
                 'mod helpers {impl super::Handler {pub fn target(&self, x: &\'static str) -> &\'static str {"/"}}}\n'
                 f'fn handler(params: Params) {{Redirect::to(Handler::target(&Handler {{}}, {SOURCE}));}}', None),
            )
            for name, code, line in qualified:
                target = project / (name + '.rs')
                target.write_text(code + '\n', encoding='utf-8')
                cases.append((name, target, line is not None))
                if line is not None:
                    expected_lines[name] = line
            for fmt in ('json', 'sarif'):
                for name, target, expected in cases:
                    result = subprocess.run([str(ROOT / 'ubs'), '--only=rust', '--ci', '--format=' + fmt, str(target)],
                        cwd=tmp, env={**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'HOME': str(tmp),
                                      'XDG_CACHE_HOME': str(tmp / 'cache'), 'UBS_SKIP_RUST_BUILD': '1'},
                        text=True, capture_output=True, timeout=180)
                    prefix = artifact / (name + '-' + fmt)
                    prefix.with_suffix('.stdout.log').write_text(result.stdout, encoding='utf-8')
                    prefix.with_suffix('.stderr.log').write_text(result.stderr, encoding='utf-8')
                    self.assertIn(result.returncode, (0, 1), (result.returncode, result.stdout, result.stderr))
                    payload = json.loads(result.stdout)
                    def records(value):
                        if isinstance(value, dict):
                            yield value
                            for child in value.values():
                                yield from records(child)
                        elif isinstance(value, list):
                            for child in value:
                                yield from records(child)
                    findings = [record for record in records(payload)
                                if record.get('rule_id', record.get('ruleId', record.get('rule'))) == RULE]
                    self.assertEqual(len(findings), int(expected), (payload, result.stderr))
                    if fmt == 'json':
                        self.assertEqual(payload['status'], 'ok', payload)
                    if expected:
                        finding = findings[0]
                        if fmt == 'json':
                            line, filename, message = finding['line'], finding['file'], finding['message']
                        else:
                            location = finding['locations'][0]['physicalLocation']
                            line = location['region']['startLine']
                            filename = location['artifactLocation']['uri']
                            message = finding['message']['text']
                        self.assertEqual(line, expected_lines[name], finding)
                        self.assertEqual(Path(filename).name, target.name, finding)
                        self.assertIn('params.get("next") -> redirect', message, finding)
                    print('RUST_REDIRECT_REAL_SCAN', fmt, name, 'PASS', flush=True)

    def test_malformed_source_is_partial_and_never_cached_as_clean(self):
        artifact = ROOT / 'test-suite/artifacts/rust-redirect-dataflow'
        artifact.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ubs-rust-incomplete-') as scratch:
            scratch = Path(scratch)
            target = scratch / 'malformed.rs'
            target.write_text(f'fn handler() {{Redirect::to({SOURCE}); (] }}\n', encoding='utf-8')
            for attempt in range(2):
                result = subprocess.run([str(ROOT / 'ubs'), str(target), '--only=rust', '--ci', '--format=json'],
                    cwd=scratch, env={**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'HOME': str(scratch),
                        'XDG_CACHE_HOME': str(scratch / 'cache'), 'UBS_SKIP_RUST_BUILD': '1'},
                    text=True, capture_output=True, timeout=180)
                (artifact / f'incomplete-{attempt}.stdout.log').write_text(result.stdout, encoding='utf-8')
                (artifact / f'incomplete-{attempt}.stderr.log').write_text(result.stderr, encoding='utf-8')
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'partial', report)
                self.assertTrue(any(failure.get('language') == 'rust'
                                    and failure.get('module_error') == 'ANALYZER_ERROR'
                                    for failure in report['failed_modules']), report)
                self.assertIn('open_redirect', json.dumps(report))

    def test_uncaught_engine_exit_one_is_not_a_successful_scan(self):
        # Inject only a process crash, not fake findings. Every other scanner
        # component and its integrity checks still execute unchanged.
        artifact = ROOT / 'test-suite/artifacts/rust-redirect-dataflow'
        artifact.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ubs-rust-process-failure-') as scratch:
            scratch = Path(scratch)
            target = scratch / 'sample.rs'
            target.write_text('fn handler() {Redirect::to("/safe");}\n', encoding='utf-8')
            shim = scratch / 'python3'
            shim.write_text('#!/bin/sh\nif [ "$1" = -m ] && [ "$2" = ubs_core.rust_scan ]; then exit 1; fi\n'
                            + 'exec ' + shlex.quote(sys.executable) + ' "$@"\n', encoding='utf-8')
            shim.chmod(0o755)
            for fmt in ('json', 'text'):
                result = subprocess.run([str(ROOT / 'modules/ubs-rust.sh'), str(target), '--no-cargo',
                        '--format=' + fmt], cwd=scratch,
                    env={**os.environ, 'PATH': str(scratch) + os.pathsep + os.environ['PATH'],
                         'HOME': str(scratch), 'XDG_CACHE_HOME': str(scratch / 'cache'),
                         'UBS_NO_AUTO_UPDATE': '1'}, text=True, capture_output=True, timeout=180)
                (artifact / f'crash-{fmt}.stdout.log').write_text(result.stdout, encoding='utf-8')
                (artifact / f'crash-{fmt}.stderr.log').write_text(result.stderr, encoding='utf-8')
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                if fmt == 'json':
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'partial', report)
                    self.assertEqual(report['module_error'], 'ANALYZER_ERROR', report)
                else:
                    self.assertIn('SCAN INCOMPLETE', result.stdout)
                    self.assertNotIn('SCAN COMPLETE', result.stdout)
                    self.assertNotIn('No critical or warning issues found', result.stdout)


class RustDetectorFailureTests(SourceCase):
    def scanner(self):
        from ubs_core.rust_scan import Scan
        return Scan([], ROOT, False, set(), 3)

    def test_import_failure_is_recorded_and_not_retried_as_clean(self):
        scanner = self.scanner()
        with patch('importlib.import_module', side_effect=ImportError('broken dependency')) as load:
            self.assertEqual(scanner.detector_hits('open_redirect'), [])
            self.assertEqual(scanner.detector_hits('open_redirect'), [])
        self.assertEqual(load.call_count, 1)
        self.assertEqual(len(scanner.scan_errors), 1)
        self.assertIn('broken dependency', scanner.scan_errors[0])

    def test_absent_entrypoint_is_incomplete(self):
        from types import SimpleNamespace
        for value in (None, 'not callable'):
            scanner = self.scanner()
            with self.subTest(value=value), patch('importlib.import_module', return_value=SimpleNamespace(find=value)):
                self.assertEqual(scanner.detector_hits('open_redirect'), [])
                self.assertIn('no callable find', scanner.scan_errors[0])

    def test_generator_failure_retains_previous_findings_and_error(self):
        from types import SimpleNamespace
        scanner = self.scanner()
        def fail(files):
            yield ROOT / 'handler.rs', 1, 1, 'a genuine finding'
            raise AnalysisLimit('limit reached')
        with patch('importlib.import_module', return_value=SimpleNamespace(find=fail)):
            hits = scanner.detector_hits('open_redirect')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].text, 'a genuine finding')
        self.assertIn('limit reached', scanner.scan_errors[0])


if __name__ == '__main__':
    unittest.main()
