"""Production Rust redirect dataflow: unsafe flows paired with safe controls."""
from __future__ import annotations

import contextlib
import io
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.rust_detectors import open_redirect
from ubs_core.rust_detectors.redirect_flow import Origin, Source, join

RULE = 'rust.security.open-redirect'
SOURCE = 'params.get("next")'


class SourceCase(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        failed = any(test is self for test, _ in self._outcome.result.failures + self._outcome.result.errors)
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
        self.count(f'''let target={SOURCE}; if !(target.starts_with('/') && !target.starts_with("//")) {{ return Err("blocked"); }} Redirect::to(target)''', 0)

    def test_reversed_local_guard_operands(self):
        self.count(f'''let target={SOURCE}; if !target.starts_with("//") && target.starts_with('/') {{ Redirect::to(target); }}''', 0)

    def test_guard_does_not_protect_sibling_or_post_join_path(self):
        self.count(f'''let target={SOURCE}; if target.starts_with('/') && !target.starts_with("//") {{ }} Redirect::to(target)''')

    def test_logging_rejection_does_not_validate(self):
        self.count(f'''let target={SOURCE}; if !(target.starts_with('/') && !target.starts_with("//")) {{ log("invalid"); }} Redirect::to(target)''')

    def test_unrelated_value_validation_cannot_suppress(self):
        self.count(f'let target={SOURCE}; if !is_allowed_redirect_host(&other) {{ return Err("blocked"); }} Redirect::to(target)')

    def test_named_external_validation(self):
        self.count(f'let target={SOURCE}; if !is_allowed_redirect_host(&target) {{ return Err("blocked"); }} Redirect::to(target)', 0)

    def test_reassignment_revokes_validation(self):
        self.count(f'let mut target={SOURCE}; if !is_allowed_redirect_host(&target) {{ return Err("blocked"); }} target={SOURCE}; Redirect::to(target)')

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

    def test_external_safe_helper_only_cleans_its_result(self):
        self.count(f'let raw={SOURCE}; let target=safe_redirect_url(raw); Redirect::to(target)', 0)
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


@unittest.skipUnless(os.environ.get('UBS_RUST_REDIRECT_E2E') == '1', 'set UBS_RUST_REDIRECT_E2E=1 for real CLI scans')
class RealScannerTests(unittest.TestCase):
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
            for fmt in ('json', 'sarif'):
                for name, target, expected in [('unsafe', dangerous, True), ('safe', safe, False)]:
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
                    self.assertEqual(bool(findings), expected, (payload, result.stderr))
                    if fmt == 'json':
                        self.assertEqual(payload['status'], 'ok', payload)
                    print('RUST_REDIRECT_REAL_SCAN', fmt, name, 'PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
