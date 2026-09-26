"""Executable D6 examples for lexical binding isolation and local summaries."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext


class JavaScriptScopeTests(unittest.TestCase):
    def scan(self, code, *expected):
        with tempfile.TemporaryDirectory(prefix='ubs-js-scopes-') as tmp:
            path = Path(tmp) / 'handler.ts'
            path.write_text(code + '\n', encoding='utf-8')
            findings = list(taint_js.run(RunContext(lang='javascript', files=[path])))
        self.assertEqual(Counter(f['rule'].removeprefix('javascript.taint.') for f in findings),
                         Counter(expected), findings)
        for finding in findings:
            self.assertEqual(finding['severity'], 'critical')
            self.assertGreater(finding['line'], 0)
            self.assertGreater(finding['col'], 0)
        return findings

    def test_sibling_function_locals_are_isolated(self):
        self.scan('function a(req) { const html = req.query.html; }\n'
                  'function b() { const html = "hello"; res.send(html); }')

    def test_sibling_callback_locals_are_isolated(self):
        self.scan('app.get("/a", req => { const html = req.query.html; });\n'
                  'app.get("/b", req => { const html = "hello"; res.send(html); });')

    def test_parameter_shadows_outer_taint(self):
        self.scan('const html = req.query.html; function clean(html) { res.send(html); }')

    def test_arrow_parameter_shadows_outer_taint(self):
        self.scan('const html = req.query.html; const clean = html => res.send(html);')

    def test_uninitialized_local_shadows_outer_taint(self):
        self.scan('const html = req.query.html; function f() { let html; res.send(html); }')

    def test_closure_captures_outer_taint(self):
        self.scan('function outer(req) { const html = req.query.html;\n'
                  'function inner() { res.send(html); } }', 'xss')

    def test_nested_function_assignment_does_not_taint_its_function_value(self):
        self.scan('const render = () => { const html = req.query.html; };\nres.send(render);')

    def test_two_same_named_helpers_resolve_lexically(self):
        self.scan('function a() { function read() { return req.query.html; } res.send(read()); }\n'
                  'function b() { function read() { return "hello"; } res.send(read()); }', 'xss')

    def test_source_returning_helper(self):
        findings = self.scan('function read() { return req.query.html; }\nres.send(read());', 'xss')
        self.assertEqual(findings[0]['line'], 2)
        self.assertIn('read()', findings[0]['message'])

    def test_helper_returns_local_alias(self):
        self.scan('function read() { const html = req.query.html; return html; }\nres.send(read());', 'xss')

    def test_constant_return_discards_input(self):
        self.scan('function clean(value) { return "hello"; }\nres.send(clean(req.query.html));')

    def test_only_used_parameter_flows_to_return(self):
        self.scan('function first(a, b) { return a; }\nres.send(first("hello", req.query.html));')
        self.scan('function second(a, b) { return b; }\nres.send(second("hello", req.query.html));', 'xss')

    def test_parameter_to_sink_effect(self):
        findings = self.scan('function output(value) { res.send(value); }\noutput(req.query.html);', 'xss')
        self.assertEqual(findings[0]['line'], 1)
        self.assertIn('output()', findings[0]['message'])

    def test_clean_parameter_to_sink_effect(self):
        self.scan('function output(value) { res.send(value); }\noutput("hello");')

    def test_transitive_sink_effect(self):
        self.scan('function outer(x) { middle(x); }\nfunction middle(y) { inner(y); }\n'
                  'function inner(z) { eval(z); }\nouter(req.query.code);', 'eval')

    def test_return_summary_does_not_mix_safe_and_unsafe_calls(self):
        findings = self.scan('function identity(x) { return x; }\n'
                             'const unsafe = identity(req.query.html);\n'
                             'const safe = identity("hello");\nres.send(safe);\nres.send(unsafe);', 'xss')
        self.assertEqual(findings[0]['line'], 5)

    def test_local_sanitizer_wrapper_is_domain_specific(self):
        self.scan('function escape(x) { return DOMPurify.sanitize(x); }\n'
                  'res.send(escape(req.query.html));\neval(escape(req.query.html));', 'eval')

    def test_outer_sanitizer_covers_local_helper_return(self):
        self.scan('function identity(x) { return x; }\nres.send(DOMPurify.sanitize(identity(req.query.html)));')

    def test_sanitizer_named_local_function_must_earn_its_summary(self):
        self.scan('function escapeHtml(x) { return x; }\nres.send(escapeHtml(req.query.html));', 'xss')

    def test_unsafe_sibling_of_sanitized_helper_result(self):
        self.scan('function identity(x) { return x; }\n'
                  'res.send(DOMPurify.sanitize(identity(req.query.a)) + req.query.b);', 'xss')

    def test_arrow_expression_return(self):
        self.scan('const read = () => req.query.html;\nres.send(read());', 'xss')
        self.scan('const ignore = x => "hello";\nres.send(ignore(req.query.html));')

    def test_arrow_block_return_and_typed_parameters(self):
        self.scan('const identity = (value: string): string => { return value; };\n'
                  'eval(identity(req.query.code));', 'eval')

    def test_named_function_expression(self):
        self.scan('const read = function localName() { return req.query.html; };\nres.send(read());', 'xss')

    def test_async_helper_return(self):
        self.scan('async function read() { return req.query.html; }\nres.send(await read());', 'xss')

    def test_mutual_recursive_return_summaries_terminate(self):
        self.scan('function a(x) { if (flag) return x; return b(x); }\n'
                  'function b(y) { return a(y); }\neval(b(req.query.code));', 'eval')

    def test_unseeded_recursive_summaries_terminate_clean(self):
        self.scan('function a(x) { return b(x); } function b(y) { return a(y); }\neval(a("hello"));')

    def test_recursive_sink_effect_terminates(self):
        self.scan('function a(x) { if (flag) return b(x); eval(x); }\n'
                  'function b(y) { a(y); }\nb(req.query.code);', 'eval')

    def test_missing_actual_parameter_is_not_unrelated_global(self):
        self.scan('const value = req.query.html; function identity(value) { return value; }\nres.send(identity());')

    def test_ambiguous_helper_binding_retains_argument_flow(self):
        self.scan('function f(x) { return "hello"; } f = external;\nres.send(f(req.query.html));', 'xss')

    def test_shadowing_helper_name_does_not_apply_outer_clean_summary(self):
        self.scan('function f(x) { return "hello"; }\nfunction outer(f) { res.send(f(req.query.html)); }', 'xss')

    def test_unknown_external_call_retains_argument_flow(self):
        self.scan('res.send(external(req.query.html));', 'xss')

    def test_function_declaration_is_not_a_call(self):
        self.scan('const value = req.query.html; function output(value) { res.send(value); }')

    def test_return_newline_is_automatic_semicolon_insertion(self):
        self.scan('function read() { return\nreq.query.html; }\nres.send(read());')

    def test_nested_argument_calls_and_commas(self):
        self.scan('function second(a, b) { return b; } function identity(x) { return x; }\n'
                  'res.send(second("a,b", identity(req.query.html)));', 'xss')

    def test_literal_fake_function_does_not_change_scopes(self):
        self.scan('const example = "function f(html) { return html; }";\nres.send(req.query.html);', 'xss')

    def test_method_locals_are_isolated(self):
        self.scan('class Example { a(req) { const html = req.query.html; }\n'
                  'b() { const html = "hello"; res.send(html); } }')

    def test_source_captured_by_nested_helper_return(self):
        self.scan('function outer(req) { const html = req.query.html;\n'
                  'function inner() { return html; } res.send(inner()); }', 'xss')

    def test_multiline_calls_preserve_sink_coordinates(self):
        findings = self.scan('function identity(x) { return x; }\n  eval(\nidentity(\nreq.query.code\n)\n);', 'eval')
        self.assertEqual((findings[0]['line'], findings[0]['col']), (2, 3))

    def test_existing_legacy_selftests(self):
        for name, check in taint_js.SELF_TESTS:
            with self.subTest(name=name):
                check()

    def test_destructured_parameter_binding_and_shadowing(self):
        self.scan('function get({value: html}) { return html; }\n'
                  'res.send(get({value: req.query.html}));', 'xss')
        self.scan('const html = req.query.html; function output({html}) { res.send(html); }')

    def test_nested_destructured_parameters(self):
        self.scan('function get({user: {name}}, [other]) { return name; }\n'
                  'res.send(get({user: {name: req.query.name}}, []));', 'xss')

    def test_rest_parameter_includes_all_actual_arguments(self):
        self.scan('function join(...values) { return values.join(" "); }\n'
                  'eval(join("safe", req.query.code));', 'eval')

    def test_missing_parameter_uses_source_default(self):
        self.scan('function get(value = req.query.html) { return value; }\nres.send(get());', 'xss')

    def test_explicit_argument_does_not_use_source_default(self):
        self.scan('function get(value = req.query.html) { return value; }\nres.send(get("hello"));')

    def test_explicit_undefined_uses_source_default(self):
        self.scan('function get(value = req.query.html) { return value; }\nres.send(get(undefined));', 'xss')

    def test_default_can_reference_prior_actual_parameter(self):
        self.scan('function get(a, b = a) { return b; }\nres.send(get(req.query.html));', 'xss')

    def test_default_flows_through_sink_summary(self):
        self.scan('function output(value = req.query.html) { res.send(value); }\noutput();', 'xss')

    def test_spread_arguments_are_not_treated_as_one_argument(self):
        self.scan('function second(a, b) { return b; }\n'
                  'res.send(second(...["hello", req.query.html]));', 'xss')

    def test_spread_can_leave_a_default_parameter_unbound(self):
        self.scan('function second(a, b = req.query.html) { return b; }\n'
                  'res.send(second(...values));', 'xss')

    def test_long_helper_chain_reaches_fixpoint(self):
        helpers = [f'function f{i}(x) {{ return f{i + 1}(x); }}' for i in range(40)]
        helpers += ['function f40(x) { return x; }', 'eval(f0(req.query.code));']
        self.scan('\n'.join(helpers), 'eval')

    def test_multiple_parameter_origins_survive_summary_join(self):
        self.scan('function choose(a, b) { if (flag) return a; return b; }\n'
                  'eval(choose("hello", req.query.code));', 'eval')

    def test_inner_block_does_not_shadow_an_outer_read(self):
        self.scan('const html = req.query.html;\nfunction output() {\n'
                  'if (flag) { let html = "hello"; }\nres.send(html); }', 'xss')

    def test_block_local_does_not_inherit_outer_taint(self):
        self.scan('const html = req.query.html;\nfunction output() {\n'
                  'if (flag) { let html = "hello"; res.send(html); } }')

    def test_block_local_does_not_taint_sibling_block(self):
        self.scan('function output(req) {\nif (flag) { let html = req.query.html; }\n'
                  'else { let html = "hello"; res.send(html); } }')

    def test_var_remains_function_scoped(self):
        self.scan('function output(req) {\nif (flag) { var html = req.query.html; }\nres.send(html); }', 'xss')

    def test_closure_captures_its_defining_block(self):
        self.scan('function outer(req) {\nif (flag) { const html = req.query.html;\n'
                  'function inner() { res.send(html); } } }', 'xss')

    def test_var_whitespace_does_not_change_binding_scope(self):
        self.scan('function output(req) {\nif (flag) { var\thtml = req.query.html; }\nres.send(html); }', 'xss')

    def test_return_property_is_not_a_return_statement(self):
        self.scan('function f() { iterator.return(req.query.html); }\nres.send(f());')


if __name__ == '__main__':
    unittest.main(verbosity=2)
