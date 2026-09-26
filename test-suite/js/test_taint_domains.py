"""D6 regressions: sanitizer effects are local to one value and sink domain."""
from __future__ import annotations

from collections import Counter
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext


class JavaScriptTaintDomainTests(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.failures_before = len(result.failures) + len(result.errors)
        print(f"[{self.id()}] RUN", flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.failures) + len(result.errors) > self.failures_before
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} ({time.monotonic() - self.started:.3f}s)", flush=True)

    def findings(self, body: str):
        with tempfile.TemporaryDirectory(prefix="ubs-js-domain-") as scratch:
            path = Path(scratch) / "handler.js"
            path.write_text(body + "\n", encoding="utf-8")
            return list(taint_js.run(RunContext(lang="javascript", files=[path])))

    def assert_rules(self, body: str, *rules: str):
        findings = self.findings(body)
        self.assertEqual(Counter(f["rule"] for f in findings),
                         Counter("javascript.taint." + rule for rule in rules), findings)
        for finding in findings:
            self.assertGreater(finding["line"], 0)
            self.assertGreater(finding["col"], 0)
            self.assertEqual(finding["severity"], "critical")
            self.assertIn(" -> ", finding["message"])
        return findings

    def test_html_escape_does_not_sanitize_other_sink_domains(self):
        for sink, rule in (("eval", "eval"), ("db.query", "sql"), ("shell.exec", "command")):
            with self.subTest(sink=sink):
                self.assert_rules(f"{sink}(DOMPurify.sanitize(req.query.value));", rule)

    def test_sql_escape_does_not_sanitize_html_or_eval(self):
        self.assert_rules("res.send(db.escape(req.query.value));", "xss")
        self.assert_rules("eval(mysql.escape(req.query.value));", "eval")

    def test_shell_escape_does_not_sanitize_html_or_sql(self):
        self.assert_rules("res.send(shellescape(req.query.value));", "xss")
        self.assert_rules("db.query(shellescape(req.query.value));", "sql")

    def test_unproven_sanitizer_names_do_not_erase_taint(self):
        for name in ("sanitizeInput", "sanitizeUrl", "encodeURIComponent", "stripTags"):
            with self.subTest(name=name):
                self.assert_rules(f"eval({name}(req.query.value));", "eval")

    def test_sanitizer_must_be_called_not_merely_mentioned(self):
        self.assert_rules("res.send(DOMPurify.sanitize + req.query.value);", "xss")
        self.assert_rules("res.send(fakeDOMPurify.sanitize(req.query.value));", "xss")
        self.assert_rules("res.send(wrapper.DOMPurify.sanitize(req.query.value));", "xss")

    def test_unsanitized_sibling_survives_direct_sanitizer(self):
        self.assert_rules("res.send(DOMPurify.sanitize(req.query.safe) + req.query.raw);", "xss")
        self.assert_rules("res.send(req.query.raw + DOMPurify.sanitize(req.query.safe));", "xss")

    def test_unsanitized_sibling_survives_assignment(self):
        self.assert_rules("const raw = req.query.raw;\n"
                          "const mixed = DOMPurify.sanitize(raw) + raw;\n"
                          "res.send(mixed);", "xss")

    def test_sanitized_source_assignment_is_clean_in_its_domain(self):
        self.assert_rules("const clean = DOMPurify.sanitize(req.query.value);\n"
                          "res.send(clean);")

    def test_sanitizer_effect_propagates_only_in_its_domain(self):
        self.assert_rules("const raw = req.query.value;\n"
                          "const clean = DOMPurify.sanitize(raw);\n"
                          "const alias = clean;\n"
                          "res.send(alias);\n"
                          "eval(alias);\n"
                          "db.query(alias);\n"
                          "shell.exec(alias);", "eval", "sql", "command")

    def test_nested_sanitizer_calls_preserve_clean_html(self):
        self.assert_rules("res.send(DOMPurify.sanitize(transform(req.query.value)));")
        self.assert_rules("res.send(DOMPurify.sanitize(req.query.a) + escapeHtml(req.query.b));")

    def test_recognized_domain_specific_calls_remain_clean(self):
        self.assert_rules("db.query(mysql.escape(req.query.value));")
        self.assert_rules("shell.exec(shellescape(req.query.value));")
        self.assert_rules("res.send(he.escape(req.query.value));")

    def test_bound_values_do_not_sanitize_dynamic_query(self):
        for bindings in ("[req.query.id]", "params", "values", "bindings", "[]"):
            with self.subTest(bindings=bindings):
                self.assert_rules(f"db.query(req.query.sql, {bindings});", "sql")

    def test_bound_values_do_not_sanitize_propagated_query(self):
        self.assert_rules("const sql = req.query.sql;\n"
                          "db.query(sql, [req.query.id]);", "sql")

    def test_bound_values_in_static_query_are_not_query_taint(self):
        self.assert_rules("db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);")
        self.assert_rules("const value = req.query.id;\n"
                          "db.query('SELECT * FROM users WHERE id = ?', [value]);")

    def test_first_query_argument_respects_nested_delimiters(self):
        self.assert_rules("db.query(format(req.query.sql, [1, 2]), [3]);", "sql")
        self.assert_rules("db.query(makeQuery({a: [1, 2]}), [req.query.id]);")

    def test_child_process_aliases_use_domain_specific_sanitizers(self):
        self.assert_rules("const { exec: run } = require('node:child_process');\n"
                          "run(DOMPurify.sanitize(req.query.command));", "command")
        self.assert_rules("const { exec: run } = require('node:child_process');\n"
                          "run(shellescape(req.query.command));")

    def test_legacy_and_structured_entrypoints_agree(self):
        source = "\n".join("eval(DOMPurify.sanitize(req.query.value));" for _ in range(5))
        with tempfile.TemporaryDirectory(prefix="ubs-js-domain-parity-") as scratch:
            path = Path(scratch) / "handler.js"
            path.write_text(source + "\n", encoding="utf-8")
            findings = list(taint_js.run(RunContext(lang="javascript", files=[path])))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(taint_js.main(["taint_js", scratch]), 0)
            fields = output.getvalue().strip().split("\t")
            self.assertEqual(fields[:2], ["js.taint.eval", "5"])
            self.assertEqual(len(findings), 5)
            self.assertEqual(len(fields[2].split(",")), 3)

    def test_existing_selftests(self):
        for name, test in taint_js.SELF_TESTS:
            with self.subTest(name=name):
                test()

    def test_template_interpolations_are_executable_input(self):
        for source in ('eval(`${req.query.value}`);',
                       'eval(`prefix ${req.query.value} suffix`);',
                       'eval(`outer ${`inner ${req.query.value}`}`);'):
            with self.subTest(source=source):
                self.assert_rules(source, "eval")

    def test_template_assignment_propagates_taint(self):
        self.assert_rules('const command = `echo ${req.query.value}`;\n'
                          'shell.exec(command);', "command")

    def test_multiline_template_assignment_propagates_taint(self):
        self.assert_rules('const query = `SELECT * FROM users\n'
                          'WHERE name = ${req.query.name}\n'
                          '`;\ndb.query(query);', "sql")

    def test_multiline_sink_keeps_original_coordinates(self):
        source = 'const html = req.query.html;\n'
        source += '    document.write(\n        html\n    );'
        findings = self.assert_rules(source, "xss")
        self.assertEqual((findings[0]["line"], findings[0]["col"]), (2, 5))

    def test_multiline_source_assignment(self):
        self.assert_rules('const html = transform(\n  req.query.html\n);\nres.send(html);', "xss")

    def test_sanitized_template_and_unsanitized_interpolation(self):
        self.assert_rules('res.send(`safe ${DOMPurify.sanitize(req.query.value)}`);')
        self.assert_rules('res.send(`${DOMPurify.sanitize(req.query.a)}${req.query.b}`);', "xss")

    def test_template_literal_text_and_escaped_interpolation_are_inert(self):
        self.assert_rules('res.send(`req.query.value`);')
        self.assert_rules(r'res.send(`\${req.query.value}`);')
        self.assert_rules('const raw = req.query.value;\nres.send(`raw`);')

    def test_multiline_comments_do_not_create_findings_or_bindings(self):
        self.assert_rules('/* example\nconst html = req.query.html;\n'
                          'document.write(html);\n*/\nres.send(html);')
        self.assert_rules('/*\nconst { exec } = require("child_process");\n*/\n'
                          'exec(req.query.command);')

    def test_source_like_strings_do_not_create_command_taint(self):
        self.assert_rules('const { exec } = require("child_process");\n'
                          'exec("req.query.command");')

    def test_quoted_bracket_request_properties_are_sources(self):
        self.assert_rules('db.query(params["tenant"]);', "sql")
        self.assert_rules('res.send(req.query["html"]);', "xss")

    def test_parentheses_inside_strings_do_not_end_sanitizer_calls(self):
        self.assert_rules('res.send(DOMPurify.sanitize(transform(")", req.query.html)));')
        self.assert_rules('res.send(DOMPurify.sanitize(transform("(", req.query.a)) + req.query.b);', "xss")

    def test_comments_do_not_join_identifiers_into_sources(self):
        self.assert_rules('res.send(re/**/q.query.html);')

    def test_each_sink_call_is_isolated_from_following_statements(self):
        source = 'res.send(DOMPurify.sanitize(req.query.a)); res.send(req.query.b);'
        findings = self.assert_rules(source, "xss")
        self.assertEqual(findings[0]["col"], source.rindex('res.send') + 1)
        self.assert_rules('db.query("SELECT 1"); res.send(req.query.html);', "xss")

    def test_multiple_vulnerable_calls_on_one_line_are_all_reported(self):
        self.assert_rules('eval(req.query.a); eval(req.query.b);', "eval", "eval")

    def test_same_line_assignment_is_analyzed(self):
        self.assert_rules('function render(req) { const html = req.query.html; res.send(html); }', "xss")

    def test_regex_literals_do_not_create_sources(self):
        self.assert_rules('const pattern = /req.query.html/;\nres.send(pattern);')
        self.assert_rules('const pattern = /[}/]req.query.html/;\nres.send(pattern);')

    def test_division_does_not_hide_input(self):
        self.assert_rules('res.send(total / req.query.value);', "xss")

    def test_sink_after_multiline_comment_is_still_visible(self):
        findings = self.assert_rules('/* start\nend */  eval(req.query.value);', "eval")
        self.assertEqual((findings[0]["line"], findings[0]["col"]), (2, 9))

    def test_reverse_order_propagation_reaches_fixed_point(self):
        assignments = [(i + 1, f'v{i}', f'v{i + 1}') for i in range(20)]
        assignments.append((21, 'v20', 'req.query.value'))
        tainted = taint_js.record_taint(assignments, 'js.taint.eval')
        self.assertIn('v0', tainted)
        self.assertLessEqual(len(tainted['v0']['path']), taint_js.PATH_LIMIT)

    def test_cyclic_unseeded_assignment_graph_terminates_clean(self):
        self.assertEqual(taint_js.record_taint([(1, 'a', 'b'), (2, 'b', 'a')]), {})

    def test_typescript_annotation_is_not_the_variable_name(self):
        self.assert_rules('const html: string = req.query.html;\nres.send(html);', "xss")

    def test_large_reverse_assignment_graph(self):
        assignments = [(i + 1, f'v{i}', f'v{i + 1}') for i in range(1000)]
        assignments.append((1001, 'v1000', 'req.query.value'))
        self.assertEqual(len(taint_js.record_taint(assignments, 'js.taint.eval')), 1001)

    def test_seeded_cycle_terminates_with_bounded_provenance(self):
        tainted = taint_js.record_taint([(1, 'a', 'b'), (2, 'b', 'a'), (3, 'a', 'req.query.value')])
        self.assertEqual(set(tainted), {'a', 'b'})
        self.assertLessEqual(len(tainted['b']['path']), taint_js.PATH_LIMIT)

    def test_lexer_preserves_length_and_newlines(self):
        source = '/* a\nb */ "c\\\"d"; `literal\n${`nested ${req.query.x}`}`;'
        for view in taint_js.lexical_views(source):
            self.assertEqual(len(view), len(source))
            self.assertEqual([i for i, c in enumerate(view) if c == '\n'],
                             [i for i, c in enumerate(source) if c == '\n'])

    def test_string_literals_do_not_register_command_aliases(self):
        self.assert_rules('const example = "const { exec } = require(\'child_process\');";\n'
                          'exec(req.query.command);')

    def test_multiline_command_import_is_a_real_binding(self):
        self.assert_rules('import {\n  exec as run\n} from "node:child_process";\n'
                          'run(req.query.command);', "command")

    def test_whitespace_does_not_turn_an_object_member_into_a_sanitizer(self):
        self.assert_rules('res.send(wrapper. DOMPurify.sanitize(req.query.value));', "xss")

    def test_transforming_a_sanitized_result_retains_uncertainty(self):
        self.assert_rules('db.query(mysql.escape(req.query.value).slice(1, -1));', "sql")
        self.assert_rules('res.send(escapeHtml(req.query.value).replace("&lt;", "<"));', "xss")

    def test_incomplete_sanitizer_call_is_not_evidence_of_safety(self):
        expr = 'DOMPurify.sanitize(' * 200 + 'req.query.value'
        self.assertIn('req.query.value', taint_js.unsanitized_expression(expr, 'js.taint.xss'))

    def test_function_locals_do_not_taint_unrelated_parameters(self):
        self.assert_rules('function unsafe(req) { const value = req.query.value; }\n'
                          'function clean(value) { eval(value); }\nclean("safe");')
        self.assert_rules('const value = req.query.value;\n'
                          'function clean(value) { eval(value); }\nclean("safe");')

    def test_safe_overwrite_and_later_source_do_not_taint_earlier_sink(self):
        self.assert_rules('let value = req.query.value; value = "safe"; eval(value);')
        self.assert_rules('let value = "safe"; eval(value); value = req.query.value;')
        self.assert_rules('let value = req.query.value; eval(value); value = "safe";', 'eval')

    def test_sink_wrapper_propagates_argument_and_keeps_sink_location(self):
        source = 'function execute(value) {\n  const command = value;\n  eval(command);\n}\nexecute(req.query.value);'
        findings = self.assert_rules(source, 'eval')
        self.assertEqual((findings[0]['line'], findings[0]['col']), (3, 3))
        self.assertIn('req.query.value', findings[0]['message'])
        self.assertIn('execute()', findings[0]['message'])
        self.assertIn('command', findings[0]['message'])

    def test_returned_source_and_parameter_dependencies(self):
        self.assert_rules('function obtain() { return req.query.value; }\neval(obtain());', 'eval')
        self.assert_rules('function select(first, second) { return second; }\n'
                          'eval(select("safe", req.query.value));', 'eval')
        self.assert_rules('function select(first, second) { return second; }\n'
                          'eval(select(req.query.value, "safe"));')
        self.assert_rules('function constant(value) { return "safe"; }\neval(constant(req.query.value));')

    def test_function_alias_reassignment_and_duplicate_declaration(self):
        self.assert_rules('function execute(value) { eval(value); }\n'
                          'const alias = execute; alias(req.query.value);', 'eval')
        self.assert_rules('function execute(value) { eval(value); }\n'
                          'execute = other; execute(req.query.value);')
        self.assert_rules('function same(value) { return "safe"; }\n'
                          'function same(value) { return value; }\n'
                          'function handler(req, res) { res.send(same(req.query.value)); }', 'xss')

    def test_arrow_and_function_expression_summaries(self):
        for declaration in ('const identity = value => value;',
                            'const identity = (value: string): string => value;',
                            'const identity = async (value) => { return value; };',
                            'const identity = function(value) { return value; };'):
            with self.subTest(declaration=declaration):
                self.assert_rules(declaration + '\neval(identity(req.query.value));', 'eval')
        self.assert_rules('const clean = value => "safe"; eval(clean(req.query.value));')
        self.assert_rules('const execute = value => { eval(value); }; execute(req.query.value);', 'eval')

    def test_http_response_parameters_and_callback_scopes(self):
        self.assert_rules('function handler(req, res) { res.send(req.query.value); }', 'xss')
        self.assert_rules('router.get("/one", (req, res) => { const value = req.query.value; });\n'
                          'router.get("/two", (req, res) => { const value = "safe"; res.send(value); });')
        self.assert_rules('router.get("/one", (req, res) => { const value = req.query.value; res.send(value); });', 'xss')

    def test_wrapped_sanitizers_and_sink_effects_remain_domain_specific(self):
        wrapper = 'function clean(value) { return DOMPurify.sanitize(value); }\n'
        self.assert_rules(wrapper + 'res.send(clean(req.query.value));')
        self.assert_rules(wrapper + 'db.query(clean(req.query.value));', 'sql')
        self.assert_rules('function render(value) { res.send(value); }\n'
                          'render(DOMPurify.sanitize(req.query.value));')
        self.assert_rules('function render(value) { res.send(value); }\n'
                          'render(DOMPurify.sanitize(req.query.value) + req.query.raw);', 'xss')

    def test_branch_joins_and_terminating_paths(self):
        self.assert_rules('let value = req.query.value; if (flag) { value = "safe"; } eval(value);', 'eval')
        self.assert_rules('let value = req.query.value; if (flag) { value = "safe"; } '
                          'else { value = "also safe"; } eval(value);')
        self.assert_rules('function route(req) { let value = "safe"; '
                          'if (flag) { value = req.query.value; return; } eval(value); }')
        self.assert_rules('function route(req) { return; eval(req.query.value); }')
        self.assert_rules('if (false) { eval(req.query.value); }')

    def test_loop_joins_preserve_zero_and_later_iterations(self):
        self.assert_rules('let value = req.query.value; while (flag) { value = "safe"; } eval(value);', 'eval')
        self.assert_rules('let value = "safe"; while (flag) { eval(value); value = req.query.value; }', 'eval')
        self.assert_rules('while (false) { eval(req.query.value); }')
        self.assert_rules('let value = req.query.value; do { value = "safe"; } while (false); eval(value);')
        self.assert_rules('let value = "safe"; do { value = req.query.value; } while (false); eval(value);', 'eval')

    def test_block_shadowing_is_restored_on_break_and_continue(self):
        for control in ('break', 'continue'):
            with self.subTest(control=control):
                self.assert_rules('let value = "safe"; while (flag) { '
                                  f'let value = req.query.value; {control}; }} eval(value);')
        self.assert_rules('let value = req.query.value; { let value = "safe"; eval(value); } eval(value);', 'eval')

    def test_for_of_values_are_tainted_and_loop_locals_do_not_escape(self):
        self.assert_rules('for (const value of req.query.items) { eval(value); }', 'eval')
        self.assert_rules('let value = "safe"; for (const value of req.query.items) {} eval(value);')
        self.assert_rules('let value = "safe"; for (value of req.query.items) {} eval(value);', 'eval')

    def test_comma_declarations_and_compound_assignments(self):
        self.assert_rules('let first = "safe", second = req.query.value; eval(second);', 'eval')
        self.assert_rules('let first = "safe", second = req.query.value; eval(first);')
        self.assert_rules('let first = req.query.value, second = first; eval(second);', 'eval')
        for operator in ('+=', '||=', '&&=', '??='):
            with self.subTest(operator=operator):
                self.assert_rules(f'let value = "safe"; value {operator} req.query.value; eval(value);', 'eval')

    def test_member_and_chained_assignments_preserve_dependencies(self):
        self.assert_rules('const obj = {}; obj.value = req.query.value; eval(obj.value);', 'eval')
        self.assert_rules('const obj = {}; obj.value = req.query.value; eval(obj.other);')
        self.assert_rules('let first, second; first = second = req.query.value; eval(second);', 'eval')

    def test_try_switch_and_finally_retain_live_taint(self):
        self.assert_rules('let value = "safe"; try { value = req.query.value; } catch (error) {} eval(value);', 'eval')
        self.assert_rules('let value = "safe"; try { call(); } catch (error) { value = req.query.value; } eval(value);', 'eval')
        self.assert_rules('let value = "safe"; switch (tag) { case 1: value = req.query.value; break; '
                          'default: value = "safe"; } eval(value);', 'eval')
        self.assert_rules('let value = req.query.value; switch (tag) { case 1: value = "safe"; break; '
                          'default: value = "safe"; } eval(value);')
        self.assert_rules('function route(req) { try { return; } finally { eval(req.query.value); } }', 'eval')

    def test_recursive_summaries_and_deep_call_chains_terminate(self):
        self.assert_rules('function first(value) { return second(value); }\n'
                          'function second(value) { if (flag) return first(value); return value; }\n'
                          'eval(first(req.query.value));', 'eval')
        self.assert_rules('function spin(value) { return spin(value); } eval(spin(req.query.value));')
        source = '\n'.join(f'function f{i}(value) {{ return f{i + 1}(value); }}' for i in range(40))
        source += '\nfunction f40(value) { return value; }\neval(f0(req.query.value));'
        findings = self.assert_rules(source, 'eval')
        self.assertIn('req.query.value', findings[0]['message'])

    def test_summary_lattice_join_is_finite_and_keeps_shortest_evidence(self):
        source = taint_js._Trace(('source', 'req.query.value'), ('req.query.value',))
        longer = taint_js._Trace(source.origin, ('req.query.value', 'alias'))
        other = taint_js._Trace(('source', 'location.hash'), ('location.hash',))
        a, b, c = frozenset({source}), frozenset({longer}), frozenset({other})
        self.assertEqual(taint_js._join(a, a), a)
        self.assertEqual(taint_js._join(a, b), taint_js._join(b, a))
        self.assertEqual(taint_js._join(taint_js._join(a, b), c), taint_js._join(a, taint_js._join(b, c)))
        self.assertEqual(next(iter(taint_js._join(a, b))).path, source.path)

    def test_existing_taint_fixture_pair_keeps_exact_sites(self):
        buggy = list(taint_js.scan_file_findings(ROOT / 'test-suite/js/buggy/taint_analysis.js'))
        self.assertEqual([(rule, line) for rule, line, _, _ in buggy], [
            ('js.taint.xss', 11), ('js.taint.xss', 16), ('js.taint.sql', 22),
            ('js.taint.sql', 29), ('js.taint.sql', 35), ('js.taint.command', 40), ('js.taint.xss', 50)])
        self.assertEqual(list(taint_js.scan_file_findings(ROOT / 'test-suite/js/clean/taint_analysis.js')), [])

    def test_unknown_nested_and_holey_argument_spreads(self):
        helper = 'function second(a, b) { return b; }\n'
        self.assert_rules(helper + 'const args = ["safe", req.query.value]; eval(second(...args));', 'eval')
        self.assert_rules(helper + 'eval(second(...[...["safe", req.query.value]]));', 'eval')
        self.assert_rules(helper + 'eval(second(...[, req.query.value]));', 'eval')
        self.assert_rules(helper + 'eval(second(...[req.query.value, "safe"]));')

    def test_conditional_expression_side_effects_join_assignment_state(self):
        for operator in ('&&', '||', '??'):
            with self.subTest(operator=operator):
                self.assert_rules(f'let value = "safe"; flag {operator} (value = req.query.value); eval(value);', 'eval')
                self.assert_rules(f'let value = req.query.value; flag {operator} (value = "safe"); eval(value);', 'eval')
        self.assert_rules('let value = "safe"; flag ? (value = req.query.value) : 0; eval(value);', 'eval')
        self.assert_rules('let value = req.query.value; flag ? (value = "safe") : (value = "safe"); eval(value);')


if __name__ == "__main__":
    unittest.main(verbosity=2)
