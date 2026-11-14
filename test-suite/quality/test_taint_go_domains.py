"""Go sanitizer-domain and SQL argument-position regression controls.

Exercise the shipped analyzer on source files, not substitute matchers. These
cases deliberately pair dangerous query/command uses with escaped HTML and
bound SQL values so a blanket increase in critical findings cannot pass.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))
from ubs_core.analyzers import taint_go
from ubs_core.registry import RunContext
import test_taint_go_packages as packages


class GoTaintDomainTests(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.previous_failures = len(result.failures) + len(result.errors)
        print(f"[{self.id()}] RUN", flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.failures) + len(result.errors) > self.previous_failures
        state = "FAIL" if failed else "PASS"
        print(f"[{self.id()}] {state} ({time.monotonic() - self.started:.3f}s)", flush=True)

    def scan(self, body: str):
        source = "package main\n\nfunc handler() {\n" + textwrap.dedent(body).strip() + "\n}\n"
        return self.scan_source(source)

    def scan_source(self, source: str):
        with tempfile.TemporaryDirectory(prefix="ubs-go-domain-") as tmp:
            path = Path(tmp) / "handler.go"
            path.write_text(textwrap.dedent(source), encoding="utf-8")
            return list(taint_go.run(RunContext(lang="go", files=[path])))

    def rules(self, body: str):
        return [finding["rule"] for finding in self.scan(body)]

    def test_html_escape_does_not_sanitize_sql_assignment(self):
        self.assertEqual(self.rules('''
            value := html.EscapeString(r.FormValue("q"))
            db.Query("SELECT * FROM users WHERE name = '" + value + "'")
        '''), ["go.taint.sql"])

    def test_html_escape_does_not_sanitize_command_assignment(self):
        self.assertEqual(self.rules('''
            value := html.EscapeString(r.FormValue("q"))
            exec.Command("sh", "-c", value)
        '''), ["go.taint.command"])

    def test_inline_html_escape_does_not_sanitize_command(self):
        self.assertEqual(self.rules('''
            exec.Command("sh", "-c", html.EscapeString(r.FormValue("q")))
        '''), ["go.taint.command"])

    def test_path_clean_is_not_xss_or_command_sanitization(self):
        for sanitizer in ("path.Clean", "filepath.Clean"):
            with self.subTest(sanitizer=sanitizer):
                self.assertEqual(self.rules(f'''
                    value := {sanitizer}(r.FormValue("q"))
                    fmt.Fprint(w, value)
                    exec.Command("sh", "-c", value)
                '''), ["go.taint.xss", "go.taint.command"])

    def test_inline_sanitizer_does_not_hide_unsafe_sibling(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            fmt.Fprintf(w, "%s%s", html.EscapeString(value), value)
        '''), ["go.taint.xss"])

    def test_sanitizer_assignment_does_not_hide_unsafe_concat(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            mixed := html.EscapeString(value) + value
            fmt.Fprint(w, mixed)
        '''), ["go.taint.xss"])

    def test_sanitizer_text_in_string_does_not_suppress(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            fmt.Fprintf(w, "html.EscapeString(%s)", value)
        '''), ["go.taint.xss"])

    def test_sanitizer_in_comment_does_not_suppress(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            fmt.Fprint(w, value) // html.EscapeString(value)
        '''), ["go.taint.xss"])

    def test_html_escape_result_and_alias_are_clean_for_html(self):
        for sanitizer in ("html.EscapeString", "template.HTMLEscapeString"):
            with self.subTest(sanitizer=sanitizer):
                self.assertEqual(self.rules(f'''
                    value := r.FormValue("q")
                    escaped := {sanitizer}(value)
                    alias := escaped
                    fmt.Fprint(w, alias)
                    fmt.Fprintf(w, "%s", {sanitizer}(value))
                '''), [])

    def test_nested_html_escape_covers_all_of_its_argument(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            fmt.Fprint(w, html.EscapeString(strings.TrimSpace(value) + value))
        '''), [])

    def test_context_method_uses_signature_not_context_variable_name(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.QueryContext(requestContext, "SELECT " + value)
            db.ExecContext(parent, value)
            db.QueryRowContext(deadlineContext, value)
        '''), ["go.taint.sql"] * 3)

    def test_sqlx_destination_is_not_the_query(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.Get(&user, "SELECT " + value)
            db.Select(&users, "SELECT " + value)
        '''), ["go.taint.sql"] * 2)

    def test_sqlx_context_destination_is_not_the_query(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.GetContext(parent, &user, "SELECT " + value)
            db.SelectContext(parent, &users, "SELECT " + value)
        '''), ["go.taint.sql"] * 2)

    def test_bound_parameters_remain_clean_for_each_signature(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.Query("SELECT * FROM users WHERE name = ?", value)
            db.QueryContext(parent, "SELECT * FROM users WHERE name = $1", value)
            db.Get(&user, "SELECT * FROM users WHERE name = ?", value)
            db.Select(&users, "SELECT * FROM users WHERE name = ?", value)
            db.GetContext(parent, &user, "SELECT * FROM users WHERE name = ?", value)
            db.SelectContext(parent, &users, "SELECT * FROM users WHERE name = ?", value)
        '''), [])

    def test_gorm_select_expression_is_not_a_sqlx_destination(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.Select(value).Find(&users)
        '''), ["go.taint.sql"])

    def test_gorm_select_bound_value_remains_clean(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.Select("COALESCE(name, ?)", value).Find(&users)
        '''), [])

    def test_multiline_sink_preserves_its_location(self):
        findings = self.scan('''
            value := r.FormValue("q")
            db.QueryContext(
                parent,
                "SELECT " + value,
            )
        ''')
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["rule"], "go.taint.sql")
        self.assertEqual(findings[0]["line"], 5)

    def test_multiple_sinks_on_one_line_are_not_greedily_merged(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            db.Query("SELECT 1"); db.Query("SELECT " + value); db.Exec(value)
        '''), ["go.taint.sql"] * 2)

    def test_fprintln_is_an_html_output_sink(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            fmt.Fprintln(w, value)
        '''), ["go.taint.xss"])

    def test_member_or_longer_names_are_not_html_sanitizers(self):
        for function in ("fakehtml.EscapeString", "obj.html.EscapeString", "html.EscapeStringCustom"):
            with self.subTest(function=function):
                self.assertEqual(self.rules(f'''
                    value := r.FormValue("q")
                    fmt.Fprint(w, {function}(value))
                '''), ["go.taint.xss"])

    def test_masking_preserves_offsets_and_go_raw_string_semantics(self):
        source = 'value := `a\\`\nnext := "/* text */" // comment\n/* block\nbody */\n'
        masked = taint_go._masked_source(source)
        self.assertEqual(len(masked), len(source))
        self.assertEqual([i for i, ch in enumerate(masked) if ch == '\n'],
                         [i for i, ch in enumerate(source) if ch == '\n'])
        self.assertIn("next :=", masked)
        self.assertNotIn("comment", masked)
        self.assertNotIn("body", masked)

    def test_data_sources_inside_literals_do_not_taint_queries(self):
        self.assertEqual(self.rules('''
            db.Query("SELECT 'r.FormValue(\\"q\\")'")
            db.Exec(`SELECT 'os.Getenv("q")'`)
        '''), [])

    def test_block_comments_do_not_create_flows(self):
        self.assertEqual(self.rules('''
            /*
            value := r.FormValue("q")
            fmt.Fprint(w, value)
            */
        '''), [])

    def test_cross_domain_provenance_is_retained(self):
        findings = self.scan('''
            value := r.FormValue("q")
            escaped := html.EscapeString(value)
            alias := escaped
            db.Query("SELECT " + alias)
        ''')
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["rule"], "go.taint.sql")
        self.assertIn("alias", findings[0]["message"])
        self.assertIn(".FormValue(", findings[0]["message"])

    def test_builtin_selftests(self):
        for name, check in taint_go.SELF_TESTS:
            with self.subTest(name=name):
                check()

    def test_fixed_executable_arguments_are_data_not_shell_source(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            exec.Command("ls", value)
            exec.CommandContext(parent, "printf", "%s", value)
            exec.Command("ls", filepath.Clean(value))
            exec.Command(`echo`, value)
        '''), [])

    def test_dynamic_executable_is_dangerous_even_after_path_clean(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            exec.Command(value, "fixed")
            exec.CommandContext(parent, filepath.Clean(value))
        '''), ["go.taint.command"] * 2)

    def test_shell_code_and_positional_data_are_distinguished(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            exec.Command("/bin/bash", "-lc", value)
            exec.CommandContext(parent, "sh", "-c", value)
            exec.Command("sh", "-c", "printf '%s'", "sh", value)
            exec.Command("sh", "/opt/fixed-script.sh", value)
        '''), ["go.taint.command"] * 2)

    def test_interpreter_code_arguments_remain_dangerous(self):
        for executable, flag in (("python3", "-c"), ("node", "--eval"),
                                 ("ruby", "-e"), ("perl", "-E"), ("php", "-r")):
            with self.subTest(executable=executable):
                self.assertEqual(self.rules(f'''
                    value := r.FormValue("q")
                    exec.Command("{executable}", "{flag}", value)
                '''), ["go.taint.command"])

    def test_dynamic_interpreter_options_and_argv_expansion_are_conservative(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            exec.Command("sh", value, "fixed")
            args := []string{"-c", value}
            exec.Command("sh", args...)
        '''), ["go.taint.command"] * 2)

    def test_command_context_does_not_treat_context_as_code(self):
        self.assertEqual(self.rules('''
            context := r.FormValue("q")
            exec.CommandContext(context, "echo", "fixed")
        '''), [])

    def test_repository_clean_taint_fixture_stays_clean(self):
        path = ROOT / "test-suite/golang/clean/taint_analysis.go"
        self.assertEqual(list(taint_go.run(RunContext(lang="go", files=[path]))), [])

    def test_reassignment_and_statement_order(self):
        self.assertEqual(self.rules('''
            value := "safe"
            fmt.Fprint(w, value)
            value = r.FormValue("q")
            fmt.Fprint(w, value)
            value = "safe"
            fmt.Fprint(w, value)
        '''), ["go.taint.xss"])

    def test_conditional_sanitization_does_not_hide_unsafe_branch(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            if escape { value = html.EscapeString(value) }
            fmt.Fprint(w, value)
        '''), ["go.taint.xss"])

    def test_both_branches_clean_and_return_stops_flow(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            if escape { value = html.EscapeString(value) } else { value = "safe" }
            fmt.Fprint(w, value)
            return
            fmt.Fprint(w, r.FormValue("unreachable"))
        '''), [])

    def test_block_shadowing_and_initializer_reference_outer_value(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            { value := html.EscapeString(value); fmt.Fprint(w, value) }
            fmt.Fprint(w, value)
            trusted := "safe"
            { trusted := r.FormValue("q"); _ = trusted }
            fmt.Fprint(w, trusted)
        '''), ["go.taint.xss"])

    def test_function_parameters_do_not_inherit_another_local(self):
        self.assertEqual(self.scan_source('''
            package main
            func unsafe() { value := r.FormValue("q"); _ = value }
            func safe(value string) { fmt.Fprint(w, value) }
            func main() { safe("constant") }
        '''), [])

    def test_simultaneous_assignment_and_compound_assignment(self):
        self.assertEqual(self.rules('''
            unsafe := r.FormValue("q")
            safe := "constant"
            safe, unsafe = unsafe, safe
            fmt.Fprint(w, unsafe)
            fmt.Fprint(w, safe)
            unsafe += safe
            fmt.Fprint(w, unsafe)
        '''), ["go.taint.xss"] * 2)

    def test_loop_carried_dependency_converges_beyond_seven_rounds(self):
        declarations = "\n".join(f'v{index} := "safe"' for index in range(1, 25))
        propagation = "\n".join(f'v{index} = v{index - 1}' for index in range(24, 0, -1))
        self.assertEqual(self.rules(f'''
            v0 := r.FormValue("q")
            {declarations}
            for keep {{
                fmt.Fprint(w, v24)
                {propagation}
            }}
        '''), ["go.taint.xss"])

    def test_loop_zero_iteration_continue_and_break_paths(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            for keep { value = "safe" }
            fmt.Fprint(w, value)
            value = "safe"
            for keep {
                fmt.Fprint(w, value)
                value = r.FormValue("q")
                continue
                value = "safe"
            }
            for { value = "safe"; break }
            fmt.Fprint(w, value)
        '''), ["go.taint.xss"] * 2)

    def test_source_after_break_cannot_reach_next_iteration(self):
        self.assertEqual(self.rules('''
            value := "safe"
            for keep {
                fmt.Fprint(w, value)
                break
                value = r.FormValue("q")
            }
        '''), [])

    def test_local_helpers_propagate_only_returned_parameters(self):
        findings = self.scan_source('''
            package main
            func selected(first, second string) string { return second }
            func constant(input string) string { return "safe" }
            func handler() {
                value := r.FormValue("q")
                fmt.Fprint(w, selected(value, "safe"))
                fmt.Fprint(w, constant(value))
                fmt.Fprint(w, selected("safe", value))
            }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])
        self.assertIn("selected()", findings[0]["message"])

    def test_local_sanitizer_summary_retains_other_domains(self):
        findings = self.scan_source('''
            package main
            func escaped(value string) string { return html.EscapeString(value) }
            func handler() {
                value := escaped(r.FormValue("q"))
                fmt.Fprint(w, value)
                db.Query(value)
                exec.Command("sh", "-c", value)
            }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.sql", "go.taint.command"])

    def test_helper_sink_summary_reports_unsafe_caller(self):
        findings = self.scan_source('''
            package main
            func render(value string) { fmt.Fprint(w, value) }
            func forward(value string) { render(value) }
            func handler() {
                forward("safe")
                forward(r.FormValue("q"))
                forward(html.EscapeString(r.FormValue("q")))
            }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])
        self.assertEqual(findings[0]["line"], 7)
        self.assertEqual(findings[0]["col"], 5)
        self.assertIn("forward()", findings[0]["message"])
        self.assertIn("render()", findings[0]["message"])

    def test_recursive_helpers_and_named_return(self):
        findings = self.scan_source('''
            package main
            func left(value string) string {
                if done { return value }
                return right(value)
            }
            func right(value string) string { return left(value) }
            func named(value string) (result string) { result = right(value); return }
            func handler() { fmt.Fprint(w, named(r.FormValue("q"))) }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])
        self.assertIn(".FormValue(", findings[0]["message"])

    def test_local_helpers_keep_tuple_result_positions(self):
        findings = self.scan_source('''
            package main
            func pair(value string) (string, string) { return "safe", value }
            func handler() {
                safe, unsafe := pair(r.FormValue("q"))
                fmt.Fprint(w, safe)
                fmt.Fprint(w, unsafe)
            }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])

    def test_variadic_summary_includes_every_argument(self):
        findings = self.scan_source('''
            package main
            func joined(prefix string, values ...string) string { return strings.Join(values, "") }
            func handler() {
                fmt.Fprint(w, joined(r.FormValue("ignored"), "safe"))
                fmt.Fprint(w, joined("safe", "safe", r.FormValue("q")))
            }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])

    def test_helper_initialized_globals_reach_function_sinks(self):
        findings = self.scan_source('''
            package main
            var unsafe = source()
            var safe = html.EscapeString(source())
            func source() string { return os.Getenv("Q") }
            func handler() { fmt.Fprint(w, unsafe); fmt.Fprint(w, safe) }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])

    def test_anonymous_http_handlers_and_goroutines_are_analyzed(self):
        findings = self.scan_source('''
            package main
            var handler = func(w http.ResponseWriter, r *http.Request) {
                fmt.Fprint(w, r.FormValue("q"))
            }
            func main() {
                http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                    fmt.Fprint(w, r.FormValue("q"))
                })
                value := r.FormValue("q")
                go func() { fmt.Fprint(w, value) }()
            }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"] * 3)

    def test_closure_returns_do_not_taint_the_enclosing_function(self):
        findings = self.scan_source('''
            package main
            func safe(value string) string {
                callback := func() string { return value }
                _ = callback
                return "safe"
            }
            func handler() { fmt.Fprint(w, safe(r.FormValue("q"))) }
        ''')
        self.assertEqual(findings, [])

    def test_struct_type_and_field_names_are_not_value_references(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            trusted := struct{value string}{value: "safe"}
            unsafe := struct{value string}{value: value}
            fmt.Fprint(w, trusted.value)
            fmt.Fprint(w, unsafe.value)
        '''), ["go.taint.xss"])

    def test_repository_buggy_taint_fixture_preserves_every_sink(self):
        path = ROOT / "test-suite/golang/buggy/taint_analysis.go"
        findings = list(taint_go.run(RunContext(lang="go", files=[path])))
        self.assertEqual([finding["rule"] for finding in findings],
                         ["go.taint.sql", "go.taint.sql", "go.taint.xss", "go.taint.sql",
                          "go.taint.sql", "go.taint.sql", "go.taint.sql", "go.taint.sql", "go.taint.command"])

    def test_return_sanitizer_cannot_undo_helper_side_effects(self):
        findings = self.scan_source('''
            package main
            func render(value string) string { fmt.Fprint(w, value); return value }
            func handler() { _ = html.EscapeString(render(r.FormValue("q"))) }
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.xss"])

    def test_multiple_init_functions_have_distinct_scopes(self):
        findings = self.scan_source('''
            package main
            func init() { db.Query(os.Getenv("Q")) }
            func init() {}
        ''')
        self.assertEqual([finding["rule"] for finding in findings], ["go.taint.sql"])

    def test_shadowed_sanitizer_package_is_conservative(self):
        self.assertEqual(self.rules('''
            value := r.FormValue("q")
            html := customEscaper
            fmt.Fprint(w, html.EscapeString(value))
        '''), ["go.taint.xss"])


class GoSanitizerImportTests(packages.PackageTestCase):
    def check(self, imports, body, *rules):
        self.source('handler.go', 'package app\n' + imports + '\nfunc h() {\n' + body + '\n}\n')
        findings = self.scan()
        self.assertEqual(sorted(item['rule'] for item in findings),
                         sorted('go.taint.' + rule for rule in rules), findings)

    def test_standard_aliases_clean_html_results_and_assignments(self):
        for path, function in (('html', 'EscapeString'), ('html/template', 'HTMLEscapeString'),
                               ('text/template', 'HTMLEscapeString')):
            with self.subTest(path=path):
                self.check('import safe "' + path + '"',
                           'value := safe.' + function + '(r.FormValue("q"))\n'
                           'fmt.Fprint(w, value)\nfmt.Fprint(w, safe.' + function + '(r.FormValue("q")))')

    def test_import_path_determines_contract_even_with_unusual_local_name(self):
        self.check('import html "text/template"', 'fmt.Fprint(w, html.HTMLEscapeString(r.FormValue("q")))')
        self.check('import template "html"', 'fmt.Fprint(w, template.EscapeString(r.FormValue("q")))')

    def test_same_spelled_custom_packages_do_not_sanitize(self):
        for name, function in (('html', 'EscapeString'), ('template', 'HTMLEscapeString')):
            with self.subTest(name=name):
                self.check('import ' + name + ' "example.test/custom"',
                           'fmt.Fprint(w, ' + name + '.' + function + '(r.FormValue("q")))', 'xss')

    def test_dot_imports_resolve_only_unshadowed_standard_functions(self):
        self.check('import . "html"', 'fmt.Fprint(w, EscapeString(r.FormValue("q")))')
        self.check('import . "text/template"', 'fmt.Fprint(w, HTMLEscapeString(r.FormValue("q")))')
        self.check('import . "html"', 'EscapeString := custom\n'
                   'fmt.Fprint(w, EscapeString(r.FormValue("q")))', 'xss')
        self.check('import (. "html"; . "example.test/custom")',
                   'fmt.Fprint(w, EscapeString(r.FormValue("q")))', 'xss')

    def test_parameter_local_and_type_shadows_remain_conservative(self):
        self.source('helper.go', 'package app\nimport safe "html"\n'
                    'func render(safe Escaper) { fmt.Fprint(w, safe.EscapeString(r.FormValue("q"))) }\n')
        for declaration in ('safe := custom', 'type safe CustomEscaper'):
            with self.subTest(declaration=declaration):
                self.check('import safe "html"', declaration + '\n'
                           'fmt.Fprint(w, safe.EscapeString(r.FormValue("q")))', 'xss', 'xss')

    def test_selector_suffix_boundaries_are_preserved(self):
        for expression, setup in (('obj . safe.EscapeString(value)', ''),
                                  ('safe.EscapeString(value)[1:]', '')):
            with self.subTest(expression=expression):
                self.check('import safe "html"', 'value := r.FormValue("q")\n' + setup + '\n'
                           'fmt.Fprint(w, ' + expression + ')', 'xss')

    def test_escape_remains_specific_to_xss(self):
        self.check('import safe "html"', 'value := safe.EscapeString(r.FormValue("q"))\n'
                   'fmt.Fprint(w, value)\ndb.Query(value)\nexec.Command("sh", "-c", value)', 'sql', 'command')

    def test_argument_sink_effects_and_unsafe_siblings_are_retained(self):
        self.source('helper.go', 'package app\n'
                    'func render(value string) string { fmt.Fprint(w, value); return value }\n')
        self.check('import safe "html"', '_ = safe.EscapeString(render(r.FormValue("q")))\n'
                   'value := r.FormValue("q")\nfmt.Fprint(w, safe.EscapeString(value) + value)', 'xss', 'xss')

    def test_same_alias_and_default_name_are_file_local(self):
        for name in ('safe', 'html'):
            with self.subTest(name=name):
                self.source('a.go', 'package app\nimport ' + name + ' "html"\n'
                            'func a() { fmt.Fprint(w, ' + name + '.EscapeString(r.FormValue("q"))) }\n')
                self.source('b.go', 'package app\nimport ' + name + ' "example.test/custom"\n'
                            'func b() { fmt.Fprint(w, ' + name + '.EscapeString(r.FormValue("q"))) }\n')
                self.assert_hits([('b.go', 3, 'go.taint.xss')])
                self.assert_hits([('b.go', 3, 'go.taint.xss')], selected=[self.sources['b.go'], self.sources['a.go']])

    def test_package_helper_summaries_keep_their_import_identity(self):
        self.source('safe.go', 'package app\nimport safe "html"\n'
                    'func clean(value string) string { return safe.EscapeString(value) }\n')
        self.source('unsafe.go', 'package app\nimport html "example.test/custom"\n'
                    'func unsafe(value string) string { return html.EscapeString(value) }\n')
        self.check('', 'fmt.Fprint(w, clean(r.FormValue("q")))\n'
                   'fmt.Fprint(w, unsafe(r.FormValue("q")))', 'xss')

    def test_closure_and_global_initializers_use_original_file_imports(self):
        self.source('a.go', 'package app\nimport safe "example.test/custom"\n'
                    'var result = fmt.Fprint(w, clean(r.FormValue("q")))\n')
        self.source('b.go', 'package app\nimport safe "html"\n'
                    'func clean(value string) string { return safe.EscapeString(value) }\n'
                    'func h() {\nvalue := func() string { return safe.EscapeString(r.FormValue("q")) }()\n'
                    'fmt.Fprint(w, value)\n}\n')
        self.assert_hits([])

    def test_import_decoys_and_blank_imports_do_not_grant_sanitization(self):
        for declaration in ('import html "example.test/custom"', 'import _ "html"'):
            with self.subTest(declaration=declaration):
                self.check(declaration + '\n// import "html"\nconst decoy = `import "html"`',
                           'fmt.Fprint(w, html.EscapeString(r.FormValue("q")))', 'xss')
        self.check(r'import safe "\x68tml"', 'fmt.Fprint(w, safe.EscapeString(r.FormValue("q")))')


class SavedNativeValueOracleTests(packages.PackageTestCase):
    """Independent source oracles for native function values, with exact sinks.

    Capturing a Go function preserves that function's behavior; changing an
    import alias later in another file cannot change the captured value. A
    possible pass-through alternative, however, cannot prove HTML escaping.
    """

    def check_source(self, imports, body, expected, helpers=''):
        source = 'package app\n' + imports + '\n' + helpers + '\nfunc h() {\n' + body + '\n}\n'
        self.source('handler.go', source)
        sites = []
        for marker, rule in expected:
            lines = [line for line, text in enumerate(source.splitlines(), 1) if marker in text]
            self.assertEqual(len(lines), 1, (marker, source))
            sites.append(('handler.go', lines[0], 'go.taint.' + rule))
        return self.assert_hits(sites)

    def test_saved_escapers_keep_only_the_html_domain_clean(self):
        for package, member in (('html', 'EscapeString'), ('html/template', 'HTMLEscapeString'),
                                ('text/template', 'HTMLEscapeString')):
            with self.subTest(package=package):
                self.check_source('import safe "' + package + '"',
                                  'escape := safe.' + member + '\n'
                                  'alias := escape\nvalue := alias(r.FormValue("q"))\n'
                                  'fmt.Fprint(w, value) // escaped output\n'
                                  'db.Query(value) // sql-site\n'
                                  'exec.Command("sh", "-c", value) // command-site',
                                  (('sql-site', 'sql'), ('command-site', 'command')))

    def test_saved_escaper_does_not_hide_argument_effects_or_raw_siblings(self):
        self.check_source('import "html"',
                          'escape := html.EscapeString\nvalue := r.FormValue("q")\n'
                          '_ = escape(render(value)) // effect-site\n'
                          'fmt.Fprint(w, escape(value) + value) // sibling-site',
                          (('effect-site', 'xss'), ('sibling-site', 'xss')),
                          'func render(value string) string { fmt.Fprint(w, value); return value }')

    def test_captured_function_survives_package_name_shadowing(self):
        self.check_source('import "html"',
                          'escape := html.EscapeString\n'
                          'html := fake\n_ = html\nfmt.Fprint(w, escape(r.FormValue("q")))', ())

    def test_callable_reassignment_and_scope_restore_do_not_keep_stale_sanitization(self):
        self.check_source('import "html"',
                          'escape := html.EscapeString\nvalue := r.FormValue("q")\n'
                          '{ escape := passthrough; fmt.Fprint(w, escape(value)) } // shadow-site\n'
                          'fmt.Fprint(w, escape(value)) // restored outer binding\n'
                          'escape = passthrough\nfmt.Fprint(w, escape(value)) // overwrite-site',
                          (('shadow-site', 'xss'), ('overwrite-site', 'xss')),
                          'func passthrough(value string) string { return value }')

    def test_function_choice_sanitizes_only_when_every_alternative_escapes(self):
        helpers = 'func passthrough(value string) string { return value }'
        self.check_source('import ("html"; "text/template")',
                          'escape := html.EscapeString\n'
                          'if choice { escape = template.HTMLEscapeString }\n'
                          'fmt.Fprint(w, escape(r.FormValue("q")))', (), helpers)
        self.check_source('import "html"',
                          'escape := html.EscapeString\nif choice { escape = passthrough }\n'
                          'fmt.Fprint(w, escape(r.FormValue("q"))) // maybe-raw',
                          (('maybe-raw', 'xss'),), helpers)

    def test_lookalike_and_dot_imports_keep_their_actual_identity(self):
        self.check_source('import html "example.test/passthrough"',
                          'escape := html.EscapeString\n'
                          'fmt.Fprint(w, escape(r.FormValue("q"))) // raw-site',
                          (('raw-site', 'xss'),))
        self.check_source('import . "html"',
                          'escape := EscapeString\nfmt.Fprint(w, escape(r.FormValue("q")))', ())

    def test_saved_decoding_and_reading_preserve_payload_but_not_error_slots(self):
        for package in ('encoding/json', 'encoding/xml'):
            with self.subTest(package=package):
                self.check_source('import (codec "' + package + '"; "io")',
                                  'read := io.ReadAll\nraw, readErr := read(r.Body)\n'
                                  'decode := codec.Unmarshal\nvar p Payload\n'
                                  'decodeErr := decode(raw, &p)\n'
                                  'db.Query(p.SQL) // payload-site\n'
                                  'db.Query(readErr.Error())\ndb.Query(decodeErr.Error())\n'
                                  'db.Query("SELECT $1", p.SQL)',
                                  (('payload-site', 'sql'),))

    def test_saved_decoder_factory_retains_the_reader(self):
        for package in ('encoding/json', 'encoding/xml'):
            with self.subTest(package=package):
                self.check_source('import codec "' + package + '"',
                                  'makeDecoder := codec.NewDecoder\n'
                                  'decoder := makeDecoder(r.Body)\nvar p Payload\n'
                                  'err := decoder.Decode(&p)\ndb.Query(p.SQL) // payload-site\n'
                                  'db.Query(err.Error())', (('payload-site', 'sql'),))

    def test_clean_saved_decoder_and_escaped_outputs_stay_clean(self):
        self.check_source('import ("encoding/json"; "strings"; "html")',
                          'makeDecoder := json.NewDecoder\n'
                          'decoder := makeDecoder(strings.NewReader(`{"SQL":"SELECT 1"}`))\n'
                          'var p Payload\ndecoder.Decode(&p)\ndb.Query(p.SQL)\n'
                          'escape := html.EscapeString\nfmt.Fprint(w, escape(r.FormValue("q")))', ())

    def test_decoder_choice_keeps_possible_output_parameter_writes(self):
        self.check_source('import ("encoding/json"; "encoding/xml")',
                          'decode := json.Unmarshal\nif choice { decode = xml.Unmarshal }\n'
                          'var p Payload\ndecode([]byte(r.FormValue("body")), &p)\n'
                          'db.Query(p.SQL) // possible-write', (('possible-write', 'sql'),))

    def test_saved_operations_in_local_helpers_keep_file_authority(self):
        self.source('helper.go', 'package app\nimport ("encoding/json"; "html")\n'
                    'func decode(raw []byte, out *Payload) { call := json.Unmarshal; call(raw, out) }\n'
                    'func escaped(value string) string { call := html.EscapeString; return call(value) }\n')
        self.check_source('import html "example.test/passthrough"',
                          'var p Payload\ndecode([]byte(r.FormValue("body")), &p)\n'
                          'db.Query(p.SQL) // helper-write\n'
                          'fmt.Fprint(w, escaped(r.FormValue("q")))', (('helper-write', 'sql'),))


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for real scanner tests')
class GoSanitizerRunnerTests(unittest.TestCase):
    def test_actual_json_and_sarif_use_imported_sanitizer_identity(self):
        cases = [
            ('html-alias', 'import safe "html"', '',
             'fmt.Fprint(w, safe.EscapeString(r.FormValue("q")))', set()),
            ('html-template-alias', 'import safe "html/template"', '',
             'fmt.Fprint(w, safe.HTMLEscapeString(r.FormValue("q")))', set()),
            ('text-template-alias', 'import safe "text/template"', '',
             'fmt.Fprint(w, safe.HTMLEscapeString(r.FormValue("q")))', set()),
            ('html-dot', 'import . "html"', '', 'fmt.Fprint(w, EscapeString(r.FormValue("q")))', set()),
            ('html-lookalike', 'import html "example.test/custom"', '',
             'fmt.Fprint(w, html.EscapeString(r.FormValue("q")))', {'xss'}),
            ('template-lookalike', 'import template "example.test/custom"', '',
             'fmt.Fprint(w, template.HTMLEscapeString(r.FormValue("q")))', {'xss'}),
            ('html-domains', 'import safe "html"', '',
             'value := safe.EscapeString(r.FormValue("q")); fmt.Fprint(w, value); '
             'db.Query(value); exec.Command("sh", "-c", value)', {'sql', 'command'}),
            ('argument-effect', 'import safe "html"',
             'func render(value string) string { fmt.Fprint(w, value); return value }',
             '_ = safe.EscapeString(render(r.FormValue("q")))', {'xss'}),
            ('saved-escape-domains', 'import "html"', '',
             'escape := html.EscapeString; value := escape(r.FormValue("q")); '
             'fmt.Fprint(w, value); db.Query(value); exec.Command("sh", "-c", value)', {'sql', 'command'}),
            ('saved-escape-choice', 'import ("html"; "text/template")', '',
             'escape := html.EscapeString; if choice { escape = template.HTMLEscapeString }; '
             'fmt.Fprint(w, escape(r.FormValue("q")))', set()),
            ('saved-escape-unknown-choice', 'import "html"',
             'func passthrough(value string) string { return value }',
             'escape := html.EscapeString; if choice { escape = passthrough }; '
             'fmt.Fprint(w, escape(r.FormValue("q")))', {'xss'}),
            ('saved-argument-effect', 'import "html"',
             'func render(value string) string { fmt.Fprint(w, value); return value }',
             'escape := html.EscapeString; _ = escape(render(r.FormValue("q")))', {'xss'}),
        ]
        for name, imports, helper, body, expected in cases:
            for output in ('json', 'sarif'):
                with self.subTest(case=name, format=output), tempfile.TemporaryDirectory(prefix='ubs-go-sanitizer-') as tmp:
                    project = Path(tmp)
                    (project / 'handler.go').write_text('package app\n' + imports + '\nfunc h() { ' + body + ' }\n')
                    (project / 'helper.go').write_text('package app\n' + helper + '\n')
                    result = subprocess.run([str(ROOT / 'ubs'), str(project), '--only=golang', '--ci',
                                             '--format=' + output], cwd=project, capture_output=True, text=True,
                                            timeout=180, env=dict(os.environ, UBS_NO_AUTO_UPDATE='1',
                                                                  UBS_CACHE_DIR=str(project / 'cache')))
                    (project / 'stdout.log').write_text(result.stdout)
                    (project / 'stderr.log').write_text(result.stderr)
                    self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    if output == 'json':
                        self.assertEqual(report['status'], 'ok', report)
                        rows = [row for scanner in report['scanners'] for row in scanner.get('findings', [])]
                        rules = {row.get('rule', row.get('rule_id', '')) for row in rows}
                    else:
                        rows = [row for run in report['runs'] for row in run.get('results', [])]
                        rules = {row.get('ruleId', '') for row in rows}
                    taint = {rule.rsplit('.', 1)[-1] for rule in rules
                             if rule.startswith(('go.taint.', 'golang.taint.'))}
                    self.assertEqual(taint, expected, report)
                    print('GO_SANITIZER_E2E_PASS', name, output, sorted(taint), flush=True)


@unittest.skipUnless(os.environ.get('UBS_TAINT_NATIVE_GO') == '1',
                     'set UBS_TAINT_NATIVE_GO=1 to compile the native callable witness')
class NativeCallableRuntimeTests(unittest.TestCase):
    def test_compiled_saved_functions_match_analyzer_contracts(self):
        source = textwrap.dedent('''\
            package main
            import (
                "encoding/json"
                "encoding/xml"
                "fmt"
                "html"
                "io"
                "net/http"
                "net/http/httptest"
                "net/url"
                "os"
                "strings"
                "text/template"
            )
            type Payload struct { SQL string; HTML string }
            type database struct { Queries []string }
            func (db *database) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func raw(value string) string { return value }
            func escaped(r *http.Request, w http.ResponseWriter, choose bool) {
                escape := html.EscapeString
                if choose { escape = template.HTMLEscapeString }
                fmt.Fprint(w, escape(r.FormValue("q")))
            }
            func snapshot(r *http.Request, w http.ResponseWriter) {
                escape := html.EscapeString
                saved := escape
                escape = raw
                fmt.Fprint(w, saved(r.FormValue("q")))
                fmt.Fprint(w, escape(r.FormValue("q"))) // raw-output
            }
            func unmarshaled(r *http.Request, db *database, w http.ResponseWriter) {
                read := io.ReadAll
                decode := json.Unmarshal
                data, readErr := read(r.Body)
                if readErr != nil { panic(readErr) }
                var p Payload
                decodeErr := decode(data, &p)
                if decodeErr != nil { panic(decodeErr) }
                db.Query(p.SQL) // decoded-query
                db.Query("SELECT $1", p.SQL)
                escape := html.EscapeString
                fmt.Fprint(w, escape(p.HTML))
            }
            func factory(r *http.Request, db *database) {
                makeDecoder := xml.NewDecoder
                decoder := makeDecoder(r.Body)
                var p Payload
                if err := decoder.Decode(&p); err != nil { panic(err) }
                db.Query(p.SQL) // factory-query
            }
            func main() {
                value := "<b>request</b>"
                req := httptest.NewRequest("GET", "/?q=" + url.QueryEscape(value), nil)
                a, b, c := httptest.NewRecorder(), httptest.NewRecorder(), httptest.NewRecorder()
                escaped(req, a, false)
                escaped(req, b, true)
                snapshot(req, c)
                body, err := json.Marshal(Payload{SQL: "SELECT request", HTML: value})
                if err != nil { panic(err) }
                db := &database{}
                rendered := httptest.NewRecorder()
                unmarshaled(httptest.NewRequest("POST", "/", strings.NewReader(string(body))), db, rendered)
                factory(httptest.NewRequest("POST", "/", strings.NewReader("<Payload><SQL>SELECT xml</SQL></Payload>")), db)
                observed := map[string]any{
                    "html": a.Body.String(), "template": b.Body.String(),
                    "snapshot": c.Body.String(), "decoded_html": rendered.Body.String(), "queries": db.Queries,
                }
                if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil { panic(err) }
            }
        ''')
        with tempfile.TemporaryDirectory(prefix='ubs-go-native-callable-') as tmp:
            path = Path(tmp) / 'main.go'
            path.write_text(source, encoding='utf-8')
            native = subprocess.run(['go', 'run', str(path)], cwd=tmp, text=True,
                                    capture_output=True, timeout=180,
                                    env=dict(os.environ, GOWORK='off', GO111MODULE='off', GOTOOLCHAIN='local'))
            self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
            self.assertEqual(json.loads(native.stdout), {
                'html': '&lt;b&gt;request&lt;/b&gt;', 'template': '&lt;b&gt;request&lt;/b&gt;',
                'snapshot': '&lt;b&gt;request&lt;/b&gt;<b>request</b>',
                'decoded_html': '&lt;b&gt;request&lt;/b&gt;',
                'queries': ['SELECT request', 'SELECT $1', 'SELECT xml'],
            })
            findings = list(taint_go.run(RunContext(lang='go', files=[path])))
            expected = {
                (number, 'go.taint.' + rule)
                for number, line in enumerate(source.splitlines(), 1)
                for marker, rule in [('raw-output', 'xss'), ('decoded-query', 'sql'), ('factory-query', 'sql')]
                if '// ' + marker in line
            }
            self.assertEqual({(row['line'], row['rule']) for row in findings}, expected, findings)
            self.assertEqual(len(findings), len(expected), findings)


if __name__ == "__main__":
    unittest.main()
