"""Go sanitizer-domain and SQL argument-position regression controls.

Exercise the shipped analyzer on source files, not substitute matchers. These
cases deliberately pair dangerous query/command uses with escaped HTML and
bound SQL values so a blanket increase in critical findings cannot pass.
"""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
