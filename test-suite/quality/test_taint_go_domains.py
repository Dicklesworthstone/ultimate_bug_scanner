"""Go sanitizer-domain and SQL argument-position regression controls.

Exercise the shipped analyzer on source files, not substitute matchers. These
cases deliberately pair dangerous query/command uses with escaped HTML and
bound SQL values so a blanket increase in critical findings cannot pass.
"""
from __future__ import annotations

import json
import os
import re
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


class GoEnvironmentSourceTests(unittest.TestCase):
    """Environment values are sources; function identities and presence are not.

    Native import identity, not an identifier spelling, selects the contract.
    Fixtures are retained for baseline/candidate and public scanner replay.
    """

    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.previous_failures = len(result.failures) + len(result.errors)
        print(f"[{self.id()}] RUN", flush=True)
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='go-environment-', dir=artifacts))

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.failures) + len(result.errors) > self.previous_failures
        state = 'FAIL' if failed else 'PASS'
        print(f"[{self.id()}] {state} ({time.monotonic() - self.started:.3f}s)", flush=True)

    def check_source(self, imports, body, expected=(), helpers=''):
        source = 'package app\n' + imports + '\n' + helpers + '\nfunc h() {\n' + body + '\n}\n'
        folder = Path(tempfile.mkdtemp(prefix='source-', dir=self.root))
        path = folder / 'handler.go'
        path.write_text(source, encoding='utf-8')
        findings = list(taint_go.run(RunContext(lang='go', files=[path])))
        sites = []
        for marker, rule, sink in expected:
            lines = [(number, line) for number, line in enumerate(source.splitlines(), 1)
                     if '// ' + marker in line]
            self.assertEqual(len(lines), 1, (marker, source))
            number, line = lines[0]
            sites.append((number, line.index(sink) + 1, 'go.taint.' + rule))
        actual = [(finding['line'], finding['col'], finding['rule']) for finding in findings]
        (folder / 'findings.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        self.assertEqual(sorted(actual), sorted(sites), (source, findings))
        return findings

    def test_direct_and_aliased_getenv_reach_every_security_domain(self):
        for name in ('os', 'environment'):
            with self.subTest(name=name):
                self.check_source('import ' + name + ' "os"',
                                  'value := ' + name + '.Getenv("UBS_INPUT")\n'
                                  'db.Query(value) // query\n'
                                  'fmt.Fprint(w, value) // output\n'
                                  'exec.Command("sh", "-c", value) // command',
                                  (('query', 'sql', 'db.Query'), ('output', 'xss', 'fmt.Fprint'),
                                   ('command', 'command', 'exec.Command')))

    def test_lookupenv_preserves_payload_and_presence_result_positions(self):
        for name in ('os', 'environment'):
            with self.subTest(name=name):
                self.check_source('import ' + name + ' "os"',
                                  'value, present := ' + name + '.LookupEnv("UBS_INPUT")\n'
                                  'db.Query(value) // query\n'
                                  'fmt.Fprint(w, present)\n'
                                  'db.Query(fmt.Sprint(present))',
                                  (('query', 'sql', 'db.Query'),))

    def test_dot_imports_and_escaped_import_paths_keep_native_authority(self):
        self.check_source('import . "os"',
                          'value, present := LookupEnv("UBS_INPUT")\n'
                          'db.Query(Getenv("UBS_INPUT") + value) // query\nfmt.Fprint(w, present)',
                          (('query', 'sql', 'db.Query'),))
        for path in ('`os`', '"\\x6fs"'):
            with self.subTest(path=path):
                self.check_source('import environment ' + path,
                                  'db.Query(environment.Getenv("UBS_INPUT")) // query',
                                  (('query', 'sql', 'db.Query'),))

    def test_local_helper_returns_keep_lookupenv_result_slots(self):
        self.check_source('import environment "os"',
                          'value, present := read("UBS_INPUT")\n'
                          'db.Query(value) // query\nfmt.Fprint(w, present)',
                          (('query', 'sql', 'db.Query'),),
                          'func read(key string) (string, bool) { return environment.LookupEnv(key) }')

    def test_saved_function_identity_survives_rebinding_and_name_shadowing(self):
        self.check_source('import "os"',
                          'read := os.Getenv\nsaved := read\nread = constant\n'
                          'os := unrelated\n_ = os\n'
                          'db.Query(saved("UBS_INPUT")) // saved\ndb.Query(read("UBS_INPUT"))',
                          (('saved', 'sql', 'db.Query'),),
                          'func constant(key string) string { return "SELECT 1" }')

    def test_saved_lookupenv_retains_clean_presence(self):
        self.check_source('import environment "os"',
                          'read := environment.LookupEnv\nalias := read\n'
                          'value, present := alias("UBS_INPUT")\n'
                          'fmt.Fprint(w, value) // output\nfmt.Fprint(w, present)',
                          (('output', 'xss', 'fmt.Fprint'),))

    def test_selected_helper_arguments_and_returned_callables_keep_sources(self):
        self.check_source('import environment "os"',
                          'read := keep(environment.Getenv)\n'
                          'db.Query(invoke(read, "UBS_INPUT")) // query\n'
                          'lookup := lookupReader()\nvalue, present := lookup("UBS_INPUT")\n'
                          'fmt.Fprint(w, value) // output\nfmt.Fprint(w, present)',
                          (('query', 'sql', 'db.Query'), ('output', 'xss', 'fmt.Fprint')),
                          'func keep(read func(string) string) func(string) string { return read }\n'
                          'func invoke(read func(string) string, key string) string { return read(key) }\n'
                          'func lookupReader() func(string) (string, bool) { return environment.LookupEnv }')

    def test_function_reference_is_not_environment_contents(self):
        self.check_source('import "os"',
                          'get := os.Getenv\nlookup := os.LookupEnv\n'
                          'fmt.Fprint(w, get)\nfmt.Fprint(w, lookup)\n'
                          'fmt.Fprint(w, os.Getenv)\nfmt.Fprint(w, os.LookupEnv)')

    def test_lookalike_packages_do_not_invent_environment_sources(self):
        for name, package in (('os', 'example.test/settings'), ('os', 'example.test/os'),
                              ('environment', 'example.test/os')):
            with self.subTest(name=name, package=package):
                self.check_source('import ' + name + ' "' + package + '"',
                                  'db.Query(' + name + '.Getenv("UBS_INPUT"))\n'
                                  'value, present := ' + name + '.LookupEnv("UBS_INPUT")\n'
                                  'fmt.Fprint(w, value, present)')

    def test_local_and_parameter_shadows_do_not_borrow_os_authority(self):
        self.check_source('import "os"',
                          'os := settings\ndb.Query(os.Getenv("UBS_INPUT"))')
        self.check_source('import "os"', '', helpers=
                          'func read(os Settings) { db.Query(os.Getenv("UBS_INPUT")) }')
        self.check_source('import . "os"',
                          'Getenv := constant\ndb.Query(Getenv("UBS_INPUT"))', helpers=
                          'func constant(key string) string { return "SELECT 1" }')

    def test_dot_import_ambiguity_does_not_grant_native_contract(self):
        self.check_source('import (. "os"; . "example.test/settings")',
                          'value, present := LookupEnv("UBS_INPUT")\n'
                          'db.Query(Getenv("UBS_INPUT"))\nfmt.Fprint(w, value, present)')

    def test_overwrites_and_real_sink_specific_controls_stay_clean(self):
        self.check_source('import (environment "os"; "html")',
                          'value := environment.Getenv("UBS_INPUT")\n'
                          'db.Query("SELECT $1", value)\n'
                          'exec.Command("printf", "%s", value)\n'
                          'escaped := html.EscapeString(value)\nfmt.Fprint(w, escaped)\n'
                          'db.Query(escaped) // escaped-sql\n'
                          'value = "SELECT 1"\ndb.Query(value)',
                          (('escaped-sql', 'sql', 'db.Query'),))

    def test_native_source_alternative_cannot_be_erased_by_an_escaper(self):
        self.check_source('import (environment "os"; "html")',
                          'read := environment.Getenv\nif choice { read = html.EscapeString }\n'
                          'value := read("UBS_INPUT")\n'
                          'db.Query(value) // query\nfmt.Fprint(w, value) // output',
                          (('query', 'sql', 'db.Query'), ('output', 'xss', 'fmt.Fprint')))

    def test_native_source_alternative_survives_unknown_function_join(self):
        self.check_source('import environment "os"',
                          'read := environment.Getenv\nif choice { read = constant }\n'
                          'db.Query(read("UBS_INPUT")) // query',
                          (('query', 'sql', 'db.Query'),),
                          'func constant(key string) string { return "SELECT 1" }')

    def test_parenthesized_native_and_captured_calls_retain_sources(self):
        self.check_source('import environment "os"',
                          'read := environment.Getenv\n'
                          'db.Query((environment.Getenv)("UBS_INPUT")) // direct\n'
                          'db.Query(((read))("UBS_INPUT")) // captured\n'
                          'value, present := (environment.LookupEnv)("UBS_INPUT")\n'
                          'db.Query(value) // lookup\nfmt.Fprint(w, present)',
                          (('direct', 'sql', 'db.Query'), ('captured', 'sql', 'db.Query'),
                           ('lookup', 'sql', 'db.Query')))

    def test_argument_effects_are_preserved_when_only_presence_is_consumed(self):
        self.check_source('import environment "os"',
                          'read := environment.LookupEnv\n'
                          '_, present := read(render(r.FormValue("q"))) // effect\n'
                          'fmt.Fprint(w, present)', (('effect', 'xss', 'render'),),
                          'func render(value string) string { fmt.Fprint(w, value); return "UBS_INPUT" }')

    def test_import_identity_is_file_local_across_package_helpers(self):
        first = self.root / 'first.go'
        second = self.root / 'second.go'
        first.write_text('package app\nimport environment "os"\n'
                         'func source() string { return environment.Getenv("UBS_INPUT") }\n',
                         encoding='utf-8')
        second.write_text('package app\nimport environment "example.test/settings"\n'
                          'func h() {\ndb.Query(source())\n'
                          'db.Query(environment.Getenv("UBS_INPUT"))\n}\n', encoding='utf-8')
        findings = list(taint_go.run(RunContext(lang='go', files=[first, second])))
        self.assertEqual([(row['path'], row['line'], row['col'], row['rule']) for row in findings],
                         [(str(second), 4, 1, 'go.taint.sql')], findings)
        self.assertEqual(list(taint_go.run(RunContext(lang='go', files=[second]))), [])

    def test_literals_comments_and_unrelated_field_names_do_not_create_sources(self):
        self.check_source('import "os"',
                          '// os.Getenv("UBS_INPUT")\n'
                          'db.Query(`os.Getenv("UBS_INPUT")`)\n'
                          'record := struct{Getenv string}{Getenv: "fixed"}\n'
                          'fmt.Fprint(w, record.Getenv)')

    def test_long_masked_literals_preserve_grouped_environment_reads(self):
        # A large inert literal must not turn native-call discovery quadratic
        # or hide a real source after the masked span.
        self.check_source('import environment "os"',
                          'db.Query(`' + 'fixed ' * 25000 + '`)\n'
                          'db.Query(((environment.Getenv))("UBS_INPUT")) // query',
                          (('query', 'sql', 'db.Query'),))

    def test_grouped_lookup_results_keep_payload_and_presence_slots(self):
        for expression in ('(environment.LookupEnv("UBS_INPUT"))',
                           '((saved("UBS_INPUT")))',
                           '(lookup("UBS_INPUT"))'):
            with self.subTest(expression=expression):
                self.check_source('import environment "os"',
                                  'saved := environment.LookupEnv\n'
                                  'value, present := ' + expression + '\n'
                                  'db.Query(value) // query\n'
                                  'fmt.Fprint(w, present)\n'
                                  'db.Query(fmt.Sprint(present))',
                                  (('query', 'sql', 'db.Query'),),
                                  'func lookup(key string) (string, bool) { '
                                  'return ((environment.LookupEnv(key))) }')

    def test_grouped_reader_results_keep_payload_and_error_slots(self):
        self.check_source('import reader "io"',
                          'payload, err := (reader.ReadAll(r.Body))\n'
                          'db.Query(string(payload)) // direct\n'
                          'fmt.Fprint(w, err)\n'
                          'other, failure := ((collect(r.Body)))\n'
                          'db.Query(string(other)) // helper\n'
                          'fmt.Fprint(w, failure)',
                          (('direct', 'sql', 'db.Query'), ('helper', 'sql', 'db.Query')),
                          'func collect(body reader.Reader) ([]byte, error) { '
                          'return ((reader.ReadAll(body))) }')

    def test_immediate_closure_can_install_an_environment_getter(self):
        self.check_source('import (environment "os"; "html")',
                          'read := html.EscapeString\n'
                          'func() { read = environment.Getenv }()\n'
                          'fmt.Fprint(w, read("UBS_INPUT")) // output',
                          (('output', 'xss', 'fmt.Fprint'),))

    def test_argument_effects_keep_new_possible_environment_getters(self):
        self.check_source('import (environment "os"; "html")',
                          'read := html.EscapeString\n'
                          'fmt.Fprint(w, read(func() string { '
                          'read = environment.Getenv; return "UBS_INPUT" }())) // output',
                          (('output', 'xss', 'fmt.Fprint'),))

    def test_immediate_closure_arguments_keep_getter_identity_without_handle_taint(self):
        self.check_source('import environment "os"',
                          'func(read func(string) string) {\n'
                          'db.Query(read("QUERY")) // query\n'
                          'fmt.Fprint(w, read)\n'
                          '}(environment.Getenv)',
                          (('query', 'sql', 'db.Query'),))
        self.check_source('import environment "os"',
                          'func(read func(string) (string, bool)) {\n'
                          'value, present := read("QUERY")\n'
                          'db.Query(value) // query\n'
                          'fmt.Fprint(w, present, read)\n'
                          '}(environment.LookupEnv)',
                          (('query', 'sql', 'db.Query'),))

    def test_argument_closure_getter_replacement_is_explicitly_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit

        helpers = 'func constant(key string) string { return "SELECT 1" }'
        with self.assertRaisesRegex(AnalysisLimit, 'environment callable replacement during argument evaluation'):
            self.check_source('import "os"',
                              'read := os.Getenv\n'
                              'db.Query(read(func() string { read = constant; return "Q" }()))',
                              helpers=helpers)
        self.check_source('import "os"',
                          'read := os.Getenv\nfunc() { read = constant }()\n'
                          'db.Query(read("Q"))', helpers=helpers)
        self.check_source('import "os"',
                          'read := os.Getenv\nsaved := read\n'
                          'db.Query(saved(func() string { read = constant; return "Q" }())) // query',
                          (('query', 'sql', 'db.Query'),), helpers=helpers)

    def test_pointer_assignment_keeps_getters_separate_from_inert_handles(self):
        self.check_source('import "os"',
                          'read := constant\nptr := &read\n*ptr = os.Getenv\n'
                          'fmt.Fprint(w, read)\ndb.Query(read("QUERY")) // query\n'
                          '*ptr = constant\ndb.Query(read("QUERY"))',
                          (('query', 'sql', 'db.Query'),),
                          'func constant(key string) string { return "SELECT 1" }')
        self.check_source('import "os"',
                          'read := constant\nptr := &read\n*ptr = os.LookupEnv\n'
                          'value, present := read("QUERY")\n'
                          'db.Query(value) // query\nfmt.Fprint(w, present, read)',
                          (('query', 'sql', 'db.Query'),),
                          'func constant(key string) (string, bool) { return "SELECT 1", true }')

    def test_helper_output_parameters_keep_possible_getter_identities(self):
        self.check_source('import "os"',
                          'read := constant\nforward(&read)\n'
                          'fmt.Fprint(w, read)\ndb.Query(read("QUERY")) // query',
                          (('query', 'sql', 'db.Query'),),
                          'func constant(key string) string { return "SELECT 1" }\n'
                          'func install(read *func(string) string) { *read = os.Getenv }\n'
                          'func forward(read *func(string) string) { install(read) }')
        self.check_source('import "os"',
                          'read := constant\ninstall(&read)\n'
                          'value, present := read("QUERY")\n'
                          'db.Query(value) // query\nfmt.Fprint(w, present, read)',
                          (('query', 'sql', 'db.Query'),),
                          'func constant(key string) (string, bool) { return "SELECT 1", true }\n'
                          'func install(read *func(string) (string, bool)) {\n'
                          '  if choice { *read = os.LookupEnv }\n}')

    def test_immediate_closure_cell_writes_preserve_getters_and_clean_overwrites(self):
        self.check_source('import "os"',
                          'read := constant\nfunc() { read = os.Getenv }()\n'
                          'db.Query(read("QUERY")) // query\n'
                          'func() { read = constant }()\n'
                          'db.Query(read("QUERY"))\nfmt.Fprint(w, read)',
                          (('query', 'sql', 'db.Query'),),
                          'func constant(key string) string { return "SELECT 1" }')

    def test_getter_containers_refuse_unmodeled_callable_storage(self):
        from ubs_core.taint_flow import AnalysisLimit

        containers = (
            'readers := []func(string) string{os.Getenv}\ndb.Query(readers[0]("Q"))',
            'readers := map[string]func(string) string{"read": os.Getenv}\n'
            'db.Query(readers["read"]("Q"))',
            'reader := struct{ Read func(string) string }{Read: os.Getenv}\n'
            'db.Query(reader.Read("Q"))',
            'saved := os.Getenv\nreaders := []func(string) string{saved}\n'
            'db.Query(readers[0]("Q"))',
            'readers := []func(string) string{source()}\ndb.Query(readers[0]("Q"))',
            'readers := []func(string) string{}\nreaders = append(readers, os.Getenv)\n'
            'db.Query(readers[0]("Q"))',
            'readers := []func(string) string{}\nreaders = keep(append(readers, source()))\n'
            'db.Query(readers[0]("Q"))',
            'readers := []func(string) string{constant}\nreaders[0] = os.Getenv\n'
            'db.Query(readers[0]("Q"))',
            'readers := map[string]func(string) string{}\nreaders["read"] = os.Getenv\n'
            'db.Query(readers["read"]("Q"))',
            'saved := os.Getenv\nreaders := []func(string) string{constant}\nreaders[0] = saved\n'
            'db.Query(readers[0]("Q"))',
            'readers := []func(string) string{constant}\nreaders[0] = source()\n'
            'db.Query(readers[0]("Q"))',
            'readers := []func(string) string{constant}\nptr := &readers[0]\n*ptr = os.Getenv\n'
            'db.Query(readers[0]("Q"))',
            'readers := []func(string) string{constant}\ninstall(&readers[0])\n'
            'db.Query(readers[0]("Q"))',
            'var reader Reader\nreader.Read = os.Getenv\ndb.Query(reader.Read("Q"))',
            'var reader Reader\ninstall(&reader.Read)\ndb.Query(reader.Read("Q"))',
        )
        helpers = ('func constant(key string) string { return "SELECT 1" }\n'
                   'func source() func(string) string { return os.Getenv }\n'
                   'func install(read *func(string) string) { *read = os.Getenv }')
        for body in containers:
            with self.subTest(body=body), self.assertRaisesRegex(
                    AnalysisLimit, 'environment callable.*(?:storage|transport)'):
                self.check_source('import "os"', body, helpers=helpers)

    def test_eager_environment_contents_and_constant_function_containers_remain_supported(self):
        self.check_source('import "os"',
                          'values := []string{os.Getenv("Q")}\ndb.Query(values[0]) // query\n'
                          'readers := []func(string) string{constant}\n'
                          'db.Query(readers[0]("Q"))\n'
                          'values = append(values, os.Getenv("Q"))\ndb.Query(values[1]) // appended',
                          (('query', 'sql', 'db.Query'), ('appended', 'sql', 'db.Query')),
                          'func constant(key string) string { return "SELECT 1" }')

    @unittest.skipUnless(os.environ.get('UBS_TAINT_NATIVE_GO') == '1',
                         'set UBS_TAINT_NATIVE_GO=1 to compile the environment witness')
    def test_compiled_environment_values_and_clean_controls_match_runtime(self):
        from test_keep_temp import prevent_child_deletion

        source = textwrap.dedent('''\
            package main
            import (
                "encoding/json"
                "fmt"
                "html"
                "net/http/httptest"
                environment "os"
            )
            type database struct { Queries []string }
            func (db *database) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func reader() func(string) string { return environment.Getenv }
            func lookup(key string) (string, bool) { return environment.LookupEnv(key) }
            func constant(key string) string { return "SELECT fixed" }
            func main() {
                db, w := &database{}, httptest.NewRecorder()
                read := reader()
                saved := read
                read = constant
                db.Query(saved("UBS_GO_ENV_VALUE")) // saved-query
                db.Query(read("UBS_GO_ENV_VALUE"))
                value, present := lookup("UBS_GO_ENV_VALUE")
                db.Query(value) // lookup-query
                db.Query("SELECT $1", value)
                fmt.Fprint(w, present)
                fmt.Fprint(w, html.EscapeString(value))
                fmt.Fprint(w, value) // raw-output
                value = "fixed"
                fmt.Fprint(w, value)
                observed := map[string]any{"rendered": w.Body.String(), "queries": db.Queries}
                if err := json.NewEncoder(environment.Stdout).Encode(observed); err != nil { panic(err) }
            }
        ''')
        path, executable = self.root / 'main.go', self.root / 'witness'
        path.write_text(source, encoding='utf-8')
        environment = dict(os.environ, GOWORK='off', GO111MODULE='off', GOTOOLCHAIN='local',
                           UBS_GO_ENV_VALUE='<b>external</b>')
        build = subprocess.run(['go', 'build', '-work', '-o', str(executable), str(path)],
                               cwd=self.root, text=True, capture_output=True, timeout=180,
                               env=environment, preexec_fn=prevent_child_deletion)
        (self.root / 'build.stdout.log').write_text(build.stdout)
        (self.root / 'build.stderr.log').write_text(build.stderr)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        native = subprocess.run([str(executable)], cwd=self.root, text=True, capture_output=True,
                                timeout=30, env=environment, preexec_fn=prevent_child_deletion)
        (self.root / 'runtime.stdout.log').write_text(native.stdout)
        (self.root / 'runtime.stderr.log').write_text(native.stderr)
        self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
        self.assertEqual(json.loads(native.stdout), {
            'rendered': 'true&lt;b&gt;external&lt;/b&gt;<b>external</b>fixed',
            'queries': ['<b>external</b>', 'SELECT fixed', '<b>external</b>', 'SELECT $1'],
        })
        findings = list(taint_go.run(RunContext(lang='go', files=[path])))
        expected = sorted(
            (number, line.index(sink) + 1, 'go.taint.' + rule)
            for number, line in enumerate(source.splitlines(), 1)
            for marker, rule, sink in [('saved-query', 'sql', 'db.Query'),
                                       ('lookup-query', 'sql', 'db.Query'),
                                       ('raw-output', 'xss', 'fmt.Fprint')]
            if '// ' + marker in line
        )
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings),
                         expected, findings)


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1',
                     'set UBS_TAINT_E2E=1 for real module reports')
class GoEnvironmentModuleTests(unittest.TestCase):
    """Category 9 public reports; this does not claim every Go category ran."""

    def test_real_module_reports_preserve_environment_payload_and_clean_presence(self):
        from test_keep_temp import prevent_child_deletion

        cases = (
            ('aliased-getenv', 'import environment "os"',
             'db.Query(environment.Getenv("UBS_INPUT"))', [('go.taint.sql', 4, 1)]),
            ('saved-lookupenv', 'import environment "os"',
             'read := environment.LookupEnv\nvalue, present := read("UBS_INPUT")\n'
             'db.Query(value)\nfmt.Fprint(w, present)', [('go.taint.sql', 6, 1)]),
            ('bound-query', 'import environment "os"',
             'value, present := environment.LookupEnv("UBS_INPUT")\n'
             'db.Query("SELECT $1", value)\nfmt.Fprint(w, present)', []),
            ('lookalike', 'import os "example.test/settings"', 'db.Query(os.Getenv("UBS_INPUT"))', []),
            ('local-shadow', 'import "os"', 'os := settings\ndb.Query(os.Getenv("UBS_INPUT"))', []),
        )
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        skipped = ','.join(str(category) for category in range(1, 23) if category != 9)
        for name, imports, body, expected in cases:
            for output in ('json', 'sarif'):
                with self.subTest(case=name, format=output):
                    folder = Path(tempfile.mkdtemp(prefix='go-env-public-' + name + '-', dir=artifacts))
                    path = folder / 'handler.go'
                    path.write_text('package app\n' + imports + '\nfunc h() {\n' + body + '\n}\n')
                    command = [str(ROOT / 'modules/ubs-golang.sh'), str(folder), '--ci',
                               '--format=' + output, '--skip=' + skipped]
                    result = subprocess.run(command, cwd=folder, capture_output=True, text=True,
                                            timeout=180, preexec_fn=prevent_child_deletion,
                                            env=dict(os.environ, UBS_KEEP_TEMP='1', UBS_NO_AUTO_UPDATE='1',
                                                     UBS_CACHE_DIR=str(folder / 'cache')))
                    (folder / 'stdout.log').write_text(result.stdout)
                    (folder / 'stderr.log').write_text(result.stderr)
                    self.assertEqual(result.returncode, 1 if expected else 0, result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    if output == 'json':
                        self.assertEqual((report['status'], report['files'], report['critical']),
                                         ('ok', 1, len(expected)), report)
                        actual = [(row.get('rule', row.get('rule_id')), row['line'], row['col'])
                                  for row in report['findings'] if row['severity'] == 'critical']
                    else:
                        actual = []
                        for run in report['runs']:
                            for invocation in run.get('invocations', []):
                                self.assertTrue(invocation['executionSuccessful'], invocation)
                            for row in run.get('results', []):
                                if row['level'] == 'error':
                                    region = row['locations'][0]['physicalLocation']['region']
                                    actual.append((row['ruleId'], region['startLine'], region['startColumn']))
                    self.assertEqual(sorted(actual), sorted(expected), report)


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


    def test_deferred_closure_reads_the_eventual_outer_cell(self):
        self.check_source('import "html"',
                          'escape := html.EscapeString\n'
                          'render := func() { fmt.Fprint(w, escape(r.FormValue("q"))) } // deferred-read\n'
                          'escape = passthrough\nrender()', (('deferred-read', 'xss'),),
                          'func passthrough(value string) string { return value }')

    def test_deferred_closure_keeps_local_global_and_immediate_native_proofs(self):
        self.check_source('import "html"',
                          'outer := html.EscapeString\n'
                          'render := func() { local := html.EscapeString; '
                          'fmt.Fprint(w, local(r.FormValue("q"))); '
                          'fmt.Fprint(w, packageEscape(r.FormValue("q"))) }\nrender()\n'
                          'func() { fmt.Fprint(w, outer(r.FormValue("q"))) }()', (),
                          'var packageEscape = html.EscapeString')

    def test_defer_and_go_keep_argument_snapshots_but_not_outer_callable_proofs(self):
        for scheduling in ('defer', 'go'):
            with self.subTest(scheduling=scheduling):
                self.check_source('import "html"',
                                  'escape := html.EscapeString\n' + scheduling + ' func() { '
                                  'fmt.Fprint(w, escape(r.FormValue("q"))) }() // delayed-read\n'
                                  + scheduling + ' func(value string) { fmt.Fprint(w, value) }'
                                  '(escape(r.FormValue("q")))\nescape = passthrough',
                                  (('delayed-read', 'xss'),),
                                  'func passthrough(value string) string { return value }')

    def test_invoked_closure_parameters_keep_native_escaper_contracts(self):
        for package, member in (('html', 'EscapeString'), ('html/template', 'HTMLEscapeString'),
                                ('text/template', 'HTMLEscapeString')):
            for scheduling in ('', 'defer ', 'go '):
                with self.subTest(package=package, scheduling=scheduling):
                    self.check_source('import safe "' + package + '"',
                                      scheduling + 'func(escape func(string) string, value string) {\n'
                                      'fmt.Fprint(w, escape(value))\n'
                                      'db.Query(escape(value)) // sql-site\n'
                                      'exec.Command("sh", "-c", escape(value)) // command-site\n'
                                      '}(safe.' + member + ', r.FormValue("q"))',
                                      (('sql-site', 'sql'), ('command-site', 'command')))

    def test_closure_callback_unknown_alternatives_never_gain_sanitizer_proof(self):
        helpers = 'func passthrough(value string) string { return value }'
        self.check_source('import "html"',
                          'escape := html.EscapeString\nif choice { escape = passthrough }\n'
                          'func(clean func(string) string) {\n'
                          'fmt.Fprint(w, clean(r.FormValue("q"))) // unknown-site\n'
                          '}(escape)', (('unknown-site', 'xss'),), helpers)
        self.check_source('import html "example.test/raw"',
                          'func(clean func(string) string) {\n'
                          'fmt.Fprint(w, clean(r.FormValue("q"))) // lookalike-site\n'
                          '}(html.EscapeString)', (('lookalike-site', 'xss'),))

    def test_closure_callback_keeps_argument_effects_and_local_reassignment(self):
        self.check_source('import "html"',
                          'func(escape func(string) string, value string) {\n'
                          '_ = escape(render(value)) // effect-site\n'
                          'saved := escape\nescape = passthrough\n'
                          'fmt.Fprint(w, saved(value))\n'
                          'fmt.Fprint(w, escape(value)) // replaced-site\n'
                          '}(html.EscapeString, r.FormValue("q"))',
                          (('effect-site', 'xss'), ('replaced-site', 'xss')),
                          'func render(value string) string { fmt.Fprint(w, value); return value }\n'
                          'func passthrough(value string) string { return value }')

    def test_deferred_callback_argument_is_snapshot_not_captured_cell(self):
        for scheduling in ('defer', 'go'):
            with self.subTest(scheduling=scheduling):
                self.check_source('import "html"',
                                  'escape := html.EscapeString\n' + scheduling + ' func(clean func(string) string) {\n'
                                  'fmt.Fprint(w, clean(r.FormValue("q")))\n'
                                  'fmt.Fprint(w, escape(r.FormValue("q"))) // captured-site\n'
                                  '}(escape)\nescape = passthrough', (('captured-site', 'xss'),),
                                  'func passthrough(value string) string { return value }')


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
    def setUp(self):
        try:
            version = subprocess.run(['go', 'version'], text=True, capture_output=True, timeout=10)
        except FileNotFoundError:
            self.skipTest('Go compiler is not installed')
        if version.returncode != 0 or not re.match(r'^go version (?:go\d|devel\b)', version.stdout):
            self.skipTest('go on PATH is not a Go compiler (go version did not identify one)')

    def test_compiled_closure_callback_arguments_match_native_contracts(self):
        from test_keep_temp import prevent_child_deletion

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
            )
            type Payload struct { SQL string; HTML string }
            type database struct { Queries []string }
            func (db *database) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func raw(value string) string { return value }
            func callbackHandler(r *http.Request, db *database, w http.ResponseWriter) {
                func(read func(io.Reader) ([]byte, error), decode func([]byte, any) error, escape func(string) string) {
                    payload, readErr := read(r.Body)
                    if readErr != nil { db.Query(readErr.Error()); return }
                    var p Payload
                    if err := decode(payload, &p); err != nil { db.Query(err.Error()); return }
                    db.Query(p.SQL) // callback-query
                    db.Query("SELECT $1", p.SQL)
                    fmt.Fprint(w, escape(p.HTML))
                    fmt.Fprint(w, p.HTML) // raw-output
                }(io.ReadAll, json.Unmarshal, html.EscapeString)
            }
            func receiverHandler(r *http.Request, db *database) {
                var p Payload
                decoder := xml.NewDecoder(r.Body)
                func(reader *xml.Decoder, out *Payload) {
                    if err := reader.Decode(out); err != nil { db.Query(err.Error()); return }
                    db.Query(out.SQL) // receiver-query
                }(decoder, &p)
            }
            func factoryHandler(r *http.Request, db *database) {
                func(factory func(io.Reader) *json.Decoder) {
                    decoder := factory(r.Body)
                    var p Payload
                    if err := decoder.Decode(&p); err != nil { db.Query(err.Error()); return }
                    db.Query(p.SQL) // factory-query
                }(json.NewDecoder)
            }
            func deferredHandler(r *http.Request, w http.ResponseWriter) {
                escape := html.EscapeString
                defer func(call func(string) string) { fmt.Fprint(w, call(r.FormValue("q"))) }(escape)
                escape = raw
            }
            func main() {
                value := "<b>request</b>"
                body, err := json.Marshal(Payload{SQL: "SELECT request", HTML: value})
                if err != nil { panic(err) }
                db, w := &database{}, httptest.NewRecorder()
                callbackHandler(httptest.NewRequest("POST", "/", strings.NewReader(string(body))), db, w)
                receiverHandler(httptest.NewRequest("POST", "/", strings.NewReader("<Payload><SQL>SELECT xml</SQL></Payload>")), db)
                factoryHandler(httptest.NewRequest("POST", "/", strings.NewReader(string(body))), db)
                deferredHandler(httptest.NewRequest("GET", "/?q=" + url.QueryEscape(value), nil), w)
                observed := map[string]any{"rendered": w.Body.String(), "queries": db.Queries}
                if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil { panic(err) }
            }
        ''')
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix='go-closure-native-', dir=artifacts))
        path = folder / 'main.go'
        path.write_text(source, encoding='utf-8')
        environment = dict(os.environ, GOWORK='off', GO111MODULE='off', GOTOOLCHAIN='local',
                           GOCACHE=str(folder / 'gocache'), GOTMPDIR=str(folder))
        executable = folder / 'witness'
        build = subprocess.run(['go', 'build', '-work', '-o', str(executable), str(path)],
                               cwd=folder, text=True, capture_output=True, timeout=180,
                               env=environment, preexec_fn=prevent_child_deletion)
        (folder / 'build.stdout.log').write_text(build.stdout)
        (folder / 'build.stderr.log').write_text(build.stderr)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        native = subprocess.run([str(executable)], cwd=folder, text=True, capture_output=True,
                                timeout=30, env=environment, preexec_fn=prevent_child_deletion)
        (folder / 'runtime.stdout.log').write_text(native.stdout)
        (folder / 'runtime.stderr.log').write_text(native.stderr)
        self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
        self.assertEqual(json.loads(native.stdout), {
            'rendered': '&lt;b&gt;request&lt;/b&gt;<b>request</b>&lt;b&gt;request&lt;/b&gt;',
            'queries': ['SELECT request', 'SELECT $1', 'SELECT xml', 'SELECT request'],
        })
        findings = list(taint_go.run(RunContext(lang='go', files=[path])))
        expected = sorted(
            (number, line.index(sink) + 1, 'go.taint.' + rule)
            for number, line in enumerate(source.splitlines(), 1)
            for marker, rule, sink in [('callback-query', 'sql', 'db.Query'),
                                       ('receiver-query', 'sql', 'db.Query'),
                                       ('factory-query', 'sql', 'db.Query'),
                                       ('raw-output', 'xss', 'fmt.Fprint')]
            if '// ' + marker in line
        )
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings),
                         expected, findings)

    def test_compiled_parenthesized_calls_match_analyzer_contracts(self):
        source = textwrap.dedent('''\
            package main
            import (
                "encoding/json"
                "fmt"
                "html"
                "io"
                "net/http"
                "net/http/httptest"
                "net/url"
                "os"
                "strings"
            )
            type Payload struct { SQL string; HTML string }
            type database struct { Queries []string }
            func (db *database) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func raw(value string) string { return value }
            func decode(data []byte, out *Payload) error { return (json.Unmarshal)(data, out) }
            func handler(r *http.Request, db *database, w http.ResponseWriter) {
                read := io.ReadAll
                data, readErr := ((read))(r.Body)
                if readErr != nil { db.Query(readErr.Error()); return }
                var p Payload
                if err := (decode)(data, &p); err != nil { db.Query(err.Error()); return }
                (db.Query)(p.SQL) // decoded-query
                (db.Query)("SELECT $1", p.SQL)
                (fmt.Fprint)(w, (html.EscapeString)(p.HTML))
                (fmt.Fprint)(w, p.HTML) // raw-output
                escape := html.EscapeString
                saved := escape
                escape = raw
                fmt.Fprint(w, (saved)((r.FormValue)("q")))
                fmt.Fprint(w, ((escape))((r.FormValue)("q"))) // overwritten-output
            }
            func factoryHandler(r *http.Request, db *database) {
                var p Payload
                if err := (json.NewDecoder)(r.Body).Decode(&p); err != nil { db.Query(err.Error()); return }
                db.Query(p.SQL) // factory-query
            }
            func main() {
                value := "<b>request</b>"
                body, err := json.Marshal(Payload{SQL: "SELECT request", HTML: value})
                if err != nil { panic(err) }
                db, w := &database{}, httptest.NewRecorder()
                handler(httptest.NewRequest("POST", "/?q=" + url.QueryEscape(value), strings.NewReader(string(body))), db, w)
                factoryHandler(httptest.NewRequest("POST", "/", strings.NewReader(string(body))), db)
                observed := map[string]any{"rendered": w.Body.String(), "queries": db.Queries}
                if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil { panic(err) }
            }
        ''')
        with tempfile.TemporaryDirectory(prefix='ubs-go-parenthesized-native-') as tmp:
            path = Path(tmp) / 'main.go'
            path.write_text(source, encoding='utf-8')
            native = subprocess.run(['go', 'run', '-work', str(path)], cwd=tmp, text=True,
                                    capture_output=True, timeout=180,
                                    env=dict(os.environ, GOWORK='off', GO111MODULE='off',
                                             GOTOOLCHAIN='local', GOTMPDIR=tmp))
            self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
            self.assertEqual(json.loads(native.stdout), {
                'rendered': '&lt;b&gt;request&lt;/b&gt;<b>request</b>&lt;b&gt;request&lt;/b&gt;<b>request</b>',
                'queries': ['SELECT request', 'SELECT $1', 'SELECT request'],
            })
            findings = list(taint_go.run(RunContext(lang='go', files=[path])))
            expected = {
                (number, 'go.taint.' + rule)
                for number, line in enumerate(source.splitlines(), 1)
                for marker, rule in [('raw-output', 'xss'), ('overwritten-output', 'xss'),
                                     ('decoded-query', 'sql'), ('factory-query', 'sql')]
                if '// ' + marker in line
            }
            self.assertEqual({(row['line'], row['rule']) for row in findings}, expected, findings)
            self.assertEqual(len(findings), len(expected), findings)

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


    def test_compiled_ordinary_destination_writes_match_analyzer_contracts(self):
        source = textwrap.dedent('''\
            package main
            import (
                "encoding/json"
                "fmt"
                "html"
                "net/http"
                "net/http/httptest"
                "net/url"
                "os"
            )
            type Payload struct { SQL string; HTML string }
            type database struct { Queries []string }
            func (db *database) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func assign(out *string, input string) { *out = input }
            func forward(out *string, input string) { assign(out, input) }
            func populate(out *Payload, input string) { out.SQL = input }
            type Base struct { SQL string }
            type Embedded struct { Base }
            func h(r *http.Request, w http.ResponseWriter, db *database) {
                value := "fixed"
                saved := value
                forward(&value, r.FormValue("q"))
                fmt.Fprint(w, value) // raw-output
                db.Query(saved)
                out := &value
                *out = "fixed"
                fmt.Fprint(w, value)
                var payload, untouched Payload
                populate(&payload, r.FormValue("q"))
                field := &payload.HTML
                *field = "constant"
                db.Query(payload.SQL) // field-query
                db.Query(untouched.SQL)
                escaped := "fixed"
                escapedOut := &escaped
                *escapedOut = html.EscapeString(r.FormValue("q"))
                fmt.Fprint(w, escaped)
                db.Query(escaped) // escaped-query
                db.Query("SELECT $1", payload.SQL)
                embedded := Embedded{Base: Base{SQL: r.FormValue("q")}}
                embedded.SQL = "fixed"
                embedded.Base.SQL = r.FormValue("q")
                db.Query(embedded.SQL) // promoted-query
            }
            func main() {
                input := "<b>request</b>"
                req := httptest.NewRequest("GET", "/?q=" + url.QueryEscape(input), nil)
                output := httptest.NewRecorder()
                db := &database{}
                h(req, output, db)
                observed := map[string]any{"rendered": output.Body.String(), "queries": db.Queries}
                if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil { panic(err) }
            }
        ''')
        with tempfile.TemporaryDirectory(prefix='ubs-go-native-writes-') as tmp:
            path = Path(tmp) / 'main.go'
            path.write_text(source, encoding='utf-8')
            native = subprocess.run(['go', 'run', str(path)], cwd=tmp, text=True,
                                    capture_output=True, timeout=180,
                                    env=dict(os.environ, GOWORK='off', GO111MODULE='off', GOTOOLCHAIN='local'))
            self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
            self.assertEqual(json.loads(native.stdout), {
                'rendered': '<b>request</b>fixed&lt;b&gt;request&lt;/b&gt;',
                'queries': ['fixed', '<b>request</b>', '', '&lt;b&gt;request&lt;/b&gt;',
                            'SELECT $1', '<b>request</b>'],
            })
            findings = list(taint_go.run(RunContext(lang='go', files=[path])))
            expected = {
                (number, 'go.taint.' + rule)
                for number, line in enumerate(source.splitlines(), 1)
                for marker, rule in [('raw-output', 'xss'), ('field-query', 'sql'),
                                     ('escaped-query', 'sql'), ('promoted-query', 'sql')]
                if '// ' + marker in line
            }
            self.assertEqual({(row['line'], row['rule']) for row in findings}, expected, findings)
            self.assertEqual(len(findings), len(expected), findings)

    def test_compiled_higher_order_native_calls_match_analyzer_contracts(self):
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
            )
            type Payload struct { SQL string; HTML string }
            type database struct { Queries []string }
            func (db *database) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func raw(value string) string { return value }
            func keep(call func(string) string) func(string) string { return call }
            func apply(call func(string) string, value string) string { return call(value) }
            func reader() func(io.Reader) ([]byte, error) { return io.ReadAll }
            func chooseDecoder(useXML bool) func([]byte, any) error {
                if useXML { return xml.Unmarshal }
                return json.Unmarshal
            }
            func decodeWith(call func([]byte, any) error, data []byte, dst *Payload) error {
                return call(data, dst)
            }
            func decoderWith(makeDecoder func(io.Reader) *json.Decoder, input io.Reader) *json.Decoder {
                return makeDecoder(input)
            }
            func decodeHandle(decoder *json.Decoder, dst *Payload) error { return decoder.Decode(dst) }
            func handler(r *http.Request, db *database, w http.ResponseWriter) {
                escape := keep(html.EscapeString)
                fmt.Fprint(w, apply(escape, r.FormValue("q")))
                fmt.Fprint(w, apply(raw, r.FormValue("q"))) // raw-output
                read := reader()
                data, readErr := read(r.Body)
                if readErr != nil { db.Query(readErr.Error()); return }
                decode := chooseDecoder(false)
                var p Payload
                if err := decodeWith(decode, data, &p); err != nil { db.Query(err.Error()); return }
                db.Query(p.SQL) // decoded-query
                db.Query("SELECT $1", p.SQL)
                db.Query(apply(escape, p.SQL)) // escaped-query
                fmt.Fprint(w, apply(escape, p.HTML))
            }
            func factoryHandler(r *http.Request, db *database) {
                decoder := decoderWith(json.NewDecoder, r.Body)
                var p Payload
                if err := decodeHandle(decoder, &p); err != nil { db.Query(err.Error()); return }
                db.Query(p.SQL) // factory-query
            }
            func main() {
                value := "<b>request</b>"
                body, err := json.Marshal(Payload{SQL: "SELECT request", HTML: value})
                if err != nil { panic(err) }
                db, w := &database{}, httptest.NewRecorder()
                handler(httptest.NewRequest("POST", "/?q=" + url.QueryEscape(value), strings.NewReader(string(body))), db, w)
                factoryHandler(httptest.NewRequest("POST", "/", strings.NewReader(string(body))), db)
                observed := map[string]any{"rendered": w.Body.String(), "queries": db.Queries}
                if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil { panic(err) }
            }
        ''')
        with tempfile.TemporaryDirectory(prefix='ubs-go-higher-native-') as tmp:
            path = Path(tmp) / 'main.go'
            path.write_text(source, encoding='utf-8')
            native = subprocess.run(['go', 'run', str(path)], cwd=tmp, text=True,
                                    capture_output=True, timeout=180,
                                    env=dict(os.environ, GOWORK='off', GO111MODULE='off', GOTOOLCHAIN='local'))
            self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
            self.assertEqual(json.loads(native.stdout), {
                'rendered': '&lt;b&gt;request&lt;/b&gt;<b>request</b>&lt;b&gt;request&lt;/b&gt;',
                'queries': ['SELECT request', 'SELECT $1', 'SELECT request', 'SELECT request'],
            })
            findings = list(taint_go.run(RunContext(lang='go', files=[path])))
            expected = {
                (number, 'go.taint.' + rule)
                for number, line in enumerate(source.splitlines(), 1)
                for marker, rule in [('raw-output', 'xss'), ('decoded-query', 'sql'),
                                     ('escaped-query', 'sql'), ('factory-query', 'sql')]
                if '// ' + marker in line
            }
            self.assertEqual({(row['line'], row['rule']) for row in findings}, expected, findings)
            self.assertEqual(len(findings), len(expected), findings)


if __name__ == "__main__":
    unittest.main()
