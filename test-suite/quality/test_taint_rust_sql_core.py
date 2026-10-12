"""Executable source-to-sink contracts for the Rust SQL engine."""
from __future__ import annotations

import sys
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.rust_detectors.sql_flow import Source, scan_text, scan_file, find
from ubs_core.taint_flow import AnalysisLimit


class RustSqlCoreTests(unittest.TestCase):
    def check(self, source, count=1):
        found = scan_text(source)
        self.assertEqual(len(found), count, (source, found))
        return found

    def test_direct(self):
        self.check('fn f() { let user = params.get("user"); db.execute(&format!("SELECT {user}")); }')

    def test_query_text_needs_no_sql_keyword(self):
        self.check('fn f() { db.execute(params.get("q")); }')

    def test_builder(self):
        self.check('fn build(user: &str) -> String { format!("SELECT {user}") } fn f() { let u = params.get("user"); let q = build(u); db.execute(q); }')

    def test_second_builder_argument(self):
        self.check('fn build(a: &str, b: &str) -> String { format!("SELECT {a} {b}") } fn f() { db.execute(build("fixed", params.get("b"))); }')

    def test_two_sources_survive_summary(self):
        found = self.check('fn build(a: &str, b: &str) -> String { format!("SELECT {a} {b}") } fn f() { db.execute(build(params.get("a"), params.get("b"))); }')
        self.assertEqual(len(next(iter(found.values()))), 2)

    def test_static_builder_does_not_inherit_argument_taint(self):
        self.check('fn build(unused: &str) -> &str { "SELECT 1" } fn f() { db.execute(build(params.get("a"))); }', 0)

    def test_alias_chain_longer_than_evidence_budget(self):
        aliases = 'let v0 = user;' + ''.join(f'let v{i} = v{i-1};' for i in range(1, 40))
        self.check(f'fn build(user: &str) -> String {{ {aliases} format!("SELECT {{v39}}") }} fn f() {{ db.execute(build(params.get("a"))); }}')

    def test_deep_call_chain(self):
        functions = 'fn h0(user: &str) -> String { format!("SELECT {user}") }'
        functions += ''.join(f'fn h{i}(user: &str) -> String {{ h{i-1}(user) }}' for i in range(1, 25))
        self.check(functions + 'fn f() { db.execute(h24(params.get("u"))); }')

    def test_reverse_declaration_order(self):
        self.check('fn wrap(u: &str) -> String { build(u) } fn build(u: &str) -> String { format!("SELECT {u}") } fn f() { db.execute(wrap(params.get("u"))); }')

    def test_recursion_fixpoint(self):
        self.check('fn build(u: &str, stop: bool) -> String { if stop { format!("SELECT {u}") } else { build(u, true) } } fn f() { db.execute(build(params.get("u"), true)); }')

    def test_return_source_created_inside_helper(self):
        self.check('fn read() -> String { params.get("q") } fn f() { db.execute(read()); }')

    def test_sink_wrapper(self):
        self.check('fn run(db: &Db, q: &str) { db.execute(q); } fn f() { run(&db, params.get("q")); }')

    def test_bound_argument_through_wrapper(self):
        self.check('fn run(db: &Db, q: &str, u: &str) { db.query(q, &[u]); } fn f() { run(&db, "SELECT * FROM t WHERE id=$1", params.get("id")); }', 0)

    def test_bound_argument_direct(self):
        self.check('fn f() { db.query("SELECT * FROM t WHERE id=$1", &[params.get("id")]); }', 0)

    def test_seaorm_sql_slot(self):
        self.check('fn f() { sea_orm::Statement::from_sql_and_values(DbBackend::Postgres, params.get("q"), []); }')

    def test_seaorm_bound_values(self):
        self.check('fn f() { sea_orm::Statement::from_sql_and_values(DbBackend::Postgres, "SELECT $1", [params.get("u")]); }', 0)

    def test_unbound_client_sql_slot(self):
        self.check('fn f() { postgres::Client::query(&client, params.get("q"), &[]); }')

    def test_bind_does_not_sanitize_query(self):
        self.check('fn f() { sqlx::query(params.get("q")).bind("value"); }')

    def test_compile_time_macro_has_only_bound_taint(self):
        self.check('fn f() { sqlx::query!("SELECT $1", params.get("u")); }', 0)

    def test_macro_cannot_hide_sibling_sink(self):
        self.check('fn f() { sqlx::query!("SELECT 1"); db.execute(params.get("q")); }')

    def test_macro_cannot_hide_nested_sink(self):
        self.check('fn f() { sqlx::query!("SELECT $1", db.execute(params.get("q"))); }')

    def test_same_line_statements(self):
        self.check('fn f() { let q = params.get("q"); db.execute(q); q = "SELECT 1"; db.execute(q); }')

    def test_clean_rebinding(self):
        self.check('fn f() { let q = params.get("q"); q = "SELECT 1"; db.execute(q); }', 0)

    def test_branch_keeps_tainted_arm(self):
        self.check('fn f(flag: bool) { let q = "SELECT 1"; if flag { q = params.get("q"); } else { q = "SELECT 2"; } db.execute(q); }')

    def test_both_branches_overwrite(self):
        self.check('fn f(flag: bool) { let q = params.get("q"); if flag { q = "SELECT 1"; } else { q = "SELECT 2"; } db.execute(q); }', 0)

    def test_branch_local_does_not_shadow_after_block(self):
        self.check('fn f(flag: bool) { let q = params.get("q"); if flag { let q = "SELECT 1"; } db.execute(q); }')

    def test_unreachable_after_return(self):
        self.check('fn f() { return; db.execute(params.get("q")); }', 0)

    def test_returned_branch(self):
        self.check('fn build(flag: bool, user: &str) -> String { if flag { return format!("SELECT {user}"); } "SELECT 1" } fn f() { db.execute(build(true, params.get("u"))); }')

    def test_loop_backedge(self):
        self.check('fn f(flag: bool) { let a = "SELECT 1"; let b = "SELECT 2"; while flag { db.execute(a); a = b; b = params.get("q"); } }')

    def test_loop_clean_overwrite(self):
        self.check('fn f(flag: bool) { let q = params.get("q"); while flag { q = "SELECT 1"; db.execute(q); } }', 0)

    def test_break_reaches_following_sink(self):
        self.check('fn f() { let q = "SELECT 1"; loop { q = params.get("q"); break; } db.execute(q); }')

    def test_continue_reaches_backedge(self):
        self.check('fn f(flag: bool) { let q = "SELECT 1"; while flag { db.execute(q); q = params.get("q"); continue; } }')

    def test_push_string_keeps_all_origins(self):
        found = self.check('fn f() { let q = params.get("a"); q.push_str(params.get("b")); db.execute(q); }')
        self.assertEqual(len(next(iter(found.values()))), 2)

    def test_write_macro(self):
        self.check('fn f() { let q = "SELECT "; let u = params.get("u"); write!(&mut q, "{u}"); db.execute(q); }')

    def test_raw_string_and_comments_are_inert(self):
        self.check('fn f() { let example = r##"db.execute(params.get("q")); /* comment */"##; /* db.execute(params.get("q")); */ db.execute("SELECT 1"); }', 0)

    def test_format_escaped_braces_are_inert(self):
        self.check('fn f() { let u = params.get("u"); db.execute(format!("SELECT {{u}}")); }', 0)

    def test_raw_format_capture(self):
        self.check('fn f() { let u = params.get("u"); db.execute(format!(r#"SELECT {u}"#)); }')

    def test_generic_call(self):
        self.check('fn f() { sqlx::query_as::<_, Row>(params.get("q")); }')

    def test_lifetimes(self):
        self.check("fn build<'a>(u: &'a str) -> String { format!(\"SELECT {u}\") } fn f() { db.execute(build(params.get(\"u\"))); }")

    def test_no_sibling_function_local_leak(self):
        self.check('fn a() { let q = params.get("q"); } fn b() { db.execute(q); }', 0)

    def test_nested_function_does_not_capture_outer_locals(self):
        self.check('fn outer() { let q = params.get("q"); fn inner() { db.execute(q); } inner(); }', 0)

    def test_nested_function_resolves_own_summary(self):
        self.check('fn build(u: &str) -> String { "SELECT 1" } fn outer() { fn build(u: &str) -> String { format!("SELECT {u}") } db.execute(build(params.get("u"))); }')

    def test_module_namesake_is_not_visible_in_parent(self):
        self.check('mod other { fn build(u: &str) -> String { "SELECT 1" } } fn f() { db.execute(build(params.get("u"))); }')

    def test_local_callable_shadow_prevents_clean_summary(self):
        self.check('fn build(u: &str) -> String { "SELECT 1" } fn f(build: Factory) { db.execute(build(params.get("u"))); }')

    def test_source_extractor(self):
        self.check('fn f(Path(id): Path<String>, db: Db) { db.execute(format!("SELECT {id}")); }')

    def test_for_binding(self):
        self.check('fn f() { for q in params.get("queries") { db.execute(q); } }')

    def test_for_shadow_restored_on_break(self):
        self.check('fn f() { let q = params.get("q"); for q in ["fixed"] { break; } db.execute(q); }')

    def test_if_let_binding(self):
        self.check('fn f() { if let Some(q) = params.get("q") { db.execute(q); } }')

    def test_if_let_shadow_restored(self):
        self.check('fn f() { let q = params.get("q"); if let Some(q) = trusted() {} db.execute(q); }')

    def test_match_pattern_binding(self):
        self.check('fn f() { let q = match params.get("q") { Some(value) => value, None => "fixed" }; db.execute(q); }')

    def test_match_block_arms_without_commas(self):
        self.check('fn f() { let q = match params.get("q") { Some(value) => { value } None => { "fixed" } }; db.execute(q); }')

    def test_match_statement_followed_by_sink(self):
        self.check('fn f() { let q = "fixed"; match choice { A => { q = params.get("q"); } B => {} } db.execute(q); }')

    def test_return_inside_match_arm(self):
        self.check('fn build(u: &str) -> String { match flag { A => { return u; } B => {} } "fixed" } fn f() { db.execute(build(params.get("q"))); }')

    def test_loop_result(self):
        self.check('fn f() { let q = loop { break params.get("q"); }; db.execute(q); }')

    def test_loop_break_shadow_restored(self):
        self.check('fn f() { let q = params.get("q"); loop { let q = "fixed"; break; } db.execute(q); }')

    def test_infinite_loop_has_no_following_sink(self):
        self.check('fn f() { loop {} db.execute(params.get("q")); }', 0)

    def test_compound_assignment(self):
        self.check('fn f() { let q = "SELECT "; q += params.get("q"); db.execute(q); }')

    def test_field_write(self):
        self.check('fn f() { let value = trusted(); value.query = params.get("q"); db.execute(value.query); }')

    def test_discarded_block_value_not_returned(self):
        self.check('fn helper(u: &str) { { u }; } fn f() { db.execute(helper(params.get("q"))); }', 0)

    def test_discarded_if_value_not_returned(self):
        self.check('fn helper(u: &str) { if flag { u } else { u }; } fn f() { db.execute(helper(params.get("q"))); }', 0)

    def test_macro_definition_is_not_executed(self):
        self.check('macro_rules! unused { () => { db.execute(params.get("q")); } } fn f() {}', 0)

    def test_function_inside_macro_not_indexed(self):
        self.check('macro_rules! unused { () => { fn bad() { db.execute(params.get("q")); } } } fn f() {}', 0)

    def test_field_source(self):
        self.check('fn f() { db.execute(query.user); }')

    def test_low_budget_is_error(self):
        with self.assertRaises(AnalysisLimit):
            scan_text('fn f() { db.execute(params.get("q")); }', max_steps=0)

    def test_bad_delimiters_are_error(self):
        with self.assertRaises(AnalysisLimit):
            scan_text('fn f() { db.execute(params.get("q"));')


class RustSqlFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ubs-sql-flow-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def source(self, text, name='main.rs'):
        path = self.directory / name
        path.write_text(text, encoding='utf-8')
        return path

    def cli(self, *args):
        result = subprocess.run(
            [sys.executable, '-m', 'ubs_core.rust_detectors.sql_flow', '--format=json', *map(str, args)],
            env=dict(os.environ, PYTHONPATH=str(ROOT / 'modules' / 'helpers')),
            cwd=self.directory, capture_output=True, text=True, timeout=30,
        )
        return result, json.loads(result.stdout)

    def test_suppress_sink_only(self):
        path = self.source('fn f() {\n let q = params.get("q");\n db.execute(q); // ubs:ignore[rust.security.sql-injection]\n}\n')
        self.assertEqual(scan_file(path), [])

    def test_source_suppression_does_not_erase_dataflow(self):
        path = self.source('fn f() {\n let q = params.get("q"); // ubs:ignore\n db.execute(q);\n}\n')
        records = scan_file(path)
        self.assertEqual([r['line'] for r in records], [3])

    def test_unrelated_rule_does_not_suppress(self):
        path = self.source('fn f() {\n db.execute(params.get("q")); // ubs:ignore[other.rule]\n}\n')
        self.assertEqual(len(scan_file(path)), 1)

    def test_marker_in_literal_is_inert(self):
        path = self.source('fn f() { db.execute(params.get("q") + "ubs:ignore"); }')
        self.assertEqual(len(scan_file(path)), 1)

    def test_multiline_sink_suppression(self):
        path = self.source('fn f() {\n db.execute(\n params.get("q") // ubs:ignore[rust.security.sql-injection]\n );\n}\n')
        self.assertEqual(scan_file(path), [])

    def test_two_same_line_sinks_preserve_columns(self):
        text = 'fn f() { db.execute(params.get("a")); db.execute(params.get("b")); }'
        records = scan_file(self.source(text))
        self.assertEqual([r['col'] for r in records], [text.index('db.') + 1, text.rindex('db.') + 1])

    def test_legacy_find_deduplicates_lines(self):
        path = self.source('fn f() { db.execute(params.get("a")); db.execute(params.get("b")); }')
        self.assertEqual(len(list(find([path]))), 1)

    def test_evidence_keeps_helper_call(self):
        path = self.source('fn run(db: &Db, query: &str) {\n db.execute(query);\n}\nfn f() { run(&db, params.get("q")); }')
        records = scan_file(path)
        self.assertEqual([r['line'] for r in records], [2])
        self.assertIn('run() SQL execution', records[0]['sample'])
        self.assertTrue(all(step['path'] == str(path) for step in records[0]['evidence']))

    def test_json_exit_one_for_findings(self):
        path = self.source('fn f() { db.execute(params.get("q")); }')
        process, report = self.cli(path)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stderr, '')
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['summary']['critical'], 1)

    def test_json_clean_exit_zero(self):
        path = self.source('fn f() { db.query("SELECT $1", &[params.get("q")]); }')
        process, report = self.cli(path)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(report['findings'], [])

    def test_partial_keeps_completed_findings(self):
        path = self.source('fn f() { db.execute(params.get("q")); }')
        process, report = self.cli(path, self.directory / 'missing.rs')
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['summary']['completed_files'], 1)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(len(report['errors']), 1)

    def test_malformed_input_not_clean(self):
        process, report = self.cli(self.source('fn f() {'))
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report['status'], 'error')

    def test_invalid_encoding_not_clean(self):
        path = self.directory / 'invalid.rs'
        path.write_bytes(b'\xff')
        process, report = self.cli(path)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report['status'], 'error')

    def test_budget_exhaustion_not_clean(self):
        path = self.source('fn f() { db.execute(params.get("q")); }')
        process, report = self.cli('--max-steps=1', path)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report['status'], 'error')
        self.assertIn('incomplete', report['errors'][0]['reason'])

    def test_authoritative_nul_list_with_unusual_path(self):
        path = self.source('fn f() { db.execute(params.get("q")); }', 'a\nb space.rs')
        listing = self.directory / 'selected.paths'
        listing.write_bytes(os.fsencode(path) + b'\0' + os.fsencode(path) + b'\0')
        process, report = self.cli('--files-from', listing)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report['summary']['files'], 1)
        self.assertEqual(report['findings'][0]['path'], str(path))

    def test_bad_file_list_not_clean(self):
        listing = self.directory / 'selected.paths'
        listing.write_bytes(b'main.rs\n')
        process, report = self.cli('--files-from', listing)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report['status'], 'error')

    def test_selection_does_not_scan_neighbors(self):
        self.source('fn f() { db.execute(params.get("q")); }', 'unselected.rs')
        path = self.source('fn f() {}')
        process, report = self.cli(path)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(report['summary']['files'], 1)


if __name__ == '__main__':
    unittest.main()
