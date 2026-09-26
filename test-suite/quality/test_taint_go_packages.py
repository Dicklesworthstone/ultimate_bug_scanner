"""Package-local Go dataflow and incremental scan regressions (D6).

Fixtures are source text only: neither imports nor analyzed Go are executed.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_go
from ubs_core.registry import RunContext
from ubs_core import go_scan


class PackageTestCase(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        self.directory = tempfile.TemporaryDirectory(prefix='ubs-go-packages-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sources = {}
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = any(test is self for test, _ in result.failures + result.errors)
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - self.started:.3f}s)', flush=True)

    def source(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip('\n'), encoding='utf-8')
        self.sources[name] = path
        return path

    def scan(self, selected=None, profile=None):
        paths = list(self.sources.values()) if selected is None else selected
        return list(taint_go.run(RunContext(lang='go', files=paths, profile=profile or {})))

    def assert_hits(self, expected, selected=None):
        findings = self.scan(selected)
        actual = [(str(Path(f['path']).relative_to(self.root)), f['line'], f['rule']) for f in findings]
        self.assertEqual(sorted(actual), sorted(expected), findings)
        return findings


class PackageFlowTests(PackageTestCase):
    def test_source_returned_by_another_file_reaches_sink(self):
        self.source('a.go', '''
            package app
            func source() string { return r.FormValue("q") }
        ''')
        self.source('b.go', '''
            package app
            func handler() { db.Query(source()) }
        ''')
        findings = self.assert_hits([('b.go', 2, 'go.taint.sql')])
        self.assertIn('source()', findings[0]['message'])

    def test_argument_reaches_sink_in_another_file(self):
        self.source('caller.go', '''
            package app
            func handler() {
                run(r.FormValue("q"))
            }
        ''')
        self.source('helper.go', '''
            package app
            func run(command string) { exec.Command("sh", "-c", command) }
        ''')
        self.assert_hits([('caller.go', 3, 'go.taint.command')])

    def test_safe_caller_and_parameterized_sql_stay_clean(self):
        self.source('a.go', '''
            package app
            func run(command string) { exec.Command("sh", "-c", command) }
            func lookup(value string) { db.Query("SELECT $1", value) }
        ''')
        self.source('b.go', '''
            package app
            func handler() { run("echo safe"); lookup(r.FormValue("q")) }
        ''')
        self.assert_hits([])

    def test_cross_file_sanitizer_is_domain_specific(self):
        self.source('a.go', '''
            package app
            func escape(value string) string { return html.EscapeString(value) }
        ''')
        self.source('b.go', '''
            package app
            func handler() {
                value := escape(r.FormValue("q"))
                fmt.Fprint(w, value)
                db.Query(value)
                exec.Command("sh", "-c", value)
            }
        ''')
        self.assert_hits([('b.go', 5, 'go.taint.sql'), ('b.go', 6, 'go.taint.command')])

    def test_cross_file_tuple_and_variadic_summaries(self):
        self.source('a.go', '''
            package app
            func pair(value string) (string, string) { return "safe", value }
            func send(values ...string) { fmt.Fprint(w, values) }
        ''')
        self.source('b.go', '''
            package app
            func handler() {
                safe, unsafe := pair(r.FormValue("q"))
                db.Query(safe)
                db.Query(unsafe)
                send("constant", unsafe)
            }
        ''')
        self.assert_hits([('b.go', 5, 'go.taint.sql'), ('b.go', 6, 'go.taint.xss')])

    def test_recursive_call_chain_spans_files(self):
        self.source('a.go', '''
            package app
            func first(v string) string { if done { return v }; return second(v) }
        ''')
        self.source('b.go', '''
            package app
            func second(v string) string { return first(v) }
            func handler() { db.Query(second(r.FormValue("q"))) }
        ''')
        self.assert_hits([('b.go', 3, 'go.taint.sql')])

    def test_long_chain_is_not_limited_by_file_or_iteration_order(self):
        self.source('handler.go', 'package app\nfunc h() { db.Query(f0()) }\n')
        for index in range(15):
            expression = f'f{index + 1}()' if index < 14 else 'r.FormValue("q")'
            self.source(f'helper{index:02}.go', f'package app\nfunc f{index}() string {{ return {expression} }}\n')
        self.assert_hits([('handler.go', 2, 'go.taint.sql')])

    def test_same_package_name_in_different_directories_is_not_linked(self):
        self.source('one/helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('two/handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        self.assert_hits([])

    def test_external_test_package_is_not_linked(self):
        self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('handler_test.go', 'package app_test\nfunc h() { db.Query(source()) }\n')
        self.assert_hits([])

    def test_missing_package_clause_never_guesses_membership(self):
        self.source('helper.go', 'func source() string { return r.FormValue("q") }\n')
        self.source('handler.go', 'func h() { db.Query(source()) }\n')
        self.assert_hits([])

    def test_package_like_comment_and_literal_do_not_link_files(self):
        self.source('helper.go', '// package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        self.assert_hits([])

    def test_only_selected_files_are_read(self):
        self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        handler = self.source('handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        self.assert_hits([], [handler])
        self.assertEqual(list(taint_go.iter_file_hits(handler, self.root)), [])

    def test_shadowed_helper_does_not_resolve_to_package_function(self):
        self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('handler.go', '''
            package app
            func h(source func() string) { db.Query(source()) }
        ''')
        self.assert_hits([])

    def test_package_qualified_name_is_not_a_local_helper_call(self):
        self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('handler.go', 'package app\nfunc h() { db.Query(other.source()) }\n')
        self.assert_hits([])

    def test_init_functions_and_methods_have_file_distinct_scopes(self):
        self.source('a.go', 'package app\nfunc init() { db.Query(r.FormValue("q")) }\n')
        self.source('b.go', 'package app\nfunc init() { exec.Command("sh", "-c", r.FormValue("q")) }\n')
        self.assert_hits([('a.go', 2, 'go.taint.sql'), ('b.go', 2, 'go.taint.command')])

    def test_build_variants_join_instead_of_trusting_last_definition(self):
        self.source('a_linux.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('z_windows.go', 'package app\nfunc source() string { return "safe" }\n')
        self.source('handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        self.assert_hits([('handler.go', 2, 'go.taint.sql')])

    def test_variants_preserve_parameter_dependent_effects(self):
        self.source('a_linux.go', 'package app\nfunc send(value string) { db.Query(value) }\n')
        self.source('z_windows.go', 'package app\nfunc send(value string) {}\n')
        self.source('handler.go', 'package app\nfunc h() { send(r.FormValue("q")) }\n')
        self.assert_hits([('handler.go', 2, 'go.taint.sql')])

    def test_comments_and_unclosed_editor_buffers_do_not_consume_other_files(self):
        self.source('a.go', 'package app\n/* unfinished comment\n')
        self.source('b.go', 'package app\nfunc h() { db.Query(r.FormValue("q")) }\n')
        self.assert_hits([('b.go', 2, 'go.taint.sql')])

    def test_paths_offsets_order_and_duplicate_inputs(self):
        first = self.source('a file\nname.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        second = self.source('z file.go', 'package app\n\nfunc h() { db.Query(source()) }\n')
        normal = self.assert_hits([('z file.go', 3, 'go.taint.sql')])
        self.assertEqual(normal[0]['col'], 12)
        self.assertEqual(self.scan([second, first, second]), normal)

    def test_profile_can_disable_package_finding(self):
        self.source('a.go', 'package app\nfunc h() { db.Query(r.FormValue("q")) }\n')
        self.assertEqual(self.scan(profile={'disabled_rules': ['go.taint.sql']}), [])

    def test_legacy_entrypoint_uses_same_package_summaries(self):
        self.source('a.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('b.go', 'package app\nfunc h() { db.Query(source()) }\n')
        output = io.StringIO()
        with patch.object(sys, 'argv', ['taint_go', str(self.root)]), contextlib.redirect_stdout(output):
            self.assertEqual(taint_go.main(), 0)
        self.assertIn('go.taint.sql\t1\tb.go:2 ', output.getvalue())

    def test_orchestrator_passes_all_files_to_taint_even_with_aggressive_prefilter(self):
        self.source('a.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('b.go', 'package app\nfunc h() { db.Query(source()) }\n')
        class EmptyPrefilter:
            def filter_files_for_analyzer(self, _name, _files):
                return []
        output = io.StringIO()
        go_scan.run_analyzers(list(self.sources.values()), output, prefilter=EmptyPrefilter())
        self.assertEqual([json.loads(line)['rule'] for line in output.getvalue().splitlines()], ['go.taint.sql'])


class PackageCacheTests(PackageTestCase):
    """Use the actual Go orchestrator and on-disk incremental cache."""

    def scan_main(self, selected=None):
        paths = list(self.sources.values()) if selected is None else selected
        listing = self.root / 'files.nul'
        listing.write_bytes(b'\0'.join(os.fsencode(path) for path in paths) + b'\0')
        sink = self.root / 'findings.ndjson'
        stats = self.root / 'cache-stats.json'
        command = [sys.executable, '-m', 'ubs_core.go_scan', '--files-from', str(listing),
                   '--sink', str(sink), '--project-dir', str(self.root)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45,
                                env=dict(os.environ, PYTHONPATH=str(ROOT / 'modules' / 'helpers'),
                                         UBS_CACHE_DIR=str(self.root / 'cache'), UBS_NO_CACHE='0',
                                         UBS_CACHE_FILE=str(stats), UBS_NO_AUTO_UPDATE='1'))
        self.assertTrue(result.stderr.strip(), result.stdout + result.stderr)
        summary = json.loads(result.stderr.splitlines()[-1])
        self.assertEqual(summary['errors'], [], result.stdout + result.stderr)
        self.assertEqual(result.returncode, int(summary['counters']['critical'] > 0),
                         result.stdout + result.stderr)
        return [json.loads(line) for line in sink.read_text().splitlines()
                if json.loads(line)['rule'].startswith('go.taint.')], json.loads(stats.read_text())

    def test_cold_warm_and_changed_helper_keep_callers_visible(self):
        self.source('helper.go', 'package app\nfunc source() string { return "safe" }\n')
        self.source('handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        cold, _ = self.scan_main()
        warm, stats = self.scan_main()
        self.assertEqual(cold, [])
        self.assertEqual(warm, cold)
        self.assertEqual(stats['hits'], 2)
        self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        changed, stats = self.scan_main()
        self.assertEqual([item['rule'] for item in changed], ['go.taint.sql'])
        self.assertEqual(Path(changed[0]['path']).name, 'handler.go')
        self.assertEqual(stats['misses'], 2)
        self.assertEqual(self.scan_main()[0], changed)

    def test_changed_caller_keeps_cached_helper_summary(self):
        self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        self.source('handler.go', 'package app\nfunc h() { db.Query("safe") }\n')
        self.assertEqual(self.scan_main()[0], [])
        self.source('handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        findings, stats = self.scan_main()
        self.assertEqual(len(findings), 1)
        self.assertEqual(stats['misses'], 2)

    def test_selection_changes_cannot_replay_larger_scan(self):
        helper = self.source('helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        handler = self.source('handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        self.assertEqual(len(self.scan_main()[0]), 1)
        self.assertEqual(self.scan_main([handler])[0], [])
        self.assertEqual(len(self.scan_main([helper, handler])[0]), 1)

    def test_unrelated_package_keeps_warm_file_hits(self):
        self.source('one/helper.go', 'package app\nfunc source() string { return "safe" }\n')
        self.source('one/handler.go', 'package app\nfunc h() { db.Query(source()) }\n')
        self.source('two/helper.go', 'package app\nfunc other() {}\n')
        self.scan_main()
        self.source('one/helper.go', 'package app\nfunc source() string { return r.FormValue("q") }\n')
        findings, stats = self.scan_main()
        self.assertEqual(len(findings), 1)
        self.assertEqual((stats['hits'], stats['misses']), (1, 2))


if __name__ == '__main__':
    unittest.main()
