"""Go package initialization dependencies and grouped declaration regressions."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest

import test_taint_go_packages as package_tests


class PackageInitializerTests(package_tests.PackageTestCase):
    def test_forward_variable_in_the_same_file(self):
        self.source('main.go', '''
            package app
            var command = raw
            var raw = os.Getenv("COMMAND")
            func h() { exec.Command("sh", "-c", command) }
        ''')
        self.assert_hits([('main.go', 4, 'go.taint.command')])

    def test_forward_variable_in_a_later_file(self):
        self.source('a.go', '''
            package app
            var command = raw
            func h() { exec.Command("sh", "-c", command) }
        ''')
        self.source('z.go', 'package app\nvar raw = os.Getenv("COMMAND")\n')
        self.assert_hits([('a.go', 3, 'go.taint.command')])

    def test_forward_reference_through_a_helper(self):
        self.source('a.go', '''
            package app
            var query = read()
            func h() { db.Query(query) }
        ''')
        self.source('m.go', 'package app\nfunc read() string { return raw }\n')
        self.source('z.go', 'package app\nvar raw = os.Getenv("QUERY")\n')
        self.assert_hits([('a.go', 3, 'go.taint.sql')])

    def test_helper_initializer_preserves_safe_return_positions(self):
        self.source('a.go', '''
            package app
            var clean, raw = values()
            func h() {
                db.Query(clean)
                db.Query(raw)
            }
        ''')
        self.source('z.go', '''
            package app
            var input = os.Getenv("QUERY")
            func values() (string, string) { return "constant", input }
        ''')
        self.assert_hits([('a.go', 5, 'go.taint.sql')])

    def test_initializer_effects_observe_later_variables(self):
        self.source('a.go', '''
            package app
            var result = send(raw)
        ''')
        self.source('m.go', 'package app\nfunc send(v string) error { return db.Query(v) }\n')
        self.source('z.go', 'package app\nvar raw = os.Getenv("QUERY")\n')
        self.assert_hits([('a.go', 2, 'go.taint.sql')])

    def test_initializer_sanitizers_do_not_clean_unrelated_domains(self):
        self.source('a.go', '''
            package app
            var escaped = html.EscapeString(raw)
            func h() {
                fmt.Fprint(w, escaped)
                db.Query(escaped)
            }
        ''')
        self.source('z.go', 'package app\nvar raw = os.Getenv("QUERY")\n')
        self.assert_hits([('a.go', 5, 'go.taint.sql')])

    def test_long_reverse_dependency_chain_converges(self):
        self.source('handler.go', 'package app\nfunc h() { db.Query(v0) }\n')
        for index in range(24):
            value = f'v{index + 1}' if index < 23 else 'os.Getenv("QUERY")'
            self.source(f'input{index:02}.go', f'package app\nvar v{index} = {value}\n')
        findings = self.assert_hits([('handler.go', 2, 'go.taint.sql')])
        self.assertIn('os.Getenv', findings[0]['message'])

    def test_safe_global_dependencies_stay_clean(self):
        self.source('a.go', 'package app\nvar query = read()\nfunc h() { db.Query(query) }\n')
        self.source('z.go', 'package app\nvar raw = "SELECT 1"\nfunc read() string { return raw }\n')
        self.assert_hits([])

    def test_grouped_globals_keep_declared_types_and_multiple_targets(self):
        self.source('a.go', '''
            package app
            var (
                query string = raw
                clean, second string = "constant", raw
                empty string
            )
            func h() {
                db.Query(query)
                db.Query(clean)
                db.Query(second)
                db.Query(empty)
            }
        ''')
        self.source('z.go', 'package app\nvar raw = os.Getenv("QUERY")\n')
        self.assert_hits([('a.go', 8, 'go.taint.sql'), ('a.go', 10, 'go.taint.sql')])

    def test_grouped_local_declarations_share_the_enclosing_scope(self):
        self.source('a.go', '''
            package app
            func h() {
                var (
                    command = r.FormValue("q")
                    copy string = command
                )
                exec.Command("sh", "-c", copy)
            }
        ''')
        self.assert_hits([('a.go', 7, 'go.taint.command')])

    def test_grouped_local_zero_value_shadows_a_tainted_global(self):
        self.source('a.go', '''
            package app
            var query = os.Getenv("QUERY")
            func h() {
                var (query string)
                db.Query(query)
            }
        ''')
        self.assert_hits([])

    def test_grouped_inner_block_does_not_overwrite_outer_binding(self):
        self.source('a.go', '''
            package app
            func h() {
                query := r.FormValue("q")
                { var (query = "safe"); db.Query(query) }
                db.Query(query)
            }
        ''')
        self.assert_hits([('a.go', 5, 'go.taint.sql')])

    def test_grouped_local_assignment_still_kills_taint(self):
        self.source('a.go', '''
            package app
            func h() {
                var (query = r.FormValue("q"))
                query = "SELECT 1"
                db.Query(query)
            }
        ''')
        self.assert_hits([])

    def test_grouped_initializer_can_call_another_file(self):
        self.source('a.go', '''
            package app
            var (
                clean, query = pair()
            )
            func h() { db.Query(clean); db.Query(query) }
        ''')
        self.source('z.go', 'package app\nfunc pair() (string, string) { return "safe", os.Getenv("QUERY") }\n')
        self.assert_hits([('a.go', 5, 'go.taint.sql')])

    def test_grouped_const_declarations_are_not_input_sources(self):
        self.source('a.go', '''
            package app
            const (
                query = "SELECT 1"
                message = "os.Getenv(QUERY)"
            )
            func h() { db.Query(query + message) }
        ''')
        self.assert_hits([])

    def test_global_names_do_not_cross_package_boundaries(self):
        self.source('a.go', 'package app\nvar query = raw\nfunc h() { db.Query(query) }\n')
        self.source('z_test.go', 'package app_test\nvar raw = os.Getenv("QUERY")\n')
        self.assert_hits([])

    def test_initializer_sinks_keep_original_file_and_column(self):
        self.source('a.go', 'package app\nvar result = db.Query(query)\n')
        self.source('z.go', 'package app\nvar query = os.Getenv("QUERY")\n')
        findings = self.assert_hits([('a.go', 2, 'go.taint.sql')])
        self.assertEqual(findings[0]['col'], 14)

    def test_incomplete_cyclic_editor_buffer_reaches_a_finite_fixpoint(self):
        # The editor buffer is deliberately not a compilable Go package. The
        # source analyzer must nevertheless terminate without a pass/depth cap.
        self.source('a.go', 'package app\nvar a = b + os.Getenv("QUERY")\n')
        self.source('z.go', 'package app\nvar b = a\nfunc h() { db.Query(b) }\n')
        probe = '''
import json, sys
from pathlib import Path
from ubs_core.analyzers.taint_go import run
from ubs_core.registry import RunContext
print(json.dumps(list(run(RunContext(lang="go", files=list(Path(sys.argv[1]).glob("*.go")))))))
'''
        result = subprocess.run([sys.executable, '-c', probe, str(self.root)], capture_output=True,
                                text=True, timeout=15,
                                env=dict(os.environ, PYTHONPATH=str(package_tests.ROOT / 'modules/helpers')))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        findings = json.loads(result.stdout)
        self.assertEqual([finding['rule'] for finding in findings], ['go.taint.sql'])


class InitializerCacheTests(package_tests.PackageTestCase):
    scan_main = package_tests.PackageCacheTests.scan_main

    def test_changed_initializer_recomputes_cached_dependent_callers(self):
        self.source('a.go', 'package app\nvar query = raw\nfunc h() { db.Query(query) }\n')
        self.source('z.go', 'package app\nvar raw = "SELECT 1"\n')
        self.assertEqual(self.scan_main()[0], [])
        self.source('z.go', 'package app\nvar raw = os.Getenv("QUERY")\n')
        findings, stats = self.scan_main()
        self.assertEqual([finding['rule'] for finding in findings], ['go.taint.sql'])
        self.assertEqual(stats['misses'], 2)
        self.assertEqual(self.scan_main()[0], findings)
        self.source('z.go', 'package app\nvar raw = "SELECT 1"\n')
        self.assertEqual(self.scan_main()[0], [])


if __name__ == '__main__':
    unittest.main()
