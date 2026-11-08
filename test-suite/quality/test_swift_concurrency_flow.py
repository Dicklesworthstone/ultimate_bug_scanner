"""Swift concurrency and closure regressions for issue #204.

The cases assert security outcomes through the strict scoped-flow API. Inline
expectations identify the real sink sites; paired controls must finish without
findings rather than merely avoiding parser exceptions. Executed Swift sources
and structured findings are retained under the test artifacts directory.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import textwrap
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))

from ubs_core.analyzers.taint_swift_traversal import flow_findings


class SwiftConcurrencyFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-concurrency-flow-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def check(self, source, *, policy='path', suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        expected = [number for number, line in enumerate(source.splitlines(), 1)
                    if '// expect-' + policy in line]
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        findings = flow_findings(path, source, policy)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        self.assertEqual([finding['line'] for finding in findings], expected, findings)
        rule = ('swift.taint.request_path_traversal' if policy == 'path'
                else 'swift.taint.request_open_redirect')
        for finding in findings:
            self.assertEqual(finding['rule'], rule)
            self.assertEqual(finding['severity'], 'critical')
            self.assertEqual(finding['path'], str(path.resolve()))
            witness = finding['extras']['taint_path']
            self.assertEqual(witness[0]['kind'], 'source')
            self.assertEqual(witness[-1]['kind'], 'sink')
            self.assertEqual((witness[-1]['line'], witness[-1]['col']),
                             (finding['line'], finding['col']))
        return findings

    def test_actor_isolation_and_self_capture_do_not_hide_task_sinks(self):
        for capture in ('weak self', 'unowned self', 'unowned(safe) self', 'unowned(unsafe) self'):
            for tainted in (False, True):
                with self.subTest(capture=capture, tainted=tainted):
                    self.check('''
                        final class Worker {
                            func load(req: Request) {
                                Task { @MainActor [%s] in
                                    consume(self)
                                    _ = String(contentsOfFile: %s) %s
                                }
                            }
                        }
                    ''' % (capture, 'req.query["path"]' if tainted else '"/srv/fixed"',
                           '// expect-path' if tainted else ''),
                               suffix=capture.replace(' ', '-') + str(tainted))

    def test_weak_self_guard_terminates_only_its_closure(self):
        self.check('''
            final class Worker {
                func load(req: Request) {
                    Task { [weak self] in
                        guard let self else { return }
                        _ = String(contentsOfFile: req.query["inside"]) // expect-path
                    }
                    _ = String(contentsOfFile: req.query["outside"]) // expect-path
                }
            }
        ''')

    def test_reference_capture_observes_later_writes_but_snapshot_does_not(self):
        self.check('''
            func handle(req: Request) {
                var path = "/srv/fixed"
                Task { _ = String(contentsOfFile: path) } // expect-path
                path = req.query["path"]
            }
        ''', suffix='reference')
        self.check('''
            func handle(req: Request) {
                var path = "/srv/fixed"
                Task { [copy = path] in _ = String(contentsOfFile: copy) }
                path = req.query["path"]
            }
        ''', suffix='snapshot')

    def test_snapshot_retains_taint_after_outer_value_is_overwritten(self):
        self.check('''
            func handle(req: Request) {
                var path = req.query["path"]
                Task { [copy = path] in _ = String(contentsOfFile: copy) } // expect-path
                path = "/srv/fixed"
                _ = String(contentsOfFile: path)
            }
        ''')

    def test_capture_initializer_is_executable_and_uses_outer_bindings(self):
        self.check('''
            func handle(req: Request) {
                let path = req.query["path"]
                Task { [path = String(contentsOfFile: path)] in // expect-path
                    consume(path)
                }
            }
        ''', suffix='tainted')
        self.check('''
            func handle(req: Request) {
                let path = "/srv/fixed"
                Task { [path = String(contentsOfFile: path)] in
                    consume(path)
                }
            }
        ''', suffix='clean')

    def test_cancelled_task_cannot_prove_a_captured_path_was_cleaned(self):
        self.check('''
            func handle(req: Request) {
                var path = req.query["path"]
                let task = Task { path = "/srv/fixed" }
                task.cancel()
                _ = String(contentsOfFile: path) // expect-path
            }
        ''', suffix='tainted')
        self.check('''
            func handle(req: Request) {
                var path = "/srv/fixed"
                let task = Task { path = "/srv/other" }
                task.cancel()
                _ = String(contentsOfFile: path)
            }
        ''', suffix='clean')

    def test_conditional_task_cleanup_does_not_validate_the_outer_value(self):
        self.check('''
            func handle(req: Request, enabled: Bool) {
                var path = req.query["path"]
                Task {
                    if enabled { path = "/srv/fixed" }
                }
                _ = String(contentsOfFile: path) // expect-path
            }
        ''')

    def test_stored_closure_receives_typed_async_throwing_arguments(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func handle(req: Request) async throws {
                        let read = { (path: String) async throws -> String in
                            return try String(contentsOfFile: path) %s
                        }
                        _ = try await read(%s)
                    }
                ''' % ('// expect-path' if tainted else '',
                       'req.query["path"]' if tainted else '"/srv/fixed"'),
                           suffix=str(tainted))

    def test_stored_closure_multiple_parameters_preserve_second_input(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func handle(req: Request) {
                        let read = { (label: String, path: String) in
                            consume(label)
                            return String(contentsOfFile: path) %s
                        }
                        _ = read("label", %s)
                    }
                ''' % ('// expect-path' if tainted else '',
                       'req.query["path"]' if tainted else '"/srv/fixed"'),
                           suffix=str(tainted))

    def test_stored_closure_preserves_return_dependencies_and_snapshot(self):
        self.check('''
            func handle(req: Request) {
                var path = req.query["path"]
                let choose = { [copy = path] () -> String in copy }
                path = "/srv/fixed"
                _ = String(contentsOfFile: choose()) // expect-path
            }
        ''', suffix='tainted')
        self.check('''
            func handle(req: Request) {
                var path = "/srv/fixed"
                let choose = { [copy = path] () -> String in copy }
                path = req.query["path"]
                _ = String(contentsOfFile: choose())
            }
        ''', suffix='clean')

    def test_typed_compact_map_closure_keeps_guard_and_conditional_flow(self):
        self.check('''
            func handle(req: Request) {
                let paths = [req.query["path"]].compactMap { (record: String?) -> String? in
                    guard let record else { return nil }
                    if record.isEmpty { return nil }
                    return record
                }
                _ = String(contentsOfFile: paths.first) // expect-path
            }
        ''', suffix='tainted')
        self.check('''
            func handle(req: Request) {
                let paths = ["/srv/fixed"].compactMap { (record: String?) -> String? in
                    guard let record else { return nil }
                    if record.isEmpty { return nil }
                    return record
                }
                _ = String(contentsOfFile: paths.first)
            }
        ''', suffix='clean')

    def test_async_let_initialization_preserves_request_dependencies(self):
        self.check('''
            func handle(req: Request) async throws {
                async let path: String = fetch(req.query["path"])
                _ = try String(contentsOfFile: await path) // expect-path
            }
        ''', suffix='tainted')
        self.check('''
            func handle(req: Request) async throws {
                async let path: String = fetch("/srv/fixed")
                _ = try String(contentsOfFile: await path)
            }
        ''', suffix='clean')

    def test_typed_catch_binding_retains_the_thrown_value(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func handle(req: Request) {
                        do {
                            throw PathError(path: %s)
                        } catch let failure as PathError {
                            _ = String(contentsOfFile: failure.path) %s
                        } catch {
                            consume(error)
                        }
                    }
                ''' % ('req.query["path"]' if tainted else '"/srv/fixed"',
                       '// expect-path' if tainted else ''), suffix=str(tainted))

    def test_implicit_catch_error_shadows_the_outer_binding(self):
        self.check('''
            func handle(req: Request) {
                let error = "/srv/fixed"
                do {
                    throw PathError(path: req.query["path"])
                } catch {
                    _ = String(contentsOfFile: error.path) // expect-path
                }
                _ = String(contentsOfFile: error)
            }
        ''')

    def test_cancellation_catch_and_defer_are_both_analyzed(self):
        self.check('''
            func handle(req: Request) {
                Task {
                    var path = "/srv/fixed"
                    defer { _ = String(contentsOfFile: path) } // expect-path
                    do {
                        try await fetch()
                    } catch is CancellationError {
                        path = req.query["path"]
                    } catch {
                        path = "/srv/other"
                    }
                }
            }
        ''')

    def test_switch_case_binding_is_local_and_carries_the_scrutinee(self):
        self.check('''
            func handle(req: Request) {
                let path = "/srv/fixed"
                switch req.query["path"] {
                case let path:
                    _ = String(contentsOfFile: path) // expect-path
                }
                _ = String(contentsOfFile: path)
            }
        ''')

    def test_switch_requires_every_reachable_branch_to_clean_a_path(self):
        for clean_all in (False, True):
            with self.subTest(clean_all=clean_all):
                self.check('''
                    func handle(req: Request, choice: Choice) {
                        var path = req.query["path"]
                        switch choice {
                        case .first: path = "/srv/first"
                        default: %s
                        }
                        _ = String(contentsOfFile: path) %s
                    }
                ''' % ('path = "/srv/other"' if clean_all else 'break',
                       '' if clean_all else '// expect-path'), suffix=str(clean_all))

    def test_repeat_executes_its_body_before_testing_the_condition(self):
        self.check('''
            func handle(req: Request, again: Bool) {
                var path = "/srv/fixed"
                repeat { path = req.query["path"] } while again
                _ = String(contentsOfFile: path) // expect-path
            }
        ''', suffix='tainted')
        self.check('''
            func handle(req: Request, again: Bool) {
                var path = req.query["path"]
                repeat { path = "/srv/fixed" } while again
                _ = String(contentsOfFile: path)
            }
        ''', suffix='clean')

    def test_repeat_continue_preserves_a_tainted_exit(self):
        self.check('''
            func handle(req: Request, flag: Bool, again: Bool) {
                var path = "/srv/fixed"
                repeat {
                    if flag { path = req.query["path"]; continue }
                    path = "/srv/other"
                } while again
                _ = String(contentsOfFile: path) // expect-path
            }
        ''')

    def test_self_static_helper_retains_argument_flow(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    struct Exporter {
                        static func choose(_ path: String) -> String { path }
                        func handle(req: Request) {
                            _ = String(contentsOfFile: Self.choose(%s)) %s
                        }
                    }
                ''' % ('req.query["path"]' if tainted else '"/srv/fixed"',
                       '// expect-path' if tainted else ''), suffix=str(tainted))

    def test_escaping_callback_initializer_does_not_hide_an_independent_sink(self):
        self.check('''
            final class Scanner {
                let onCapture: (Data?) -> Void
                init(onCapture: @escaping (Data?) -> Void) {
                    self.onCapture = onCapture
                }
            }
            func handle(req: Request) {
                let scanner = Scanner(onCapture: { data in consume(data) })
                _ = String(contentsOfFile: req.query["path"]) // expect-path
            }
        ''')

    def test_builtin_file_sink_aliases_remain_callable_inside_tasks(self):
        for callee in ('file', 'configuration.file', 'configuration.file.self'):
            for tainted in (False, True):
                with self.subTest(callee=callee, tainted=tainted):
                    self.check('''
                        func submit(req: Request) {
                            let request = %s
                            Task {
                                let reader = %s
                                reader(request) %s
                            }
                        }
                    ''' % ('req.query["path"]' if tainted else '"/srv/fixed"', callee,
                           '// expect-path' if tainted else ''),
                               suffix=callee + str(tainted))


if __name__ == '__main__':
    unittest.main()
