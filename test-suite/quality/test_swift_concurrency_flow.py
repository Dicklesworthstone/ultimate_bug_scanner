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

    def test_selected_helper_exports_writes_to_a_callers_captured_variable(self):
        for attribute in ('', '@escaping '):
            for tainted in (False, True):
                with self.subTest(attribute=attribute, tainted=tainted):
                    self.check('''
                        func invoke(_ body: %s() -> Void) { body() }
                        func handle(req: Request) {
                            var path = "/srv/fixed"
                            let changePath = { path = %s }
                            invoke(changePath)
                            _ = String(contentsOfFile: path) %s
                        }
                    ''' % (attribute, 'req.query["path"]' if tainted else '"/srv/other"',
                           '// expect-path' if tainted else ''),
                               suffix=attribute.strip() + str(tainted))

    def test_helper_callback_effects_are_conditional_on_reachable_invocation(self):
        for body, invoked in (('body()', True), ('if enabled { body() }', True),
                              ('if false { body() }', False), ('consume(enabled)', False)):
            with self.subTest(body=body):
                self.check('''
                    func invoke(_ enabled: Bool, _ body: () -> Void) { %s }
                    func handle(req: Request, enabled: Bool) {
                        var path = "/srv/fixed"
                        invoke(enabled, { path = req.query["path"] })
                        _ = String(contentsOfFile: path) %s
                    }
                ''' % (body, '// expect-path' if invoked else ''),
                           suffix=str(invoked) + str(len(body)))

    def test_captured_writes_cross_transitive_and_nested_helper_calls(self):
        for nested in (False, True):
            for tainted in (False, True):
                with self.subTest(nested=nested, tainted=tainted):
                    assignment = 'path = ' + ('req.query["path"]' if tainted else '"/srv/other"')
                    self.check('''
                        func invoke(_ body: () -> Void) { body() }
                        func forward(_ body: () -> Void) { invoke(body) }
                        func handle(req: Request) {
                            var path = "/srv/fixed"
                            forward({ %s })
                            _ = String(contentsOfFile: path) %s
                        }
                    ''' % ('invoke({ ' + assignment + ' })' if nested else assignment,
                           '// expect-path' if tainted else ''),
                               suffix=str(nested) + str(tainted))

    def test_read_only_and_snapshot_callbacks_do_not_replay_stale_capture_values(self):
        for capture in ('', '[path] in '):
            with self.subTest(capture=capture):
                self.check('''
                    func invoke(_ body: () -> Void) { body() }
                    func handle(req: Request) {
                        var path = req.query["path"]
                        let read = { %sconsume(path) }
                        path = "/srv/fixed"
                        invoke(read)
                        _ = String(contentsOfFile: path)
                    }
                ''' % capture, suffix=str(bool(capture)))

    def test_nested_helper_write_is_retained_when_capture_join_already_has_its_value(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func invoke(_ body: () -> Void) { body() }
                    func handle(req: Request) {
                        let input = %s
                        var path = input
                        let outer = { invoke({ path = input }) }
                        path = "/srv/fixed"
                        invoke(outer)
                        _ = String(contentsOfFile: path) %s
                    }
                ''' % ('req.query["path"]' if tainted else '"/srv/other"',
                       '// expect-path' if tainted else ''), suffix=str(tainted))

    def test_callback_local_shadow_does_not_write_the_outer_capture(self):
        self.check('''
            func invoke(_ body: () -> Void) { body() }
            func handle(req: Request) {
                var path = "/srv/fixed"
                invoke({
                    var path = req.query["path"]
                    consume(path)
                })
                _ = String(contentsOfFile: path)
            }
        ''')

    def test_captured_inout_writes_are_distinct_from_unchanged_exit_values(self):
        for body, written in (('path = value', True), ('consume(path)', False)):
            for forwarded in (False, True):
                for tainted in (False, True):
                    with self.subTest(body=body, forwarded=forwarded, tainted=tainted):
                        self.check('''
                            func update(_ path: inout String, _ value: String) { %s }
                            func forward(_ path: inout String, _ value: String) { update(&path, value) }
                            func invoke(_ body: () -> Void) { body() }
                            func handle(req: Request, fixed: String) {
                                let requestInput = req.query["path"]
                                let input = %s
                                var path = input
                                let outer = { %s(&path, input) }
                                path = fixed
                                invoke(outer)
                                _ = String(contentsOfFile: path) %s
                            }
                        ''' % (body, 'requestInput' if tainted else '"/srv/other"',
                               'forward' if forwarded else 'update',
                               '// expect-path' if written and tainted else ''),
                                   suffix=str(written) + str(forwarded) + str(tainted))

    def test_captured_inout_write_metadata_keeps_parameter_positions(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func update(_ first: inout String, _ path: inout String, _ value: String) {
                        path = value
                    }
                    func invoke(_ body: () -> Void) { body() }
                    func handle(req: Request, fixed: String) {
                        let requestInput = req.query["path"]
                        let input = %s
                        var first = "/srv/fixed"
                        var path = input
                        let outer = { update(&first, &path, input) }
                        path = fixed
                        invoke(outer)
                        _ = String(contentsOfFile: first)
                        _ = String(contentsOfFile: path) %s
                    }
                ''' % ('requestInput' if tainted else '"/srv/other"',
                       '// expect-path' if tainted else ''), suffix=str(tainted))

    def test_helper_callback_cannot_prove_a_conditional_capture_cleanup(self):
        self.check('''
            func invoke(_ enabled: Bool, _ body: () -> Void) {
                if enabled { body() }
            }
            func handle(req: Request, enabled: Bool) {
                var path = req.query["path"]
                invoke(enabled, { path = "/srv/fixed" })
                _ = String(contentsOfFile: path) // expect-path
            }
        ''')

    def test_callee_parameter_name_does_not_alias_a_closure_capture(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func invoke(_ path: String, _ body: () -> Void) { body() }
                    func use(_ path: String, other: String) {
                        invoke(other, { _ = String(contentsOfFile: path) }) %s
                    }
                    func handle(req: Request) {
                        use(%s, other: %s)
                    }
                ''' % ('// expect-path' if tainted else '',
                       'req.query["path"]' if tainted else '"/srv/fixed"',
                       '"/srv/fixed"' if tainted else 'req.query["path"]'),
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
