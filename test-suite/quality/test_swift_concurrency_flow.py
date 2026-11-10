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

from ubs_core.analyzers.taint_swift_traversal import SwiftEngine, SwiftUnsupported, flow_findings
from ubs_core.taint_flow import Budget


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
        rule = {'path': 'swift.taint.request_path_traversal',
                'redirect': 'swift.taint.request_open_redirect',
                'header': 'swift.taint.header-injection',
                'outbound': 'swift.taint.outbound-url'}[policy]
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

    def check_pattern_boundary(self, source, *, suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(SwiftUnsupported, 'matching-operator'):
            flow_findings(path, source)
        findings = flow_findings(path, source, recover=True)
        expected = {number for number, line in enumerate(source.splitlines(), 1) if '// expect-path' in line}
        actual = {item['line'] for item in findings if item['rule'] == 'swift.taint.request_path_traversal'}
        self.assertTrue(expected <= actual, findings)
        self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                            and 'matching-operator' in item['extras']['reason'] for item in findings), findings)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
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

    def test_callable_fields_receive_the_selected_argument(self):
        # Member calls, optional invocation, and an extracted function value
        # must all reach the same body. A receiver's other fields are not the
        # selected callable and cannot supply its argument or return value.
        for kind in ('closure', 'native', 'helper'):
            for invocation in ('direct', 'extracted', 'optional'):
                for tainted in (False, True):
                    with self.subTest(kind=kind, invocation=invocation, tainted=tainted):
                        marker = '// expect-path' if tainted else ''
                        definition = ('func read(_ path: String) -> String {\n'
                                      '    return String(contentsOfFile: path) ' + marker + '\n}\n'
                                      if kind == 'helper' else '')
                        initializer = ('{ (path: String) in path }'
                                       if kind == 'closure' else 'readFile' if kind == 'native' else 'read')
                        declaration = ': ((String) -> String)?' if invocation == 'optional' else ''
                        argument = 'req.query["path"]' if tainted else '"/srv/fixed"'
                        selected = ('selected' if invocation == 'extracted' else
                                    'reader.load' + ('?' if invocation == 'optional' else ''))
                        expression = selected + '(' + argument + ')'
                        if kind == 'closure':
                            expression = 'String(contentsOfFile: ' + expression + ')'
                        call = ('let selected = reader.load\n    ' if invocation == 'extracted' else '') + '_ = ' + expression
                        if kind in {'native', 'closure'}:
                            call += ' ' + marker
                        self.check(definition + 'struct Reader {\n    let load' + declaration + ' = '
                                   + initializer + '\n}\nfunc handle(req: Request) {\n'
                                   '    let reader = Reader()\n    ' + call + '\n}\n',
                                   suffix='-' + kind + '-' + invocation + '-' + str(tainted))

    def test_unrelated_methods_do_not_invoke_aggregate_callback_fields(self):
        for stored in ('closure', 'helper', 'native'):
            with self.subTest(stored=stored):
                definition = ('func read(_ path: String) -> String { return String(contentsOfFile: path) }\n'
                              if stored == 'helper' else '')
                value = ('{ (path: String) in path }' if stored == 'closure'
                         else 'readFile' if stored == 'native' else 'read')
                self.check(definition + '''
                    struct Reader {
                        let load: (String) -> String
                        func title(_ value: String) -> String { return "/srv/fixed" }
                    }
                    func handle(req: Request) {
                        let reader = Reader(load: %s)
                        _ = String(contentsOfFile: reader.title(req.query["path"]))
                    }
                ''' % value, suffix='-' + stored)

    def test_callable_field_initializer_defers_its_sink_until_invocation(self):
        for invocation in ('direct', 'extracted', 'optional'):
            for tainted in (False, True):
                with self.subTest(invocation=invocation, tainted=tainted):
                    declaration = ': ((String) -> String)?' if invocation == 'optional' else ''
                    selected = ('selected' if invocation == 'extracted' else
                                'reader.load' + ('?' if invocation == 'optional' else ''))
                    self.check('''
                        struct Reader {
                            let load%s = { (path: String) in
                                return String(contentsOfFile: path) %s
                            }
                        }
                        func handle(req: Request) {
                            let reader = Reader()
                            %s
                            _ = %s(%s)
                        }
                    ''' % (declaration, '// expect-path' if tainted else '',
                           'let selected = reader.load' if invocation == 'extracted' else '',
                           selected, 'req.query["path"]' if tainted else '"/srv/fixed"'),
                               suffix='-' + invocation + '-' + str(tainted))

    def test_escaped_callable_field_retains_limitation_and_independent_sink(self):
        source = textwrap.dedent('''
            struct Reader {
                let load = { (path: String) in
                    return String(contentsOfFile: path)
                }
            }
            func handle(req: Request) {
                let reader = Reader()
                consume(reader.load)
                _ = String(contentsOfFile: req.query["path"])
            }
        ''').lstrip('\n')
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + '.swift')
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'unknown closure parameter.*incomplete'):
            flow_findings(path, source, 'path')
        findings = flow_findings(path, source, 'path', recover=True)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        self.assertEqual([(item['rule'], item['line']) for item in findings], [
            ('swift.taint.request_path_traversal', 9),
            ('swift.taint.analysis-limited', 3),
        ], findings)

    def test_declared_callable_field_shadows_a_native_sink_name(self):
        for name in ('file', 'readFile'):
            for returns_input in (False, True):
                with self.subTest(name=name, returns_input=returns_input):
                    self.check('''
                        struct Reader {
                            let %s = { (path: String) in %s }
                        }
                        func handle(req: Request) {
                            let reader = Reader()
                            let result = reader.%s(req.query["path"])
                            _ = String(contentsOfFile: result) %s
                        }
                    ''' % (name, 'path' if returns_input else '"/srv/fixed"', name,
                           '// expect-path' if returns_input else ''),
                               suffix='-' + name + '-' + str(returns_input))

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
                    enum Choice { case first, second }
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

    def test_switch_failed_where_effects_reach_later_case(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func update(_ value: String, _ target: inout String) -> Bool {
                        target = value
                        return false
                    }
                    func handle(req: Request, choice: Int) {
                        var path = "/srv/fixed"
                        switch choice {
                        case _ where update(%s, &path): break
                        default:
                            _ = try? String(contentsOfFile: path) %s
                        }
                    }
                ''' % ('req.query["path"]!' if tainted else '"/srv/other"',
                       '// expect-path' if tainted else ''), suffix=str(tainted))

    def test_switch_scrutinee_is_evaluated_once_before_case_bindings(self):
        self.check('''
            func take(_ path: inout String) -> String {
                let original = path
                path = "/srv/fixed"
                return original
            }
            func handle(req: Request) {
                var path = req.query["path"]!
                switch take(&path) {
                case let original:
                    _ = try? String(contentsOfFile: original) // expect-path
                }
                _ = try? String(contentsOfFile: path)
            }
        ''')

    def test_switch_later_binding_keeps_the_original_scrutinee_after_where_mutation(self):
        self.check('''
            func update(_ value: String, _ target: inout String) -> Bool {
                target = value
                return false
            }
            func handle(req: Request) {
                var path = "/srv/fixed"
                switch path {
                case _ where update(req.query["path"]!, &path): break
                case let original:
                    _ = try? String(contentsOfFile: original)
                }
                _ = try? String(contentsOfFile: path) // expect-path
            }
        ''')

    def test_switch_compound_patterns_bind_only_their_own_arm(self):
        self.check('''
            func handle(req: Request) {
                let path = "/srv/fixed"
                switch req.query["path"]! {
                case let path where false, let path where true:
                    _ = try? String(contentsOfFile: path) // expect-path
                default: break
                }
                _ = try? String(contentsOfFile: path)
            }
        ''')

    def test_switch_optional_tuple_and_cast_patterns_preserve_input_dependencies(self):
        cases = (
            ('req.query["path"]', '.some(let path)'),
            ('req.query["path"]', 'let path?'),
            ('(0, req.query["path"]!)', '(_, let path)'),
            ('(0, req.query["path"]!)', 'let (_, path)'),
            ('req.query["path"]! as Any', 'let path as String'),
        )
        for index, (subject, pattern) in enumerate(cases):
            with self.subTest(pattern=pattern):
                self.check('''
                    func handle(req: Request) {
                        switch %s {
                        case %s:
                            _ = try? String(contentsOfFile: path) // expect-path
                        default: break
                        }
                    }
                ''' % (subject, pattern), suffix=str(index))

    def test_conditional_case_bindings_preserve_scope_and_dependencies(self):
        for form in ('if', 'guard', 'while'):
            for tainted in (False, True):
                source = 'req.query["path"]' if tainted else 'Optional("/srv/fixed")'
                sink = '_ = try? String(contentsOfFile: path)' + (' // expect-path' if tainted else '')
                if form == 'guard':
                    selected = 'guard case .some(let path) = %s else { return }\n%s' % (source, sink)
                else:
                    selected = '%s case .some(let path) = %s {\n%s\n%s\n}' % (
                        form, source, sink, 'break' if form == 'while' else '')
                with self.subTest(form=form, tainted=tainted):
                    self.check('''
                        func handle(req: Request) {
                            %s
                        }
                    ''' % selected, suffix=form + str(tainted))
        self.check('''
            func handle(req: Request, enabled: Bool) {
                let path = "/srv/fixed"
                if enabled, case let path? = req.query["path"], !path.isEmpty {
                    _ = try? String(contentsOfFile: path) // expect-path
                }
                _ = try? String(contentsOfFile: path)
            }
        ''', suffix='scope')

    def test_switch_case_body_condition_is_not_mistaken_for_a_new_arm(self):
        self.check('''
            func handle(req: Request, selected: Int) {
                switch selected {
                case 0:
                    if case .some(let path) = req.query["path"] {
                        _ = try? String(contentsOfFile: path) // expect-path
                    }
                default: break
                }
            }
        ''')

    def test_switch_qualified_declared_enum_case_is_supported(self):
        self.check('''
            enum Choice { case first, second }
            func handle(req: Request, choice: Choice) {
                switch choice {
                case Choice.first:
                    _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                case Choice.second: break
                }
            }
        ''')

    def test_switch_declared_enum_types_follow_local_and_field_scopes(self):
        cases = (
            '''enum Choice { case first, second }
            func handle(req: Request, input: Choice) {
                let choice: Choice = input
                switch choice {
                case .first: _ = try? String(contentsOfFile: VALUE) EXPECT
                default: break
                }
            }''',
            '''struct Holder {
                enum Choice { case first, second }
                let choice: Choice
            }
            struct Handler {
                enum Choice { case unrelated }
                func handle(req: Request, holder: Holder) {
                    switch holder.choice {
                    case .first: _ = try? String(contentsOfFile: VALUE) EXPECT
                    default: break
                    }
                }
            }''',
            '''struct Outer {
                enum Choice { case first, second }
                struct Inner {
                    enum Choice { case unrelated }
                    func handle(req: Request, choice: Outer.Choice) {
                        switch choice {
                        case Outer.Choice.first: _ = try? String(contentsOfFile: VALUE) EXPECT
                        default: break
                        }
                    }
                }
            }''',
        )
        for index, source in enumerate(cases):
            for tainted in (False, True):
                with self.subTest(index=index, tainted=tainted):
                    self.check(source.replace('VALUE', 'req.query["path"]!' if tainted else '"/srv/fixed"')
                               .replace('EXPECT', '// expect-path' if tainted else ''),
                               suffix=str(index) + str(tainted))

    def test_switch_unknown_member_and_custom_operators_remain_incomplete(self):
        self.check_pattern_boundary('''
            enum Choice { case first }
            func handle(req: Request, value: External) {
                switch value { case .first: break; default: break }
                _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
            }
        ''', suffix='external')
        for label, pattern_type in (('Pattern.any', 'Pattern'), ('"fixed"', 'String')):
            with self.subTest(label=label):
                self.check_pattern_boundary('''
                    enum Pattern { case any }
                    func ~= (pattern: %s, value: String) -> Bool {
                        _ = try? String(contentsOfFile: value)
                        return true
                    }
                    func handle(req: Request) {
                        switch req.query["path"]! { case %s: break; default: break }
                        _ = try? String(contentsOfFile: req.query["other"]!) // expect-path
                    }
                ''' % (pattern_type, label), suffix=pattern_type)

    def test_switch_projected_patterns_cannot_use_the_parent_enum_type(self):
        for form in ('switch choice { case .pair(let path, .marker): break; default: break }',
                     'if case .pair(let path, .marker) = choice { consume(path) }'):
            with self.subTest(form=form):
                self.check_pattern_boundary('''
                    enum Choice { case marker, pair(String, String) }
                    extension String { static var marker: String { "/srv/fixed" } }
                    func handle(req: Request, choice: Choice) {
                        %s
                        _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                    }
                ''' % form, suffix='switch' if form.startswith('switch') else 'if')

    def test_switch_type_proofs_respect_subject_and_qualifier_shadowing(self):
        cases = (
            '''enum Choice { case first }
            func ~= (pattern: Choice, value: String) -> Bool { true }
            func handle(req: Request, choice: Choice) {
                let choice = req.query["path"]!
                switch choice { case Choice.first: break; default: break }
                _ = try? String(contentsOfFile: choice) // expect-path
            }''',
            '''enum Choice { case first }
            func ~= (pattern: Choice, value: String) -> Bool { true }
            func handle(req: Request, choice: Choice) {
                switch req.query["path"]! {
                case let choice:
                    switch choice { case Choice.first: break; default: break }
                    _ = try? String(contentsOfFile: choice) // expect-path
                }
            }''',
            '''struct Outer {
                enum Choice { case first }
                struct Inner {
                    enum Choice { case first }
                    func handle(req: Request, value: Outer.Choice) {
                        switch value { case Choice.first: break; default: break }
                        _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                    }
                }
            }
            func ~= (pattern: Outer.Inner.Choice, value: Outer.Choice) -> Bool { true }''',
            '''enum Choice { case first }
            struct Factory {
                let path: String
                var first: Choice {
                    _ = try? String(contentsOfFile: path) // expect-path
                    return .first
                }
            }
            func handle(req: Request, choice: Choice) {
                let Choice = Factory(path: req.query["path"]!)
                switch choice { case Choice.first: break; default: break }
                _ = try? String(contentsOfFile: req.query["other"]!) // expect-path
            }''',
        )
        for index, source in enumerate(cases):
            with self.subTest(index=index):
                self.check_pattern_boundary(source, suffix=str(index))

    def test_switch_modifier_static_and_generic_types_need_exact_identity(self):
        cases = (
            '''enum Choice { case first }
            struct inoutChoice: Equatable {
                static var first: inoutChoice { inoutChoice() }
            }
            func handle(req: Request, value: inoutChoice) {
                switch value { case .first: break; default: break }
                _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
            }''',
            '''enum Choice {
                case first
                static func handle(req: Request) {
                    switch self { case Choice.first: break; default: break }
                    _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                }
            }
            func ~= (pattern: Choice, value: Choice.Type) -> Bool { true }''',
            '''enum Choice {
                case first
                static func handle(req: Request) {
                    Task {
                        switch self { case Choice.first: break; default: break }
                        _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                    }
                }
            }
            func ~= (pattern: Choice, value: Choice.Type) -> Bool { true }''',
            '''enum Choice { case first }
            protocol Selectable: Equatable { static var first: Self { get } }
            func handle<Choice: Selectable>(req: Request, value: Choice) {
                switch value { case .first: break; default: break }
                _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
            }''',
            '''enum Choice { case first }
            extension String { static var first: String { "/srv/fixed" } }
            struct Handler {
                typealias Choice = String
                func handle(req: Request, value: Choice) {
                    switch value { case .first: break; default: break }
                    _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                }
            }''',
        )
        for index, source in enumerate(cases):
            with self.subTest(index=index):
                self.check_pattern_boundary(source, suffix=str(index))

    def test_switch_associated_wildcards_and_instance_self_stay_supported(self):
        for pattern in ('.some(_)', 'Optional.some(_)'):
            with self.subTest(pattern=pattern):
                self.check('''
                    func handle(req: Request) {
                        switch req.query["path"] {
                        case %s: _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                        default: break
                        }
                    }
                ''' % pattern, suffix=pattern.replace('.', '-').replace('(', '').replace(')', ''))
        self.check('''
            enum Choice {
                case first, second
                func handle(req: Request) {
                    switch self {
                    case .first: _ = try? String(contentsOfFile: req.query["path"]!) // expect-path
                    default: break
                    }
                }
            }
        ''', suffix='self')

    def test_switch_computed_property_label_remains_an_explicit_boundary(self):
        for label in ('Marker.value', '.value', 'External.value'):
            source = '''struct Marker { static var value: String { "/srv/fixed" } }
            func handle(req: Request) {
                let path = req.query["path"]!
                switch path {
                case %s: break
                default: break
                }
                _ = try? String(contentsOfFile: path)
            }''' % label
            path = self.artifacts / (self.id().rsplit('.', 1)[-1] + label.replace('.', '-') + '.swift')
            path.write_text(source, encoding='utf-8')
            with self.subTest(label=label):
                with self.assertRaisesRegex(SwiftUnsupported, 'matching-operator'):
                    flow_findings(path, source)
                findings = flow_findings(path, source, recover=True)
                self.assertTrue(any(item['rule'] == 'swift.taint.request_path_traversal' and item['line'] == 8
                                    for item in findings), findings)
                self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                                    and 'matching-operator' in item['extras']['reason'] for item in findings), findings)
                path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')

    def test_switch_custom_literal_matching_is_not_assumed_pure(self):
        source = textwrap.dedent('''
            struct Key: ExpressibleByIntegerLiteral, Equatable {
                let raw: Int
                init(integerLiteral value: Int) { raw = value }
                static func == (left: Key, right: Key) -> Bool { left.raw == right.raw }
            }
            func handle(req: Request, key: Key) {
                switch key {
                case 0: break
                default: break
                }
                _ = try? String(contentsOfFile: req.query["path"]!)
            }
        ''').lstrip('\n')
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + '.swift')
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(SwiftUnsupported, 'matching-operator'):
            flow_findings(path, source)
        findings = flow_findings(path, source, recover=True)
        self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                            and 'matching-operator' in item['extras']['reason'] for item in findings), findings)
        self.assertTrue(any(item['rule'] == 'swift.taint.request_path_traversal' and item['line'] == 11
                            for item in findings), findings)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')

    def test_switch_expression_returns_from_a_closure(self):
        self.check('''
            func handle(req: Request, flag: Bool) {
                let select = { (value: String) in
                    switch flag {
                    case true: value
                    default: "/srv/fixed"
                    }
                }
                _ = try? String(contentsOfFile: select(req.query["path"]!)) // expect-path
            }
        ''')

    def test_switch_case_bindings_retain_all_four_sink_policies(self):
        sinks = {
            'path': '_ = try? String(contentsOfFile: value)',
            'redirect': '_ = req.redirect(to: value)',
            'header': 'response.headers["X-Trace"] = value',
            'outbound': '_ = URLSession.shared.dataTask(with: URL(string: value)!)',
        }
        for policy, sink in sinks.items():
            for tainted in (False, True):
                with self.subTest(policy=policy, tainted=tainted):
                    self.check('''
                        import Foundation
                        func handle(req: Request) {
                            switch %s {
                            case let value:
                                %s %s
                            }
                        }
                    ''' % ('req.query["value"]!' if tainted else '"/srv/fixed"', sink,
                           '// expect-' + policy if tainted else ''),
                               policy=policy, suffix=policy + str(tainted))

    def test_switch_where_validation_applies_only_to_its_checked_binding(self):
        self.check(r'''
            func handle(req: Request) {
                let original = req.query["header"]!
                switch original {
                case let checked where !checked.contains("\r") && !checked.contains("\n"):
                    response.headers["X-Checked"] = checked
                    response.headers["X-Original"] = original // expect-header
                default: break
                }
            }
        ''', policy='header')

    def test_switch_false_where_does_not_execute_its_body(self):
        self.check('''
            func handle(req: Request) {
                switch req.query["path"]! {
                case let path where false:
                    _ = try? String(contentsOfFile: path)
                default: break
                }
            }
        ''')

    def test_switch_fallthrough_runs_case_defer_and_bypasses_next_where(self):
        self.check('''
            func handle(req: Request, choice: Int, flag: Bool) {
                var path = "/srv/fixed"
                switch choice {
                case 0:
                    defer { path = req.query["path"]! }
                    if flag { fallthrough }
                case 1 where false:
                    _ = try? String(contentsOfFile: path) // expect-path
                default: break
                }
            }
        ''')

    def test_nested_switch_fallthrough_stays_with_its_own_switch(self):
        self.check('''
            func handle(req: Request, outer: Int, inner: Int) {
                var path = "/srv/fixed"
                switch outer {
                case 0:
                    switch inner {
                    case 0:
                        path = req.query["path"]!
                        fallthrough
                    default:
                        _ = try? String(contentsOfFile: path) // expect-path
                    }
                    path = "/srv/fixed"
                default:
                    _ = try? String(contentsOfFile: path)
                }
            }
        ''')

    def test_switch_expression_values_reach_callers_and_assignments(self):
        for spelling in ('implicit', 'return', 'assignment'):
            for tainted in (False, True):
                choose = '''switch flag {
                    case true: value
                    default: "/srv/fixed"
                }'''
                if spelling == 'return':
                    choose = 'return ' + choose
                elif spelling == 'assignment':
                    choose = 'let result = ' + choose + '\nreturn result'
                with self.subTest(spelling=spelling, tainted=tainted):
                    self.check('''
                        func choose(_ value: String, flag: Bool) -> String {
                            %s
                        }
                        func handle(req: Request, flag: Bool) {
                            _ = try? String(contentsOfFile: choose(%s, flag: flag)) %s
                        }
                    ''' % (choose, 'req.query["path"]!' if tainted else '"/srv/fixed"',
                           '// expect-path' if tainted else ''), suffix=spelling + str(tainted))

    def test_repeat_does_not_consume_a_following_while_statement(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func handle(req: Request, flag: Bool) {
                        var path = "/srv/fixed"
                        repeat { consume(path) }
                        while false
                        while flag {
                            path = %s
                            break
                        }
                        _ = try? String(contentsOfFile: path) %s
                    }
                ''' % ('req.query["path"]!' if tainted else '"/srv/other"',
                       '// expect-path' if tainted else ''), suffix=str(tainted))

    def test_repeat_condition_throw_runs_enclosing_defer_before_later_cleanup(self):
        for attempt in ('try', 'try?'):
            with self.subTest(attempt=attempt):
                self.check('''
                    func handle(req: Request) throws {
                        var path = "/srv/fixed"
                        defer { _ = try? String(contentsOfFile: path) } %s
                        repeat { path = req.query["path"]! }
                        while (%s keepGoing()) == true
                        path = "/srv/fixed"
                    }
                ''' % ('// expect-path' if attempt == 'try' else '', attempt), suffix=attempt)

    def test_repeat_defer_runs_on_continue_and_break(self):
        for transfer in ('continue', 'break'):
            for tainted in (False, True):
                with self.subTest(transfer=transfer, tainted=tainted):
                    self.check('''
                        func handle(req: Request, flag: Bool) {
                            var path = "/srv/fixed"
                            repeat {
                                defer { path = %s }
                                if flag { %s }
                                path = "/srv/other"
                            } while false
                            _ = try? String(contentsOfFile: path) %s
                        }
                    ''' % ('req.query["path"]!' if tainted else '"/srv/fixed"', transfer,
                           '// expect-path' if tainted else ''), suffix=transfer + str(tainted))

    def test_repeat_only_registered_defers_run_on_early_exits(self):
        for exit_kind in ('break', 'continue'):
            for registered in (False, True):
                deferred = 'defer { path = "/srv/fixed" }'
                with self.subTest(exit_kind=exit_kind, registered=registered):
                    self.check('''
                        func handle(req: Request, stop: Bool) {
                            var path = req.query["path"]!
                            repeat {
                                %s
                                if stop { %s }
                                %s
                            } while false
                            _ = try? String(contentsOfFile: path) %s
                        }
                    ''' % (deferred if registered else '', exit_kind,
                           '' if registered else deferred, '' if registered else '// expect-path'),
                               suffix=exit_kind + str(registered))

    def test_switch_only_registered_defers_run_on_early_break(self):
        for registered in (False, True):
            deferred = 'defer { path = "/srv/fixed" }'
            with self.subTest(registered=registered):
                self.check('''
                    func handle(req: Request, selected: Bool, stop: Bool) {
                        var path = req.query["path"]!
                        switch selected {
                        case true:
                            %s
                            if stop { break }
                            %s
                        default: path = "/srv/fixed"
                        }
                        _ = try? String(contentsOfFile: path) %s
                    }
                ''' % (deferred if registered else '', '' if registered else deferred,
                       '' if registered else '// expect-path'), suffix=str(registered))

    def test_return_only_runs_registered_defers_and_preserves_reverse_order(self):
        for kind in ('repeat', 'switch'):
            for registered in (False, True):
                deferred = 'defer { path = "/srv/fixed" }'
                statements = '%s\nif stop { return }\n%s' % (
                    deferred if registered else '', '' if registered else deferred)
                scope = ('repeat {\n%s\n} while false' % statements if kind == 'repeat' else
                         'switch selected { case true:\n%s\ndefault: path = "/srv/fixed" }' % statements)
                with self.subTest(kind=kind, registered=registered):
                    self.check('''
                        func clean(_ path: inout String, _ selected: Bool, _ stop: Bool) {
                            %s
                        }
                        func handle(req: Request, selected: Bool, stop: Bool) {
                            var path = req.query["path"]!
                            clean(&path, selected, stop)
                            _ = try? String(contentsOfFile: path) %s
                        }
                    ''' % (scope, '' if registered else '// expect-path'), suffix=kind + str(registered))
        for unsafe_last in (False, True):
            first = 'req.query["path"]!' if unsafe_last else '"/srv/fixed"'
            second = '"/srv/fixed"' if unsafe_last else 'req.query["path"]!'
            self.check('''
                func handle(req: Request) {
                    var path = "/srv/fixed"
                    repeat {
                        defer { path = %s }
                        defer { path = %s }
                    } while false
                    _ = try? String(contentsOfFile: path) %s
                }
            ''' % (first, second, '// expect-path' if unsafe_last else ''), suffix='order' + str(unsafe_last))

    def test_conditional_defer_registration_remains_explicitly_incomplete(self):
        source = textwrap.dedent('''
            func handle(req: Request) {
                var path = req.query["path"]!
                repeat {
                    #if DEBUG
                    defer { path = "/srv/fixed" }
                    #endif
                } while false
                _ = try? String(contentsOfFile: path)
            }
        ''').lstrip('\n')
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + '.swift')
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(SwiftUnsupported, 'conditional defer registration'):
            flow_findings(path, source)
        findings = flow_findings(path, source, recover=True)
        self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                            and 'conditional defer registration' in item['extras']['reason'] for item in findings), findings)
        self.assertTrue(any(item['rule'] == 'swift.taint.request_path_traversal' and item['line'] == 8
                            for item in findings), findings)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')

    def test_repeat_nested_switch_break_and_continue_have_distinct_targets(self):
        for transfer in ('break', 'continue'):
            with self.subTest(transfer=transfer):
                self.check('''
                    func handle(req: Request, choice: Int) {
                        var path = "/srv/fixed"
                        repeat {
                            switch choice {
                            case 0:
                                path = req.query["path"]!
                                %s
                            default: break
                            }
                            path = "/srv/fixed"
                        } while false
                        _ = try? String(contentsOfFile: path) %s
                    }
                ''' % (transfer, '// expect-path' if transfer == 'continue' else ''), suffix=transfer)

    def test_repeat_loop_carried_dependencies_reach_a_later_iteration(self):
        for tainted in (False, True):
            with self.subTest(tainted=tainted):
                self.check('''
                    func handle(req: Request, again: Bool) {
                        var first = "/srv/fixed"
                        var second = "/srv/fixed"
                        repeat {
                            _ = try? String(contentsOfFile: second) %s
                            second = first
                            first = %s
                        } while again
                    }
                ''' % ('// expect-path' if tainted else '',
                       'req.query["path"]!' if tainted else '"/srv/fixed"'), suffix=str(tainted))

    def test_switch_and_repeat_analysis_fit_a_fixed_work_budget(self):
        for tainted in (False, True):
            cases = '\n'.join('case %d: path = "/srv/fixed"' % index for index in range(96))
            source = '''func handle(req: Request, choice: Int, again: Bool) {
                var path = "/srv/fixed"
                repeat {
                    switch choice {
                    %s
                    default: path = %s
                    }
                    _ = try? String(contentsOfFile: path)
                } while again
            }''' % (cases, 'req.query["path"]!' if tainted else '"/srv/fixed"')
            path = self.artifacts / (self.id().rsplit('.', 1)[-1] + str(tainted) + '.swift')
            path.write_text(source, encoding='utf-8')
            engine = SwiftEngine(path, source)
            engine.budget = Budget(20_000)
            effects = engine.analyze()
            self.assertEqual(set(effects), {source.index('String(contentsOfFile:')} if tainted else set())
            self.assertGreater(engine.budget.remaining, 0)
            path.with_suffix('.json').write_text(json.dumps({
                'effects': sorted(effects), 'work_units': 20_000 - engine.budget.remaining,
                'contexts': len(engine.contexts),
            }, indent=2), encoding='utf-8')

    def test_unmodeled_expression_pattern_keeps_its_sink_and_reports_incomplete(self):
        source = textwrap.dedent('''
            func handle(req: Request, selected: String) throws {
                switch selected {
                case try String(contentsOfFile: req.query["path"]!): break
                default: break
                }
            }
        ''').lstrip('\n')
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + '.swift')
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(SwiftUnsupported, 'matching-operator'):
            flow_findings(path, source)
        findings = flow_findings(path, source, recover=True)
        self.assertEqual([(item['rule'], item['line']) for item in findings], [
            ('swift.taint.request_path_traversal', 3), ('swift.taint.analysis-limited', 3)])
        self.assertIn('matching-operator', findings[-1]['extras']['reason'])
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')

    def test_invalid_fallthrough_never_becomes_a_clean_scan(self):
        for arms in ('case 0: fallthrough', 'case 0: fallthrough\ncase let path: consume(path)'):
            source = '''func handle(req: Request, choice: Int) {
                switch choice { %s }
                _ = try? String(contentsOfFile: req.query["path"]!)
            }''' % arms
            for recover in (False, True):
                with self.subTest(arms=arms, recover=recover):
                    with self.assertRaisesRegex(ValueError, 'fallthrough'):
                        flow_findings(self.artifacts / 'invalid-fallthrough.swift', source, recover=recover)

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
