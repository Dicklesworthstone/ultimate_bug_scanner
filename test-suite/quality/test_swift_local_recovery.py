"""Local Swift analysis limitations must not erase established security flows.

Strict analysis refuses unsupported effects. Normal analysis reports their
source location and conservative scope, while retaining real sinks in the
same function and its siblings. Malformed input and exhausted budgets remain
fatal in both modes. Source fixtures and findings are retained in artifacts.
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

from ubs_core.analyzers.taint_swift_traversal import (
    SwiftEngine, SwiftUnsupported, flow_findings,
)
from ubs_core.taint_flow import AnalysisLimit


PATH_RULE = 'swift.taint.request_path_traversal'
LIMIT_RULE = 'swift.taint.analysis-limited'


class SwiftLocalRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-local-recovery-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def fixture(self, source, suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        return path, source

    def analyze(self, path, source, *, recover):
        mode = 'recovery' if recover else 'strict'
        try:
            findings = flow_findings(path, source, 'path', recover=recover)
        except Exception as error:
            path.with_suffix('.' + mode + '-error.json').write_text(json.dumps({
                'type': type(error).__name__, 'message': str(error),
                'offset': getattr(error, 'offset', None),
            }, indent=2), encoding='utf-8')
            raise
        path.with_suffix('.' + mode + '.json').write_text(
            json.dumps(findings, indent=2), encoding='utf-8')
        return findings

    def assert_sinks(self, findings, path, lines):
        self.assertTrue(all(item['rule'] in {PATH_RULE, LIMIT_RULE} for item in findings), findings)
        sinks = [item for item in findings if item['rule'] == PATH_RULE]
        self.assertEqual([item['line'] for item in sinks], list(lines), findings)
        for finding in sinks:
            self.assertEqual(finding['path'], str(path.resolve()), finding)
            self.assertEqual(finding['severity'], 'critical', finding)
            route = finding['extras']['taint_path']
            self.assertEqual(route[0]['kind'], 'source', finding)
            self.assertEqual(route[-1]['kind'], 'sink', finding)
            self.assertEqual((route[-1]['line'], route[-1]['col']),
                             (finding['line'], finding['col']), finding)
        return sinks

    def assert_warning(self, findings, path, *, reason, line, col, scope, construct):
        warnings = [item for item in findings if item['rule'] == LIMIT_RULE
                    and item['extras']['reason'] == reason]
        self.assertEqual(len(warnings), 1, findings)
        warning = warnings[0]
        self.assertEqual(warning['path'], str(path.resolve()), warning)
        self.assertEqual((warning['line'], warning['col']), (line, col), warning)
        self.assertEqual(warning['severity'], 'warning', warning)
        self.assertEqual(warning['extras']['analysis'], 'conservative', warning)
        self.assertEqual(warning['extras']['policy'], 'path', warning)
        self.assertEqual(warning['extras']['scope'], scope, warning)
        self.assertTrue(warning['extras']['construct'].startswith(construct), warning)
        self.assertIn(reason, warning['message'], warning)
        self.assertNotIn('taint_path', warning['extras'], warning)
        return warning

    def test_stored_heap_capture_reports_unknown_effect_and_keeps_independent_sinks(self):
        path, source = self.fixture('''
            class Box { var path: String = "/srv/fixed" }
            func handle(req: Request) {
                let box = Box()
                let read = { String(contentsOfFile: box.path) }
                update(box, req.query["path"])
                _ = read()
                _ = String(contentsOfFile: req.query["after"])
            }
            func sibling(req: Request) {
                _ = String(contentsOfFile: req.query["sibling"])
            }
        ''')
        with self.assertRaisesRegex(SwiftUnsupported, 'heap/alias') as refused:
            self.analyze(path, source, recover=False)
        self.assertEqual(refused.exception.offset, source.index('update('))
        findings = self.analyze(path, source, recover=True)
        self.assert_sinks(findings, path, (7, 10))
        self.assert_warning(
            findings, path,
            reason='Swift unresolved reference call needs heap/alias analysis',
            line=5, col=5, scope='handle', construct='update(box,')
        self.assert_warning(
            findings, path,
            reason='Swift unknown closure parameter or opaque value reaches a sink',
            line=4, col=18, scope='<closure>', construct='String(contentsOfFile: box.path)')
        self.assertEqual(sum(item['rule'] == LIMIT_RULE for item in findings), 2, findings)

    def test_stored_heap_capture_with_only_fixed_path_updates_is_clean(self):
        path, source = self.fixture('''
            class Box { var path: String = "/srv/fixed" }
            func handle(req: Request) {
                let box = Box()
                let read = { String(contentsOfFile: box.path) }
                update(box, "/srv/other")
                _ = read()
            }
        ''')
        for recover in (False, True):
            with self.subTest(recover=recover):
                self.assertEqual(self.analyze(path, source, recover=recover), [])

    def test_implicit_initializer_field_assignment_preserves_value_identity(self):
        for value, expected in (('req.query["path"]!', (9,)), ('"/srv/fixed"', ())):
            with self.subTest(value=value):
                path, source = self.fixture('''
                    final class Box {
                        let path: String
                        init(_ value: String) {
                            path = value
                        }
                    }
                    func handle(req: Request) {
                        let box = Box(%s)
                        _ = String(contentsOfFile: box.path)
                    }
                ''' % value, '-tainted' if expected else '-fixed')
                for recover in (False, True):
                    with self.subTest(recover=recover):
                        findings = self.analyze(path, source, recover=recover)
                        self.assert_sinks(findings, path, expected)
                        self.assertFalse(any(item['rule'] == LIMIT_RULE for item in findings), findings)

    def test_initializer_local_shadow_does_not_taint_the_stored_field(self):
        path, source = self.fixture('''
            final class Box {
                let path: String
                init(_ value: String) {
                    var path = "/srv/local"
                    path = value
                    self.path = "/srv/fixed"
                    consume(path)
                }
            }
            func handle(req: Request) {
                let box = Box(req.query["path"]!)
                _ = String(contentsOfFile: box.path)
            }
        ''')
        for recover in (False, True):
            with self.subTest(recover=recover):
                self.assertEqual(self.analyze(path, source, recover=recover), [])

    def test_unsupported_loop_pattern_is_local_and_later_sinks_are_retained(self):
        path, source = self.fixture('''
            func handle(req: Request) {
                let values: [Any] = [req.query["candidate"]!]
                for case let value as String in values {
                    consume(value)
                }
                _ = String(contentsOfFile: req.query["after"])
            }
            func sibling(req: Request) {
                _ = String(contentsOfFile: req.query["sibling"])
            }
        ''')
        with self.assertRaisesRegex(SwiftUnsupported, 'iteration binding needs pattern analysis') as refused:
            self.analyze(path, source, recover=False)
        self.assertEqual(refused.exception.offset, source.index('case let'))
        findings = self.analyze(path, source, recover=True)
        self.assert_sinks(findings, path, (6, 9))
        self.assert_warning(
            findings, path, reason='Swift iteration binding needs pattern analysis',
            line=3, col=9, scope='handle', construct='case let value as String in values')
        self.assertEqual(sum(item['rule'] == LIMIT_RULE for item in findings), 1, findings)

    def test_mixed_named_and_closure_callables_analyze_each_unsafe_alternative(self):
        sources = (('helper', '''
            func read(_ path: String) {
                _ = String(contentsOfFile: path)
            }
            func handle(req: Request, flag: Bool) {
                let callback = flag ? read : { path in consume(path) }
                callback(req.query["path"]!)
            }
        ''', (2,)), ('closure', '''
            func read(_ path: String) {
                consume(path)
            }
            func handle(req: Request, flag: Bool) {
                let callback = flag ? read : { path in
                    _ = String(contentsOfFile: path)
                }
                callback(req.query["path"]!)
            }
        ''', (6,)), ('fixed-argument', '''
            func read(_ path: String) {
                _ = String(contentsOfFile: path)
            }
            func handle(req: Request, flag: Bool) {
                let callback = flag ? read : { path in
                    _ = String(contentsOfFile: path)
                }
                callback("/srv/fixed")
            }
        ''', ()), ('safe-branches', '''
            func read(_ path: String) {
                consume(path)
            }
            func handle(req: Request, flag: Bool) {
                let callback = flag ? read : { path in consume(path) }
                callback(req.query["path"]!)
                _ = String(contentsOfFile: "/srv/fixed")
            }
        ''', ()))
        for name, source, expected in sources:
            path, source = self.fixture(source, '-' + name)
            for recover in (False, True):
                with self.subTest(case=name, recover=recover):
                    findings = self.analyze(path, source, recover=recover)
                    self.assert_sinks(findings, path, expected)
                    self.assertFalse(any(item['rule'] == LIMIT_RULE for item in findings), findings)

    def test_recursive_stored_callback_warns_without_erasing_the_real_base_case_sink(self):
        path, source = self.fixture('''
            func handle(req: Request) {
                var visit: ((Int) -> Void)?
                visit = { remaining in
                    if remaining > 0 {
                        visit?(remaining - 1)
                    } else {
                        _ = String(contentsOfFile: req.query["path"])
                    }
                }
                visit?(1)
            }
        ''')
        with self.assertRaisesRegex(SwiftUnsupported, 'recursive stored callback') as refused:
            self.analyze(path, source, recover=False)
        self.assertEqual(refused.exception.offset, source.index('{ remaining'))
        findings = self.analyze(path, source, recover=True)
        self.assert_sinks(findings, path, (7,))
        self.assert_warning(
            findings, path, reason='Swift recursive stored callback needs a recursive closure summary',
            line=3, col=13, scope='<closure>', construct='{ remaining in')
        self.assertEqual(sum(item['rule'] == LIMIT_RULE for item in findings), 1, findings)

    def assert_supported_object_flow(self, source, *, tainted, suffix):
        path, source = self.fixture(source, suffix)
        expected = [number for number, line in enumerate(source.splitlines(), 1)
                    if '// expect-path' in line] if tainted else []
        for recover in (False, True):
            with self.subTest(recover=recover):
                findings = self.analyze(path, source, recover=recover)
                self.assert_sinks(findings, path, expected)
                self.assertFalse(any(item['rule'] == LIMIT_RULE for item in findings), findings)

    def test_receiver_method_mutations_reach_direct_and_method_field_reads(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    final class Box {
                        var path = "/srv/initial"
                        func set(_ value: String) { self.path = value }
                        func read() {
                            _ = String(contentsOfFile: self.path) // expect-path
                        }
                    }
                    func handle(req: Request) {
                        let box = Box()
                        box.set(%s)
                        _ = String(contentsOfFile: box.path) // expect-path
                        box.read()
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_implicit_self_calls_and_initializer_helpers_preserve_mutations(self):
        cases = (('implicit-self', '''
            final class Box {
                var path = "/srv/initial"
                func set(_ value: String) { path = value }
                func handle(req: Request) {
                    set(%s)
                    _ = String(contentsOfFile: path) // expect-path
                }
            }
        '''), ('initializer-helper', '''
            final class Box {
                var path = "/srv/initial"
                init(_ value: String) { self.set(value) }
                func set(_ value: String) { path = value }
            }
            func handle(req: Request) {
                let box = Box(%s)
                _ = String(contentsOfFile: box.path) // expect-path
            }
        '''))
        for name, source in cases:
            for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                with self.subTest(case=name, tainted=tainted):
                    self.assert_supported_object_flow(source % value, tainted=tainted,
                                                      suffix='-' + name + '-' + str(tainted))

    def test_reference_helper_and_returned_alias_mutations_reach_original(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    final class Box { var path = "/srv/initial" }
                    func identity(_ box: Box) -> Box { box }
                    func change(_ box: Box, _ value: String) {
                        let alias = box
                        alias.path = value
                    }
                    func handle(req: Request) {
                        let box = Box()
                        let alias = identity(box)
                        change(alias, %s)
                        _ = String(contentsOfFile: box.path) // expect-path
                        _ = String(contentsOfFile: alias.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_reference_aliases_value_copies_and_distinct_allocations(self):
        cases = (('reference-alias', 'final class', 'original', True),
                 ('value-copy', 'struct', 'original', False),
                 ('distinct-allocation', 'final class', 'Box()', False))
        for name, declaration, copied, shared in cases:
            for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                with self.subTest(case=name, tainted=tainted):
                    self.assert_supported_object_flow('''
                        %s Box { var path = "/srv/initial"; init() {} }
                        func handle(req: Request) {
                            var original = Box()
                            var alias = %s
                            alias.path = %s
                            _ = String(contentsOfFile: original.path) %s
                            _ = String(contentsOfFile: alias.path) // expect-path
                        }
                    ''' % (declaration, copied, value, '// expect-path' if shared else ''),
                        tainted=tainted, suffix='-' + name + '-' + str(tainted))

    def test_conditional_reference_alias_updates_each_possible_referent(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    final class Box { var path = "/srv/initial" }
                    func handle(req: Request, enabled: Bool) {
                        let first = Box()
                        let second = Box()
                        let alias = enabled ? first : second
                        alias.path = %s
                        _ = String(contentsOfFile: first.path) // expect-path
                        _ = String(contentsOfFile: second.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_same_and_distinct_reference_arguments_keep_alias_identity(self):
        for shared in (False, True):
            for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                with self.subTest(shared=shared, tainted=tainted):
                    self.assert_supported_object_flow('''
                        final class Box { var path = "/srv/initial"; init() {} }
                        func changeAndRead(_ first: Box, _ second: Box, _ value: String) {
                            first.path = value
                            _ = String(contentsOfFile: second.path) %s
                        }
                        func handle(req: Request) {
                            let first = Box()
                            let second = Box()
                            changeAndRead(first, %s, %s)
                        }
                    ''' % ('// expect-path' if shared else '', 'first' if shared else 'second', value),
                        tainted=tainted, suffix='-' + str(shared) + '-' + str(tainted))

    def test_unknown_incoming_class_parameters_may_alias(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    final class Box { var path = "/srv/initial" }
                    func handle(req: Request, first: Box, second: Box) {
                        first.path = %s
                        _ = String(contentsOfFile: second.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_indirect_getter_sinks_and_implicit_getter_chains(self):
        cases = (('indirect-sink', '''
            final class Box {
                var path = "/srv/initial"
                var read: String {
                    String(contentsOfFile: path) // expect-path
                }
            }
            func handle(req: Request) {
                let box = Box()
                box.path = %s
                consume(box.read)
            }
        '''), ('getter-chain', '''
            struct Box {
                let req: Request
                var raw: String { %s }
                var path: String { raw }
            }
            func handle(req: Request) {
                let box = Box(req: req)
                _ = String(contentsOfFile: box.path) // expect-path
            }
        '''))
        for name, source in cases:
            for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                with self.subTest(case=name, tainted=tainted):
                    self.assert_supported_object_flow(source % value, tainted=tainted,
                                                      suffix='-' + name + '-' + str(tainted))

    def test_getter_mutation_reaches_later_field_read(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    final class Box {
                        let req: Request
                        var path = "/srv/initial"
                        init(_ request: Request) { req = request }
                        var change: String {
                            path = %s
                            return "done"
                        }
                    }
                    func handle(req: Request) {
                        let box = Box(req)
                        consume(box.change)
                        _ = String(contentsOfFile: box.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_mixed_concrete_getters_preserve_all_possible_returns(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    class Provider {
                        var path: String { return "/srv/base" }
                    }
                    final class Safe: Provider {
                        override var path: String { return "/srv/fixed" }
                    }
                    final class Candidate: Provider {
                        let req: Request
                        init(_ request: Request) { req = request }
                        override var path: String { return %s }
                    }
                    func handle(req: Request, enabled: Bool) {
                        let provider: Provider = enabled ? Safe() : Candidate(req)
                        _ = String(contentsOfFile: provider.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_recursive_receiver_summary_converges_and_preserves_mutation(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    final class Box {
                        var path = "/srv/initial"
                        func assign(_ value: String, again: Bool) {
                            if again {
                                self.assign(value, again: false)
                            } else {
                                self.path = value
                            }
                        }
                    }
                    func handle(req: Request) {
                        let box = Box()
                        box.assign(%s, again: true)
                        _ = String(contentsOfFile: box.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_reference_casts_and_opaque_return_aliases_preserve_identity(self):
        for alias in ('box as AnyObject', 'externalIdentity(box)'):
            for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                with self.subTest(alias=alias, tainted=tainted):
                    self.assert_supported_object_flow('''
                        final class Box { var path = "/srv/initial" }
                        func handle(req: Request) {
                            let box = Box()
                            let erased = %s
                            let selected = erased as! Box
                            selected.path = %s
                            _ = String(contentsOfFile: box.path) // expect-path
                        }
                    ''' % (alias, value), tainted=tainted, suffix='-' + str(len(alias)) + str(tainted))

    def test_opaque_reference_call_and_polymorphic_aliases_report_local_limits(self):
        cases = (('opaque-call', '''
            final class Box { var path = "/srv/initial" }
            func handle(req: Request) {
                let box = Box()
                externalMutation(box, req.query["path"]!)
                _ = String(contentsOfFile: box.path)
                _ = String(contentsOfFile: req.query["after"]!)
            }
        ''', 'unresolved reference call', 6), ('polymorphic-alias', '''
            class Base { var path = "/srv/initial" }
            final class Derived: Base {}
            func handle(req: Request, first: Base, second: Derived) {
                first.path = req.query["path"]!
                _ = String(contentsOfFile: second.path)
                _ = String(contentsOfFile: req.query["after"]!)
            }
        ''', 'incoming polymorphic references', 6), ('dynamic-getter', '''
            class Provider { var path: String { "/srv/fixed" } }
            func handle(req: Request, provider: Provider) {
                _ = String(contentsOfFile: provider.path)
                _ = String(contentsOfFile: req.query["after"]!)
            }
        ''', 'incoming polymorphic references', 4))
        for name, source, reason, sink_line in cases:
            with self.subTest(case=name):
                path, source = self.fixture(source, '-' + name)
                with self.assertRaisesRegex(SwiftUnsupported, reason):
                    self.analyze(path, source, recover=False)
                findings = self.analyze(path, source, recover=True)
                self.assertTrue(any(item['rule'] == LIMIT_RULE and reason in item['extras']['reason']
                                    for item in findings), findings)
                self.assertTrue(any(item['rule'] == PATH_RULE and item['line'] == sink_line
                                    for item in findings), findings)

    def test_explicit_async_getter_and_protocol_requirement_are_executable(self):
        for tainted, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            with self.subTest(tainted=tainted):
                self.assert_supported_object_flow('''
                    protocol Provider { var path: String { get async throws } }
                    struct Reader: Provider {
                        let req: Request
                        var path: String { get async throws { %s } }
                    }
                    func handle(req: Request) async throws {
                        let reader = Reader(req: req)
                        _ = String(contentsOfFile: try await reader.path) // expect-path
                    }
                ''' % value, tainted=tainted, suffix='-' + str(tainted))

    def test_opaque_accessors_are_local_to_their_executed_use(self):
        declaration = '''
            final class Box {
                var path: String {
                    get { "/srv/fixed" }
                    set { consume(newValue) }
                }
            }
        '''
        for use in ('', 'consume(box.path)', 'box.path = req.query["path"]!'):
            with self.subTest(use=use):
                path, source = self.fixture(declaration + '''
                    func handle(req: Request) {
                        let box = Box()
                        %s
                        _ = String(contentsOfFile: req.query["after"]!) // expect-path
                    }
                ''' % use, '-' + str(len(use)))
                expected = [number for number, line in enumerate(source.splitlines(), 1)
                            if '// expect-path' in line]
                if use:
                    with self.assertRaisesRegex(SwiftUnsupported, 'property accessor'):
                        self.analyze(path, source, recover=False)
                else:
                    self.assert_sinks(self.analyze(path, source, recover=False), path, expected)
                findings = self.analyze(path, source, recover=True)
                self.assert_sinks(findings, path, expected)
                warnings = [item for item in findings if item['rule'] == LIMIT_RULE]
                self.assertEqual(bool(warnings), bool(use), findings)
                if warnings:
                    self.assertTrue(any('property accessor' in item['extras']['reason'] for item in warnings))

    def test_malformed_syntax_is_fatal_even_when_recovery_is_enabled(self):
        sources = (
            'func handle(req: Request) {\n    _ = String(contentsOfFile: req.query["path"])\n',
            r'let value = #"\#(name)"',
        )
        for index, source in enumerate(sources):
            path, source = self.fixture(source, '-' + str(index))
            for recover in (False, True):
                with self.subTest(source=index, recover=recover):
                    with self.assertRaises(ValueError) as refused:
                        self.analyze(path, source, recover=recover)
                    self.assertNotIsInstance(refused.exception, SwiftUnsupported)

    def test_graph_budget_exhaustion_remains_fatal_in_recovery_mode(self):
        path, source = self.fixture('''
            func handle(req: Request) {
                _ = String(contentsOfFile: req.query["path"])
            }
        ''')
        for recover in (False, True):
            with self.subTest(recover=recover):
                engine = SwiftEngine(path, source, 'path', recover=recover)
                # Enter analysis, then exhaust the real work budget while the
                # graph is being built. Local recovery must not catch this.
                engine.budget.remaining = 1
                with self.assertRaises(AnalysisLimit):
                    engine.analyze()
                self.assertEqual(engine.diagnostics, {})


if __name__ == '__main__':
    unittest.main()
