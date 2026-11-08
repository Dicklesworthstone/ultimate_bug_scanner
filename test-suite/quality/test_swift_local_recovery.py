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
        with self.assertRaisesRegex(SwiftUnsupported, 'heap/capture') as refused:
            self.analyze(path, source, recover=False)
        self.assertEqual(refused.exception.offset, source.index('update('))
        findings = self.analyze(path, source, recover=True)
        self.assert_sinks(findings, path, (7, 10))
        self.assert_warning(
            findings, path,
            reason='Swift callback with unknown request-derived call effects needs heap/capture analysis',
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
