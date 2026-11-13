"""Callable identity and bounded Swift callback work (GH #204, wz5i).

Ordinary member dispatch must not execute a callback stored in another field.
The scale control repeats real Swift method calls and checks both the modeled
work and the unsafe/clean outcomes; it does not increase analyzer limits.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))

from ubs_core.analyzers.taint_swift_traversal import (
    SwiftEngine, SwiftParser, SwiftUnsupported, flow_findings,
)
from ubs_core.taint_flow import AnalysisLimit, Budget

PATH_RULE = 'swift.taint.request_path_traversal'


class CountingSwiftEngine(SwiftEngine):
    """Count actual callback evaluations without replacing their execution."""
    def __init__(self, *args, **kwargs):
        self.closure_evaluations = 0
        self.transformed_traces = 0
        super().__init__(*args, **kwargs)

    def inline_closure(self, *args, **kwargs):
        self.closure_evaluations += 1
        return super().inline_closure(*args, **kwargs)

    def forget(self, value, keep=frozenset()):
        self.transformed_traces += len(value)
        return super().forget(value, keep)


class SwiftClosureWorkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-closure-work-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def fixture(self, source, suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        path = self.artifacts / (self._testMethodName + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        return path, source

    def check(self, source, *, unsafe=False, suffix=''):
        path, source = self.fixture(source, suffix)
        expected = {line for line, text in enumerate(source.splitlines(), 1)
                    if '// expect-path' in text} if unsafe else set()
        for recover in (False, True):
            with self.subTest(recover=recover):
                findings = flow_findings(path, source, 'path', recover=recover)
                self.assertEqual({item['line'] for item in findings if item['rule'] == PATH_RULE},
                                 expected, findings)
                self.assertTrue(all(item['rule'] == PATH_RULE for item in findings), findings)
                for finding in findings:
                    self.assertEqual(finding['severity'], 'critical')
                    self.assertEqual(finding['extras']['taint_path'][-1]['kind'], 'sink')
                    self.assertEqual(finding['extras']['taint_path'][-1]['line'], finding['line'])
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')

    def test_ordinary_method_does_not_invoke_unrelated_stored_callback(self):
        self.check('''
            struct Box {
                let work: (String) -> String
                func answer(_ value: String) -> String { "/srv/fixed" }
            }
            func handle(req: Request) {
                let box = Box(work: { value in value })
                _ = String(contentsOfFile: box.answer(req.query["path"]!))
            }
        ''')
        self.check('''
            struct Box {
                let work: () -> String
                func answer(_ value: String) -> String { "/srv/fixed" }
            }
            func handle(req: Request) {
                let box = Box(work: { req.query["path"]! })
                _ = String(contentsOfFile: box.answer("ignored"))
            }
        ''', suffix='-captured')

    def test_selected_callable_field_preserves_each_callable_kind(self):
        for kind, declarations, callback, invocation in (
            ('closure', '', '{ path in String(contentsOfFile: path) /* expect-path */ }', 'box.work'),
            ('named', 'func read(_ path: String) { _ = String(contentsOfFile: path) /* expect-path */ }',
             'read', 'box.work'),
            ('native', '', 'serveFile', 'box.work'),
        ):
            for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                source = f'''
                    {declarations}
                    struct Box {{ let work: (String) -> Void }}
                    func handle(req: Request) {{
                        let box = Box(work: {callback})
                        {invocation}({value}) {'// expect-path' if kind == 'native' else ''}
                    }}
                '''.replace('/* expect-path */', '// expect-path\n')
                with self.subTest(kind=kind, unsafe=unsafe):
                    self.check(source, unsafe=unsafe, suffix=f'-{kind}-{unsafe}')

    def test_callable_field_projection_does_not_call_a_sibling(self):
        self.check('''
            struct Box {
                let unsafe: () -> String
                let fixed: () -> String
            }
            func handle(req: Request) {
                let box = Box(unsafe: { req.query["path"]! }, fixed: { "/srv/fixed" })
                _ = String(contentsOfFile: box.fixed())
                _ = String(contentsOfFile: box.unsafe()) // expect-path
            }
        ''', unsafe=True)

    def test_callable_getter_and_alias_keep_stored_parameter_binding(self):
        for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            self.check('''
                final class Box {
                    let work: (String) -> String
                    init(work: @escaping (String) -> String) { self.work = work }
                    var selected: (String) -> String { work }
                }
                func handle(req: Request) {
                    let box = Box(work: { value in value })
                    let alias = box
                    _ = String(contentsOfFile: alias.selected(%s)) // expect-path
                }
            ''' % value, unsafe=unsafe, suffix=str(unsafe))

    def test_forwarded_returned_closures_keep_live_captures_and_snapshots(self):
        for snapshot in (False, True):
            self.check('''
                func forward(_ callback: () -> String) -> () -> String { callback }
                func handle(req: Request) {
                    var path = "/srv/fixed"
                    let callback = forward({ %s path })
                    let factory = { callback }
                    path = req.query["path"]!
                    let read = factory()
                    _ = String(contentsOfFile: read()) // expect-path
                }
            ''' % ('[path] in' if snapshot else ''), unsafe=not snapshot, suffix=str(snapshot))

    def test_nested_callback_writes_preserve_reference_aliases(self):
        for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            self.check('''
                final class Box { var path = "/srv/initial" }
                func invoke(_ callback: () -> Void) { callback() }
                func handle(req: Request) {
                    let box = Box()
                    let alias = box
                    let read = { String(contentsOfFile: box.path) } // expect-path
                    let update = { invoke({ alias.path = %s }) }
                    update()
                    _ = read()
                }
            ''' % value, unsafe=unsafe, suffix=str(unsafe))

    def test_callback_writes_create_absent_lexical_slots_without_crossing_frames(self):
        for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]')):
            for indirect in (False, True):
                self.check('''
                    func invoke(_ callback: () -> Void, _ path: String) {
                        callback()
                        _ = String(contentsOfFile: path)
                    }
                    func handle(req: Request) {
                        var path: String?
                        let change = { path = %s }
                        %s
                        _ = String(contentsOfFile: path!) // expect-path
                    }
                ''' % (value, 'invoke(change, "/srv/unrelated")' if indirect else 'change()'),
                    unsafe=unsafe, suffix=f'-{unsafe}-{indirect}')

    def test_selected_call_as_function_invokes_the_selected_body(self):
        for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            for invocation in ('reader(%s)', 'box.work(%s)', 'make()(%s)'):
                self.check('''
                    struct Reader {
                        func callAsFunction(_ path: String) {
                            _ = String(contentsOfFile: path) // expect-path
                        }
                    }
                    struct Box { let work: Reader }
                    func make() -> Reader { Reader() }
                    func handle(req: Request) {
                        let reader = Reader()
                        let box = Box(work: reader)
                        %s
                    }
                ''' % (invocation % value), unsafe=unsafe,
                    suffix=f'-{unsafe}-{invocation.split("(", 1)[0]}')

    def test_unknown_callable_fields_and_factory_results_remain_incomplete(self):
        for name, parameters, statements in (
            ('incoming', ', box: Box', 'box.work(req.query["path"]!)'),
            ('factory', '', 'let box = Box(work: externalFactory()); box.work(req.query["path"]!)'),
            ('alias', '', 'let work = externalFactory(); work(req.query["path"]!)'),
            ('immediate', '', 'externalFactory()(req.query["path"]!)'),
            ('writer-factory', '', 'let body = externalFactory(); let writer = body.write; writer(to: req.query["path"]!)'),
        ):
            path, source = self.fixture('''
                struct Box { let work: (String) -> Void }
                func handle(req: Request%s) {
                    %s
                    _ = String(contentsOfFile: req.query["known"]!) // expect-path
                }
            ''' % (parameters, statements), '-' + name)
            with self.subTest(name=name, recover=False):
                with self.assertRaisesRegex(SwiftUnsupported, 'callable'):
                    flow_findings(path, source)
            with self.subTest(name=name, recover=True):
                findings = flow_findings(path, source, recover=True)
                expected = {line for line, text in enumerate(source.splitlines(), 1)
                            if '// expect-path' in text}
                self.assertEqual({item['line'] for item in findings if item['rule'] == PATH_RULE},
                                 expected, findings)
                self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                                    and 'callable' in item['message'] for item in findings), findings)

    def test_an_opaque_alternative_does_not_erase_known_callable_findings(self):
        for kind, declarations, callback, call_marker in (
            ('closure', '', '{ path in String(contentsOfFile: path) /* expect-path */ }', ''),
            ('named', 'func read(_ path: String) { _ = String(contentsOfFile: path) /* expect-path */ }',
             'read', ''),
            ('native', '', 'serveFile', '// expect-path'),
        ):
            source = '''
                %s
                struct Box { let work: (String) -> Void }
                func handle(req: Request) {
                    var work = %s
                    if req.query["mode"] == "external" { work = externalFactory() }
                    let box = Box(work: work)
                    box.work(req.query["path"]!) %s
                }
            ''' % (declarations, callback, call_marker)
            path, source = self.fixture(source.replace('/* expect-path */', '// expect-path\n'), '-' + kind)
            with self.subTest(kind=kind, recover=False):
                with self.assertRaisesRegex(SwiftUnsupported, 'opaque callable'):
                    flow_findings(path, source)
            with self.subTest(kind=kind, recover=True):
                findings = flow_findings(path, source, recover=True)
                expected = {line for line, text in enumerate(source.splitlines(), 1)
                            if '// expect-path' in text}
                self.assertEqual({item['line'] for item in findings if item['rule'] == PATH_RULE},
                                 expected, findings)
                self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                                    and 'opaque callable' in item['message'] for item in findings), findings)

    def test_named_callable_alternatives_join_independent_inout_mutations(self):
        functions = (
            'func assign(_ path: inout String, _ value: String) { path = value }',
            'func clear(_ path: inout String, _ value: String) { path = "/srv/fixed" }',
        )
        for reverse in (False, True):
            for unsafe, value in ((False, '"/srv/final"'), (True, 'req.query["path"]!')):
                self.check('''
                    %s
                    func handle(req: Request) {
                        var path = "/srv/initial"
                        let work = req.query["mode"] == "assign" ? assign : clear
                        work(&path, %s)
                        _ = String(contentsOfFile: path) // expect-path
                    }
                ''' % ('\n'.join(reversed(functions) if reverse else functions), value),
                    unsafe=unsafe, suffix=f'-{reverse}-{unsafe}')

    def test_opaque_callable_returns_preserve_request_provenance(self):
        for unknown in ('externalFactory()', 'externalIdentity', 'Imported.externalIdentity'):
            for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
                path, source = self.fixture('''
                    func fixed(_ value: String) -> String { "/srv/fixed" }
                    func handle(req: Request) {
                        let work = req.query["mode"] == "safe" ? fixed : %s
                        let path = work(%s)
                        _ = String(contentsOfFile: path) // expect-path
                    }
                ''' % (unknown, value), '-' + unknown.replace('()', '') + '-' + str(unsafe))
                with self.subTest(unknown=unknown, unsafe=unsafe, recover=False):
                    with self.assertRaisesRegex(SwiftUnsupported, 'opaque callable'):
                        flow_findings(path, source)
                with self.subTest(unknown=unknown, unsafe=unsafe, recover=True):
                    findings = flow_findings(path, source, recover=True)
                    expected = {line for line, text in enumerate(source.splitlines(), 1)
                                if '// expect-path' in text} if unsafe else set()
                    self.assertEqual({item['line'] for item in findings if item['rule'] == PATH_RULE},
                                     expected, findings)
                    self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                                        and 'opaque callable' in item['message'] for item in findings), findings)

    def test_unknown_callback_parameter_is_not_an_already_reported_limitation(self):
        path, source = self.fixture('''
            func handle(req: Request) {
                perform { callback in callback(req.query["path"]!) }
                _ = String(contentsOfFile: req.query["after"]!) // expect-path
            }
        ''')
        with self.assertRaisesRegex(SwiftUnsupported, 'unresolved callable'):
            flow_findings(path, source)
        findings = flow_findings(path, source, recover=True)
        self.assertEqual({item['line'] for item in findings if item['rule'] == PATH_RULE}, {3}, findings)
        self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                            and 'unresolved callable' in item['message'] for item in findings), findings)

    def test_mixed_native_http_method_retains_its_known_sink_and_opaque_effects(self):
        for unsafe, value in ((False, '"https://api.example.com"'), (True, 'req.query["url"]!')):
            path, source = self.fixture('''
                func handle(req: Request) async throws {
                    let send = req.query["mode"] == "native" ? URLSession.shared.data : externalFactory()
                    _ = try await send(from: URL(string: %s)!) // expect-outbound
                }
            ''' % value, '-' + str(unsafe))
            with self.assertRaisesRegex(SwiftUnsupported, 'opaque callable'):
                flow_findings(path, source, 'outbound')
            findings = flow_findings(path, source, 'outbound', recover=True)
            self.assertEqual({item['line'] for item in findings if item['rule'] == 'swift.taint.outbound-url'},
                             {3} if unsafe else set(), findings)
            self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited'
                                and 'opaque callable' in item['message'] for item in findings), findings)

    def test_native_writer_alias_checks_the_labeled_destination(self):
        for unsafe, value in ((False, '"/srv/fixed"'), (True, 'req.query["path"]!')):
            self.check('''
                func handle(req: Request) {
                    let path = %s
                    Task {
                        let writer = body.write
                        writer(to: path) // expect-path
                    }
                }
            ''' % value, unsafe=unsafe, suffix='-' + str(unsafe))

    @staticmethod
    def modifier_source(count, unsafe):
        value = 'req.query["path"]!' if unsafe else '"/srv/fixed"'
        statements = '\n'.join('    _ = row.padding()' for _ in range(count))
        return ('''struct Row {
    let action: () -> String
    func padding() -> String { "fixed" }
}
func body(req: Request) {
    let row = Row(action: { %s })
%s
    _ = String(contentsOfFile: row.action()) // expect-path
}
''' % (value, statements))

    def test_ordinary_member_calls_do_not_multiply_callback_evaluation(self):
        receipts = []
        for unsafe in (False, True):
            runs = []
            for count in (40, 160):
                path, source = self.fixture(self.modifier_source(count, unsafe), f'-{count}-{unsafe}')
                started = time.monotonic()
                engine = CountingSwiftEngine(path, source, parser=SwiftParser(source))
                result = engine.analyze()
                elapsed = time.monotonic() - started
                expected = {source.index('String(contentsOfFile:')} if unsafe else set()
                self.assertEqual(set(result), expected, result)
                self.assertFalse(engine.diagnostics, engine.diagnostics)
                self.assertLessEqual(engine.closure_evaluations, 12,
                                     'Unrelated padding() methods must not execute action callbacks')
                used = 500_000 - engine.budget.remaining
                self.assertLess(used, 5_000)
                receipt = dict(statements=count, unsafe=unsafe, callback_evaluations=engine.closure_evaluations,
                               work=used, elapsed=elapsed, effects=sorted(result))
                runs.append(receipt)
                receipts.append(receipt)
            self.assertEqual(runs[0]['callback_evaluations'], runs[1]['callback_evaluations'])
            self.assertLessEqual(runs[1]['work'], runs[0]['work'] * 4 + 128)
        (self.artifacts / 'work.json').write_text(json.dumps(receipts, indent=2), encoding='utf-8')

    def test_exhausted_work_and_recursive_callbacks_remain_incomplete(self):
        path, source = self.fixture(self.modifier_source(40, True))
        for recover in (False, True):
            engine = SwiftEngine(path, source, parser=SwiftParser(source, recover=recover), recover=recover)
            engine.budget = Budget(5)
            with self.assertRaises(AnalysisLimit):
                engine.analyze()
        path, source = self.fixture('''
            func handle(req: Request) {
                var recurse: (() -> Void)?
                recurse = {
                    recurse?()
                    _ = String(contentsOfFile: req.query["path"]!)
                }
                recurse?()
            }
        ''', '-recursive')
        with self.assertRaisesRegex(SwiftUnsupported, 'recursive stored callback'):
            flow_findings(path, source, 'path')
        findings = flow_findings(path, source, 'path', recover=True)
        self.assertEqual({item['line'] for item in findings if item['rule'] == PATH_RULE}, {5})
        self.assertTrue(any(item['rule'] == 'swift.taint.analysis-limited' for item in findings), findings)

    def test_branching_url_metadata_keeps_flow_work_linear(self):
        """Discarded URL identities must not create exponentially many values.

        Every optional conversion can leave the original request unchanged, so
        all four sinks remain unsafe. The fixed-value twin has no request flow.
        These source programs originally created 2**N sink facts for one source
        even though the alternative URL identities were no longer observable.
        """
        receipts = []
        policies = (
            ('path', 'String(contentsOfFile: value)', 'swift.taint.request_path_traversal'),
            ('redirect', 'req.redirect(to: value)', 'swift.taint.request_open_redirect'),
            ('header', 'HTTPHeaders([("X-Trace", value)])', 'swift.taint.header-injection'),
            ('outbound', 'URLSession.shared.data(from: URL(string: value)!)', 'swift.taint.outbound-url'),
        )
        for policy, sink, rule in policies:
            for unsafe in (False, True):
                runs = []
                for count in (4, 8, 12):
                    initial = 'req.query["value"]!' if unsafe else '"https://api.example.com/fixed"'
                    body = '\n'.join('''
                        if enabled {
                            let parsed%d = URL(string: value)!
                            value = parsed%d.host! + ""
                        }
                    ''' % (index, index) for index in range(count))
                    path, source = self.fixture('''
                        func handle(req: Request, enabled: Bool) {
                            var value = %s
                            %s
                            _ = %s // selected-sink
                        }
                    ''' % (initial, body, sink), f'-{policy}-{count}-{unsafe}')
                    engine = CountingSwiftEngine(path, source, policy, parser=SwiftParser(source))
                    effects = engine.analyze()
                    expected = {source.index(sink)} if unsafe else set()
                    self.assertEqual(set(effects), expected)
                    self.assertFalse(engine.diagnostics)
                    findings = flow_findings(path, source, policy)
                    self.assertEqual([(item['rule'], item['line']) for item in findings],
                        [(rule, source[:source.index(sink)].count('\n') + 1)] if unsafe else [])
                    if unsafe:
                        self.assertEqual(findings[0]['extras']['source_count'], 1)
                        trace = findings[0]['extras']['taint_path']
                        self.assertEqual(trace[0]['kind'], 'source')
                        self.assertEqual(trace[-1]['kind'], 'sink')
                    row = dict(policy=policy, branches=count, unsafe=unsafe,
                               processed_traces=engine.transformed_traces,
                               work=500_000 - engine.budget.remaining,
                               effects=sorted(effects), findings=findings)
                    runs.append(row)
                    receipts.append(row)
                # Increasing source size may add work, but not a powerset of
                # historical transformations with the same current value.
                self.assertLessEqual(runs[1]['processed_traces'],
                                     runs[0]['processed_traces'] * 2 + 64)
                self.assertLessEqual(runs[2]['processed_traces'],
                                     runs[1]['processed_traces'] * 2 + 64)
        (self.artifacts / 'url-metadata-work.json').write_text(json.dumps(receipts, indent=2), encoding='utf-8')

    def test_current_validation_and_separate_request_origins_survive_history_collapse(self):
        cases = (
            ('path', 'URL(fileURLWithPath: raw).lastPathComponent', 'raw', '',
             'serveFile(%s)', 'swift.taint.request_path_traversal'),
            ('redirect', 'raw', 'raw', '''
                guard checked.hasPrefix("/"), !checked.hasPrefix("//"), !checked.contains("\\\\"),
                      !checked.contains("\\n"), !checked.contains("\\r"), !checked.contains("\\t") else { return }
                ''', 'req.redirect(to: %s)', 'swift.taint.request_open_redirect'),
            ('header', 'raw.replacingOccurrences(of: "\\r", with: "").replacingOccurrences(of: "\\n", with: "")',
             'raw', '', 'HTTPHeaders([("X-Trace", %s)])', 'swift.taint.header-injection'),
            ('outbound', 'URL(string: raw)!', 'URL(string: raw)!', '''
                guard checked.scheme == "https", checked.host == "api.example.com" else { return }
                ''', 'URLSession.shared.data(from: %s)', 'swift.taint.outbound-url'),
        )
        receipts = []
        for policy, checked, unchecked, proof, sink, rule in cases:
            path, source = self.fixture('''
                func handle(req: Request) {
                    let raw = req.query["first"]! + req.query["second"]!
                    var checked = %s
                    let unchecked = %s
                    %s
                    _ = %s // validated
                    _ = %s // expect-unsafe
                    checked = unchecked
                    _ = %s // expect-unsafe
                }
            ''' % (checked, unchecked, proof, sink % 'checked', sink % 'unchecked', sink % 'checked'),
                '-' + policy)
            expected = [number for number, line in enumerate(source.splitlines(), 1)
                        if '// expect-unsafe' in line]
            for recover in (False, True):
                with self.subTest(policy=policy, recover=recover):
                    findings = flow_findings(path, source, policy, recover=recover)
                    self.assertEqual([(item['rule'], item['line']) for item in findings],
                                     [(rule, line) for line in expected], findings)
                    for finding in findings:
                        self.assertEqual(finding['extras']['source_count'], 2)
                        self.assertEqual(finding['severity'], 'critical')
                    receipts.append(dict(policy=policy, recover=recover, findings=findings))
        (self.artifacts / 'current-validation-and-origins.json').write_text(
            json.dumps(receipts, indent=2), encoding='utf-8')

    def test_opaque_callback_work_keeps_every_diagnostic_and_request_source(self):
        receipts = []
        for unsafe in (False, True):
            runs = []
            for count in (10, 40, 80):
                value = 'req.query["first"]! + req.query["second"]!' if unsafe else '"/srv/fixed"'
                statements = '\n'.join('external.store(path)' for _ in range(count))
                path, source = self.fixture('''
                    func handle(req: Request) {
                        var path = %s
                        Task {
                    %s
                        }
                        _ = String(contentsOfFile: path) // expect-path
                    }
                ''' % (value, statements), f'-{count}-{unsafe}')
                engine = CountingSwiftEngine(path, source,
                    parser=SwiftParser(source, recover=True), recover=True)
                started = time.monotonic()
                effects = engine.analyze()
                elapsed = time.monotonic() - started
                sink = source.index('String(contentsOfFile:')
                self.assertEqual(set(effects), {sink} if unsafe else set())
                expected_limits = {number for number, line in enumerate(source.splitlines(), 1)
                    if 'external.store(' in line or '// expect-path' in line} if unsafe else set()
                self.assertEqual({item['line'] for item in engine.diagnostics.values()}, expected_limits)
                if unsafe:
                    sources = {trace.key[1] for trace in effects[sink]}
                    self.assertEqual(sources, {source.index('req.query["first"]'),
                                               source.index('req.query["second"]')})
                    with self.assertRaisesRegex(SwiftUnsupported, 'heap/capture'):
                        flow_findings(path, source)
                else:
                    self.assertEqual(flow_findings(path, source), [])
                receipt = dict(statements=count, unsafe=unsafe, elapsed=elapsed,
                    transformed_traces=engine.transformed_traces,
                    diagnostics=len(engine.diagnostics), effects=sorted(effects))
                runs.append(receipt)
                receipts.append(receipt)
            # Repeated opaque calls add diagnostics, not new origins of the
            # same unknowable value. Real independent request origins above
            # must remain distinct. Count actual processed facts rather than
            # relying on machine-dependent wall-clock thresholds.
            self.assertLessEqual(runs[1]['transformed_traces'],
                                 runs[0]['transformed_traces'] * 4 + 128)
            self.assertLessEqual(runs[2]['transformed_traces'],
                                 runs[1]['transformed_traces'] * 2 + 128)
        (self.artifacts / 'opaque-work.json').write_text(json.dumps(receipts, indent=2), encoding='utf-8')

    def test_unknown_values_do_not_share_validation_or_hide_independent_sinks(self):
        cases = (
            ('path', 'URL(fileURLWithPath: %s).lastPathComponent', '',
             'serveFile(%s)', 'swift.taint.request_path_traversal'),
            ('redirect', '%s', '''
                guard left.hasPrefix("/"), !left.hasPrefix("//"), !left.contains("\\\\"),
                      !left.contains("\\n"), !left.contains("\\r"), !left.contains("\\t") else { return }
                ''', 'req.redirect(to: %s)', 'swift.taint.request_open_redirect'),
            ('header', '%s', '''
                let left = left.replacingOccurrences(of: "\\r", with: "")
                               .replacingOccurrences(of: "\\n", with: "")
                ''', 'HTTPHeaders([("X-Trace", %s)])', 'swift.taint.header-injection'),
            ('outbound', 'URL(string: %s)!', '''
                guard left.scheme == "https", left.host == "api.example.com" else { return }
                ''', 'URLSession.shared.data(from: %s)', 'swift.taint.outbound-url'),
        )
        for policy, value, proof, sink, rule in cases:
            left = value % 'first.value'
            right = 'second.value' if policy == 'path' else value % 'second.value'
            known = 'URL(string: req.query["known"]!)!' if policy == 'outbound' else 'req.query["known"]!'
            path, source = self.fixture('''
                final class Box { @Wrapped var value = "/srv/fixed" }
                func handle(req: Request) {
                    let first = Box()
                    let second = Box()
                    let left = %s
                    let right = %s
                    %s
                    _ = %s // safe-value
                    _ = %s // unknown-value
                    _ = %s // known-source
                }
            ''' % (left, right, proof, sink % 'left', sink % 'right', sink % known), '-' + policy)
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(SwiftUnsupported, 'wrapped stored property'):
                    flow_findings(path, source, policy)
                findings = flow_findings(path, source, policy, recover=True)
                lines = {marker: next(number for number, line in enumerate(source.splitlines(), 1)
                                      if marker in line)
                         for marker in ('safe-value', 'unknown-value', 'known-source')}
                self.assertEqual([(item['rule'], item['line']) for item in findings
                                  if item['rule'] != 'swift.taint.analysis-limited'],
                                 [(rule, lines['known-source'])], findings)
                sink_limits = [item['line'] for item in findings
                    if item['rule'] == 'swift.taint.analysis-limited'
                    and 'reaches a sink' in item['extras']['reason']]
                self.assertEqual(sink_limits, [lines['unknown-value']], findings)
                self.assertFalse(any(item['line'] == lines['safe-value'] for item in findings), findings)
            # An opaque effect after validation must invalidate the proof,
            # even when its unknown origin was already present in the value.
            first_sink = '_ = ' + sink % 'left'
            mutated = source.replace(first_sink,
                'Task {}\nexternal.change(req.query["mutation"])\n' + first_sink, 1)
            path, mutated = self.fixture(mutated, '-' + policy + '-mutated')
            with self.subTest(policy=policy, mutation=True):
                findings = flow_findings(path, mutated, policy, recover=True)
                expected = [number for number, line in enumerate(mutated.splitlines(), 1)
                            if 'safe-value' in line or 'unknown-value' in line]
                self.assertEqual([item['line'] for item in findings
                    if item['rule'] == 'swift.taint.analysis-limited'
                    and 'reaches a sink' in item['extras']['reason']], expected, findings)
                expected_source = next(number for number, line in enumerate(mutated.splitlines(), 1)
                                       if 'known-source' in line)
                self.assertEqual([(item['rule'], item['line']) for item in findings
                                  if item['rule'] != 'swift.taint.analysis-limited'],
                                 [(rule, expected_source)], findings)

    def joined_engine(self, source, unsafe, suffix, policy='path'):
        path, source = self.fixture(source, suffix)
        engine = SwiftEngine(path, source, policy, parser=SwiftParser(source))
        result = engine.analyze()
        expected = {source.index('String(contentsOfFile:')} if unsafe else set()
        self.assertEqual(set(result), expected, result)
        self.assertFalse(engine.diagnostics, engine.diagnostics)
        joined = [key for key in engine.contexts if len(key) == 5]
        self.assertTrue(joined, 'The source must exceed the precise-context limit')
        groups = {}
        for key in engine.contexts:
            group = key[0], key[2]
            groups[group] = groups.get(group, 0) + 1
        self.assertLessEqual(max(groups.values()), 17)
        return engine

    def test_joined_inputs_revisit_a_late_unsafe_argument(self):
        calls = '\n'.join(f'    read("/srv/fixed-{index}")' for index in range(40))
        for unsafe, value in ((False, '"/srv/final"'), (True, 'req.query["late"]!')):
            self.joined_engine('''
                func read(_ path: String) { _ = String(contentsOfFile: path) }
                func handle(req: Request) {
                %s
                    read(%s)
                }
            ''' % (calls, value), unsafe, str(unsafe))

    def test_joined_receivers_keep_late_mutation_and_alias_identity(self):
        calls = '\n'.join(f'    alias.set("/srv/fixed-{index}")' for index in range(40))
        for unsafe, value in ((False, '"/srv/final"'), (True, 'req.query["late"]!')):
            self.joined_engine('''
                final class Box {
                    var path = "/srv/initial"
                    func set(_ value: String) { path = value }
                    func read() { _ = String(contentsOfFile: path) }
                }
                func handle(req: Request) {
                    let box = Box()
                    let alias = box
                %s
                    alias.set(%s)
                    box.read()
                }
            ''' % (calls, value), unsafe, str(unsafe))

    def test_joined_fact_alternatives_do_not_reuse_a_validation_proof(self):
        calls = '\n'.join(f'    consume(identity("/srv/fixed-{index}"))' for index in range(40))
        for unsafe in (False, True):
            path, source = self.fixture('''
                func identity(_ value: String) -> String { value }
                func handle(req: Request) {
                    let raw = req.query["next"]!
                    var target = raw
                    guard target.hasPrefix("/"), !target.hasPrefix("//"),
                          !target.contains("\\\\"), !target.contains("\\n"),
                          !target.contains("\\r"), !target.contains("\\t") else { return }
                %s
                    consume(identity(target))
                    _ = req.redirect(to: identity(%s))
                }
            ''' % (calls, 'raw' if unsafe else 'target'), str(unsafe))
            engine = SwiftEngine(path, source, 'redirect', parser=SwiftParser(source))
            result = engine.analyze()
            self.assertEqual(set(result), {source.index('req.redirect')} if unsafe else set(), result)
            self.assertTrue(any(len(key) == 5 for key in engine.contexts))
            self.assertFalse(engine.diagnostics, engine.diagnostics)

    def test_closures_created_before_and_after_context_joining_keep_their_inputs(self):
        calls = '\n'.join(f'    consume(make("/srv/fixed-{index}"))' for index in range(40))
        for unsafe, value in ((False, '"/srv/final"'), (True, 'req.query["late"]!')):
            self.joined_engine('''
                func make(_ path: String) -> () -> String { { [path] in path } }
                func handle(req: Request) {
                    let before = make("/srv/before")
                %s
                    let after = make(%s)
                    consume(before())
                    _ = String(contentsOfFile: after())
                }
            ''' % (calls, value), unsafe, str(unsafe))


if __name__ == '__main__':
    unittest.main()
