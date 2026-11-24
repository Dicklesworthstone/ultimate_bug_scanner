"""Selected Swift initialization must trace fields without inventing clean flow.

The sources below state their expected sink sites independently of the
frontend. Retain each source and result so failures are directly reproducible.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
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


def issue229_sources():
    """The reporter's complete seven-case matrix, including source directives."""
    view = textwrap.dedent('''\
        import SwiftUI

        struct Screen: View {
            @State private var busy = false
            var body: some View { Text(busy ? "Loading" : "Idle") }

            func load(_ url: URL) async {
                busy = true
                let request = URLRequest(url: url)
                _ = try? await URLSession.shared.data(for: request)
                busy = false
            }
        }
    ''')
    model = textwrap.dedent('''\
        import Foundation
        import Combine

        final class Model: ObservableObject {
            @Published var busy = false

            func start() {
                busy = true
                let request = 1
                _ = request
                _ = FileManager.default
            }
        }
    ''')
    derived = textwrap.dedent('''\
        import Foundation
        import Combine
        import Vapor

        final class Model: ObservableObject {
            @Published var path = ""

            func handle(req: Request) -> String? {
                path = req.query["path"]!
                return try? String(contentsOfFile: path)
            }
        }
    ''')
    return {
        'view': view,
        'model': model,
        'attribute': model.replace('@Published var busy', '@MainActor var busy')
                          .replace('    func start', '    @MainActor func start'),
        'derived': derived,
        'renamed': model.replace('request', 'payload'),
        'plain': model.replace('@Published var busy', 'var busy'),
        'directive': '\n'.join(
            line + ' // ubs:ignore[taint-source] a counter, not an incoming request'
            if 'request' in line else line for line in model.split('\n')),
    }


class SwiftInitializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-initializers-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def source(self, source, suffix=''):
        source = textwrap.dedent(source).strip() + '\n'
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        return path, source

    def check(self, source, policy='path', suffix=''):
        path, source = self.source(source, suffix)
        findings = flow_findings(path, source, policy)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        expected = [number for number, line in enumerate(source.splitlines(), 1) if '// unsafe' in line]
        rule = {'path': 'swift.taint.request_path_traversal',
                'redirect': 'swift.taint.request_open_redirect',
                'header': 'swift.taint.header-injection',
                'outbound': 'swift.taint.outbound-url'}[policy]
        self.assertEqual([(row['rule'], row['line'], row['severity']) for row in findings],
                         [(rule, line, 'critical') for line in expected], findings)
        return findings

    def unsupported(self, source, reason, suffix=''):
        path, source = self.source(source, suffix)
        with self.assertRaisesRegex(SwiftUnsupported, reason):
            flow_findings(path, source, 'path')
        findings = flow_findings(path, source, 'path', recover=True)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        limited = [row for row in findings if row['rule'] == 'swift.taint.analysis-limited']
        self.assertTrue(limited, findings)
        self.assertTrue(any(reason in row['extras']['reason'] for row in limited), findings)
        return findings

    def wrapper_scan(self, path, mode, fmt, label, *, cache_dir=None):
        """Use verified public entrypoints; retain every actual command/result."""
        evidence = self.artifacts / label
        evidence.mkdir()
        command = ([str(ROOT / 'modules/ubs-swift.sh'), '--format=' + fmt, str(path)]
                   if mode == 'module' else
                   [str(ROOT / 'ubs'), '--module-dir=' + str(ROOT / 'modules'),
                    '--no-auto-update', '--only=swift', '--format=' + fmt,
                    *(['--no-cache'] if cache_dir is None else []), str(path)])
        environment = {
            **os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
            'UBS_NO_CACHE': '1' if cache_dir is None else '0',
            'UBS_CACHE_DIR': str(cache_dir or evidence / 'cache'),
            'PYTHONDONTWRITEBYTECODE': '1', 'NO_COLOR': '1',
        }
        # Ambient escape hatches must not turn these into integrity/partial
        # bypass tests. The same cwd also keeps cache identities comparable.
        for name in ('UBS_ALLOW_UNVERIFIED_HELPERS', 'UBS_VERIFIED_ASSET_DIR',
                     'UBS_ALLOW_PARTIAL', 'UBS_SKIP_TYPE_NARROWING'):
            environment.pop(name, None)
        result = subprocess.run(command, cwd=self.artifacts, env=environment,
                                text=True, capture_output=True, timeout=90, check=False)
        (evidence / 'stdout.log').write_text(result.stdout, encoding='utf-8')
        (evidence / 'stderr.log').write_text(result.stderr, encoding='utf-8')
        (evidence / 'command.json').write_text(json.dumps({
            'command': command, 'cwd': str(self.artifacts), 'exit': result.returncode,
        }, indent=2), encoding='utf-8')
        if fmt == 'text':
            return result, result.stdout
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail('Invalid scanner JSON for %s: %s\nexit=%s\nstderr=%s' %
                      (label, error, result.returncode, result.stderr))
        return result, payload

    def assert_wrapper_report(self, result, payload, mode, *, incomplete, sink_line=None):
        self.assertEqual(result.returncode, 2 if incomplete else int(sink_line is not None),
                         (payload, result.stderr))
        self.assertEqual(payload['status'], 'partial' if incomplete else 'ok', payload)
        scanner = payload if mode == 'module' else payload['scanners'][0]
        self.assertEqual(scanner['status'], payload['status'], payload)
        self.assertEqual(scanner['files'], 1, scanner)
        if incomplete:
            self.assertEqual(scanner['module_error'], 'ANALYZER_ERROR', scanner)
            self.assertIn('analysis is incomplete', scanner['message'], scanner)
        else:
            self.assertNotIn('module_error', scanner)
            if mode == 'runner':
                self.assertEqual(payload['failed_modules'], [], payload)
        rows = payload['findings']
        key = 'rule' if mode == 'module' else 'rule_id'
        sinks = [row for row in rows if row[key] == 'swift.taint.request_path_traversal']
        self.assertEqual([(row['line'], row['severity']) for row in sinks],
                         [(sink_line, 'critical')] if sink_line is not None else [], rows)
        return rows

    def test_issue229_complete_reporter_matrix_in_all_taint_policies(self):
        for case, source in issue229_sources().items():
            path, source = self.source(source, '-' + case)
            for policy in ('path', 'redirect', 'header', 'outbound'):
                with self.subTest(case=case, policy=policy):
                    findings = flow_findings(path, source, policy, recover=True)
                    path.with_suffix('.' + policy + '.json').write_text(
                        json.dumps(findings, indent=2), encoding='utf-8')
                    limits = [row for row in findings if row['rule'] == 'swift.taint.analysis-limited']
                    # Proven native scalar transfer preserves request facts
                    # and completes; the path policy still reports its sink.
                    self.assertEqual(limits, [], findings)
                    sinks = [row for row in findings if row['severity'] == 'critical']
                    expected = [('swift.taint.request_path_traversal', 10)] \
                        if case == 'derived' and policy == 'path' else []
                    self.assertEqual([(row['rule'], row['line']) for row in sinks], expected, findings)

    def test_issue229_complete_reporter_matrix_through_module_and_runner(self):
        for case, source in issue229_sources().items():
            path, _ = self.source(source, '-' + case)
            for mode in ('module', 'runner'):
                with self.subTest(case=case, mode=mode):
                    result, payload = self.wrapper_scan(path, mode, 'json', 'matrix-' + case + '-' + mode)
                    rows = self.assert_wrapper_report(result, payload, mode, incomplete=False,
                                                      sink_line=10 if case == 'derived' else None)
                    key = 'rule' if mode == 'module' else 'rule_id'
                    self.assertFalse(any(row[key] == 'swift.taint.analysis-limited' for row in rows), rows)

    def test_issue229_text_and_sarif_retain_completion_and_findings(self):
        cases = issue229_sources()
        for case in ('view', 'derived'):
            path, _ = self.source(cases[case], '-' + case)
            for mode in ('module', 'runner'):
                for fmt in ('text', 'sarif'):
                    with self.subTest(case=case, mode=mode, format=fmt):
                        result, payload = self.wrapper_scan(path, mode, fmt, '-'.join((case, mode, fmt)))
                        self.assertEqual(result.returncode, 1 if case == 'derived' else 0, result.stderr)
                        if fmt == 'text':
                            combined = result.stdout + result.stderr
                            self.assertNotIn('Swift analysis did not complete', combined)
                            self.assertEqual('Request-derived path reaches file' in combined, case == 'derived', combined)
                            if mode == 'runner':
                                self.assertNotIn('Status: partial', combined)
                        else:
                            rows = [row for run in payload['runs'] for row in run.get('results', [])]
                            sinks = [row for row in rows if row['ruleId'] == 'swift.taint.request_path_traversal']
                            self.assertEqual([row['locations'][0]['physicalLocation']['region']['startLine']
                                              for row in sinks], [10] if case == 'derived' else [], rows)
                            self.assertFalse(any(row['ruleId'] == 'swift.taint.analysis-limited' for row in rows), rows)
                            invocations = [item for run in payload['runs'] for item in run.get('invocations', [])]
                            self.assertTrue(all(item.get('executionSuccessful', True) for item in invocations), payload)

    def test_issue229_ordinary_attributes_preserve_storage_flow(self):
        for index, attribute in enumerate((
                '@MainActor', '@_Concurrency.MainActor', '@objc', '@objc(path)',
                '@available(iOS 16, *)', '@MainActor\n    @available(iOS 16, *)',
                '@available(iOS 16, *) private(set) @MainActor')):
            with self.subTest(attribute=attribute):
                self.check('''
                    import Foundation
                    final class Model: NSObject {
                        %s var path = ""
                        @MainActor func handle(req: Request) {
                            path = req.query["path"]!
                            _ = String(contentsOfFile: path) // unsafe
                        }
                    }
                ''' % attribute, suffix='-attribute' + str(index))
        self.check('''
            import AppKit
            final class Model: NSObject {
                @IBOutlet weak var label: NSTextField?
                func start() {
                    label = nil
                    let request = 1
                    _ = request
                    _ = String(contentsOfFile: "/fixed")
                }
            }
        ''', suffix='-outlet')

    def test_issue229_framework_scalar_writes_and_readback_are_clean(self):
        for index, attribute in enumerate((
                '@State', '@Published', '@SwiftUI.State', '@Combine.Published',
                '@SwiftUI.State<String>', '@Combine.Published<String>',
                '@MainActor @Published', '@available(iOS 16, *)\n    @State',
                '@SwiftUI.State private(set)', '@MainActor\n    @Combine.Published')):
            with self.subTest(attribute=attribute):
                self.check('''
                    import SwiftUI
                    import Combine
                    final class Model {
                        %s var path = ""
                        func handle(req: Request) {
                            let fixed = "/fixed"
                            self.path = fixed
                            _ = String(contentsOfFile: self.path)
                        }
                    }
                ''' % attribute, suffix='-framework' + str(index))
        for index, (declaration, assigned) in enumerate((
                ('var busy = false', 'true'), ('var count = 0', '2'),
                ('var busy: Bool = false', 'false'), ('var label: String = ""', '"fixed"'))):
            self.check('''
                import SwiftUI
                struct Model {
                    @State %s
                    func handle(req: Request) {
                        _ = req
                        self.%s = %s
                        _ = String(contentsOfFile: "/fixed")
                    }
                }
            ''' % (declaration, declaration.split()[1].rstrip(':'), assigned), suffix='-scalar' + str(index))

    def test_issue229_unknown_wrappers_and_effectful_setters_remain_incomplete(self):
        cases = (
            ('@Unknown var busy = false', 'busy = true', 'wrapped stored property'),
            ('@Binding var busy: Bool', 'busy = true', 'wrapped stored property'),
            ('@AppStorage("busy") var busy = false', 'busy = true', 'wrapped stored property'),
            ('@Published @Unknown var busy = false', 'busy = true', 'wrapped stored property'),
            ('@State(wrappedValue: false) var busy: Bool', 'busy = true', 'wrapped stored property'),
            ('@State var count = 0', 'count += 1', 'wrapped stored property'),
            ('@Published var busy = false { didSet { observe(busy) } }', 'busy = true', 'observer'),
            ('@State var busy = false { willSet { observe(newValue) } }', 'busy = true', 'observer'),
            ('var busy: Bool { get { false } set { observe(newValue) } }', 'busy = true', 'accessor'),
            ('@Published var busy = false', 'busy = unknownValue()', 'wrapped stored property'),
        )
        for index, (declaration, assignment, reason) in enumerate(cases):
            with self.subTest(declaration=declaration, assignment=assignment):
                findings = self.unsupported('''
                    import SwiftUI
                    import Combine
                    final class Model {
                        %s
                        func handle(req: Request) {
                            %s
                            _ = String(contentsOfFile: req.query["independent"]!)
                        }
                    }
                ''' % (declaration, assignment), reason, '-effects' + str(index))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == 7 for row in findings), findings)

    def test_issue229_native_names_do_not_authorize_shadowed_wrappers(self):
        cases = (
            ('State', 'import SwiftUI', '@propertyWrapper struct State<T> { var wrappedValue: T }'),
            ('Published', 'import Combine', '@propertyWrapper struct Published<T> { var wrappedValue: T }'),
            ('Published', 'import Combine', 'typealias Published = Unknown'),
            ('State', '', ''),
            ('Published', '', ''),
            ('MainActor', '', '@propertyWrapper struct MainActor<T> { var wrappedValue: T }'),
            ('SwiftUI.State', 'import SwiftUI', 'enum SwiftUI { @propertyWrapper struct State<T> { var wrappedValue: T } }'),
            ('Combine.Published', 'import Combine', 'enum Combine { @propertyWrapper struct Published<T> { var wrappedValue: T } }'),
            ('State', 'import SwiftUI', 'extension State<Bool> {}'),
            ('SwiftUI.State', 'import SwiftUI', 'extension SwiftUI.State<Bool> {}'),
            ('Published', 'import Combine', 'extension Published<Bool> {}'),
            ('Combine.Published', 'import Combine', 'extension Combine.Published<Bool> {}'),
            ('SwiftUI.State', 'import SwiftUI',
             'typealias LocalState = SwiftUI.State<Bool>; extension LocalState {}'),
            ('Combine.Published', 'import Combine',
             'typealias LocalPublished = Combine.Published<Bool>; extension LocalPublished {}'),
        )
        for index, (name, imported, shadow) in enumerate(cases):
            with self.subTest(wrapper=name, shadow=shadow):
                findings = self.unsupported('''
                    %s
                    final class Model {
                        @%s var busy = false
                        func handle(req: Request) {
                            busy = true
                            _ = String(contentsOfFile: req.query["independent"]!)
                        }
                    }
                    %s
                ''' % (imported, name, shadow), 'wrapped stored property', '-identity' + str(index))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    for row in findings), findings)

    def test_issue229_request_overwrite_keeps_flow_and_wrapper_boundaries(self):
        for wrapper in ('State', 'Published'):
            # Both stores are modeled for native scalar storage. Weak updates
            # retain the earlier request source without inventing incompleteness.
            self.check('''
                import SwiftUI
                import Combine
                final class Model {
                    @%s var path = ""
                    func handle(req: Request) {
                        path = req.query["path"]!
                        path = "/fixed"
                        _ = String(contentsOfFile: path) // unsafe
                    }
                }
            ''' % wrapper, suffix='-' + wrapper)
        findings = self.unsupported('''
            final class Model {
                @Unknown var path = ""
                func handle(req: Request) {
                    path = req.query["path"]!
                    path = "/fixed"
                    _ = String(contentsOfFile: path)
                }
            }
        ''', 'wrapped stored property', '-unknown')
        self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                            and row['line'] == 6 for row in findings), findings)

    def test_issue229_dispatch_and_declaration_effects_are_not_plain_storage(self):
        cases = (
            ('class Model', '@Published var busy = false', 'busy = true'),
            ('enum Other { final class Model {} }; class Model', '@Published var busy = false', 'busy = true'),
            ('final class Model: NSObject', '@Published @objc dynamic var busy = false', 'busy = true'),
            ('final class Model: NSObject', '@objc dynamic var busy = false', 'busy = true'),
            ('final class Model: NSObject', '@MainActor lazy var busy = false', 'busy = true'),
            ('final class Model: NSObject', '@NSManaged var busy: Bool', 'busy = true'),
            ('final class Model: NSObject', '@NSCopying var label: NSString = ""', 'label = "fixed"'),
            ('@Observable final class Model', '@Published var busy = false', 'busy = true'),
            ('final class Model', '@Published<String> var busy = false', 'busy = true'),
            ('final class Model', '@CustomActor var busy = false', 'busy = true'),
        )
        for index, (owner, declaration, assignment) in enumerate(cases):
            with self.subTest(owner=owner, declaration=declaration):
                source = '''
                    import Foundation
                    import SwiftUI
                    import Combine
                    %s {
                        %s
                        func handle(req: Request) {
                            %s
                            _ = String(contentsOfFile: req.query["independent"]!) // independent
                        }
                    }
                ''' % (owner, declaration, assignment)
                findings = self.unsupported(source, 'analysis', '-dispatch' + str(index))
                sink_line = next(number for number, line in enumerate(
                    textwrap.dedent(source).strip().splitlines(), 1) if '// independent' in line)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == sink_line for row in findings), findings)

    def test_issue229_attribute_arguments_do_not_become_declaration_modifiers(self):
        for word in ('static', 'class', 'final', 'lazy'):
            with self.subTest(attribute_message=word):
                self.check('''
                    import Foundation
                    final class Model {
                        @available(*, deprecated, message: "%s")
                        var path = ""
                        @available(*, deprecated, message: "%s")
                        func store(_ value: String) { path = value }
                        @available(*, deprecated, message: "%s")
                        var current: String { path }
                        func handle(req: Request) {
                            store(req.query["path"]!)
                            _ = String(contentsOfFile: current) // unsafe
                        }
                    }
                ''' % (word, word, word), suffix='-argument-' + word)
        # An availability message cannot make an overridable class final and
        # therefore cannot authorize native wrapper dispatch for its fields.
        self.unsupported('''
            import Combine
            @available(*, deprecated, message: "final")
            class Model {
                @Published var busy = false
                func handle(req: Request) {
                    busy = true
                    _ = String(contentsOfFile: req.query["path"]!)
                }
            }
        ''', 'wrapped stored property', '-owner-final-message')

    def test_issue229_generic_owner_bindings_cannot_borrow_framework_identity(self):
        cases = (
            ('final class Model<State>', '@State', ''),
            ('final class Model<Published>', '@Published', ''),
            ('final class Model<Bool>', '@State', ''),
            ('final class Outer<SwiftUI> { final class Model', '@SwiftUI.State', '}'),
            ('final class Outer<Combine> { final class Model', '@Combine.Published', '}'),
        )
        for index, (owner, wrapper, ending) in enumerate(cases):
            with self.subTest(owner=owner):
                self.unsupported('''
                    import SwiftUI
                    import Combine
                    %s {
                        %s var busy = false
                        func handle(req: Request) {
                            busy = true
                            _ = String(contentsOfFile: req.query["path"]!)
                        }
                    } %s
                ''' % (owner, wrapper, ending), 'analysis', '-generic' + str(index))

    def test_issue229_custom_values_and_callable_storage_stay_incomplete(self):
        cases = (
            ('final class Payload { var value = false }', '@State var value = Payload()', 'value = Payload()'),
            ('', '@State var work: () -> String = { "fixed" }', 'work = { req.query["path"]! }'),
            ('', '@Published var value: Any = false', 'value = true'),
            ('struct Custom: ExpressibleByBooleanLiteral { init(booleanLiteral value: Swift.Bool) {} }; '
             'typealias Bool = Custom', '@State var busy: Bool = false', 'busy = true'),
            ('struct Custom: ExpressibleByStringLiteral { init(stringLiteral value: Swift.String) {} }; '
             'typealias String = Custom', '@Published var path: String = ""', 'path = "fixed"'),
        )
        for index, (setup, declaration, assignment) in enumerate(cases):
            with self.subTest(declaration=declaration):
                source = '''
                    import SwiftUI
                    import Combine
                    %s
                    final class Model {
                        %s
                        func handle(req: Request) {
                            %s
                            _ = Swift.String(contentsOfFile: req.query["independent"]!) // independent
                        }
                    }
                ''' % (setup, declaration, assignment)
                findings = self.unsupported(source, 'wrapped stored property', '-custom-value' + str(index))
                sink_line = next(number for number, line in enumerate(
                    textwrap.dedent(source).strip().splitlines(), 1) if '// independent' in line)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == sink_line for row in findings), findings)

    def test_issue229_wrapped_typed_request_read_keeps_the_original_finding(self):
        # Keep the original late-review source, including its no-argument
        # method: an incomplete accessor must not erase the declared Request.
        source = '''
            import Vapor
            final class Model {
                @Unknown var request: Request
                func handle() {
                    _ = try? String(contentsOfFile: request.query["path"]!)
                }
            }
        '''
        findings = self.unsupported(source, 'wrapped stored property')
        self.assertEqual([(row['rule'], row['line'], row['severity'])
                          for row in findings if row['severity'] == 'critical'],
                         [('swift.taint.request_path_traversal', 5, 'critical')], findings)
        path, _ = self.source(source)
        for mode in ('module', 'runner'):
            with self.subTest(mode=mode):
                result, payload = self.wrapper_scan(path, mode, 'json', 'typed-request-' + mode)
                self.assert_wrapper_report(result, payload, mode, incomplete=True, sink_line=5)

    def test_issue229_executable_wrapper_defaults_are_not_proven_clean(self):
        template = '''
            import SwiftUI
            import Vapor
            enum Incoming { static var request: Request? }
            struct Screen: View {
                @State private var path: String = %s
                var body: some View { Text("Example") }
                func load(req: Request) {
                    path = "/fixed"
                    _ = try? String(contentsOfFile: path)
                    _ = String(contentsOfFile: req.query["independent"]!) // unsafe
                }
            }
        '''
        for index, default in enumerate(('initialPath()', 'Incoming.request!.query["path"]!')):
            with self.subTest(default=default):
                findings = self.unsupported(template % default, 'wrapped stored property',
                                            '-default' + str(index))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == 10 for row in findings), findings)
        # A literal default establishes the bounded value model. The same
        # independent unsafe sink remains a finding without a coverage limit.
        self.check(template % '"/original"', suffix='-literal-control')

    def test_issue229_published_callbacks_and_inheritance_remain_incomplete(self):
        sources = (
            '''
                import Combine
                import Vapor
                final class Model: ObservableObject {
                    var current: Request?
                    @Published var busy = false
                    var subscription: AnyCancellable?
                    func observe() {
                        subscription = $busy.sink { [unowned self] _ in
                            _ = try? String(contentsOfFile: self.current!.query["path"]!)
                        }
                    }
                    func handle(req: Request) {
                        current = req
                        busy = true
                        _ = String(contentsOfFile: req.query["independent"]!) // independent
                    }
                }
            ''',
            '''
                import Combine
                import Vapor
                final class Model: ObservableObject {
                    var current: Request?
                    @Published var busy = false
                    var objectWillChange: ObservableObjectPublisher {
                        _ = try? String(contentsOfFile: current!.query["path"]!)
                        return ObservableObjectPublisher()
                    }
                    func handle(req: Request) {
                        current = req
                        busy = true
                        _ = String(contentsOfFile: req.query["independent"]!) // independent
                    }
                }
            ''',
        )
        for index, source in enumerate(sources):
            with self.subTest(callback=index):
                findings = self.unsupported(source, 'wrapped stored property', '-callback' + str(index))
                sink_line = next(number for number, line in enumerate(
                    textwrap.dedent(source).strip().splitlines(), 1) if '// independent' in line)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == sink_line for row in findings), findings)
        for index, (setup, inherited) in enumerate((
                ('protocol CustomObserver: ObservableObject {}', 'CustomObserver'),
                ('class Base: ObservableObject {}', 'Base'))):
            with self.subTest(inherited=inherited):
                findings = self.unsupported('''
                    import Combine
                    %s
                    final class Model: %s {
                        @Published var busy = false
                        func handle(req: Request) {
                            busy = true
                            _ = String(contentsOfFile: req.query["independent"]!)
                        }
                    }
                ''' % (setup, inherited), 'wrapped stored property', '-inheritance' + str(index))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == 7 for row in findings), findings)

    def test_issue229_projected_and_backing_storage_are_not_plain_assignments(self):
        for index, (wrapper, access) in enumerate((
                ('State', '_ = $busy'), ('State', '_busy = State(initialValue: true)'),
                ('Published', '_ = $busy'), ('Published', '_busy = Published(initialValue: true)'))):
            with self.subTest(wrapper=wrapper, access=access):
                findings = self.unsupported('''
                    import SwiftUI
                    import Combine
                    final class Model {
                        @%s var busy = false
                        func accessStorage() { %s }
                        func handle(req: Request) {
                            busy = true
                            _ = String(contentsOfFile: req.query["independent"]!)
                        }
                    }
                ''' % (wrapper, access), 'wrapped stored property', '-storage' + str(index))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == 8 for row in findings), findings)
        for wrapper in ('State', 'Published'):
            with self.subTest(inert_identifiers=wrapper):
                self.check('''
                    import SwiftUI
                    import Combine
                    final class Model: Combine.ObservableObject {
                        @%s var busy = false
                        func handle(req: Request) {
                            let note = "$busy _busy objectWillChange"
                            _ = note
                            // $busy _busy objectWillChange are inert here.
                            busy = true
                            _ = String(contentsOfFile: req.query["independent"]!) // unsafe
                        }
                    }
                ''' % wrapper, suffix='-inert-' + wrapper)

    def test_issue229_partial_suppression_and_cache_invalidation(self):
        path, clean = self.source(issue229_sources()['model'], '-cache')
        cache = self.artifacts / 'wrapper-cache'
        for attempt in range(2):
            result, payload = self.wrapper_scan(path, 'runner', 'json', 'clean-cache-' + str(attempt), cache_dir=cache)
            self.assert_wrapper_report(result, payload, 'runner', incomplete=False)
            self.assertEqual(payload['scanners'][0]['extras']['profile']['cache_hits'], attempt, payload)
        unsupported = clean.replace('@Published', '@Unknown').replace(
            'busy = true', 'busy = true // ubs:ignore[swift.taint.analysis-limited] supported later')
        path.write_text(unsupported, encoding='utf-8')
        for attempt in range(2):
            result, payload = self.wrapper_scan(path, 'runner', 'json', 'partial-cache-' + str(attempt), cache_dir=cache)
            rows = self.assert_wrapper_report(result, payload, 'runner', incomplete=True)
            self.assertFalse(any(row['rule_id'] == 'swift.taint.analysis-limited' for row in rows), rows)
            self.assertEqual(payload['scanners'][0]['extras']['profile']['cache_hits'], 0, payload)
        path.write_text(clean, encoding='utf-8')
        result, payload = self.wrapper_scan(path, 'runner', 'json', 'restored-cache', cache_dir=cache)
        self.assert_wrapper_report(result, payload, 'runner', incomplete=False)
        self.assertEqual(payload['scanners'][0]['extras']['profile']['cache_hits'], 1, payload)

    def test_incoming_callable_field_alias_keeps_opaque_alternative(self):
        for default in ('', ' = { _ in "/default" }'):
            with self.subTest(default=default):
                findings = self.unsupported('''
                    struct Box { var work: (String) -> String%s }
                    func fixed(_ value: String) -> String { "/fixed" }
                    func handle(req: Request, box: Box) {
                        let work = req.query["mode"] == "safe" ? fixed : box.work
                        let path = work(req.query["path"]!)
                        _ = String(contentsOfFile: path)
                    }
                ''' % default, 'opaque callable', '-incoming' + str(bool(default)))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    for row in findings), findings)
                self.check('''
                    struct Box { var work: (String) -> String%s }
                    func fixed(_ value: String) -> String { "/fixed" }
                    func handle(req: Request) {
                        let box = %s
                        let work = req.query["mode"] == "safe" ? fixed : box.work
                        _ = String(contentsOfFile: work(req.query["path"]!))
                    }
                ''' % (default, 'Box()' if default else 'Box(work: fixed)'),
                    suffix='-constructed' + str(bool(default)))

    def test_known_layout_cannot_erase_incoming_object_alternative(self):
        sources = (
            '''
                struct Box { let work: (String) -> String }
                func fixed(_ value: String) -> String { "/fixed" }
                func handle(req: Request, incoming: Box) {
                    let box = req.query["mode"] == "safe" ? Box(work: fixed) : incoming
                    _ = String(contentsOfFile: box.work(req.query["path"]!))
                }
            ''',
            '''
                struct Box { let work: (String) -> String }
                func fixed(_ value: String) -> String { "/fixed" }
                func handle(req: Request, incoming: Box?) {
                    let box = req.query["mode"] == "safe" ? Box(work: fixed) : incoming!
                    _ = String(contentsOfFile: box.work(req.query["path"]!))
                }
            ''',
            '''
                struct Box { let work: (String) -> String }
                func fixed(_ value: String) -> String { "/fixed" }
                func handle(req: Request, incoming: inout Box) {
                    let box = req.query["mode"] == "safe" ? Box(work: fixed) : incoming
                    _ = String(contentsOfFile: box.work(req.query["path"]!))
                }
            ''',
            '''
                struct Box { let request: Request? }
                func handle(req: Request, incoming: Box) {
                    let box = req.query["mode"] == "safe" ? Box(request: nil) : incoming
                    _ = String(contentsOfFile: box.request!.query["path"]!)
                }
            ''',
            '''
                func fixed(_ value: String) -> String { "/fixed" }
                struct Box {
                    let work: (String) -> String
                    func handle(req: Request) {
                        let box = req.query["mode"] == "safe" ? Box(work: fixed) : self
                        _ = String(contentsOfFile: box.work(req.query["path"]!))
                    }
                }
            ''',
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                findings = self.unsupported(source, 'mixed incoming stored property', '-' + str(index))
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    for row in findings), findings)
        self.check('''
            struct Box { let work: (String) -> String }
            func fixed(_ value: String) -> String { "/fixed" }
            func make() -> Box { Box(work: fixed) }
            func forward(_ box: Box) -> Box { box }
            func handle(req: Request) {
                let box = req.query["mode"] == "safe" ? Box(work: fixed) : forward(make())
                _ = String(contentsOfFile: box.work(req.query["path"]!))
            }
        ''', suffix='-known-clean')
        self.check('''
            struct Box { let path: String }
            func handle(req: Request) {
                let box = req.query["mode"] == "safe" ? Box(path: "/fixed") : Box(path: req.query["path"]!)
                _ = String(contentsOfFile: box.path) // unsafe
            }
        ''', suffix='-known-unsafe')

    def test_type_alias_constructor_reports_unmodeled_unused_effects(self):
        for callee, declaration in (
                ('Wrapper', 'typealias Wrapper = Input'),
                ('Names.Wrapper', 'struct Names { typealias Wrapper = Input }'),
                ('Names.Wrapper.init', 'struct Names { typealias Wrapper = Input }')):
            with self.subTest(callee=callee):
                source = '''
                    struct Input {
                        init(_ path: String) { _ = String(contentsOfFile: path) }
                    }
                    %s
                    func handle(req: Request) {
                        let unused = %s(req.query["path"]!)
                        _ = String(contentsOfFile: req.query["other"]!) // known
                    }
                ''' % (declaration, callee)
                findings = self.unsupported(source, 'object initialization through a type alias', '-' + callee)
                known_line = next(number for number, line in enumerate(
                    textwrap.dedent(source).strip().splitlines(), 1) if '// known' in line)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == known_line for row in findings), findings)
        self.check('''
            struct Input { let path: String }
            struct Names { typealias Work = Input }
            func fixed(_ value: String) -> String { "/fixed" }
            func handle(req: Request) {
                let Work = fixed
                _ = String(contentsOfFile: Work(req.query["path"]!))
            }
        ''', suffix='-lexical-callable')

    def test_global_field_mutations_preserve_shared_state_refusal(self):
        cases = (
            ('final class Box { var path = "/fixed" }; let shared = Box()',
             'shared.path = INPUT', 'shared.path', 'req.query["path"]!', '"/fixed"'),
            ('final class Box { var path = "/fixed" }; let shared = Box(); let alias = shared',
             'let local = alias; local.path = INPUT', 'shared.path', 'req.query["path"]!', '"/fixed"'),
            ('final class Box { var path = "/fixed" }; let shared = Box(); '
             'func assign(_ box: Box, _ value: String) { box.path = value }',
             'assign(shared, INPUT)', 'shared.path', 'req.query["path"]!', '"/fixed"'),
            ('final class Leaf { var path = "/fixed" }; struct Box { var leaf = Leaf() }; let shared = Box()',
             'let alias = shared.leaf; alias.path = INPUT', 'shared.leaf.path', 'req.query["path"]!', '"/fixed"'),
            ('final class Leaf { var path = "/fixed" }; '
             'final class Box { var leaf = Leaf(); func assign(_ value: String) { leaf.path = value } }; '
             'let shared = Box()',
             'shared.assign(INPUT)', 'shared.leaf.path', 'req.query["path"]!', '"/fixed"'),
            ('struct Box { var request: Request?; init() { request = nil } }; var shared = Box()',
             'shared.request = INPUT', 'shared.request!.query["path"]!', 'req', 'nil'),
        )
        for index, (setup, change, read, unsafe, clean) in enumerate(cases):
            with self.subTest(index=index):
                source = '''
                    %s
                    func change(req: Request) { %s }
                    func read() { _ = String(contentsOfFile: %s) } // shared sink
                    func handle(req: Request) { change(req: req); read() }
                ''' % (setup, change.replace('INPUT', unsafe), read)
                findings = self.unsupported(source, 'global field mutation', '-global' + str(index))
                sink_line = next(number for number, line in enumerate(
                    textwrap.dedent(source).strip().splitlines(), 1) if '// shared sink' in line)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    and row['line'] == sink_line for row in findings), findings)
                self.check(source.replace(change.replace('INPUT', unsafe), change.replace('INPUT', clean)),
                           suffix='-global-clean' + str(index))
        incoming = '''
            final class Box { var path = "/fixed" }
            let shared = Box()
            func read() { _ = String(contentsOfFile: shared.path) }
            func handle(req: Request, incoming: Box) {
                incoming.path = req.query["path"]!
                read()
            }
        '''
        findings = self.unsupported(incoming, 'global field mutation', '-incoming-global')
        self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                            and row['line'] == 3 for row in findings), findings)
        self.check(incoming.replace('req.query["path"]!', '"/fixed"'), suffix='-incoming-global-clean')
        self.check('''
            struct Box { var path = "/fixed" }
            let shared = Box()
            func handle(req: Request) {
                var local = shared
                local.path = req.query["path"]!
                _ = String(contentsOfFile: local.path) // unsafe
                _ = String(contentsOfFile: shared.path)
            }
        ''', suffix='-value-copy')

    def test_native_string_storage_keeps_alias_flow_and_custom_string_boundary(self):
        for declaration, shadow in (
                ('String', ''),
                ('Swift.String', 'struct String { let work: (Swift.String) -> Swift.String }')):
            with self.subTest(declaration=declaration):
                self.check('''
                    %s
                    final class Box { var path: %s = "/fixed" }
                    func handle(req: Request, first: Box, second: Box) {
                        first.path = req.query["path"]!
                        _ = Swift.String(contentsOfFile: second.path) // unsafe
                    }
                ''' % (shadow, declaration), suffix='-' + declaration)
        findings = self.unsupported('''
            struct String { let work: (Swift.String) -> Swift.String }
            struct Box { let path: String }
            func fixed(_ value: Swift.String) -> Swift.String { "/fixed" }
            func handle(req: Request, incoming: Box) {
                let box = req.query["mode"] == "safe" ? Box(path: String(work: fixed)) : incoming
                _ = Swift.String(contentsOfFile: box.path.work(req.query["path"]!))
            }
        ''', 'mixed incoming stored property', '-custom-string')
        self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                            for row in findings), findings)

    def test_memberwise_fields_are_independent_for_all_policies(self):
        sinks = {
            'path': '_ = String(contentsOfFile: input.%s)',
            'redirect': '_ = req.redirect(to: input.%s)',
            'header': 'response.headers["X-Value"] = input.%s',
            'outbound': '_ = URLSession.shared.data(from: URL(string: input.%s)!)',
        }
        for policy, sink in sinks.items():
            with self.subTest(policy=policy):
                self.check('''
                    import Foundation
                    struct Input { let unsafe: String; let fixed: String }
                    func handle(req: Request) {
                        let input = Input(unsafe: req.query["target"]!, fixed: "/fixed")
                        %s // unsafe
                        %s
                    }
                ''' % (sink % 'unsafe', sink % 'fixed'), policy, '-' + policy)

    def test_explicit_initializer_body_sinks_and_stored_fields(self):
        self.check('''
            struct Input {
                let path: String
                let fixed: String
                init(value: String) {
                    _ = String(contentsOfFile: value) // unsafe
                    path = value
                    self.fixed = "/fixed"
                }
            }
            func handle(req: Request) {
                let input = Input(value: req.query["path"]!)
                _ = String(contentsOfFile: input.path) // unsafe
                _ = String(contentsOfFile: input.fixed)
            }
        ''')

    def test_initializer_literal_overwrite_kills_only_that_field(self):
        self.check('''
            struct Input {
                var path: String
                let other: String
                init(_ value: String) {
                    path = value
                    other = value
                    path = "/fixed"
                }
            }
            func handle(req: Request) {
                let input = Input(req.query["path"]!)
                _ = String(contentsOfFile: input.path)
                _ = String(contentsOfFile: input.other) // unsafe
            }
        ''')

    def test_initializer_branches_do_not_erase_unsafe_alternative(self):
        self.check('''
            struct Input {
                var path: String
                init(_ value: String, fixed: Bool) {
                    if fixed { path = "/fixed" } else { path = value }
                }
            }
            func handle(req: Request, fixed: Bool) {
                let input = Input(req.query["path"]!, fixed: fixed)
                _ = String(contentsOfFile: input.path) // unsafe
            }
        ''')

    def test_nested_memberwise_values_and_request_fields(self):
        self.check('''
            struct Inner { let path: String }
            struct Outer { let inner: Inner; let request: Request; let fixed: String }
            func handle(req: Request) {
                let outer = Outer(inner: Inner(path: req.query["path"]!), request: req, fixed: "/fixed")
                _ = String(contentsOfFile: outer.inner.path) // unsafe
                _ = String(contentsOfFile: outer.request.query["other"]!) // unsafe
                _ = String(contentsOfFile: outer.fixed)
            }
        ''')

    def test_nested_reference_aliases_survive_container_copies_and_helper_calls(self):
        self.check('''
            final class Inner {
                var path = "/fixed"
                func set(_ value: String) { path = value }
            }
            struct Outer { let inner: Inner; let fixed: String }
            func mutate(_ inner: Inner, _ value: String) { inner.set(value) }
            func handle(req: Request) {
                let shared = Inner()
                let a = Outer(inner: shared, fixed: "/fixed")
                let b = Outer(inner: shared, fixed: "/other")
                mutate(a.inner, req.query["path"]!)
                _ = String(contentsOfFile: a.inner.path) // unsafe
                _ = String(contentsOfFile: b.inner.path) // unsafe
                _ = String(contentsOfFile: a.fixed)
                _ = String(contentsOfFile: b.fixed)
            }
        ''')

    def test_nested_value_mutation_does_not_mutate_a_struct_copy(self):
        self.check('''
            struct Inner {
                var path = "/fixed"
                mutating func set(_ value: String) { path = value }
            }
            struct Outer { var inner: Inner; let fixed: String }
            func handle(req: Request) {
                var a = Outer(inner: Inner(), fixed: "/fixed")
                let b = a
                a.inner.set(req.query["path"]!)
                _ = String(contentsOfFile: a.inner.path) // unsafe
                _ = String(contentsOfFile: b.inner.path)
                _ = String(contentsOfFile: a.fixed)
            }
        ''')

    def test_initializer_write_through_implicit_stored_base(self):
        self.check('''
            struct Inner { var path = "/fixed" }
            struct Input {
                var inner = Inner()
                let fixed = "/fixed"
                init(_ value: String) { inner.path = value }
            }
            func handle(req: Request) {
                let input = Input(req.query["p"]!)
                _ = String(contentsOfFile: input.inner.path) // unsafe
                _ = String(contentsOfFile: input.fixed)
            }
        ''')

    def test_unmodeled_callback_local_type_cannot_erase_a_request_shape(self):
        self.unsupported('''
            func handle(req: Request) {
                let make = {
                    struct Input { let request: Request }
                    return Input(request: req)
                }
                let input = make()
                _ = String(contentsOfFile: input.request.query["p"]!)
            }
        ''', 'object initialization')

    def test_unknown_element_write_cannot_erase_stored_request_provenance(self):
        for value, item_type, projected in (
                ('req', 'Request', 'values["input"]!'),
                ('Input(request: req)', 'Input', 'values["input"]!.request')):
            with self.subTest(value=value):
                self.unsupported('''
                    struct Input { let request: Request }
                    func handle(req: Request) {
                        var values: [String: %s] = [:]
                        values["input"] = %s
                        _ = String(contentsOfFile: %s.query["p"]!)
                    }
                ''' % (item_type, value, projected), 'field/element write needs heap analysis', '-' + str(len(value)))

    def test_constructor_defaults_use_declaration_scope(self):
        self.check('''
            struct Input {
                static let name = upload.filename
                var path = name
                let fixed = "/fixed"
            }
            func handle(req: Request) {
                let name = "/caller-name"
                let input = Input()
                _ = String(contentsOfFile: input.path) // unsafe
                _ = String(contentsOfFile: input.fixed)
            }
        ''')
        self.check('''
            struct Input {
                static func make() -> String { upload.filename }
                var path = make()
            }
            func make() -> String { "/caller-helper" }
            func handle(req: Request) {
                let input = Input()
                _ = String(contentsOfFile: input.path) // unsafe
            }
        ''', suffix='-helper')

    def test_unused_default_field_still_runs_initializer_effects(self):
        self.check('''
            func readPath() -> String {
                let path = upload.filename
                _ = String(contentsOfFile: path) // unsafe
                return "/fixed"
            }
            final class Input { let unused = readPath(); let fixed = "/fixed" }
            func handle(req: Request) {
                let input = Input()
                _ = String(contentsOfFile: input.fixed)
            }
        ''')

    def test_request_decoding_runs_custom_initializer_and_synthesized_fields(self):
        self.check('''
            struct Input: Decodable { let path: String; let fixed = "/fixed" }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path) // unsafe
                _ = String(contentsOfFile: input.fixed)
            }
        ''')
        self.check('''
            struct Input: Decodable {
                let path: String
                init(from decoder: Decoder) throws {
                    let container = try decoder.singleValueContainer()
                    let incoming = try container.decode(String.self)
                    _ = String(contentsOfFile: incoming) // unsafe
                    path = incoming
                }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path) // unsafe
            }
        ''', suffix='-custom')

    def test_custom_decoder_can_replace_untrusted_data_with_a_literal(self):
        self.check('''
            struct Input: Decodable {
                let path: String
                init(from decoder: Decoder) throws { path = "/fixed" }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''')

    def test_unrelated_from_overload_cannot_sanitize_decoded_data(self):
        self.unsupported('''
            struct Input: Decodable {
                let path: String
                init(from value: String) { path = "/fixed" }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''', 'Decodable initialization')
        self.check('''
            struct Input: Decodable {
                let path: String
                init(from value: String) { path = "/fixed" }
                init(from decoder: any Decoder) throws {
                    let c = try decoder.singleValueContainer()
                    path = try c.decode(String.self)
                }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path) // unsafe
            }
        ''', suffix='-typed-overload')

    def test_nested_custom_decoder_runs_even_when_its_result_is_discarded(self):
        self.check('''
            struct Nested: Decodable {
                init(from decoder: Decoder) throws {
                    let c = try decoder.singleValueContainer()
                    let path = try c.decode(String.self)
                    _ = String(contentsOfFile: path) // unsafe
                }
            }
            struct Input: Decodable {
                let path: String
                init(from decoder: Decoder) throws {
                    let c = try decoder.singleValueContainer()
                    _ = try c.decode(Nested.self)
                    path = "/fixed"
                }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''')

    def test_shadowed_decoder_type_cannot_select_an_unrelated_initializer(self):
        self.unsupported('''
            struct Decoder {}
            struct Input: Swift.Decodable {
                let path: String
                init(from value: Decoder) { path = "/fixed" }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''', 'Decodable initialization')
        self.check('''
            struct Decoder {}
            struct Input: Swift.Decodable {
                let path: String
                init(from decoder: Swift.Decoder) throws {
                    let c = try decoder.singleValueContainer()
                    path = try c.decode(String.self)
                }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path) // unsafe
            }
        ''', suffix='-qualified')
        self.unsupported('''
            struct Input: Swift.Decodable {
                typealias Decoder = String
                let path: String
                init(from value: Decoder) { path = "/fixed" }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''', 'Decodable initialization', '-nested-alias')

    def test_shadowed_request_content_decoder_reports_incomplete(self):
        self.unsupported('''
            struct ContentContainer {
                func decode(_ type: Input.Type) -> Input { Input(path: "/fixed") }
            }
            struct Request { let content: ContentContainer }
            struct Input: Decodable { let path: String }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''', 'decoder identity')

    def test_qualified_decoder_extensions_keep_their_incomplete_boundary(self):
        self.unsupported('''
            extension Swift.Decoder {
                func singleValueContainer() -> String { "/fixed" }
            }
            struct Input: Swift.Decodable {
                let path: String
                init(from decoder: Swift.Decoder) throws {
                    let c = try decoder.singleValueContainer()
                    path = try c.decode(String.self)
                }
            }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''', 'extended decoder dispatch')

    def test_shadowed_decodable_protocol_does_not_grant_synthesized_initialization(self):
        self.unsupported('''
            protocol Decodable {}
            struct Input: Decodable { let path: String }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path)
            }
        ''', 'Decodable initialization')
        self.check('''
            protocol Decodable {}
            struct Input: Swift.Decodable { let path: String }
            func handle(req: Request) {
                let input = try req.content.decode(Input.self)
                _ = String(contentsOfFile: input.path) // unsafe
            }
        ''', suffix='-qualified')

    def test_nested_type_initializer_runs_even_when_result_is_unused(self):
        self.check('''
            struct Outer {
                struct Inner {
                    init(value: String) { _ = String(contentsOfFile: value) } // unsafe
                }
            }
            func handle(req: Request) { let unused = Outer.Inner(value: req.query["path"]!) }
        ''')

    def test_initializer_overload_bindings_and_default_argument_effects(self):
        self.check('''
            struct Input {
                let path: String
                init(path: String) { self.path = path }
                init(fixed: Bool) { path = "/fixed" }
            }
            func handle(req: Request) {
                let a = Input(path: req.query["path"]!)
                let b = Input(fixed: true)
                _ = String(contentsOfFile: a.path) // unsafe
                _ = String(contentsOfFile: b.path)
            }
        ''')
        self.unsupported('''
            struct Input { init(path: String) {} }
            func handle(req: Request) {
                let unused = Input(other: req.query["path"]!)
                _ = String(contentsOfFile: "/fixed")
            }
        ''', 'selected helper arguments could not bind', '-mismatch')

    def test_unmodeled_initialization_remains_explicitly_incomplete(self):
        cases = {
            'generic': ('struct Input<T> { init(path: String) {} }',
                        'Input<Int>(path: req.query["path"]!)', 'generic type initialization'),
            'delegate': ('struct Input { init(path: String) {} }',
                         'Input.init(path: req.query["path"]!)', 'delegating initializer'),
            'wrapper': ('struct Input { @Wrapper var path: String = "/fixed" }',
                        'Input()', 'wrapped stored property'),
            'lazy': ('struct Input { lazy var path: String = "/fixed" }',
                     'Input()', 'lazy stored property'),
            'inheritance': ('class Base { init() { sideEffect() } }; final class Input: Base {}',
                            'Input()', 'inherited initialization'),
        }
        for label, (declaration, call, reason) in cases.items():
            with self.subTest(case=label):
                findings = self.unsupported(declaration + '\n' + '''
                    func handle(req: Request) {
                        let input = %s
                        _ = String(contentsOfFile: req.query["path"]!)
                    }
                ''' % call, reason, '-' + label)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal' for row in findings))

    def test_declaration_attributes_leave_stored_property_flow_intact(self):
        self.check('''
            import Foundation
            final class Model: NSObject {
                @available(iOS 15, *)
                @MainActor @objc private(set) var path = ""
                @MainActor func handle(req: Request) {
                    path = req.query["path"]!
                    _ = try? String(contentsOfFile: self.path) // unsafe
                }
            }
        ''')

    def test_custom_and_observed_setters_still_require_analysis_on_literal_writes(self):
        cases = (
            ('local-State', '''
                import SwiftUI
                @propertyWrapper struct State {
                    var wrappedValue: String {
                        get { return "" }
                        set { record(newValue) }
                    }
                }
                final class Model {
                    @MainActor @State var path: String
                    @MainActor func start(req: Request) {
                        path = "/fixed"
                        _ = try? String(contentsOfFile: req.query["other"]!)
                    }
                }
            ''', 'wrapped stored property'),
            ('generic-local', '''
                @propertyWrapper struct Local<Value> {
                    var wrappedValue: Value { didSet { record(wrappedValue) } }
                }
                final class Model {
                    @Local<String> var path = ""
                    func start(req: Request) {
                        path = "/fixed"
                        _ = try? String(contentsOfFile: req.query["other"]!)
                    }
                }
            ''', 'wrapped stored property'),
            ('observed-Published', '''
                import Combine
                final class Model {
                    @Published var path = "" { didSet { record(path) } }
                    func start(req: Request) {
                        path = "/fixed"
                        _ = try? String(contentsOfFile: req.query["other"]!)
                    }
                }
            ''', 'property observer'),
        )
        for label, source, reason in cases:
            with self.subTest(case=label):
                findings = self.unsupported(source, reason, '-' + label)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal'
                                    for row in findings), findings)

    def test_framework_wrapper_identity_respects_the_import_and_qualifier(self):
        source = '''
            import %s
            final class Model {
                @%s private var path = ""
                func handle(req: Request) {
                    path = req.query["path"]!
                    _ = try? String(contentsOfFile: path) // unsafe
                }
            }
        '''
        for module, wrapper in (('SwiftUI', 'SwiftUI.State'), ('SwiftUI', 'SwiftUI.State<String>'),
                                ('Combine', 'Published<String>')):
            with self.subTest(wrapper=wrapper):
                self.check(source % (module, wrapper), suffix='-' + wrapper.replace('<String>', '-String'))
        self.unsupported(source % ('VendorKit', 'State'), 'wrapped stored property', '-vendor')

    def test_framework_wrapper_writes_that_need_accessor_analysis(self):
        for wrapper, declaration, assignment in (
            ('Binding', '@Binding var path: String', '= req.query["path"]!'),
            ('AppStorage', '@AppStorage("path") var path = ""', '= req.query["path"]!'),
            ('State', '@State var path = ""', '+= "/fixed"'),
        ):
            with self.subTest(wrapper=wrapper):
                findings = self.unsupported('''
                    import SwiftUI
                    struct Model {
                        %s
                        func handle(req: Request) {
                            path %s
                            _ = try? String(contentsOfFile: req.query["other"]!)
                        }
                    }
                ''' % (declaration, assignment), 'wrapped stored property', '-' + wrapper)
                self.assertTrue(any(row['rule'] == 'swift.taint.analysis-limited' and row['line'] == 5
                                    for row in findings), findings)
                self.assertTrue(any(row['rule'] == 'swift.taint.request_path_traversal' and row['line'] == 6
                                    for row in findings), findings)

    def test_many_independent_fields_remain_within_the_default_budget(self):
        declarations = '\n'.join('let field%d: String' % index for index in range(48))
        arguments = ', '.join('field%d: %s' % (index, 'req.query["path"]!' if index == 47 else '"/fixed"')
                              for index in range(48))
        source = ('struct Input {\n' + declarations + '\n}\nfunc handle(req: Request) {\n'
                  'let input = Input(' + arguments + ')\n'
                  '_ = String(contentsOfFile: input.field0)\n'
                  '_ = String(contentsOfFile: input.field47) // unsafe\n}\n')
        self.check(source)
        path, source = self.source(source, '-budget')
        engine = SwiftEngine(path, source)
        effects = engine.analyze()
        self.assertEqual({engine.step(offset, 'sink', 'file').line for offset in effects}, {54})
        self.assertLess(500_000 - engine.budget.remaining, 100_000)

    def test_recursive_stored_value_expansion_has_an_explicit_bound(self):
        source = 'struct Box { let value: String }\n'
        for index in range(1, 18):
            source += 'struct Box%d { let value: %s }\n' % (index, 'Box' if index == 1 else 'Box%d' % (index - 1))
        value = 'Box(value: req.query["path"]!)'
        for index in range(1, 18):
            value = 'Box%d(value: %s)' % (index, value)
        source += 'func handle(req: Request) { let unused = %s; _ = String(contentsOfFile: req.query["other"]!) }\n' % value
        path, source = self.source(source)
        with self.assertRaisesRegex(AnalysisLimit, 'stored-field depth limit'):
            flow_findings(path, source, 'path')


if __name__ == '__main__':
    unittest.main()
