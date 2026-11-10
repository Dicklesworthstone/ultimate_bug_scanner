"""Selected Swift initialization must trace fields without inventing clean flow.

The sources below state their expected sink sites independently of the
frontend. Retain each source and result so failures are directly reproducible.
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
