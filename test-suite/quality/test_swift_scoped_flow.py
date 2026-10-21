"""Swift value identity, call binding and exceptional-boundary regressions.

Complements the independent ordinary-CLI request-flow oracle with selected
frontend semantics. Sources and complete structured findings are retained in
artifacts; assertions specify actual sink sites and genuine safe controls.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import textwrap
from types import SimpleNamespace
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers.taint_swift_traversal import (
    file_url_read_offsets, flow_findings, swift_source_tokens, swift_validated_tokens, swift_request_source_tokens,
)
from ubs_core.taint_flow import AnalysisLimit


LOCAL = (r'target.hasPrefix("/") && !target.hasPrefix("//") && '
         r'!target.contains("\\") && !target.contains("\n") && '
         r'!target.contains("\r") && !target.contains("\t")')


class SwiftScopedFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-scoped-flow-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def check(self, source, lines=(), policy='redirect', suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        findings = flow_findings(path, source, policy)
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        self.assertEqual([item['line'] for item in findings], list(lines), findings)
        expected = 'swift.taint.request_open_redirect' if policy == 'redirect' else 'swift.taint.request_path_traversal'
        for finding in findings:
            self.assertEqual(finding['rule'], expected)
            self.assertEqual(finding['severity'], 'critical')
            self.assertEqual(finding['path'], str(path.resolve()))
            route = finding['extras']['taint_path']
            self.assertEqual(route[0]['kind'], 'source')
            self.assertEqual(route[-1]['kind'], 'sink')
            self.assertEqual(route[-1]['line'], finding['line'])
        return findings

    def test_nested_comments_preserve_newlines_and_sink_locations(self):
        comment = '/* outer\n /* inner */\n end */'
        tokens = swift_validated_tokens(comment)
        self.assertEqual([(token.value, token.start, token.end) for token in tokens],
                         [('\n', 8, 9), ('\n', 21, 22)])
        self.check('''
            func handle(req: Request) {
                /* outer comment
                   nested /* inner
                   comment */
                */
                _ = String(contentsOfFile: req.query["file"])
            }
        ''', (6,), 'path')

    def test_guard_optional_binding(self):
        self.check('''
            func handle(req: Request) -> Response {
                guard let target = req.query["next"] else { return Response.redirect(to: "/") }
                return req.redirect(to: target)
            }
        ''', (3,))

    def test_native_vision_requests_are_not_web_request_sources(self):
        sources = ('''
            import Vision
            func extract() {
                let request = VNGenerateImageFeaturePrintRequest()
                Task { consume(request) }
                _ = Data(contentsOf: bundledURL)
            }
        ''', '''
            import Vision
            final class Detector {
                #if canImport(Vision)
                let request: VNCoreMLRequest?
                #endif
                init() { request = makeRequest() }
                func extract() { Task { consume(request) } }
            }
            func prewarm(request: VNCoreMLRequest) { Task { consume(request) } }
            func load() { _ = Data(contentsOf: bundledURL) }
        ''')
        for index, source in enumerate(sources):
            with self.subTest(source=source):
                self.assertFalse(swift_request_source_tokens(swift_validated_tokens(source)))
                self.check(source, suffix=str(index))
                from ubs_core.swift_detectors.outbound_url import scan
                target = self.artifacts / ('vision-outbound-' + str(index) + '.swift')
                target.write_text(textwrap.dedent(source), encoding='utf-8')
                self.assertEqual(list(scan(SimpleNamespace(project_dir=self.artifacts, files=[target]))), [])

    def test_vision_import_does_not_exempt_actual_outbound_request(self):
        from ubs_core.swift_detectors.outbound_url import scan
        source = '''import Vision
        func load(req: Request) {
            let target = req.query["url"]
            _ = Data(contentsOf: URL(string: target)!)
        }
        '''
        target = self.artifacts / 'vision-real-outbound.swift'
        target.write_text(source, encoding='utf-8')
        self.assertTrue(list(scan(SimpleNamespace(project_dir=self.artifacts, files=[target]))))

    def test_native_request_negative_proof_keeps_unknown_shadowing_and_sources(self):
        prefix = 'import Vision\nlet request = VNGenerateImageFeaturePrintRequest()\n'
        tails = (
            'func handle(request: Request) { Task { consume(request) } }',
            'func handle(request: OtherType) { Task { consume(request) } }',
            'func handle() { let request = unknown(); Task { consume(request) } }',
            'func handle() { let work = { request in consume(request) } }',
            'func handle() { let work = { (request: OtherType) in consume(request) } }',
            'func handle() { let work = { [request = unknown()] in consume(request) } }',
            'func handle() { for (request, _) in unknown() { consume(request) } }',
            'func handle() { for request in unknown() { consume(request) } }',
            'func handle() { let (request, _) = unknown(); consume(request) }',
            'func handle() { consume(request.query["next"]) }',
            'func handle() { consume(other.request) }',
            'func handle() { consume(upload.filename) }',
            r'func handle() { consume("\(request)") }',
            'struct VNGenerateImageFeaturePrintRequest {}',
            'func VNGenerateImageFeaturePrintRequest() -> Request {}',
            'func f(VNGenerateImageFeaturePrintRequest: () -> Any) { consume(request) }',
            'class Child: Parent { func f() { let request = VNCoreMLRequest(); consume(self.request) } }',
            'func f() { provider { VNCoreMLRequest in let request = VNCoreMLRequest(); consume(request) } }',
            'func f() { provider { Vision in let request = Vision.VNCoreMLRequest(); consume(request) } }',
            'func f<VNCoreMLRequest>() { let request = VNCoreMLRequest(); consume(request) }',
            'func f() { if let request = VNCoreMLRequest() { consume(request) }; consume(request) }',
            'func f() {\n#if canImport(Vision)\nif let request = VNCoreMLRequest() { consume(request) }\n#endif\nconsume(request) }',
            'func f() { let other = 1, request = unknown(); consume(request) }',
            'class C { let other: Int, request: OtherType; func f() { consume(request) } }',
        )
        for tail in tails:
            with self.subTest(tail=tail):
                self.assertTrue(swift_request_source_tokens(swift_validated_tokens(prefix + tail)))
        source = '''import Vision
        func first() { let request = VNCoreMLRequest(); consume(request) }
        func second() { consume(request) }
        '''
        self.assertTrue(swift_request_source_tokens(swift_validated_tokens(source)))
        source = '''import Vision
        class Detector { class func extract() { consume(request); let request = VNCoreMLRequest() } }
        '''
        self.assertTrue(swift_request_source_tokens(swift_validated_tokens(source)))

    def test_process_exit_terminates_guard_and_keeps_argument_sinks(self):
        for call in ('exit(1)', 'Darwin.exit(1)', 'Glibc.exit(1)', 'fatalError()', 'Swift.preconditionFailure()'):
            with self.subTest(call=call):
                self.check(f'''
                    func handle(req: Request) {{
                        let target = req.query["next"]
                        guard {LOCAL} else {{ {call} }}
                        _ = req.redirect(to: target)
                    }}
                ''')
        self.check('''
            func handle(req: Request) {
                fatalError(String(contentsOfFile: req.query["file"]))
                _ = String(contentsOfFile: req.query["unreachable"])
            }
        ''', (2,), 'path')

    def test_shadowed_process_exit_cannot_prove_guard_termination(self):
        for declaration in ('func exit(_ status: Int) {}', 'let exit = callback'):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, 'guard.*does not exit'):
                self.check('''
                    %s
                    func handle(req: Request) {
                        let target = req.query["next"]
                        guard allowed(target) else { exit(1) }
                        _ = req.redirect(to: target)
                    }
                ''' % declaration)
        with self.assertRaisesRegex(ValueError, 'guard.*does not exit'):
            self.check('''
                class Handler: ExternalBase {
                    func handle(req: Request) {
                        guard allowed(req) else { exit(1) }
                        _ = req.redirect(to: req.query["next"])
                    }
                }
            ''')

    def test_tuple_loop_propagates_each_component_to_sinks(self):
        for policy, sink in (('path', 'String(contentsOfFile: target)'),
                             ('redirect', 'req.redirect(to: target)')):
            for value in ('(req.query["next"], "safe")', '("safe", req.query["next"])'):
                with self.subTest(policy=policy, value=value):
                    self.check('''
                        func handle(req: Request) {
                            for (target, other) in [%s] {
                                _ = %s
                            }
                        }
                    ''' % (value, sink), (3,), policy, str(len(value)))

    def test_nested_tuple_loop_and_wildcards_preserve_sources(self):
        self.check('''
            func handle(req: Request) {
                for (_, (target, _)) in [(0, (req.query["next"], 1))] {
                    _ = req.redirect(to: target)
                }
            }
        ''', (3,))

    def test_tuple_loop_preserves_request_object_shape(self):
        self.check('''
            func handle(req: Request) {
                for (input, _) in [(req, 0)] {
                    _ = input.redirect(to: input.query["next"])
                }
            }
        ''', (3,))

    def test_request_collection_iteration_is_an_untrusted_source(self):
        for sequence in ('req.headers', 'req.query', 'req.parameters', 'req.params', 'req.content'):
            with self.subTest(sequence=sequence):
                self.check('''
                    func handle(req: Request) {
                        for (_, target) in %s {
                            _ = req.redirect(to: target)
                        }
                    }
                ''' % sequence, (3,), suffix=sequence.rsplit('.', 1)[-1])
        self.check('''
            func handle(req: Request) {
                let headers = req.headers
                for target in headers {
                    _ = String(contentsOfFile: target)
                }
            }
        ''', (4,), 'path', 'scalar-alias')

    def test_request_iteration_where_validation_stays_binding_local(self):
        self.check(f'''
            func handle(req: Request) {{
                for (other, target) in req.headers where {LOCAL} {{
                    _ = req.redirect(to: target)
                    _ = req.redirect(to: other)
                }}
            }}
        ''', (4,))

    def test_tuple_loop_shadowing_does_not_leak(self):
        self.check('''
            func handle(req: Request) {
                let target = req.query["next"]
                for (target, _) in [("/fixed", 0)] {
                    _ = req.redirect(to: target)
                }
                _ = req.redirect(to: target)
            }
        ''', (6,))

    def test_tuple_loop_reads_sequence_before_binding_names(self):
        self.check('''
            func handle(req: Request) {
                let target = [(req.query["next"], 0)]
                for (target, _) in target {
                    _ = req.redirect(to: target)
                }
            }
        ''', (4,))

    def test_tuple_loop_break_continue_and_outer_write(self):
        self.check('''
            func handle(req: Request) {
                var output = "/fixed"
                for (target, _) in [(req.query["next"], 0)] {
                    if flag { continue }
                    output = target
                    break
                    _ = req.redirect(to: target)
                }
                _ = req.redirect(to: output)
            }
        ''', (9,))

    def test_tuple_loop_where_validation_is_binding_local(self):
        self.check(f'''
            func handle(req: Request) {{
                for (target, other) in [(req.query["next"] ?? "/", "/fixed")] where {LOCAL} {{
                    _ = req.redirect(to: target)
                    _ = req.redirect(to: other)
                }}
            }}
        ''', (4,))

    def test_tuple_loop_all_discard_still_evaluates_sequence(self):
        self.check('''
            func handle(req: Request) {
                for (_, _) in [(req.redirect(to: req.query["next"]), 0)] {}
            }
        ''', (2,))

    def test_tuple_loop_clean_and_zero_iteration_path(self):
        self.check('''
            func handle(req: Request) {
                var output = req.query["next"]
                for (a, (b, _)) in [("/a", ("/b", 0))] {
                    _ = req.redirect(to: a)
                    _ = req.redirect(to: b)
                    output = "/fixed"
                }
                _ = req.redirect(to: output)
            }
        ''', (8,))

    def test_unsupported_loop_patterns_remain_incomplete(self):
        for pattern in ('case let (a, b)', '(a, a)', '(a, b?)', '(a, b) as Pair'):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, 'iteration binding.*incomplete'):
                self.check('func handle(req: Request) { for %s in values { _ = req.redirect(to: req.query["next"]) } }' % pattern)

    def test_append_contents_label_is_not_a_file_read_obligation(self):
        for policy in ('path', 'redirect'):
            self.check('''
                func detect() {
                    let values = requests.map { request in request.result }
                    for (evidence, box) in values { record(evidence, box) }
                    output.append(contentsOf: values)
                }
            ''', policy=policy, suffix=policy)

    def test_append_does_not_hide_actual_request_or_file_read(self):
        self.check('''
            func handle(req: Request) {
                output.append(contentsOf: ["fixed"])
                _ = String(contentsOfFile: req.query["path"])
            }
        ''', (3,), 'path')
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                func handle(req: Request) {
                    let work = Task { consume(req.query["path"]) }
                    output.append(contentsOf: ["fixed"])
                }
            ''')

    def test_if_optional_binding(self):
        self.check('''
            func handle(req: Request) -> Response {
                if let target = req.query["next"] {
                    return req.redirect(to: target)
                }
                return req.redirect(to: "/")
            }
        ''', (3,))

    def test_optional_same_name_reads_the_outer_binding(self):
        self.check('''
            func handle(req: Request) -> Response {
                let target = req.query["next"]
                if let target = target { return req.redirect(to: target) }
                return req.redirect(to: "/")
            }
        ''', (3,))

    def test_guard_shorthand_optional_binding(self):
        self.check('''
            func handle(req: Request) -> Response {
                let target = req.query["next"]
                guard let target else { return req.redirect(to: "/") }
                return req.redirect(to: target)
            }
        ''', (4,))

    def test_genuine_named_validator(self):
        self.check(f'''
            func validate(_ target: String) -> String {{
                guard {LOCAL} else {{ return "/home" }}
                return target
            }}
            func handle(req: Request) -> Response {{
                return req.redirect(to: validate(req.query["next"] ?? "/"))
            }}
        ''')

    def test_overload_labels_select_the_actual_argument(self):
        self.check('''
            func target(raw value: String) -> String { return value }
            func target(ignoring value: String) -> String { return "/home" }
            func handle(req: Request) -> Response {
                return req.redirect(to: target(ignoring: req.query["next"] ?? "/"))
            }
        ''')

    def test_overload_unsafe_selected_label(self):
        self.check('''
            func target(raw value: String) -> String { return value }
            func target(ignoring value: String) -> String { return "/home" }
            func handle(req: Request) -> Response {
                return req.redirect(to: target(raw: req.query["next"] ?? "/"))
            }
        ''', (4,))

    def test_static_helper(self):
        self.check('''
            struct Router {
                static func chosen(_ value: String) -> String { return value }
            }
            func handle(req: Request) -> Response {
                return req.redirect(to: Router.chosen(req.query["next"] ?? "/"))
            }
        ''', (5,))

    def test_instance_helper(self):
        self.check('''
            struct Router {
                func chosen(_ value: String) -> String { return value }
            }
            func handle(req: Request) -> Response {
                let router = Router()
                return req.redirect(to: router.chosen(req.query["next"] ?? "/"))
            }
        ''', (6,))

    def test_function_value_alias(self):
        self.check('''
            func identity(_ value: String) -> String { return value }
            func handle(req: Request) -> Response {
                let route = identity
                return req.redirect(to: route(req.query["next"] ?? "/"))
            }
        ''', (4,))

    def test_recursive_helper_reaches_fixed_point(self):
        self.check('''
            func chosen(_ value: String, flag: Bool) -> String {
                if flag { return chosen(value, flag: false) }
                return value
            }
            func handle(req: Request) -> Response {
                return req.redirect(to: chosen(req.query["next"] ?? "/", flag: true))
            }
        ''', (6,))

    def test_branch_shadow_does_not_kill_outer(self):
        self.check('''
            func handle(req: Request, flag: Bool) -> Response {
                let target = req.query["next"] ?? "/"
                if flag { let target = "/home" }
                return req.redirect(to: target)
            }
        ''', (4,))

    def test_uninitialized_inner_declaration_does_not_kill_outer(self):
        self.check('''
            func handle(req: Request, flag: Bool) -> Response {
                let target = req.query["next"] ?? "/"
                if flag {
                    var target: String
                    target = "/home"
                }
                return req.redirect(to: target)
            }
        ''', (7,))

    def test_loop_reassignment_joins_zero_iterations(self):
        self.check('''
            func handle(req: Request, flag: Bool) -> Response {
                var target = req.query["next"] ?? "/"
                while flag { target = "/home" }
                return req.redirect(to: target)
            }
        ''', (4,))

    def test_loop_source_reaches_sink(self):
        self.check('''
            func handle(req: Request, flag: Bool) -> Response {
                var target = "/home"
                while flag { target = req.query["next"] ?? "/" }
                return req.redirect(to: target)
            }
        ''', (4,))

    def test_inout_helper_mutation(self):
        self.check('''
            func choose(_ target: inout String, _ incoming: String) { target = incoming }
            func handle(req: Request) -> Response {
                var target = "/home"
                choose(&target, req.query["next"] ?? "/")
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_inout_helper_can_kill_request_data(self):
        self.check('''
            func clear(_ target: inout String) { target = "/home" }
            func handle(req: Request) -> Response {
                var target = req.query["next"] ?? "/"
                clear(&target)
                return req.redirect(to: target)
            }
        ''')

    def test_string_mutation_invalidates_guard(self):
        self.check(f'''
            func handle(req: Request) -> Response {{
                var target = req.query["next"] ?? "/"
                guard {LOCAL} else {{ return req.redirect(to: "/") }}
                target.append(req.query["suffix"] ?? "")
                return req.redirect(to: target)
            }}
        ''', (5,))

    def test_string_value_copy_survives_other_binding_mutation(self):
        self.check(f'''
            func handle(req: Request) -> Response {{
                var target = req.query["next"] ?? "/"
                guard {LOCAL} else {{ return req.redirect(to: "/") }}
                let checked = target
                target.append(req.query["suffix"] ?? "")
                return req.redirect(to: checked)
            }}
        ''')

    def test_remove_first_invalidates_local_guard(self):
        self.check(f'''
            func handle(req: Request) -> Response {{
                var target = req.query["next"] ?? "/"
                guard {LOCAL} else {{ return req.redirect(to: "/") }}
                target.removeFirst()
                return req.redirect(to: target)
            }}
        ''', (5,))

    def test_ternary_true_arm_preserves_source(self):
        self.check('''
            func handle(req: Request, flag: Bool) -> Response {
                let incoming = req.query["next"] ?? "/"
                let target = flag ? incoming : "/home"
                return req.redirect(to: target)
            }
        ''', (4,))

    def test_ternary_false_arm_preserves_source(self):
        self.check('''
            func handle(req: Request, flag: Bool) -> Response {
                let incoming = req.query["next"] ?? "/"
                let target = flag ? "/home" : incoming
                return req.redirect(to: target)
            }
        ''', (4,))

    def test_ternary_mutations_join_alternative_states(self):
        self.check('''
            func choose(_ target: inout String, _ value: String) -> Bool { target = value; return true }
            func handle(req: Request, flag: Bool) -> Response {
                var target = "/home"
                _ = flag ? choose(&target, req.query["next"] ?? "/") : choose(&target, "/home")
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_short_circuit_and_does_not_guarantee_helper_mutation(self):
        self.check('''
            func clear(_ target: inout String) -> Bool { target = "/home"; return true }
            func handle(req: Request, flag: Bool) -> Response {
                var target = req.query["next"] ?? "/"
                _ = flag && clear(&target)
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_short_circuit_or_does_not_guarantee_helper_mutation(self):
        self.check('''
            func clear(_ target: inout String) -> Bool { target = "/home"; return true }
            func handle(req: Request, flag: Bool) -> Response {
                var target = req.query["next"] ?? "/"
                _ = flag || clear(&target)
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_coalescing_does_not_guarantee_helper_mutation(self):
        self.check('''
            func clear(_ target: inout String) -> String { target = "/home"; return "/" }
            func handle(req: Request, present: String?) -> Response {
                var target = req.query["next"] ?? "/"
                _ = present ?? clear(&target)
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_source_returning_local_redirect_helper(self):
        self.check('''
            func redirect(_ request: Request) -> String {
                return request.query["next"] ?? "/"
            }
            func handle(req: Request) -> Response {
                return req.redirect(to: redirect(req))
            }
        ''', (5,))

    def test_redirect_label_does_not_erase_selected_helper(self):
        self.check('''
            func redirect(to request: Request) -> String {
                return request.query["next"] ?? "/"
            }
            func handle(req: Request) -> Response {
                return req.redirect(to: redirect(to: req))
            }
        ''', (5,))

    def test_unused_redirect_label_does_not_erase_request_argument(self):
        self.check('''
            func redirect(to ignored: String, request: Request) -> String {
                return request.query["next"] ?? "/"
            }
            func handle(req: Request) -> Response {
                return req.redirect(to: redirect(to: "/", request: req))
            }
        ''', (5,))

    def test_source_returning_local_file_helper(self):
        self.check('''
            func file(_ request: Request) -> String {
                return request.query["file"] ?? "index.txt"
            }
            func handle(req: Request) throws -> String {
                return try String(contentsOfFile: file(req))
            }
        ''', (5,), 'path')

    def test_selected_redirect_wrapper_reports_actual_sink_and_call(self):
        rows = self.check('''
            func redirect(to value: String) -> Response {
                return Response.redirect(to: value)
            }
            func handle(req: Request) -> Response {
                let target = req.query["next"] ?? "/"
                return redirect(to: target)
            }
        ''', (2,))
        self.assertEqual([(step['kind'], step['line']) for step in rows[0]['extras']['taint_path']],
                         [('source', 5), ('assign', 5), ('call', 6), ('sink', 2)])

    def test_attributed_function_keeps_executable_body(self):
        self.check('''
            @MainActor func handle(req: Request) -> Response {
                return req.redirect(to: req.query["next"] ?? "/")
            }
        ''', (2,))

    def test_array_literal_index_keeps_source(self):
        self.check('''
            func handle(req: Request) -> Response {
                return req.redirect(to: [req.query["next"] ?? "/"][0])
            }
        ''', (2,))

    def test_array_literal_first_keeps_source(self):
        self.check('''
            func handle(req: Request) -> Response {
                return req.redirect(to: [req.query["next"] ?? "/"].first!)
            }
        ''', (2,))

    def test_dictionary_literal_subscript_keeps_source(self):
        self.check('''
            func handle(req: Request) -> Response {
                return req.redirect(to: ["target": req.query["next"] ?? "/"]["target"]!)
            }
        ''', (2,))

    def test_typed_scheme_and_host_serialization(self):
        self.check('''
            func handle(req: Request) -> Response {
                let raw = req.query["next"] ?? "/"
                guard let url = URL(string: raw), url.scheme == "https", url.host == "app.example.com" else {
                    return req.redirect(to: "/")
                }
                return req.redirect(to: url.absoluteString)
            }
        ''')

    def test_checked_url_does_not_prove_raw_input(self):
        self.check('''
            func handle(req: Request) -> Response {
                let raw = req.query["next"] ?? "/"
                guard let url = URL(string: raw), url.scheme == "https", url.host == "app.example.com" else {
                    return req.redirect(to: "/")
                }
                return req.redirect(to: raw)
            }
        ''', (6,))

    def test_optional_host_immutable_allowlist(self):
        self.check('''
            let allowed = Set(["app.example.com", "accounts.example.com"])
            func handle(req: Request) -> Response {
                let raw = req.query["next"] ?? "/"
                guard let url = URL(string: raw), url.scheme == "https", let host = url.host, allowed.contains(host) else {
                    return req.redirect(to: "/")
                }
                return req.redirect(to: url.absoluteString)
            }
        ''')

    def test_undeclared_allowlist_is_no_proof(self):
        self.check('''
            func handle(req: Request) -> Response {
                let raw = req.query["next"] ?? "/"
                guard let url = URL(string: raw), url.scheme == "https", let host = url.host, allowed.contains(host) else {
                    return req.redirect(to: "/")
                }
                return req.redirect(to: url.absoluteString)
            }
        ''', (6,))

    def test_url_rebinding_invalidates_extracted_host(self):
        self.check('''
            func handle(req: Request) -> Response {
                guard var url = URL(string: req.query["first"] ?? ""), let oldHost = url.host else { return req.redirect(to: "/") }
                url = URL(string: req.query["next"] ?? "")!
                guard url.scheme == "https", oldHost == "app.example.com" else { return req.redirect(to: "/") }
                return req.redirect(to: url.absoluteString)
            }
        ''', (5,))

    def test_url_component_mutation_invalidates_proof(self):
        self.check('''
            func handle(req: Request) -> Response {
                guard var url = URLComponents(string: req.query["next"] ?? ""), url.scheme == "https", url.host == "app.example.com" else { return req.redirect(to: "/") }
                url.host = req.query["host"] ?? "evil.example"
                return req.redirect(to: url.string ?? "/")
            }
        ''', (4,))

    def test_string_extension_does_not_fabricate_url_type(self):
        self.check('''
            extension String { var host: String { "app.example.com" } }
            func handle(req: Request) -> Response {
                let target = req.query["next"] ?? "/"
                guard target.host == "app.example.com" else { return req.redirect(to: "/") }
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_shadowed_foundation_namespace_does_not_validate_url(self):
        self.check('''
            enum Foundation {
                struct URL {
                    let raw: String
                    init?(string: String) { raw = string }
                    var scheme: String? { "https" }
                    var host: String? { "app.example.com" }
                    var absoluteString: String { raw }
                }
            }
            func handle(req: Request) -> Response {
                guard let url = Foundation.URL(string: req.query["next"] ?? "/"), url.scheme == "https", url.host == "app.example.com" else { return req.redirect(to: "/") }
                return req.redirect(to: url.absoluteString)
            }
        ''', (12,))

    def test_unknown_url_property_drops_checked_identity(self):
        self.check('''
            import Foundation
            extension URL {
                var fragmentTarget: Foundation.URL { Foundation.URL(string: self.fragment ?? "")! }
            }
            func handle(req: Request) -> Response {
                guard let url = Foundation.URL(string: req.query["next"] ?? "/"), url.scheme == "https", url.host == "app.example.com" else { return req.redirect(to: "/") }
                return req.redirect(to: url.fragmentTarget.absoluteString)
            }
        ''', (7,))

    def test_qualified_string_extension_drops_local_guard(self):
        self.check(f'''
            extension Swift.String {{
                var rawRedirect: String {{ String(self.dropFirst()) }}
            }}
            func handle(req: Request) -> Response {{
                let target = req.query["next"] ?? "/"
                guard {LOCAL} else {{ return req.redirect(to: "/") }}
                return req.redirect(to: target.rawRedirect)
            }}
        ''', (7,))

    def test_multiline_interpolation(self):
        self.check('''
            func handle(req: Request) -> Response {
                let target = """
                https://example.com/\\(req.query["next"] ?? "")
                """
                return req.redirect(to: target)
            }
        ''', (5,))

    def test_raw_string_interpolation(self):
        self.check(r'''
            func handle(req: Request) -> Response {
                let target = #"https://example.com/\#(req.query["next"] ?? "")"#
                return req.redirect(to: target)
            }
        ''', (3,))

    def test_request_byte_contents_are_not_the_destination(self):
        self.check('''
            func handle(req: Request) throws {
                let content = req.query["text"] ?? ""
                try Data(content.utf8).write(to: URL(fileURLWithPath: "/srv/files/fixed.txt"))
            }
        ''', policy='path')

    def test_native_file_reader_offsets_distinguish_same_line_reads(self):
        source = textwrap.dedent('''
            import Foundation
            func handle(req: Request) throws {
                let file = URL(fileURLWithPath: "/srv/fixed.txt")
                let remote = URL(string: req.query["url"] ?? "")!
                _ = try Foundation.String(contentsOf: file); _ = try Data(contentsOf: remote)
            }
        ''').lstrip('\n')
        self.assertEqual(file_url_read_offsets(Path('offsets.swift'), source),
                         frozenset({source.index('String(contentsOf:')}))

    def test_source_less_native_file_reader_still_has_identity(self):
        source = ('let file = URL(fileURLWithPath: "/srv/fixed.txt")\n'
                  '_ = try Data(contentsOf: file)\n')
        self.assertEqual(file_url_read_offsets(Path('source-less.swift'), source),
                         frozenset({source.index('Data(contentsOf:')}))

    def test_mixed_file_and_remote_reader_has_no_file_only_exemption(self):
        source = textwrap.dedent('''
            func handle(req: Request, flag: Bool) throws {
                let file = URL(fileURLWithPath: "/srv/fixed.txt")
                let remote = URL(string: req.query["url"] ?? "")!
                let chosen = flag ? file : remote
                _ = try String(contentsOf: chosen)
            }
        ''')
        self.assertEqual(file_url_read_offsets(Path('mixed.swift'), source), frozenset())

    def test_appending_component_cannot_turn_mixed_urls_into_file_urls(self):
        source = textwrap.dedent('''
            func handle(req: Request, flag: Bool) throws {
                let file = URL(fileURLWithPath: "/srv/fixed.txt")
                let remote = URL(string: req.query["url"] ?? "")!
                let chosen = (flag ? file : remote).appendingPathComponent(req.query["path"] ?? "")
                _ = try String(contentsOf: chosen)
            }
        ''')
        self.assertEqual(file_url_read_offsets(Path('mixed-component.swift'), source), frozenset())

    def test_every_selected_reader_context_must_be_a_file_url(self):
        source = textwrap.dedent('''
            func read(_ url: URL) throws -> String { try String(contentsOf: url) }
            func handle(req: Request) throws {
                _ = try read(URL(fileURLWithPath: "/srv/fixed.txt"))
                _ = try read(URL(string: req.query["url"] ?? "")!)
            }
        ''')
        self.assertEqual(file_url_read_offsets(Path('contexts.swift'), source), frozenset())

    def test_selected_helper_file_reader_reaches_final_identity(self):
        source = textwrap.dedent('''
            func chosen() -> URL { URL(fileURLWithPath: "/srv/fixed.txt") }
            func handle(req: Request) throws {
                _ = try String(contentsOf: chosen())
            }
        ''')
        self.assertEqual(file_url_read_offsets(Path('helper.swift'), source),
                         frozenset({source.index('String(contentsOf:')}))

    def test_custom_string_constructor_has_no_native_file_exemption(self):
        source = textwrap.dedent('''
            struct String { init(contentsOf url: Foundation.URL) {} }
            func handle(req: Request) {
                _ = String(contentsOf: Foundation.URL(fileURLWithPath: "/srv/fixed.txt"))
            }
        ''')
        self.assertEqual(file_url_read_offsets(Path('custom.swift'), source), frozenset())

    def test_url_locality_does_not_prove_file_containment(self):
        self.check(f'''
            func handle(req: Request) throws -> String {{
                let target = req.query["path"] ?? "/"
                guard {LOCAL} else {{ return "blocked" }}
                return try String(contentsOfFile: target)
            }}
        ''', (4,), 'path')

    def test_untrusted_root_cannot_prove_containment(self):
        self.check('''
            func handle(req: Request) throws -> String {
                let root = URL(fileURLWithPath: req.query["root"] ?? "").standardizedFileURL
                let target = root.appendingPathComponent(req.query["path"] ?? "").standardizedFileURL
                guard target.path.hasPrefix(root.path + "/") else { return "blocked" }
                return try String(contentsOf: target)
            }
        ''', (5,), 'path')

    def test_basename_is_only_a_file_leaf_proof(self):
        self.check('''
            func handle(req: Request) throws {
                let name = URL(fileURLWithPath: req.query["path"] ?? "").lastPathComponent
                _ = try String(contentsOfFile: name)
                try FileManager.default.removeItem(atPath: name)
            }
        ''', (4,), 'path')

    def test_guard_else_must_exit(self):
        with self.assertRaisesRegex(ValueError, 'guard else.*incomplete'):
            self.check(f'''
                func handle(req: Request) -> Response {{
                    let target = req.query["next"] ?? "/"
                    guard {LOCAL} else {{ print("blocked") }}
                    return req.redirect(to: target)
                }}
            ''')

    def test_escaping_closure_is_explicitly_incomplete(self):
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                func handle(req: Request) {
                    let target = req.query["next"] ?? "/"
                    DispatchQueue.main.async { Response.redirect(to: target) }
                }
            ''')

    def test_nested_tainted_capture_is_explicitly_incomplete(self):
        with self.assertRaisesRegex(ValueError, 'nested capture.*incomplete'):
            self.check('''
                func handle(req: Request) -> Response {
                    let destination = req.query["next"] ?? "/"
                    func captured() -> String { return destination }
                    return req.redirect(to: captured())
                }
            ''')

    def test_typealias_url_requires_object_field_analysis(self):
        with self.assertRaisesRegex(ValueError, 'object initialization.*incomplete'):
            self.check('''
                struct UserURL {
                    let raw: String
                    init?(string: String) { raw = string }
                    var scheme: String? { "https" }
                    var host: String? { "app.example.com" }
                    var absoluteString: String { raw }
                }
                typealias URL = UserURL
                func handle(req: Request) -> Response {
                    guard let url = URL(string: req.query["next"] ?? "/"), url.scheme == "https", url.host == "app.example.com" else { return req.redirect(to: "/") }
                    return req.redirect(to: url.absoluteString)
                }
            ''')

    def test_nonfinal_receiver_requires_dynamic_dispatch_analysis(self):
        with self.assertRaisesRegex(ValueError, 'unresolved receiver dispatch.*incomplete'):
            self.check('''
                class Router {
                    func chosen(_ value: String) -> String { "/home" }
                }
                class UnsafeRouter: Router {
                    override func chosen(_ value: String) -> String { value }
                }
                func handle(req: Request, router: Router) -> Response {
                    return req.redirect(to: router.chosen(req.query["next"] ?? "/"))
                }
            ''')

    def test_selected_foreach_callback_is_explicitly_incomplete(self):
        with self.assertRaisesRegex(ValueError, 'callback.*incomplete'):
            self.check('''
                func send(_ target: String) {
                    _ = Response.redirect(to: target)
                }
                func handle(req: Request) {
                    let targets = [req.query["next"] ?? "/"]
                    targets.forEach(send)
                }
            ''')

    def test_global_request_mutation_is_explicitly_incomplete(self):
        with self.assertRaisesRegex(ValueError, 'global mutation.*incomplete'):
            self.check('''
                var allowed = Set(["app.example.com"])
                func configure(req: Request) { allowed.insert(req.query["host"] ?? "") }
            ''')

    def test_malformed_lexical_input_is_not_clean(self):
        for source in ('func handle() {', 'let text = "unterminated', '/* nested /* comment */'):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'incomplete'):
                self.check(source)

    def test_unrelated_client_task_and_result_builder_have_no_request_obligation(self):
        # Real frontend syntax, no modeled incoming-request operation or sink.
        # The variable name is deliberately a conservative source sentinel.
        for policy in ('path', 'redirect'):
            with self.subTest(policy=policy):
                self.check('''
                    struct Panel {
                        func section<Content>(@ViewBuilder content: () -> Content) -> Content { content() }
                        func refresh() async {
                            let request = UUID()
                            let work = Task { await fetch() }
                            await withTaskCancellationHandler {
                                await work.value
                            } onCancel: { work.cancel() }
                        }
                    }
                ''', policy=policy, suffix=policy)

    def test_unrelated_parameter_attribute_does_not_hide_a_real_sink(self):
        for attribute in ('@ViewBuilder', '@UI.ViewBuilder', '@Builder(mode: .plain)'):
            with self.subTest(attribute=attribute):
                self.check('''
                    func panel<Content>(%s content: () -> Content) -> Content { content() }
                    func handle(req: Request) -> Response {
                        return req.redirect(to: req.query["next"] ?? "/")
                    }
                ''' % attribute, (3,), suffix=str(len(attribute)))

    def test_selected_parameter_transform_is_not_assumed_transparent(self):
        for source in ('''
            func transform(@Wrapped value: String) -> String { value }
            func handle(req: Request) -> Response {
                return req.redirect(to: transform(value: req.query["next"] ?? "/"))
            }
        ''', '''
            func handle(@Wrapped input: Request) -> Response {
                return input.redirect(to: input.query["next"] ?? "/")
            }
        '''):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'attributed parameters.*incomplete'):
                self.check(source)

    def test_actual_source_without_sink_remains_conservatively_incomplete(self):
        # Keep the old fail-closed boundary for actual incoming request state.
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                func handle(input: Request) {
                    let work = Task { consume(input.query["next"]) }
                }
            ''')

    def test_file_export_argument_labels_are_not_incoming_sources(self):
        for label in ('filename', 'fileName', 'originalFilename', 'originalFileName'):
            for arguments in (f'{label}: name, data: data', f'data: data, {label}\n/* label */ : name'):
                for policy in ('path', 'redirect'):
                    with self.subTest(label=label, arguments=arguments, policy=policy):
                        self.check('''
                            func export() async throws -> IntentFile {
                                let snapshot = try await MainActor.run { try latestSnapshot() }
                                let data = encode(snapshot)
                                let name = exportName(snapshot)
                                return IntentFile(%s)
                            }
                        ''' % arguments, policy=policy,
                                   suffix=f'-{label}-{len(arguments)}-{policy}')

    def test_filename_labels_do_not_hide_real_member_sources(self):
        for label in ('filename', 'fileName', 'originalFilename', 'originalFileName'):
            for policy, sink in (('path', 'String(contentsOfFile: target)'),
                                 ('redirect', 'Response.redirect(to: target)')):
                with self.subTest(label=label, policy=policy):
                    self.check('''
                        func forward(filename target: String) {
                            %s
                        }
                        func handle(upload: Upload) {
                            forward(filename: upload.%s)
                        }
                    ''' % (sink, label), (2,), policy=policy, suffix=f'-{label}-{policy}')

    def test_request_argument_labels_are_not_incoming_sources(self):
        for label in ('req', 'request'):
            for arguments in (f'{label}: draft', f'id: draftID, {label}\n/* label */ : draft'):
                for policy in ('path', 'redirect'):
                    with self.subTest(label=label, arguments=arguments, policy=policy):
                        self.check('''
                            struct Editor {
                                var saved: Draft { Draft(%s) }
                                var body: some View {
                                    ForEach(files) { file in Text(file.name) }
                                }
                                func save() { Task { persist(Draft(%s)) } }
                            }
                        ''' % (arguments, arguments), policy=policy,
                                   suffix=f'-{label}-{len(arguments)}-{policy}')

    def test_request_label_exclusion_preserves_value_witnesses(self):
        for name in ('req', 'request'):
            for source in (f'output([{name}: value])', f'output(flag ? {name} : value)',
                           f'output(request: {name})', f'output(request: upload.{name})',
                           f'output(request: {name}?.query["next"])',
                           'output(request: "copy-\\(' + name + '.query["name"])")',
                           f'func handle({name}: Request) {{}}'):
                with self.subTest(source=source):
                    self.assertTrue(swift_source_tokens(swift_validated_tokens(source)))
            for source in (f'output({name}: draft)', f'output(id: key, {name} /* label */\n: draft)',
                           'print("\\(output(' + name + ': draft))")'):
                with self.subTest(source=source):
                    self.assertFalse(swift_source_tokens(iter(swift_validated_tokens(source))))

    def test_request_labels_do_not_hide_real_captures_or_sinks(self):
        for label in ('req', 'request'):
            for policy, sink in (('path', 'String(contentsOfFile: target)'),
                                 ('redirect', 'Response.redirect(to: target)')):
                with self.subTest(label=label, policy=policy):
                    self.check('''
                        func forward(%s target: String) {
                            %s
                        }
                        func handle(req: Request) {
                            forward(%s: req.query["target"])
                        }
                    ''' % (label, sink, label), (2,), policy=policy, suffix=f'-{label}-{policy}')
                    with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
                        self.check('''
                            func handle(req: Request) {
                                Task { forward(%s: req.query["target"]) }
                            }
                        ''' % label, policy=policy, suffix=f'-capture-{label}-{policy}')

    def test_actual_filename_capture_remains_explicitly_incomplete(self):
        sources = (
            'Task { IntentFile(filename: upload.filename) }',
            r'Task { IntentFile(filename: "copy-\(upload.fileName)") }',
            'Task { IntentFile(filename: req.query["name"]) }',
        )
        for index, expression in enumerate(sources):
            for policy in ('path', 'redirect'):
                with self.subTest(expression=expression, policy=policy), self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
                    self.check('func handle(upload: Upload) { %s }' % expression,
                               policy=policy, suffix=f'-{index}-{policy}')

    def test_filename_source_witness_requires_proven_label_position(self):
        # A colon alone is not evidence of an argument label: dictionary keys,
        # ternary values and member values must stay conservative witnesses.
        for source in ('output([filename: value])', 'output(flag ? filename : value)',
                       'output(filename: upload.filename)', 'output(filename: upload?.filename)',
                       r'output(filename: "copy-\(upload.filename)")',
                       'output(filename: req.query["name"])'):
            with self.subTest(source=source):
                self.assertTrue(swift_source_tokens(swift_validated_tokens(source)))
        for source in ('output(filename: "safe.csv")',
                       'output(data: bytes, filename /* label */\n: "safe.csv")',
                       r'print("\(output(filename: "safe.csv"))")'):
            with self.subTest(source=source):
                # The function also receives a generator when selecting bodies.
                self.assertFalse(swift_source_tokens(iter(swift_validated_tokens(source))))

    def test_sink_hidden_in_interpolation_or_alias_is_not_filtered_out(self):
        sources = (r'''
            func handle(req: Request) -> String {
                return "\(Response.redirect(to: req.query["next"] ?? "/"))"
            }
        ''', '''
            func handle(req: Request) -> Response {
                let input = req
                let target = input.query["next"] ?? "/"
                return dispatch(target)
            }
            func dispatch(_ target: String) -> Response {
                return Response.redirect(to: target)
            }
        ''')
        for index, (source, lines) in enumerate(zip(sources, ((2,), (7,)))):
            with self.subTest(index=index):
                self.check(source, lines, suffix=str(index))

    def test_nested_literal_interpolation_still_activates_relevant_failure(self):
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check(r'''
                func handle(req: Request) -> String {
                    return "outer \("inner \(Task { Response.redirect(to: req.query["next"] ?? "/") })")"
                }
            ''')

    def test_api_write_without_destination_is_not_a_file_sink_obligation(self):
        for index, call in enumerate((
            'panel.write("/api/billing", body: request)',
            'panel?.write("/api/billing", body: ["to": request])',
            'panel.write(body: wrap(to: request))',
            'panel.write("to", body: request)',
            'panel.write(\n "/api/billing",\n body: request\n)',
        )):
            for policy in ('path', 'redirect'):
                with self.subTest(call=call, policy=policy):
                    self.check('func submit() { let request = UUID(); Task { %s } }' % call,
                               policy=policy, suffix=str(index) + policy)

    def test_api_write_keeps_real_nested_and_unknown_file_obligations(self):
        for index, call in enumerate((
            'body.write(to: request)',
            'body.write(`to`: request)',
            'panel.write("/api", body: body.write(to: request))',
            'panel.write("/api", body: { body.write(to: request) })',
            r'panel.write("/api", body: "value-\(body.write(to: request))")',
            'let writer = body.write; writer(to: request)',
            'panel.write("/api", body: request.query["path"])',
            'panel.write("/api", body: request); readFile(path: request)',
        )):
            for policy in ('path', 'redirect'):
                with self.subTest(call=call, policy=policy), self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
                    self.check('func submit() { let request = UUID(); Task { %s } }' % call,
                               policy=policy, suffix=str(index) + policy)

    def test_file_write_destination_still_reports_request_path(self):
        self.check('''
            func submit(req: Request) {
                try body.write(to: URL(fileURLWithPath: req.query["path"] ?? ""))
            }
        ''', (2,), policy='path')

    def test_unrelated_unsupported_closure_with_a_sink_is_still_incomplete(self):
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                func load() {
                    let request = UUID()
                    Task { consume(request) }
                }
                func output(_ target: String) -> Response {
                    return Response.redirect(to: target)
                }
            ''')

    def test_all_modeled_sink_families_keep_unknown_capture_fail_closed(self):
        calls = (
            'Response.redirect(to: request)',
            'HTTPResponse(headers: ["Location": request])',
            'HTTPHeaders([("Location", request)])',
            'headers.add(name: "Location", value: request)',
            'headers.replaceOrAdd(name: .location, value: request)',
            'headers["Location"] = request',
            'String(contentsOf: request)', 'Data(contentsOfFile: request)',
            'FileHandle(forReadingFrom: request)',
            'FileManager.default.removeItem(atPath: request)',
            'sendFile(request)', 'streamFile(at: request)', 'readFile(path: request)',
            'serveFile(request)', 'writeFile(request)', 'file(request)', 'body.write(to: request)',
        )
        for index, call in enumerate(calls):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
                self.check('func work() { let request = UUID(); Task { %s } }' % call,
                           suffix=str(index))

    def test_collection_closure_elements_reach_real_sink_sites(self):
        for callback in ('map', 'compactMap', 'flatMap', 'filter', 'forEach', 'contains', 'first'):
            with self.subTest(callback=callback):
                self.check('''
                    func handle(req: Request) {
                        _ = req.query.%s { element in
                            return String(contentsOfFile: element)
                        }
                    }
                ''' % callback, (3,), 'path', callback)

    def test_collection_closure_return_and_capture_flow(self):
        self.check('''
            func handle(req: Request) {
                let targets = [req.query["path"]].map { $0 }
                _ = String(contentsOfFile: targets.first)
            }
        ''', (3,), 'path')
        self.check('''
            func handle(req: Request) {
                let destination = req.query["path"]
                _ = [1].map { unused in
                    String(contentsOfFile: destination)
                }
            }
        ''', (4,), 'path', 'capture')

    def test_collection_closure_bindings_shadow_and_do_not_leak(self):
        self.check('''
            func handle(req: Request) {
                let target = req.query["path"]
                _ = ["/fixed"].map { target in String(contentsOfFile: target) }
                _ = String(contentsOfFile: target)
            }
        ''', (4,), 'path')
        self.check('''
            func handle(req: Request) {
                let target = "/fixed"
                _ = [req.query["path"]].map { target in String(contentsOfFile: target) }
                _ = String(contentsOfFile: target)
            }
        ''', (3,), 'path', 'reverse')

    def test_collection_closure_mutations_join_across_invocations(self):
        self.check('''
            func handle(req: Request) {
                var target = "/fixed"
                _ = [1, 2].map { item in
                    _ = String(contentsOfFile: target)
                    target = req.query["path"]
                    return item
                }
                _ = String(contentsOfFile: target)
            }
        ''', (4, 8), 'path')
        self.check('''
            func handle(req: Request) {
                var target = req.query["path"]
                _ = [].map { item in target = "/fixed"; return item }
                _ = String(contentsOfFile: target)
            }
        ''', (4,), 'path', 'empty')

    def test_nested_collection_closures_keep_outer_capture_identity(self):
        self.check('''
            func handle(req: Request) {
                _ = [req.query["path"]].map { outer in
                    ["fixed"].map { _ in String(contentsOfFile: outer) }
                }
            }
        ''', (3,), 'path')
        self.check('''
            func handle(req: Request) {
                _ = [req.query["path"]].map { outer in
                    ["fixed"].map { outer in String(contentsOfFile: outer) }
                }
            }
        ''', (), 'path', 'shadow')

    def test_collection_element_validation_does_not_validate_receiver(self):
        self.check('''
            func handle(req: Request) {
                let targets = [req.query["next"]]
                _ = targets.filter { target in
                    guard %s else { return false }
                    _ = req.redirect(to: target)
                    return true
                }
                _ = req.redirect(to: targets.first)
            }
        ''' % LOCAL, (8,))

    def test_testing_macros_analyze_real_arguments_and_awaited_body(self):
        self.check('''
            import Testing
            func handle(req: Request) async throws {
                #expect(String(contentsOfFile: req.query["path"]) == "")
                let path = try #require(req.query["path"])
                _ = String(contentsOfFile: path)
                await #expect(throws: (any Error).self) {
                    try await String(contentsOfFile: req.query["other"])
                }
            }
        ''', (3, 5, 7), 'path')

    def test_unresolved_collection_and_macro_dispatch_stays_incomplete(self):
        for body in (
            'let closure = { req.query["path"] }',
            'Task { String(contentsOfFile: req.query["path"]) }',
            'unknown { String(contentsOfFile: req.query["path"]) }',
            'items.map { [path = req.query["path"]] in String(contentsOfFile: path) }',
            'items.map { (left, right) in String(contentsOfFile: left) }',
        ):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
                self.check('func handle(req: Request) { %s }' % body, policy='path')
        for prefix in ('', 'import Testing\nmacro expect() = externalMacro()'):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'macro.*incomplete'):
                self.check(prefix + '\nfunc handle(req: Request) { #expect(String(contentsOfFile: req.query["path"])) }', policy='path')
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                struct Custom { func map(_ body: () -> String) {} }
                func handle(req: Request) {
                    Custom().map { String(contentsOfFile: req.query["path"]) }
                }
            ''', policy='path')

    def test_closure_captures_do_not_hide_indirect_or_nested_sinks(self):
        self.check('''
            func read(_ path: String) { _ = String(contentsOfFile: path) }
            func handle(req: Request) {
                let path = req.query["path"]
                _ = [1].map { _ in read(path) }
            }
        ''', (1,), 'path')
        self.check('''
            func handle(req: Request) {
                let paths = [req.query["path"]].map { outer in
                    [1].map { inner in outer }
                }
                _ = String(contentsOfFile: paths.first)
            }
        ''', (5,), 'path', 'nested-return')
        self.check('''
            func handle(req: Request) {
                _ = [req].map { original in
                    original.query.map { path in String(contentsOfFile: path) }
                }
            }
        ''', (3,), 'path', 'request-shape')

    def test_closure_throws_and_short_circuit_do_not_erase_captures(self):
        self.check('''
            func handle(req: Request) {
                var path = "/fixed"
                _ = [1].map { _ in
                    path = req.query["path"]
                    throw SomeError()
                }
                _ = String(contentsOfFile: path)
            }
        ''', (7,), 'path')
        self.check('''
            func handle(req: Request) {
                var path = req.query["path"]
                _ = condition && items.map { _ in path = "/fixed"; return true }
                _ = String(contentsOfFile: path)
            }
        ''', (4,), 'path', 'short-circuit')

    def test_collection_callable_field_does_not_claim_nonescaping_semantics(self):
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                struct Custom { let map: (@escaping () -> String) -> Void }
                func handle(req: Request) {
                    let custom = Custom(map: storeForLater)
                    var target = "/fixed"
                    custom.map { String(contentsOfFile: target) }
                    target = req.query["path"]
                }
            ''', policy='path')

    def test_unknown_collection_callback_sees_later_capture_mutations(self):
        self.check('''
            func handle(req: Request) {
                var path = "/fixed"
                items.map { _ in String(contentsOfFile: path) }
                path = req.query["path"]
            }
        ''', (3,), 'path')
        self.check('''
            func handle(req: Request) {
                items.map { _ in
                    var path = "/fixed"
                    other.map { _ in String(contentsOfFile: path) }
                    path = req.query["path"]
                }
            }
        ''', (4,), 'path', 'nested')
        self.check('''
            func handle(req: Request) {
                var path = "/fixed"
                let pending = [1].lazy.map { _ in String(contentsOfFile: path) }
                path = req.query["path"]
                _ = Array(pending)
            }
        ''', (3,), 'path', 'lazy')

    def test_unknown_map_return_is_not_a_sanitizer(self):
        self.check('''
            func handle(req: Request) {
                let transformed = req.query.map { _ in "/fixed" }
                _ = String(contentsOfFile: transformed)
            }
        ''', (3,), 'path')

    def test_testing_throw_result_retains_exception_dependencies(self):
        self.check('''
            import Testing
            func handle(req: Request) async throws {
                let error = await #expect(throws: SomeError.self) {
                    throw SomeError(path: req.query["path"])
                }
                _ = String(contentsOfFile: error.path)
            }
        ''', (6,), 'path')
        self.check('''
            import Testing
            func fail(_ path: String) throws { throw SomeError(path: path) }
            func forward(_ path: String) throws { try fail(path) }
            func handle(req: Request) async throws {
                let error = await #expect(throws: SomeError.self) {
                    try forward(req.query["path"])
                }
                _ = String(contentsOfFile: error.path)
            }
        ''', (8,), 'path', 'helper')

    def test_callback_object_alias_mutations_are_explicitly_incomplete(self):
        for mutation in ('alias.path = req.query["path"]',
                         'alias.setPath(req.query["path"])',
                         'update(alias, req.query["path"])',
                         'alias.append(req.query["path"])'):
            for late in (False, True):
                with self.subTest(mutation=mutation, late=late), self.assertRaisesRegex(ValueError, 'heap/capture.*incomplete'):
                    self.check('''
                        class Box {}
                        func handle(req: Request) {
                            let box = Box()
                            let alias = box
                            %s
                            let pending = [1].lazy.map { _ in String(contentsOfFile: box.path) }
                            %s
                            _ = Array(pending)
                        }
                    ''' % ('' if late else mutation, mutation if late else ''), policy='path')

    def test_callback_alias_request_objects_are_explicitly_incomplete(self):
        for value, access in (('req', 'box.value.query["path"]'),
                              ('req.query', 'box.value["path"]'),
                              ('req.content', 'box.value.decode(String.self)')):
            for mutation in (f'alias.value = {value}', f'alias.setValue({value})'):
                with self.subTest(value=value, mutation=mutation), self.assertRaisesRegex(ValueError, 'heap/capture.*incomplete'):
                    self.check('''
                        class Box {}
                        func handle(req: Request) {
                            let box = Box()
                            let alias = box
                            let pending = [1].lazy.map { _ in String(contentsOfFile: %s) }
                            %s
                            _ = Array(pending)
                        }
                    ''' % (access, mutation), policy='path')

    def test_malformed_interpolation_is_not_a_source_free_clean_result(self):
        for source in (r'func title() { print("\(broken[)") }', r'let x = "\( { )"'):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'incomplete'):
                self.check(source)

    def test_nested_delimiter_budget_is_not_clean(self):
        source = 'func handle(req: Request) { let value = ' + '(' * 130 + 'req.query["next"]' + ')' * 130 + ' }'
        with self.assertRaises(AnalysisLimit):
            self.check(source)

    def test_vapor_route_handler_trailing_closure_redirect_and_guard(self):
        self.check('''
            import Vapor
            func routes(_ app: Application) throws {
                app.get("go") { req -> Response in
                    let to = req.query[String.self, at: "to"] ?? "/"
                    return req.redirect(to: to)
                }
            }
        ''', (5,))
        self.check(f'''
            import Vapor
            func routes(_ app: Application) throws {{
                app.get("go") {{ req -> Response in
                    let target = req.query[String.self, at: "to"] ?? "/"
                    guard {LOCAL} else {{ return req.redirect(to: "/") }}
                    return req.redirect(to: target)
                }}
            }}
        ''', (), suffix='_clean')

    def test_vapor_route_handler_trailing_closure_path_traversal(self):
        self.check('''
            import Vapor
            func routes(_ app: Application) throws {
                app.get("read") { (req: Request) async throws -> String in
                    try String(contentsOfFile: req.query["path"] ?? "")
                }
            }
        ''', (4,), 'path')

    def test_vapor_route_handler_trailing_closure_capturing_outer_taint_is_incomplete(self):
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                func handle(outerReq: Request, app: Application) {
                    let leaked = outerReq.query["next"] ?? "/"
                    app.get("go") { req -> Response in
                        return req.redirect(to: leaked)
                    }
                }
            ''')

    def test_route_callback_cannot_drop_future_captured_request_values(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.check('''
                func handle(outerReq: Request, app: Application) {
                    var target = "/safe"
                    app.get("go") { req -> Response in
                        return req.redirect(to: target)
                    }
                    target = outerReq.query["next"] ?? "/"
                }
            ''')

    def test_route_callback_cannot_drop_request_collection_captures(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.check('''
                func handle(outerReq: Request, app: Application) {
                    let paths = outerReq.query
                    app.get("read") { req -> String in
                        return String(contentsOfFile: paths["file"])
                    }
                }
            ''', policy='path')

    def test_route_callback_cannot_drop_future_heap_alias_writes(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.check('''
                class Box {}
                func handle(outerReq: Request, app: Application) {
                    let box = Box()
                    let alias = box
                    app.get("read") { req -> String in
                        return String(contentsOfFile: box.value)
                    }
                    alias.value = outerReq.query["file"]
                }
            ''', policy='path')


if __name__ == '__main__':
    unittest.main()
