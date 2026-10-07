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
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers.taint_swift_traversal import file_url_read_offsets, flow_findings
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

    def test_guard_optional_binding(self):
        self.check('''
            func handle(req: Request) -> Response {
                guard let target = req.query["next"] else { return Response.redirect(to: "/") }
                return req.redirect(to: target)
            }
        ''', (3,))

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

    def test_nested_delimiter_budget_is_not_clean(self):
        source = 'func handle(req: Request) { let value = ' + '(' * 130 + 'req.query["next"]' + ')' * 130 + ' }'
        with self.assertRaises(AnalysisLimit):
            self.check(source)


if __name__ == '__main__':
    unittest.main()
