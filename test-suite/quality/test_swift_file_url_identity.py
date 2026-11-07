"""Swift outbound findings must follow the exact scoped destination value.

These tests run the real outbound detector with selected Swift sources. They
protect its HTTP coverage while canonical filesystem reads are classified by
the scoped frontend. Source files and complete findings remain in artifacts.
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

from ubs_core.swift_detectors.outbound_url import scan


class SwiftFileURLIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-file-url-identity-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def check(self, source, expected=(), suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        findings = list(scan(SimpleNamespace(project_dir=path.parent, files=[path])))
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        self.assertEqual([item['line'] for item in findings], list(expected), findings)
        for finding in findings:
            self.assertEqual(finding['rule'], 'swift.taint.outbound-url')
            self.assertEqual(finding['severity'], 'critical')
            self.assertEqual(finding['count'], 1)
            self.assertEqual(finding['path'], str(path.resolve()))
            witness = finding['extras']['taint_path']
            self.assertEqual(witness[0]['kind'], 'source')
            self.assertEqual(witness[-1]['kind'], 'sink')
            self.assertEqual(witness[-1]['line'], finding['line'])
        return path, source

    def test_safe_named_helpers_and_function_aliases_do_not_hide_request_urls(self):
        for name in ('safeURL', 'sanitizeURL', 'identity'):
            for alias in (False, True):
                with self.subTest(helper=name, alias=alias):
                    self.check('''
                        func %s(_ value: String) -> String { return value }
                        func handle(req: Request) async throws {
                            let chosen = %s
                            let remote = URL(string: %s(req.query["url"]!))!
                            _ = try await URLSession.shared.data(from: remote)
                        }
                    ''' % (name, name, 'chosen' if alias else name), (5,), name + str(alias))

    def test_literal_overwrites_and_unrelated_function_bindings_are_clean(self):
        self.check('''
            func overwrite(req: Request) async throws {
                var target = req.query["url"]!
                target = "https://api.example.com"
                _ = try await URLSession.shared.data(from: URL(string: target)!)
            }
            func unrelated(req: Request) async throws {
                let target = "https://api.example.com"
                _ = try await URLSession.shared.data(from: URL(string: target)!)
            }
            func unsafe(req: Request) async throws {
                let target = req.query["url"]!
                _ = try await URLSession.shared.data(from: URL(string: target)!)
            }
        ''', (12,))

    def test_conditional_overwrite_keeps_the_unsafe_branch(self):
        for both in (False, True):
            with self.subTest(both=both):
                self.check('''
                    func handle(req: Request, enabled: Bool) async throws {
                        var target = req.query["url"]!
                        if enabled { target = "https://api.example.com" } %s
                        _ = try await URLSession.shared.data(from: URL(string: target)!)
                    }
                ''' % ('else { target = "https://hooks.example.com" }' if both else ''),
                    () if both else (4,), str(both))

    def test_selected_url_guards_and_validating_helper_are_clean(self):
        self.check('''
            let hosts = Set(["api.example.com", "hooks.example.com"])
            func selected(_ raw: String) throws -> URL {
                guard let target = URL(string: raw), target.scheme == "https",
                    let host = target.host, hosts.contains(host) else { throw Blocked() }
                return target
            }
            func handle(req: Request) async throws {
                let remote = try selected(req.query["arbitrary"]!)
                let session = Foundation.URLSession.shared
                _ = try await session.data(from: remote)
            }
        ''')

    def test_both_scheme_and_exact_host_must_guard_the_selected_url(self):
        guards = (
            'target.scheme == "https"',
            'target.host == "api.example.com"',
            'target.scheme == "https", target.host!.hasSuffix("example.com")',
            'other.scheme == "https", other.host == "api.example.com"',
        )
        for index, guard in enumerate(guards):
            with self.subTest(guard=guard):
                self.check('''
                    func handle(req: Request) async throws {
                        let target = URL(string: req.query["value"]!)!
                        let other = URL(string: "https://api.example.com")!
                        guard %s else { return }
                        _ = try await URLSession.shared.data(from: target)
                    }
                ''' % guard, (5,), str(index))

    def test_checked_url_does_not_validate_raw_or_changed_values(self):
        variants = (
            'URL(string: raw)!',
            'URL(string: target.absoluteString + req.query["suffix"]!)!',
            'unknownTransform(target)',
        )
        for index, outgoing in enumerate(variants):
            with self.subTest(outgoing=outgoing):
                self.check('''
                    func handle(req: Request) async throws {
                        let raw = req.query["url"]!
                        guard let target = URL(string: raw), target.scheme == "https",
                            target.host == "api.example.com" else { return }
                        _ = try await URLSession.shared.data(from: %s)
                    }
                ''' % outgoing, (5,), str(index))

    def test_url_components_mutation_and_rebinding_invalidate_guard(self):
        for mutation in ('target.host = req.query["host"]!',
                         'target = URLComponents(string: req.query["next"]!)!'):
            with self.subTest(mutation=mutation):
                self.check('''
                    func handle(req: Request) async throws {
                        guard var target = URLComponents(string: req.query["url"]!),
                            target.scheme == "https", target.host == "api.example.com" else { return }
                        %s
                        _ = try await URLSession.shared.data(from: target.url!)
                    }
                ''' % mutation, (5,), 'host' if '.host' in mutation else 'rebind')

    def test_checked_url_components_can_supply_the_selected_url(self):
        self.check('''
            func handle(req: Request) async throws {
                guard let target = URLComponents(string: req.query["url"]!),
                    target.scheme == "https", target.host == "api.example.com" else { return }
                _ = try await URLSession.shared.data(from: target.url!)
            }
        ''')

    def test_rebinding_does_not_reuse_an_old_host_property_guard(self):
        self.check('''
            func handle(req: Request) async throws {
                guard var target = URL(string: req.query["first"]!), let oldHost = target.host else { return }
                target = URL(string: req.query["next"]!)!
                guard target.scheme == "https", oldHost == "api.example.com" else { return }
                _ = try await URLSession.shared.data(from: target)
            }
        ''', (5,))

    def test_request_destination_is_separate_from_headers_and_body(self):
        self.check('''
            func handle(req: Request, session: URLSession) async throws {
                var outgoing = URLRequest(url: URL(string: "https://api.example.com")!)
                outgoing.setValue(req.query["header"]!, forHTTPHeaderField: "X-Audit")
                outgoing.addValue(req.query["more"]!, forHTTPHeaderField: "X-Audit")
                outgoing.httpBody = Data(req.query["body"]!.utf8)
                outgoing.httpMethod = req.query["method"]!
                _ = try await session.data(for: outgoing)
            }
        ''')

    def test_request_url_mutation_and_value_copies(self):
        self.check('''
            func handle(req: Request, session: Foundation.URLSession) async throws {
                var outgoing = Foundation.URLRequest(url: URL(string: "https://api.example.com")!)
                let copy = outgoing
                outgoing.url = URL(string: req.query["url"]!)!
                _ = try await session.data(for: outgoing)
                _ = try await session.data(for: copy)
                outgoing.url = URL(string: "https://api.example.com")!
                _ = try await session.data(for: outgoing)
            }
        ''', (5,))

    def test_validated_request_url_is_not_sanitized_by_headers(self):
        self.check('''
            func handle(req: Request) async throws {
                guard let target = URL(string: req.query["url"]!), target.scheme == "https",
                    target.host == "api.example.com" else { return }
                let good = URLRequest(url: target)
                _ = try await URLSession.shared.data(for: good)
                var bad = URLRequest(url: URL(string: req.query["next"]!)!)
                bad.setValue("fixed", forHTTPHeaderField: "Host")
                _ = try await URLSession.shared.data(for: bad)
            }
        ''', (8,))

    def test_native_session_and_bound_method_aliases_keep_the_sink(self):
        for setup, callee in (
            ('let session = URLSession.shared', 'session.data'),
            ('let session = URLSession(configuration: .ephemeral)', 'session.data'),
            ('let download = URLSession.shared.data', 'download'),
        ):
            with self.subTest(setup=setup):
                self.check('''
                    func handle(req: Request) async throws {
                        %s
                        _ = try await %s(from: URL(string: req.query["value"]!)!)
                    }
                ''' % (setup, callee), (3,), str(len(setup)))

    def test_custom_same_file_client_method_is_not_a_native_http_sink(self):
        self.check('''
            struct LocalBuffer {
                func data(from value: URL) -> String { return "recorded" }
            }
            func handle(req: Request) {
                let client = LocalBuffer()
                _ = client.data(from: URL(string: req.query["url"]!)!)
            }
        ''')

    def test_unknown_client_and_mixed_session_alternative_remain_incomplete(self):
        for source in ('''
            func handle(req: Request, client: ExternalClient) {
                _ = client.get(url: req.query["url"]!)
            }
        ''', '''
            func handle(req: Request, enabled: Bool) async throws {
                let session = enabled ? URLSession.shared : externalSession()
                _ = try await session.data(from: URL(string: req.query["url"]!)!)
            }
        ''', '''
            func handle(req: Request) {
                _ = AF.request(req.query["url"]!)
            }
        '''):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, 'outbound HTTP.*incomplete'):
                    self.check(source)

    def test_unresolved_consumers_of_native_requests_remain_incomplete(self):
        for index, call in enumerate((
            'client.get(URLRequest(url: URL(string: req.query["url"]!)!))',
            'client.get(outgoing)',
            'client.request(outgoing)',
            'client.get(outgoing, "audit")',
            'consume(outgoing)',
        )):
            with self.subTest(call=call):
                with self.assertRaisesRegex(ValueError, 'outbound HTTP.*incomplete'):
                    self.check('''
                        func handle(req: Request, client: ExternalClient) {
                            let outgoing = URLRequest(url: URL(string: req.query["url"]!)!)
                            _ = %s
                        }
                    ''' % call, suffix=str(index))

    def test_helper_and_branch_request_values_keep_unresolved_dispatch_explicit(self):
        with self.assertRaisesRegex(ValueError, 'outbound HTTP.*incomplete'):
            self.check('''
                func makeRequest(_ raw: String) -> URLRequest {
                    return URLRequest(url: URL(string: raw)!)
                }
                func handle(req: Request, client: ExternalClient, enabled: Bool) {
                    let outgoing = enabled ? makeRequest(req.query["url"]!) : unknownRequest()
                    _ = client.get(outgoing)
                }
            ''')

    def test_selected_local_request_consumer_does_not_become_an_http_sink(self):
        self.check('''
            struct LocalStore {
                func get(_ value: URLRequest, _ label: String) -> String { return "stored" }
            }
            func handle(req: Request) {
                let client = LocalStore()
                let outgoing = URLRequest(url: URL(string: req.query["url"]!)!)
                _ = client.get(outgoing, "audit")
                _ = client.get(URLRequest(url: URL(string: req.query["next"]!)!), "audit")
            }
        ''')

    def test_labeled_callable_reference_is_not_an_empty_destination_call(self):
        for reference in ('URLSession.shared.data(from:)',
                          'URLSession.shared.dataTask(with:completionHandler:)',
                          'client.get(url:)', 'selected(url:)'):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(ValueError, 'callable reference.*incomplete'):
                    self.check('''
                        func selected(url: URL) async throws {
                            _ = try await URLSession.shared.data(from: url)
                        }
                        func handle(req: Request, client: ExternalClient) async throws {
                            let send = %s
                            _ = try await send(URL(string: req.query["url"]!)!)
                        }
                    ''' % reference)

    def test_native_looking_shadow_and_request_extension_do_not_grant_safety(self):
        sources = ('''
            enum Foundation { static var URLSession: ExternalSession { makeSession() } }
            func handle(req: Request) async throws {
                _ = try await Foundation.URLSession.shared.data(from: URL(string: req.query["url"]!)!)
            }
        ''', '''
            extension URLRequest {
                mutating func setValue(_ value: URL, forHTTPHeaderField field: String) { self.url = value }
            }
            func handle(req: Request) async throws {
                var outgoing = URLRequest(url: URL(string: "https://api.example.com")!)
                outgoing.setValue(URL(string: req.query["url"]!)!, forHTTPHeaderField: "X-Audit")
                _ = try await URLSession.shared.data(for: outgoing)
            }
        ''')
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    self.check(source, suffix=str(index))

    def test_unknown_member_keeps_its_place_in_a_client_union(self):
        with self.assertRaisesRegex(ValueError, 'outbound HTTP.*incomplete'):
            self.check('''
                func handle(req: Request, enabled: Bool, service: ExternalService) async throws {
                    let session = enabled ? URLSession.shared : service.session
                    _ = try await session.data(from: URL(string: req.query["url"]!)!)
                }
            ''')

    def test_without_an_outbound_operation_unrelated_closures_do_not_activate_it(self):
        self.check('''
            func handle(req: Request) {
                let data = req.content
                Task { consume(data) }
            }
        ''')

    def test_analysis_budget_and_escaping_network_callbacks_remain_incomplete(self):
        from ubs_core.analyzers.taint_swift_traversal import SwiftEngine
        from ubs_core.taint_flow import AnalysisLimit
        source = '''func handle(req: Request) async throws {
            _ = try await URLSession.shared.data(from: URL(string: req.query["url"]!)!)
        }'''
        engine = SwiftEngine(self.artifacts / 'budget.swift', source, 'outbound')
        engine.budget.remaining = 0
        with self.assertRaises(AnalysisLimit):
            engine.analyze()
        with self.assertRaisesRegex(ValueError, 'closure.*incomplete'):
            self.check('''
                func handle(req: Request) {
                    URLSession.shared.dataTask(with: URL(string: req.query["url"]!)!) { data, response, error in
                        consume(data)
                    }
                }
            ''')

    def test_vapor_request_client_uses_selected_destination(self):
        self.check('''
            func handle(req: Request) async throws {
                let client = req.client
                _ = try await client.get(URI(string: req.query["url"]!))
                _ = try await req.application.client.get(URI(string: "https://api.example.com"))
            }
        ''', (3,))

    def test_local_redirect_proof_does_not_discharge_http_destination(self):
        self.check(r'''
            func handle(req: Request) async throws {
                let target = req.query["url"]!
                guard target.hasPrefix("/"), !target.hasPrefix("//"), !target.contains("\\"),
                    !target.contains("\n"), !target.contains("\r"), !target.contains("\t") else { return }
                _ = try await URLSession.shared.data(from: URL(string: target)!)
            }
        ''', (5,))

    def test_relative_base_keeps_its_request_dependency(self):
        self.check('''
            func handle(req: Request) async throws {
                let root = URL(string: req.query["base"]!)!
                let target = URL(string: "status", relativeTo: root)!
                _ = try await URLSession.shared.data(from: target)
            }
        ''', (4,))

    def test_request_parameter_and_key_names_do_not_select_security(self):
        self.check('''
            func handle(incoming: Request) async throws {
                let value = incoming.query["arbitrary"]!
                _ = try await URLSession.shared.data(from: URL(string: value)!)
            }
        ''', (3,))

    def test_rule_scoped_suppression_does_not_hide_other_http_sinks(self):
        self.check('''
            func handle(req: Request) async throws {
                let target = URL(string: req.query["url"]!)!
                _ = try await URLSession.shared.data(from: target) // ubs:ignore[swift.taint.outbound-url]
                _ = try await URLSession.shared.data(from: target) // ubs:ignore[swift.taint.request_path_traversal]
            }
        ''', (4,))

    def test_original_http_fixture_sites_and_local_client_decoy(self):
        for relative, expected in (
            ('ssrf_buggy/RequestURLs.swift', [25, 30, 36, 41, 51]),
            ('ssrf_clean/RequestURLsSafe.swift', []),
        ):
            with self.subTest(fixture=relative):
                path = ROOT / 'test-suite/swift' / relative
                findings = list(scan(SimpleNamespace(project_dir=path.parent, files=[path])))
                self.assertEqual([(row['rule'], row['line']) for row in findings],
                                 [('swift.taint.outbound-url', line) for line in expected], findings)
        # The fixture's local HTTPClient.get body just copies bytes into Data;
        # its name is not evidence of an actual outbound operation at line 46.

    def test_checked_standardized_file_url(self):
        self.check('''
            func handle(req: Request) throws -> String {
                let root = URL(fileURLWithPath: "/srv/files").standardizedFileURL
                let target = root.appendingPathComponent(req.query["path"] ?? "").standardizedFileURL
                guard target.path.hasPrefix(root.path + "/") else {
                    return "blocked"
                }
                return try String(contentsOf: target)
            }
        ''')

    def test_uncontained_file_url_remains_a_path_finding(self):
        path, source = self.check('''
            func handle(req: Request) throws -> Data {
                let target = URL(fileURLWithPath: req.query["path"] ?? "")
                return try Data(contentsOf: target)
            }
        ''')
        from ubs_core.analyzers.taint_swift_traversal import flow_findings
        findings = flow_findings(path, source, 'path')
        self.assertEqual([item['line'] for item in findings], [3], findings)
        self.assertEqual(findings[0]['rule'], 'swift.taint.request_path_traversal')

    def test_real_remote_readers_still_report(self):
        for reader in ('Data', 'String'):
            with self.subTest(reader=reader):
                self.check('''
                    func handle(req: Request) throws -> %s {
                        let target = URL(string: req.query["url"] ?? "")!
                        return try %s(contentsOf: target)
                    }
                ''' % (reader, reader), (3,), reader)

    def test_file_to_http_rebinding_loses_exemption(self):
        self.check('''
            func handle(req: Request) throws -> String {
                var target = URL(fileURLWithPath: req.query["path"] ?? "")
                target = URL(string: req.query["url"] ?? "")!
                return try String(contentsOf: target)
            }
        ''', (4,))

    def test_branch_join_keeps_the_remote_alternative(self):
        self.check('''
            func handle(req: Request, remote: Bool) throws -> Data {
                var target = URL(fileURLWithPath: req.query["path"] ?? "")
                if remote {
                    target = URL(string: req.query["url"] ?? "")!
                }
                return try Data(contentsOf: target)
            }
        ''', (6,))

    def test_same_line_http_reader_is_not_exempted_with_file_reader(self):
        for order in ('fileFirst', 'remoteFirst'):
            with self.subTest(order=order):
                calls = ('let file = try String(contentsOf: local); return try String(contentsOf: target)'
                         if order == 'fileFirst' else
                         'let remote = try String(contentsOf: target); return try String(contentsOf: local)')
                self.check('''
                    func handle(req: Request) throws -> String {
                        let local = URL(fileURLWithPath: req.query["path"] ?? "")
                        let target = URL(string: req.query["url"] ?? "")!
                        %s
                    }
                ''' % calls, (4,), order)

    def test_same_line_urlsession_is_not_exempted_with_file_reader(self):
        self.check('''
            func handle(req: Request) async throws -> (Data, URLResponse) {
                let target = URL(fileURLWithPath: req.query["path"] ?? "")
                let remote = URL(string: req.query["url"] ?? "")!
                let file = try Data(contentsOf: target); return try await URLSession.shared.data(from: remote)
            }
        ''', (4,))

    def test_selected_helper_preserves_file_url_identity(self):
        self.check('''
            func selected(_ value: String) -> URL {
                return URL(fileURLWithPath: value)
            }
            func handle(req: Request) throws -> Data {
                let target = selected(req.query["path"] ?? "")
                return try Data(contentsOf: target)
            }
        ''')

    def test_selected_helper_preserves_remote_url_identity(self):
        self.check('''
            func selected(_ value: String) -> URL {
                return URL(string: value)!
            }
            func handle(req: Request) throws -> Data {
                let target = selected(req.query["url"] ?? "")
                return try Data(contentsOf: target)
            }
        ''', (6,))

    def test_file_identity_does_not_transfer_between_function_scopes(self):
        self.check('''
            func local(req: Request) throws -> String {
                let target = URL(fileURLWithPath: req.query["path"] ?? "")
                return try String(contentsOf: target)
            }
            func remote(req: Request) throws -> String {
                let target = URL(string: req.query["url"] ?? "")!
                return try String(contentsOf: target)
            }
        ''', (7,))

    def test_qualified_and_multiline_file_reads(self):
        self.check('''
            func handle(req: Request) throws -> String {
                let target = Foundation.URL(fileURLWithPath: req.query["path"] ?? "")
                return try Foundation.String(
                    contentsOf: target
                )
            }
        ''')

    def test_unknown_value_transform_does_not_keep_file_identity(self):
        self.check('''
            func handle(req: Request) throws -> Data {
                let path = URL(fileURLWithPath: req.query["url"] ?? "")
                let target = unknownURLTransform(path)
                return try Data(contentsOf: target)
            }
        ''', (4,))

    def test_selected_reader_helper_joins_file_and_remote_contexts(self):
        self.check('''
            func handle(req: Request) throws -> Data {
                let target = URL(fileURLWithPath: req.query["path"] ?? "")
                let remote = URL(string: req.query["url"] ?? "")!
                let file = try read(target)
                return try read(remote)
            }
            func read(_ target: URL) throws -> Data {
                return try Data(contentsOf: target)
            }
        ''', (8,))

    def test_incomplete_classification_and_invalid_utf8_propagate(self):
        malformed = self.artifacts / 'malformed.swift'
        malformed.write_text('''func handle(req: Request) throws -> Data {
            let target = URL(fileURLWithPath: req.query["url"] ?? "")
            return try Data(contentsOf: target
        ''', encoding='utf-8')
        with self.assertRaises((ValueError, SyntaxError)):
            list(scan(SimpleNamespace(project_dir=malformed.parent, files=[malformed])))

        invalid = self.artifacts / 'invalid-utf8.swift'
        invalid.write_bytes(b'let target = req.query["url"]\nData(contentsOf: target)\n\xff')
        with self.assertRaises(UnicodeDecodeError):
            list(scan(SimpleNamespace(project_dir=invalid.parent, files=[invalid])))


if __name__ == '__main__':
    unittest.main()
