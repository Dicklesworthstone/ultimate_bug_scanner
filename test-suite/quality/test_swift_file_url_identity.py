"""File-URL exemptions must follow the exact outbound reader argument.

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
        return path, source

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
