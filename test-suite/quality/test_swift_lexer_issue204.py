"""Swift literal and interpolation regressions for issue #204.

The page-marker literal comes from franken_ocr at
b77ba7ac6de17aeb82f104cf4a54eda86913b094, ios/Sources/HtmlExport.swift.
The other cases exercise executable interpolation with exact source-to-sink
expectations, inert raw text, regex boundaries and fatal resource limits.
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
from ubs_core.analyzers.taint_swift_traversal import flow_findings, swift_validated_tokens
from ubs_core.taint_flow import AnalysisLimit


class SwiftLexerIssue204Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts' / ('swift-lexer-issue204-' + uuid.uuid4().hex)
        cls.artifacts.mkdir(parents=True)

    def check(self, source, lines=(), suffix=''):
        source = textwrap.dedent(source).strip('\n') + '\n'
        path = self.artifacts / (self.id().rsplit('.', 1)[-1] + suffix + '.swift')
        path.write_text(source, encoding='utf-8')
        findings = flow_findings(path, source, 'redirect')
        path.with_suffix('.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        self.assertEqual([item['line'] for item in findings], list(lines), findings)
        for finding in findings:
            self.assertEqual(finding['rule'], 'swift.taint.request_open_redirect')
            self.assertEqual(finding['severity'], 'critical')
            self.assertEqual(finding['path'], str(path.resolve()))
            route = finding['extras']['taint_path']
            self.assertEqual(route[0]['kind'], 'source')
            self.assertEqual(route[-1]['kind'], 'sink')
            self.assertEqual(route[-1]['line'], finding['line'])
        return findings

    def test_franken_ocr_page_marker_preserves_quotes_and_interpolation(self):
        source = r'''#"<div class="page-marker"><span>Page \#(number)</span></div>"#'''
        token, = swift_validated_tokens(source)
        self.assertEqual(token.kind, 'template')
        self.assertEqual(token.value, '<div class="page-marker"><span>Page </span></div>')
        self.assertEqual((token.start, token.end), (0, len(source)))
        self.assertEqual([[part.value for part in hole] for hole in token.parts], [['number']])
        self.assertEqual(token.parts[0][0].start, source.index('number'))

    def test_arbitrary_hash_counts_preserve_executable_interpolation(self):
        for count in (1, 2, 33, 64):
            hashes = '#' * count
            target = hashes + '"<a href="\\' + hashes + '(req.query["next"])">"' + hashes
            with self.subTest(count=count, source='query'):
                self.check('''
                    func handle(req: Request) -> Response {
                        let target = %s
                        return req.redirect(to: target)
                    }
                ''' % target, (3,), suffix=str(count))
            # This source exists only in the hole. A split delimiter must not
            # hide it from the source-witness applicability check.
            filename = hashes + '"/files/\\' + hashes + '(upload.filename)"' + hashes
            with self.subTest(count=count, source='filename'):
                self.check('''
                    func export(upload: Upload) -> Response {
                        let target = %s
                        return Response.redirect(to: target)
                    }
                ''' % filename, (3,), suffix=str(count) + '-filename')

    def test_raw_interpolation_with_fewer_hashes_is_inert(self):
        self.check(r'''
            func handle(req: Request) -> Response {
                let target = ##"/local/\(req.query["next"])/\#(req.query["next"])"##
                return req.redirect(to: target)
            }
        ''')

    def test_nested_raw_strings_and_multiline_interpolation_keep_sources(self):
        self.check(r'''
            func handle(req: Request) -> Response {
                let target = ##"outer \##(#"inner \#(req.query["next"] ?? #")"#)"#)"##
                return req.redirect(to: target)
            }
        ''', (3,), suffix='single')
        self.check(r'''
            func handle(req: Request) -> Response {
                let target = ##"""
                <div class="content">\##(
                    req.query["next"] /* ) /* nested */ */ ?? #"\#("quoted)")"#
                )</div>
                """##
                return req.redirect(to: target)
            }
        ''', (7,), suffix='multiline')

    def test_regex_parentheses_do_not_terminate_string_interpolation(self):
        for literal in (
            r'''"\(req.query["next"].replacing(/[)]/, with: ""))"''',
            r'''#"\#(req.query["next"].replacing(#/[)]/#, with: ""))"#''',
        ):
            with self.subTest(literal=literal):
                self.check('''
                    func handle(req: Request) -> Response {
                        let target = %s
                        return req.redirect(to: target)
                    }
                ''' % literal, (3,), suffix=str(len(literal)))

    def test_nested_interpolation_is_lexed_once_within_the_budget(self):
        target = 'req.query["next"]'
        for _ in range(20):
            target = '"\\(' + target + ')"'
        self.check('''
            func handle(req: Request) -> Response {
                return req.redirect(to: %s)
            }
        ''' % target, (2,))

    def test_regex_continuation_and_division_share_interpolation_lexing(self):
        # Physical line breaks in the interpolation require a multiline outer
        # string, as in SwiftParserTest's multiline-string interpolation cases.
        source = r'''"""
        \(text.replacing(
            /* a regex begins after the call's opening parenthesis */
            /[)]/,
            with: "")) \((12
            /* division continues after an operand */
            / 3))
        """'''
        token, = swift_validated_tokens(source)
        self.assertEqual(token.kind, 'template')
        self.assertEqual(len(token.parts), 2)
        self.assertEqual([part.kind for part in token.parts[0] if part.value == '[)]'], ['regex'])
        self.assertEqual([part.kind for part in token.parts[1] if part.value == '/'], ['code'])

    def test_array_regex_does_not_expose_pattern_delimiters(self):
        source = 'let patterns = [ /[)]/, /[({]/ ]'
        tokens = swift_validated_tokens(source)
        patterns = [token for token in tokens if token.kind == 'regex']
        self.assertEqual([token.value for token in patterns], ['[)]', '[({]'])
        self.assertEqual([source[token.start:token.end] for token in patterns], ['/[)]/', '/[({]/'])
        # Division after an element's operand must still be an operator.
        tokens = swift_validated_tokens('let values = [12 / 3, 24 / 6]')
        self.assertEqual([token.kind for token in tokens if token.value == '/'], ['code', 'code'])
        # A literal containing a punctuation mark is still an operand; its
        # contents must not determine the next slash's syntactic role.
        tokens = swift_validated_tokens('let values = ["[" / 3, "(" / 4]')
        self.assertEqual([token.kind for token in tokens if token.value == '/'], ['code', 'code'])
        self.check(r'''
            func handle(req: Request) -> Response {
                let target = "\(req.query["next"]) \([ /[)]/ ])"
                return req.redirect(to: target)
            }
        ''', (3,))

    def test_malformed_interpolation_still_fails_before_applicability(self):
        for source in (
            r'''let value = "\(number"''',
            r'''let value = #"\#(number] )"#''',
            r'''let value = "\(/* unterminated )"''',
            r'''let value = "\(#/[)]/)"''',
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    flow_findings(self.artifacts / 'malformed.swift', source, 'redirect')

    def test_interpolation_nesting_limit_remains_fatal(self):
        target = 'number'
        for _ in range(70):
            target = '"\\(' + target + ')"'
        # No source or sink is required: limits cannot turn into a clean skip.
        with self.assertRaises(AnalysisLimit):
            flow_findings(self.artifacts / 'nesting-limit.swift', 'let value = ' + target, 'redirect')


if __name__ == '__main__':
    unittest.main()
