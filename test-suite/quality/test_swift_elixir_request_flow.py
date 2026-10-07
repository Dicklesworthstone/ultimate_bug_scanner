"""Independent Swift/Elixir request-flow oracle (mj1j.7 and mj1j.9).

Authored against the original line-based passes before their replacements.
Expected results describe language bindings and actual sink arguments, never
the spelling of a helper name. Real CLI companions run with
UBS_SCOPED_REQUEST_E2E=1; all generated sources and evidence stay in artifacts.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import (
    taint_elixir_redirect, taint_elixir_traversal,
    taint_swift_redirect, taint_swift_traversal,
)
from ubs_core.registry import RunContext

RULES = {
    ('swift', 'redirect'): 'swift.taint.request_open_redirect',
    ('swift', 'path'): 'swift.taint.request_path_traversal',
    ('elixir', 'redirect'): 'elixir.taint.open_redirect',
    ('elixir', 'path'): 'elixir.taint.request_path_traversal',
}
ANALYZERS = {
    ('swift', 'redirect'): taint_swift_redirect,
    ('swift', 'path'): taint_swift_traversal,
    ('elixir', 'redirect'): taint_elixir_redirect,
    ('elixir', 'path'): taint_elixir_traversal,
}
SWIFT_LOCAL = (
    r'target.hasPrefix("/") && !target.hasPrefix("//") && '
    r'!target.contains("\\") && !target.contains("\n") && '
    r'!target.contains("\r") && !target.contains("\t")'
)
ELIXIR_LOCAL = (
    r'String.starts_with?(target, "/") and not String.starts_with?(target, "//") '
    r'and not String.contains?(target, ["\\", "\n", "\r", "\t"])'
)


@dataclass(frozen=True)
class Case:
    lang: str
    kind: str
    name: str
    code: str
    lines: tuple[int, ...]

    @property
    def source(self):
        return textwrap.dedent(self.code).strip('\n') + '\n'

    @property
    def rule(self):
        return RULES[self.lang, self.kind]


CASES = (
    Case('swift', 'redirect', 'direct', '''
        func handle(req: Request) -> Response {
            return req.redirect(to: req.query["next"] ?? "/")
        }''', (2,)),
    Case('swift', 'redirect', 'safe_named_identity', '''
        func safeRedirect(_ value: String) -> String {
            return value
        }
        func handle(req: Request) -> Response {
            return req.redirect(to: safeRedirect(req.query["next"] ?? "/"))
        }''', (5,)),
    Case('swift', 'redirect', 'alpha_renamed_identity', '''
        func identity(_ value: String) -> String {
            return value
        }
        func handle(req: Request) -> Response {
            return req.redirect(to: identity(req.query["next"] ?? "/"))
        }''', (5,)),
    Case('swift', 'redirect', 'literal_kill', '''
        func handle(req: Request) -> Response {
            var target = req.query["next"] ?? "/"
            target = "/home"
            return req.redirect(to: target)
        }''', ()),
    Case('swift', 'redirect', 'post_declaration_source', '''
        func handle(req: Request) -> Response {
            var target = "/home"
            target = req.query["next"] ?? "/"
            return req.redirect(to: target)
        }''', (4,)),
    Case('swift', 'redirect', 'selected_sink_helper', '''
        func dispatch(_ target: String) -> Response {
            return Response.redirect(to: target)
        }
        func handle(req: Request) -> Response {
            return dispatch(req.query["next"] ?? "/")
        }''', (2,)),
    Case('swift', 'redirect', 'constant_helper', '''
        func destination(_ value: String) -> String {
            return "/home"
        }
        func handle(req: Request) -> Response {
            return req.redirect(to: destination(req.query["next"] ?? "/"))
        }''', ()),
    Case('swift', 'redirect', 'argument_labels', '''
        func dispatch(to target: String, ignoring other: String) -> Response {
            return Response.redirect(to: target)
        }
        func handle(req: Request) -> Response {
            return dispatch(to: "/home", ignoring: req.query["next"] ?? "/")
        }''', ()),
    Case('swift', 'redirect', 'full_local_guard', f'''
        func handle(req: Request) -> Response {{
            let target = req.query["next"] ?? "/"
            guard {SWIFT_LOCAL} else {{
                return req.redirect(to: "/home")
            }}
            return req.redirect(to: target)
        }}''', ()),
    Case('swift', 'redirect', 'weak_local_guard', '''
        func handle(req: Request) -> Response {
            let target = req.query["next"] ?? "/"
            guard target.hasPrefix("/") && !target.hasPrefix("//") else {
                return req.redirect(to: "/home")
            }
            return req.redirect(to: target)
        }''', (6,)),
    Case('swift', 'redirect', 'unrelated_guard', f'''
        func handle(req: Request) -> Response {{
            let untrusted = req.query["next"] ?? "/"
            let target = "/home"
            guard {SWIFT_LOCAL} else {{
                return req.redirect(to: "/home")
            }}
            return req.redirect(to: untrusted)
        }}''', (7,)),
    Case('swift', 'redirect', 'proof_invalidated_by_rebinding', f'''
        func handle(req: Request) -> Response {{
            var target = req.query["next"] ?? "/"
            guard {SWIFT_LOCAL} else {{
                return req.redirect(to: "/home")
            }}
            target = req.query["other"] ?? "/"
            return req.redirect(to: target)
        }}''', (7,)),
    Case('swift', 'redirect', 'branch_join', '''
        func handle(req: Request, flag: Bool) -> Response {
            var target = req.query["next"] ?? "/"
            if flag {
                target = "/home"
            }
            return req.redirect(to: target)
        }''', (6,)),
    Case('swift', 'redirect', 'both_branches_kill', '''
        func handle(req: Request, flag: Bool) -> Response {
            var target = req.query["next"] ?? "/"
            if flag {
                target = "/home"
            } else {
                target = "/about"
            }
            return req.redirect(to: target)
        }''', ()),
    Case('swift', 'redirect', 'scope_isolation', '''
        func remember(req: Request) {
            let target = req.query["next"] ?? "/"
        }
        func clean() -> Response {
            let target = "/home"
            return Response.redirect(to: target)
        }''', ()),
    Case('swift', 'redirect', 'source_suppression_retains_flow', '''
        func handle(req: Request) -> Response {
            let target = req.query["next"] ?? "/" // ubs:ignore
            return req.redirect(to: target)
        }''', (3,)),
    Case('swift', 'redirect', 'sink_suppression', '''
        func handle(req: Request) -> Response {
            let target = req.query["next"] ?? "/"
            return req.redirect(to: target) // ubs:ignore
        }''', ()),
    Case('swift', 'redirect', 'lexical_decoy', '''
        func clean() -> Response {
            let text = #"req.redirect(to: req.query["next"])"#
            return Response.redirect(to: "/home")
        }''', ()),
    Case('swift', 'path', 'direct_file', '''
        func handle(req: Request) throws -> String {
            return try String(contentsOfFile: req.query["path"] ?? "")
        }''', (2,)),
    Case('swift', 'path', 'path_literal_kill', '''
        func handle(req: Request) throws -> String {
            var target = req.query["path"] ?? ""
            target = "/srv/files/help.txt"
            return try String(contentsOfFile: target)
        }''', ()),
    Case('swift', 'path', 'path_selected_helper', '''
        func readTarget(_ target: String) throws -> String {
            return try String(contentsOfFile: target)
        }
        func handle(req: Request) throws -> String {
            return try readTarget(req.query["path"] ?? "")
        }''', (2,)),
    Case('swift', 'path', 'checked_standardized_file_url', '''
        func handle(req: Request) throws -> String {
            let root = URL(fileURLWithPath: "/srv/files").standardizedFileURL
            let target = root.appendingPathComponent(req.query["path"] ?? "").standardizedFileURL
            guard target.path.hasPrefix(root.path + "/") else {
                return "blocked"
            }
            return try String(contentsOf: target)
        }''', ()),
    Case('swift', 'path', 'late_guard_cannot_protect_prior_sink', '''
        func handle(req: Request) throws -> String {
            let root = URL(fileURLWithPath: "/srv/files").standardizedFileURL
            let target = root.appendingPathComponent(req.query["path"] ?? "").standardizedFileURL
            let result = try String(contentsOf: target)
            guard target.path.hasPrefix(root.path + "/") else {
                return "blocked"
            }
            return result
        }''', (4,)),
    Case('elixir', 'redirect', 'direct', '''
        defmodule Handler do
          def handle(conn, params) do
            redirect(conn, external: params["next"])
          end
        end''', (3,)),
    Case('elixir', 'redirect', 'safe_named_identity', '''
        defmodule Handler do
          defp safe_redirect(value), do: value
          def handle(conn, params) do
            redirect(conn, external: safe_redirect(params["next"]))
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'alpha_renamed_identity', '''
        defmodule Handler do
          defp identity(value), do: value
          def handle(conn, params) do
            redirect(conn, external: identity(params["next"]))
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'literal_kill', '''
        defmodule Handler do
          def handle(conn, params) do
            target = params["next"]
            target = "/home"
            redirect(conn, external: target)
          end
        end''', ()),
    Case('elixir', 'redirect', 'selected_sink_helper', '''
        defmodule Handler do
          defp dispatch(conn, target) do
            redirect(conn, external: target)
          end
          def handle(conn, params) do
            dispatch(conn, params["next"])
          end
        end''', (3,)),
    Case('elixir', 'redirect', 'constant_helper', '''
        defmodule Handler do
          defp destination(_value), do: "/home"
          def handle(conn, params) do
            redirect(conn, external: destination(params["next"]))
          end
        end''', ()),
    Case('elixir', 'redirect', 'request_value_pipeline', '''
        defmodule Handler do
          defp safe_redirect(value), do: value
          def handle(conn, params) do
            target = params["next"] |> safe_redirect()
            conn |> redirect(external: target)
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'map_fetch_tuple', '''
        defmodule Handler do
          def handle(conn, params) do
            {:ok, target} = Map.fetch(params, "next")
            redirect(conn, external: target)
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'map_fetch_case', '''
        defmodule Handler do
          def handle(conn, params) do
            case Map.fetch(params, "next") do
              {:ok, target} -> redirect(conn, external: target)
              :error -> redirect(conn, external: "/home")
            end
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'selected_function_clause', '''
        defmodule Handler do
          defp pick(:safe, _value), do: "/home"
          defp pick(:raw, value), do: value
          def handle(conn, params) do
            redirect(conn, external: pick(:raw, params["next"]))
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'safe_function_clause', '''
        defmodule Handler do
          defp pick(:safe, _value), do: "/home"
          defp pick(:raw, value), do: value
          def handle(conn, params) do
            redirect(conn, external: pick(:safe, params["next"]))
          end
        end''', ()),
    Case('elixir', 'redirect', 'branch_assignment_does_not_escape', '''
        defmodule Handler do
          def handle(conn, params) do
            target = "/home"
            if params["flag"] do
              target = params["next"]
            end
            redirect(conn, external: target)
          end
        end''', ()),
    Case('elixir', 'redirect', 'branch_result_join', '''
        defmodule Handler do
          def handle(conn, params) do
            target = if params["flag"] do
              params["next"]
            else
              "/home"
            end
            redirect(conn, external: target)
          end
        end''', (8,)),
    Case('elixir', 'redirect', 'full_local_guard', f'''
        defmodule Handler do
          def handle(conn, params) do
            target = params["next"]
            if {ELIXIR_LOCAL} do
              redirect(conn, external: target)
            else
              redirect(conn, external: "/home")
            end
          end
        end''', ()),
    Case('elixir', 'redirect', 'weak_local_guard', '''
        defmodule Handler do
          def handle(conn, params) do
            target = params["next"]
            if String.starts_with?(target, "/") and not String.starts_with?(target, "//") do
              redirect(conn, external: target)
            else
              redirect(conn, external: "/home")
            end
          end
        end''', (5,)),
    Case('elixir', 'redirect', 'source_suppression_retains_flow', '''
        defmodule Handler do
          def handle(conn, params) do
            target = params["next"] # ubs:ignore
            redirect(conn, external: target)
          end
        end''', (4,)),
    Case('elixir', 'redirect', 'sink_suppression', '''
        defmodule Handler do
          def handle(conn, params) do
            target = params["next"]
            redirect(conn, external: target) # ubs:ignore
          end
        end''', ()),
    Case('elixir', 'redirect', 'lexical_decoy', '''
        defmodule Handler do
          def handle(conn, _params) do
            text = ~S(redirect(conn, external: params["next"]))
            redirect(conn, external: "/home")
          end
        end''', ()),
    Case('elixir', 'path', 'direct_file', '''
        defmodule Handler do
          def handle(_conn, params) do
            File.read!(params["path"])
          end
        end''', (3,)),
    Case('elixir', 'path', 'path_literal_kill', '''
        defmodule Handler do
          def handle(_conn, params) do
            target = params["path"]
            target = "/srv/files/help.txt"
            File.read!(target)
          end
        end''', ()),
    Case('elixir', 'path', 'path_selected_helper', '''
        defmodule Handler do
          defp read_target(target), do: File.read!(target)
          def handle(_conn, params) do
            read_target(params["path"])
          end
        end''', (2,)),
    Case('elixir', 'path', 'checked_expanded_path', '''
        defmodule Handler do
          def handle(_conn, params) do
            root = Path.expand("/srv/files")
            target = Path.expand(params["path"], root)
            if String.starts_with?(target, root <> "/") do
              File.read!(target)
            else
              "blocked"
            end
          end
        end''', ()),
    Case('elixir', 'path', 'late_guard_cannot_protect_prior_sink', '''
        defmodule Handler do
          def handle(_conn, params) do
            root = Path.expand("/srv/files")
            target = Path.expand(params["path"], root)
            result = File.read!(target)
            if String.starts_with?(target, root <> "/") do
              result
            else
              "blocked"
            end
          end
        end''', (5,)),
)
BY_NAME = {(case.lang, case.name): case for case in CASES}


class LoggedCase(unittest.TestCase):
    def setUp(self):
        self.artifact = ROOT / 'test-suite/artifacts/scoped-request-flow' / (
            self.id().split('.')[-1] + '-' + uuid.uuid4().hex)
        self.artifact.mkdir(parents=True)

    def source_file(self, case):
        directory = self.artifact / (case.lang + '-' + case.name)
        directory.mkdir(exist_ok=True)
        target = directory / ('selected source.' + ('swift' if case.lang == 'swift' else 'ex'))
        if not target.exists() or target.read_text(encoding='utf-8') != case.source:
            target.write_text(case.source, encoding='utf-8')
        return directory, target

    def observe(self, case):
        directory, target = self.source_file(case)
        started = time.monotonic()
        try:
            findings = list(ANALYZERS[case.lang, case.kind].run(
                RunContext(lang=case.lang, files=[target])))
        except Exception as exc:
            (directory / 'error.txt').write_text(repr(exc), encoding='utf-8')
            raise
        (directory / 'findings.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        (directory / 'identity.json').write_text(json.dumps({
            'python': sys.version, 'executable': sys.executable,
            'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'elapsed': time.monotonic() - started,
        }, indent=2), encoding='utf-8')
        return findings


class ScopedRequestSemanticTests(LoggedCase):
    def check_case(self, case):
        findings = self.observe(case)
        self.assertEqual(sorted((row['rule'], row['line']) for row in findings),
                         [(case.rule, line) for line in case.lines], findings)
        for row in findings:
            self.assertEqual(row['severity'], 'critical', row)

    def test_alpha_renaming_preserves_bindings_and_findings(self):
        for lang, old_name in (('swift', 'safeRedirect'), ('elixir', 'safe_redirect')):
            first = BY_NAME[lang, 'safe_named_identity']
            second = BY_NAME[lang, 'alpha_renamed_identity']
            self.assertEqual(first.source.replace(old_name, 'identity'), second.source)
            with self.subTest(lang=lang):
                self.check_case(first)
                self.check_case(second)

    def test_malformed_selected_source_is_explicit(self):
        cases = (
            Case('swift', 'redirect', 'malformed',
                 'func handle(req: Request) -> Response {\nreturn req.redirect(to: req.query["next"] ?? "/")', ()),
            Case('elixir', 'redirect', 'malformed',
                 'defmodule Handler do\ndef handle(conn, params) do\nredirect(conn, external: params["next"])', ()),
        )
        for case in cases:
            with self.subTest(lang=case.lang):
                with self.assertRaisesRegex(ValueError, 'incomplete|unclosed|unterminated|parse|syntax'):
                    self.observe(case)

    def test_selected_helper_trace_ends_at_the_actual_sink(self):
        for lang in ('swift', 'elixir'):
            with self.subTest(lang=lang):
                case = BY_NAME[lang, 'selected_sink_helper']
                findings = self.observe(case)
                self.assertEqual(len(findings), 1, findings)
                trace = findings[0].get('extras', {}).get('taint_path', [])
                self.assertTrue(any(step.get('kind') == 'source' for step in trace), findings)
                self.assertEqual((trace[-1].get('kind'), trace[-1].get('line')),
                                 ('sink', case.lines[0]), findings)


def semantic_test(case):
    def test(self):
        self.check_case(case)
    return test


for _case in CASES:
    setattr(ScopedRequestSemanticTests, 'test_' + _case.lang + '_' + _case.name,
            semantic_test(_case))


@unittest.skipUnless(os.environ.get('UBS_SCOPED_REQUEST_E2E') == '1',
                     'set UBS_SCOPED_REQUEST_E2E=1 for actual CLI scans')
class ScopedRequestPublicTests(LoggedCase):
    def scan(self, case, fmt, extra=(), attempt='scan'):
        directory, target = self.source_file(case)
        evidence = directory / (fmt + '-' + attempt)
        evidence.mkdir(exist_ok=True)
        command = [str(ROOT / 'ubs'), '--only=' + case.lang, '--ci',
                   '--format=' + fmt, *extra, str(target)]
        env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
               'NO_COLOR': '1', 'CI': '1', 'PYTHONDONTWRITEBYTECODE': '1',
               'UBS_CACHE_DIR': str(directory / 'cache')}
        started = time.monotonic()
        result = subprocess.run(command, cwd=directory, env=env, text=True,
                                capture_output=True, timeout=180)
        (evidence / 'stdout.log').write_text(result.stdout, encoding='utf-8')
        (evidence / 'stderr.log').write_text(result.stderr, encoding='utf-8')
        (evidence / 'identity.json').write_text(json.dumps({
            'command': command, 'cwd': str(directory), 'exit': result.returncode,
            'elapsed': time.monotonic() - started, 'python': sys.version,
            'source_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'path': env['PATH'],
        }, indent=2), encoding='utf-8')
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            self.fail((command, result.returncode, result.stdout, result.stderr))
        return result, payload, target

    def assert_result(self, case, fmt, result, payload, target):
        self.assertEqual(result.returncode, int(bool(case.lines)),
                         (result.stdout, result.stderr))
        if fmt == 'json':
            self.assertEqual(payload['status'], 'ok', payload)
            self.assertEqual(payload['failed_modules'], [], payload)
            self.assertEqual(payload['totals']['files'], 1, payload)
            self.assertEqual(payload['totals']['critical'], len(case.lines), payload)
            records = [row for row in (payload.get('findings') or [])
                       if row['rule_id'] in RULES.values()]
            observed = [(row['rule_id'], row['line']) for row in records]
            paths = [row['file'] for row in records]
        else:
            records = [row for run in payload['runs'] for row in run.get('results', [])
                       if row['ruleId'] in RULES.values()]
            observed = [(row['ruleId'], row['locations'][0]['physicalLocation']['region']['startLine'])
                        for row in records]
            paths = [row['locations'][0]['physicalLocation']['artifactLocation']['uri'] for row in records]
        self.assertEqual(sorted(observed), [(case.rule, line) for line in case.lines], payload)
        from urllib.parse import unquote
        for path in paths:
            self.assertEqual(Path(unquote(path)).name, target.name, payload)

    def test_original_oracle_through_json_and_sarif(self):
        names = ('direct', 'safe_named_identity', 'alpha_renamed_identity',
                 'literal_kill', 'selected_sink_helper', 'constant_helper',
                 'full_local_guard', 'weak_local_guard', 'source_suppression_retains_flow',
                 'direct_file', 'checked_standardized_file_url', 'checked_expanded_path',
                 'late_guard_cannot_protect_prior_sink')
        for case in CASES:
            if case.name not in names:
                continue
            directory, target = self.source_file(case)
            sibling = directory / ('unselected.' + target.suffix.lstrip('.'))
            sibling.write_text(BY_NAME[case.lang, 'direct'].source, encoding='utf-8')
            for fmt in ('json', 'sarif'):
                with self.subTest(lang=case.lang, case=case.name, format=fmt):
                    result, payload, target = self.scan(case, fmt, ('--no-cache',))
                    self.assert_result(case, fmt, result, payload, target)
                    print('SCOPED_REQUEST_PUBLIC', case.lang, case.name, fmt, 'PASS', flush=True)

    def test_warm_cache_replays_and_helper_edits_invalidate(self):
        for lang in ('swift', 'elixir'):
            original = BY_NAME[lang, 'safe_named_identity']
            if lang == 'swift':
                safe_code = '''
                    func safeRedirect(_ value: String) -> String {
                        return "/home"
                    }
                    func handle(req: Request) -> Response {
                        return req.redirect(to: safeRedirect(req.query["next"] ?? "/"))
                    }'''
            else:
                safe_code = '''
                    defmodule Handler do
                      defp safe_redirect(_value), do: "/home"
                      def handle(conn, params) do
                        redirect(conn, external: safe_redirect(params["next"]))
                      end
                    end'''
            safe = Case(lang, 'redirect', original.name, safe_code, ())
            for attempt, case in enumerate((original, original, safe, safe)):
                with self.subTest(lang=lang, attempt=attempt):
                    result, payload, target = self.scan(
                        case, 'json', attempt='cache-' + str(attempt))
                    self.assert_result(case, 'json', result, payload, target)
                    profile = payload['scanners'][0]['extras']['profile']
                    self.assertEqual(profile['cache_hits'], int(attempt in (1, 3)), payload)

    def test_malformed_scans_remain_partial_and_are_not_cached(self):
        sources = {
            'swift': 'func handle(req: Request) -> Response {\nreturn req.redirect(to: req.query["next"] ?? "/")',
            'elixir': 'defmodule Handler do\ndef handle(conn, params) do\nredirect(conn, external: params["next"])',
        }
        for lang, source in sources.items():
            case = Case(lang, 'redirect', 'malformed-public', source, ())
            for attempt in range(2):
                with self.subTest(lang=lang, attempt=attempt):
                    result, payload, _target = self.scan(
                        case, 'json', attempt='malformed-' + str(attempt))
                    self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                    self.assertEqual(payload['status'], 'partial', payload)
                    self.assertTrue(any(row.get('language') == lang and
                                        row.get('module_error') == 'ANALYZER_ERROR'
                                        for row in payload['failed_modules']), payload)
                    profile = payload['scanners'][0]['extras']['profile']
                    self.assertEqual(profile['cache_hits'], 0, payload)

    def test_security_category_selection_does_not_change_later_answers(self):
        for lang, category in (('swift', 6), ('elixir', 4)):
            original = BY_NAME[lang, 'direct']
            suppressed = Case(lang, original.kind, original.name, original.code, ())
            for attempt, (case, extra) in enumerate((
                    (original, ()),
                    (suppressed, ('--skip=' + str(category),)),
                    (original, ()))):
                with self.subTest(lang=lang, attempt=attempt):
                    result, payload, target = self.scan(
                        case, 'json', extra, attempt='policy-' + str(attempt))
                    self.assert_result(case, 'json', result, payload, target)


if __name__ == '__main__':
    unittest.main()
