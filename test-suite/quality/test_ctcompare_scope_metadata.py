"""GH #143: authorization scopes are metadata; credentials still need safe equality.

Exercise the real source scanners, not just their vocabulary sets. Metadata is
an adjacent identifier term, not a blanket exemption for a name or assignment
that also carries secret material.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import ctcompare_go  # noqa: E402
from ubs_core.analyzers import ctcompare_js  # noqa: E402
from ubs_core.analyzers import ctcompare_py  # noqa: E402
from ubs_core.analyzers import ctcompare_rust  # noqa: E402

LANGUAGES = ("go", "python", "js", "rust")
EXTENSIONS = {"go": ".go", "python": ".py", "js": ".js", "rust": ".rs"}


def identifier(language: str, words: tuple[str, ...]) -> str:
    if language == "go":
        return "".join(word.capitalize() for word in words)
    if language == "js":
        return words[0] + "".join(word.capitalize() for word in words[1:])
    return "_".join(words)


def comparison_source(
    language: str,
    name: str,
    *,
    operator: str = "!=",
    right: str = '"local_clone_only"',
    member: bool = True,
    reverse: bool = False,
    alias: str | None = None,
) -> tuple[str, int]:
    """A valid source snippet and the exact line that would be reported."""
    operand = f"handoff.{name}" if member else name
    if language == "go":
        lines = ["package handoff"]
        if member:
            lines.append(f"type Intent struct {{ {name} string }}")
        param = "handoff Intent" if member else f"{name} string"
        lines.append(f"func check({param}, expected string) bool {{")
        if alias:
            lines.append(f"    {alias} := {operand}")
    elif language == "python":
        param = "handoff" if member else name
        lines = [f"def check({param}, expected):"]
        if alias:
            lines.append(f"    {alias} = {operand}")
    elif language == "js":
        param = "handoff" if member else name
        lines = [f"function check({param}, expected) {{"]
        if alias:
            lines.append(f"    const {alias} = {operand};")
    else:
        lines = [f"struct Intent {{ {name}: String }}"] if member else []
        param = "handoff: &Intent" if member else f"{name}: &str"
        lines.append(f"fn check({param}, expected: &str) -> bool {{")
        if alias:
            lines.append(f"    let {alias} = &{operand};")
    left = alias or operand
    if reverse:
        left, right = right, left
    expression = f"{left} {operator} {right}"
    if language == "rust":
        lines.append(f"    {expression}")
    else:
        suffix = ";" if language == "js" else ""
        lines.append(f"    return {expression}{suffix}")
    comparison_line = len(lines)
    if language != "python":
        lines.append("}")
    return "\n".join(lines) + "\n", comparison_line


def scan_lines(language: str, source: str) -> list[int]:
    if language == "rust":
        return sorted(line for line, _code in ctcompare_rust.scan_file(source))
    artifacts = REPO_ROOT / "test-suite" / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ctcompare-scope-", dir=artifacts) as tmp:
        root = Path(tmp)
        path = root / ("handoff" + EXTENSIONS[language])
        path.write_text(source, encoding="utf-8")
        if language == "python":
            issues: list = []
            ctcompare_py.analyze(path, issues)
        else:
            analyzer = ctcompare_go if language == "go" else ctcompare_js
            issues = analyzer.scan_file(path, root)
        return sorted(line for _path, line, _code in issues)


def operators(language: str) -> tuple[str, ...]:
    return ("==", "!=", "===", "!==") if language == "js" else ("==", "!=")


class ScopeMetadataTests(unittest.TestCase):
    def test_jsx_attributes_do_not_taint_javascript_variables(self) -> None:
        source = '''function Screen({id, className, copyState}) {
  const selected = id === "claude";
  const copied = copyState === "copied";
  return <div className="panel">
    <h2 id="network-heading">Public downloads</h2>
    <p>No credentials or repository ownership needed.</p>
    <p>{className === "panel" ? "Ready" : "Pending"}</p>
  </div>;
}
'''
        self.assertEqual(scan_lines('js', source), [])

    def test_jsx_interpolated_assignments_still_taint_real_aliases(self) -> None:
        source = '''function Screen({authorization, supplied}) {
  let candidate;
  const view = <div title={candidate = authorization}>Public content</div>;
  return candidate === supplied;
}
'''
        self.assertEqual(scan_lines('js', source), [4])

    def test_js_plain_and_conditional_alias_assignments_remain_sensitive(self) -> None:
        for assignment in ('candidate = authorization;',
                           'if (ready) candidate = authorization;',
                           'consume(candidate = authorization);'):
            source = '\n'.join(['function check(authorization, supplied, ready) {',
                                'let candidate;', assignment,
                                'return candidate === supplied;', '}']) + '\n'
            with self.subTest(assignment=assignment):
                self.assertEqual(scan_lines('js', source), [4])

    def test_multiline_jsx_attributes_and_expression_assignments(self) -> None:
        source = '''function Screen({id, className, authorization, supplied}) {
  let candidate;
  const view = <Widget
    id="download-domains"
    className="public"
    title={candidate = authorization}
  >No credentials or ownership needed.</Widget>;
  const selected = id === "claude";
  const styled = className === "public";
  return candidate !== supplied;
}
'''
        self.assertEqual(scan_lines('js', source), [10])

    def test_less_than_does_not_hide_following_secret_assignment(self) -> None:
        for condition in ('count<limit && ready', 'count < limit', 'a>b && c<d'):
            source = '\n'.join(['function check(authorization, supplied) {',
                                'let candidate;', f'if ({condition}) {{',
                                'candidate = authorization;', '}',
                                'return candidate === supplied;', '}']) + '\n'
            with self.subTest(condition=condition):
                self.assertEqual(scan_lines('js', source), [6])

    def test_timing_safe_alias_comparison_remains_clean(self) -> None:
        source = '''function check(authorization, supplied) {
  let candidate;
  candidate = authorization;
  return crypto.timingSafeEqual(candidate, supplied);
}
'''
        self.assertEqual(scan_lines('js', source), [])

    def test_reported_authorization_scope(self) -> None:
        # The report's exact member/literal inequality, once per language.
        for language in LANGUAGES:
            with self.subTest(language=language):
                name = identifier(language, ("authorization", "scope"))
                operator = "!==" if language == "js" else "!="
                source, _line = comparison_source(language, name, operator=operator)
                self.assertEqual(scan_lines(language, source), [])

    def test_singular_and_plural_scopes(self) -> None:
        for language in LANGUAGES:
            for prefix in ("authorization", "token"):
                for suffix in ("scope", "scopes"):
                    name = identifier(language, (prefix, suffix))
                    for member in (False, True):
                        for operator in operators(language):
                            for reverse in (False, True):
                                with self.subTest(language=language, name=name, member=member,
                                                  operator=operator, reverse=reverse):
                                    source, _line = comparison_source(
                                        language, name, operator=operator, member=member,
                                        reverse=reverse, right='"read"',
                                    )
                                    self.assertEqual(scan_lines(language, source), [])

    def test_identifier_spelling_variants(self) -> None:
        for language in LANGUAGES:
            for name in ("authorization_scope", "authorizationScope", "AuthorizationScope",
                         "AUTHORIZATION_SCOPE", "AUTHORIZATION_SCOPES"):
                with self.subTest(language=language, name=name):
                    source, _line = comparison_source(language, name, member=False)
                    self.assertEqual(scan_lines(language, source), [])

    def test_scope_assignment_does_not_taint_an_alias(self) -> None:
        for language in LANGUAGES:
            for suffix in ("scope", "scopes"):
                with self.subTest(language=language, suffix=suffix):
                    name = identifier(language, ("authorization", suffix))
                    source, _line = comparison_source(language, name, alias="value")
                    self.assertEqual(scan_lines(language, source), [])


class CredentialDetectionTests(unittest.TestCase):
    def assert_sensitive(self, language: str, name: str, **kwargs) -> None:
        source, line = comparison_source(language, name, right="expected", **kwargs)
        self.assertEqual(scan_lines(language, source), [line], source)

    def test_real_credentials_still_reported(self) -> None:
        for language in LANGUAGES:
            for words in (("authorization", "token"), ("password",), ("api", "key"),
                          ("auth", "token"), ("signature",), ("hmac",)):
                name = identifier(language, words)
                for member in (False, True):
                    for operator in operators(language):
                        for reverse in (False, True):
                            with self.subTest(language=language, name=name, member=member,
                                              operator=operator, reverse=reverse):
                                self.assert_sensitive(language, name, member=member,
                                                      operator=operator, reverse=reverse)

    def test_scope_is_not_a_blanket_secret_exemption(self) -> None:
        cases = (
            ("scope", "authorization"),
            ("scopes", "authorization"),
            ("authorization", "scoped"),
            ("authorization", "scopeless"),
            ("authorization", "granted", "scope"),
            ("authorization", "scope", "secret"),
            ("authorization", "scopes", "password"),
            ("authorization", "scope", "api", "key"),
        )
        for language in LANGUAGES:
            for words in cases:
                name = identifier(language, words)
                with self.subTest(language=language, name=name):
                    self.assert_sensitive(language, name)

    def test_secret_assignment_still_taints_a_scope_named_alias(self) -> None:
        for language in LANGUAGES:
            for words in (("authorization", "token"), ("password",)):
                for suffix in ("scope", "scopes"):
                    name = identifier(language, words)
                    alias = identifier(language, ("authorization", suffix))
                    with self.subTest(language=language, name=name, alias=alias):
                        self.assert_sensitive(language, name, alias=alias)

    def test_js_comment_views_keep_multiline_suppression_local(self) -> None:
        source = '\n'.join([
            'function check(req, expectedAuthToken) {',
            'const publicUrl = "https://example.org/token";',
            'const alias = req.headers.authorization;',
            '// ubs:ignore -- comparison below is deliberate',
            'if (alias',
            '    !== expectedAuthToken) {',
            '  return false;',
            '}',
            'if (alias !== expectedAuthToken) {',
            '  return false;',
            '}',
            'if (alias !== expectedAuthToken) {',
            '  // ubs:ignore -- relocated block-opening marker',
            '  return false;',
            '}',
            'if (alias !== expectedAuthToken) { // ubs:ignore -- trailing marker',
            '  return false;',
            '}',
            'if (alias !== expectedAuthToken) {',
            '  return false;',
            '}',
            '}',
        ]) + '\n'
        self.assertEqual(scan_lines('js', source), [9, 19], source)

    def test_js_continued_operands_preserve_quotes_and_physical_lines(self) -> None:
        source = '\n'.join([
            'function check(request, expectedPassword) {',
            'const password = request.password;',
            'const value = password;',
            'const publicUrl = "https://example.org/a//b";',
            'if (publicUrl === "https://example.org/a//b") {',
            '  return true;',
            '}',
            'if (value',
            '    === expectedPassword) {',
            '  return true;',
            '}',
            'const comment = "/* public metadata */";',
            'if (value /* explanatory comment */ !== expectedPassword) {',
            '  return false;',
            '}',
            '}',
        ]) + '\n'
        self.assertEqual(scan_lines('js', source), [9, 13], source)


class CallResultMetadataTests(unittest.TestCase):
    """GH #181, #185: a call result's public discriminant is not the secret.

    `openAuthSessionAsync(authorization.authorize_url)` taints `result`
    through its callee name and argument; `result.type` is the returned
    status, while aliases and value members of a secret stay reported.
    """

    def test_reported_auth_session_discriminants_are_clean(self) -> None:
        for source in (
            # GH #181
            'import * as WebBrowser from "expo-web-browser";\n\n'
            'export async function connect(authorization: { authorize_url: string }) {\n'
            '  const result = await WebBrowser.openAuthSessionAsync(authorization.authorize_url, "example:///callback");\n'
            '  if (result.type !== "success") return "cancelled";\n'
            '  return result.url;\n'
            '}\n',
            # GH #185
            'import * as WebBrowser from "expo-web-browser";\n\n'
            'export async function connect(authorizeUrl: string, redirectUri: string): Promise<string> {\n'
            '  const result = await WebBrowser.openAuthSessionAsync(authorizeUrl, redirectUri);\n'
            '  if (result.type !== "success") {\n'
            '    throw new Error("auth cancelled");\n'
            '  }\n'
            '  return result.url;\n'
            '}\n',
            # Member chains, TypeScript assertions, parentheses and assignment heads.
            'export async function f(authorizeUrl: string, creds: string) {\n'
            '  const result = await WebBrowser.openAuthSessionAsync(authorizeUrl, "x") as AuthResult;\n'
            '  const session = makeAuthClient(creds).connect();\n'
            '  if ((result!.type) !== "success") return 1;\n'
            '  if (result?.error.kind === "dismiss") return 2;\n'
            '  const open = session.state === "open";\n'
            '  return open;\n'
            '}\n',
        ):
            with self.subTest(source=source):
                self.assertEqual(scan_lines('js', source), [], source)

    def test_reported_positive_controls_stay_reported(self) -> None:
        controls = (
            # GH #181 controls: scalar, value member and metadata member of an alias.
            'export function scalar(supplied: string, authorization: string) {\n'
            '  const result = authorization;\n'
            '  return result === supplied;\n'
            '}\n',
            'export function member(supplied: string, authorization: { value: string }) {\n'
            '  const result = authorization;\n'
            '  return result.value === supplied;\n'
            '}\n',
            'export function namedType(supplied: string, authorization: { type: string }) {\n'
            '  const result = authorization;\n'
            '  return result.type === supplied;\n'
            '}\n',
            # GH #185 control.
            'export function check(authToken: string, storedAuthToken: string): boolean {\n'
            '  return authToken === storedAuthToken;\n'
            '}\n',
        )
        for source in controls:
            with self.subTest(source=source):
                self.assertEqual(len(scan_lines('js', source)), 1, source)

    def test_call_results_keep_secret_values(self) -> None:
        source = '\n'.join([
            'export async function f(authorization: any, authorizeUrl: string, supplied: string) {',
            '  const token = getAuthToken();',
            '  const exchanged = await exchange(authorization);',
            '  let mixed = await WebBrowser.openAuthSessionAsync(authorizeUrl, "x");',
            '  mixed = authorization;',
            '  const member = (await login(authorization)).authSession;',
            '  if (token === supplied) return 1;',
            '  if (exchanged.accessToken === supplied) return 2;',
            '  if (exchanged.authTokenId === supplied) return 3;',
            '  if (mixed.type === supplied) return 4;',
            '  if (member.type === supplied) return 5;',
            '  return 0;',
            '}',
        ]) + '\n'
        # A scalar call result, a secret-named member, a name that was also
        # assigned a secret alias, and a member read before assignment.
        self.assertEqual(scan_lines('js', source), [7, 8, 9, 10, 11], source)


if __name__ == "__main__":
    unittest.main()
