"""GH #143: authorization scopes are metadata; credentials still need safe equality.

Exercise the real source scanners, not just their vocabulary sets. Metadata is
an adjacent identifier term, not a blanket exemption for a name or assignment
that also carries secret material.
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
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
    # Keep the actual scanner inputs for inspection, including failed cases.
    # Repository policy forbids deleting fixtures after an assertion runs.
    root = Path(tempfile.mkdtemp(prefix="ctcompare-scope-", dir=artifacts))
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


class GoCollectorRootTests(unittest.TestCase):
    def test_requested_root_exempts_ancestors_but_not_ignored_children(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="ctcompare-go-root-", dir=artifacts))
        code, line = comparison_source("go", "SessionToken", right="expected", member=False)
        for ancestor in ("build", "vendor"):
            with self.subTest(ancestor=ancestor):
                project = work / ancestor / "project"
                project.mkdir(parents=True)
                source = project / "session.go"
                source.write_text(code, encoding="utf-8")
                generated = project / "build"
                generated.mkdir()
                excluded = generated / "generated.go"
                excluded.write_text(code, encoding="utf-8")
                other = project / "notes.txt"
                other.write_text(code, encoding="utf-8")

                self.assertEqual([source], list(ctcompare_go.iter_files(project)))
                self.assertEqual(
                    [("session.go", line)],
                    [(name, row) for name, row, _ in ctcompare_go.collect_issues(project)],
                )
                # Explicit selection keeps its existing semantics even when
                # the same directory would be pruned from its parent walk.
                self.assertEqual([excluded], list(ctcompare_go.iter_files(generated)))
                self.assertEqual([excluded], list(ctcompare_go.iter_files(excluded)))
                for selected in (generated, excluded):
                    with self.subTest(selected=selected):
                        self.assertEqual(
                            [("generated.go", line)],
                            [(name, row) for name, row, _ in ctcompare_go.collect_issues(selected)],
                        )
                self.assertEqual([], list(ctcompare_go.iter_files(other)))


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


class JavascriptAssignmentOperandTests(unittest.TestCase):
    def test_type_guard_assignment_does_not_compare_its_destination(self):
        for destination in ("const token", "let authToken", "var secret", "credential", "state.authToken"):
            for operator in operators("js"):
                with self.subTest(destination=destination, operator=operator):
                    source = f'{destination} = typeof link {operator} "string" ? new URL(link).searchParams.get("t") : null;\n'
                    self.assertEqual(scan_lines("js", source), [])

    def test_chained_and_compound_assignments_bound_the_right_hand_comparison(self):
        for assignment in ("=", "+=", "-=", "*=", "/=", "%=", "**=", "&&=", "||=", "??=", "&=", "|=", "^=", "<<=", ">>=", ">>>="):
            with self.subTest(assignment=assignment):
                source = f'authToken {assignment} secret = typeof link === "string";\n'
                self.assertEqual(scan_lines("js", source), [])
                unsafe = f'authToken {assignment} result = password === supplied;\n'
                self.assertEqual(scan_lines("js", unsafe), [1])

    def test_assigned_secret_comparisons_remain_findings(self):
        for operator in operators("js"):
            for left in ("password", "authToken", "credentials.secret"):
                with self.subTest(operator=operator, left=left):
                    self.assertEqual(scan_lines("js", f'const result = {left} {operator} supplied;\n'), [1])
        self.assertEqual(scan_lines("js", 'const alias = password;\nconst result = alias === supplied;\n'), [2])

    def test_nested_assignment_is_an_operand_not_an_outer_boundary(self):
        for expression in (
            '(authToken = supplied) === expected',
            '(authToken ||= supplied) === expected',
            '(authToken = other = supplied) === expected',
            'authToken === (other = supplied)',
            '(authToken += suffix) === supplied',
            'state[password === supplied] = typeof link === "string"',
        ):
            with self.subTest(expression=expression):
                self.assertEqual(scan_lines("js", f'const result = {expression};\n'), [1])

    def test_type_guard_does_not_hide_adjacent_or_conditional_secret_comparisons(self):
        source = '''const token = typeof link === "string" ? link : null;
if (typeof link !== "string" || authToken === supplied) return false;
const result = typeof link === "string" ? password === supplied : false;
const other = typeof link === "string" ? true : password === supplied;
'''
        self.assertEqual(scan_lines("js", source), [2, 3, 4])

    def test_typeof_compound_operands_keep_the_secret(self):
        for expression in ('typeof link + password', 'typeof link + ":" + authToken'):
            with self.subTest(expression=expression):
                self.assertEqual(scan_lines("js", f'const result = {expression} === supplied;\n'), [1])

    def test_arrow_and_quoted_assignment_text_do_not_hide_secrets(self):
        for expression in (
            'authToken === "typeof value"',
            'authToken === "a=b"',
            'authToken === "left => right"',
            'authToken === `value=${supplied}`',
            'row => row.authToken === supplied',
            '(authToken) => authToken === supplied',
        ):
            with self.subTest(expression=expression):
                self.assertEqual(scan_lines("js", f'const result = {expression};\n'), [1])

    def test_assignment_text_inside_regular_expressions_is_not_a_boundary(self):
        for literal in ('/x=y/', '/[=]/', r'/a\/=b/'):
            with self.subTest(literal=literal):
                source = f'const result = authToken + {literal}.source === supplied;\n'
                self.assertEqual(scan_lines("js", source), [1])


class JavascriptParameterBindingTests(unittest.TestCase):
    """A new parameter binding cannot inherit an unrelated local's value."""

    def assert_sites(self, body):
        source = 'const r = password;\n' + textwrap.dedent(body)
        expected = [number for number, line in enumerate(source.splitlines(), 1)
                    if '// expect-secret' in line]
        self.assertEqual(scan_lines('js', source), expected, source)

    def test_callback_parameter_shadows_unrelated_secret_alias(self):
        self.assert_sites('''
            const sent = rows(w).filter((r) => r.status === "sent").length;
            const selected = rows.filter(r => r.value === supplied);
            const block = rows.filter((r: Row) => {
                return r.status === "sent";
            });
            const ordinary = rows.filter(function (r) { return r.value === supplied; });
            const captured = rows.filter(r => (() => r.value === supplied)());
            const secretMember = rows.filter(r => r.password === supplied); // expect-secret
            const secretName = rows.filter(password => password === supplied); // expect-secret
            const outside = r.value === supplied; // expect-secret
        ''')

    def test_secret_defaults_destructuring_and_reassignments_remain_findings(self):
        self.assert_sites('''
            const defaults = rows.filter((r = password) => r.value === supplied); // expect-secret
            const destructured = rows.filter(({password: r}) => r === supplied); // expect-secret
            const destructuredDefault = rows.filter(({value: r = password}) => r === supplied); // expect-secret
            const reassigned = rows.filter(r => { r = password; return r.value === supplied; }); // expect-secret
            const propertyWrite = rows.filter(r => { r.value = password; return r.value === supplied; }); // expect-secret
            const assignmentPattern = rows.filter(r => { ({password: r} = credentials); return r === supplied; }); // expect-secret
            const tightPattern = rows.filter(r => { ({password:r}=credentials); return r === supplied; }); // expect-secret
            const escaped = rows.filter(r => { mutate(r); return r.value === supplied; }); // expect-secret
            const mutated = rows.filter(r => { r.mutate(); return r.value === supplied; }); // expect-secret
            const aliased = rows.filter(r => { const alias = r; alias.value = password; return r.value === supplied; }); // expect-secret
            const captured = rows.filter(row => r.value === supplied); // expect-secret
            const nested = rows.filter(r => ((r = password) => r.value === supplied)()); // expect-secret
            const closedOverWrite = rows.filter(r => {
                function write() { r = password; }
                write();
                return r.value === supplied; // expect-secret
            });
        ''')

    def test_callback_secret_inputs_are_not_reclassified_by_shadowing(self):
        self.assert_sites('''
            const direct = [r].filter(r => r.value === supplied); // expect-secret
            const named = credentials.filter(r => r.value === supplied); // expect-secret
            const nested = getRows(password).filter(r => r.value === supplied); // expect-secret
            const continued = credentials
                .filter(r => r.value === supplied); // expect-secret
            const nextLine = [r].filter(
                r => r.value === supplied); // expect-secret
        ''')

    def test_new_parameter_does_not_inherit_old_call_result_metadata_evidence(self):
        source = '''const r = await login(password);
rows.filter((r = password) => r.status === supplied);
rows.filter(r => { r = password; return r.status === supplied; });
rows.filter(({password: r}) => r.status === supplied);
'''
        self.assertEqual(scan_lines('js', source), [2, 3, 4])

    def test_boolean_operands_and_comments_keep_their_own_scope(self):
        self.assert_sites('''
            const both = rows.filter(r => r.status === "sent" && r.mode !== "hidden");
            const comment = rows.filter(/* public row */ (r) => r.status === "sent");
            /* before callback */ rows.filter(r => r.status === "sent");
            rows.filter(r => r.status === "sent"); /* keep outside */ r.value === supplied; // expect-secret
            const mixed = rows.filter(r => r.status === "sent" && password === supplied); // expect-secret
        ''')

    def test_callback_inputs_resolve_the_local_declaration_not_another_function(self):
        self.assert_sites('''
            async function earlier() {
                const w = await world({SESSION_SECRET: password});
                const r = await requestMagicLink(w, SECRET);
                return r;
            }
            async function current() {
                const w = await world();
                return rows(w).filter((r) => r.status === "sent").length;
            }
            async function actualSecretInput() {
                const w = password;
                const alias = w;
                return rows(alias).filter((r) => r.value === supplied); // expect-secret
            }
        ''')

    def test_object_inputs_and_block_shadows_retain_captured_secrets(self):
        self.assert_sites('''
            const wrapped = getRows({value: password}).filter(r => r.value === supplied); // expect-secret
            const indirect = getRows({value: r}).filter(r => r.value === supplied); // expect-secret
            const data = password;
            function captured() {
                if (ready) { const data = []; use(data); }
                return data.filter(r => r.value === supplied); // expect-secret
            }
            function loopLocal() {
                for (let data of publicRows) use(data);
                return data.filter(r => r.value === supplied); // expect-secret
            }
            const deeplyWrapped = getRows({value: (() => { observe(); return password; })()}).filter(r => r.value === supplied); // expect-secret
        ''')

    def test_named_function_metadata_policy_is_not_changed_by_callback_repair(self):
        self.assert_sites('''
            async function derive() { const keys = await loadKeys(secret); return keys; }
            function publicId(keys) { return keys.id === supplied; }
            function nestedId(keys) { return rows.some(row => row.key_id === keys.id); }
            function actualMaterial(keys) { return keys.value === supplied; } // expect-secret
            function namedMaterial(keys) { return keys.hmac === supplied; } // expect-secret
        ''')


class JavascriptLocalBindingTests(unittest.TestCase):
    """Real aliases and mutations must retain conservative detection."""

    def test_secret_aliases_captures_and_object_writes_remain_findings(self):
        source = '''function earlier(authorization) {
  const result = authorization;
  return () => result.value === supplied;
}
function actual(authorization) {
  const result = authorization;
  return result.value === supplied;
}
function indirect(authorization) {
  const source = authorization;
  const result = source;
  return result.value === supplied;
}
function mutated(response, authorization) {
  const result = response.json();
  result.value = authorization;
  return result.value === supplied;
}
function nestedMutation(response, authorization) {
  const result = response.json();
  function fill() { result.value = authorization; }
  fill();
  return result.value === supplied;
}
'''
        self.assertEqual(scan_lines('js', source), [3, 7, 12, 17, 23], source)

    def test_block_locals_do_not_clear_an_outer_secret(self):
        source = '''const result = authorization;
function current(response) {
  if (ready) { const result = response.json(); use(result); }
  return result.value === supplied;
}
'''
        self.assertEqual(scan_lines('js', source), [4], source)

    def test_aliases_destructuring_computed_writes_and_escapes_keep_taint(self):
        source = '''function earlier(authorization) { const result = authorization; }
function alias(response, authorization) {
  const source = response.json();
  const result = source;
  source.value = authorization;
  return result.value === supplied; // expect-secret
}
function pattern(response, authorization) {
  const result = response.json();
  ({value: result.value} = authorization);
  return result.value === supplied; // expect-secret
}
function computed(response, authorization) {
  const result = response.json();
  result[
    field
  ] = authorization;
  return result.value === supplied; // expect-secret
}
function method(response, authorization) {
  const result = response.json();
  result.fill(authorization);
  return result.value === supplied; // expect-secret
}
function escaped(response, authorization) {
  const result = response.json();
  fill({record: result}, authorization);
  return result.value === supplied; // expect-secret
}
'''
        expected = [line for line, code in enumerate(source.splitlines(), 1)
                    if '// expect-secret' in code]
        self.assertEqual(scan_lines('js', source), expected, source)

    def test_asserted_escapes_optional_calls_and_shadowed_classes_keep_taint(self):
        for mutation in (
            'result!.value = authorization;',
            '(result as Box).value = authorization;',
            'fill(result!, authorization);',
            'fill(result as Box, authorization);',
            'result.fill?.(authorization);',
            'fill(result.nested, authorization);',
        ):
            field = 'nested.value' if 'result.nested' in mutation else 'value'
            source = ('function earlier(authorization) { const result = authorization; }\n'
                      'function current(authorization) {\n'
                      '  const result = readBox();\n'
                      f'  {mutation}\n'
                      f'  return result.{field} === supplied;\n'
                      '}\n')
            with self.subTest(mutation=mutation):
                self.assertEqual(scan_lines('js', source), [5], source)
        source = '''function earlier(authorization) { const result = authorization; }
function classShadow(response) {
  const result = response.json();
  function inner(authorization) {
    class result { static value = authorization; }
    return result.value === supplied;
  }
}
'''
        self.assertEqual(scan_lines('js', source), [6], source)

    def test_secret_receiver_returned_alias_keeps_taint(self):
        source = '''function earlier(authorization) { const output = authorization; }
function wrap(value) { return {value}; }
function unsafe(authorization, supplied) {
  const record = wrap(authorization);
  const output = record.valueOf();
  return output.value === supplied;
}
'''
        self.assertEqual(scan_lines('js', source), [6], source)


class CallResultMetadataTests(unittest.TestCase):
    """GH #181, #185: a call result's public discriminant is not the secret.

    `openAuthSessionAsync(authorization.authorize_url)` taints `result`
    through its callee name and argument; `result.type` is the returned
    status, while aliases and value members of a secret stay reported.
    """

    def test_multiline_call_results_keep_metadata_and_secret_members_distinct(self):
        for field in ('createdAt', 'updatedAt', 'expiresAt', 'collaborativeFlowId'):
            for padding in (0, 6, 20):
                source = ('async function current(authorization, supplied) {\n'
                          '  const result = await exchange({\n'
                          '    authorization,\n'
                          + '    value: 1,\n' * padding
                          + '  });\n'
                          + f'  const metadata = result.{field} === supplied;\n'
                          + '  return result.accessToken === supplied;\n'
                          + '}\n')
                with self.subTest(field=field, padding=padding):
                    self.assertEqual(scan_lines('js', source), [6 + padding], source)

    def test_timestamp_named_secret_and_plain_alias_stay_reported(self):
        for value in ('authorization', 'await exchange(authorization).value'):
            source = ('async function current(authorization, supplied) {\n'
                      f'  const result = {value};\n'
                      '  return result.updatedAt === supplied;\n'
                      '}\n')
            with self.subTest(value=value):
                self.assertEqual(scan_lines('js', source), [3], source)
        source = ('async function current(authorization, supplied) {\n'
                  '  const result = await exchange(authorization);\n'
                  '  return result.authTokenUpdatedAt === supplied;\n'
                  '}\n')
        self.assertEqual(scan_lines('js', source), [3], source)

    def test_arrow_body_assignments_are_not_lost_when_reading_complete_rhs(self):
        source = '''let value;
const capture =
  run(() => value = authorization);
if (value === supplied) deny();
'''
        self.assertEqual(scan_lines('js', source), [4], source)
        source = '''const value =
  authorization;
if (value === supplied) deny();
'''
        self.assertEqual(scan_lines('js', source), [3], source)

    def test_next_line_member_reads_and_operators_do_not_become_call_results(self):
        for continuation in ('.value', '?.value', '[field]', '+ authorization'):
            source = ('async function current(authorization, supplied) {\n'
                      '  const result = exchange(authorization)\n'
                      f'    {continuation};\n'
                      '  return result.updatedAt === supplied;\n'
                      '}\n')
            with self.subTest(continuation=continuation):
                self.assertEqual(scan_lines('js', source), [4], source)

    def test_call_result_property_writes_cannot_hide_secret_timestamps(self):
        for write in ('result.updatedAt = authorization;',
                      'result["updatedAt"] = authorization;',
                      '(result).updatedAt = authorization;',
                      '(result as Record).updatedAt = authorization;',
                      'const alias = result; alias.updatedAt = authorization;'):
            for name in ('result', 'result$'):
                source = ('async function current(authorization, supplied) {\n'
                          f'  const {name} = exchange(authorization);\n'
                          f'  {write.replace("result", name)}\n'
                          f'  return {name}.updatedAt === supplied;\n'
                          '}\n')
                with self.subTest(write=write, name=name):
                    self.assertEqual(scan_lines('js', source), [4], source)

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


class StructuralFingerprintTests(unittest.TestCase):
    """GH #195: local record fingerprints have a role; the name alone does not."""

    RECORDS = textwrap.dedent('''\
        from dataclasses import dataclass, field
        @dataclass(frozen=True)
        class Value:
            status: int = 0
            origins: frozenset[str] = frozenset()
        @dataclass
        class State:
            exit: str = ""
            values: dict[str, Value] = field(default_factory=dict)
            def signature(self):
                return self.exit, tuple(sorted(self.values.items()))
    ''')

    def reports(self, suffix, prefix=None):
        source = (self.RECORDS if prefix is None else prefix) + textwrap.dedent(suffix)
        return [code for _path, _line, code in ctcompare_py._scan_code(source)]

    def test_state_fingerprints_in_typed_pending_collection(self):
        self.assertEqual(self.reports('''
            class Flow:
                def __init__(self):
                    self.exceptions: list[list[State]] = []
                def note_exception(self, state: State):
                    if not self.exceptions:
                        return
                    pending = self.exceptions[-1]
                    signature = state.signature()
                    if all(previous.signature() != signature for previous in pending):
                        pending.append(state)
        '''), [])

    def test_constructor_result_and_single_assignment_aliases(self):
        self.assertEqual(self.reports('''
            def check():
                state = State()
                signature = state.signature()
                saved_signature = signature
                return saved_signature == State().signature()
        '''), [])

    def test_unknown_signature_method_and_parameter_stay_reported(self):
        source = 'def is_new(pending, signature):\n    return all(previous.signature() != signature for previous in pending)\n'
        self.assertEqual(scan_lines('python', source), [2])
        self.assertEqual(self.reports('''
            def verify(unrelated, expected):
                return unrelated.signature() == expected
        '''), ['return unrelated.signature() == expected'])

    def test_real_secret_operands_win_over_public_fingerprint(self):
        self.assertEqual(self.reports('''
            def verify(state: State, password, expected, secret):
                password = state.signature()
                public = state.signature()
                return password == expected, public == secret
        '''), ['return password == expected, public == secret'])
        self.assertEqual(self.reports('''
            import hmac
            def verify(state: State, key, body):
                return state.signature() == hmac.new(key, body, 'sha256').digest()
        '''), ["return state.signature() == hmac.new(key, body, 'sha256').digest()"])

    def test_secret_bearing_tuple_and_security_qualified_method_stay_reported(self):
        for body in ('return self.password, tuple(sorted(self.values.items()))',
                     'return hmac.new(self.exit, self.values).digest(), 0',
                     'return unknown(), tuple(sorted(self.values.items()))'):
            with self.subTest(body=body):
                prefix = self.RECORDS.replace('return self.exit, tuple(sorted(self.values.items()))', body)
                self.assertEqual(self.reports('''
                    def verify(state: State, expected):
                        return state.signature() == expected
                ''', prefix), ['return state.signature() == expected'])
        prefix = self.RECORDS.replace('def signature(self)', 'def hmac_signature(self)')
        self.assertEqual(self.reports('''
            def verify(state: State, expected):
                return state.hmac_signature() == expected
        ''', prefix), ['return state.hmac_signature() == expected'])

    def test_opaque_tuple_and_constructor_alias_do_not_prove_public(self):
        for initialize in ('self.value = password', 'self.value = hmac.new(key, body).digest()'):
            with self.subTest(initialize=initialize):
                prefix = ('class Record:\n'
                          '    def __init__(self, password, key, body):\n'
                          f'        {initialize}\n'
                          '    def signature(self):\n'
                          '        return (self.value,)\n')
                self.assertEqual(self.reports('''
                    def verify(record: Record, expected):
                        return record.signature() == expected
                ''', prefix), ['return record.signature() == expected'])
        prefix = self.RECORDS.replace('    def signature(self):',
                                    '    def __init__(self, password):\n        self.exit = password\n'
                                    '    def signature(self):')
        self.assertEqual(self.reports('''
            def verify(state: State, expected):
                return state.signature() == expected
        ''', prefix), ['return state.signature() == expected'])

    def test_rebinding_and_misleading_local_annotations_do_not_prove_receiver(self):
        cases = (
            'def verify(state: State, other, expected):\n    state = other\n    return state.signature() == expected\n',
            'def verify(state: State, other, flag, expected):\n    if flag:\n        state = other\n    return state.signature() == expected\n',
            'def verify(other, expected):\n    state: State = other\n    return state.signature() == expected\n',
            'def verify(State, expected):\n    state = State()\n    return state.signature() == expected\n',
            'State = foreign_class\ndef verify(state: State, expected):\n    return state.signature() == expected\n',
            'def verify(password, expected):\n    state = State(password)\n    return state.signature() == expected\n',
            'def verify(password, expected):\n    payload = password\n    state = State({"x": Value(payload)})\n    return state.signature() == expected\n',
            'def verify(state: State, password, expected):\n    state.values = {"x": Value(password)}\n    return state.signature() == expected\n',
            'def verify(state: State, password, expected):\n    payload = password\n    state.values["x"] = Value(payload)\n    return state.signature() == expected\n',
            'def verify(state: State, password, expected):\n    state.values.update({"x": Value(password)})\n    return state.signature() == expected\n',
            'def verify(state: State, password, expected):\n    state.exit: str = password\n    return state.signature() == expected\n',
            'def verify(state: State, password, expected):\n    state.values |= {"x": password}\n    return state.signature() == expected\n',
            'def verify(secret: State, expected):\n    state = secret\n    return state.signature() == expected\n',
            'def verify(state: State, password, expected):\n    values = state.values\n    values["x"] = password\n    return state.signature() == expected\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(self.reports(source), ['return state.signature() == expected'])

    def test_monkey_patches_reflection_and_escaped_objects_remain_sensitive(self):
        cases = (
            'State.signature = get_password\ndef verify(state: State, expected):\n    return state.signature() == expected\n',
            'mutate(State)\ndef verify(state: State, expected):\n    return state.signature() == expected\n',
            'def verify(state: State, expected):\n    mutate(state)\n    return state.signature() == expected\n',
            'def verify(state: State, expected):\n    alias = state\n    mutate(alias)\n    return state.signature() == expected\n',
            'setattr(State, "signature", get_password)\ndef verify(state: State, expected):\n    return state.signature() == expected\n',
            'Alias = State\nmutate(Alias)\ndef verify(state: State, expected):\n    return state.signature() == expected\n',
            'def verify(state: State, expected):\n    mutate([state])\n    return state.signature() == expected\n',
            'def verify(state: State, expected):\n    holder = [state]\n    mutate(holder)\n    return state.signature() == expected\n',
            'def verify(state: State, expected):\n    holder: list[State] = [state]\n    mutate(holder)\n    return state.signature() == expected\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(self.reports(source), ['return state.signature() == expected'])

    def test_subclasses_custom_new_descriptors_and_factories_stay_sensitive(self):
        prefixes = (
            self.RECORDS + 'class Credential(State):\n    def signature(self):\n        return self.password\n',
            self.RECORDS.replace('    def signature(self):',
                                 '    def __new__(cls):\n        return credential\n    def signature(self):'),
            self.RECORDS.replace('    def signature(self):',
                                 '    @property\n    def exit(self):\n        return self.password\n    def signature(self):'),
            self.RECORDS.replace('field(default_factory=dict)', 'field(default_factory=get_password)'),
            self.RECORDS.replace('@dataclass\nclass State', '@dataclass(frozen=dynamic())\nclass State'),
            self.RECORDS.replace('values: dict[str, Value]', 'values: dict[str, object]'),
            self.RECORDS.replace('status: int = 0', 'data: str = ""'),
            self.RECORDS.replace('exit: str = ""', 'exit: str = "hunter2"'),
            self.RECORDS.replace('    def signature(self):',
                                 '    def __post_init__(self):\n        self.exit = password\n    def signature(self):'),
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assertEqual(self.reports('''
                    def verify(state: State, expected):
                        return state.signature() == expected
                ''', prefix), ['return state.signature() == expected'])

    def test_secret_constructor_or_field_write_in_caller_defeats_record_contract(self):
        for prepare in ('state = State({"x": Value(payload)})',
                        'state = State()\n    state.exit = payload',
                        'state = State()\n    fields = state.values\n    fields["x"] = payload',
                        'state = State()\n    fields = state.values\n    alias = fields\n    alias["x"] = payload'):
            source = ('def caller(password, expected):\n'
                      '    payload = password\n'
                      f'    {prepare}\n'
                      '    return verify(state, expected)\n'
                      'def verify(state: State, expected):\n'
                      '    return state.signature() == expected\n')
            with self.subTest(prepare=prepare):
                self.assertEqual(self.reports(source), ['return state.signature() == expected'])

    def test_fingerprint_role_does_not_cross_shadowing_scopes(self):
        self.assertEqual(self.reports('''
            def outer(state: State):
                signature = state.signature()
                def inner(signature, expected):
                    return signature == expected
                return lambda signature: signature == "supplied"
        '''), ['return signature == expected', 'return lambda signature: signature == "supplied"'])
        self.assertEqual(self.reports('''
            def verify(state: State, unknown, expected):
                return all(state.signature() == expected for state in unknown)
        '''), ['return all(state.signature() == expected for state in unknown)'])
        self.assertEqual(self.reports('''
            def verify(passwords: list[State], expected):
                return all(state.signature() == expected for state in passwords)
        '''), ['return all(state.signature() == expected for state in passwords)'])
        self.assertEqual(self.reports('''
            def verify(state: State, password, expected):
                checks = (state.signature() == expected for index in [0])
                state.exit = password
                return all(checks)
        '''), ['checks = (state.signature() == expected for index in [0])'])
        self.assertEqual(self.reports('''
            def verify(state: State, expected):
                ignored = [mutate(state) for index in [0]]
                return state.signature() == expected
        '''), ['return state.signature() == expected'])

    def test_actual_csharp_state_fingerprint_needs_no_suppression(self):
        path = HELPERS_DIR / 'ubs_core/analyzers/narrowing_csharp.py'
        source = path.read_text(encoding='utf-8')
        self.assertNotIn('ubs:ignore[python.ctcompare.secret_eq]', source)
        self.assertEqual(ctcompare_py._scan_code(source), [])


class PythonSecretComparisonFlowTests(unittest.TestCase):
    """Public fingerprint evidence must not erase a possible credential."""

    def assert_sites(self, source):
        code = StructuralFingerprintTests.RECORDS + textwrap.dedent(source)
        expected = [number for number, line in enumerate(code.splitlines(), 1)
                    if '# expect-secret' in line]
        actual = [line for _path, line, _code in ctcompare_py._scan_code(code)]
        self.assertEqual(actual, expected, code)

    def test_conditional_public_overwrite_preserves_secret_on_other_path(self):
        self.assert_sites('''
            def verify(state: State, password, supplied, flag):
                value = password
                if flag:
                    value = state.signature()
                return value == supplied  # expect-secret
        ''')
        for first, second in (('password', 'state.signature()'), ('state.signature()', 'password')):
            with self.subTest(first=first):
                self.assert_sites(
                    'def verify(state: State, password, supplied, flag):\n'
                    '    if flag:\n'
                    f'        value = {first}\n'
                    '    else:\n'
                    f'        value = {second}\n'
                    '    return value == supplied  # expect-secret\n'
                )

    def test_public_overwrite_on_every_normal_branch_is_clean(self):
        source = '''
            def verify(state: State, password, supplied, flag):
                value = password
                if flag:
                    value = state.signature()
                else:
                    value = State().signature()
                return value == supplied
        '''
        self.assert_sites(source)
        self.assert_sites(source.replace('password', 'public_label'))

    def test_zero_iteration_loops_and_exception_paths_preserve_secret_aliases(self):
        bodies = (
            'for item in items:\n        value = state.signature()',
            'while items:\n        value = state.signature()\n        break',
            'try:\n        value = state.signature()\n    except Exception:\n        pass',
        )
        if sys.version_info >= (3, 10):
            bodies += ('match items:\n        case []:\n            value = state.signature()',)
        for body in bodies:
            with self.subTest(body=body):
                source = (
                    'def verify(state: State, password, supplied, items):\n'
                    '    value = password\n'
                    '    ' + body + '\n'
                    '    return value == supplied  # expect-secret\n'
                )
                self.assert_sites(source)
                self.assert_sites(source.replace('password', 'public_label').replace('  # expect-secret', ''))

    def test_secret_container_literal_and_alias_comparisons_remain_findings(self):
        self.assert_sites('''
            def verify(password, supplied):
                direct = (password,) == ("guess",)  # expect-secret
                value = [password]
                alias = value
                copied = alias != ["guess"]  # expect-secret
                mapping = {"value": password}
                mapped = mapping != {"value": supplied}  # expect-secret
                keyed = {password: 1} == {supplied: 1}  # expect-secret
                return direct, copied, mapped, keyed
        ''')

    def test_loop_targets_and_backedges_preserve_comparison_evaluation(self):
        self.assert_sites('''
            def target(slots, password, supplied, items):
                for slots[password == supplied] in items:  # expect-secret
                    pass
            def backedge(state: State, password, supplied, items):
                value = state.signature()
                for item in items:
                    accepted = value == supplied  # expect-secret
                    value = password
                return accepted
            def while_backedge(state: State, password, supplied, ready):
                value = state.signature()
                while ready and value != supplied:  # expect-secret
                    value = password
        ''')

    def test_iteration_targets_keep_secret_element_provenance(self):
        self.assert_sites('''
            def verify(password, supplied):
                values = [password]
                for value in values:
                    accepted = value == supplied  # expect-secret
                for label, value in [("public", password)]:
                    public = label == supplied
                    accepted = value != supplied  # expect-secret
                return accepted
            async def verify_async(password, supplied):
                values = [password]
                async for value in values:
                    accepted = value == supplied  # expect-secret
        ''')

    def test_iteration_unpacking_reads_all_elements_before_assigning_targets(self):
        self.assert_sites('''
            def verify(password, supplied):
                first = password
                second = "public"
                for first, second in [(second, first)]:
                    public = first == supplied
                    accepted = second == supplied  # expect-secret
                values = [password]
                for value in [*values]:
                    accepted = value == supplied  # expect-secret
        ''')

    def test_iteration_overwrites_before_the_body_but_preserves_empty_path(self):
        self.assert_sites('''
            def verify(password, supplied):
                value = password
                for value in ["public"]:
                    accepted = value == supplied
                for label in {"public": password}:
                    accepted = label == supplied
                value = password
                for value in []:
                    accepted = value == supplied
                return value == supplied  # expect-secret
        ''')

    def test_iteration_same_binding_preserves_public_roles_and_mutations(self):
        self.assert_sites('''
            import hashlib
            def public_checksum(payload, supplied):
                h = hashlib.sha256(payload)
                for h in (h,):
                    accepted = h.hexdigest() == supplied
                return accepted
            def public_signature(self, node, supplied):
                sig = self._call_signature(node)
                for sig in (sig,):
                    accepted = sig == supplied
                return accepted
            def repeated_signature(self, node, password, supplied):
                sig = self._call_signature(node)
                for sig, sig in [(password, sig)]:
                    accepted = sig == supplied
                return accepted
            def hash_backedge(payload, password, supplied):
                h = hashlib.sha256(payload)
                for h in (h, h):
                    accepted = h.hexdigest() == supplied  # expect-secret
                    h.update(password)
                return accepted
            def mutation_in_target(payload, password, supplied, slots):
                h = hashlib.sha256(payload)
                for slots[h.update(password)], h in [(0, h)]:
                    accepted = h.hexdigest() == supplied  # expect-secret
                return accepted
        ''')

    def test_exception_handler_joins_intermediate_and_nested_statement_states(self):
        self.assert_sites('''
            def verify(state: State, password, supplied, flag):
                value = state.signature()
                try:
                    if flag:
                        value = password
                        work()
                        value = state.signature()
                    work()
                    value = state.signature()
                except Exception:
                    return value == supplied  # expect-secret
            def separate_function(state: State, password, supplied):
                value = state.signature()
                try:
                    def unrelated():
                        value = password
                        work()
                    work()
                except Exception:
                    return value == supplied
        ''')

    def test_conditional_container_and_branch_alias_keep_material_provenance(self):
        self.assert_sites('''
            def conditional(state: State, password, flag):
                value = (password,) if flag else state.signature()
                return value == ("guess",)  # expect-secret
            def branch(state: State, password, flag):
                value = (password,)
                if flag:
                    value = state.signature()
                return value == ("guess",)  # expect-secret
        ''')

    def test_container_evidence_does_not_cross_function_boundaries(self):
        self.assert_sites('''
            def secret(password):
                value = (password,)
                return value == ("guess",)  # expect-secret
            def public():
                value = ("mode", "read")
                return value == ("mode", "read")
        ''')

    def test_adjacent_comparison_pairs_own_numeric_and_shape_exemptions(self):
        self.assert_sites('''
            def verify(count, password, supplied, expected_signature):
                first = 0 == count == password == supplied  # expect-secret
                second = password == supplied != 0  # expect-secret
                third = ("a", "b") == count == expected_signature  # expect-secret
                clean = count == 0 == count
                return first, second, third, clean
        ''')

    def test_literal_dispatch_and_timing_safe_calls_stay_clean(self):
        self.assert_sites('''
            def dispatch(self, node, completion):
                sig = self._call_signature(node)
                if sig == ("socket", "socketpair"):
                    return 1
                return self._reference_signature(completion) == ("asyncio", "ALL_COMPLETED")
            def verify(password, supplied):
                return hmac.compare_digest(password, supplied)
        ''')

    def test_real_python_module_preserves_public_and_secret_pair(self):
        import json
        import os
        import shutil
        import subprocess

        if shutil.which('rg') is None or shutil.which('jq') is None:
            self.skipTest('Python module requires rg and jq')
        artifacts = REPO_ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='ctcompare-flow-', dir=artifacts))
        source = StructuralFingerprintTests.RECORDS + textwrap.dedent('''
            def ordinary(state: State):
                signature = state.signature()
                return signature == State().signature()
            def verify(state: State, password, supplied, flag):
                value = password
                if flag:
                    value = state.signature()
                return value == supplied
        ''')
        path = root / 'comparisons.py'
        path.write_text(source, encoding='utf-8')
        for output_format in ('json', 'sarif'):
            command = [str(REPO_ROOT / 'modules/ubs-python.sh'), str(path),
                       '--ci', '--format=' + output_format]
            completed = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False,
                                       timeout=60, env={**os.environ, 'UBS_NO_AUTO_UPDATE': '1',
                                                        'UBS_CATEGORY_FILTER': '7'})
            (root / (output_format + '.stdout')).write_text(completed.stdout, encoding='utf-8')
            (root / (output_format + '.stderr')).write_text(completed.stderr, encoding='utf-8')
            print('[ctcompare-flow-%s] exit=%s command=%r' % (output_format, completed.returncode, command))
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            document = json.loads(completed.stdout)
            if output_format == 'json':
                self.assertEqual(document['status'], 'ok')
                findings = [row for row in document['findings'] if row['rule'] == ctcompare_py.RULE_ID]
                self.assertEqual([(sample['line'], row['severity']) for row in findings
                                  for sample in row['samples']],
                                 [(len(source.splitlines()), 'critical')])
            else:
                findings = [row for row in document['runs'][0]['results'] if row['ruleId'] == ctcompare_py.RULE_ID]
                self.assertEqual([row['locations'][0]['physicalLocation']['region']['startLine']
                                  for row in findings], [len(source.splitlines())])

    def test_local_unkeyed_digest_wrapper_is_public_only_for_public_inputs(self):
        self.assert_sites('''
            import hashlib
            def digest(data):
                return hashlib.sha256(data).hexdigest()
            def checksum(payload, expected, password):
                try:
                    public = digest(payload)
                except OSError:
                    public = ""
                accepted = public == expected
                secret_value = digest(password)
                first = secret_value == expected  # expect-secret
                second = digest(data=password) == expected  # expect-secret
                return accepted, first, second
        ''')

    def test_digest_helper_binding_and_implementation_must_be_resolved(self):
        variants = (
            ('import hashlib', 'hashlib.sha256(data).hexdigest()', 'def other(digest):\n    return digest\n'),
            ('import hashlib', 'hashlib.sha256(data).hexdigest()', 'hashlib.sha256 = replacement\n'),
            ('import hashlib', 'hashlib.sha256(data).hexdigest()', 'hashlib.__setattr__("sha256", replacement)\n'),
            ('import hashlib', 'hashlib.sha256(data).hexdigest()', 'from unknown import *\n'),
            ('import sys\nsys.modules["hashlib"] = forged\nimport hashlib',
             'hashlib.sha256(data).hexdigest()', ''),
            ('from .hashlib import sha256', 'sha256(data).hexdigest()', ''),
            ('import hashlib', 'hashlib.sha256(data).hexdigest()', 'mutate(hashlib)\n'),
            ('import hashlib', 'hashlib.sha256(data).hexdigest()', 'mutate(digest)\n'),
            ('import hashlib', 'hashlib.blake2b(data, key=key).hexdigest()', ''),
            ('import hashlib', 'opaque(data)', ''),
            ('from somewhere import sha256', 'sha256(data).hexdigest()', ''),
        )
        for imports, expression, suffix in variants:
            with self.subTest(expression=expression, suffix=suffix):
                self.assert_sites(
                    imports + '\ndef digest(data):\n    return ' + expression + '\n' + suffix
                    + 'def verify(payload, supplied):\n    return digest(payload) == supplied  # expect-secret\n'
                )
        self.assert_sites('''
            def verify(payload, supplied):
                return digest(payload) == supplied  # expect-secret
        ''')

    def test_hashlib_import_aliases_keep_the_wrapper_input_role(self):
        self.assert_sites('''
            import hashlib as hashes
            from hashlib import sha512 as checksum_ctor
            def digest(data):
                return hashes.sha256(data).hexdigest()
            def hexdigest(data):
                return checksum_ctor(data).hexdigest()
            def verify(payload, supplied, password):
                accepted = digest(payload) == supplied
                return accepted, hexdigest(password) == supplied  # expect-secret
        ''')

    def test_actual_release_contract_digest_is_public(self):
        source = (REPO_ROOT / 'scripts/release_generation.py').read_text(encoding='utf-8')
        self.assertEqual(ctcompare_py._scan_code(source), [])


if __name__ == "__main__":
    unittest.main()
