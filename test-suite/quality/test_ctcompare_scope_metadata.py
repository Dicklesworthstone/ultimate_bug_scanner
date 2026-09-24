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


if __name__ == "__main__":
    unittest.main()
