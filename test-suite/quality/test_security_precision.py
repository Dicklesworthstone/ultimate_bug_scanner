#!/usr/bin/env python3
"""GH #102 precision regressions for three security detectors.

Each false positive from the report is pinned by a clean fixture and paired
with the true positives the rule exists for:

* JS ``js.security.hardcoded-secrets`` — SCREAMING_SNAKE error/enum codes
  (``CREDENTIALS: 'E_CREDENTIALS'``) are not secrets; real literals, uppercase
  keys, ``Object.freeze`` wrappers and ``E_*`` env fallbacks still are.
* Python yaml Loader classification — SafeLoader subclasses (trivial, or with a
  strict mapping constructor) are safe; ``Loader``/``UnsafeLoader``/``FullLoader``/
  ``None``, python/ tag registrations, eval-ing constructors and reassuring
  class names stay critical; imported/dynamic loaders are reported for review.
  The no-Loader shape is covered by ``py.yaml-unsafe`` (ast-grep, when the
  binary is available) and the category-7 regex.
* Python ``python.ctcompare.secret_eq`` — an unkeyed hashlib digest of public
  bytes checked against a public manifest is an integrity check; keyed MACs,
  hashes of secrets, secret-fed hash objects and unresolved receivers stay
  reported. The clean fixture's runtime contract (accept intact, reject
  modified) is executed here so it cannot be weakened to please the scanner.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import ctcompare_py  # noqa: E402
from ubs_core.analyzers import sec_hardcoded_secrets  # noqa: E402
from ubs_core.py_detectors import unsafe_deserialization  # noqa: E402
from ubs_core.py_patterns.security_rg import PATTERNS  # noqa: E402
from ubs_core.py_rules import _RULES  # noqa: E402
from ubs_core.py_scan import iter_matches  # noqa: E402

JS_SECURITY = REPO_ROOT / "test-suite" / "js" / "security"
PY_SECURITY = REPO_ROOT / "test-suite" / "python" / "security"


def expected_lines(path: Path, marker: str) -> list[int]:
    """1-based line numbers carrying ``expect: <marker>`` in a fixture."""
    token = f"expect: {marker}"
    return [
        idx
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if token in line
    ]


class HardcodedSecretsSymbolicConstantTests(unittest.TestCase):
    def test_error_code_dictionary_is_clean(self) -> None:
        findings = list(sec_hardcoded_secrets.scan_file_findings(JS_SECURITY / "error-code-constants-clean.mjs"))
        self.assertEqual(findings, [])

    def test_issue_snippet_is_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_gh102_js_") as tmp:
            target = Path(tmp) / "error-codes.mjs"
            target.write_text(
                "const CODES = Object.freeze({ CREDENTIALS: 'E_CREDENTIALS' });\n"
                "throw new Error(CODES.CREDENTIALS);\n",
                encoding="utf-8",
            )
            self.assertEqual(list(sec_hardcoded_secrets.scan_file_findings(target)), [])

    def test_credential_material_still_reported(self) -> None:
        fixture = JS_SECURITY / "error-code-constants-buggy.mjs"
        findings = list(sec_hardcoded_secrets.scan_file_findings(fixture))
        self.assertEqual(sorted(line for line, _ in findings), expected_lines(fixture, "secret"))

    def test_symbolic_constant_shape(self) -> None:
        for literal in ("'E_CREDENTIALS'", '"ERR-TOKEN-EXPIRED-401"', "`HTTP_401`", "'API_KEY_MISSING'"):
            self.assertTrue(sec_hardcoded_secrets.is_symbolic_constant(literal), literal)
        for literal in (
            "'sk_live_4f8a2b91cd77e530'", "'AKIAIOSFODNN7EXAMPLE'", "'SESSION_SECRET_9f3a7c1e2b4d'",
            "'e_credentials'", "'CREDENTIALS'", "'E_CREDENTIALS_'", "'4F8A_2B91'", "''",
        ):
            self.assertFalse(sec_hardcoded_secrets.is_symbolic_constant(literal), literal)


class YamlLoaderClassificationTests(unittest.TestCase):
    UNSAFE = unsafe_deserialization.YAML_UNSAFE_LOADER_RULE_ID
    UNRESOLVED = unsafe_deserialization.YAML_LOADER_UNRESOLVED_RULE_ID

    @staticmethod
    def hits(path: Path) -> dict[str, list[int]]:
        grouped: dict[str, list[int]] = {}
        for rule_id, _path, line, _col, _detail in unsafe_deserialization.find([path]):
            grouped.setdefault(rule_id, []).append(line)
        return grouped

    def test_safe_loader_subclasses_are_clean(self) -> None:
        self.assertEqual(self.hits(PY_SECURITY / "yaml_loader_clean.py"), {})

    def test_issue_snippet_is_clean(self) -> None:
        source = (
            "import yaml\n"
            "\n"
            "class StrictSafeLoader(yaml.SafeLoader):\n"
            "    pass\n"
            "\n"
            'yaml.load("title: fixture", Loader=StrictSafeLoader)\n'
        )
        self.assertEqual(unsafe_deserialization.analyze_source(source), [])

    def test_unsafe_and_unresolved_loaders_are_reported(self) -> None:
        fixture = PY_SECURITY / "yaml_loader_buggy.py"
        hits = self.hits(fixture)
        self.assertEqual(sorted(hits.get(self.UNSAFE, [])), expected_lines(fixture, "unsafe"))
        self.assertEqual(sorted(hits.get(self.UNRESOLVED, [])), expected_lines(fixture, "unresolved"))
        # The no-Loader call belongs to py.yaml-unsafe / py.security.yaml-load.
        for line in expected_lines(fixture, "no-loader"):
            for lines in hits.values():
                self.assertNotIn(line, lines)

    def test_reassuring_name_and_dynamic_tag_are_not_evidence(self) -> None:
        source = (
            "import yaml\n"
            "class SafeLoader(yaml.Loader):\n"
            "    pass\n"
            "class DynamicTagLoader(yaml.SafeLoader):\n"
            "    pass\n"
            "DynamicTagLoader.add_constructor(TAG, lambda loader, node: node.value)\n"
            "yaml.load(s, Loader=SafeLoader)\n"
            "yaml.load(s, Loader=DynamicTagLoader)\n"
            "yaml.load(s, Loader=yaml.SafeLoader)  # ubs:ignore\n"
        )
        self.assertEqual(
            [(rule.rsplit(".", 1)[-1], line) for rule, line, _ in unsafe_deserialization.analyze_source(source)],
            [("yaml-unsafe-loader", 7), ("yaml-loader-unresolved", 8)],
        )

    def test_legacy_pickle_loader_rule_unchanged(self) -> None:
        hits = self.hits(PY_SECURITY / "unsafe_deserialization_buggy.py")
        self.assertGreaterEqual(len(hits.get(unsafe_deserialization.RULE_ID, [])), 12)
        self.assertEqual(self.hits(PY_SECURITY / "unsafe_deserialization_clean.py"), {})


YAML_VARIANTS = "\n".join([
    "import yaml",
    "yaml.load(stream)",                                  # 2  no loader
    "yaml.load_all(stream)",                              # 3  no loader
    "yaml.load(open(path))",                              # 4  no loader, nested call
    "yaml.load(stream, Loader=yaml.SafeLoader)",          # 5
    "yaml.load(stream, yaml.SafeLoader)",                 # 6  positional loader
    "yaml.load(stream, Loader=StrictSafeLoader)",         # 7
    "yaml.load_all(stream, Loader=yaml.SafeLoader)",      # 8
    "yaml.load(stream, Loader=yaml.Loader)",              # 9  classified by the AST detector
    "yaml.safe_load(stream)",                             # 10
    "",
])
NO_LOADER_LINES = [2, 3, 4]


class YamlNoLoaderLayersTests(unittest.TestCase):
    def test_category7_regex_matches_single_argument_calls_only(self) -> None:
        pattern = next(p for p in PATTERNS if p.rule_id == "py.security.yaml-load")
        self.assertEqual([line for line, _ in iter_matches(pattern, YAML_VARIANTS)], NO_LOADER_LINES)

    def test_ast_grep_rule_matches_single_argument_calls_only(self) -> None:
        binary = shutil.which("ast-grep") or shutil.which("sg")
        if not binary:
            self.skipTest("ast-grep not installed")
        rule_text = dict(_RULES)["yaml-unsafe"]
        with tempfile.TemporaryDirectory(prefix="ubs_gh102_sg_") as tmp:
            rule = Path(tmp) / "yaml-unsafe.yml"
            rule.write_text(rule_text, encoding="utf-8")
            target = Path(tmp) / "variants.py"
            target.write_text(YAML_VARIANTS, encoding="utf-8")
            proc = subprocess.run(
                [binary, "scan", "-r", str(rule), "--report-style", "short", str(target)],
                capture_output=True, text=True, check=False,
            )
        lines = sorted(
            int(part.split(":")[1])
            for part in proc.stdout.splitlines()
            if part.startswith(str(target))
        )
        self.assertEqual(lines, NO_LOADER_LINES, proc.stdout + proc.stderr)


class ConstantTimeCompareDigestRoleTests(unittest.TestCase):
    @staticmethod
    def issue_lines(path: Path) -> list[int]:
        issues: list = []
        ctcompare_py.analyze(path, issues)
        return sorted(line for _path, line, _code in issues)

    def test_public_checksum_fixture_is_clean(self) -> None:
        self.assertEqual(self.issue_lines(PY_SECURITY / "public_checksum_compare_clean.py"), [])

    def test_authentication_comparisons_still_reported(self) -> None:
        fixture = PY_SECURITY / "public_checksum_compare_buggy.py"
        self.assertEqual(self.issue_lines(fixture), expected_lines(fixture, "secret_eq"))

    def test_existing_pairs_unchanged(self) -> None:
        self.assertEqual(self.issue_lines(PY_SECURITY / "constant_time_compare_clean.py"), [])
        self.assertEqual(self.issue_lines(PY_SECURITY / "parser_token_compare_clean.py"), [])
        self.assertEqual(len(self.issue_lines(PY_SECURITY / "constant_time_compare_buggy.py")), 6)
        self.assertEqual(len(self.issue_lines(PY_SECURITY / "parser_token_compare_buggy.py")), 5)

    def test_runtime_integrity_check_accepts_intact_and_rejects_modified_payload(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "public_checksum_compare_clean", PY_SECURITY / "public_checksum_compare_clean.py"
        )
        fixture = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory(prefix="ubs_gh102_ct_") as tmp:
            root = Path(tmp)
            fixture.prepare_public_fixture(root)
            fixture.verify_public_fixture(root)  # intact payload verifies
            manifest_sha256 = __import__("json").loads((root / "manifest.json").read_text())["sha256"]
            self.assertTrue(fixture.verify_streamed(root, manifest_sha256))
            self.assertTrue(fixture.verify_named_algorithm(b"public article bytes", "sha256", manifest_sha256))
            (root / "article.html").write_bytes(b"public article bytes, edited")
            with self.assertRaises(RuntimeError):
                fixture.verify_public_fixture(root)
            self.assertFalse(fixture.verify_streamed(root, manifest_sha256))
            # Same length, different bytes: the size check alone must not pass it.
            (root / "article.html").write_bytes(b"public article BYTES")
            with self.assertRaises(RuntimeError):
                fixture.verify_public_fixture(root)


if __name__ == "__main__":
    unittest.main()
