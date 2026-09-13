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
import json
import os
import re
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
from ubs_core.analyzers import ctcompare_rust  # noqa: E402
from ubs_core.analyzers import sec_hardcoded_secrets  # noqa: E402
from ubs_core.py_detectors import unsafe_deserialization  # noqa: E402
from ubs_core.py_patterns.security_rg import PATTERNS  # noqa: E402
from ubs_core.py_rules import _RULES  # noqa: E402
from ubs_core.py_scan import iter_matches  # noqa: E402
from ubs_core.rust_detectors import jwt_verification  # noqa: E402
from ubs_core.rust_detectors import security_randomness  # noqa: E402
from ubs_core.rust_detectors import (  # noqa: E402
    host_header_url, open_redirect, request_regex, request_url,
    response_header, sql_injection,
)
from ubs_core import rust_rules  # noqa: E402

JS_SECURITY = REPO_ROOT / "test-suite" / "js" / "security"
PY_SECURITY = REPO_ROOT / "test-suite" / "python" / "security"


class RustPanicContextTests(unittest.TestCase):
    """Use the actual scanner and ast-grep, never pre-populated AST hits."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs_panic_context_")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.rules = self.root / "rules"
        rust_rules.generate(self.rules)

    def package(self, name: str, extra: str = "", source: str = "tests/receipt.rs") -> Path:
        root = self.root / name
        root.mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "panic_context"\nversion = "0.1.0"\nedition = "2024"\n' + extra,
            encoding="utf-8",
        )
        target = root / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('fn receipt() { panic!("wire input receipt required") }\n', encoding="utf-8")
        return target

    def scan(self, paths: list[Path], *, fail_on_warning: bool = False,
             cache: bool = False, without_tomllib: bool = False,
             categories: tuple[int, ...] = (1,), ast: bool = True) -> tuple[int, dict]:
        inputs = self.root / "inputs"
        inputs.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
        output = self.root / "scan.json"
        args = [
            "--files-from", str(inputs), "--sink", str(self.root / "findings.ndjson"),
            "--project-dir", str(self.root),
            "--skip", ",".join(str(n) for n in range(1, 25) if n not in categories),
            "--skip-type-narrowing",
            "--quiet", "--json-out", str(output),
        ]
        if ast:
            args.extend(["--ast-rule-dir", str(self.rules)])
        if fail_on_warning:
            args.append("--fail-on-warning")
        command = [sys.executable, "-m", "ubs_core.rust_scan"]
        if without_tomllib:
            command = [sys.executable, "-c", (
                "import runpy,sys; sys.modules['tomllib']=None; "
                "runpy.run_module('ubs_core.rust_scan',run_name='__main__')"
            )]
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0" if cache else "1", UBS_CACHE_DIR=str(self.root / "cache"))
        result = subprocess.run(command + args, cwd=self.root, env=env,
                                text=True, capture_output=True, timeout=30)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        try:
            document = json.loads(output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.fail(f"scanner returned invalid JSON: {exc}")
        return result.returncode, document

    def test_assertion_inventory_counts_each_macro_once(self) -> None:
        targets = [self.package(name) for name in ("first", "second")]
        for target in targets:
            target.write_text(
                "fn receipt() { assert!(true); assert_eq!(1, 1); }\n"
                "fn other() { assert_ne!(1, 2); }\n",
                encoding="utf-8",
            )
        code, doc = self.scan(targets, categories=(21,), fail_on_warning=True)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.panic.assert-macros"]
        self.assertEqual(code, 1)
        self.assertEqual(len(hits), 6)
        self.assertEqual(doc["warning"], 6)
        for target in targets:
            sites = [hit for hit in hits if Path(hit["path"]) == target]
            self.assertEqual(sorted(hit["line"] for hit in sites), [1, 1, 2])
            first_line = [hit["col"] for hit in sites if hit["line"] == 1]
            self.assertEqual(len(set(first_line)), 2)

    def test_assertion_inventory_retains_line_fallback_without_ast(self) -> None:
        target = self.package("fallback")
        target.write_text(
            "fn receipt() {\n    assert!(true);\n    assert_eq!(1, 1);\n"
            "    assert_ne!(1, 2);\n}\n",
            encoding="utf-8",
        )
        code, doc = self.scan([target], categories=(21,), ast=False, fail_on_warning=True)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.panic.assert-macros"]
        self.assertEqual(code, 1)
        self.assertEqual(sorted(hit["line"] for hit in hits), [2, 3, 4])
        self.assertEqual(doc["warning"], 3)

    def test_async_lock_inventory_does_not_duplicate_line_fallbacks(self) -> None:
        for name, acquisition, rule in (
            ("blocking", "mutex.lock().unwrap()", "rust.async-locking.std-lock-async"),
            ("async", "mutex.lock().await", "rust.async-locking.tokio-guard-await"),
        ):
            with self.subTest(acquisition=acquisition):
                targets = [self.package(f"{name}_{suffix}") for suffix in ("first", "second")]
                for target in targets:
                    target.write_text(
                        f"async fn receipt() {{ let guard = {acquisition}; pending().await; }}\n",
                        encoding="utf-8",
                    )
                code, doc = self.scan(targets, categories=(20,), fail_on_warning=True)
                hits = [hit for hit in doc["findings"] if hit["rule"] == rule]
                self.assertEqual(code, 1)
                self.assertEqual(len(hits), 2)
                self.assertEqual({Path(hit["path"]) for hit in hits}, set(targets))
                self.assertTrue(all(hit["severity"] == "warning" for hit in hits))

    def test_integration_panic_stays_visible_and_warning_gate_still_fails(self) -> None:
        target = self.package("native")
        code, doc = self.scan([target])
        self.assertEqual(code, 0)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        self.assertEqual(len(hits), 1)
        self.assertEqual((hits[0]["severity"], hits[0]["line"]), ("warning", 1))
        self.assertEqual(Path(hits[0]["path"]), target)
        self.assertEqual((doc["files"], doc["critical"], doc["warning"]), (1, 0, 1))
        self.assertEqual(self.scan([target], fail_on_warning=True)[0], 1)

    def test_production_and_ambiguous_paths_remain_critical(self) -> None:
        targets = [
            self.package("production", source="src/lib.rs"),
            self.package("misleading", source="src/tests/helper.rs"),
            self.package("tests/ancestor", source="src/lib.rs"),
            self.package("disabled", "autotests = false\n"),
            self.package("bin_overlap", '\n[[bin]]\nname="receipt"\npath="tests/receipt.rs"\n'),
            self.package("lib_overlap", '\n[lib]\npath="tests/receipt.rs"\n'),
            self.package("build_overlap", 'build="tests/receipt.rs"\n'),
            self.package("custom_harness", '\n[[test]]\nname="receipt"\nharness=false\n'),
        ]
        missing = self.root / "missing/tests/receipt.rs"
        missing.parent.mkdir(parents=True)
        missing.write_text('fn receipt() { panic!("missing metadata") }\n', encoding="utf-8")
        targets.append(missing)
        invalid = self.package("invalid")
        (invalid.parent.parent / "Cargo.toml").write_text("[package\n", encoding="utf-8")
        targets.append(invalid)
        after = self.package("after", source="src/lib.rs")
        after.write_text('#[cfg(test)]\nmod tests {}\nfn production() { panic!("still production") }\n',
                         encoding="utf-8")
        targets.append(after)
        linked = self.root / "production/tests/linked.rs"
        linked.parent.mkdir()
        linked.symlink_to(targets[0])
        targets.append(linked)
        code, doc = self.scan(targets)
        self.assertEqual(code, 1)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        self.assertEqual({Path(hit["path"]) for hit in hits}, set(targets))
        self.assertTrue(all(hit["severity"] == "critical" for hit in hits), hits)

    def test_original_default_test_module_panics_remain_critical(self) -> None:
        fixture = REPO_ROOT / "test-suite/rust/exclude_tests_mod/src"
        code, doc = self.scan([fixture / "lib.rs", fixture / "tests_support.rs"])
        self.assertEqual(code, 1)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(hit["severity"] == "critical" for hit in hits))

    def test_missing_toml_parser_keeps_critical(self) -> None:
        target = self.package("native")
        code, doc = self.scan([target], without_tomllib=True)
        self.assertEqual((code, doc["critical"]), (1, 1))

    def test_legacy_autodiscovery_and_workspace_metadata_are_respected(self) -> None:
        target = self.package("legacy", '\n[lib]\npath="src/lib.rs"\n')
        (target.parent.parent / "src").mkdir()
        (target.parent.parent / "src/lib.rs").write_text("", encoding="utf-8")
        manifest = target.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('edition = "2024"', 'edition = "2015"'))
        self.assertEqual(self.scan([target])[0], 1)
        inherited = self.package("workspace/native", '\n[lib]\npath="src/lib.rs"\n')
        (inherited.parent.parent / "src").mkdir()
        (inherited.parent.parent / "src/lib.rs").write_text("", encoding="utf-8")
        manifest = inherited.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('edition = "2024"', 'edition.workspace = true'))
        self.assertEqual(self.scan([inherited])[0], 1)
        workspace = self.root / "workspace/Cargo.toml"
        workspace.write_text('[workspace]\nmembers=["native"]\n[workspace.package]\nedition="2024"\n')
        self.assertEqual(self.scan([inherited], cache=True)[0], 0)
        workspace.write_text(workspace.read_text().replace('"2024"', '"2015"'))
        self.assertEqual(self.scan([inherited], cache=True)[0], 1)

    def test_manifest_changes_invalidate_cached_severity(self) -> None:
        target = self.package("native")
        self.assertEqual(self.scan([target], cache=True)[0], 0)
        code, cached = self.scan([target], cache=True)
        self.assertEqual(code, 0)
        self.assertEqual(cached["extras"]["profile"]["cache_hits"], 1)
        manifest = target.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text(encoding="utf-8") + "autotests=false\n", encoding="utf-8")
        code, changed = self.scan([target], cache=True)
        self.assertEqual((code, changed["critical"]), (1, 1))
        self.assertEqual(changed["extras"]["profile"]["cache_hits"], 0)


class RustJwtDecoderIdentityTests(unittest.TestCase):
    @staticmethod
    def hits(source: str) -> list[int]:
        with tempfile.TemporaryDirectory(prefix="ubs_rust_jwt_") as tmp:
            target = Path(tmp) / "input.rs"
            target.write_text(source, encoding="utf-8")
            return [line for _, line, _, _ in jwt_verification.find([target])]

    def test_binary_decoder_names_are_not_jwt_evidence(self) -> None:
        source = (
            "fn decode(bytes: &[u8]) -> Option<u8> { bytes.first().copied() }\n"
            "fn exercise(bytes: &[u8]) {\n"
            "    let _ = decode(bytes);\n"
            "    let _ = base64::decode(bytes);\n"
            "    let _ = Frame::decode(bytes);\n"
            "    let _ = codec.decode(bytes);\n"
            "}\n"
            "// use jsonwebtoken::decode;\n"
            'const DOC: &str = "use jsonwebtoken::decode;";\n'
            'const RAW_DOC: &str = r#"use jsonwebtoken::*;"#;\n'
            "/* use jsonwebtoken as jwt; */\n"
        )
        self.assertEqual(self.hits(source), [])

    def test_imported_and_qualified_jwt_decoders_still_require_binding(self) -> None:
        cases = [
            ("", "jsonwebtoken::decode"),
            ("", "::jsonwebtoken::decode"),
            ("use jsonwebtoken::decode;", "decode"),
            ("use jsonwebtoken::{Algorithm, decode, Validation};", "decode"),
            ("use jsonwebtoken::decode as parse_token;", "parse_token"),
            ("use jsonwebtoken::{decode as parse_token, Validation};", "parse_token"),
            ("use {base64::decode as bytes, jsonwebtoken::{decode as parse_token}};", "parse_token"),
            ("use jsonwebtoken as jwt;", "jwt::decode"),
            ("use jsonwebtoken::{self as jwt, Validation};", "jwt::decode"),
            ("extern crate jsonwebtoken as jwt;", "jwt::decode"),
            ("use jsonwebtoken::*;", "decode"),
            ("use jsonwebtoken as jwt; use jwt::decode as parse_token;", "parse_token"),
        ]
        for imports, call in cases:
            with self.subTest(imports=imports, call=call):
                source = (
                    imports + "\n"
                    "fn verify(token: &str, key: &DecodingKey) {\n"
                    "    let validation = Validation::default();\n"
                    f"    let _ = {call}::<Claims>(token, key, &validation);\n"
                    "}\n"
                )
                self.assertEqual(self.hits(source), [4])
                bound = source.replace(
                    "    let validation = Validation::default();\n",
                    "    let mut validation = Validation::default();\n"
                    '    validation.set_issuer(&["issuer"]);\n'
                    '    validation.set_audience(&["audience"]);\n'
                    '    validation.set_required_spec_claims(&["exp", "iss", "aud"]);\n',
                )
                self.assertEqual(self.hits(bound), [])

    def test_unrelated_qualified_calls_do_not_inherit_a_jwt_import(self) -> None:
        self.assertEqual(self.hits(
            "use jsonwebtoken::decode;\n"
            "fn exercise(bytes: &[u8]) {\n"
            "    let _ = base64::decode(bytes);\n"
            "    let _ = Frame::decode(bytes);\n"
            "    let _ = codec.decode(bytes);\n"
            "}\n"
            "mod binary { fn decode(bytes: &[u8]) {} }\n"
        ), [])

    def test_original_jwt_security_fixtures_remain_classified(self) -> None:
        rust = REPO_ROOT / "test-suite" / "rust"
        self.assertEqual(list(jwt_verification.find([rust / "clean/jwt_verification.rs"])), [])
        self.assertGreaterEqual(len(list(jwt_verification.find([rust / "buggy/jwt_verification.rs"]))), 6)


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

    def test_registrations_via_alias_classmethod_and_library_constructors(self) -> None:
        source = (
            "import yaml as y\n"
            "from yaml import SafeLoader\n"
            "class A(y.SafeLoader):\n"
            "    pass\n"
            "y.add_constructor('tag:yaml.org,2002:python/object/apply', lambda l, n: None, Loader=A)\n"
            "class B(y.SafeLoader):\n"
            "    @classmethod\n"
            "    def install(cls):\n"
            "        cls.add_constructor('!!python/name:os.system', cls.construct_scalar)\n"
            "class C(SafeLoader):\n"
            "    pass\n"
            "C.add_constructor('!pair', y.SafeLoader.construct_mapping)\n"
            "C.add_multi_constructor('!x', SafeLoader.construct_yaml_map)\n"
            "y.load(s, Loader=A)\n"
            "y.load(s, Loader=B)\n"
            "y.load(s, Loader=C)\n"
        )
        self.assertEqual(
            [(rule.rsplit(".", 1)[-1], line) for rule, line, _ in unsafe_deserialization.analyze_source(source)],
            [("yaml-unsafe-loader", 14), ("yaml-unsafe-loader", 15)],
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
                capture_output=True, text=True, check=False, timeout=30,
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


class RustPreparedSourceTests(unittest.TestCase):
    COMPARE = '''const API_SECRET: &str = "secret";
fn verify(provided: &str) {
    let alias = next_alias;
    let next_alias = API_SECRET;
    let local = alias;
    local == provided;
    API_SECRET == (
        provided);
    API_SECRET == provided; // ubs:ignore
    // ubs:ignore
    API_SECRET != provided;
}
fn unrelated(token: &str) {
    token == "BR2";
}
fn other(provided: &str) {
    local == provided;
    API_SECRET != provided;
}
'''
    RANDOM = '''fn create_session_token() {
    let token = rand::random::<u64>();
    let token = rand::random::<u64>(); // ubs:ignore
    // ubs:ignore
    let token = rand::random::<u64>();
}
fn doc() {
    let text = "token rand::random::<u64>() // literal";
}
fn csrf_nonce() {
    let nonce = rand::random::<
        u64>();
}
fn unrelated() {
    let number = rand::random::<u64>();
}
'''

    def test_rust_compare_multiline_alias_scopes_and_markers(self):
        findings = ctcompare_rust.scan_file(self.COMPARE)
        self.assertEqual([line for line, _ in findings], [6, 7, 18])
        self.assertEqual(
            findings,
            [(line, self.COMPARE.splitlines()[line - 1].strip()) for line in [6, 7, 18]],
        )

    def test_rust_random_multiline_and_markers(self):
        with tempfile.TemporaryDirectory(prefix="ubs-rust-reuse-") as tmp:
            path = Path(tmp) / "source.rs"
            path.write_text(self.RANDOM, encoding="utf-8")
            findings = list(security_randomness.find([path]))
            self.assertEqual([hit[1] for hit in findings], [2, 11])
            # The same pathname must observe replacement contents on a later
            # invocation; reuse is confined to one immutable file read.
            path.write_text("fn ordinary() {}\n", encoding="utf-8")
            self.assertEqual(list(security_randomness.find([path])), [])
            path.write_text(self.RANDOM, encoding="utf-8")
            self.assertEqual(list(security_randomness.find([path])), findings)

    def test_rust_compare_source_reuse_does_not_cross_scans(self):
        first = ctcompare_rust.scan_file(self.COMPARE)
        self.assertTrue(first)
        self.assertEqual(ctcompare_rust.scan_file("fn ordinary(x: u32) { x == 1; }"), [])
        self.assertEqual(ctcompare_rust.scan_file(self.COMPARE), first)

    def test_rust_comment_stripping_once_per_source_line(self):
        # Count actual calls while running the detector, without substituting
        # its parser or outputs. Lookahead and taint fixpoint passes must reuse
        # the prepared lines rather than rescan them.
        counts = {}
        codes = {ctcompare_rust.strip_line_comments.__code__,
                 security_randomness.strip_line_comments.__code__}

        def record(frame, event, arg):
            if event == "call" and frame.f_code in codes:
                counts[frame.f_code] = counts.get(frame.f_code, 0) + 1

        previous = sys.getprofile()
        with tempfile.TemporaryDirectory(prefix="ubs-rust-reuse-") as tmp:
            path = Path(tmp) / "source.rs"
            path.write_text(self.RANDOM, encoding="utf-8")
            try:
                sys.setprofile(record)
                compared = ctcompare_rust.scan_file(self.COMPARE)
                random = list(security_randomness.find([path]))
            finally:
                sys.setprofile(previous)
        self.assertEqual([line for line, _ in compared], [6, 7, 18])
        self.assertEqual([hit[1] for hit in random], [2, 11])
        self.assertEqual(counts[ctcompare_rust.strip_line_comments.__code__], len(self.COMPARE.splitlines()))
        self.assertEqual(counts[security_randomness.strip_line_comments.__code__], len(self.RANDOM.splitlines()))


class RustTaintReferenceTests(unittest.TestCase):
    DETECTORS = (
        request_url, open_redirect, request_regex,
        response_header, host_header_url, sql_injection,
    )
    FORMATTED = (response_header, host_header_url, sql_injection)

    @classmethod
    def original_refs(cls, detector, expression, tainted):
        # Retain the original algorithm as the independent behavior oracle:
        # optimize its cost, not its matching, masking or tie-breaking.
        if detector in cls.FORMATTED:
            searchable = detector.without_string_literals(expression)
        elif detector is request_regex:
            searchable = detector.mask_literals(expression)
        else:
            searchable = expression
        return [
            name for name in tainted
            if re.search(rf'\b{re.escape(name)}\b', searchable)
            or (detector in cls.FORMATTED and re.search(
                rf'\{{\s*{re.escape(name)}\s*(?::|[}}])', expression
            ))
        ]

    def test_reference_boundaries_literals_captures_and_order_match_original(self):
        # Deliberately different from expression order: the first recorded
        # taint owns the displayed evidence path when several names match.
        tainted = dict.fromkeys(["beta", "alpha", "_x", "Alpha", "a1", "x"])
        expressions = [
            "alpha + beta + alpha", "alpha_beta alphabeta 1alpha alpha1",
            "obj.alpha + &beta + r#_x + Alpha + a1", "éalpha alphaé αalpha alpha中",
            "alpha\u0301 + \u0301beta", '"alpha" + beta', 'r#"alpha // beta"# + _x',
            'format!("{alpha} { beta :>10} {_x:?}")',
            'format!("{alpha:{beta}} {{alpha}} {alpha_} {alphaé}")',
            '"{ alpha\n:10} {beta!} {1alpha}"', "", "αβ_中文",
        ]
        for detector in self.DETECTORS:
            for expression in expressions:
                with self.subTest(detector=detector.__name__, expression=expression):
                    self.assertEqual(
                        detector.refs_in_expr(expression, tainted),
                        self.original_refs(detector, expression, tainted),
                    )
            self.assertEqual(detector.refs_in_expr("alpha + beta", tainted), ["beta", "alpha"])
            self.assertEqual(detector.refs_in_expr("anything", {}), [])

    def test_large_taint_table_does_not_compile_one_regex_per_name(self):
        # More identifiers than Python's regex cache can hold reproduces the
        # CASS timeout's cache thrashing. Observe real compiler calls; no mock
        # replaces either the regular-expression engine or a detector.
        tainted = dict.fromkeys(f"value_{i}" for i in range(2048))
        expression = 'value_2047 + value_0 + format!("{value_1024:?}")'
        calls = []

        def record(frame, event, arg):
            if event == "call" and frame.f_code.co_name == "compile" and frame.f_globals.get("__name__") == "re._compiler":
                calls.append(1)

        previous = sys.getprofile()
        re.purge()
        try:
            sys.setprofile(record)
            results = [detector.refs_in_expr(expression, tainted) for detector in self.DETECTORS]
        finally:
            sys.setprofile(previous)
        for detector, result in zip(self.DETECTORS, results):
            self.assertEqual(result, self.original_refs(detector, expression, tainted))
        self.assertLessEqual(len(calls), 4, f"regex compilations scaled with taint table: {len(calls)}")


if __name__ == "__main__":
    unittest.main()
