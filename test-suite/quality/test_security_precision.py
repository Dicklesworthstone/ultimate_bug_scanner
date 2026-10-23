#!/usr/bin/env python3
"""Precision regressions for security detectors and native rule packs.

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
* Java hardcoded secrets require literal assignments; blocking Future calls
  require scoped receiver evidence and an applicable exception handler.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

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


def sarif_location_path(uri: str, base: Path | None = None) -> Path:
    """The native path a SARIF artifactLocation.uri names (SARIF 2.1.0 section 3.10).

    A file URI is decoded to its absolute path; a relative reference is decoded
    and, when `base` is given, resolved against it.
    """
    from urllib.parse import unquote, urlparse

    parsed = urlparse(uri)
    if parsed.scheme == "file":
        return Path(unquote(parsed.path))
    relative = Path(unquote(uri))
    return base / relative if base is not None else relative
from ubs_core.rust_detectors import jwt_verification  # noqa: E402
from ubs_core.rust_detectors import hardcoded_secrets as rust_hardcoded_secrets  # noqa: E402
from ubs_core.rust_detectors import security_randomness  # noqa: E402
from ubs_core.rust_detectors import (  # noqa: E402
    archive_entry_path, host_header_url, open_redirect, request_regex, request_url,
    response_header, sql_injection,
)
from ubs_core import rust_rules  # noqa: E402
from ubs_core.swift_detectors import security_randomness as swift_randomness  # noqa: E402
from ubs_core.csharp_detectors import (  # noqa: E402
    archive_extraction as cs_archive, header_injection as cs_header,
    outbound_url as cs_outbound, security_randomness as cs_random,
)

JS_SECURITY = REPO_ROOT / "test-suite" / "js" / "security"
PY_SECURITY = REPO_ROOT / "test-suite" / "python" / "security"


class SwiftPredictableMaterialTests(unittest.TestCase):
    """Clock reads are not tokens; predictable credential material still is."""

    def findings(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Example.swift"
            path.write_text(source)
            return swift_randomness.collect_findings(SimpleNamespace(project_dir=path.parent, files=[path]))

    def test_discarded_calendar_argument_in_security_function_is_not_material(self):
        source = """func rejectsInvalidBearer() async throws {
    _ = try await api.load(.month(containing: Date()))
}
"""
        self.assertEqual(self.findings(source), [])

    def test_predictable_sources_still_reach_security_destinations(self):
        for expression in ("Date()", "Date.now", "NSDate()", "Date().timeIntervalSince1970",
                           "DispatchTime.now().uptimeNanoseconds", "ProcessInfo.processInfo.processIdentifier",
                           "ObjectIdentifier(instance).hashValue", "CFAbsoluteTimeGetCurrent()"):
            with self.subTest(expression=expression):
                source = f"func createValue() {{\n    let bearerToken = {expression}\n}}\n"
                self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_security_return_and_materialization_remain_suspicious(self):
        for expression in ('return "reset-\\(Date().timeIntervalSince1970)"',
                           'return Date()', 'return String(Date().timeIntervalSince1970)',
                           'let value = SHA256.hash(data: Data(Date().description.utf8))'):
            with self.subTest(expression=expression):
                self.assertEqual([row[1] for row in self.findings(f"func resetToken() {{\n    {expression}\n}}\n")], [2])

    def test_source_stays_reported_before_alias_conversion_and_return(self):
        source = """func resetToken() -> String {
    let observed = Date()
    let copied = observed
    let material = String(copied)
    return material
}
"""
        self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_source_stays_reported_before_helper_return(self):
        source = """func sessionToken() -> String {
    let observed = Date()
    return encode(observed)
}
"""
        self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_named_source_stays_reported_across_nested_function_uncertainty(self):
        source = """func sessionToken() -> String {
    let observed = Date()
    func identity(_ x: String) -> String { return x }
    return encode(observed)
}
"""
        self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_named_timing_value_keeps_conservative_security_context_warning(self):
        source = """func rejectsInvalidBearer() async throws {
    let started = Date()
    recordElapsed(started)
}
"""
        self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_conditional_overwrite_does_not_erase_predictable_origin(self):
        source = """func sessionToken() -> String {
    var observed = Date()
    if condition { observed = secureValue() }
    return encode(observed)
}
"""
        self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_later_and_conditional_assignments_retain_predictable_origins(self):
        for assignment in ('observed = Date()', 'if condition { observed = Date() }',
                           'observed += Date().timeIntervalSince1970'):
            with self.subTest(assignment=assignment):
                source = f"""func sessionToken() -> String {{
    var observed = initialValue()
    {assignment}
    return encode(observed)
}}
"""
                self.assertEqual([row[1] for row in self.findings(source)], [3])

    def test_predictable_alias_does_not_leak_into_sibling_function(self):
        source = """func observe() {
    let observed = Date()
}
func sessionToken() -> String {
    let observed = secureToken()
    return observed
}
"""
        self.assertEqual(self.findings(source), [])

    def test_tuple_subscript_and_unknown_helpers_keep_baseline_warnings(self):
        for statement in ('let (observed, spare) = (Date(), 0)',
                          'state[0] = Date()', 'seed(Date())',
                          'recordElapsed(Date().timeIntervalSince(started))'):
            with self.subTest(statement=statement):
                source = f"func sessionToken() {{\n    {statement}\n}}\n"
                self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_discarded_security_material_remains_suspicious(self):
        for statement in ('_ = String(Date().timeIntervalSince1970)',
                          '_ = bearerToken(Date())',
                          '_ = build { return Date() }',
                          '_ = build { state[0] = Date() }',
                          '_ = read(); state[0] = Date()',
                          '_ = "value-\\(Date().timeIntervalSince1970)"'):
            with self.subTest(statement=statement):
                source = f"func sessionToken() {{\n    {statement}\n}}\n"
                self.assertEqual([row[1] for row in self.findings(source)], [2])

    def test_existing_weak_random_fixtures_remain_effective(self):
        buggy = REPO_ROOT / "test-suite/swift/security_randomness_buggy/Tokens.swift"
        clean = REPO_ROOT / "test-suite/swift/security_randomness_clean/Tokens.swift"
        self.assertEqual([row[1] for row in self.findings(buggy.read_text())], [5, 9, 13, 14, 18, 22, 23])
        self.assertEqual(self.findings(clean.read_text()), [])


class JVMArchiveDataflowTests(unittest.TestCase):
    """Archive names reach actual destinations under value-specific root proofs."""

    @classmethod
    def setUpClass(cls):
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        cls.root = Path(tempfile.mkdtemp(prefix="jvm-archive-", dir=artifacts))

    @staticmethod
    def program(language, body, helper=""):
        signature = ("void unpack(ZipEntry entry, HttpServletRequest request, boolean enabled, Path destination)" if language == "java" else
                     "fun unpack(entry: ZipEntry, request: HttpServletRequest, enabled: Boolean, destination: Path)")
        return ("import java.nio.file.Path;\nimport java.nio.file.Paths;\nimport java.nio.file.Files;\n"
                "import java.io.File;\nimport java.io.FileOutputStream;\nimport java.io.RandomAccessFile;\n"
                "import java.util.zip.ZipEntry;\nimport java.util.zip.ZipFile;\n"
                "import javax.servlet.http.HttpServletRequest;\nclass ArchiveProbe {\n" + helper + "\n" +
                signature + " {\n" + body + "\n}\n}\n")

    @staticmethod
    def cases(language):
        path = "Path" if language == "java" else "var"
        string = "String" if language == "java" else "var"
        name = "entry.getName()" if language == "java" else "entry.name"
        root = path + ' root = Paths.get("/srv/out").toAbsolutePath().normalize();\n'
        source = path + ' target = root.resolve(' + name + ');\n'
        canonical = source.replace(');', ').normalize();')
        reject = 'throw new IllegalArgumentException("outside");' if language == "java" else 'throw IllegalArgumentException("outside");'
        guard = 'if (!target.startsWith(root)) { ' + reject + ' }\n'
        unsafe = 'Files.writeString(target, "data"); // expect-finding\n'
        safe = 'Files.writeString(target, "data");\n'
        identity = ('Path safeDestination(Path value) { return value; }' if language == "java" else
                    'fun safeDestination(value: Path): Path { return value }')
        checked = (('Path checked(Path root, String name) {\n' if language == "java" else
                    'fun checked(root: Path, name: String): Path {\n') +
                   path + ' target = root.resolve(name).normalize();\n' + guard + 'return target;\n}')
        checked_sink = checked.replace('Path checked(', 'void checked(').replace('): Path {', ') {').replace(
            'return target;', unsafe.rstrip())
        untrusted_root = root.replace('"/srv/out"', 'request.getParameter("root")')
        cases = [
            ("direct_destination", root + source + unsafe, ""),
            ("construction_only", root + source, ""),
            ("identity_helper_name_is_not_proof", root + source +
             'Files.writeString(safeDestination(target), "data"); // expect-finding\n', identity),
            ("unknown_helper_name_is_not_proof", root + source +
             'Files.writeString(safeDestination(target), "data"); // expect-finding\n', ""),
            ("literal_overwrite", root + source + 'target = Paths.get("/srv/out/fixed");\n' + safe, ""),
            ("one_branch_overwrite", root + source + 'if (enabled) { target = Paths.get("/srv/out/fixed"); }\n' + unsafe, ""),
            ("both_branches_overwrite", root + source +
             'if (enabled) { target = Paths.get("/srv/out/a"); } else { target = Paths.get("/srv/out/b"); }\n' + safe, ""),
            ("normalization_alone", root + canonical + unsafe, ""),
            ("same_target_rejecting_guard", root + canonical + guard + safe, ""),
            ("positive_guard", root + canonical + 'if (target.startsWith(root)) {\n' + safe + '}\n', ""),
            ("fallthrough_guard", root + canonical + 'if (!target.startsWith(root)) { audit(); }\n' + unsafe, ""),
            ("post_sink_guard", root + canonical + unsafe + guard, ""),
            ("conditional_guard", root + canonical + 'if (enabled) {\n' + guard + '}\n' + unsafe, ""),
            ("wrong_receiver_guard", root + canonical + path + ' audit = root.resolve("fixed").normalize();\n' +
             guard.replace('!target.', '!audit.') + unsafe, ""),
            ("target_reassigned_after_guard", root + canonical + guard + 'target = root.resolve(' + name + ');\n' + unsafe, ""),
            ("immutable_alias_guard", root + canonical + path + ' alias = target;\n' +
             guard.replace('!target.', '!alias.') + safe, ""),
            ("alias_reassigned_before_guard", root + canonical + path + ' alias = target;\n'
             'alias = root.resolve("fixed").normalize();\n' + guard.replace('!target.', '!alias.') + unsafe, ""),
            ("target_reassigned_before_alias_guard", root + canonical + path + ' alias = target;\n'
             'target = root.resolve(' + name + ');\n' + guard.replace('!target.', '!alias.') + unsafe, ""),
            ("alias_created_before_target_guard", root + canonical + path + ' alias = target;\n' + guard +
             safe.replace('(target,', '(alias,'), ""),
            ("checked_helper_trusted_root", root + path + ' target = checked(root, ' + name + ');\n' + safe, checked),
            ("checked_helper_attacker_root", untrusted_root + path + ' target = checked(root, ' + name + ');\n' + unsafe, checked),
            ("checked_sink_attacker_root", untrusted_root + 'checked(root, ' + name + ');\n', checked_sink),
            ("checked_sink_trusted_root", root + 'checked(root, ' + name + ');\n', checked_sink.replace(' // expect-finding', '')),
            ("direct_attacker_root", untrusted_root + canonical + guard + unsafe, ""),
            ("trusted_actual_guard_root", untrusted_root + canonical +
             'root = Paths.get("/srv/out").toAbsolutePath().normalize();\n' + guard + safe, ""),
            ("request_only_not_archive_rule", root + source.replace(name, 'request.getParameter("name")') + safe, ""),
            ("copy_source_only", root + source + 'Files.copy(target, root.resolve("fixed"));\n', ""),
            ("copy_destination", root + source + 'Files.copy(root.resolve("fixed"), target); // expect-finding\n', ""),
            ("move_destination", root + source + 'Files.move(root.resolve("fixed"), target); // expect-finding\n', ""),
            ("content_argument", root + 'Files.writeString(root.resolve("fixed"), ' + name + ');\n', ""),
            ("output_stream_destination", root + source +
             ('new ' if language == "java" else '') + 'FileOutputStream(target.toFile()); // expect-finding\n', ""),
            ("readonly_random_access", root + source +
             ('new ' if language == "java" else '') + 'RandomAccessFile(target.toFile(), "r");\n', ""),
            ("writable_random_access", root + source +
             ('new ' if language == "java" else '') + 'RandomAccessFile(target.toFile(), "rw"); // expect-finding\n', ""),
            ("contained_parent_preparation", root + canonical + guard + 'Files.createDirectories(target.getParent());\n' + safe, ""),
            ("contained_parent_write_is_not_proven", root + canonical + guard +
             'Files.writeString(target.getParent(), "data"); // expect-finding\n', ""),
            ("contained_parent_nonrecursive_mkdir", root + canonical + guard +
             'Files.createDirectory(target.getParent()); // expect-finding\n', ""),
            ("twice_parent_preparation", root + canonical + guard +
             'Files.createDirectories(target.getParent().getParent()); // expect-finding\n', ""),
            ("canonical_string_separator_guard", root + string + ' base = root.toFile().getCanonicalPath();\n' +
             string + ' target = root.resolve(' + name + ').toFile().getCanonicalPath();\n' +
             guard.replace('startsWith(root)', 'startsWith(base + File.separator)') +
             ('new ' if language == "java" else '') + 'FileOutputStream(target);\n', ""),
            ("canonical_string_unsafe_prefix", root + string + ' base = root.toFile().getCanonicalPath();\n' +
             string + ' target = root.resolve(' + name + ').toFile().getCanonicalPath();\n' +
             guard.replace('startsWith(root)', 'startsWith(base)') +
             ('new ' if language == "java" else '') + 'FileOutputStream(target); // expect-finding\n', ""),
            ("literal_entry_constructor", root +
             ('ZipEntry local = new ' if language == "java" else 'val local = ') + 'ZipEntry("fixed");\n' +
             source.replace(name, 'local.getName()') + safe, ""),
            ("tainted_entry_constructor", root +
             ('ZipEntry local = new ' if language == "java" else 'val local = ') + 'ZipEntry(' + name + ');\n' +
             source.replace(name, 'local.getName()') + unsafe, ""),
        ]
        if language == "kotlin":
            cases.append(("require_guard", root + canonical + 'require(target.startsWith(root))\n' + safe, ""))
        return cases

    def scan(self, language, name, source):
        from ubs_core.java_detectors import archive_extraction

        path = self.root / (language + "-" + name + (".java" if language == "java" else ".kt"))
        path.write_text(source, encoding="utf-8")
        findings = list(archive_extraction.find([path], language=language, rule_id=language + ".security.archive-extraction"))
        return path, findings

    def test_value_root_and_destination_semantics(self):
        for language in ("java", "kotlin"):
            for name, body, helper in self.cases(language):
                with self.subTest(language=language, case=name):
                    source = self.program(language, body, helper)
                    _, findings = self.scan(language, name, source)
                    expected = [number for number, line in enumerate(source.splitlines(), 1) if "// expect-finding" in line]
                    self.assertEqual([row[1] for row in findings], expected, findings)

    def test_original_archive_fixtures_at_actual_sinks(self):
        from ubs_core.java_detectors import archive_extraction

        for language, relative, expected in (
                ("java", "java/security/ArchiveExtractionBuggy.java", [17, 20, 21, 31, 34]),
                ("java", "java/security/ArchiveExtractionClean.java", []),
                ("kotlin", "kotlin/archive_extraction_buggy/zip_slip.kt", [12, 14, 16, 27, 34]),
                ("kotlin", "kotlin/archive_extraction_clean/zip_slip_safe.kt", [])):
            with self.subTest(path=relative):
                findings = list(archive_extraction.find([REPO_ROOT / "test-suite" / relative],
                    language=language, rule_id=language + ".security.archive-extraction"))
                self.assertEqual([row[1] for row in findings], expected, findings)

    def test_archive_identity_selected_helper_and_iteration(self):
        for language in ("java", "kotlin"):
            helper = ("ZipEntry relay(ZipEntry value) { return value; }" if language == "java" else
                      "fun relay(value: ZipEntry): ZipEntry { return value }")
            body = ("ZipEntry forwarded = relay(entry);" if language == "java" else "val forwarded = relay(entry)")
            body += '\nFiles.writeString(Paths.get("/srv/out").resolve(forwarded.getName()), "data"); // expect-finding\n'
            source = self.program(language, body, helper)
            _, findings = self.scan(language, "entry-helper", source)
            self.assertEqual([row[1] for row in findings], [number for number, line in enumerate(source.splitlines(), 1)
                                                         if "// expect-finding" in line])
        source = self.program("kotlin", 'val zip = ZipFile("archive.zip")\n'
            'for (item in zip.entries()) {\n'
            'Files.writeString(Paths.get("/srv/out").resolve(item.name), "data"); // expect-finding\n}\n')
        _, findings = self.scan("kotlin", "for-loop", source)
        expected = [number for number, line in enumerate(source.splitlines(), 1) if "// expect-finding" in line]
        self.assertEqual([row[1] for row in findings], expected, findings)

    def test_suppression_belongs_to_the_actual_sink(self):
        for language in ("java", "kotlin"):
            _, body, helper = self.cases(language)[0]
            rule = language + ".security.archive-extraction"
            for owner, marker, expected in (
                    ("source", "ubs:ignore[" + rule + "]", True),
                    ("sink", "ubs:ignore[" + rule + "]", False),
                    ("sink", "ubs:ignore[unrelated.rule]", True)):
                with self.subTest(language=language, owner=owner, marker=marker):
                    changed = body.replace("// expect-finding", "// " + marker) if owner == "sink" else body.replace(
                        ');\nFiles.writeString', '); // ' + marker + '\nFiles.writeString')
                    _, findings = self.scan(language, "suppressed-" + owner + str(expected), self.program(language, changed, helper))
                    self.assertEqual(len(findings), int(expected), findings)

    def test_annotated_request_root_is_not_a_trusted_helper_argument(self):
        for language in ("java", "kotlin"):
            body, helper = next((body, helper) for name, body, helper in self.cases(language)
                                if name == "checked_helper_attacker_root")
            source = self.program(language, body.replace('request.getParameter("root")', 'rootName'), helper)
            source = source.replace("Path destination", "@RequestParam String rootName") if language == "java" else source.replace(
                "destination: Path", "@RequestParam rootName: String")
            _, findings = self.scan(language, "annotated-root", source)
            expected = [number for number, line in enumerate(source.splitlines(), 1) if "// expect-finding" in line]
            self.assertEqual([row[1] for row in findings], expected, findings)

    def test_unrelated_entry_types_do_not_become_archive_sources(self):
        for language in ("java", "kotlin"):
            _, body, _ = self.cases(language)[0]
            source = self.program(language, body).replace("import java.util.zip.ZipEntry;", "import example.ZipEntry;")
            _, findings = self.scan(language, "unrelated-entry", source)
            self.assertEqual(findings, [])

    def test_unsupported_archive_state_is_partial_and_keeps_independent_findings(self):
        from ubs_core.java_detectors import archive_extraction
        from ubs_core.taint_flow import AnalysisLimit

        for language in ("java", "kotlin"):
            _, body, _ = self.cases(language)[0]
            source = self.program(language, body + '\nexternal(entry);\n')
            path = self.root / ("unknown-state." + ("java" if language == "java" else "kt"))
            path.write_text(source, encoding="utf-8")
            findings = []
            with self.assertRaisesRegex(AnalysisLimit, "archive state escapes"):
                findings.extend(archive_extraction.find([path], language=language))
            self.assertEqual([row[1] for row in findings], [number for number, line in enumerate(source.splitlines(), 1)
                                                         if "// expect-finding" in line], findings)
            engine = archive_extraction.ArchiveEngine(path, self.program(language, body))
            engine.budget.remaining = 0
            with self.assertRaises(AnalysisLimit):
                engine.analyze()

    def test_malformed_or_unsupported_files_keep_independent_supported_findings(self):
        from ubs_core.java_detectors import archive_extraction

        for language in ("java", "kotlin"):
            _, body, _ = self.cases(language)[0]
            source = self.program(language, body)
            supported, expected = self.scan(language, "supported", source)
            invalid = self.root / ("malformed." + ("java" if language == "java" else "kt"))
            invalid.write_text(source + "{", encoding="utf-8")
            findings = []
            with self.assertRaisesRegex(ValueError, "incomplete"):
                findings.extend(archive_extraction.find([invalid, supported], language=language))
            self.assertEqual(findings, expected)

    def test_source_to_actual_sink_witness(self):
        from ubs_core.java_detectors import archive_extraction

        _, body, _ = self.cases("java")[0]
        source = self.program("java", body)
        path, _ = self.scan("java", "witness", source)
        facts = archive_extraction.ArchiveEngine(path, source).analyze()
        sink = next(number for number, line in enumerate(source.splitlines(), 1) if "// expect-finding" in line)
        origin = next(number for number, line in enumerate(source.splitlines(), 1) if "entry.getName()" in line)
        self.assertEqual(list(facts), [sink])
        for fact in facts.values():
            for trace in fact:
                self.assertEqual((trace.evidence[0].line, trace.evidence[0].kind), (origin, "source"))
                self.assertEqual((trace.evidence[-1].line, trace.evidence[-1].kind), (sink, "sink"))

    @unittest.skipUnless(os.environ.get("UBS_JVM_ARCHIVE_E2E") == "1",
                         "set UBS_JVM_ARCHIVE_E2E=1 for actual CLI scans")
    def test_module_and_runner_json_sarif_and_partial_status(self):
        for language in ("java", "kotlin"):
            rule = language + ".security.archive-extraction"
            selected_cases = {name: (body, helper) for name, body, helper in self.cases(language)}
            unsafe, helper = selected_cases["identity_helper_name_is_not_proof"]
            clean, clean_helper = selected_cases["checked_helper_trusted_root"]
            cases = (("unsafe", unsafe, helper, False), ("clean", clean, clean_helper, False),
                     ("partial", unsafe + "\nexternal(entry);\n", helper, True))
            for label, body, helper, partial in cases:
                directory = self.root / (language + "-" + label + "-cli")
                directory.mkdir()
                source = self.program(language, body, helper)
                path = directory / ("ArchiveProbe.java" if language == "java" else "ArchiveProbe.kt")
                path.write_text(source, encoding="utf-8")
                expected = [number for number, line in enumerate(source.splitlines(), 1) if "// expect-finding" in line]
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                           UBS_NO_CACHE="1", ENABLE_UV_TOOLS="0", CI="1", NO_COLOR="1",
                           XDG_CACHE_HOME=str(directory / "cache"), XDG_CONFIG_HOME=str(directory / "config"),
                           XDG_DATA_HOME=str(directory / "data"))
                for surface in ("module", "runner"):
                    for format_ in ("json", "sarif"):
                        with self.subTest(language=language, case=label, surface=surface, format=format_):
                            entry = (REPO_ROOT / "modules" / ("ubs-" + language + ".sh")
                                     if surface == "module" else REPO_ROOT / "ubs")
                            command = ("bash", str(entry), "--only=4" if surface == "module" else "--only=" + language,
                                       "--format=" + format_, "--ci", str(path))
                            started = time.monotonic()
                            proc = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=180, env=env)
                            output = directory / (surface + "-" + format_)
                            output.with_suffix(".stdout").write_text(proc.stdout, encoding="utf-8")
                            output.with_suffix(".stderr").write_text(proc.stderr, encoding="utf-8")
                            output.with_suffix(".command.json").write_text(json.dumps({
                                "command": command, "exit": proc.returncode, "seconds": time.monotonic() - started,
                                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            }, indent=2), encoding="utf-8")
                            context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                            self.assertEqual(proc.returncode, 2 if partial else int(bool(expected)), context)
                            try:
                                report = json.loads(proc.stdout)
                            except json.JSONDecodeError as error:
                                self.fail(f"Invalid scanner JSON: {error}\n{context}")
                            if format_ == "json":
                                self.assertEqual(report["status"], "partial" if partial else "ok", context)
                                rule_key = "rule" if surface == "module" else "rule_id"
                                rows = [row for row in report.get("findings", []) if row[rule_key] == rule]
                                self.assertEqual([(row["line"], row["severity"]) for row in rows],
                                                 [(line, "critical") for line in expected], context)
                                for row in rows:
                                    self.assertEqual(Path(row["path" if surface == "module" else "file"]).resolve(), path, context)
                                    self.assertIn("archive filesystem destination", row["message"], context)
                                totals = report if surface == "module" else report["totals"]
                                self.assertEqual((totals["critical"], totals["warning"]), (len(expected), 0), context)
                            else:
                                rows = [row for run in report["runs"] for row in run.get("results", []) if row["ruleId"] == rule]
                                sites = [row["locations"][0]["physicalLocation"] for row in rows]
                                self.assertEqual([(site["region"]["startLine"], row["level"]) for site, row in zip(sites, rows)],
                                                 [(line, "error") for line in expected], context)
                                for site in sites:
                                    self.assertEqual(sarif_location_path(site["artifactLocation"]["uri"], directory).resolve(), path, context)
                                invocations = [item for run in report["runs"] for item in run.get("invocations", [])]
                                if partial:
                                    self.assertTrue(invocations, context)
                                    self.assertTrue(all(item["executionSuccessful"] is False for item in invocations), context)
                                else:
                                    self.assertTrue(all(item.get("executionSuccessful") is not False for item in invocations), context)


@unittest.skipUnless(os.environ.get("UBS_SPRING_SQL_E2E") == "1",
                     "set UBS_SPRING_SQL_E2E=1 for actual Spring SQL CLI scans")
class SpringSqlPublicTests(unittest.TestCase):
    """The SQL text and bound values have different roles at Spring sinks."""

    @classmethod
    def setUpClass(cls):
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "spring-sql-public"
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.root = Path(tempfile.mkdtemp(prefix="run-", dir=artifacts))

    @staticmethod
    def programs(language, clean):
        fixtures = (
            ("ListProbe", "org.springframework.jdbc.core.JdbcOperations",
             'jdbc.queryForList(sql, request.getParameter("id"));',
             '"SELECT id FROM users WHERE id = ?"'),
            ("NamedProbe", "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations",
             'jdbc.queryForList(sql, java.util.Map.of("id", request.getParameter("id")));',
             '"SELECT id FROM users WHERE id = :id"'),
            ("ExecuteProbe", "org.springframework.jdbc.core.JdbcTemplate",
             'jdbc.execute(sql);', '"CREATE TABLE example (id integer)"'),
        )
        result = []
        for name, api, call, literal in fixtures:
            value = literal if clean else 'request.getParameter("query")'
            imports = 'import jakarta.servlet.http.HttpServletRequest;\nimport ' + api + ';\n'
            receiver = api.rsplit(".", 1)[-1]
            if language == "java":
                text = (imports + 'class ' + name + ' {\n'
                        '  void run(HttpServletRequest request, ' + receiver + ' jdbc) {\n'
                        '    String sql = ' + value + ';\n    ' + call + '\n  }\n}\n')
                suffix, line = ".java", 6
            else:
                text = (imports + 'fun run(request: HttpServletRequest, jdbc: ' + receiver + ') {\n'
                        '    val sql = ' + value + ';\n    ' + call + '\n}\n')
                suffix, line = ".kt", 5
            result.append((name + suffix, text, line))
        return result

    def test_module_and_runner_exact_sql_sites_and_partial_results(self):
        for language in ("java", "kotlin"):
            rule = language + ".security.sql-injection"
            for label in ("unsafe", "clean", "partial"):
                directory = self.root / (language + "-" + label)
                directory.mkdir()
                programs = self.programs(language, label == "clean")
                expected = [] if label == "clean" else sorted(
                    (name, rule, line, 5, "critical") for name, _text, line in programs)
                for name, source, _line in programs:
                    (directory / name).write_text(source, encoding="utf-8")
                if label == "partial":
                    # A broken selected neighbor must not erase the three
                    # independently supported findings or claim a clean scan.
                    suffix = ".java" if language == "java" else ".kt"
                    broken = programs[0][1].replace("ListProbe", "Broken") + "{\n"
                    (directory / ("Broken" + suffix)).write_text(broken, encoding="utf-8")
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_AUTO_UPDATE="1",
                           UBS_ENABLE_AUTO_UPDATE="0", UBS_NO_CACHE="1", ENABLE_UV_TOOLS="0",
                           CI="1", NO_COLOR="1", UBS_CACHE_DIR=str(directory / "cache"),
                           XDG_CACHE_HOME=str(directory / "xdg-cache"),
                           XDG_CONFIG_HOME=str(directory / "config"), XDG_DATA_HOME=str(directory / "data"))
                for surface in ("module", "runner"):
                    for format_ in ("json", "sarif"):
                        case = "-".join((language, label, surface, format_))
                        with self.subTest(case=case):
                            entry = (REPO_ROOT / "modules" / ("ubs-" + language + ".sh")
                                     if surface == "module" else REPO_ROOT / "ubs")
                            selection = ("--only=" + ("4" if language == "java" else "13")
                                         if surface == "module" else "--only=" + language)
                            command = ["bash", str(entry), selection, "--format=" + format_, "--ci", str(directory)]
                            print("[spring-sql-" + case + "] RUN", flush=True)
                            started = time.monotonic()
                            proc = subprocess.run(command, cwd=directory, env=env, capture_output=True,
                                                  text=True, timeout=180)
                            elapsed = time.monotonic() - started
                            output = directory / (surface + "-" + format_)
                            output.with_suffix(".stdout").write_text(proc.stdout, encoding="utf-8")
                            output.with_suffix(".stderr").write_text(proc.stderr, encoding="utf-8")
                            sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in directory.glob("*.java" if language == "java" else "*.kt")}
                            tools = {path: hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest()
                                     for path in ("ubs", "modules/helpers/ubs_core/analyzers/taint_java_sql.py",
                                                  "modules/helpers/ubs_core/analyzers/taint_kotlin_sql.py")}
                            output.with_suffix(".receipt.json").write_text(json.dumps({
                                "case": case, "command": command, "exit": proc.returncode, "seconds": elapsed,
                                "sources": sources, "tools": tools, "python": sys.version,
                                "ast_grep": shutil.which("ast-grep"),
                            }, indent=2), encoding="utf-8")
                            context = f"{command!r}\nexit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                            self.assertEqual(proc.returncode, 2 if label == "partial" else int(bool(expected)), context)
                            try:
                                report = json.loads(proc.stdout)
                            except json.JSONDecodeError as error:
                                self.fail(f"Invalid scanner JSON: {error}\n{context}")
                            if format_ == "json":
                                self.assertEqual(report["status"], "partial" if label == "partial" else "ok", context)
                                rows = report.get("findings", [])
                                actual = []
                                for row in rows:
                                    path = Path(row["path" if surface == "module" else "file"])
                                    self.assertEqual(path.resolve().parent, directory, context)
                                    actual.append((path.name, row["rule" if surface == "module" else "rule_id"],
                                                   row["line"], row["col"], row["severity"]))
                                    evidence = row["extras"]["taint_path"]
                                    self.assertEqual((evidence[0]["kind"], evidence[0]["line"]),
                                                     ("source", row["line"] - 1), context)
                                    self.assertEqual((evidence[-1]["kind"], evidence[-1]["line"]),
                                                     ("sink", row["line"]), context)
                                totals = report if surface == "module" else report["totals"]
                                self.assertEqual((totals["critical"], totals["warning"], totals["info"]),
                                                 (len(expected), 0, 0), context)
                            else:
                                actual = []
                                for run in report["runs"]:
                                    for row in run.get("results", []):
                                        location = row["locations"][0]["physicalLocation"]
                                        path = sarif_location_path(location["artifactLocation"]["uri"], directory).resolve()
                                        self.assertEqual(path.parent, directory, context)
                                        self.assertEqual(row["level"], "error", context)
                                        actual.append((path.name, row["ruleId"], location["region"]["startLine"],
                                                       location["region"]["startColumn"], "critical"))
                                        self.assertTrue(row.get("codeFlows"), context)
                                invocations = [item for run in report["runs"] for item in run.get("invocations", [])]
                                if label == "partial":
                                    self.assertTrue(invocations, context)
                                    self.assertTrue(all(item["executionSuccessful"] is False for item in invocations), context)
                                else:
                                    self.assertTrue(all(item.get("executionSuccessful") is not False for item in invocations), context)
                            self.assertEqual(sorted(actual), expected, context)
                            print(f"[spring-sql-{case}] PASS ({elapsed:.3f}s)", flush=True)


class JVMOutboundDataflowTests(unittest.TestCase):
    """An HTTP destination is a value, not all text in a nearby statement."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="ubs-jvm-outbound-", dir="/tmp"))

    @staticmethod
    def program(language, body, helper="", fields=""):
        signature = ("void handle(HttpServletRequest request, boolean enabled)" if language == "java" else
                     "fun handle(request: HttpServletRequest, enabled: Boolean)")
        return ("import java.net.URI;\nimport java.net.URL;\nimport java.net.http.HttpRequest;\n"
                "import java.util.Set;\nimport javax.servlet.http.HttpServletRequest;\nclass OutboundProbe {\n" +
                fields + "\n" + helper + "\n" + signature + " {\n" + body + "}\n}\n")

    @staticmethod
    def cases(language):
        declaration = "String" if language == "java" else "var"
        uri = "URI" if language == "java" else "var"
        reject = 'throw new IllegalArgumentException("blocked");' if language == "java" else 'throw IllegalArgumentException("blocked");'
        source = declaration + ' target = request.getParameter("url");\n'
        parsed = uri + ' target = URI.create(request.getParameter("url"));\n'
        safe = 'client.get(target);\n'
        unsafe = 'client.get(target); // expect-finding\n'
        scheme = '"https".equals(target.getScheme())' if language == "java" else 'target.scheme == "https"'
        host = '"api.example.com".equals(target.getHost())' if language == "java" else 'target.host == "api.example.com"'
        guard = 'if (!(' + scheme + ') || !(' + host + ')) { ' + reject + ' }\n'
        identity = ('String safeURL(String value) { return value; }' if language == "java" else
                    'fun safeURL(value: String): String { return value }')
        constant = ('String endpoint(String value) { return "https://api.example.com"; }' if language == "java" else
                    'fun endpoint(value: String): String { return "https://api.example.com" }')
        origin = ('String endpoint() { return request.getParameter("url"); }' if language == "java" else
                  'fun endpoint(): String { return request.getParameter("url") }')
        validating = (('String endpoint(String raw) {\n' if language == "java" else
                       'fun endpoint(raw: String): String {\n') + parsed.replace('request.getParameter("url")', 'raw') +
                      guard + 'return target.toString();\n}')
        cases = [
            ("direct", source + unsafe, ""),
            ("identity_safe_name", source + 'client.get(safeURL(target)); // expect-finding\n', identity),
            ("renamed_identity", source + 'client.get(relay(target)); // expect-finding\n', identity.replace("safeURL", "relay")),
            ("constant_helper_discards_input", 'client.get(endpoint(request.getParameter("url")));\n', constant),
            ("helper_returns_request", 'client.get(endpoint()); // expect-finding\n', origin),
            ("unknown_safe_named_helper", 'client.get(validateOutboundUrl(request.getParameter("url"))); // expect-finding\n', ""),
            ("constant_overwrite", source + 'target = "https://api.example.com";\n' + safe, ""),
            ("conditional_constant_overwrite", source + 'if (enabled) { target = "https://api.example.com"; }\n' + unsafe, ""),
            ("both_branches_overwrite", source + 'if (enabled) { target = "https://api.example.com"; } else { target = "https://hooks.example.com"; }\n' + safe, ""),
            ("full_guard", parsed + guard + safe, ""),
            ("scheme_only_guard", parsed + 'if (!(' + scheme + ')) { ' + reject + ' }\n' + unsafe, ""),
            ("host_only_guard", parsed + 'if (!(' + host + ')) { ' + reject + ' }\n' + unsafe, ""),
            ("unsafe_host_suffix", parsed + guard.replace(host, 'target.getHost().endsWith("example.com")') + unsafe, ""),
            ("fallthrough_guard", parsed + guard.replace(reject, 'log("blocked");') + unsafe, ""),
            ("unrelated_uri_guard", parsed + uri + ' audit = URI.create("https://api.example.com");\n' +
             guard.replace("target.", "audit.") + unsafe, ""),
            ("reassignment_after_guard", parsed + guard + 'target = URI.create(request.getParameter("other"));\n' + unsafe, ""),
            ("guarded_alias", parsed + guard + uri + ' alias = target;\nclient.get(alias);\n', ""),
            ("alias_before_guard", parsed + uri + ' alias = target;\n' + guard + 'client.get(alias);\n', ""),
            ("positive_branch_guard", parsed + 'if (' + scheme + ' && ' + host + ') {\n' + safe + '} else {\n' + unsafe + '}\n', ""),
            ("real_helper_validation", 'client.get(endpoint(request.getParameter("url")));\n', validating),
            ("renamed_real_helper", 'client.get(ordinary(request.getParameter("url")));\n', validating.replace("endpoint", "ordinary")),
            ("helper_partial_validation", 'client.get(endpoint(request.getParameter("url"))); // expect-finding\n', validating.replace(guard, 'if (!(' + scheme + ')) { ' + reject + ' }\n')),
            ("resolve_overrides_authority", uri + ' target = URI.create("https://api.example.com/").resolve(request.getParameter("url"));\n' + unsafe, ""),
            ("resolve_invalidates_guard", parsed + guard + 'target = target.resolve(request.getParameter("other"));\n' + unsafe, ""),
            ("resolve_then_validate", uri + ' target = URI.create("https://api.example.com/").resolve(request.getParameter("url"));\n' + guard + safe, ""),
            ("string_change_invalidates_guard", parsed + guard + 'client.get("https://" + target.toString()); // expect-finding\n', ""),
            ("helper_unknown_transformation", parsed + guard + 'client.get(transform(target.toString())); // expect-finding\n',
             ('String transform(String value) { return mystery(value); }' if language == "java" else
              'fun transform(value: String): String { return mystery(value) }')),
            ("direct_open_stream", 'new URL(request.getParameter("url")).openStream(); // expect-finding\n' if language == "java" else
             'URL(request.getParameter("url")).openStream(); // expect-finding\n', ""),
            ("request_body_is_not_destination", 'restTemplate.postForObject("https://api.example.com", request.getParameter("payload"), String.class);\n', ""),
            ("post_destination_is_first_argument", 'restTemplate.postForObject(request.getParameter("url"), "fixed", String.class); // expect-finding\n', ""),
            ("uri_path_query_are_not_destination", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", null, "api.example.com", -1, request.getParameter("path"), request.getParameter("query"), null);\n' + safe, ""),
            ("uri_component_host_is_destination", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", null, request.getParameter("host"), -1, "/", null, null);\n' + unsafe, ""),
            ("uri_component_port_is_destination", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", null, "api.example.com", parseInt(request.getParameter("port")), "/", null, null);\n' + unsafe, ""),
            ("uri_null_host_path_can_supply_authority", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", null, null, -1, request.getParameter("path"), null, null);\n' + unsafe, ""),
            ("uri_null_authority_path_can_supply_authority", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", null, request.getParameter("path"), null, null);\n' + unsafe, ""),
            ("uri_short_null_host_path_can_supply_authority", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", null, request.getParameter("path"), null);\n' + unsafe, ""),
            ("uri_unknown_host_path_can_supply_authority", uri + ' target = ' + ('new ' if language == "java" else '') +
             'URI("https", host, request.getParameter("path"), null);\n' + unsafe, ""),
            ("inert_check_comment", source + '// URI.create(target); getHost(); getScheme(); throw\n' + unsafe, ""),
        ]
        if language == "kotlin":
            cases.extend([
                ("template_change_invalidates_guard", parsed + guard + 'client.get("https://$target"); // expect-finding\n', ""),
                ("named_url_operand", source + 'client.get(body = "fixed", urlString = target); // expect-finding\n', ""),
            ])
        return cases

    def check_source(self, language, name, text):
        from ubs_core.java_detectors import ssrf_outbound_url

        path = self.root / (language + "-" + name + (".java" if language == "java" else ".kt"))
        path.write_text(text, encoding="utf-8")
        rows = list(ssrf_outbound_url.find([path], language=language, rule_id=language + ".security.ssrf-outbound-url"))
        expected = [number for number, line in enumerate(text.splitlines(), 1) if "// expect-finding" in line]
        self.assertEqual([(Path(row[0]), row[1], row[2]) for row in rows], [(path, line, 1) for line in expected], rows)
        return path, expected

    def test_value_and_control_flow(self):
        for language in ("java", "kotlin"):
            for name, body, helper in self.cases(language):
                with self.subTest(language=language, case=name):
                    self.check_source(language, name, self.program(language, body, helper))

    def test_builder_destination_state(self):
        for language in ("java", "kotlin"):
            builder = "HttpRequest.Builder" if language == "java" else "var"
            request = "HttpRequest" if language == "java" else "var"
            clean = builder + ' builder = HttpRequest.newBuilder(URI.create("https://api.example.com"));\n'
            unsafe = builder + ' builder = HttpRequest.newBuilder(URI.create(request.getParameter("url")));\n'
            badbuild = 'builder.build(); // expect-finding\n'
            cases = [
                ("header_is_not_destination", clean + 'builder.header("X-Value", request.getParameter("value"));\nbuilder.build();\n'),
                ("fluent_header_is_not_destination", request + ' outgoing = HttpRequest.newBuilder(URI.create("https://api.example.com"))\n.header("X-Value", request.getParameter("value")).build();\nclient.send(outgoing, handler);\n'),
                ("body_is_not_destination", clean + 'builder.POST(HttpRequest.BodyPublishers.ofString(request.getParameter("body")));\nbuilder.build();\n'),
                ("destination_survives_headers", unsafe + 'builder.header("X-Value", "fixed");\n' + badbuild),
                ("destination_overwrite", unsafe + 'builder.uri(URI.create("https://api.example.com"));\nbuilder.build();\n'),
                ("unsafe_destination_mutation", clean + 'builder.uri(URI.create(request.getParameter("url")));\n' + badbuild),
                ("conditional_mutation", unsafe + 'if (enabled) { builder.uri(URI.create("https://api.example.com")); }\n' + badbuild),
                ("alias_mutation", clean + builder + ' alias = builder;\nalias.uri(URI.create(request.getParameter("url")));\n' + badbuild),
                ("alias_overwrite", unsafe + builder + ' alias = builder;\nalias.uri(URI.create("https://api.example.com"));\nbuilder.build();\n'),
                ("fluent_alias_mutation", clean + builder + ' alias = builder;\nalias.header("X-Value", "fixed").uri(URI.create(request.getParameter("url")));\n' + badbuild),
                ("copied_builder_is_distinct", unsafe + builder + ' copy = builder.copy();\ncopy.uri(URI.create("https://api.example.com"));\n' + badbuild + 'copy.build();\n'),
                ("copy_retains_destination", unsafe + builder + ' copy = builder.copy();\nbuilder.uri(URI.create("https://api.example.com"));\ncopy.build(); // expect-finding\n'),
                ("request_is_immutable_snapshot", clean + request + ' outgoing = builder.build();\nbuilder.uri(URI.create(request.getParameter("url")));\nclient.send(outgoing, handler);\n' + badbuild),
                ("request_snapshot_retains_destination", unsafe + request + ' outgoing = builder.build(); // expect-finding\nbuilder.uri(URI.create("https://api.example.com"));\nclient.send(outgoing, handler); // expect-finding\n'),
                ("send_async", unsafe + 'client.sendAsync(builder.build(), handler); // expect-finding\n'),
                ("joined_receiver_overwrite", clean.replace(' builder =', ' first =') +
                 unsafe.replace(' builder =', ' second =') + builder + ' selected = first;\n' +
                 'if (enabled) { selected = first; } else { selected = second; }\n' +
                 'selected.uri(URI.create("https://api.example.com"));\nselected.build();\n' +
                 'second.build(); // expect-finding\n'),
                ("other_joined_alias_stays_weak", clean.replace(' builder =', ' first =') +
                 unsafe.replace(' builder =', ' second =') + builder + ' selected = first;\n' +
                 builder + ' other = second;\n' +
                 'if (enabled) { selected = first; other = second; } else { selected = second; other = first; }\n' +
                 'selected.uri(URI.create("https://api.example.com"));\nselected.build();\n' +
                 'other.build(); // expect-finding\n'),
            ]
            for name, body in cases:
                with self.subTest(language=language, case=name):
                    self.check_source(language, name, self.program(language, body))

    def test_factory_and_allowlist_identity(self):
        for language in ("java", "kotlin"):
            fields = ('private static final Set<String> HOSTS = Set.of("api.example.com");' if language == "java" else
                      'private val HOSTS = setOf("api.example.com")')
            reject = 'throw new IllegalArgumentException();' if language == "java" else 'throw IllegalArgumentException();'
            parsed = ('URI' if language == "java" else 'var') + ' target = URI.create(request.getParameter("url"));\n'
            guard = ('if (!"https".equals(target.getScheme()) || !HOSTS.contains(target.getHost()))' if language == "java" else
                     'if (target.scheme != "https" || target.host !in HOSTS)') + ' { ' + reject + ' }\n'
            clean = self.program(language, parsed + guard + 'client.get(target);\n', fields=fields)
            with self.subTest(language=language, case="verified_host_set"):
                self.check_source(language, "host_set", clean)
            unsafe = clean.replace('client.get(target);', 'client.get(target); // expect-finding')
            for name, text in (
                ("foreign_uri_import", unsafe.replace('import java.net.URI;', 'import example.URI;')),
                ("local_uri_factory", unsafe.replace(parsed, ('Object URI = factory;\n' if language == "java" else
                                                              'val URI = factory;\n') + parsed)),
                ("field_uri_factory", unsafe.replace(fields, fields + ('\nObject URI;' if language == "java" else '\nval URI: Factory'))),
                ("local_host_set", unsafe.replace(parsed, ('Set<String> HOSTS = requestHosts;\n' if language == "java" else
                                                           'val HOSTS = requestHosts;\n') + parsed)),
                ("mutated_host_set", unsafe.replace(parsed, 'HOSTS.add(request.getParameter("host"));\n' + parsed)),
                ("foreign_set_factory", unsafe.replace('import java.util.Set;', 'import example.Set;')),
            ):
                with self.subTest(language=language, case=name):
                    self.check_source(language, name, text)

    def test_original_ssrf_fixtures(self):
        from ubs_core.java_detectors import ssrf_outbound_url

        for language, name, expected in (
            ("java", "java/security/SsrfBuggy.java", [20, 21, 26, 31, 36, 43, 50]),
            ("java", "java/security/SsrfClean.java", []),
            ("kotlin", "kotlin/ssrf_buggy/RequestUrls.kt", [20, 25]),
            ("kotlin", "kotlin/ssrf_clean/RequestUrlsSafe.kt", []),
        ):
            with self.subTest(path=name):
                rows = list(ssrf_outbound_url.find([REPO_ROOT / "test-suite" / name], language=language,
                                                  rule_id=language + ".security.ssrf-outbound-url"))
                self.assertEqual([row[1] for row in rows], expected, rows)

    def test_annotated_parameters_are_scoped_sources(self):
        for language in ("java", "kotlin"):
            for annotation in ("RequestParam", "RequestHeader", "QueryParam", "PathVariable", "CookieValue"):
                signature = ("void annotated(@" + annotation + " String target)" if language == "java" else
                             "fun annotated(@" + annotation + " target: String)")
                helper = signature + ' {\nclient.get(target); // expect-finding\n}\n'
                body = ('String' if language == "java" else 'val') + ' target = "https://api.example.com";\nclient.get(target);\n'
                with self.subTest(language=language, annotation=annotation):
                    self.check_source(language, "annotated-" + annotation, self.program(language, body, helper))

    def test_unsupported_state_and_budget_are_explicit(self):
        from ubs_core.java_detectors import ssrf_outbound_url
        from ubs_core.taint_flow import AnalysisLimit

        cases = (
            ('restTemplate.getForObject("https://{host}/", String.class, request.getParameter("host"));', ""),
            ('HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("https://api.example.com"));\n'
             'change(builder, request.getParameter("url"));\nbuilder.build();',
             'void change(HttpRequest.Builder builder, String target) { builder.uri(URI.create(target)); }'),
            ('HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("https://api.example.com"));\n'
             'unknown(builder, request.getParameter("url"));\nbuilder.build();', ""),
            ('switch (request.getParameter("url")) { default: client.get(request.getParameter("other")); }', ""),
        )
        for index, (body, helper) in enumerate(cases):
            with self.subTest(case=index):
                path = self.root / ("unsupported-" + str(index) + ".java")
                path.write_text(self.program("java", body, helper), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    list(ssrf_outbound_url.find([path]))
        engine = ssrf_outbound_url.SSRFEngine(self.root / "budget.java", self.program("java",
            'client.get(request.getParameter("url"));'))
        engine.budget.remaining = 0
        with self.assertRaises(AnalysisLimit):
            engine.analyze()

    def test_module_and_runner_json_sarif(self):
        for language in ("java", "kotlin"):
            for name, body, helper in self.cases(language):
                if name not in {"identity_safe_name", "real_helper_validation"}:
                    continue
                text = self.program(language, body, helper)
                directory = self.root / (language + "-" + name + "-cli")
                directory.mkdir()
                path = directory / ("OutboundProbe.java" if language == "java" else "OutboundProbe.kt")
                path.write_text(text, encoding="utf-8")
                expected = [number for number, line in enumerate(text.splitlines(), 1) if "// expect-finding" in line]
                for surface in ("module", "runner"):
                    for format_ in ("json", "sarif"):
                        with self.subTest(language=language, case=name, surface=surface, format=format_):
                            entry = (REPO_ROOT / "modules" / ("ubs-" + language + ".sh")
                                     if surface == "module" else REPO_ROOT / "ubs")
                            command = (str(entry), "--only=4" if surface == "module" else "--only=" + language,
                                       "--format=" + format_, "--ci", str(path))
                            started = time.monotonic()
                            proc = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=180,
                                                  env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_AUTO_UPDATE="1",
                                                           UBS_NO_CACHE="1", ENABLE_UV_TOOLS="0"))
                            label = surface + "-" + format_
                            (directory / (label + ".stdout")).write_text(proc.stdout, encoding="utf-8")
                            (directory / (label + ".stderr")).write_text(proc.stderr, encoding="utf-8")
                            (directory / (label + ".command.json")).write_text(json.dumps({
                                "command": command, "exit": proc.returncode, "seconds": time.monotonic() - started,
                                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            }, indent=2), encoding="utf-8")
                            context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                            self.assertEqual(proc.returncode, int(bool(expected)), context)
                            try:
                                report = json.loads(proc.stdout)
                            except json.JSONDecodeError as error:
                                self.fail(f"Invalid scanner JSON: {error}\n{context}")
                            rule = language + ".security.ssrf-outbound-url"
                            if format_ == "json":
                                records = report.get("findings", []) if surface == "runner" else report["findings"]
                                key = "rule_id" if surface == "runner" else "rule"
                                actual = [(row[key], row["line"], row["severity"]) for row in records]
                                self.assertEqual(actual, [(rule, line, "critical") for line in expected], context)
                                totals = report["totals"] if surface == "runner" else report
                                self.assertEqual((totals["critical"], totals["warning"]), (len(expected), 0), context)
                            else:
                                records = [row for run in report["runs"] for row in run.get("results", [])]
                                unexpected = [row for row in records if row.get("ruleId") != rule
                                              and row.get("level", "warning") in {"error", "warning"}]
                                self.assertEqual(unexpected, [], context)
                                actual = [(row["ruleId"], row["locations"][0]["physicalLocation"]["region"]["startLine"],
                                           row["level"]) for row in records if row["ruleId"] == rule]
                                self.assertEqual(actual, [(rule, line, "error") for line in expected], context)


class JVMHeaderDataflowTests(unittest.TestCase):
    """Header safety belongs to the value and branch, never a helper's name."""

    @classmethod
    def setUpClass(cls):
        artifacts = REPO_ROOT / "test-suite/artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.root = Path(tempfile.mkdtemp(prefix="jvm-header-flow-", dir=artifacts))

    @staticmethod
    def cases(language):
        declaration = "String" if language == "java" else "var"
        thrown = 'throw new IllegalArgumentException("bad");' if language == "java" else 'throw IllegalArgumentException("bad");'
        source = declaration + ' value = request.getParameter("value");\n'
        unsafe = 'response.setHeader("X-Value", value); // expect-finding\n'
        safe = 'response.setHeader("X-Value", value);\n'
        guard = 'if (value.contains("\\r") || value.contains("\\n")) { ' + thrown + ' }\n'
        identity = ('String safeHeaderValue(String raw) { return raw; }' if language == "java" else
                    'fun safeHeaderValue(raw: String): String { return raw }')
        strip = ('String clean(String raw) { return raw.replace("\\r", "").replace("\\n", ""); }'
                 if language == "java" else
                 'fun clean(raw: String): String { return raw.replace("\\r", "").replace("\\n", "") }')
        recursive = ('String relay(String raw, boolean repeat) { if (repeat) return relay(raw, false); return raw; }'
                     if language == "java" else
                     'fun relay(raw: String, repeat: Boolean): String { if (repeat) return relay(raw, false); return raw }')
        writer = ('void write(String raw, HttpServletResponse response) {\n' if language == "java" else
                  'fun write(raw: String, response: HttpServletResponse) {\n')
        writer += 'response.setHeader("X-Value", raw); // expect-finding\n}\n'
        cases = [
            ("direct", source + unsafe, ""),
            ("safe_name_identity", declaration + ' value = safeHeaderValue(request.getParameter("value"));\n' + unsafe, identity),
            ("renamed_identity", declaration + ' value = identity(request.getParameter("value"));\n' + unsafe,
             identity.replace("safeHeaderValue", "identity")),
            ("recursive_identity", declaration + ' value = relay(request.getParameter("value"), enabled);\n' + unsafe, recursive),
            ("selected_helper_sink", 'write(request.getParameter("value"), response);\n', writer),
            ("selected_helper_safe_argument", 'write(request.getParameter("value").replace("\\r", "").replace("\\n", ""), response);\n',
             writer.replace(" // expect-finding", "")),
            ("constant_overwrite", source + 'value = "fixed";\n' + safe, ""),
            ("branch_overwrite", source + 'if (enabled) { value = "fixed"; }\n' + unsafe, ""),
            ("both_branches_overwrite", source + 'if (enabled) { value = "first"; } else { value = "second"; }\n' + safe, ""),
            ("real_reject", source + guard + safe, ""),
            ("partial_reject", source + 'if (value.contains("\\r")) { ' + thrown + ' }\n' + unsafe, ""),
            ("fallthrough_check", source + 'if (value.contains("\\r") || value.contains("\\n")) { log("bad"); }\n' + unsafe, ""),
            ("different_value_check", source + declaration + ' other = request.getParameter("other");\n' +
             guard.replace("value.contains", "other.contains") + unsafe, ""),
            ("rebound_after_guard", source + guard + 'value = request.getParameter("other");\n' + unsafe, ""),
            ("guarded_branch_only", source + 'if (!value.contains("\\r") && !value.contains("\\n")) {\n' +
             safe + '} else {\n' + unsafe + '}\n', ""),
            ("helper_real_strip", declaration + ' value = clean(request.getParameter("value"));\n' + safe, strip),
            ("inline_real_strip", source + 'value = value.replace("\\r", "").replace("\\n", "");\n' + safe, ""),
            ("strip_one_character", source + 'value = value.replace("\\r", "");\n' + unsafe, ""),
            ("replace_first_is_not_safe", source + 'value = value.replaceFirst("[\\r\\n]", "");\n' + unsafe, ""),
            ("unrelated_strip_argument", source + 'response.setHeader("X-Value".replace("\\r", "").replace("\\n", ""), value); // expect-finding\n', ""),
            ("partial_strip_in_helper", declaration + ' value = clean(request.getParameter("value"));\n' + unsafe,
             strip.replace('.replace("\\n", "")', "")),
            ("sanitized_and_raw_concat", source + 'value = value.replace("\\r", "").replace("\\n", "") + request.getParameter("other");\n' + unsafe, ""),
            ("guard_then_control_concat", source + guard + 'value = value + "\\r\\n";\n' + unsafe, ""),
            ("guard_then_control_append", source + guard + 'value += "\\r\\n";\n' + unsafe, ""),
            ("guard_then_safe_prefix", source + guard + 'value = "prefix=" + value;\n' + safe, ""),
            ("encoded_value", source + 'value = URLEncoder.encode(value, StandardCharsets.UTF_8);\n' + safe, ""),
            ("unknown_safe_named_helper", declaration + ' value = sanitizeHeader(request.getParameter("value"));\n' + unsafe, ""),
            ("inert_guard_text", source + declaration + ' decoy = "\\r\\n throw return";\n' + unsafe, ""),
        ]
        if language == "java":
            cases.extend([
                ("indexof_reject", source + "if (value.indexOf('\\r') >= 0 || value.indexOf('\\n') >= 0) { " + thrown + " }\n" + safe, ""),
                ("regex_strip", source + 'value = value.replaceAll("[\\r\\n]", "");\n' + safe, ""),
                ("regex_reinserts_match", source + 'value = value.replaceAll("[\\r\\n]", "$0");\n' + unsafe, ""),
            ])
        else:
            cases.extend([
                ("require_reject", source + "require(!value.contains('\\r') && !value.contains('\\n'))\n" + safe, ""),
                ("named_header_arguments", source + 'response.header(value = value, name = "X-Value"); // expect-finding\n', ""),
                ("template_replacement_reintroduces_controls", source + 'val replacement = request.getParameter("other");\n' +
                 'value = value.replace("\\n", "").replace("\\r", "$replacement");\n' + unsafe, ""),
                ("braced_template_replacement_reintroduces_controls", source + 'val replacement = request.getParameter("other");\n' +
                 'value = value.replace("\\n", "").replace("\\r", "${replacement}");\n' + unsafe, ""),
            ])
        return cases

    @staticmethod
    def program(language, body, helper=""):
        imports = "\n".join((
            "import javax.servlet.http.HttpServletRequest;", "import javax.servlet.http.HttpServletResponse;",
            "import java.net.URLEncoder;", "import java.nio.charset.StandardCharsets;"))
        signature = ("void handle(HttpServletRequest request, HttpServletResponse response, boolean enabled)" if language == "java" else
                     "fun handle(request: HttpServletRequest, response: HttpServletResponse, enabled: Boolean)")
        if language == "kotlin" and "response.header(value =" in body:
            imports = imports.replace("javax.servlet.http.HttpServletResponse", "io.ktor.server.response.ApplicationResponse")
            imports += "\nimport io.ktor.server.response.header;"
            signature = signature.replace("HttpServletResponse", "ApplicationResponse")
        return imports + "\nclass HeaderProbe {\n" + helper + "\n" + signature + " {\n" + body + "}\n}\n"

    def test_value_and_control_flow(self):
        from ubs_core.java_detectors import header_injection

        for language in ("java", "kotlin"):
            for name, body, helper in self.cases(language):
                with self.subTest(language=language, case=name):
                    text = self.program(language, body, helper)
                    path = self.root / (language + "-" + name + (".java" if language == "java" else ".kt"))
                    path.write_text(text, encoding="utf-8")
                    rule = language + ".security.header-injection"
                    findings = list(header_injection.find([path], language=language, rule_id=rule))
                    expected = [number for number, line in enumerate(text.splitlines(), 1) if "// expect-finding" in line]
                    (path.with_suffix(path.suffix + ".result.json")).write_text(
                        json.dumps({"expected_lines": expected, "findings": findings}, default=str, indent=2), encoding="utf-8")
                    self.assertEqual([row[1] for row in findings], expected, findings)

    def test_original_header_fixtures(self):
        from ubs_core.java_detectors import header_injection

        cases = (
            ("java", "java/security/HeaderInjectionBuggy.java", [13, 18, 23, 30, 35, 40]),
            ("java", "java/security/HeaderInjectionClean.java", []),
            ("java", "java/security/HeaderInjectionMultilineBuggy.java", [9]),
            ("java", "java/security/HeaderInjectionMultilineClean.java", []),
            ("kotlin", "kotlin/header_injection_buggy/HeaderInjectionBuggy.kt", [22, 27, 32]),
            ("kotlin", "kotlin/header_injection_clean/HeaderInjectionClean.kt", []),
        )
        for language, relative, expected in cases:
            with self.subTest(path=relative):
                findings = list(header_injection.find([REPO_ROOT / "test-suite" / relative],
                                                     language=language, rule_id=language + ".security.header-injection"))
                self.assertEqual([row[1] for row in findings], expected, findings)

    def test_shadowed_encoder_does_not_confer_safety(self):
        from ubs_core.java_detectors import header_injection

        for language in ("java", "kotlin"):
            body = next(body for name, body, _ in self.cases(language) if name == "encoded_value")
            text = self.program(language, body).replace("import java.net.URLEncoder;", "")
            text += ('class URLEncoder { static String encode(String raw, Object charset) { return raw; } }\n'
                     if language == "java" else
                     'object URLEncoder { fun encode(raw: String, charset: Any): String { return raw } }\n')
            path = self.root / ("shadowed-encoder." + ("java" if language == "java" else "kt"))
            path.write_text(text, encoding="utf-8")
            hits = list(header_injection.find([path], language=language, rule_id=language + ".security.header-injection"))
            expected = [number for number, line in enumerate(text.splitlines(), 1) if 'response.setHeader(' in line]
            self.assertEqual([row[1] for row in hits], expected, hits)

    def test_unsupported_control_flow_is_explicit(self):
        from ubs_core.java_detectors import header_injection
        from ubs_core.taint_flow import AnalysisLimit

        text = self.program("java", 'String value = request.getParameter("value");\n'
                            'switch (value) { default: response.setHeader("X-Value", value); }')
        path = self.root / "unsupported.java"
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            list(header_injection.find([path]))
        engine = header_injection.HeaderEngine(path, self.program("java",
            'response.setHeader("X-Value", request.getParameter("value"));'))
        engine.budget.remaining = 0
        with self.assertRaises(AnalysisLimit):
            engine.analyze()

    def test_module_and_runner_json_sarif(self):
        for language in ("java", "kotlin"):
            for name, body, helper in self.cases(language):
                positive = "safe_name_identity" if language == "java" else "template_replacement_reintroduces_controls"
                if name not in {positive, "constant_overwrite"}:
                    continue
                text = self.program(language, body, helper)
                directory = self.root / (language + "-" + name + "-cli")
                directory.mkdir()
                path = directory / ("HeaderProbe.java" if language == "java" else "HeaderProbe.kt")
                path.write_text(text, encoding="utf-8")
                expected = [number for number, line in enumerate(text.splitlines(), 1) if "// expect-finding" in line]
                for surface in ("module", "runner"):
                    for format_ in ("json", "sarif"):
                        with self.subTest(language=language, case=name, surface=surface, format=format_):
                            entry = (REPO_ROOT / "modules" / ("ubs-" + language + ".sh")
                                     if surface == "module" else REPO_ROOT / "ubs")
                            command = (str(entry), "--only=4" if surface == "module" else "--only=" + language,
                                       "--format=" + format_, "--ci", str(path))
                            started = time.monotonic()
                            proc = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=180,
                                                  env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_AUTO_UPDATE="1",
                                                           UBS_NO_CACHE="1", ENABLE_UV_TOOLS="0"))
                            label = surface + "-" + format_
                            (directory / (label + ".stdout")).write_text(proc.stdout, encoding="utf-8")
                            (directory / (label + ".stderr")).write_text(proc.stderr, encoding="utf-8")
                            (directory / (label + ".command.json")).write_text(json.dumps({
                                "command": command, "exit": proc.returncode, "seconds": time.monotonic() - started,
                                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            }, indent=2), encoding="utf-8")
                            context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                            self.assertEqual(proc.returncode, int(bool(expected)), context)
                            try:
                                report = json.loads(proc.stdout)
                            except json.JSONDecodeError as error:
                                self.fail(f"Invalid scanner JSON: {error}\n{context}")
                            rule = language + ".security.header-injection"
                            if format_ == "json":
                                records = report.get("findings", []) if surface == "runner" else report["findings"]
                                key = "rule_id" if surface == "runner" else "rule"
                                actual = [(row[key], row["line"], row["severity"]) for row in records]
                                self.assertEqual(actual, [(rule, line, "critical") for line in expected], context)
                                totals = report["totals"] if surface == "runner" else report
                                self.assertEqual((totals["critical"], totals["warning"]), (len(expected), 0), context)
                            else:
                                records = [row for run in report["runs"] for row in run.get("results", [])]
                                actual = [(row["ruleId"], row["locations"][0]["physicalLocation"]["region"]["startLine"],
                                           row["level"]) for row in records]
                                self.assertEqual(actual, [(rule, line, "error") for line in expected], context)


class JavaRulePrecisionTests(unittest.TestCase):
    """Exercise generated Java rules and the public module on real sources."""

    FUTURE_RULE = "java.async.future-get-no-try"
    SECRET_RULE = "java.secrets.string-decl"  # ubs:ignore[py.security.hardcoded-secrets] — public diagnostic rule ID, not a secret
    LITERAL_RULE = "java.secrets.hardcoded"
    POSITIVE = """import java.util.concurrent.*;
import java.util.*;
class Positive {
    Future<String> fieldFuture;
    void secrets() {
        String apiToken = "literal-credential-value"; // secret:token
        String PASSWORD = "literal-password-value"; // secret:password
    }
    void local() throws Exception {
        Future<String> pending = CompletableFuture.completedFuture("ready");
        pending.get(); // future:local
        pending.get(1, TimeUnit.SECONDS); // future:timed
    }
    void parameter(Future<String> pending) throws Exception {
        pending.get(); // future:parameter
    }
    void qualified(java.util.concurrent.CompletableFuture<String> pending) {
        pending.join(); // future:qualified
    }
    void fields() throws Exception {
        fieldFuture.get(); // future:field
        this.fieldFuture.get(); // future:explicit_field
    }
    void factories() throws Exception {
        CompletableFuture.supplyAsync(() -> "ready").get(); // future:factory
        CompletableFuture.completedFuture("ready").copy().join(); // future:factory_chain
        new CompletableFuture<String>().get(); // future:constructor
        var inferred = CompletableFuture.completedFuture("ready");
        inferred.get(); // future:inferred
        CompletableFuture<String> typed = CompletableFuture.completedFuture("ready");
        typed.copy().join(); // future:typed_chain
    }
    void capturedParameter(Future<String> pending) {
        Callable<String> work = () -> pending.get(); // future:captured_parameter
    }
    void capturedLocal() {
        Future<String> pending = CompletableFuture.completedFuture("ready");
        Callable<String> work = () -> pending.get(); // future:captured_local
    }
    void delayed(CompletableFuture<String> pending) {
        try {
            Runnable work = () -> pending.join(); // future:delayed
        } catch (Exception error) {}
    }
    void wrongGetCatch(Future<String> pending) throws ExecutionException {
        try {
            pending.get(); // future:wrong_get_catch
        } catch (InterruptedException error) {}
    }
    void wrongJoinCatch(CompletableFuture<String> pending) {
        try {
            pending.join(); // future:wrong_join_catch
        } catch (IllegalArgumentException error) {}
    }
    void catchBody(Future<String> pending) throws Exception {
        try { throw new IllegalArgumentException(); }
        catch (Exception error) {
            pending.get(); // future:catch_body
        }
    }
    void loops(List<Future<String>> tasks) throws Exception {
        for (Future<String> pending : tasks) {
            pending.get(); // future:enhanced_loop
        }
        for (Future<String> pending = tasks.get(0); pending != null; pending = null) {
            pending.get(); // future:basic_loop
        }
    }
}
"""
    NEGATIVE = """import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.io.*;
class Negative {
    Future<String> fieldFuture;
    void ordinary(Optional<String> maybe, String configured) {
        String greeting = "hello";
        String url = "https://example.invalid";
        String apiToken = System.getenv("API_TOKEN");
        String PASSWORD = configured;
        if (maybe.isPresent()) {
            String present = maybe.get();
        }
    }
    void unrelated(Supplier<String> pending, Map<String, String> lookup) {
        pending.get();
        lookup.get("key");
    }
    void otherMethod(Future<String> pending) {}
    void localShadow() {
        Supplier<String> fieldFuture = () -> "ready";
        fieldFuture.get();
    }
    void parameterShadow(Supplier<String> fieldFuture) {
        fieldFuture.get();
        Runnable work = () -> { fieldFuture.get(); };
    }
    void mapCapture(Map<String, String> fieldFuture) {
        Runnable work = () -> { fieldFuture.get("key"); };
    }
    void lambdaShadow() {
        Function<Supplier<String>, String> first = fieldFuture -> fieldFuture.get();
        Function<Supplier<String>, String> second = (fieldFuture) -> fieldFuture.get();
        Function<Supplier<String>, String> third = (Supplier<String> fieldFuture) -> fieldFuture.get();
    }
    void loopShadow(List<Supplier<String>> sources) {
        for (Supplier<String> fieldFuture : sources) { fieldFuture.get(); }
        for (Supplier<String> fieldFuture = sources.get(0); fieldFuture != null; fieldFuture = null) {
            fieldFuture.get();
        }
    }
    void expiredLocal() {
        { Future<String> pending = CompletableFuture.completedFuture("ready"); }
        Supplier<String> pending = () -> "ready";
        pending.get();
    }
    void nestedClass() {
        class Inner {
            Supplier<String> fieldFuture;
            void run() { fieldFuture.get(); }
        }
    }
    void handled(Future<String> pending, CompletableFuture<String> complete) throws Exception {
        try { pending.get(); } catch (ExecutionException error) {}
        try { pending.get(); } catch (InterruptedException | ExecutionException error) {}
        try { complete.join(); } catch (CompletionException error) {}
        try { complete.join(); } catch (RuntimeException error) {}
        try { complete.join(); } catch (java.lang.Exception error) {}
        complete.handle((value, error) -> "recovered").join();
        complete.exceptionally(error -> "recovered").get();
    }
    void handledResource(Future<InputStream> pending) {
        try (InputStream stream = pending.get()) {} catch (Exception error) {}
    }
}
"""
    FUTURE_ANCHORS = {
        "local": "pending.get()", "timed": "pending.get(1, TimeUnit.SECONDS)",
        "parameter": "pending.get()", "qualified": "pending.join()",
        "field": "fieldFuture.get()", "explicit_field": "this.fieldFuture.get()",
        "factory": 'CompletableFuture.supplyAsync(() -> "ready").get()',
        "factory_chain": 'CompletableFuture.completedFuture("ready").copy().join()',
        "constructor": "new CompletableFuture<String>().get()", "inferred": "inferred.get()",
        "typed_chain": "typed.copy().join()", "captured_parameter": "pending.get()",
        "captured_local": "pending.get()", "delayed": "pending.join()",
        "wrong_get_catch": "pending.get()", "wrong_join_catch": "pending.join()",
        "catch_body": "pending.get()", "enhanced_loop": "pending.get()",
        "basic_loop": "pending.get()",
    }

    def setUp(self) -> None:
        from ubs_core import java_rules

        self.assertIsNotNone(shutil.which("ast-grep"), "Java precision regression requires real ast-grep")
        self.temp = tempfile.TemporaryDirectory(prefix="ubs_java_precision_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.positive = self.project / "Positive.java"
        self.negative = self.project / "Negative.java"
        self.positive.write_text(self.POSITIVE, encoding="utf-8")
        self.negative.write_text(self.NEGATIVE, encoding="utf-8")
        self.rules = self.root / "rules"
        self.manifest = java_rules.generate(self.rules)

    def _process(self, command: list[str], *, no_ast: bool = False) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                   UBS_CACHE_DIR=str(self.root / ("fallback-cache" if no_ast else "cache")),
                   UBS_CACHE_FILE=str(self.root / "cache-stats.json"), UBS_PROFILE="1",
                   UBS_TEST_FORCE_NO_AST_GREP=str(int(no_ast)), NO_COLOR="1")
        proc = subprocess.run(command, cwd=self.root, env=env, text=True,
                              capture_output=True, timeout=180)
        self.assertIn(proc.returncode, (0, 1), f"{command!r}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")
        return proc

    def _json(self, proc: subprocess.CompletedProcess[str]) -> dict | list:
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"invalid Java scanner JSON: {exc}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")

    def _cache_counts(self, proc: subprocess.CompletedProcess[str], hits: int, misses: int) -> None:
        context = f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
        try:
            stats = json.loads((self.root / "cache-stats.json").read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            self.fail(f"invalid Java scanner cache statistics: {exc}; {context}")
        self.assertEqual((stats["hits"], stats["misses"]), (hits, misses), context)

    def _expected(self, rule: str) -> list[tuple[str, int, int]]:
        if rule == self.FUTURE_RULE:
            anchors = {f"future:{tag}": code for tag, code in self.FUTURE_ANCHORS.items()}
        else:
            anchors = {"secret:token": "String apiToken", "secret:password": "String PASSWORD"}
        sites = []
        for tag, code in anchors.items():
            matches = [(number, line) for number, line in enumerate(self.POSITIVE.splitlines(), 1)
                       if line.endswith(f"// {tag}")]
            self.assertEqual(len(matches), 1, tag)
            number, line = matches[0]
            sites.append((str(self.positive), number, 1 if rule == self.LITERAL_RULE else line.index(code) + 1))
        return sorted(sites)

    def test_generated_rules_require_literals_and_scoped_future_evidence(self) -> None:
        for rule in (self.SECRET_RULE, "java.hardcoded-secrets", self.FUTURE_RULE):
            with self.subTest(rule=rule):
                proc = self._process(["ast-grep", "scan", "--rule",
                                      str(self.rules / self.manifest[rule]["file"]),
                                      "--json", str(self.positive), str(self.negative)])
                records = self._json(proc)
                actual = []
                for record in records:
                    self.assertEqual(record["ruleId"], rule)
                    self.assertEqual(record["severity"], "warning")
                    start = record["range"]["start"]
                    actual.append((str((self.root / record["file"]).resolve()),
                                   start["line"] + 1, start["column"] + 1))
                self.assertEqual(sorted(actual), self._expected(rule), proc.stdout + proc.stderr)

    def test_public_module_json_sarif_cache_and_literal_fallback_precision(self) -> None:
        rules = (self.SECRET_RULE, self.LITERAL_RULE, self.FUTURE_RULE)

        def scan(paths: list[Path], output_format: str, hits: int, *, positive: bool,
                 no_ast: bool = False) -> list[tuple]:
            inputs = self.root / "inputs"
            inputs.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
            proc = self._process([str(REPO_ROOT / "modules/ubs-java.sh"), "--no-build", "--ci",
                                  "--no-color", "--fail-on-warning", "--only=3,21",
                                  f"--format={output_format}", "--files-from", str(inputs),
                                  str(self.project)], no_ast=no_ast)
            context = f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
            self.assertEqual(proc.returncode, int(positive), context)
            payload = self._json(proc)
            self._cache_counts(proc, hits, len(paths) - hits)
            expected = sorted((rule, *site, "warning") for rule in rules
                              if positive and (not no_ast or rule == self.LITERAL_RULE)
                              for site in self._expected(rule))
            expected_ast = [site for site in expected if site[0] != self.LITERAL_RULE]
            actual = []
            if output_format == "json":
                self.assertEqual(payload["status"], "ok", context)
                self.assertEqual(payload["critical"], 0, context)
                self.assertEqual(payload["warning"], len(expected), context)
                self.assertEqual(payload["info"], 0, context)
                for record in payload["findings"]:
                    actual.append((record["rule"], str((self.root / record["path"]).resolve()),
                                   record["line"], record["col"], record["severity"]))
                self.assertEqual(sorted((record["rule"], str((self.root / record["path"]).resolve()),
                                         record["line"], record["col"], record["severity"])
                                        for record in payload["extras"]["ast_findings"]), expected_ast, context)
            else:
                self.assertEqual(payload["version"], "2.1.0", context)
                by_driver = {}
                for run in payload["runs"]:
                    driver = run["tool"]["driver"]["name"]
                    self.assertNotIn(driver, by_driver, context)
                    run_sites = []
                    for result in run.get("results", []):
                        self.assertEqual(result["level"], "warning", context)
                        self.assertEqual(len(result["locations"]), 1, context)
                        location = result["locations"][0]["physicalLocation"]
                        region = location["region"]
                        run_sites.append((result["ruleId"], str(sarif_location_path(location["artifactLocation"]["uri"], self.root).resolve()),
                                          region["startLine"], region["startColumn"], "warning"))
                    by_driver[driver] = sorted(run_sites)
                # SARIF keeps the original AST evidence in a separate run,
                # including counted AST sites already present in heuristics.
                self.assertEqual(by_driver, {"ubs-java-heuristics": expected,
                                             "ubs-java-ast": expected_ast}, context)
                actual = by_driver["ubs-java-heuristics"]
            self.assertEqual(sorted(actual), expected, context)
            return sorted(actual)

        paths = [self.positive, self.negative]
        cold = scan(paths, "json", 0, positive=True)
        self.assertEqual(scan(paths, "sarif", 2, positive=True), cold)
        scan([self.negative], "json", 1, positive=False)
        self.positive.write_text(self.NEGATIVE.replace("class Negative", "class Positive"), encoding="utf-8")
        scan(paths, "json", 1, positive=False)
        scan(paths, "sarif", 2, positive=False)
        self.positive.write_text(self.POSITIVE, encoding="utf-8")
        scan(paths, "json", 0, positive=True, no_ast=True)
        scan([self.negative], "json", 1, positive=False, no_ast=True)

    def test_optional_category_filter_preserves_enabled_json_sarif_and_text(self) -> None:
        optional_rule = "java.optional-isPresent-then-get"
        detector_rule = "java.null-optional.optional-get"
        inputs = self.root / "inputs"
        inputs.write_bytes(os.fsencode(self.negative) + b"\0")
        for categories, enabled in (("1", True), ("3,21", False)):
            for index, output_format in enumerate(("json", "sarif", "text")):
                with self.subTest(categories=categories, output_format=output_format):
                    proc = self._process([
                        str(REPO_ROOT / "modules/ubs-java.sh"), "--no-build", "--ci", "--no-color",
                        "--fail-on-warning", f"--only={categories}", f"--format={output_format}",
                        "--files-from", str(inputs), str(self.project),
                    ])
                    context = f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                    self.assertEqual(proc.returncode, int(enabled), context)
                    self._cache_counts(proc, int(index > 0), int(index == 0))
                    expected_info = [(optional_rule, str(self.negative), 12, 9, "info")] if enabled else []
                    # The separate legacy Optional.get detector remains a
                    # warning even for this guarded call; retain its exact
                    # source alongside the AST style recommendation.
                    expected = sorted(expected_info + (
                        [(detector_rule, str(self.negative), 13, 1, "warning")] if enabled else []))
                    if output_format == "text":
                        self.assertIn("Critical issues: 0", proc.stdout, context)
                        self.assertIn(f"Warning issues: {int(enabled)}", proc.stdout, context)
                        self.assertIn(f"Info items: {int(enabled)}", proc.stdout, context)
                        if enabled:
                            self.assertEqual(proc.stdout.count("1. NULL & OPTIONAL PITFALLS"), 1, context)
                            self.assertIn(f"{self.negative}:12", proc.stdout, context)
                            self.assertIn(f"{self.negative}:13", proc.stdout, context)
                            self.assertIn(optional_rule, proc.stdout, context)
                            self.assertIn(detector_rule, proc.stdout, context)
                            self.assertLess(proc.stdout.index("1. NULL & OPTIONAL PITFALLS"),
                                            proc.stdout.index(optional_rule), context)
                        else:
                            self.assertNotIn("1. NULL & OPTIONAL PITFALLS", proc.stdout, context)
                            self.assertNotIn(optional_rule, proc.stdout, context)
                            self.assertNotIn(detector_rule, proc.stdout, context)
                        self.assertNotIn("15. AST-GREP RULE PACK FINDINGS", proc.stdout.upper(), context)
                        continue
                    payload = self._json(proc)
                    if output_format == "json":
                        self.assertEqual(payload["status"], "ok", context)
                        self.assertEqual((payload["critical"], payload["warning"], payload["info"]),
                                         (0, int(enabled), int(enabled)), context)
                        self.assertEqual(sorted((record["rule"], record["path"], record["line"],
                                                 record["col"], record["severity"])
                                                for record in payload["findings"]), expected, context)
                        self.assertEqual([(record["rule"], record["path"], record["line"],
                                           record["col"], record["severity"])
                                          for record in payload["extras"]["ast_findings"]], expected_info, context)
                        for record in payload["extras"]["ast_findings"]:
                            self.assertEqual(record["category_id"], 1, context)
                    else:
                        self.assertEqual(payload["version"], "2.1.0", context)
                        by_driver = {}
                        for run in payload["runs"]:
                            driver = run["tool"]["driver"]["name"]
                            self.assertNotIn(driver, by_driver, context)
                            sites = []
                            for result in run.get("results", []):
                                self.assertEqual(len(result["locations"]), 1, context)
                                location = result["locations"][0]["physicalLocation"]
                                region = location["region"]
                                self.assertIn(result["level"], ("note", "warning"), context)
                                sites.append((result["ruleId"], str(sarif_location_path(location["artifactLocation"]["uri"])),
                                              region["startLine"], region["startColumn"],
                                              "info" if result["level"] == "note" else "warning"))
                            by_driver[driver] = sorted(sites)
                        self.assertEqual(by_driver, {"ubs-java-heuristics": expected,
                                                     "ubs-java-ast": expected_info}, context)


class PublicScopedSuppressionTests(unittest.TestCase):
    """Real module reports must agree on scoped sites, counts, and exit status."""

    CASES = {
        "cpp": ("cpp", "3", [], "#include <mutex>\nvoid check(std::mutex &m) {\n", "}\n",
                "m.lock();", 'const char *note = "{marker}"; ',
                (("cpp.concurrency.manual-lock", "warning"),), "cpp.raw-new"),
        "rust": ("rs", "1,23", [], "fn check(raw: &str) {\n", "}\n",
                 "let parsed: i32 = raw.parse().unwrap();", 'let note = "{marker}"; ',
                 (("rust.ownership.unwrap-expect", "warning"),
                  ("rust.parsing.parse-unwrap", "warning")), "rust.panic.assert-macros"),
        "java": ("java", "19", ["--no-build"],
                 "import java.sql.*;\nclass Case {\n void check(Connection conn) throws SQLException {\n",
                 " }\n}\n", "Statement handle{index} = conn.createStatement();",
                 'String note = "{marker}"; ',
                 (("java.resource.statement-no-close", "warning"),), "java.optional-isPresent-then-get"),
        "swift": ("swift", "1,11", [], "func check() throws {\n", "}\n",
                  "let value{index} = try! operation()", 'let note = "{marker}"; ',
                  (("swift.force-try", "warning"), ("swift.optionals.try-bang", "warning"),
                   ("swift.optionals.force-some", "info")), "swift.force-cast"),
        "csharp": ("cs", "3,17", ["--no-dotnet"],
                   "using System.Threading;\nclass Case {\n void Check() {\n", " }\n}\n",
                   "Thread.Sleep(5);", 'string note = "{marker}"; ',
                   (("cs.pattern.thread-sleep", "warning"), ("cs-thread-sleep", "warning")),
                   "cs-md5-create"),
    }

    def _exercise(self, language: str) -> None:
        self.assertIsNotNone(shutil.which("ast-grep"), "public suppression regression requires real ast-grep")
        suffix, categories, flags, opening, closing, statement, literal, rules, wrong = self.CASES[language]
        with tempfile.TemporaryDirectory(prefix=f"ubs_{language}_public_scope_") as td:
            root = Path(td)
            project = root / "project"
            project.mkdir()
            marker = "ubs:ignore"
            all_scope = marker + "[" + ",".join(rule for rule, _ in rules) + "]"
            variants = ("wrong", "unknown", "literal", "baseline", "above", "trailing", "bare", "selective")
            expected: list[tuple[str, str, int, str]] = []
            paths = []
            sources = {}
            for index, variant in enumerate(variants):
                path = project / f"{index:02d}_{variant}.{suffix}"
                paths.append(path)
                body = []
                if variant == "above":
                    body.append("    // " + all_scope)
                code = statement.format(index=index)
                if variant == "literal":
                    # Both a bare token and a valid matching scope are ordinary
                    # string contents on the actual hazardous source line.
                    code = literal.format(marker=marker + " " + all_scope) + code
                scope = {
                    "wrong": marker + "[" + wrong + "]",
                    "unknown": marker + "[unknown.public.rule]",
                    "trailing": all_scope,
                    "bare": marker,
                    "selective": marker + "[" + rules[0][0] + "]",
                }.get(variant)
                body.append("    " + code + (" // " + scope if scope else ""))
                line = len(opening.splitlines()) + len(body)
                retained = rules if variant in ("wrong", "unknown", "literal", "baseline") else (
                    rules[1:] if variant == "selective" else ())
                expected.extend((rule, str(path), line, severity) for rule, severity in retained)
                if variant == "above":
                    # The comment belongs to the first statement. A following
                    # unmarked statement remains a real positive control.
                    body.append("    " + statement.format(index="adjacent"))
                    expected.extend((rule, str(path), line + 1, severity) for rule, severity in rules)
                header = opening.replace("class Case", f"class Case{index}")
                if language == "swift":
                    header = header.replace("func check", f"func check{index}")
                source = header + "\n".join(body) + "\n" + closing
                path.write_text(source, encoding="utf-8")
                sources[variant] = source
            if language == "swift":
                control = project / "08_print.swift"
                control.write_text('func trace() {\n    print("retained control")\n}\n', encoding="utf-8")
                paths.append(control)
                expected.extend((rule, str(control), 2, "info")
                                for rule in ("swift.print-call", "swift.debug.print-minimal"))

            scan_sequence = 0

            def scan(selected: list[Path], output_format: str,
                     sites: list[tuple[str, str, int, str]], hits: int, *, meta: bool = False) -> list[tuple]:
                nonlocal scan_sequence
                scan_sequence += 1
                inputs = root / "inputs"
                inputs.write_bytes(b"\0".join(os.fsencode(path) for path in selected) + b"\0")
                stats_file = root / "cache-stats.json"
                records_file = root / f"findings-{scan_sequence}.ndjson"
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                           UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(stats_file),
                           UBS_PROFILE="1", UBS_SKIP_TYPE_NARROWING="1",
                           UBS_TEST_FORCE_NO_AST_GREP="0", NO_COLOR="1")
                command = [str(REPO_ROOT / "modules" / f"ubs-{language}.sh"), "--ci", "--no-color",
                           "--fail-on-warning", f"--only={categories}", f"--format={output_format}",
                           "--files-from", str(inputs), *flags, str(project)]
                if language == "rust" and output_format == "json":
                    # Rust's public JSON stdout is a summary; this public
                    # option retains the actual source findings separately.
                    command.insert(-1, f"--report-json={records_file}")
                if meta:
                    self.assertEqual(output_format, "text")
                    self.assertTrue(selected == paths or len(selected) == 1)
                    skip = ",".join(str(category) for category in range(1, 25)
                                    if str(category) not in categories.split(","))
                    command = [str(REPO_ROOT / "ubs"), "--ci", "--no-color", "--no-auto-update",
                               "--fail-on-warning", f"--only={language}", f"--skip-{language}={skip}",
                               "--format=text", *flags,
                               str(selected[0] if len(selected) == 1 else project)]
                proc = subprocess.run(command, cwd=root, env=env, text=True,
                                      capture_output=True, timeout=180)
                context = f"{command!r}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                totals = {severity: sum(site[3] == severity for site in sites)
                          for severity in ("critical", "warning", "info")}
                self.assertEqual(proc.returncode, int(totals["critical"] + totals["warning"] > 0), context)
                if not meta:
                    try:
                        stats = json.loads(stats_file.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError) as exc:
                        self.fail(f"invalid public suppression cache statistics: {exc}; {context}")
                    self.assertEqual((stats["hits"], stats["misses"]), (hits, len(selected) - hits), context)
                if output_format == "text":
                    text = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
                    for severity, label in (("critical", "Critical issues"),
                                            ("warning", "Warning issues"), ("info", "Info items")):
                        self.assertRegex(text, rf"{label}:\s+{totals[severity]}\b", context)
                    # Renderers deliberately cap previews. Every preview must
                    # still identify a retained finding using trusted metadata.
                    printed = []
                    location = (rf"(?P<path>\S+\.{suffix}):(?P<line>\d+)(?::\d+)?:?\s+"
                                r"\[rule:(?P<rule>[A-Za-z0-9_.:-]+)\]")
                    for match in re.finditer(location, text):
                        site = (match["rule"], str((root / match["path"]).resolve()), int(match["line"]))
                        self.assertIn(site, [item[:3] for item in sites], context)
                        printed.append(site)
                    if sites:
                        self.assertTrue(printed, context)
                        self.assertIn(rules[0][0], {site[0] for site in printed}, context)
                        if meta and (language != "swift" or len(selected) == 1):
                            # Swift's AST traversal order is independent of
                            # input order. Its three preview controls each get
                            # a separate real meta scan below, so a preview cap
                            # cannot hide lost wrong/unknown/literal findings.
                            controls = {str(paths[variants.index(name)])
                                        for name in ("wrong", "unknown", "literal")}
                            for site in sites:
                                if site[0] == rules[0][0] and site[1] in controls:
                                    self.assertIn(site[:3], printed, context)
                    else:
                        self.assertEqual(printed, [], context)
                        for path in selected:
                            self.assertNotRegex(text, re.escape(path.name) + r":\d+", context)
                    return printed
                try:
                    payload = json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"invalid public suppression report: {exc}; {context}")
                if output_format == "json":
                    self.assertEqual(payload["status"], "ok", context)
                    self.assertEqual({severity: payload[severity] for severity in totals}, totals, context)
                    if language == "rust":
                        try:
                            records = [json.loads(line) for line in
                                       records_file.read_text(encoding="utf-8").splitlines()]
                        except (json.JSONDecodeError, OSError) as exc:
                            self.fail(f"invalid Rust public source findings: {exc}; {context}")
                    else:
                        records = payload["findings"]
                    actual = []
                    for record in records:
                        self.assertIs(type(record["col"]), int, context)
                        self.assertGreaterEqual(record["col"], 1, context)
                        self.assertEqual(record.get("count", 1), 1, context)
                        actual.append((record["rule"], str((root / record["path"]).resolve()),
                                       record["line"], record["severity"], record["col"]))
                    self.assertEqual(sorted(item[:4] for item in actual), sorted(sites), context)
                    return sorted(actual)
                self.assertEqual(payload["version"], "2.1.0", context)
                by_driver = {}
                for run in payload["runs"]:
                    driver = run["tool"]["driver"]["name"]
                    self.assertNotIn(driver, by_driver, context)
                    actual = []
                    for record in run.get("results", []):
                        self.assertEqual(len(record["locations"]), 1, context)
                        loc = record["locations"][0]["physicalLocation"]
                        actual.append((record["ruleId"], str(sarif_location_path(loc["artifactLocation"]["uri"], root).resolve()),
                                       loc["region"]["startLine"],
                                       "info" if record["level"] == "note" else record["level"],
                                       loc["region"]["startColumn"]))
                    self.assertEqual(sorted(item[:4] for item in actual), sorted(sites), context)
                    by_driver[driver] = sorted(actual)
                drivers = {f"ubs-{language}"} if language != "java" else {
                    "ubs-java-heuristics", "ubs-java-ast"}
                self.assertEqual(set(by_driver), drivers, context)
                return next(iter(by_driver.values()))

            cold = scan(paths, "json", expected, 0)
            self.assertEqual(scan(paths, "json", expected, len(paths)), cold)
            self.assertEqual(scan(paths, "sarif", expected, len(paths)), cold)
            scan(paths, "text", expected, len(paths))
            scan(paths, "text", expected, len(paths), meta=True)
            if language == "swift":
                for name in ("wrong", "unknown", "literal"):
                    selected = paths[variants.index(name)]
                    sites = [site for site in expected if site[1] == str(selected)]
                    scan([selected], "text", sites, 1, meta=True)
            suppressed = [paths[variants.index(name)] for name in ("trailing", "bare")]
            for output_format in ("json", "sarif", "text"):
                scan(suppressed, output_format, [], len(suppressed))
            wrong_path = paths[variants.index("wrong")]
            wrong_path.write_text(sources["wrong"].replace(marker + "[" + wrong + "]", all_scope),
                                  encoding="utf-8")
            partial_sites = [site for site in expected if site[1] != str(wrong_path)]
            partial = scan(paths, "json", partial_sites, len(paths) - 1)
            self.assertEqual(scan(paths, "sarif", partial_sites, len(paths)), partial)

    def test_cpp_public_rule_scopes(self) -> None:
        self._exercise("cpp")

    def test_rust_public_rule_scopes(self) -> None:
        self._exercise("rust")

    def test_java_public_rule_scopes(self) -> None:
        self._exercise("java")

    def test_swift_public_rule_scopes_and_unmarked_prints(self) -> None:
        self._exercise("swift")

    def test_csharp_public_rule_scopes_preserve_independent_ast_findings(self) -> None:
        self._exercise("csharp")


class NativeSourceIdentityTests(unittest.TestCase):
    def scan(self, root: Path, language: str, paths: list[Path], extra_args: list[str],
             expected: dict[str, list[tuple[Path, int, int, str]]], hits: int) -> list[dict]:
        sink = root / "identity.ndjson"
        stats = root / "identity-cache.json"
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(stats))
        proc = subprocess.run(
            [sys.executable, "-m", f"ubs_core.{language}_scan", "--files-from", "-",
             "--sink", str(sink), "--project-dir", str(root / "project"),
             "--fail-on-warning", *extra_args],
            input="\0".join(str(path) for path in paths) + "\0", cwd=root, env=env,
            text=True, capture_output=True, timeout=180,
        )
        context = f"{language} paths={paths}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
        owners = {source for sites in expected.values() for source, _, _, _ in sites}
        self.assertEqual(proc.returncode, int(bool(owners)), context)
        self.assertTrue(sink.is_file(), context)
        self.assertTrue(stats.is_file(), context)
        try:
            records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
            cache_stats = json.loads(stats.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.fail(f"invalid native scanner output: {exc}; {context}")
        self.assertEqual((cache_stats["hits"], cache_stats["misses"]),
                         (hits, len(paths) - hits), context)
        actual: dict[str, list[tuple[Path, int, int, str]]] = {rule: [] for rule in expected}
        for record in records:
            source = (root / record["path"]).resolve()
            self.assertIn(source, owners, context)
            if record["rule"] in actual:
                actual[record["rule"]].append((source, record["line"], record["col"], record["severity"]))
        self.assertEqual({rule: sorted(sites) for rule, sites in actual.items()},
                         {rule: sorted(sites) for rule, sites in expected.items()}, context)
        if not owners:
            self.assertEqual(records, [], context)
        return sorted(records, key=lambda record: (record["path"], record["rule"],
                                                   record["line"], record["col"]))

    def test_generated_ast_paths_keep_distinct_same_display_sources(self) -> None:
        from ubs_core import csharp_rules, elixir_rules

        cases = (
            ("csharp", csharp_rules, ".cs", 17, "cs-md5-create", "warning", 3, 9,
             "class Example {\n    void Run() {\n        MD5.Create();\n    }\n}\n",
             "class Example {\n    void Run() {\n        MD5.Create();\n        MD5.Create();\n    }\n}\n",
             "class Clean {}\n"),
            ("elixir", elixir_rules, ".ex", 4, "elixir.code-eval-string", "critical", 1, 1,
             "Code.eval_string(input)\n", "Code.eval_string(input)\nCode.eval_string(input)\n",
             "value = 42\n"),
        )
        for language, pack, suffix, category, rule, severity, line, col, hazard, changed, clean in cases:
            with self.subTest(language=language), tempfile.TemporaryDirectory(prefix="ubs_ast_source_identity_") as td:
                root = Path(td)
                outside = Path(f"outside/Case{suffix}")
                inside = Path(f"project/outside/Case{suffix}")
                clean_paths = [Path(f"Clean{suffix}"), Path(f"project/Clean{suffix}")]
                for path, source in ((outside, hazard), (inside, hazard),
                                     *((path, clean) for path in clean_paths)):
                    (root / path).parent.mkdir(parents=True, exist_ok=True)
                    (root / path).write_text(source, encoding="utf-8")
                rules = root / "rules"
                manifest = pack.generate(rules)
                self.assertIn(rule, manifest)
                extra = ["--ast-rule-dir", str(rules), "--skip",
                         ",".join(str(n) for n in range(1, 25) if n != category)]
                paths = [outside, inside, *clean_paths]
                # Before canonical dedup, both positives were "outside/Case"
                # despite denoting different source files at the same site.
                expected = {rule: [(root / outside, line, col, severity),
                                   (root / inside, line, col, severity)]}
                cold = self.scan(root, language, paths, extra, expected, 0)
                self.assertEqual(self.scan(root, language, paths, extra, expected, 4), cold)
                self.scan(root, language, clean_paths, extra, {rule: []}, 2)
                for source in (outside, inside):
                    subset = self.scan(root, language, [source], extra,
                                       {rule: [(root / source, line, col, severity)]}, 1)
                    self.assertEqual(subset, [record for record in cold
                                              if (root / record["path"]).resolve() == root / source])
                (root / inside).write_text(changed, encoding="utf-8")
                expected[rule].append((root / inside, line + 1, col, severity))
                partial = self.scan(root, language, paths, extra, expected, 3)
                self.assertEqual(self.scan(root, language, paths, extra, expected, 4), partial)

    def test_rust_root_relative_detectors_ignore_existing_cwd_shadows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_rust_source_identity_") as td:
            root = Path(td)
            positives = [Path("project/Same.rs"), Path("project/nested/Same.rs")]
            shadows = [Path("Same.rs"), Path("nested/Same.rs")]
            hazard = (
                "fn settings() {\n"
                '    let api_key = "abcd1234efgh5678";\n'
                "    let disabled = true;\n"
                "    client.danger_accept_invalid_certs(disabled);\n"
                "}\n"
            )
            for path in positives + shadows:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(hazard if path in positives else "fn clean() {}\n",
                                         encoding="utf-8")
            secrets = "rust.security.hardcoded-secrets"
            tls = "rust.security.tls-verification"
            expected = {
                secrets: [(root / path, 2, 1, "critical") for path in positives],
                tls: [(root / path, 4, 1, "critical") for path in positives],
            }
            extra = ["--skip-type-narrowing", "--quiet", "--skip",
                     ",".join(str(n) for n in range(1, 25) if n != 8)]
            paths = positives + shadows
            cold = self.scan(root, "rust", paths, extra, expected, 0)
            self.assertEqual(self.scan(root, "rust", paths, extra, expected, 4), cold)
            self.scan(root, "rust", shadows, extra, {secrets: [], tls: []}, 2)
            for path in positives:
                subset_expected = {rule: [site for site in sites if site[0] == root / path]
                                   for rule, sites in expected.items()}
                subset = self.scan(root, "rust", [path], extra, subset_expected, 1)
                self.assertEqual(subset, [record for record in cold
                                          if (root / record["path"]).resolve() == root / path])
            (root / positives[0]).write_text(hazard.replace("disabled = true", "disabled = false"),
                                             encoding="utf-8")
            expected[tls] = [site for site in expected[tls] if site[0] == root / positives[1]]
            partial = self.scan(root, "rust", paths, extra, expected, 3)
            self.assertEqual(self.scan(root, "rust", paths, extra, expected, 4), partial)


class CSharpSourcePathTests(unittest.TestCase):
    def test_outside_relative_detector_paths_do_not_transfer_to_project_shadow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_csharp_source_paths_") as td:
            root = Path(td)
            project = root / "project"
            outside = Path("outside/Case.cs")
            shadow = Path("project/outside/Case.cs")
            inside = Path("project/Inside.cs")
            hazard = 'var url = Request.Query["url"];\nclient.GetAsync(url);\n'
            for path, source in ((outside, hazard), (shadow, "class Safe {}\n"), (inside, hazard)):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(source, encoding="utf-8")
            sink = root / "findings.ndjson"
            stats = root / "cache.json"
            env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                       UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(stats))
            rule_id = "csharp.security.outbound-url"

            def scan(paths: list[Path], hits: int, expected: dict[Path, list[int]]) -> list[dict]:
                self.assertTrue(all(not path.is_absolute() for path in paths))
                proc = subprocess.run(
                    [sys.executable, "-m", "ubs_core.csharp_scan", "--sink", str(sink),
                     "--project-dir", str(project),
                     "--skip", ",".join(str(n) for n in range(1, 25) if n != 8)],
                    input="\0".join(str(path) for path in paths) + "\0",
                    cwd=root, env=env, text=True, capture_output=True, timeout=180,
                )
                context = f"paths={paths}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                self.assertEqual(proc.returncode, int(bool(expected)), context)
                self.assertTrue(sink.is_file(), context)
                self.assertTrue(stats.is_file(), context)
                try:
                    records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                    cache_stats = json.loads(stats.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    self.fail(f"invalid C# scanner output: {exc}; {context}")
                self.assertEqual((cache_stats["hits"], cache_stats["misses"]),
                                 (hits, len(paths) - hits), context)
                actual: dict[Path, list[int]] = {}
                for record in records:
                    source = (root / record["path"]).resolve()
                    self.assertIn(source, expected, context)
                    if record["rule"] == rule_id:
                        self.assertEqual(record["severity"], "critical", context)
                        self.assertEqual(record["col"], 1, context)
                        actual.setdefault(source, []).append(record["line"])
                self.assertEqual({path: sorted(lines) for path, lines in actual.items()}, expected, context)
                if not expected:
                    self.assertEqual(records, [], context)
                return sorted(records, key=lambda record: (record["path"], record["rule"],
                                                           record["line"], record["col"]))

            outside_source = root / outside
            inside_source = root / inside
            paths = [outside, shadow, inside]
            expected = {outside_source: [2], inside_source: [2]}
            cold = scan(paths, 0, expected)
            self.assertEqual(scan(paths, 3, expected), cold)
            scan([shadow], 1, {})
            outside_records = [record for record in cold
                               if (root / record["path"]).resolve() == outside_source]
            self.assertEqual(scan([outside], 1, {outside_source: [2]}), outside_records)
            inside_records = [record for record in cold
                              if (root / record["path"]).resolve() == inside_source]
            self.assertEqual(scan([inside], 1, {inside_source: [2]}), inside_records)

            outside_source.write_text(hazard + "client.GetAsync(url);\n", encoding="utf-8")
            changed = {outside_source: [2, 3], inside_source: [2]}
            partial = scan(paths, 2, changed)
            self.assertEqual(scan(paths, 3, changed), partial)
            scan([shadow], 1, {})


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
        python_args = ["-m", "ubs_core.rust_scan"]
        if without_tomllib:
            python_args = ["-c", (
                "import runpy,sys; sys.modules['tomllib']=None; "
                "runpy.run_module('ubs_core.rust_scan',run_name='__main__')"
            )]
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0" if cache else "1", UBS_CACHE_DIR=str(self.root / "cache"))
        result = subprocess.run([sys.executable, *python_args, *args], cwd=self.root, env=env,
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

    def test_resource_aggregate_weights_survive_full_and_partial_cache_replay(self) -> None:
        first = self.package("aggregate_first", source="src/lib.rs")
        second = self.package("aggregate_second", source="src/lib.rs")
        first_source = (
            "fn launch() {\n"
            "    let first = std::thread::spawn(|| {});\n"
            "    let second = std::thread::spawn(|| {});\n"
            "    assert!(true);\n"
            "    assert_eq!(1, 1);\n"
            "}\n"
        )
        first.write_text(first_source, encoding="utf-8")
        second.write_text(
            "fn independent() {\n"
            "    std::thread::spawn(|| {});\n"
            "    std::thread::spawn(|| {});\n"
            "    std::thread::spawn(|| {});\n"
            "    assert!(true);\n"
            "    assert_ne!(1, 2);\n"
            "}\n",
            encoding="utf-8",
        )
        aggregate_rule = "rust.resource-lifecycle.thread_join"
        concrete_rule = "rust.panic.assert-macros"

        def scan_counts(expected: dict[Path, int], hits: int, misses: int) -> list[dict]:
            code, document = self.scan([first, second], categories=(19, 21), ast=False,
                                       cache=True, fail_on_warning=True)
            self.assertEqual(code, 1)
            self.assertEqual(document["status"], "ok")
            self.assertEqual(document["files"], 2)
            profile = document["extras"]["profile"]
            self.assertEqual((profile["cache_hits"], profile["cache_misses"]), (hits, misses))
            records = document["findings"]
            self.assertEqual({record["rule"] for record in records},
                             {aggregate_rule, concrete_rule})
            aggregates = [record for record in records if record["rule"] == aggregate_rule]
            self.assertEqual(len(aggregates), 2)
            self.assertEqual({Path(record["path"]): record.get("count", 1)
                              for record in aggregates}, expected)
            for record in aggregates:
                self.assertEqual((record["severity"], record["line"], record["col"]),
                                 ("critical", 1, 1))
                if expected[Path(record["path"])] > 1:
                    self.assertEqual(record["count"], expected[Path(record["path"])])
            concrete = [record for record in records if record["rule"] == concrete_rule]
            self.assertEqual(len(concrete), 4)
            self.assertEqual(sorted((Path(record["path"]), record["line"]) for record in concrete),
                             [(first, 4), (first, 5), (second, 5), (second, 6)])
            self.assertTrue(all(record["severity"] == "warning" and record.get("count", 1) == 1
                                for record in concrete), concrete)
            self.assertEqual((document["critical"], document["warning"], document["info"]),
                             (sum(expected.values()), 4, 0))
            for severity in ("critical", "warning", "info"):
                self.assertEqual(sum(record.get("count", 1) for record in records
                                     if record["severity"] == severity), document[severity])
            return sorted(records, key=lambda record: (record["path"], record["rule"],
                                                       record["line"], record["col"]))

        cold = scan_counts({first: 2, second: 3}, 0, 2)
        warm = scan_counts({first: 2, second: 3}, 2, 0)
        self.assertEqual(warm, cold)

        # Repair only one acquisition. The other file must replay its weight
        # of three while the changed file contributes a freshly scanned one.
        first.write_text(first_source.replace("    assert_eq!(1, 1);\n",
                                              "    assert_eq!(1, 1);\n    let _ = first.join();\n"),
                         encoding="utf-8")
        partial = scan_counts({first: 1, second: 3}, 1, 1)
        self.assertEqual([record for record in partial if Path(record["path"]) == second],
                         [record for record in cold if Path(record["path"]) == second])
        self.assertEqual(scan_counts({first: 1, second: 3}, 2, 0), partial)

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

    def test_proven_test_scopes_warn_but_shared_unknown_and_boundary_sites_stay_critical(self) -> None:
        target = self.package("scoped", source="src/lib.rs")
        source = '''fn production() { panic!("runtime"); } // critical
#[cfg(test)]
mod checks {
    fn helper() { panic!("unit helper"); } // warning
}
#[cfg(all(test, feature = "wire"))]
fn gated() { panic!("test-only cfg"); } // warning
#[test]
fn unit() { panic!("unit runner"); } // warning
#[cfg(any(test, unix))]
fn shared() { panic!("also runtime"); } // critical
#[custom::test]
fn unknown() { panic!("unproven runner"); } // critical
#[cfg(test)] fn one() { panic!("boundary test"); } fn two() { panic!("boundary runtime"); } // critical
#[cfg(test)]
mod incomplete {
    fn unknown() { panic!("unclosed scope"); } // critical
'''
        target.write_text(source, encoding="utf-8")
        code, doc = self.scan([target])
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        expected = [(number, line.rsplit("// ", 1)[1])
                    for number, line in enumerate(source.splitlines(), 1) if "panic!" in line]
        expected.append((14, "critical"))  # Both sites on the mixed boundary stay visible.
        self.assertEqual(code, 1)
        self.assertEqual(sorted((hit["line"], hit["severity"]) for hit in hits), sorted(expected))
        self.assertEqual((doc["critical"], doc["warning"]), (6, 3))
        self.assertEqual(self.scan([target], fail_on_warning=True)[0], 1)

    def test_all_test_only_panic_sites_still_fail_warning_gate(self) -> None:
        target = self.package("all_scoped", source="src/lib.rs")
        target.write_text('#[cfg(test)]\nmod checks {\n    fn helper() { panic!("failure path"); }\n}\n',
                          encoding="utf-8")
        code, doc = self.scan([target])
        self.assertEqual((code, doc["critical"], doc["warning"]), (0, 0, 1))
        self.assertEqual(doc["findings"][0]["severity"], "warning")
        self.assertEqual(self.scan([target], fail_on_warning=True)[0], 1)

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


class RustRestoredDiagnosticTests(unittest.TestCase):
    """Exercise the real generated pack and public reports at original fixture sites."""

    # Independent expectations from the legacy diagnostic contract. A generic
    # unwrap, cast, or filesystem finding at these lines cannot satisfy them.
    EXPECTED = {
        "rust.casts.ptr-cast": ("info", "Raw pointer cast; verify layouts and lifetimes", (
            (126, "ptr as *mut u8"), (139, "bytes as *const [u8]"), (140, "ptr as *mut u8"))),
        "rust.parsing.parse-float-no-finite-check": ("info", "validate with is_finite() after parsing", (
            (150, "input.parse::<f64>().unwrap_or(0.0)"),)),
        "rust.numeric.instant-now-elapsed": ("warning", "you likely want elapsed() on a previously-stored Instant", (
            (159, "Instant::now().elapsed()"),)),
        "rust.numeric.instant-subtraction": ("warning", "use checked_sub()", (
            (160, "Instant::now() - Duration::from_secs(1)"),)),
        "rust.panic.from-slice-panic": ("warning", "validate length first or use try_from", (
            (176, "Nonce::from_slice(data)"), (177, "GenericArray::from_slice(data)"),
            (178, "Key::from_slice(data)"))),
        "rust.numeric.i64-negate-overflow": ("info", "consider checked_neg() or promote to i128", (
            (154, "1_i64.wrapping_neg()"), (155, "-(values.len() as i64)"))),
        "rust.numeric.wrapping-arithmetic": ("info", "verify this is intentional and not masking a bug", (
            (156, "1_u64.wrapping_add(values.len() as u64)"),
            (157, "1_u64.wrapping_sub(values.len() as u64)"),
            (158, "1_u64.wrapping_mul(values.len() as u64)"))),
        "rust.async.tokio-spawn-no-move": ("info", "consider `async move` to avoid borrow across await", (
            (61, "tokio::spawn(async { async_work().await })"),)),
        "rust.async.tokio-block-in-place": ("info", "ensure this is truly needed and guarded", (
            (64, "tokio::task::block_in_place("),)),
        "rust.filesystem.write-not-atomic": ("info", "for durability, write to a temp file and rename", (
            (185, "std::fs::write("),)),
        "rust.collections.map-clone": ("info", "can often be replaced with .cloned()", (
            (96, "items.iter().map(|item| item.clone())"),)),
        "rust.parsing.strict-utf8": ("warning", "consider from_utf8_lossy() for untrusted input", (
            (152, "String::from_utf8("), (153, "str::from_utf8("))),
        "rust.perf.regex-new-unwrap": ("info", "consider compile-time regex! or handle error with context", (
            (108, "regex::Regex::new("), (117, "regex::Regex::new("))),
        "rust.panic.debug-assert-macros": ("info", "ensure invariants are also enforced where needed", (
            (73, "debug_assert!("), (74, "debug_assert_eq!("), (75, "debug_assert_ne!("))),
    }

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs_rust_restored_")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.fixture = self.root / "coverage.rs"
        shutil.copyfile(REPO_ROOT / "test-suite/rust/buggy/ast_grep_rule_pack_coverage.rs", self.fixture)
        self.source = self.fixture.read_text(encoding="utf-8")
        self.rules = self.root / "rules"
        rust_rules.generate(self.rules)

    def _process(self, command: list[str], cache_name: str, *, cache: bool = True) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0" if cache else "1", UBS_CACHE_DIR=str(self.root / cache_name),
                   UBS_CACHE_FILE=str(self.root / f"{cache_name}.stats"),
                   UBS_ENABLE_AUTO_UPDATE="0", UBS_PROFILE="1", NO_COLOR="1")
        proc = subprocess.run(command, cwd=self.root, env=env, text=True,
                              capture_output=True, timeout=180, check=False)
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        return proc

    def _json(self, text: str, proc: subprocess.CompletedProcess[str]) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            self.fail(f"Invalid Rust report: {exc}; report={text!r}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")

    def _native(self, target: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
        paths = self.root / "inputs"
        paths.write_bytes(os.fsencode(target) + b"\0")
        output = self.root / "native.json"
        proc = self._process([
            sys.executable, "-m", "ubs_core.rust_scan", "--files-from", str(paths),
            "--sink", str(self.root / "native.ndjson"), "--json-out", str(output),
            "--project-dir", str(self.root), "--ast-rule-dir", str(self.rules),
            "--skip-type-narrowing", "--quiet",
        ], "native-cache")
        self.assertTrue(output.is_file(), proc.stdout + proc.stderr)
        return proc, self._json(output.read_text(encoding="utf-8"), proc)

    def _cli(self, meta: bool, output_format: str, *, cache: bool = True) -> tuple[subprocess.CompletedProcess[str], dict]:
        command = ([str(REPO_ROOT / "ubs"), "--only=rust", "--no-auto-update"] if meta
                   else [str(REPO_ROOT / "modules/ubs-rust.sh")])
        proc = self._process([
            *command, "--no-cargo", f"--format={output_format}", str(self.fixture),
        ], f"cli-cache-{meta}", cache=cache)
        return proc, self._json(proc.stdout, proc)

    def _cli_cache_counts(self, meta: bool, payload: dict, proc: subprocess.CompletedProcess[str]) -> tuple[int, int]:
        if meta:
            return payload["profile"]["cache_hits"], payload["profile"]["cache_misses"]
        # The standalone Rust summary omits profile fields; its native scanner
        # still writes this real cache-statistics sidecar on every invocation.
        stats_path = self.root / f"cli-cache-{meta}.stats"
        self.assertTrue(stats_path.is_file(), proc.stdout + proc.stderr)
        stats = self._json(stats_path.read_text(encoding="utf-8"), proc)
        return stats["hits"], stats["misses"]

    def _expected_sites(self, anchors: tuple[tuple[int, str], ...]) -> list[tuple[int, int]]:
        lines = self.source.splitlines()
        return sorted((line, lines[line - 1].index(anchor) + 1) for line, anchor in anchors)

    def _assert_native(self, records: list[dict]) -> None:
        for rule, (severity, guidance, anchors) in self.EXPECTED.items():
            with self.subTest(rule=rule):
                hits = [record for record in records if record["rule"] == rule]
                self.assertEqual(sorted((hit["line"], hit["col"]) for hit in hits),
                                 self._expected_sites(anchors), hits)
                for hit in hits:
                    self.assertEqual(Path(hit["path"]).resolve(), self.fixture)
                    self.assertEqual(hit["severity"], severity)
                    self.assertIn(guidance, hit["message"])
        ordinary_asserts = [record for record in records if record["rule"] == "rust.panic.assert-macros"]
        self.assertFalse(any(record["line"] in (73, 74, 75) for record in ordinary_asserts))

    def _assert_sarif(self, payload: dict) -> list[tuple]:
        self.assertEqual(payload["version"], "2.1.0")
        results = [result for run in payload["runs"] for result in run.get("results", [])]
        normalized = []
        for rule, (severity, guidance, anchors) in self.EXPECTED.items():
            with self.subTest(rule=rule):
                hits = [result for result in results if result["ruleId"] == rule]
                sites = []
                for hit in hits:
                    location = hit["locations"][0]["physicalLocation"]
                    self.assertTrue(location["artifactLocation"]["uri"].endswith(self.fixture.name), location)
                    region = location["region"]
                    sites.append((region["startLine"], region["startColumn"]))
                    self.assertEqual(hit["level"], "note" if severity == "info" else severity)
                    self.assertIn(guidance, hit["message"]["text"])
                    normalized.append((rule, hit["level"], *sites[-1], hit["message"]["text"]))
                self.assertEqual(sorted(sites), self._expected_sites(anchors), hits)
        ordinary_asserts = [result for result in results if result["ruleId"] == "rust.panic.assert-macros"]
        self.assertFalse(any(result["locations"][0]["physicalLocation"]["region"]["startLine"] in (73, 74, 75)
                             for result in ordinary_asserts))
        return sorted(normalized)

    def test_original_sites_and_guidance_survive_native_cache_hits(self) -> None:
        cold_proc, cold = self._native(self.fixture)
        self.assertEqual(cold_proc.returncode, 1)
        self.assertEqual(cold["status"], "ok")
        self.assertEqual(cold["files"], 1)
        self.assertEqual((cold["profile"]["cache_hits"], cold["profile"]["cache_misses"]), (0, 1))
        self._assert_native(cold["findings"])
        cold_bytes = (self.root / "native.ndjson").read_bytes()
        warm_proc, warm = self._native(self.fixture)
        self.assertEqual(warm_proc.returncode, cold_proc.returncode)
        self.assertEqual((warm["profile"]["cache_hits"], warm["profile"]["cache_misses"]), (1, 0))
        self._assert_native(warm["findings"])
        self.assertEqual(warm["findings"], cold["findings"])
        self.assertEqual((self.root / "native.ndjson").read_bytes(), cold_bytes)

    def test_module_and_meta_sarif_preserve_uncached_and_cached_diagnostics(self) -> None:
        for meta in (False, True):
            with self.subTest(meta=meta):
                cold_proc, cold = self._cli(meta, "json")
                self.assertEqual(cold_proc.returncode, 1)
                self.assertEqual(self._cli_cache_counts(meta, cold, cold_proc), (0, 1))
                warm_proc, warm = self._cli(meta, "json")
                self.assertEqual(warm_proc.returncode, cold_proc.returncode)
                self.assertEqual(self._cli_cache_counts(meta, warm, warm_proc), (1, 0))
                cached_proc, cached = self._cli(meta, "sarif")
                self.assertEqual(cached_proc.returncode, cold_proc.returncode)
                cached_sites = self._assert_sarif(cached)
                uncached_proc, uncached = self._cli(meta, "sarif", cache=False)
                self.assertEqual(uncached_proc.returncode, cold_proc.returncode)
                self.assertEqual(self._assert_sarif(uncached), cached_sites)

    def test_safe_variants_comments_and_strings_do_not_trigger_restored_checks(self) -> None:
        target = self.root / "safe_variants.rs"
        target.write_text(
            "fn safe(input: &str, bytes: &[u8], value: i64, items: &[String]) {\n"
            "    let _ = value as usize;\n"
            "    let _ = input.parse::<f64>();\n"
            "    let started = Instant::now();\n"
            "    let _ = started.elapsed();\n"
            "    let _ = started.checked_sub(Duration::from_secs(1));\n"
            "    let _ = Nonce::try_from(bytes);\n"
            "    let _ = GenericArray::try_from(bytes);\n"
            "    let _ = Key::try_from(bytes);\n"
            "    let _ = value.checked_neg();\n"
            "    let _ = value.checked_add(1);\n"
            "    let _ = value.checked_sub(1);\n"
            "    let _ = value.checked_mul(1);\n"
            "    let _ = std::fs::rename(\"staged\", \"live\");\n"
            "    let _ = items.iter().cloned();\n"
            "    let _ = String::from_utf8_lossy(bytes);\n"
            "    let _ = str::from_utf8(bytes);\n"
            "    let _ = regex::Regex::new(input);\n"
            "    assert!(value != 0);\n"
            "    tokio::task::block_in_place(|| work());\n"
            "}\n"
            "async fn scheduled() { let task = tokio::spawn(async move { work() }); task.await; }\n"
            "fn work() {}\n"
            "// Instant::now().elapsed(); debug_assert!(false); Nonce::from_slice(bytes);\n"
            'const TEXT: &str = "tokio::spawn(async { work() }); value.wrapping_neg();";\n',
            encoding="utf-8",
        )
        _, doc = self._native(target)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(doc["files"], 1)
        restored = [record for record in doc["findings"] if record["rule"] in self.EXPECTED]
        self.assertEqual(restored, [])


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
            ("use ::jsonwebtoken::{decode as parse_token};", "parse_token"),
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

    def test_imports_do_not_escape_their_rust_scope(self) -> None:
        cases = [
            "mod auth { use jsonwebtoken::decode; }\n"
            "mod binary {\n"
            "    fn decode(bytes: &[u8]) {}\n"
            "    fn run(bytes: &[u8]) { decode(bytes); }\n"
            "}\n",
            "fn auth(token: &str) { use jsonwebtoken::decode; }\n"
            "fn decode(bytes: &[u8]) {}\n"
            "fn binary(bytes: &[u8]) { decode(bytes); }\n",
            "use jsonwebtoken::decode;\n"
            "mod binary {\n"
            "    fn decode(bytes: &[u8]) {}\n"
            "    fn run(bytes: &[u8]) { decode(bytes); }\n"
            "}\n",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(self.hits(source), [])

    def test_local_bindings_shadow_imports_only_in_their_scope(self) -> None:
        source = (
            "use jsonwebtoken::decode;\n"
            "fn auth(token: &str, key: &DecodingKey) {\n"
            "    decode::<Claims>(token, key, &Validation::default());\n"
            "    {\n"
            "        let decode = |bytes: &[u8]| bytes.len();\n"
            "        decode(b\"binary\");\n"
            "    }\n"
            "    decode::<Claims>(token, key, &Validation::default());\n"
            "}\n"
            "fn binary(decode: fn(&[u8]), bytes: &[u8]) { decode(bytes); }\n"
        )
        self.assertEqual(self.hits(source), [3, 8])

    def test_value_bindings_do_not_hide_crate_namespaces_or_initializers(self) -> None:
        self.assertEqual(self.hits(
            "use jsonwebtoken::{self as jwt, decode};\n"
            "fn auth(token: &str, key: &DecodingKey) {\n"
            "    let jwt = 7;\n"
            "    jwt::decode::<Claims>(token, key, &Validation::default());\n"
            "    let decode = decode::<Claims>(token, key, &Validation::default());\n"
            "}\n"
        ), [4, 5])

    def test_local_module_names_do_not_impersonate_external_crates(self) -> None:
        self.assertEqual(self.hits(
            "mod jsonwebtoken { pub fn decode(bytes: &[u8]) {} }\n"
            "fn binary(bytes: &[u8]) { jsonwebtoken::decode(bytes); }\n"
            "use ::jsonwebtoken::decode as parse_token;\n"
            "fn auth(token: &str, key: &DecodingKey) {\n"
            "    parse_token::<Claims>(token, key, &Validation::default());\n"
            "}\n"
        ), [5])

    def test_unsafe_decoder_names_require_jwt_identity(self) -> None:
        self.assertEqual(self.hits(
            "fn insecure_decode(bytes: &[u8]) {}\n"
            "fn dangerous_unsafe_decode(bytes: &[u8]) {}\n"
            "fn run(bytes: &[u8]) {\n"
            "    insecure_decode(bytes);\n"
            "    dangerous_unsafe_decode(bytes);\n"
            "    binary::dangerous::insecure_decode(bytes);\n"
            "}\n"
        ), [])

    def test_unsafe_jwt_decoder_aliases_and_globs_still_report(self) -> None:
        cases = [
            ("", "jsonwebtoken::dangerous::insecure_decode"),
            ("use jsonwebtoken::dangerous::insecure_decode as parse;", "parse"),
            ("use jsonwebtoken::{dangerous::{insecure_decode as parse}};", "parse"),
            ("use jsonwebtoken::dangerous as unchecked;", "unchecked::insecure_decode"),
            ("use jsonwebtoken::dangerous::*;", "insecure_decode"),
            ("use jsonwebtoken::dangerous_unsafe_decode as parse;", "parse"),
            ("use jsonwebtoken::*;", "dangerous_unsafe_decode"),
            ("extern crate jsonwebtoken as jwt; use jwt::dangerous as unchecked;", "unchecked::insecure_decode"),
        ]
        for imports, call in cases:
            with self.subTest(imports=imports, call=call):
                self.assertEqual(self.hits(
                    imports + "\n"
                    "fn auth(token: &str) {\n"
                    f"    {call}::<Claims>(token);\n"
                    "}\n"
                ), [3])

    def test_nested_module_explicit_imports_keep_jwt_identity(self) -> None:
        source = (
            "use jsonwebtoken as jwt;\n"
            "mod auth {\n"
            "    use super::jwt::{decode as verify, dangerous::insecure_decode as parse};\n"
            "    fn run(token: &str, key: &DecodingKey) {\n"
            "        verify::<Claims>(token, key, &jwt::Validation::default());\n"
            "        parse::<Claims>(token);\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(self.hits(source), [5, 6])

    def test_original_jwt_security_fixtures_remain_classified(self) -> None:
        rust = REPO_ROOT / "test-suite" / "rust"
        self.assertEqual(list(jwt_verification.find([rust / "clean/jwt_verification.rs"])), [])
        self.assertEqual(
            [line for _, line, _, _ in jwt_verification.find([rust / "buggy/jwt_verification.rs"])],
            [11, 15, 23, 24, 32, 33, 41, 44, 52, 65],
        )


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


class RustPublicCredentialMetadataTests(unittest.TestCase):
    """Public locator labels and material values are different evidence classes."""

    CLEAN = '''const SEARCH_API_KEY_CREDENTIAL_HANDLE: &str = "cred_search_api_key";
const SEARCH_CREDENTIAL_ENV_VAR: &str = "SEARCH_API_KEY";
const CLIENT_SECRET_ENV_VAR: &str = "SEARCH_CLIENT_SECRET";
fn catalogue() {
    let secret_label = "credential-ref:catalog/live_api_key";
    let credential_ref = "credential-ref:catalog/client_secret";
    settings.insert("credential_handle", "cred_search_api_key");
}
'''
    MATERIAL = '''const SEARCH_API_KEY_CREDENTIAL_HANDLE: &str = "sk_live_abc123xyz";
const SEARCH_CREDENTIAL_ENV_VAR: &str = "actual-secret-credential";
const CLIENT_SECRET_ENV_VAR: &str = "literal-password-value";
fn catalogue() {
    let secret_label = "literal-secret-value";
    let credential_ref = "literal-token-value";
    settings.insert("credential_handle", "literal-token-value");
    let password = "credential-ref:catalog/client_secret";
    let auth_token = "ABC12345SECRET67890";
    let token = "opaque-continuation-value";
    let credential_handle = std::env::var("AUTH_TOKEN").unwrap_or("live-default-token".to_owned());
}
'''

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(prefix="rust-credential-metadata-", dir=artifacts)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def test_metadata_requires_both_a_locator_target_and_a_locator_literal(self) -> None:
        clean = self.root / "metadata.rs"
        material = self.root / "material.rs"
        clean.write_text(self.CLEAN, encoding="utf-8")
        material.write_text(self.MATERIAL, encoding="utf-8")
        self.assertEqual(list(rust_hardcoded_secrets.find([clean], self.root)), [])
        self.assertEqual([hit[1] for hit in rust_hardcoded_secrets.find([material], self.root)],
                         [1, 2, 3, 5, 6, 7, 8, 9, 10, 11])

    def test_credential_locations_point_to_material_not_enclosing_headers(self) -> None:
        source = '''fn access_token_loader() {
    let access_token = "credential-material-731-retain";
}
fn api_token_cache() {
    if let Ok(mut cache) = token_cache.lock() {
        *cache = Some(Token {
            access_token: "credential-material-731-retain".to_owned(),
            id: 1,
            refresh_token: "credential-material-732-retain".to_owned(),
        });
    }
    let password =
        "credential-material-733-retain";
}
'''
        material = self.root / "material_locations.rs"
        material.write_text(source, encoding="utf-8")
        findings = list(rust_hardcoded_secrets.find([material], self.root))
        self.assertEqual([hit[1] for hit in findings], [2, 7, 9, 12])
        self.assertEqual([hit[3] for hit in findings],
                         [source.splitlines()[index - 1].strip() for index in [2, 7, 9, 12]])
        code, doc = RustPanicContextTests.scan(self, [material], categories=(8,), ast=False)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.security.hardcoded-secrets"]
        self.assertEqual(code, 1)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual([hit["line"] for hit in hits], [2, 7, 9, 12])
        self.assertTrue(all(hit["severity"] == "critical" for hit in hits), hits)

    def test_multiline_env_fallback_location_retains_the_critical_default(self) -> None:
        source = '''fn access_token_fallback() -> String {
    let value =
        std::env::var("ACCESS_TOKEN")
            .unwrap_or("credential-material-734-retain".to_owned());
    value
}
'''
        material = self.root / "env_fallback_location.rs"
        material.write_text(source, encoding="utf-8")
        findings = list(rust_hardcoded_secrets.find([material], self.root))
        self.assertEqual([hit[1] for hit in findings], [3])
        self.assertEqual(findings[0][3], source.splitlines()[2].strip())

    def test_dynamic_credentials_without_a_literal_fallback_remain_clean(self) -> None:
        source = '''fn access_token_loader() -> Result<String, Error> {
    let access_token = std::env::var("ACCESS_TOKEN")?;
    Ok(access_token)
}
'''
        clean = self.root / "dynamic_credentials.rs"
        clean.write_text(source, encoding="utf-8")
        self.assertEqual(list(rust_hardcoded_secrets.find([clean], self.root)), [])

    def test_public_scanner_keeps_material_values_critical(self) -> None:
        clean = self.root / "metadata.rs"
        material = self.root / "material.rs"
        clean.write_text(self.CLEAN, encoding="utf-8")
        material.write_text(self.MATERIAL, encoding="utf-8")
        code, doc = RustPanicContextTests.scan(self, [clean, material], categories=(8,), ast=False)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.security.hardcoded-secrets"]
        self.assertEqual(code, 1)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual([hit["line"] for hit in hits], [1, 2, 3, 5, 6, 7, 8, 9, 10, 11])
        self.assertTrue(all(hit["severity"] == "critical" and Path(hit["path"]) == material
                            for hit in hits), hits)
        self.assertEqual(RustPanicContextTests.scan(self, [clean], categories=(8,), ast=False)[0], 0)


class RustComparisonBoundaryTests(unittest.TestCase):
    """Namespace arms and boolean destinations are not secret operands."""

    RULE = "rust.security.constant-time-compare"
    # Preserve the actual CASS ordering: a later diagnostic match arm used to
    # taint `doctor` in the fixpoint pass, corrupting both earlier comparisons.
    RESTORE = '''fn restore(command: doctor::DoctorBackupCommand,
           execution_mode: doctor::DoctorExecutionMode) {
    if command == doctor::DoctorBackupCommand::Restore {
        let apply_requested = execution_mode == doctor::DoctorExecutionMode::RestoreApply;
        let (restore_plan, plan_fingerprint) = doctor_restore_plan_payload(
            &data_dir,
            &db_path,
            &backup_id_text,
            &verification,
            apply_requested,
            requested_plan_fingerprint.clone(),
        );
        consume(restore_plan, plan_fingerprint);
    }
    match command {
        doctor::DoctorBackupCommand::Verify => {
            println!(
                "doctor backup {} verification: {}",
                backup_id_text,
                payload["backup_verification"]["status"]
            );
        }
        doctor::DoctorBackupCommand::Restore => {}
    }
}
'''
    COMPARISONS = '''fn verify(expected_signature: &str, provided: &str, ordinary: &str, expected: &str) {
    let alias: &str = expected_signature;
    alias != provided; // expect: typed-alias
    let mut value = ordinary;
    value = expected_signature;
    value == provided; // expect: assigned-alias
    expected_signature == (
        provided); // multiline right operand
    let password_matches = ordinary == expected;
    let _ = expected_signature == provided; // expect: discard-positive
    let _ = ordinary == expected;
    // ubs:ignore[unknown.public.rule]
    alias == provided; // expect: unrelated-scope
    // ubs:ignore[rust.security.constant-time-compare]
    alias == provided;
    alias == provided; // expect: adjacent-unmarked
}
fn comparison_is_not_assignment(candidate: &str, expected_signature: &str, ordinary: &str) {
    candidate == expected_signature; // expect: direct-positive
    candidate == ordinary;
}
fn local_namespace_shadow(provided: &str) {
    let doctor: &str = load_secret();
    doctor == provided; // expect: namespace-shadow
}
fn unrelated_function(doctor: &str, ordinary: &str) {
    doctor == ordinary;
}
fn branch_neighbors(mode: Mode, expected_signature: &str, provided: &str) {
    if mode == Mode::Restore {
        expected_signature == provided; // expect: branch-body
    }
    if expected_signature != provided { // expect: branch-condition
        consume(provided);
    }
    mode == Mode::Restore;
}
fn timing_safe(expected_signature: &[u8], provided: &[u8]) -> bool {
    expected_signature.ct_eq(provided).into()
}
'''

    def expected_sites(self, source: str) -> list[tuple[int, str]]:
        return [(number, line.strip()) for number, line in enumerate(source.splitlines(), 1)
                if "// expect:" in line or line.strip() == "expected_signature == ("]

    def test_real_restore_match_arm_does_not_taint_namespace(self) -> None:
        self.assertEqual(ctcompare_rust.scan_file(self.RESTORE), [])

    def test_quoted_equals_fields_do_not_seed_or_revoke_module_taint(self) -> None:
        literals = (
            ("ordinary", "&'static str", '"KEY=VALUE credential secret"'),
            ("byte", "&'static [u8]", 'b"KEY=VALUE credential secret"'),
            ("raw", "&'static str", 'r#"KEY=VALUE credential secret"#'),
            ("character", "char", "'='"),
        )
        for kind, field_type, literal in literals:
            with self.subTest(kind=kind):
                source = f'''struct Help {{
    summary: {field_type},
    usage: {field_type},
    credential_handle: {field_type},
}}
const credential_handle: &str = "cred_provider_runtime";
const HELP: Help = Help {{
    summary: {literal},
    usage: {literal},
    credential_handle: {literal},
}};
fn ordinary(summary: u64, usage: u64, expected_rows: u64, supplied: &str) {{
    let accounted = summary;
    summary != expected_rows;
    accounted != expected_rows;
    usage != expected_rows;
    credential_handle == supplied;
}}
'''
                self.assertEqual(ctcompare_rust.scan_file(source), [])
                field = f"summary: {literal}"
                self.assertEqual(ctcompare_rust.clean_operand_text(field), field)

    def test_real_assignments_keep_secret_literal_and_lookup_rhs(self) -> None:
        source = '''const SERVER_SECRET: &str = "credential=material-retained";
static PRIVATE_TOKEN: &str = r#"token=material-retained"#;
fn verify(payload: Value, supplied: &str, ordinary: &str) {
    SERVER_SECRET != supplied; // expect: module-secret
    PRIVATE_TOKEN == supplied; // expect: module-token
    let typed_alias: &str = SERVER_SECRET;
    typed_alias == supplied; // expect: typed-alias
    let typed_env: String = std::env::var("AUTH_TOKEN").unwrap();
    typed_env == supplied; // expect: typed-env-alias
    let mut reassigned = ordinary.to_owned();
    reassigned = std::env::var("AUTH_TOKEN").unwrap();
    reassigned != supplied; // expect: reassigned-env
    let field = payload["auth_token"].as_str().unwrap();
    field != supplied; // expect: indexed-alias
    let keyed = payload.get("api_key").and_then(Value::as_str).unwrap();
    keyed == supplied; // expect: keyed-alias
    std::env::var("API_KEY").unwrap() != supplied; // expect: direct-env
    payload["auth_token"].as_str().unwrap() != supplied; // expect: direct-index
    let credential_handle = std::env::var("REAL_SECRET").unwrap();
    let alias = credential_handle.as_str();
    alias == supplied; // expect: late-locator-alias
    let credential_handle = "cred_provider_runtime";
}
'''
        expected = self.expected_sites(source)
        self.assertEqual(len(expected), 10)
        self.assertEqual(ctcompare_rust.scan_file(source), expected)

    def test_public_operands_do_not_combine_into_secret_vocabulary(self) -> None:
        operands = ("PUBLIC_API_PROFILE", "hex::encode(Sha256::digest(profile_bytes))")
        for operand in operands:
            self.assertFalse(ctcompare_rust.is_sensitive_operand_text(operand), operand)
        self.assertFalse(ctcompare_rust.is_sensitive_operand_text(
            "hex::encode(Sha256::digest(PUBLIC_API_PROFILE))"))
        source = '''const SEARCH_API_KEY_CREDENTIAL_HANDLE: &str = "cred_search_api_key";
fn integrity(manifest: Manifest, refusal_code: &str, requirement: Requirement) {
    hex::encode(Sha256::digest(PUBLIC_API_PROFILE)) != manifest.content_hash_sha256;
    match mode {
        Mode::Live if refusal_code == "provider.credential_missing" => {}
        _ if entitlement_state == "missing" => "provider.credential_missing",
    }
    requirement.handle_key == SEARCH_API_KEY_CREDENTIAL_HANDLE;
    output.error_code.as_deref() == Some("provider.credential_missing");
    value.missing_requirements == vec!["ApiKey".to_owned()];
}
'''
        self.assertEqual(ctcompare_rust.scan_file(source), [])

    def test_metadata_names_do_not_hide_material_or_keyed_digests(self) -> None:
        source = '''fn verify(auth_token: &str, expected_signature: &str, supplied: &str) {
    auth_token == supplied;
    expected_signature != supplied;
    let credential_handle = auth_token;
    credential_handle == supplied;
    let secret_label = load_secret();
    secret_label != supplied;
    let expected = hex::encode(Sha256::digest(auth_token));
    expected == supplied;
    hmac.finalize().into_bytes() == supplied;
}
'''
        self.assertEqual([line for line, _ in ctcompare_rust.scan_file(source)], [2, 3, 5, 7, 9, 10])

    def test_secret_lookup_literals_taint_direct_values_and_aliases_but_public_keys_do_not(self) -> None:
        secret = '''fn verify(payload: Value, supplied: &str) {
    let candidate = std::env::var("AUTH_TOKEN").unwrap();
    candidate == supplied;
    env::var("API_KEY").unwrap() != supplied;
    option_env!("CLIENT_SECRET") == supplied;
    let field = payload["auth_token"].as_str();
    field == supplied;
    payload.get("api_key") != supplied;
    let key = payload.get("password");
    key == supplied;
}
'''
        public = '''fn verify(payload: Value, supplied: &str) {
    let candidate = std::env::var("PUBLIC_API_PROFILE").unwrap();
    candidate == supplied;
    env::var("PUBLIC_PROVIDER_CODE").unwrap() != supplied;
    payload["profile_name"].as_str() == supplied;
    payload.get("profile_name") != supplied;
    payload.get("provider.credential_missing") == supplied;
    let message = r#"payload["auth_token"] std::env::var("AUTH_TOKEN")"#;
    message == supplied;
    let wrapped = Some("provider.credential_missing");
    wrapped == supplied;
}
'''
        self.assertEqual([line for line, _ in ctcompare_rust.scan_file(secret)], [3, 4, 5, 7, 8, 10])
        self.assertEqual(ctcompare_rust.scan_file(public), [])

    def test_locator_proof_does_not_transfer_to_members_parameters_or_reassignments(self) -> None:
        source = '''const SEARCH_API_KEY_CREDENTIAL_HANDLE: &str = "cred_search_api_key";
fn public(requirement: Requirement) {
    requirement.handle_key == SEARCH_API_KEY_CREDENTIAL_HANDLE;
}
fn members(request: Request, supplied: &str) {
    request.SEARCH_API_KEY_CREDENTIAL_HANDLE == supplied;
    other::SEARCH_API_KEY_CREDENTIAL_HANDLE != supplied;
}
fn parameter(SEARCH_API_KEY_CREDENTIAL_HANDLE: &str, supplied: &str) {
    SEARCH_API_KEY_CREDENTIAL_HANDLE == supplied;
}
fn reassignment(supplied: &str) {
    let SEARCH_API_KEY_CREDENTIAL_HANDLE = read_value();
    SEARCH_API_KEY_CREDENTIAL_HANDLE == supplied;
}
'''
        self.assertEqual([line for line, _ in ctcompare_rust.scan_file(source)], [6, 7, 10, 14])

    def test_locator_writes_never_hide_unproven_bindings_in_either_order(self) -> None:
        secret = '    let credential_handle = std::env::var("REAL_SECRET").unwrap();\n'
        locator = '    let credential_handle = "cred_provider_runtime";\n'
        compare = '    if credential_handle == supplied { grant(); }\n'
        alias = '    let candidate = credential_handle;\n    if candidate == supplied { grant(); }\n'
        cases = (
            ("late shadow", secret + compare + locator, [3]),
            ("early locator", locator + secret + compare, [4]),
            ("late shadow alias", secret + alias + locator, [4]),
            ("early locator alias", locator + secret + alias, [5]),
            ("late reassignment", secret.replace("let ", "let mut ") + compare
             + '    credential_handle = "cred_provider_runtime";\n', [3]),
            ("early reassignment", locator.replace("let ", "let mut ")
             + '    credential_handle = std::env::var("REAL_SECRET").unwrap();\n' + compare, [4]),
        )
        for name, body, expected in cases:
            with self.subTest(order=name):
                source = "fn verify(supplied: &str) {\n" + body + "}\n"
                self.assertEqual([line for line, _ in ctcompare_rust.scan_file(source)], expected)
        parameter = ('fn verify(credential_handle: &str, supplied: &str) {\n'
                     + compare + locator + '}\n')
        self.assertEqual([line for line, _ in ctcompare_rust.scan_file(parameter)], [2])

    def test_real_aliases_operands_neighbors_and_function_shadowing(self) -> None:
        expected = self.expected_sites(self.COMPARISONS)
        self.assertEqual(len(expected), 10)
        self.assertEqual(ctcompare_rust.scan_file(self.COMPARISONS), expected)
        # Existing positive/clean source pairs also protect the original
        # detector's secret vocabulary, constant-time APIs, and function scopes.
        fixtures = REPO_ROOT / "test-suite/rust"
        for name, count in (("constant_time_compare.rs", 8),
                            ("secret_compare_function_scope.rs", 4)):
            with self.subTest(fixture=name):
                self.assertEqual(len(ctcompare_rust.scan_file(
                    (fixtures / "buggy" / name).read_text(encoding="utf-8"))), count)
                self.assertEqual(ctcompare_rust.scan_file(
                    (fixtures / "clean" / name).read_text(encoding="utf-8")), [])

    def test_public_generated_and_fallback_reports_preserve_exact_cached_sites(self) -> None:
        self.assertIsNotNone(shutil.which("ast-grep"), "generated public scan requires real ast-grep")
        for ast in (True, False):
            with self.subTest(ast=ast), tempfile.TemporaryDirectory(prefix="ubs_rust_comparison_") as td:
                root = Path(td)
                project = root / "project"
                project.mkdir()
                clean = project / "restore.rs"
                positive = project / "compare.rs"
                clean.write_text(self.RESTORE, encoding="utf-8")
                positive.write_text(self.COMPARISONS, encoding="utf-8")
                inputs = root / "inputs"
                report = root / "findings.ndjson"
                statistics = root / "cache-stats.json"
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                           UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(statistics),
                           UBS_PROFILE="1", UBS_SKIP_TYPE_NARROWING="1", NO_COLOR="1",
                           UBS_TEST_FORCE_NO_AST_GREP="0" if ast else "1")

                def scan(selected: list[Path], source: str, output_format: str, hits: int) -> list[tuple]:
                    inputs.write_bytes(b"\0".join(os.fsencode(path) for path in selected) + b"\0")
                    command = [str(REPO_ROOT / "modules/ubs-rust.sh"), "--no-cargo", "--ci",
                               "--no-color", "--only=8", f"--format={output_format}",
                               f"--report-json={report}", "--files-from", str(inputs), str(project)]
                    proc = subprocess.run(command, cwd=root, env=env, text=True,
                                          capture_output=True, timeout=180)
                    context = f"{command!r}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                    expected = [(self.RULE, str(positive), line, 1, "critical")
                                for line, _ in self.expected_sites(source)] if positive in selected else []
                    self.assertEqual(proc.returncode, int(bool(expected)), context)
                    try:
                        payload = json.loads(proc.stdout)
                        stats = json.loads(statistics.read_text(encoding="utf-8"))
                        records = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
                    except (json.JSONDecodeError, OSError) as exc:
                        self.fail(f"invalid Rust comparison report/statistics: {exc}; {context}")
                    self.assertEqual((stats["hits"], stats["misses"]),
                                     (hits, len(selected) - hits), context)
                    actual = []
                    for record in records:
                        self.assertEqual(record.get("count", 1), 1, context)
                        actual.append((record["rule"], str((root / record["path"]).resolve()),
                                       record["line"], record["col"], record["severity"]))
                    self.assertEqual(sorted(actual), sorted(expected), context)
                    if output_format == "json":
                        self.assertEqual(payload["status"], "ok", context)
                        self.assertEqual((payload["critical"], payload["warning"], payload["info"]),
                                         (len(expected), 0, 0), context)
                    else:
                        self.assertEqual(payload["version"], "2.1.0", context)
                        self.assertEqual(len(payload["runs"]), 1, context)
                        run = payload["runs"][0]
                        self.assertEqual(run["tool"]["driver"]["name"], "ubs-rust", context)
                        sarif = []
                        for record in run["results"]:
                            self.assertEqual(record["level"], "error", context)
                            self.assertEqual(len(record["locations"]), 1, context)
                            location = record["locations"][0]["physicalLocation"]
                            sarif.append((record["ruleId"], str(sarif_location_path(location["artifactLocation"]["uri"], root).resolve()),
                                          location["region"]["startLine"], location["region"]["startColumn"], "critical"))
                        self.assertEqual(sorted(sarif), sorted(expected), context)
                    return sorted(records, key=lambda record: (record["path"], record["line"], record["col"]))

                cold = scan([clean, positive], self.COMPARISONS, "json", 0)
                self.assertEqual(scan([clean, positive], self.COMPARISONS, "json", 2), cold)
                self.assertEqual(scan([clean, positive], self.COMPARISONS, "sarif", 2), cold)
                self.assertEqual(scan([clean], self.RESTORE, "json", 1), [])
                repaired = self.COMPARISONS.replace(
                    "alias != provided; // expect: typed-alias", "consume(alias); // repaired typed-alias")
                positive.write_text(repaired, encoding="utf-8")
                partial = scan([clean, positive], repaired, "json", 1)
                self.assertEqual(len(partial), len(cold) - 1)
                self.assertEqual(scan([clean, positive], repaired, "sarif", 2), partial)


class RustCryptographicRandomnessTests(unittest.TestCase):
    RULE = "rust.security.non-crypto-random"
    SECURE = '''use rand::{Rng, RngCore};
fn create_session_token() {
    let mut rng = rand::rng();
    let token: [u8; 32] = rng.random();
    let mut salt = [0_u8; 32];
    rand::rng().fill_bytes(&mut salt);
    let token: [u8; 32] = rand::random();
    let token = rand::random::<[u8; 32]>();
    let token = rand::thread_rng().gen::<[u8; 32]>();
    let mut thread = rand::rngs::ThreadRng::default();
    let token: [u8; 32] = thread.random();
    let mut standard = rand::rngs::StdRng::from_entropy();
    let token: [u8; 32] = standard.random();
    let mut standard = rand::rngs::StdRng::from_os_rng();
    let token: [u8; 32] = standard.random();
}
fn csrf_nonce() {
    let token = rand::random::<
        [u8; 32]>();
    let mut rng = rand::rng();
    let salt: [u8; 32] = rng.random();
}
fn count_sessions_bounded() {
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    if std::time::Instant::now() >= deadline {
        return;
    }
}
fn doctor_source_authority() {
    let source_authority_started = Instant::now();
}
fn api_key_timeout() {
    let started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(2);
    if Instant::now() >= deadline {
        return;
    }
}
fn verify_pack_source_citations() {
    verify_citations(
        &mut plan,
        Instant::now() + Duration::from_millis(500),
    );
}
fn unique_failed_seed_backup_root() {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH);
    let nonce = NEXT_NONCE.fetch_add(1, Ordering::Relaxed);
    backups_dir.join(format!("{timestamp}.{}.{}.bak", std::process::id(), nonce))
}
fn doctor_lock_metadata_pid_is_current_process(pid: u32) -> bool {
    pid == std::process::id()
}
'''
    WEAK = '''fn create_session_token() {
    let nonce = fastrand::u64(..); // expect: weak
    let mut small = rand::rngs::SmallRng::seed_from_u64(7);
    let token = small.next_u64(); // expect: weak
    let mut small = rand::rngs::SmallRng::from_os_rng();
    let token = small.next_u64(); // expect: weak
    let mut seeded = rand::rngs::StdRng::seed_from_u64(7);
    let token = seeded.next_u64(); // expect: weak
    let token = std::time::SystemTime::now(); // expect: weak
    let token = std::process::id(); // expect: weak
    let token = hasher.finish(); // expect: weak
    let token = fastrand::u64(..); // ubs:ignore[rust.security.non-crypto-random]

    let token = fastrand::u64(..); // ubs:ignore[rust.panic.assert-macros] expect: weak
    let token = fastrand::u64( // expect: weak
        ..); // multiline ends here
    let text = "token fastrand::u64(..)";
}
fn display_jitter() {
    let number = fastrand::u64(..);
}
fn api_key_from_seed() {
    let seed = SystemTime::now().duration_since(UNIX_EPOCH); // expect: weak
}
fn csrf_nonce_from_clock() {
    SystemTime::now().duration_since(UNIX_EPOCH) // expect: weak
}
fn password_reset_token() {
    return format!("{}", std::process::id()); // expect: weak
}
'''

    @staticmethod
    def weak_lines(source: str) -> list[int]:
        return [line for line, text in enumerate(source.splitlines(), 1)
                if "expect: weak" in text]

    def test_crypto_generators_and_insecure_sources_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_rust_random_") as tmp:
            root = Path(tmp)
            secure = root / "secure.rs"
            weak = root / "weak.rs"
            secure.write_text(self.SECURE, encoding="utf-8")
            weak.write_text(self.WEAK, encoding="utf-8")
            self.assertEqual(list(security_randomness.find([secure])), [])
            findings = list(security_randomness.find([weak]))
            self.assertEqual([(path, line, col) for path, line, col, _ in findings],
                             [(weak, line, 1) for line in self.weak_lines(self.WEAK)])
            # Keep the formerly flagged original ThreadRng/random examples as
            # explicit controls, while the other real fixture hazards survive.
            original = REPO_ROOT / "test-suite/rust/buggy/security_randomness.rs"
            original_hits = list(security_randomness.find([original]))
            self.assertFalse(any(line in (8, 9, 13) for _, line, _, _ in original_hits))
            self.assertGreaterEqual(len(original_hits), 5)

    def test_public_reports_and_cache_preserve_crypto_controls_and_weak_sites(self) -> None:
        self.assertIsNotNone(shutil.which("ast-grep"), "real generated Rust scan required")
        for ast in (True, False):
            with self.subTest(ast=ast), tempfile.TemporaryDirectory(prefix="ubs_rust_random_cli_") as tmp:
                root = Path(tmp)
                project = root / "project"
                project.mkdir()
                secure = project / "secure.rs"
                weak = project / "weak.rs"
                secure.write_text(self.SECURE, encoding="utf-8")
                weak.write_text(self.WEAK, encoding="utf-8")
                inputs = root / "inputs"
                report = root / "findings.ndjson"
                statistics = root / "cache-stats.json"
                env = dict(os.environ, UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / "cache"),
                           UBS_CACHE_FILE=str(statistics), UBS_PROFILE="1", NO_COLOR="1",
                           UBS_SKIP_TYPE_NARROWING="1", UBS_TEST_FORCE_NO_AST_GREP="0" if ast else "1")

                def scan(selected: list[Path], source: str, output_format: str, hits: int) -> list[dict]:
                    inputs.write_bytes(b"\0".join(os.fsencode(path) for path in selected) + b"\0")
                    command = [str(REPO_ROOT / "modules/ubs-rust.sh"), "--no-cargo", "--ci",
                               "--no-color", "--only=8", f"--format={output_format}",
                               f"--report-json={report}", "--files-from", str(inputs), str(project)]
                    proc = subprocess.run(command, cwd=root, env=env, text=True,
                                          capture_output=True, timeout=180)
                    context = f"{command!r}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                    expected = [(self.RULE, str(weak), line, 1, "critical")
                                for line in self.weak_lines(source)] if weak in selected else []
                    self.assertEqual(proc.returncode, int(bool(expected)), context)
                    try:
                        payload = json.loads(proc.stdout)
                        stats = json.loads(statistics.read_text(encoding="utf-8"))
                        records = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
                    except (json.JSONDecodeError, OSError) as exc:
                        self.fail(f"invalid Rust randomness report/statistics: {exc}; {context}")
                    self.assertEqual((stats["hits"], stats["misses"]), (hits, len(selected) - hits), context)
                    actual = [(record["rule"], str((root / record["path"]).resolve()),
                               record["line"], record["col"], record["severity"]) for record in records]
                    self.assertEqual(sorted(actual), sorted(expected), context)
                    self.assertTrue(all(record.get("count", 1) == 1 for record in records), context)
                    if output_format == "json":
                        self.assertEqual(payload["status"], "ok", context)
                        self.assertEqual((payload["critical"], payload["warning"], payload["info"]),
                                         (len(expected), 0, 0), context)
                    else:
                        self.assertEqual(payload["version"], "2.1.0", context)
                        self.assertEqual(len(payload["runs"]), 1, context)
                        sarif = []
                        for record in payload["runs"][0]["results"]:
                            self.assertEqual(record["level"], "error", context)
                            self.assertEqual(len(record["locations"]), 1, context)
                            loc = record["locations"][0]["physicalLocation"]
                            sarif.append((record["ruleId"], str(sarif_location_path(loc["artifactLocation"]["uri"], root).resolve()),
                                          loc["region"]["startLine"], loc["region"]["startColumn"], "critical"))
                        self.assertEqual(sorted(sarif), sorted(expected), context)
                    return sorted(records, key=lambda record: (record["path"], record["line"], record["col"]))

                cold = scan([secure, weak], self.WEAK, "json", 0)
                self.assertEqual(scan([secure, weak], self.WEAK, "json", 2), cold)
                self.assertEqual(scan([secure, weak], self.WEAK, "sarif", 2), cold)
                self.assertEqual(scan([secure], self.WEAK, "json", 1), [])
                repaired = self.WEAK.replace("let nonce = fastrand::u64(..); // expect: weak",
                                             "let nonce = rand::random::<[u8; 32]>();")
                weak.write_text(repaired, encoding="utf-8")
                partial = scan([secure, weak], repaired, "json", 1)
                self.assertEqual(len(partial), len(cold) - 1)
                self.assertEqual(scan([secure, weak], repaired, "sarif", 2), partial)


class RustArchiveEntryPathTests(unittest.TestCase):
    """Run the real archive-path detector on source and binding counterexamples."""

    CASS_COLLECTIONS = '''use std::path::{Path, PathBuf};
use std::fs;
fn archive_aliases(zip_entry: &zip::read::ZipFile<'_>, destination: &Path) {
    let entry_path = zip_entry.name();
    let path = zip_entry.name();
    destination.join(entry_path); // hazard: archive-alias
}
fn directory_size_bytes_best_effort(root: &Path) {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(iter) = fs::read_dir(&current) else { continue; };
        for entry in iter.flatten() {
            let entry_path = entry.path();
            match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => stack.push(entry_path),
                _ => continue,
            }
        }
    }
}
fn quarantine_summary(quarantine_dir: &Path) {
    let mut quarantine_files: Vec<String> = Vec::new();
    for file_name in ["watch-poison.jsonl", "index-poison.jsonl"] {
        let path = quarantine_dir.join(file_name);
        quarantine_files.push(path.display().to_string());
    }
}
fn recursive_size_for_test(root: &Path) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).unwrap().flatten() {
            stack.push(entry.path());
        }
    }
}
fn oom_fixture_paths(amp_dir: &Path) {
    let mut paths = Vec::new();
    for idx in 0..4 {
        let path = amp_dir.join(format!("thread-oom-{idx}.json"));
        paths.push(path);
    }
}
fn split_batch_fixture_paths(amp_dir: &Path) {
    let mut paths: Vec<PathBuf> = Vec::new();
    for idx in 0..4 {
        let path = amp_dir.join(format!("thread-batch-oom-solo-ok-{idx}.json"));
        paths.push(path);
    }
}
fn filesystem_entry(entry: std::fs::DirEntry, destination: &Path) {
    destination.join(entry.path());
}
'''

    POSITIVES = '''use std::path::{Path, PathBuf};
fn named_archive(zip_entry: &ZipFile, tar_entry: &TarEntry, destination: &Path) {
    destination.join(zip_entry.name()); // hazard: zip-direct
    let mut output = PathBuf::new();
    output.push(tar_entry.path()); // hazard: tar-direct
    let name = zip_entry.name();
    destination.join(name); // hazard: named-alias
    {
        destination.join(name); // hazard: captured-alias
    }
}
fn neutral_zip(item: &zip::read::ZipFile<'_>, destination: &Path) {
    destination.join(item.name()); // hazard: typed-neutral-zip
}
fn neutral_tar(item: &mut tar::Entry<'_, std::fs::File>, destination: &mut PathBuf) {
    destination.push(item.path()?); // hazard: typed-neutral-tar
}
fn collection_name_is_not_a_type(zip_entry: &ZipFile) {
    let mut paths: PathBuf = PathBuf::new();
    paths.push(zip_entry.name()); // hazard: path-named-like-collection
}
fn destination_shadow(zip_entry: &ZipFile) {
    let mut paths: Vec<PathBuf> = Vec::new();
    paths.push(PathBuf::from(zip_entry.name()));
    {
        let mut paths = PathBuf::new();
        paths.push(zip_entry.name()); // hazard: pathbuf-shadows-vector
    }
    paths.push(PathBuf::from(zip_entry.name()));
}
fn source_shadow(entry: std::fs::DirEntry, archive: &mut ZipArchive, destination: &Path) {
    destination.join(entry.path());
    {
        let entry: zip::read::ZipFile<'_> = archive.by_index(0).unwrap();
        destination.join(entry.name()); // hazard: archive-shadows-directory-entry
    }
    destination.join(entry.path());
}
'''

    SCOPES = '''use std::path::Path;
fn tainted_name(zip_entry: &ZipFile, destination: &Path) {
    let name = zip_entry.name();
    destination.join(name); // hazard: function-local-alias
}
fn other_function(name: &str, destination: &Path) {
    destination.join(name);
}
fn lexical_scopes(zip_entry: &ZipFile, destination: &Path) {
    let name = "fixed.txt";
    {
        let name = zip_entry.name();
        destination.join(name); // hazard: inner-alias
        {
            destination.join(name); // hazard: nested-capture
        }
    }
    destination.join(name);
    let name = zip_entry.name();
    destination.join(name); // hazard: before-clean-shadow
    let name = "another-fixed.txt";
    destination.join(name);
}
fn markers(zip_entry: &ZipFile, destination: &Path) {
    destination.join(zip_entry.name()); // ubs:ignore[rust.security.archive-entry-path]
    destination.join(zip_entry.name()); // ubs:ignore
    destination.join(zip_entry.name()); // ubs:ignore[rust.security.other] hazard: wrong-scope
}
'''

    PATTERN_SHADOWS = '''use std::path::PathBuf;
trait ArchiveItem { fn name(&self) -> &str; }
fn if_let_shadow(zip_entry: &impl ArchiveItem, candidate: Option<PathBuf>) {
    let mut output: Vec<&str> = Vec::new();
    output.push(zip_entry.name());
    if let Some(mut output) = candidate {
        output.push(zip_entry.name()); // hazard: if-let-pathbuf
    }
    output.push(zip_entry.name());
}
fn while_let_shadow(zip_entry: &impl ArchiveItem, mut candidates: Vec<PathBuf>) {
    let mut output: Vec<&str> = Vec::new();
    while let Some(mut output) = candidates.pop() {
        output.push(zip_entry.name()); // hazard: while-let-pathbuf
    }
    output.push(zip_entry.name());
}
fn match_shadow(zip_entry: &impl ArchiveItem, candidate: Option<PathBuf>) {
    let mut output: Vec<&str> = Vec::new();
    match candidate {
        Some(mut output) => {
            output.push(zip_entry.name()); // hazard: match-pathbuf
        }
        None => {}
    }
    output.push(zip_entry.name());
}
fn closure_shadow(zip_entry: &impl ArchiveItem) {
    let mut output: Vec<&str> = Vec::new();
    let append = |mut output: PathBuf| output.push(zip_entry.name()); // hazard: braceless-pathbuf
    append(PathBuf::new());
    output.push(zip_entry.name());
}
fn collection_captures(zip_entry: &impl ArchiveItem, mut candidates: Vec<PathBuf>) {
    let mut output: Vec<&str> = Vec::new();
    if let Some(candidate) = candidates.pop() {
        output.push(zip_entry.name());
        drop(candidate);
    }
    while let Some(candidate) = candidates.pop() {
        output.push(zip_entry.name());
        drop(candidate);
    }
    match candidates.pop() {
        Some(candidate) => {
            output.push(zip_entry.name());
            drop(candidate);
        }
        None => {}
    }
    let mut append = || output.push(zip_entry.name());
    append();
}
'''

    CONDITIONAL_VALUES = '''use std::path::Path;
trait ArchiveItem { fn name(&self) -> &str; }
fn conditional_values(zip_entry: &impl ArchiveItem, destination: &Path, keep: bool) {
    let mut name = zip_entry.name();
    name = if keep { name } else { "fixed.txt" };
    destination.join(name); // hazard: if-value-retains-alias
    name = "unconditionally-fixed.txt";
    destination.join(name);
    let mut other = zip_entry.name();
    other = match keep {
        true => other,
        false => "another-fixed.txt",
    };
    destination.join(other); // hazard: match-value-retains-alias
    other = "unconditionally-fixed-again.txt";
    destination.join(other);
}
'''

    ITERATOR_OUTPUTS = '''use std::path::Path;
trait ArchiveItem { fn name(&self) -> &str; }
fn iterator_outputs<E: ArchiveItem>(
    root: &Path, destination: &Path, mut archive_entries: impl Iterator<Item = E>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)?.map_while(|_| archive_entries.next()) {
        destination.join(entry.name()); // hazard: direct-transform
    }
    let directory_entries = std::fs::read_dir(root)?;
    for entry in directory_entries.map_while(|_| archive_entries.next()) {
        destination.join(entry.name()); // hazard: named-iterator-transform
    }
    for entry in std::fs::read_dir(root)?.flatten() {
        destination.join(entry.path());
    }
    let directory_entries = std::fs::read_dir(root)?;
    for entry in directory_entries.flatten() {
        destination.join(entry.path());
    }
    Ok(())
}
fn let_else_directory_iterator(root: &Path, destination: &Path) {
    let Ok(iter) = std::fs::read_dir(root) else { return; };
    for entry in iter.flatten() {
        destination.join(entry.path());
    }
}
'''

    def assert_source_findings(self, source: str, labels: tuple[str, ...]) -> None:
        # Expected sites are independently marked in Rust source. Compare full
        # records as a multiset so duplicates cannot hide behind a set conversion.
        lines = source.splitlines()
        expected_lines = [
            number for number, line in enumerate(lines, 1)
            if any(f"hazard: {label}" in line for label in labels)
        ]
        self.assertEqual(len(expected_lines), len(labels))
        with tempfile.TemporaryDirectory(prefix="ubs-rust-archive-precision-") as tmp:
            path = Path(tmp) / "source.rs"
            path.write_text(source, encoding="utf-8")
            self.assertCountEqual(
                list(archive_entry_path.find([path])),
                [(path, line, 1, lines[line - 1].strip()) for line in expected_lines],
            )

    def test_cass_collection_and_directory_paths_are_not_archive_destinations(self) -> None:
        # These are the five CASS call flows, with one same-file archive alias
        # source to expose the former whole-file taint of `path`/`entry_path`.
        self.assert_source_findings(self.CASS_COLLECTIONS, ("archive-alias",))

    def test_archive_destinations_survive_types_captures_and_receiver_shadowing(self) -> None:
        self.assert_source_findings(self.POSITIVES, (
            "zip-direct", "tar-direct", "named-alias", "captured-alias",
            "typed-neutral-zip", "typed-neutral-tar", "path-named-like-collection",
            "pathbuf-shadows-vector", "archive-shadows-directory-entry",
        ))

    def test_alias_lifetimes_clean_shadows_and_exact_marker_scopes(self) -> None:
        self.assert_source_findings(self.SCOPES, (
            "function-local-alias", "inner-alias", "nested-capture",
            "before-clean-shadow", "wrong-scope",
        ))

    def test_pattern_and_braceless_closure_shadows_override_collection_safety(self) -> None:
        self.assert_source_findings(self.PATTERN_SHADOWS, (
            "if-let-pathbuf", "while-let-pathbuf", "match-pathbuf", "braceless-pathbuf",
        ))

    def test_conditional_rhs_retains_possible_alias_but_fixed_assignment_clears_it(self) -> None:
        self.assert_source_findings(self.CONDITIONAL_VALUES, (
            "if-value-retains-alias", "match-value-retains-alias",
        ))

    def test_transforming_iterators_are_not_directory_entry_proof(self) -> None:
        self.assert_source_findings(self.ITERATOR_OUTPUTS, (
            "direct-transform", "named-iterator-transform",
        ))

    def test_tuple_and_braceless_match_shadows_override_collection_safety(self) -> None:
        source = '''use std::path::PathBuf;
trait ArchiveItem { fn name(&self) -> &str; }
fn destructuring(zip_entry: &impl ArchiveItem, candidate: Option<PathBuf>) {
    let mut output: Vec<&str> = Vec::new();
    output.push(zip_entry.name());
    {
        let (mut output, _) = (PathBuf::new(), ());
        output.push(zip_entry.name()); // hazard: tuple-pathbuf
    }
    output.push(zip_entry.name());
    match candidate {
        Some(mut output) => output.push(zip_entry.name()), // hazard: braceless-match-pathbuf
        None => (),
    };
    output.push(zip_entry.name());
}
'''
        self.assert_source_findings(source, ("tuple-pathbuf", "braceless-match-pathbuf"))

    def test_collection_constructor_chain_must_prove_its_final_receiver_kind(self) -> None:
        source = '''use std::path::PathBuf;
trait ArchiveItem { fn name(&self) -> &str; }
fn constructor_chains(zip_entry: &impl ArchiveItem) {
    let mut output = vec![PathBuf::from("root")].into_iter().collect::<PathBuf>();
    output.push(zip_entry.name()); // hazard: collected-pathbuf
    let mut output = Vec::<&str>::new();
    output.push(zip_entry.name());
    let mut output = vec![zip_entry.name()];
    output.push(zip_entry.name());
    let mut append = || output.push(zip_entry.name());
    append();
}
'''
        self.assert_source_findings(source, ("collected-pathbuf",))

    def test_match_guards_preserve_captured_aliases_and_real_pattern_shadows(self) -> None:
        source = '''use std::path::{Path, PathBuf};
trait ArchiveItem { fn name(&self) -> &str; }
fn guarded_alias(zip_entry: &impl ArchiveItem, destination: &Path) {
    let name = zip_entry.name();
    match true {
        true if !name.is_empty() => {
            destination.join(name); // hazard: braced-guard-capture
        }
        _ => {}
    }
    let _ = match true {
        true if !name.is_empty() => destination.join(name), // hazard: braceless-guard-capture
        _ => PathBuf::new(),
    };
    match Some("fixed.txt") {
        Some(name) if !name.is_empty() => {
            destination.join(name);
        }
        _ => {}
    }
    let _ = match Some("another-fixed.txt") {
        Some(name) if !name.is_empty() => destination.join(name),
        _ => PathBuf::new(),
    };
    destination.join(name); // hazard: alias-after-guarded-shadows
}
'''
        self.assert_source_findings(source, (
            "braced-guard-capture", "braceless-guard-capture",
            "alias-after-guarded-shadows",
        ))

    def test_tuple_for_bindings_shadow_only_the_inner_collection_receiver(self) -> None:
        source = '''use std::path::PathBuf;
trait ArchiveItem { fn name(&self) -> &str; }
fn enumerated_paths(zip_entry: &impl ArchiveItem, candidates: Vec<PathBuf>) {
    let mut output: Vec<&str> = Vec::new();
    output.push(zip_entry.name());
    for (_index, mut output) in candidates.into_iter().enumerate() {
        output.push(zip_entry.name()); // hazard: enumerated-pathbuf
    }
    output.push(zip_entry.name());
    for (index, candidate) in [PathBuf::new()].into_iter().enumerate() {
        output.push(zip_entry.name());
        drop((index, candidate));
    }
}
'''
        self.assert_source_findings(source, ("enumerated-pathbuf",))

    def test_nested_vec_type_does_not_exempt_path_writing_wrappers(self) -> None:
        source = '''use std::marker::PhantomData;
use std::path::PathBuf;
trait ArchiveItem { fn name(&self) -> &str; }
struct Destination<T> {
    path: PathBuf,
    tag: PhantomData<T>,
}
impl<T> Destination<T> {
    fn push(&mut self, value: &str) {
        self.path.push(value);
    }
}
fn wrapped_parameter(zip_entry: &impl ArchiveItem, output: &mut Destination<Vec<u8>>) {
    output.push(zip_entry.name()); // hazard: nested-vec-parameter
}
fn wrapped_local(zip_entry: &impl ArchiveItem) {
    let mut output: Destination<Vec<u8>> = Destination {
        path: PathBuf::new(),
        tag: PhantomData,
    };
    output.push(zip_entry.name()); // hazard: nested-vec-local
}
fn owned_vector<'a>(zip_entry: &'a impl ArchiveItem, mut output: Vec<&'a str>) {
    output.push(zip_entry.name());
}
fn borrowed_vector<'a>(zip_entry: &'a impl ArchiveItem, output: &mut Vec<&'a str>) {
    output.push(zip_entry.name());
}
fn qualified_borrowed_vector<'a>(
    zip_entry: &'a impl ArchiveItem, output: &mut std::vec::Vec<&'a str>,
) {
    output.push(zip_entry.name());
}
'''
        self.assert_source_findings(source, ("nested-vec-parameter", "nested-vec-local"))

    def test_long_masked_literal_and_whitespace_cannot_stall_match_arm_detection(self) -> None:
        # A failed arrow search after this comma previously explored overlapping
        # whitespace/capture partitions. Keep a real sink after the long span so
        # returning early without scanning the rest of the source cannot pass.
        source = "\n".join([
            "fn ordinary() {",
            '    let _ = ("' + "ordinary diagnostic text " * 2048 + '",',
            " " * 32768 + "1usize);",
            "}",
            "fn extract(zip_entry: &ZipFile, destination: &Path) {",
            "    destination.join(zip_entry.name());",
            "}",
        ])
        program = """import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from ubs_core.rust_detectors.archive_entry_path import find
records = [[str(path), line, col, code] for path, line, col, code in find([Path(sys.argv[2])])]
print(json.dumps(records))
"""
        with tempfile.TemporaryDirectory(prefix="ubs-rust-archive-bounded-") as tmp:
            path = Path(tmp) / "long_source.rs"
            path.write_text(source, encoding="utf-8")
            command = [sys.executable, "-I", "-B", "-c", program, str(HELPERS_DIR), str(path)]
            try:
                proc = subprocess.run(
                    command, cwd=tmp, text=True, capture_output=True, timeout=10,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "archive detector exceeded the 10-second liveness bound; "
                    f"stdout={error.stdout!r}, stderr={error.stderr!r}"
                )
            context = f"exit={proc.returncode}, stdout={proc.stdout!r}, stderr={proc.stderr!r}"
            self.assertEqual(proc.returncode, 0, context)
            try:
                records = json.loads(proc.stdout)
            except json.JSONDecodeError as error:
                self.fail(f"invalid archive detector record JSON: {error}; {context}")
            self.assertEqual(
                records,
                [[str(path), 6, 1, "destination.join(zip_entry.name());"]],
                context,
            )

    def test_source_replacement_and_file_order_do_not_reuse_archive_bindings(self) -> None:
        tainted = """fn extract(zip_entry: &ZipFile, destination: &Path) {
    let path = zip_entry.name();
    destination.join(path);
}
"""
        clean = """fn fixture(destination: &Path) {
    let path = PathBuf::from("fixture.json");
    destination.join(path);
}
"""
        with tempfile.TemporaryDirectory(prefix="ubs-rust-archive-isolation-") as tmp:
            first, second = Path(tmp) / "first.rs", Path(tmp) / "second.rs"
            first.write_text(tainted, encoding="utf-8")
            second.write_text(clean, encoding="utf-8")
            expected = [(first, 3, 1, "destination.join(path);")]
            self.assertEqual(list(archive_entry_path.find([first, second])), expected)
            self.assertEqual(list(archive_entry_path.find([second, first])), expected)
            first.write_text(clean, encoding="utf-8")
            self.assertEqual(list(archive_entry_path.find([first, second])), [])
            first.write_text(tainted, encoding="utf-8")
            self.assertEqual(list(archive_entry_path.find([first])), expected)


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
    let token = fastrand::u64(..);
    let token = fastrand::u64(..); // ubs:ignore
    // ubs:ignore
    let token = fastrand::u64(..);
}
fn doc() {
    let text = "token fastrand::u64(..) // literal";
}
fn csrf_nonce() {
    let nonce = fastrand::u64(
        ..);
}
fn unrelated() {
    let number = fastrand::u64(..);
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


class CSharpSecuritySuppressionTests(unittest.TestCase):
    CASES = (
        (cs_archive, 'ZipArchive archive;\nvar target = Path.Combine(destination, entry.FullName);\n',
         'ZipArchive archive;\nvar target = SafeArchivePath(destination, entry.FullName);\n'),
        (cs_header, 'var name = Request.Query["name"];\nResponse.Headers.Append("X-Name", name);\n',
         'var name = Request.Query["name"];\nResponse.Headers.Append("X-Name", Uri.EscapeDataString(name));\n'),
        (cs_outbound, 'var url = Request.Query["url"];\nawait client.GetAsync(url);\n',
         'var url = Request.Query["url"];\nawait client.GetAsync(SafeOutboundUrl(url));\n'),
        (cs_random, 'var rng = new Random();\nvar authToken = rng.Next();\n',
         'var authToken = RandomNumberGenerator.GetBytes(32);\n'),
    )

    def findings(self, detector, text):
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="ubs-csharp-ownership-", dir=artifacts) as tmp:
            source = Path(tmp) / "Ownership.cs"
            source.write_text(text, encoding="utf-8")
            rows = list(detector.find([source], base_dir=source.parent))
            self.assertTrue(all(row[0] == "Ownership.cs" and row[2] == 1 for row in rows), rows)
            return rows

    def test_exact_sink_scope_and_lexical_marker_ownership(self):
        for detector, positive, safe in self.CASES:
            rule = detector.RULE_ID
            lines = positive.splitlines(keepends=True)
            variants = (
                ("unmarked", positive, [2]),
                ("safe", safe, []),
                ("owned", lines[0] + lines[1].rstrip() + f" // ubs:ignore[{rule}]\n", []),
                ("bare", lines[0] + lines[1].rstrip() + " // ubs:ignore\n", []),
                ("wrong", lines[0] + lines[1].rstrip() + " // ubs:ignore[csharp.other.rule]\n", [2]),
                ("quoted", lines[0] + lines[1].rstrip() + f' var example = "ubs:ignore[{rule}]";\n', [2]),
                ("preceding-owned", lines[0] + f"// ubs:ignore[{rule}]\n" + lines[1], []),
                ("preceding-wrong", lines[0] + "// ubs:ignore[csharp.other.rule]\n" + lines[1], [3]),
            )
            for name, text, expected in variants:
                with self.subTest(rule=rule, placement=name):
                    self.assertEqual([row[1] for row in self.findings(detector, text)], expected)

    def test_annotated_source_and_alias_facts_reach_later_sink(self):
        for detector, positive, _ in self.CASES[1:]:
            source, sink = positive.splitlines(keepends=True)
            for marker in ("ubs:ignore", f"ubs:ignore[{detector.RULE_ID}]", "ubs:ignore[csharp.other.rule]"):
                with self.subTest(rule=detector.RULE_ID, source_marker=marker):
                    text = source.rstrip() + f" // {marker}\nConsole.WriteLine(0);\n" + sink
                    self.assertEqual([row[1] for row in self.findings(detector, text)], [3])
            with self.subTest(rule=detector.RULE_ID, source_marker="quoted"):
                text = source.rstrip() + f' var example = "ubs:ignore[{detector.RULE_ID}]";\nConsole.WriteLine(0);\n' + sink
                self.assertEqual([row[1] for row in self.findings(detector, text)], [3])
        for detector, source, transfer, sink in (
            (cs_header, 'var name = Request.Query["name"];\n', 'var alias = name;\n', 'Response.Headers.Append("X-Name", alias);\n'),
            (cs_outbound, 'var url = Request.Query["url"];\n', 'var target = url;\n', 'await client.GetAsync(target);\n'),
        ):
            for marker in ("", f" // ubs:ignore[{detector.RULE_ID}]", " // ubs:ignore[csharp.other.rule]"):
                with self.subTest(rule=detector.RULE_ID, alias_marker=marker):
                    text = source + transfer.rstrip() + marker + "\nConsole.WriteLine(0);\n" + sink
                    self.assertEqual([row[1] for row in self.findings(detector, text)], [4])


if __name__ == "__main__":
    unittest.main()
