#!/usr/bin/env python3
"""Cargo integration-test context survives targeted multi-file scans (GH #152).

`ubs tests/a.rs` scans the file in place, so `cargo_integration_test_root`
finds the crate's Cargo.toml and reports `panic!` there as a warning.
`ubs tests/a.rs tests/b.rs` scans copies in a shadow workspace that has no
Cargo.toml; the same files used to be classified as library code (critical).
The meta-runner now exports where the workspace came from and the Rust scanner
judges manifest context at the real location.
"""
from __future__ import annotations

import json
import os
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

from ubs_core.rust_scan import (  # noqa: E402
    cargo_audit_counts,
    cargo_diagnostic_counts,
    cargo_project_in_context,
    integration_test_root_in_context,
    shadow_source_path,
)

MANIFEST = '[package]\nname = "ubs-repro"\nversion = "0.0.1"\nedition = "2021"\n\n[dependencies]\n'
TEST_SOURCE = (
    "fn must_be_even(value: u32) -> u32 {{\n"
    "    if value % 2 != 0 {{\n"
    '        panic!("expected an even value, got {{value}}");\n'
    "    }}\n"
    "    value\n"
    "}}\n"
    "\n"
    "#[test]\n"
    "fn adds_{name}() {{\n"
    "    assert_eq!(must_be_even(ubs_repro::add(2, 2)), 4);\n"
    "}}\n"
)
PROD_SOURCE = (
    "pub fn add(a: u32, b: u32) -> u32 {\n"
    "    if a > 100 {\n"
    '        panic!("too large");\n'
    "    }\n"
    "    a + b\n"
    "}\n"
)


def make_crate(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
    (root / "src" / "lib.rs").write_text(PROD_SOURCE, encoding="utf-8")
    for name in ("a", "b"):
        (root / "tests" / f"{name}.rs").write_text(TEST_SOURCE.format(name=name), encoding="utf-8")


class ShadowSourcePathTests(unittest.TestCase):
    def test_selected_cargo_manifest_requires_matching_original_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-cargo-context-") as tmp:
            base = Path(tmp).resolve()
            source, shadow = base / "source", base / "shadow"
            source.mkdir()
            shadow.mkdir()
            for root in (source, shadow):
                (root / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
                (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            env = {"UBS_SHADOW_WORKSPACE_DIR": str(shadow), "UBS_SHADOW_SOURCE_DIR": str(source)}
            self.assertEqual(cargo_project_in_context(source, {}), source)
            self.assertEqual(cargo_project_in_context(shadow, env), source)
            with self.assertRaisesRegex(ValueError, "no original source mapping"):
                cargo_project_in_context(base / "shadow-other", env)
            (source / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Cargo.lock differs"):
                cargo_project_in_context(shadow, env)
            (source / "Cargo.toml").write_text(MANIFEST + "# changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Cargo.toml differs"):
                cargo_project_in_context(shadow, env)

    def test_successful_cargo_discovery_diagnostics_remain_visible(self) -> None:
        text = "error: unclosed table, expected `]`\nwarning: ordinary warning\n"
        self.assertEqual(cargo_diagnostic_counts(text, 0), (2, 0))
        self.assertEqual(cargo_diagnostic_counts(text, 101), (1, 1))
        self.assertEqual(cargo_diagnostic_counts(text, None), (1, 1))

    def test_coded_errors_still_block_even_a_contradictory_zero_exit(self) -> None:
        text = ("\x1b[1m\x1b[91merror[E0308]\x1b[0m\x1b[1m: mismatched types\x1b[0m\n"
                "error: could not compile example\nwarning: build failed\n")
        self.assertEqual(cargo_diagnostic_counts(text, 101), (1, 2))
        self.assertEqual(cargo_diagnostic_counts(text, 0), (2, 1))
        self.assertEqual(cargo_diagnostic_counts("", 0), (0, 0))

    @staticmethod
    def audit_report() -> dict:
        return {"settings": {"target_arch": [], "target_os": [], "severity": None, "ignore": [],
                             "informational_warnings": ["unmaintained", "unsound", "notice"]},
                "vulnerabilities": {"found": False, "count": 0, "list": []},
                "warnings": {"unmaintained": [{"kind": "unmaintained",
                    "package": {"name": "paste", "version": "1.0.15"},
                    "advisory": {"id": "RUSTSEC-2024-0436", "informational": "unmaintained"}}],
                    "yanked": [{"kind": "yanked", "package": {"name": "chacha20", "version": "0.10.1"},
                                "advisory": None}]}}

    def test_native_audit_informational_notices_remain_warnings(self) -> None:
        result = cargo_audit_counts(self.audit_report())
        self.assertEqual((result["critical"], result["warning"]), (0, 2))
        self.assertIn("RUSTSEC-2024-0436", result["details"])
        self.assertIn("yanked: chacha20 0.10.1", result["details"])

    def test_audit_vulnerabilities_and_unsoundness_remain_critical(self) -> None:
        report = self.audit_report()
        report["vulnerabilities"] = {"found": True, "count": 1, "list": [{"advisory": {"id": "RUSTSEC-2000-0001"}}]}
        report["warnings"]["unsound"] = [{"kind": "unsound", "package": {"name": "example", "version": "1.0.0"},
                                          "advisory": {"id": "RUSTSEC-2000-0002", "informational": "unsound"}}]
        result = cargo_audit_counts(report)
        self.assertEqual((result["critical"], result["warning"]), (2, 2))

    def test_unknown_ignored_and_contradictory_audits_cannot_report_clean(self) -> None:
        cases = []
        for key, value in (("severity", "critical"), ("target_os", ["linux"]),
                           ("target_arch", ["x86_64"]), ("future_filter", True),
                           ("informational_warnings", ["unmaintained", "notice"]),
                           ("informational_warnings", ["unmaintained", "unsound", {}])):
            report = self.audit_report()
            report["settings"][key] = value
            cases.append(report)
        report = self.audit_report()
        report["settings"].pop("severity")
        cases.append(report)
        report = self.audit_report()
        report["settings"]["ignore"] = ["RUSTSEC-2000-0001"]
        cases.append(report)
        report = self.audit_report()
        report["warnings"]["unknown"] = []
        cases.append(report)
        report = self.audit_report()
        report["vulnerabilities"]["count"] = True
        cases.append(report)
        report = self.audit_report()
        report["vulnerabilities"]["found"] = True
        cases.append(report)
        report = self.audit_report()
        report["warnings"]["unmaintained"][0]["advisory"]["informational"] = "unsound"
        cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                cargo_audit_counts(report)

    def test_maps_workspace_copy_to_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-shadow-map-") as tmp:
            base = Path(tmp).resolve()
            crate, shadow = base / "crate", base / "shadow"
            make_crate(crate)
            (shadow / "tests").mkdir(parents=True)
            copy = shadow / "tests" / "a.rs"
            copy.write_text((crate / "tests" / "a.rs").read_text(), encoding="utf-8")
            env = {"UBS_SHADOW_WORKSPACE_DIR": str(shadow), "UBS_SHADOW_SOURCE_DIR": str(crate)}

            self.assertEqual(shadow_source_path(copy, env), crate / "tests" / "a.rs")
            self.assertTrue(integration_test_root_in_context(copy, env))
            # Without the context the copy has no manifest and stays production.
            self.assertFalse(integration_test_root_in_context(copy, {}))
            # A path outside the workspace, or a sibling sharing its prefix, maps to nothing.
            self.assertIsNone(shadow_source_path(crate / "tests" / "a.rs", env))
            self.assertIsNone(shadow_source_path(base / "shadow-other" / "tests" / "a.rs", env))

    def test_symlinked_workspace_spelling_and_mirror_map(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-shadow-mirror-") as tmp:
            base = Path(tmp).resolve()
            project, external = base / "project", base / "elsewhere" / "crate"
            project.mkdir()
            make_crate(external)
            real_ws = base / "real-ws"
            mirror = real_ws / str(external / "tests").lstrip("/")
            mirror.mkdir(parents=True)
            copy = mirror / "b.rs"
            copy.write_text((external / "tests" / "b.rs").read_text(), encoding="utf-8")
            linked_ws = base / "linked-ws"
            linked_ws.symlink_to(real_ws, target_is_directory=True)
            mirror_map = base / "mirror.0"
            mirror_map.write_text(f"{linked_ws / str(external / 'tests').lstrip('/')}\0{external / 'tests'}\0",
                                  encoding="utf-8")
            env = {"UBS_SHADOW_WORKSPACE_DIR": str(linked_ws), "UBS_SHADOW_SOURCE_DIR": str(project),
                   "UBS_WORKSPACE_MIRROR_MAP": str(mirror_map)}

            # The scanner may see the resolved spelling of a symlinked workspace.
            self.assertEqual(shadow_source_path(copy, env), external / "tests" / "b.rs")
            self.assertTrue(integration_test_root_in_context(copy, env))

    def test_production_source_and_custom_test_targets_stay_production(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-shadow-neg-") as tmp:
            base = Path(tmp).resolve()
            crate, shadow = base / "crate", base / "shadow"
            make_crate(crate)
            (shadow / "src").mkdir(parents=True)
            (shadow / "tests").mkdir()
            lib_copy = shadow / "src" / "lib.rs"
            lib_copy.write_text(PROD_SOURCE, encoding="utf-8")
            test_copy = shadow / "tests" / "a.rs"
            test_copy.write_text("", encoding="utf-8")
            env = {"UBS_SHADOW_WORKSPACE_DIR": str(shadow), "UBS_SHADOW_SOURCE_DIR": str(crate)}
            self.assertFalse(integration_test_root_in_context(lib_copy, env))
            # Explicit [[test]] configuration is not default autodiscovery.
            (crate / "Cargo.toml").write_text(MANIFEST + '\n[[test]]\nname = "a"\npath = "tests/a.rs"\n',
                                              encoding="utf-8")
            self.assertFalse(integration_test_root_in_context(test_copy, env))


class TargetedScanClassificationTests(unittest.TestCase):
    def scan(self, crate: Path, *targets: str) -> tuple[int, dict]:
        env = {**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1", "NO_COLOR": "1"}
        result = subprocess.run(
            [str(REPO_ROOT / "ubs"), *targets, "--only=rust", "--no-cargo", "--format=json", "--ci"],
            cwd=crate, capture_output=True, text=True, env=env, timeout=600,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode, json.loads(result.stdout)

    @staticmethod
    def panic_severities(report: dict) -> dict[tuple[str, int], str]:
        return {
            (Path(f["file"]).name if Path(f["file"]).parent.name != "src" else "src/" + Path(f["file"]).name,
             f["line"]): f["severity"]
            for f in report.get("findings", [])
            if f.get("rule_id") == "rust.ownership.panic-macro"
        }

    def test_multi_file_scan_matches_single_file_scans(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-gh152-") as tmp:
            crate = Path(tmp).resolve() / "crate"
            make_crate(crate)
            single = {}
            for target in ("tests/a.rs", "tests/b.rs"):
                _, report = self.scan(crate, target)
                single.update(self.panic_severities(report))
            code, multi_report = self.scan(crate, "tests/a.rs", "tests/b.rs")
            multi = self.panic_severities(multi_report)

            self.assertEqual(single, {("a.rs", 3): "warning", ("b.rs", 3): "warning"}, single)
            self.assertEqual(multi, single, multi_report.get("findings"))
            self.assertEqual(multi_report["totals"]["critical"], 0, multi_report.get("findings"))
            self.assertEqual(code, 0)

            # Positive control: production source in the same targeted scan stays critical.
            code, mixed = self.scan(crate, "tests/a.rs", "src/lib.rs")
            severities = self.panic_severities(mixed)
            self.assertEqual(severities.get(("src/lib.rs", 3)), "critical", mixed.get("findings"))
            self.assertEqual(severities.get(("a.rs", 3)), "warning", mixed.get("findings"))
            self.assertEqual(code, 1)


@unittest.skipUnless(all(shutil.which(tool) for tool in ("cargo", "cargo-clippy", "rustfmt")),
                     "real Cargo, Clippy and rustfmt are required")
class TargetedCargoExecutionTests(unittest.TestCase):
    def make_workspace(self, root: Path) -> None:
        (root / "inner" / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text('[workspace]\nmembers = ["inner"]\nresolver = "3"\n', encoding="utf-8")
        (root / "inner" / "Cargo.toml").write_text(
            '[package]\nname = "ubs-context-witness"\nversion = "0.1.0"\nedition = "2024"\n', encoding="utf-8")
        (root / "inner" / "src" / "lib.rs").write_text(
            '#![forbid(unsafe_code)]\n\npub fn answer() -> u32 {\n    42\n}\n', encoding="utf-8")

    def cargo(self, root: Path, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target"),
               "CARGO_BUILD_BUILD_DIR": str(root / "target")}
        return subprocess.run(["cargo", *args], cwd=root, env=env, capture_output=True, text=True, timeout=180)

    def scan(self, root: Path, fmt: str = "json") -> subprocess.CompletedProcess:
        env = {**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1", "NO_COLOR": "1",
               "CARGO_TARGET_DIR": str(root / "target"), "CARGO_BUILD_BUILD_DIR": str(root / "target")}
        return subprocess.run(
            [str(REPO_ROOT / "ubs"), "--ci", f"--format={fmt}", "Cargo.toml", "Cargo.lock", "inner/src/lib.rs"],
            cwd=root, env=env, capture_output=True, text=True, timeout=600)

    def test_selected_manifest_runs_real_cargo_in_complete_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-real-cargo-context-") as tmp:
            root = Path(tmp).resolve()
            self.make_workspace(root)
            for args in (("fmt", "--check"), ("clippy", "--", "-D", "warnings"), ("test",)):
                native = self.cargo(root, *args)
                self.assertEqual(native.returncode, 0, native.stderr)
            for fmt in ("json", "sarif"):
                result = self.scan(root, fmt)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                if fmt == "json":
                    self.assertEqual(report["status"], "ok")
                    self.assertEqual(report["failed_modules"], [])
                    self.assertEqual(report["totals"]["critical"], 0)
                else:
                    self.assertEqual(len(report["runs"]), 1)
                    self.assertFalse(any(item.get("level") == "error" for item in report["runs"][0]["results"]))

    def test_unselected_module_compiler_failure_stays_critical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-real-cargo-error-") as tmp:
            root = Path(tmp).resolve()
            self.make_workspace(root)
            (root / "inner" / "src" / "lib.rs").write_text(
                '#![forbid(unsafe_code)]\n\npub mod broken;\n', encoding="utf-8")
            (root / "inner" / "src" / "broken.rs").write_text(
                'pub fn broken() -> u32 {\n    "not a number"\n}\n', encoding="utf-8")
            native = self.cargo(root, "clippy", "--", "-D", "warnings")
            self.assertEqual(native.returncode, 101, native.stderr)
            self.assertIn("E0308", native.stderr)
            result = self.scan(root)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["failed_modules"], [])
            self.assertTrue(any(f["rule_id"] == "rust.lints.phase" and f["severity"] == "critical"
                                for f in report["findings"]), report.get("findings"))

    def make_git_dependency_with_negative_manifest(self, root: Path) -> None:
        self.make_workspace(root)
        upstream = root / "diagnostic-upstream"
        (upstream / "src").mkdir(parents=True)
        (upstream / "tests" / "fixtures" / "malformed").mkdir(parents=True)
        (upstream / "Cargo.toml").write_text(
            '[package]\nname = "ubs-cargo-diagnostic-fixture"\nversion = "0.1.0"\nedition = "2024"\n\n[workspace]\n',
            encoding="utf-8")
        (upstream / "src" / "lib.rs").write_text(
            "pub fn answer() -> u32 {\n    42\n}\n", encoding="utf-8")
        (upstream / "tests" / "fixtures" / "malformed" / "Cargo.toml").write_text(
            "[package\n", encoding="utf-8")
        for args in (
            ["init", "--quiet", "--initial-branch=main"],
            ["add", "Cargo.toml", "src/lib.rs", "tests/fixtures/malformed/Cargo.toml"],
            ["-c", "user.name=UBS fixture", "-c", "user.email=ubs-fixture@example.invalid",
             "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Cargo discovery fixture"],
        ):
            subprocess.run(["git", *args], cwd=upstream, check=True, capture_output=True, text=True)
        manifest = root / "inner" / "Cargo.toml"
        manifest.write_text(manifest.read_text(encoding="utf-8") +
            '\n[dependencies]\nubs-cargo-diagnostic-fixture = { git = ' +
            json.dumps(upstream.as_uri()) + " }\n", encoding="utf-8")
        (root / "inner" / "src" / "lib.rs").write_text(
            "pub fn answer() -> u32 {\n    ubs_cargo_diagnostic_fixture::answer()\n}\n",
            encoding="utf-8")

    def test_successful_git_package_discovery_errors_are_visible_warnings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-native-git-discovery-") as tmp:
            root = Path(tmp).resolve()
            self.make_git_dependency_with_negative_manifest(root)
            for args in (("clippy", "--", "-D", "warnings"), ("check",), ("test", "--no-run")):
                native = self.cargo(root, *args)
                self.assertEqual(native.returncode, 0, native.stderr)
                self.assertIn("error", native.stderr)
                self.assertIn("malformed/Cargo.toml", native.stderr)
            for fmt in ("json", "sarif"):
                result = self.scan(root, fmt)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                report = json.loads(result.stdout)
                if fmt == "json":
                    self.assertEqual(report["status"], "ok")
                    self.assertEqual(report["failed_modules"], [])
                    self.assertEqual(report["totals"]["critical"], 0)
                    self.assertGreaterEqual(report["totals"]["warning"], 3)
                else:
                    self.assertFalse(any(r.get("level") == "error" for r in report["runs"][0]["results"]))
                    self.assertTrue(any(r.get("level") == "warning" for r in report["runs"][0]["results"]))


if __name__ == "__main__":
    unittest.main()
