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


if __name__ == "__main__":
    unittest.main()
