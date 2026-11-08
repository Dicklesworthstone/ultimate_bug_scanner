#!/usr/bin/env python3
"""Qualify complete unsigned candidates without executing or publishing them."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/build_release_candidate.py"
SPEC = importlib.util.spec_from_file_location("build_release_candidate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
candidate = importlib.util.module_from_spec(SPEC)
with mock.patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
    SPEC.loader.exec_module(candidate)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ubs-release-candidate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "candidate"
        self.version = (ROOT / "VERSION").read_text().strip()
        self.manifest = candidate.generation.parse_manifest((ROOT / "ubs").read_bytes())
        names = set(candidate.FLAT_PAYLOAD.values()) | {
            "VERSION", "README.md", "SHA256SUMS", "scripts/release_generation.py",
        } | {"modules/" + name for name in self.manifest.assets}
        for name in names:
            destination = self.source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.helper = next(name for name in self.manifest.assets if name.startswith("helpers/"))
        self.module = next(name for name in self.manifest.assets if re.fullmatch(r"ubs-[a-z]+\.sh", name))

    def build(self) -> dict[str, object]:
        return candidate.build_candidate(self.source, self.version, self.output)

    def assert_rejected(self, message: str) -> None:
        with self.assertRaisesRegex(candidate.CandidateError, message):
            self.build()
        self.assertFalse(self.output.exists(), "preflight failure must not create a candidate directory")

    def refresh_source_sums(self) -> None:
        (self.source / "SHA256SUMS").write_text("".join(
            f"{sha256(self.source / name)}  {name}\n" for name in sorted(candidate.SOURCE_CHECKSUM_ASSETS)
        ))

    def repin(self, relative: str) -> None:
        """Change the outer pin so tests can reach nested consistency checks."""
        runner_path = self.source / "ubs"
        runner = runner_path.read_text()
        manifest = candidate.generation.parse_manifest(runner.encode())
        key = f"[{relative[4:-3]}]" if re.fullmatch(r"ubs-[a-z]+\.sh", relative) else f"['{relative}']"
        old = f"{key}='{manifest.assets[relative]}'"
        new = f"{key}='{sha256(self.source / 'modules' / relative)}'"
        self.assertEqual(runner.count(old), 1)
        runner_path.write_text(runner.replace(old, new, 1))

    def test_current_tree_builds_complete_unsigned_payload_without_source_changes(self) -> None:
        before = {str(path.relative_to(self.source)): sha256(path)
                  for path in self.source.rglob("*") if path.is_file()}
        report = self.build()
        self.assertEqual(report["status"], "unsigned")
        self.assertEqual(report["version"], self.version)
        self.assertEqual(report["runtime_assets"], len(self.manifest.assets))
        self.assertEqual(report["runner_sha256"], sha256(ROOT / "ubs"))
        expected = set(candidate.FLAT_PAYLOAD) | {"SHA256SUMS", "VERSION"} | {
            "modules/" + name for name in self.manifest.assets
        }
        self.assertEqual({path.relative_to(self.output).as_posix()
                          for path in self.output.rglob("*") if path.is_file()}, expected)
        for name, relative in candidate.FLAT_PAYLOAD.items():
            self.assertEqual((self.output / name).read_bytes(), (ROOT / relative).read_bytes())
        for name, pin in self.manifest.assets.items():
            self.assertEqual(sha256(self.output / "modules" / name), pin, name)
        sums = dict(line.split("  ", 1)[::-1] for line in (self.output / "SHA256SUMS").read_text().splitlines())
        self.assertEqual(set(sums), set(candidate.FLAT_PAYLOAD))
        for name, pin in sums.items():
            self.assertEqual(sha256(self.output / name), pin)
        self.assertEqual(report["sha256sums_sha256"], sha256(self.output / "SHA256SUMS"))
        self.assertEqual(before, {str(path.relative_to(self.source)): sha256(path)
                                  for path in self.source.rglob("*") if path.is_file()})

    def test_cli_reports_unsigned_candidate_and_refuses_reuse(self) -> None:
        command = [sys.executable, str(SCRIPT), "--version", self.version, "--output", str(self.output)]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"candidate emitted invalid JSON: {exc}: {result.stdout}")
        self.assertEqual(report["status"], "unsigned")
        self.assertEqual((self.output / "VERSION").read_bytes(), (ROOT / "VERSION").read_bytes())
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("output already exists", result.stderr)

    def test_requires_one_literal_supported_generation_marker(self) -> None:
        original = (self.source / "ubs").read_bytes()
        for replacement in (b"", b"UBS_RELEASE_GENERATIONS=0\n", b'UBS_RELEASE_GENERATIONS="1"\n',
                            b"UBS_RELEASE_GENERATIONS=1 \n",
                            b"UBS_RELEASE_GENERATIONS=1\nUBS_RELEASE_GENERATIONS=1\n",
                            b"UBS_RELEASE_GENERATIONS=1\nUBS_RELEASE_GENERATIONS=0\n"):
            with self.subTest(declaration=replacement):
                (self.source / "ubs").write_bytes(original.replace(b"UBS_RELEASE_GENERATIONS=1\n", replacement))
                self.refresh_source_sums()
                self.assert_rejected("exactly one literal UBS_RELEASE_GENERATIONS=1")

    def test_requested_version_must_match_source(self) -> None:
        self.version = "0.0.1"
        self.assert_rejected("VERSION does not match")

    def test_prerelease_version_is_rejected_before_assembly(self) -> None:
        self.version += "-rc1"
        self.assert_rejected("generation protocol requires a stable version")

    def test_runner_version_must_match_source(self) -> None:
        path = self.source / "ubs"
        path.write_text(path.read_text().replace(f'UBS_VERSION="{self.version}"', 'UBS_VERSION="0.0.1"', 1))
        self.refresh_source_sums()
        self.assert_rejected("UBS_VERSION does not match")

    def test_readme_version_must_match_source(self) -> None:
        path = self.source / "README.md"
        path.write_text(path.read_text().replace(f"version-{self.version}-blue.svg", "version-0.0.1-blue.svg"))
        self.assert_rejected("README version badge")

    def test_embedded_helper_must_match_reviewed_source(self) -> None:
        path = self.source / "scripts/release_generation.py"
        path.write_bytes(path.read_bytes() + b"\n# source changed without re-embedding\n")
        self.assert_rejected("embedded generation helper differs")

    def test_runtime_changes_require_matching_runner_pins(self) -> None:
        for name in (self.module, self.helper, "lib/ubs-common.sh"):
            path = self.source / "modules" / name
            original = path.read_bytes()
            with self.subTest(asset=name):
                path.write_bytes(original + b"\n# changed after release pins were computed\n")
                self.assert_rejected("checksum mismatch for modules/" + re.escape(name))
            path.write_bytes(original)

    def test_module_library_pin_must_match_even_when_outer_module_hash_is_valid(self) -> None:
        path = self.source / "modules" / self.module
        original = self.manifest.assets["lib/ubs-common.sh"]
        path.write_text(path.read_text().replace(f'UBS_LIB_CHECKSUM="{original}"',
                                                 f'UBS_LIB_CHECKSUM="{"0" * 64}"', 1))
        self.repin(self.module)
        self.refresh_source_sums()
        self.assert_rejected("inconsistent shared-library pin")

    def test_transitive_helper_pins_must_match_even_when_all_outer_hashes_are_valid(self) -> None:
        path = self.source / "modules/lib/ubs-common.sh"
        old = f"['contract.json']='{self.manifest.assets['contract.json']}'"
        path.write_text(path.read_text().replace(old, f"['contract.json']='{'0' * 64}'", 1))
        new_library_pin = sha256(path)
        self.repin("lib/ubs-common.sh")
        for name in self.manifest.assets:
            if re.fullmatch(r"ubs-[a-z]+\.sh", name):
                path = self.source / "modules" / name
                path.write_text(path.read_text().replace(
                    f'UBS_LIB_CHECKSUM="{self.manifest.assets["lib/ubs-common.sh"]}"',
                    f'UBS_LIB_CHECKSUM="{new_library_pin}"', 1))
                self.repin(name)
        self.refresh_source_sums()
        self.assert_rejected("shared-library helper pins do not match")

    def test_daemon_bytes_must_match_runner_pin(self) -> None:
        path = self.source / "ubs-daemon"
        path.write_bytes(path.read_bytes() + b"\n# changed companion\n")
        self.refresh_source_sums()
        self.assert_rejected("required daemon pin")

    def test_daemon_pin_is_required(self) -> None:
        path = self.source / "ubs"
        path.write_text(re.sub(r'^UBS_DAEMON_SHA256=.*\n', '', path.read_text(), flags=re.M))
        self.refresh_source_sums()
        self.assert_rejected("required daemon pin")

    def test_distributed_minisign_key_must_match_runner_trust(self) -> None:
        path = self.source / "minisign.pub"
        lines = path.read_text().splitlines()
        lines[1] = lines[1][:-1] + ("A" if lines[1][-1] != "A" else "B")
        path.write_text("\n".join(lines) + "\n")
        self.assert_rejected("minisign public key")

    def test_installer_default_key_must_match_distributed_key(self) -> None:
        path = self.source / "install.sh"
        key = (self.source / "minisign.pub").read_text().splitlines()[1]
        changed = key[:-1] + ("A" if key[-1] != "A" else "B")
        path.write_text(path.read_text().replace("UBS_MINISIGN_PUBKEY:-" + key,
                                                 "UBS_MINISIGN_PUBKEY:-" + changed, 1))
        self.refresh_source_sums()
        self.assert_rejected("minisign public key")

    def test_ambiguous_minisign_key_file_is_rejected(self) -> None:
        path = self.source / "minisign.pub"
        path.write_text(path.read_text() + path.read_text().splitlines()[1] + "\n")
        self.assert_rejected("minisign public key")

    def test_source_checksum_manifest_is_verified(self) -> None:
        path = self.source / "SHA256SUMS"
        path.write_text(path.read_text().replace(sha256(self.source / "install.sh"), "0" * 64, 1))
        self.assert_rejected("source SHA256SUMS mismatch: install.sh")

    def test_source_checksum_manifest_requires_unique_complete_entries(self) -> None:
        path = self.source / "SHA256SUMS"
        original = path.read_text()
        for bad in (original + original.splitlines()[0] + "\n",
                    "\n".join(line for line in original.splitlines() if not line.endswith("  ubs")) + "\n",
                    original + "0" * 64 + "  ../outside\n"):
            with self.subTest(manifest=bad):
                path.write_text(bad)
                self.assert_rejected("source SHA256SUMS")

    def test_missing_flat_asset_is_rejected_before_output(self) -> None:
        for relative in candidate.FLAT_PAYLOAD.values():
            path = self.source / relative
            saved = path.with_name(path.name + ".retained")
            with self.subTest(asset=relative):
                path.rename(saved)
                self.assert_rejected("No such file|not found")
                saved.rename(path)

    def test_missing_runtime_asset_is_rejected_before_output(self) -> None:
        path = self.source / "modules" / self.helper
        path.rename(path.with_name(path.name + ".retained"))
        self.assert_rejected("No such file|not found")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support")
    def test_symlinked_payload_and_pinned_parent_are_rejected(self) -> None:
        for relative in ("scripts/verify.sh", "modules/helpers"):
            path = self.source / relative
            saved = path.with_name(path.name + ".retained")
            with self.subTest(path=relative):
                path.rename(saved)
                path.symlink_to(saved, target_is_directory=saved.is_dir())
                self.assert_rejected("symlink|unsafe cached asset directory")
                # Rename the rejected link out of the way, retaining both it
                # and its target until this disposable fixture is cleaned up.
                path.rename(path.with_name(path.name + ".rejected-link"))
                saved.rename(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support")
    def test_nonregular_payload_is_rejected_without_opening_it(self) -> None:
        path = self.source / "scripts/verify.sh"
        path.rename(path.with_suffix(".retained"))
        os.mkfifo(path)
        self.assert_rejected("not a regular file")

    def test_existing_output_and_unrelated_files_are_preserved(self) -> None:
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_bytes(b"unrelated existing candidate\n")
        with self.assertRaisesRegex(candidate.CandidateError, "output already exists"):
            self.build()
        self.assertEqual(list(self.output.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"unrelated existing candidate\n")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support")
    def test_dangling_output_symlink_is_preserved(self) -> None:
        target = self.root / "do-not-create"
        self.output.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(candidate.CandidateError, "output already exists"):
            self.build()
        self.assertTrue(self.output.is_symlink())
        self.assertFalse(target.exists())

    def test_unpinned_source_extras_are_not_bundled(self) -> None:
        extra = self.source / "modules/helpers/sitecustomize.py"
        self.assertFalse(extra.exists())
        extra.write_text("raise RuntimeError('untrusted extra must not be imported')\n")
        self.build()
        self.assertFalse((self.output / "modules/helpers/sitecustomize.py").exists())

    def test_candidate_code_is_not_executed_and_no_external_tools_are_called(self) -> None:
        helper = self.source / "scripts/release_generation.py"
        original = helper.read_bytes()
        injected = original + b"\nraise RuntimeError('candidate helper must not be imported')\n"
        helper.write_bytes(injected)
        runner = self.source / "ubs"
        runner.write_bytes(runner.read_bytes().replace(original, injected, 1) + b"\nexit 99\n")
        self.refresh_source_sums()
        with mock.patch.object(candidate.generation.subprocess, "run", side_effect=AssertionError("external command")):
            self.build()
        self.assertEqual((self.output / "ubs").read_bytes(), runner.read_bytes())

    def test_assembly_uses_validated_bytes_when_source_changes_after_preflight(self) -> None:
        original = candidate.validate_source
        helper = self.source / "modules" / self.helper
        expected = helper.read_bytes()

        def mutate_after_validation(source: Path, version: str):
            result = original(source, version)
            helper.write_bytes(b"changed after validation\n")
            return result

        with mock.patch.object(candidate, "validate_source", side_effect=mutate_after_validation):
            self.build()
        self.assertEqual((self.output / "modules" / self.helper).read_bytes(), expected)

    def test_nested_pins_are_checked_on_captured_bytes_despite_source_replacement(self) -> None:
        module = self.source / "modules" / self.module
        original = module.read_bytes()
        valid = f'UBS_LIB_CHECKSUM="{self.manifest.assets["lib/ubs-common.sh"]}"'.encode()
        invalid = f'UBS_LIB_CHECKSUM="{"0" * 64}"'.encode()
        module.write_bytes(original.replace(valid, invalid, 1))
        self.repin(self.module)
        self.refresh_source_sums()
        read = candidate.generation.read_cached_asset

        def replace_after_capture(root: Path, relative: str, limit: int):
            data = read(root, relative, limit)
            if root == self.source and relative == "modules/" + self.module:
                module.write_bytes(original)
            return data

        with mock.patch.object(candidate.generation, "read_cached_asset", side_effect=replace_after_capture):
            self.assert_rejected("inconsistent shared-library pin")

    @unittest.skipUnless(os.name == "posix", "POSIX executable modes")
    def test_candidate_modes_are_usable_under_restrictive_umask(self) -> None:
        previous = os.umask(0o077)
        try:
            self.build()
        finally:
            os.umask(previous)
        for path in self.output.rglob("*"):
            relative = path.relative_to(self.output).as_posix()
            executable = relative in candidate.EXECUTABLES or bool(re.fullmatch(r"modules/ubs-[a-z]+\.sh", relative))
            expected = 0o755 if path.is_dir() or executable else 0o644
            self.assertEqual(path.stat().st_mode & 0o777, expected, relative)

    def test_release_publishes_every_authenticated_flat_payload(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        publish = workflow.split("- name: Create GitHub release", 1)[1].split("        env:", 1)[0]
        names = set(re.findall(r"^\s+dist/([^\s*]+)\s*$", publish, re.M))
        self.assertTrue(set(candidate.FLAT_PAYLOAD) <= names,
                        "release upload omits: " + ", ".join(sorted(set(candidate.FLAT_PAYLOAD) - names)))
        self.assertTrue({"SHA256SUMS", "SHA256SUMS.minisig"} <= names)


if __name__ == "__main__":
    unittest.main()
