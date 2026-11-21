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

    def test_cli_check_only_validates_without_creating_output(self) -> None:
        before = set(self.root.iterdir())
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--version", self.version, "--check-only"],
            cwd=self.root, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "validated")
        self.assertEqual(report["runner_sha256"], sha256(ROOT / "ubs"))
        self.assertNotIn("output", report)
        self.assertEqual(set(self.root.iterdir()), before)

    def git(self, *args: str) -> str:
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        result = subprocess.run(["git", *args], cwd=self.source, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def commit_source(self) -> str:
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "UBS candidate test")
        self.git("config", "user.email", "ubs-test@example.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("add", ".")
        self.git("commit", "-qm", "complete candidate")
        return self.git("rev-parse", "HEAD^{tree}")

    def test_git_candidate_uses_committed_bytes_despite_dirty_working_tree(self) -> None:
        tree = self.commit_source()
        helper = self.source / "modules" / self.helper
        expected = helper.read_bytes()
        helper.write_bytes(expected + b"\n# uncommitted source edit\n")
        self.assert_rejected("checksum mismatch")
        report = candidate.build_candidate(self.source, self.version, self.output, "HEAD")
        self.assertEqual(report["source_tree"], tree)
        self.assertEqual((self.output / "modules" / self.helper).read_bytes(), expected)
        self.assertNotEqual(helper.read_bytes(), expected, "assembly must preserve the source edit")

    def test_git_snapshot_retains_blob_identity_when_branch_and_index_move(self) -> None:
        tree = self.commit_source()
        source = candidate.GitSource(self.source, "HEAD")
        expected = (self.source / "install.sh").read_bytes()
        (self.source / "install.sh").write_bytes(expected + b"\n# later commit\n")
        self.git("add", "install.sh")
        self.git("commit", "-qm", "different installer")
        self.assertEqual(source.tree, tree)
        self.assertNotEqual(self.git("rev-parse", "HEAD^{tree}"), tree)
        self.assertEqual(source.read("install.sh", candidate.generation.MAX_ASSET_BYTES), expected)

    def test_git_reader_rejects_missing_and_oversize_inputs(self) -> None:
        self.commit_source()
        source = candidate.GitSource(self.source, "HEAD")
        with self.assertRaisesRegex(candidate.CandidateError, "missing required input"):
            source.read("missing.py", 1024)
        with self.assertRaisesRegex(candidate.CandidateError, "exceeds size limit"):
            source.read("ubs", 1)
        with self.assertRaisesRegex(candidate.CandidateError, "could not read release Git tree"):
            candidate.GitSource(self.source, "does-not-exist")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support")
    def test_git_reader_rejects_committed_symlinks_even_with_regular_working_copy(self) -> None:
        self.commit_source()
        path = self.source / "scripts/verify.sh"
        retained = path.with_name("verify-retained.sh")
        path.rename(retained)
        path.symlink_to(retained.name)
        self.git("add", "scripts/verify.sh")
        tree = self.git("write-tree")
        path.rename(path.with_name("verify-rejected-link.sh"))
        retained.rename(path)
        with self.assertRaisesRegex(candidate.CandidateError, "not a regular file"):
            candidate.build_candidate(self.source, self.version, self.output, tree)
        self.assertFalse(self.output.exists())

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


class ReleaseWorkflowTests(unittest.TestCase):
    def test_build_recipe_requires_install_and_repository_gates_before_signing(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        build = workflow.split("\n  build-artifacts:\n", 1)[1].split("\n  oci-image:\n", 1)[0]
        steps = re.split(r"^      - name: (.+)$", build, flags=re.M)
        names = steps[1::2]
        bodies = dict(zip(names, steps[2::2]))
        signing = names.index("Sign checksums with minisign")
        for name in ("Qualify release publication and verification", "Require repository quality gates",
                     "Require complete clean self-scan", "Assemble complete generation-capable release payload"):
            with self.subTest(gate=name):
                self.assertLess(names.index(name), signing)
                self.assertNotRegex(bodies[name], r"(?m)^\s+(?:if|continue-on-error):")
        self.assertRegex(steps[0], r'(?m)^      UBS_RELEASE_QUALIFICATION: "1"$')
        self.assertRegex(steps[0], r'(?m)^      UBS_DAEMON_E2E: "1"$')
        for script in ("test_release_candidate_install.py", "test_release_self_scan.py"):
            self.assertIn(script, bodies["Qualify release publication and verification"])
        for command in ("shellcheck ubs modules/ubs-*.sh scripts/*.sh", "bash test-suite/run_all.sh",
                        "bash scripts/verify_checksums.sh", "bash scripts/verify_sha256sums.sh"):
            self.assertIn(command, bodies["Require repository quality gates"])
        assembly = bodies["Assemble complete generation-capable release payload"]
        self.assertIn('--source-ref "$RELEASE_COMMIT" --check-only --require-working-tree-match', assembly)
        self.assertIn('--source-ref "$RELEASE_COMMIT" --output dist', assembly)

    def test_publication_waits_for_successful_candidate_and_nix_gates(self) -> None:
        # The image push is already public publication, before the later
        # GitHub Release job. Check the recipe's dependency contract without
        # executing Actions or adding a YAML dependency to the test suite.
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        jobs = workflow.split("\njobs:\n", 1)[1]
        sections = re.split(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs, flags=re.M)
        bodies = dict(zip(sections[1::2], sections[2::2]))
        required = {
            "oci-image": {"gather", "build-artifacts", "nix-check"},
            "publish": {"build-artifacts", "oci-image", "nix-check"},
        }
        for name, prerequisites in required.items():
            with self.subTest(job=name):
                self.assertIn(name, bodies)
                header = bodies[name].split("\n    steps:", 1)[0]
                needs = re.search(r"^    needs:[ \t]*([^\n]*)$", header, re.M)
                self.assertIsNotNone(needs, name + " has no publication prerequisites")
                value = needs[1].strip()
                if value.startswith("[") and value.endswith("]"):
                    dependencies = {part.strip() for part in value[1:-1].split(",")}
                elif value:
                    dependencies = {value}
                else:
                    block = re.match(r"(?:\n      - [A-Za-z0-9_-]+[ \t]*)+", header[needs.end():])
                    self.assertIsNotNone(block, name + " has unrecognized prerequisite syntax")
                    dependencies = set(re.findall(r"- ([A-Za-z0-9_-]+)", block[0]))
                self.assertFalse(prerequisites - dependencies,
                                 name + " can run before " + ", ".join(sorted(prerequisites - dependencies)))
                self.assertNotRegex(header, r"(?m)^    if:",
                                    name + " must retain default successful-dependency semantics")
        for name in ("build-artifacts", "nix-check", "oci-image"):
            with self.subTest(failure_propagation=name):
                self.assertIn(name, bodies)
                for value in re.findall(r"(?m)^\s+continue-on-error:[ \t]*([^\n]+)", bodies[name]):
                    self.assertEqual(value.split("#", 1)[0].strip(), "false",
                                     name + " must not tolerate failed qualification/signing steps")


if __name__ == "__main__":
    unittest.main()
