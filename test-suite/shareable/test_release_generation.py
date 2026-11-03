#!/usr/bin/env python3
"""Deterministic update transaction/fault tests, without network or live installs.

These unit fixtures are intentionally small. They supplement, not substitute
for, the released-v5.4.17 upgrade/real-scan cases in test_installed_contract.py.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/release_generation.py"
spec = importlib.util.spec_from_file_location("release_generation", SOURCE)
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)


def fixture_runner(version: str, assets: dict[str, bytes]) -> bytes:
    modules = []
    helpers = []
    languages = []
    inventory = []
    for name, data in sorted(assets.items()):
        sha = hashlib.sha256(data).hexdigest()
        if name.startswith("ubs-") and name.endswith(".sh"):
            modules.append(f"  [{name[4:-3]}]='{sha}'")
            languages.append(name[4:-3])
        else:
            helpers.append(f"  ['{name}']='{sha}'")
            inventory.append(f'  "{name}"')
    return ("#!/usr/bin/env bash\n" + f'UBS_VERSION="{version}"\n'
            + "UBS_RELEASE_GENERATIONS=1\ndeclare -A MODULE_CHECKSUMS=(\n"
            + "\n".join(modules) + "\n)\ndeclare -A HELPER_CHECKSUMS=(\n"
            + "\n".join(helpers) + "\n)\nHELPER_ASSETS=(\n"
            + "\n".join(inventory) + "\n)\nALL_LANGS=(" + " ".join(languages) + ")\n").encode()


def coherent_assets(assets: dict[str, bytes]) -> dict[str, bytes]:
    """Build a small actual pin graph, including module -> library -> helpers."""
    result = dict(assets)
    helper_pins = []
    for name, data in sorted(assets.items()):
        if name != "lib/ubs-common.sh" and not (name.startswith("ubs-") and name.endswith(".sh")):
            helper_pins.append(f"  ['{name}']='{hashlib.sha256(data).hexdigest()}'")
    library = (assets["lib/ubs-common.sh"] + b"declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(\n"
               + "\n".join(helper_pins).encode() + b"\n)\n")
    result["lib/ubs-common.sh"] = library
    pin = f'UBS_LIB_CHECKSUM="{hashlib.sha256(library).hexdigest()}"\n'.encode()
    for name, data in assets.items():
        if name.startswith("ubs-") and name.endswith(".sh"):
            result[name] = data + pin
    return result


FETCH = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlparse, unquote
args = sys.argv[1:]
url = next(a for a in args if "://" in a)
if not url.startswith("file://"):
    raise SystemExit(22)
source = Path(unquote(urlparse(url).path))
if source.name == os.environ.get("UPDATE_BLOCK_ASSET"):
    Path(os.environ["UPDATE_BLOCK_READY"]).write_text("blocked")
    release = os.environ.get("UPDATE_BLOCK_RELEASE")
    while not release or not Path(release).exists():
        time.sleep(0.05)
try:
    destination = Path(args[args.index("-o") + 1])
    destination.write_bytes(source.read_bytes())
except OSError:
    raise SystemExit(22)
'''


class ReleaseGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-release-generation-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "installed modules"
        self.cache.mkdir()
        self.old_assets = {
            "contract.json": b'{"contract_version":1,"modules":{"old":{}}}\n',
            "ubs-rust.sh": b"#!/bin/sh\nprintf 'old module\\n'\n",
            "helpers/nested/helper.py": b"print('old helper')\n",
            "lib/ubs-common.sh": b"# old common library\n",
        }
        self.new_assets = {
            "contract.json": b'{"contract_version":1,"modules":{"rust":{}}}\n',
            "ubs-rust.sh": b"#!/bin/sh\nprintf 'new module\\n'\n",
            "ubs-js.sh": b"#!/bin/sh\nprintf 'new js module\\n'\n",
            "helpers/nested/helper.py": b"print('new helper')\n",
            "helpers/empty.py": b"",
            "lib/ubs-common.sh": b"# new common library\n",
        }
        self.old_assets = coherent_assets(self.old_assets)
        self.new_assets = coherent_assets(self.new_assets)
        self.installed = self.root / "installed ubs"
        self.installed.write_bytes(fixture_runner("5.4.17", self.old_assets))
        self.installed.chmod(0o755)
        for name, data in self.old_assets.items():
            path = self.cache / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.candidate = self.root / "candidate"
        self.candidate.write_bytes(fixture_runner("5.5.1", self.new_assets))
        self.manifest = generation.parse_manifest(self.candidate.read_bytes())
        self.mirror = self.root / "mirror"
        self.remote = self.mirror / "v5.5.1/modules"
        for name, data in self.new_assets.items():
            path = self.remote / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "curl").write_text(FETCH)
        (self.bin / "curl").chmod(0o755)
        self.env = {**os.environ, "UBS_REPO_RAW_BASE": self.mirror.as_uri(),
                    "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        self.patch_env = mock.patch.dict(os.environ, self.env)
        self.patch_env.start()
        self.addCleanup(self.patch_env.stop)
        self.old_runner_bytes = self.installed.read_bytes()

    def prepare(self) -> Path:
        return generation.prepare(self.candidate, self.cache, self.mirror.as_uri(), allow_override=True)

    def assert_old_intact(self) -> None:
        self.assertEqual(self.installed.read_bytes(), self.old_runner_bytes)
        for name, data in self.old_assets.items():
            self.assertEqual((self.cache / name).read_bytes(), data, name)

    def assert_complete(self, path: Path) -> None:
        generation.check_ready(path, self.manifest, complete=True)
        for name, data in self.new_assets.items():
            self.assertEqual((path / name).read_bytes(), data, name)
        self.assertEqual((path / "ubs-rust.sh").stat().st_mode & 0o777, 0o755)
        self.assertEqual((path / "contract.json").stat().st_mode & 0o777, 0o644)
        self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_complete_set_is_published_without_mutating_active_installation(self) -> None:
        target = self.prepare()
        self.assert_complete(target)
        self.assert_old_intact()
        self.assertEqual(
            generation.select(self.candidate, self.cache, "https://offline.invalid", migrate_legacy=False,
                              allow_override=False), target,
        )

    def test_old_runner_selects_legacy_root_until_runner_is_published(self) -> None:
        target = self.prepare()
        self.assertEqual(generation.select(self.installed, self.cache, "unused", migrate_legacy=False,
                                           allow_override=False), self.cache)
        replacement = self.installed.with_suffix(".new")
        shutil.copyfile(self.candidate, replacement)
        os.replace(replacement, self.installed)
        self.assertEqual(generation.select(self.installed, self.cache, "unused", migrate_legacy=False,
                                           allow_override=False), target)
        self.assert_complete(target)

    def test_published_generation_is_reusable_offline(self) -> None:
        target = self.prepare()
        with mock.patch.object(generation, "download", side_effect=AssertionError("unexpected download")):
            self.assertEqual(self.prepare(), target)
        self.assert_complete(target)

    def test_matching_cached_files_are_copied_not_linked(self) -> None:
        for name, data in self.new_assets.items():
            path = self.cache / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        with mock.patch.object(generation, "download", side_effect=AssertionError("unexpected download")):
            target = self.prepare()
        self.assertNotEqual((target / "contract.json").stat().st_ino,
                            (self.cache / "contract.json").stat().st_ino)
        (self.cache / "contract.json").write_bytes(b"later damage")
        self.assert_complete(target)

    def test_each_corrupted_download_leaves_old_installation_untouched(self) -> None:
        for name, original in self.new_assets.items():
            if not original:  # A pinned empty file can be materialized without downloading.
                continue
            with self.subTest(asset=name):
                (self.remote / name).write_bytes(b"corrupt transport")
                with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
                    self.prepare()
                self.assert_old_intact()
                self.assertFalse(generation.generation_path(self.cache, self.manifest).exists())
                (self.remote / name).write_bytes(original)

    def test_failed_download_and_empty_contract_never_activate(self) -> None:
        contract = self.remote / "contract.json"
        parked = contract.with_suffix(".parked")
        contract.rename(parked)
        with self.assertRaisesRegex(generation.UpdateError, "could not fetch"):
            self.prepare()
        contract.write_bytes(b"")
        with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
            self.prepare()
        self.assert_old_intact()
        self.assertFalse(generation.generation_path(self.cache, self.manifest).exists())

    def test_killed_download_does_not_leave_a_selectable_generation_and_retry_works(self) -> None:
        blocked = self.root / "blocked"
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", str(SOURCE), "prepare", str(self.candidate), str(self.cache),
             self.mirror.as_uri(), "0"],
            env={**self.env, "UPDATE_BLOCK_ASSET": "helper.py", "UPDATE_BLOCK_READY": str(blocked)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not blocked.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(blocked.exists(), "download never reached the interruption point")
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            self.assert_old_intact()
            self.assertFalse(generation.generation_path(self.cache, self.manifest).exists())
            self.assertTrue(list((self.cache / generation.GENERATION_DIRECTORY).glob(".stage-*")))
            self.assert_complete(self.prepare())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)

    def test_failure_at_generation_publication_keeps_active_files(self) -> None:
        with mock.patch.object(generation.os, "rename", side_effect=OSError("interrupted publication")):
            with self.assertRaisesRegex(OSError, "interrupted publication"):
                self.prepare()
        self.assert_old_intact()
        self.assertFalse(generation.generation_path(self.cache, self.manifest).exists())
        self.assert_complete(self.prepare())

    def test_concurrent_preparers_publish_one_complete_generation(self) -> None:
        # Use real processes and flock: an in-process mock cannot reproduce
        # one updater observing another updater's partially downloaded tree.
        blocked = self.root / "writer-blocked"
        release = self.root / "writer-release"
        command = [sys.executable, "-I", "-S", str(SOURCE), "prepare",
                   str(self.candidate), str(self.cache), self.mirror.as_uri(), "0"]
        first = subprocess.Popen(
            command, env={**self.env, "UPDATE_BLOCK_ASSET": "helper.py",
                          "UPDATE_BLOCK_READY": str(blocked), "UPDATE_BLOCK_RELEASE": str(release)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        processes = [first]
        try:
            deadline = time.monotonic() + 10
            while not blocked.exists() and first.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(blocked.exists(), "first updater did not reach the download barrier")
            second = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, start_new_session=True)
            processes.append(second)
            # The currently installed runner can continue selecting its old
            # cache while both updaters run; staging never replaces its files.
            for _ in range(5):
                self.assertEqual(generation.select(self.installed, self.cache, "unused",
                                                   migrate_legacy=False, allow_override=False), self.cache)
                self.assert_old_intact()
                self.assertFalse(generation.generation_path(self.cache, self.manifest).exists())
                self.assertIsNone(second.poll(), "second updater bypassed the generation lock")
                time.sleep(0.02)
            release.write_text("continue")
            targets = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                targets.append(Path(stdout.strip()))
            self.assertEqual(targets[0], targets[1])
            self.assert_complete(targets[0])
            self.assert_old_intact()
        finally:
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=10)

    def test_existing_damaged_generation_is_not_silently_trusted(self) -> None:
        target = self.prepare()
        (target / "contract.json").write_bytes(b"damaged")
        with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
            self.prepare()
        self.assert_old_intact()

    def test_ready_marker_cannot_refer_to_another_runner(self) -> None:
        target = self.prepare()
        (target / generation.READY_FILE).write_bytes(b"{}\n")
        with self.assertRaisesRegex(generation.UpdateError, "incomplete or mismatched"):
            generation.select(self.candidate, self.cache, "unused", migrate_legacy=False,
                              allow_override=False)
        self.assert_old_intact()

    def test_symlink_generation_container_is_rejected(self) -> None:
        other = self.root / "other"
        other.mkdir()
        (self.cache / generation.GENERATION_DIRECTORY).symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(generation.UpdateError, "symlink"):
            self.prepare()
        self.assertEqual(list(other.iterdir()), [])
        self.assert_old_intact()

    def test_symlinked_module_inside_completed_generation_is_rejected(self) -> None:
        target = self.prepare()
        module = target / "ubs-rust.sh"
        module.rename(module.with_suffix(".parked"))
        module.symlink_to(self.remote / "ubs-rust.sh")
        with self.assertRaises(OSError):
            self.prepare()
        self.assert_old_intact()

    def test_known_legacy_contract_migrates_but_arbitrary_damage_does_not(self) -> None:
        known = hashlib.sha256(self.old_assets["contract.json"]).hexdigest()
        with mock.patch.object(generation, "LEGACY_CONTRACTS", frozenset({known})):
            self.assert_complete(generation.select(self.candidate, self.cache, self.mirror.as_uri(),
                                                   migrate_legacy=True, allow_override=True))
        # A generation belongs to the version and pinned assets, independent
        # of unrelated comments or installer-local changes to runner bytes.
        self.candidate.write_bytes(self.candidate.read_bytes().replace(
            b'UBS_VERSION="5.5.1"', b'UBS_VERSION="5.5.2"'))
        (self.cache / "contract.json").write_bytes(b"unknown damage")
        with mock.patch.object(generation, "download", side_effect=AssertionError("unexpected repair")):
            self.assertEqual(generation.select(self.candidate, self.cache, self.mirror.as_uri(),
                                               migrate_legacy=True, allow_override=True), self.cache)

    def test_restrictive_umask_does_not_break_other_users(self) -> None:
        previous = os.umask(0o077)
        try:
            self.assert_complete(self.prepare())
        finally:
            os.umask(previous)

    def test_legacy_target_without_generation_support_is_not_published(self) -> None:
        self.candidate.write_bytes(self.candidate.read_bytes().replace(b"UBS_RELEASE_GENERATIONS=1\n", b""))
        with self.assertRaisesRegex(generation.UpdateError, "does not support"):
            self.prepare()
        self.assert_old_intact()

    def test_literal_parser_rejects_ambiguous_or_unsafe_manifests(self) -> None:
        source = self.candidate.read_bytes()
        bad_versions = source + b'UBS_VERSION="5.5.2"\n'
        bad_path = source.replace(b"helpers/nested/helper.py", b"../outside.py")
        bad_shell = source.replace(b"['contract.json']", b"[$(touch /tmp/not-executed)]")
        bad_digest = source.replace(self.manifest.assets["contract.json"].encode(), b"not-a-sha256")
        duplicate = source.replace(b"declare -A HELPER_CHECKSUMS=(\n", b"declare -A HELPER_CHECKSUMS=(\n"
                                   + f"  ['contract.json']='{self.manifest.assets['contract.json']}'\n".encode())
        no_contract = source.replace(b"['contract.json']", b"['not-contract.json']")
        for bad in (bad_versions, bad_path, bad_shell, bad_digest, duplicate, no_contract):
            with self.subTest(source=bad[:80]):
                with self.assertRaises(generation.UpdateError):
                    generation.parse_manifest(bad)

    def test_file_download_requires_an_explicit_source_override(self) -> None:
        with self.assertRaisesRegex(generation.UpdateError, "non-HTTPS"):
            generation.download(self.mirror.as_uri(), self.root / "download", allow_override=False)

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "Linux descriptor inventory")
    def test_rejected_directory_reads_do_not_leak_descriptors(self) -> None:
        # An opened directory cannot become a buffered binary stream. The
        # opener must close its real descriptor when that conversion raises.
        before = set(os.listdir("/proc/self/fd"))
        for _ in range(24):
            with self.assertRaises(IsADirectoryError):
                generation.read_regular(self.root)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def publish(self, **kwargs) -> Path:
        return generation.publish(
            self.candidate, self.cache, self.mirror.as_uri(), self.installed,
            hashlib.sha256(self.old_runner_bytes).hexdigest(), allow_override=True, **kwargs,
        )

    def test_standalone_runner_contains_the_tested_generation_source_verbatim(self) -> None:
        runner = (ROOT / "ubs").read_bytes()
        embedded = runner.split(b"<<'PYRELEASEGENERATION'\n", 1)[1]
        embedded = embedded.split(b"\nPYRELEASEGENERATION\n", 1)[0] + b"\n"
        self.assertEqual(embedded, SOURCE.read_bytes())

    def test_loaded_manifest_survives_runner_path_replacement(self) -> None:
        old = generation.parse_manifest(self.installed.read_bytes())
        old_runtime = generation.manifest_from_arguments(
            old.version, [f"{name}={pin}" for name, pin in old.assets.items()],
        )
        target = self.publish()
        self.assertEqual(generation.select_manifest(old_runtime, self.cache), self.cache)
        current_runtime = generation.manifest_from_arguments(
            self.manifest.version, [f"{name}={pin}" for name, pin in self.manifest.assets.items()],
        )
        self.assertEqual(generation.select_manifest(current_runtime, self.cache), target)
        # Editing runner-only text does not strand an otherwise identical set.
        commented = generation.parse_manifest(self.candidate.read_bytes() + b"# changed comment\n")
        self.assertNotEqual(commented.runner_sha256, self.manifest.runner_sha256)
        self.assertEqual(generation.generation_path(self.cache, commented), target)

    def test_publish_preserves_permissions_and_old_cache(self) -> None:
        self.installed.chmod(0o751)
        target = self.publish()
        self.assert_complete(target)
        self.assertEqual(self.installed.read_bytes(), self.candidate.read_bytes())
        self.assertEqual(self.installed.stat().st_mode & 0o777, 0o751)
        for name, data in self.old_assets.items():
            self.assertEqual((self.cache / name).read_bytes(), data, name)

    def test_fresh_publication_requires_an_absent_destination(self) -> None:
        fresh = self.root / "fresh runner"
        generation.publish(self.candidate, self.cache, self.mirror.as_uri(), fresh, "absent",
                           allow_override=True)
        self.assertEqual(fresh.read_bytes(), self.candidate.read_bytes())
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o755)
        with self.assertRaisesRegex(generation.UpdateError, "changed during update"):
            generation.publish(self.candidate, self.cache, self.mirror.as_uri(), fresh, "absent",
                               allow_override=True)
        self.assert_old_intact()

    def test_stale_publication_lease_and_downgrade_are_refused(self) -> None:
        self.installed.write_bytes(self.old_runner_bytes + b"# other updater\n")
        with self.assertRaisesRegex(generation.UpdateError, "changed during update"):
            self.publish()
        changed = self.installed.read_bytes()
        self.candidate.write_bytes(fixture_runner("5.3.0", self.new_assets))
        with self.assertRaisesRegex(generation.UpdateError, "downgrade"):
            generation.publish(self.candidate, self.cache, self.mirror.as_uri(), self.installed,
                               hashlib.sha256(changed).hexdigest(), allow_override=True)
        self.assertEqual(self.installed.read_bytes(), changed)
        self.assertFalse((self.cache / generation.GENERATION_DIRECTORY).exists())

    def test_failure_at_runner_publication_leaves_a_reusable_verified_generation(self) -> None:
        replace = generation.os.replace

        def fail_runner(source, destination):
            if Path(destination) == self.installed:
                raise OSError("runner publication interrupted")
            return replace(source, destination)

        with mock.patch.object(generation.os, "replace", side_effect=fail_runner):
            with self.assertRaisesRegex(OSError, "publication interrupted"):
                self.publish()
        self.assert_old_intact()
        target = generation.generation_path(self.cache, self.manifest)
        self.assert_complete(target)
        with mock.patch.object(generation, "download", side_effect=AssertionError("unexpected download")):
            self.assertEqual(self.publish(), target)
        self.assertEqual(self.installed.read_bytes(), self.candidate.read_bytes())

    def test_external_runner_replacement_during_preparation_invalidates_lease(self) -> None:
        prepare = generation.prepare_manifest
        replaced = self.old_runner_bytes + b"# old updater replaced this runner\n"

        def external_update(*args, **kwargs):
            result = prepare(*args, **kwargs)
            self.installed.write_bytes(replaced)
            return result

        with mock.patch.object(generation, "prepare_manifest", side_effect=external_update):
            with self.assertRaisesRegex(generation.UpdateError, "changed during preparation"):
                self.publish()
        self.assertEqual(self.installed.read_bytes(), replaced)
        self.assert_complete(generation.generation_path(self.cache, self.manifest))

    def test_candidate_daemon_must_match_before_any_publication(self) -> None:
        daemon = self.root / "daemon"
        good = b"print('verified daemon')\n"
        daemon.write_bytes(b"untrusted daemon")
        pin = hashlib.sha256(good).hexdigest()
        self.candidate.write_bytes(self.candidate.read_bytes() + f'UBS_DAEMON_SHA256="{pin}"\n'.encode())
        with self.assertRaisesRegex(generation.UpdateError, "daemon checksum"):
            self.publish(daemon_source=daemon)
        self.assert_old_intact()
        self.assertFalse((self.cache / generation.GENERATION_DIRECTORY).exists())
        daemon.write_bytes(good)
        self.assert_complete(self.publish(daemon_source=daemon))
        published = self.installed.with_name(self.installed.name + f".daemon.{pin}.py")
        self.assertEqual(published.read_bytes(), good)

    def test_explicit_repair_verifies_all_assets_before_replacing_any(self) -> None:
        target = self.prepare()
        damaged = b"damaged cached helper"
        helper = target / "helpers/nested/helper.py"
        helper.write_bytes(damaged)
        (target / generation.READY_FILE).write_bytes(b"{}\n")
        (self.remote / "ubs-js.sh").write_bytes(b"untrusted replacement")
        (target / "ubs-js.sh").write_bytes(b"damaged module")
        with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
            generation.prepare_manifest(self.manifest, self.cache, self.mirror.as_uri(),
                                        allow_override=True, repair=True)
        self.assertEqual(helper.read_bytes(), damaged)
        self.assertEqual((target / generation.READY_FILE).read_bytes(), b"{}\n")
        (self.remote / "ubs-js.sh").write_bytes(self.new_assets["ubs-js.sh"])
        generation.prepare_manifest(self.manifest, self.cache, self.mirror.as_uri(),
                                    allow_override=True, repair=True)
        self.assert_complete(target)
        self.assert_old_intact()

    def test_interrupted_same_generation_repair_fails_closed_and_retries(self) -> None:
        target = self.prepare()
        (target / "contract.json").write_bytes(b"damaged contract")
        helper = target / "helpers/nested/helper.py"
        helper.write_bytes(b"damaged helper")
        replace = generation.os.replace

        def interrupt_repair(source, destination):
            if Path(destination) == helper:
                raise OSError("repair interrupted")
            return replace(source, destination)

        with mock.patch.object(generation.os, "replace", side_effect=interrupt_repair):
            with self.assertRaisesRegex(OSError, "repair interrupted"):
                generation.prepare_manifest(self.manifest, self.cache, self.mirror.as_uri(),
                                            allow_override=True, repair=True)
        with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
            generation.check_ready(target, self.manifest, complete=True)
        generation.prepare_manifest(self.manifest, self.cache, self.mirror.as_uri(),
                                    allow_override=True, repair=True)
        self.assert_complete(target)
        self.assert_old_intact()

    def test_missing_target_below_symlinked_generation_container_is_rejected(self) -> None:
        other = self.root / "other releases"
        other.mkdir()
        (self.cache / generation.GENERATION_DIRECTORY).symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(generation.UpdateError, "symlink"):
            generation.select_manifest(self.manifest, self.cache)
        self.assertEqual(list(other.iterdir()), [])

    def test_verified_local_source_can_prepare_an_offline_installation(self) -> None:
        with mock.patch.object(generation, "download", side_effect=AssertionError("unexpected download")):
            target = generation.prepare(self.candidate, self.cache, "https://offline.invalid",
                                        allow_override=False, local_source=self.remote)
        self.assert_complete(target)
        self.assert_old_intact()

    def test_inventory_and_case_collisions_are_rejected_before_download(self) -> None:
        source = self.candidate.read_bytes()
        bad_helper_list = source.replace(b'  "contract.json"\n', b'')
        bad_languages = source.replace(b"ALL_LANGS=(js rust)", b"ALL_LANGS=(js)")
        duplicate_version = source + b'UBS_VERSION="$(uname)"\n'
        collision = dict(self.new_assets)
        collision["helpers/Nested/helper.py"] = b"different case"
        file_directory = dict(self.new_assets)
        file_directory["helpers/nested"] = b"not a directory"
        for candidate in (bad_helper_list, bad_languages, duplicate_version,
                          fixture_runner("5.5.1", collision), fixture_runner("5.5.1", file_directory)):
            with self.subTest(candidate=candidate[-100:]):
                with self.assertRaises(generation.UpdateError):
                    generation.parse_manifest(candidate)
        self.assert_old_intact()

    def test_individually_pinned_module_with_incompatible_library_is_not_published(self) -> None:
        assets = dict(self.new_assets)
        assets["ubs-rust.sh"] = self.old_assets["ubs-rust.sh"]
        self.candidate.write_bytes(fixture_runner("5.5.1", assets))
        with self.assertRaisesRegex(generation.UpdateError, "inconsistent shared-library pin"):
            self.publish()
        self.assert_old_intact()
        manifest = generation.parse_manifest(self.candidate.read_bytes())
        self.assertFalse(generation.generation_path(self.cache, manifest).exists())

    def test_individually_pinned_library_with_inconsistent_helper_pins_is_not_published(self) -> None:
        assets = dict(self.new_assets)
        original_library = assets["lib/ubs-common.sh"]
        original_pin = hashlib.sha256(original_library).hexdigest().encode()
        helper_pin = hashlib.sha256(assets["helpers/nested/helper.py"]).hexdigest().encode()
        assets["lib/ubs-common.sh"] = original_library.replace(helper_pin, b"0" * 64)
        replacement_pin = hashlib.sha256(assets["lib/ubs-common.sh"]).hexdigest().encode()
        for name, data in tuple(assets.items()):
            if name.startswith("ubs-"):
                assets[name] = data.replace(original_pin, replacement_pin)
        self.candidate.write_bytes(fixture_runner("5.5.1", assets))
        for name, data in assets.items():
            (self.remote / name).write_bytes(data)
        with self.assertRaisesRegex(generation.UpdateError, "helper pins do not match"):
            self.publish()
        self.assert_old_intact()

    def test_same_version_publication_repairs_asset_and_ready_marker(self) -> None:
        target = self.publish()
        (target / "helpers/nested/helper.py").write_bytes(b"damaged helper")
        (target / generation.READY_FILE).write_bytes(b"{}\n")
        current = self.installed.read_bytes()
        generation.publish(self.candidate, self.cache, self.mirror.as_uri(), self.installed,
                           hashlib.sha256(current).hexdigest(), allow_override=True)
        self.assert_complete(target)
        self.assertEqual(self.installed.read_bytes(), current)

    def test_selection_verifies_all_assets_despite_valid_ready_marker(self) -> None:
        target = self.prepare()
        for name in self.new_assets:
            with self.subTest(asset=name):
                asset = target / name
                original = asset.read_bytes()
                asset.write_bytes(b"tampered after preparation")
                with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
                    generation.select_manifest(self.manifest, self.cache)
                asset.write_bytes(original)
        self.assertEqual(generation.select_manifest(self.manifest, self.cache), target)

    def test_final_asset_validation_precedes_runner_publication(self) -> None:
        prepare = generation.prepare_manifest

        def damage_after_prepare(*args, **kwargs):
            result = prepare(*args, **kwargs)
            (result / "helpers/nested/helper.py").write_bytes(b"late damage")
            return result

        with mock.patch.object(generation, "prepare_manifest", side_effect=damage_after_prepare):
            with self.assertRaisesRegex(generation.UpdateError, "checksum mismatch"):
                self.publish()
        self.assert_old_intact()

    def test_manifest_selection_cli_uses_loaded_pins_not_a_runner_path(self) -> None:
        target = self.prepare()
        self.candidate.write_bytes(b"runner path replaced with unrelated bytes")
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(SOURCE), "select-manifest", str(self.cache),
             self.manifest.version, *(f"{name}={pin}" for name, pin in self.manifest.assets.items())],
            env=self.env, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), str(target))

    def test_concurrent_publishers_serialize_runner_publication(self) -> None:
        blocked = self.root / "publish blocked"
        release = self.root / "publish release"
        command = [sys.executable, "-I", "-S", str(SOURCE), "publish", str(self.candidate),
                   str(self.cache), self.mirror.as_uri(), str(self.installed),
                   hashlib.sha256(self.old_runner_bytes).hexdigest()]
        first = subprocess.Popen(
            command, env={**self.env, "UPDATE_BLOCK_ASSET": "helper.py",
                          "UPDATE_BLOCK_READY": str(blocked), "UPDATE_BLOCK_RELEASE": str(release)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        second = None
        try:
            deadline = time.monotonic() + 10
            while not blocked.exists() and first.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(blocked.exists(), "first updater never reached the download barrier")
            second = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
            time.sleep(0.1)
            self.assertIsNone(second.poll(), "second updater bypassed the publication lock")
            self.assert_old_intact()
            release.write_text("continue")
            out1, err1 = first.communicate(timeout=20)
            out2, err2 = second.communicate(timeout=20)
            self.assertEqual(first.returncode, 0, out1 + err1)
            self.assertEqual(second.returncode, 0, out2 + err2)
            self.assertEqual(out1, out2)
            self.assert_complete(Path(out1.strip()))
            self.assertEqual(self.installed.read_bytes(), self.candidate.read_bytes())
        finally:
            release.write_text("continue")
            for process in (first, second):
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=20)

    def test_windows_lock_protocol_uses_and_releases_the_same_byte(self) -> None:
        # Protocol coverage on this host, not a claim of native Windows execution.
        events = []

        def locking(descriptor, mode, length):
            events.append((mode, length, os.lseek(descriptor, 0, os.SEEK_CUR)))

        windows = SimpleNamespace(LK_LOCK=1, LK_UNLCK=0, locking=locking)
        with (self.root / "portable.lock").open("w+b") as stream:
            stream.seek(17)
            with mock.patch.object(generation, "IS_WINDOWS", True), \
                    mock.patch.object(generation, "msvcrt", windows):
                with self.assertRaisesRegex(RuntimeError, "body interrupted"):
                    with generation.exclusive_lock(stream.fileno()):
                        stream.seek(31)
                        raise RuntimeError("body interrupted")
        self.assertEqual(events, [(1, 1, 0), (0, 1, 0)])

    def test_windows_lock_failure_and_missing_backend_never_enter_transaction(self) -> None:
        windows = SimpleNamespace(LK_LOCK=1, LK_UNLCK=0,
                                  locking=mock.Mock(side_effect=OSError("lock contention")))
        with (self.root / "portable.lock").open("w+b") as stream:
            with mock.patch.object(generation, "IS_WINDOWS", True), \
                    mock.patch.object(generation, "msvcrt", windows):
                with self.assertRaisesRegex(OSError, "lock contention"):
                    with generation.exclusive_lock(stream.fileno()):
                        self.fail("transaction entered without a lock")
            self.assertEqual(windows.locking.call_count, 1)
            with mock.patch.object(generation, "IS_WINDOWS", False), \
                    mock.patch.object(generation, "fcntl", None):
                with self.assertRaisesRegex(generation.UpdateError, "supported update lock"):
                    with generation.exclusive_lock(stream.fileno()):
                        self.fail("transaction entered without a lock backend")

    def test_portable_regular_open_rejects_symlink_without_native_nofollow(self) -> None:
        link = self.root / "linked runner"
        link.symlink_to(self.installed)
        with mock.patch.object(generation, "OPEN_NOFOLLOW", 0):
            with self.assertRaisesRegex(OSError, "symlink or reparse"):
                generation.read_regular(link)
            self.assertEqual(generation.read_regular(self.installed), self.old_runner_bytes)

    def test_portable_regular_open_detects_replacement_between_lstat_and_open(self) -> None:
        target = self.root / "raced file"
        target.write_bytes(b"original bytes")
        replacement = self.root / "replacement file"
        replacement.write_bytes(b"substituted bytes")
        saved = self.root / "saved original"
        original_open = generation.os.open

        def replace_before_open(path, flags, mode=0o600):
            if Path(path) == target:
                target.rename(saved)
                replacement.rename(target)
            return original_open(path, flags, mode)

        with mock.patch.object(generation, "OPEN_NOFOLLOW", 0), \
                mock.patch.object(generation.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(generation.UpdateError, "identity changed"):
                generation.read_regular(target)
        self.assertEqual(saved.read_bytes(), b"original bytes")

    def test_reparse_attributes_are_rejected_for_files_and_directories(self) -> None:
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=reparse)
        with self.assertRaisesRegex(OSError, "symlink or reparse"):
            generation.require_regular(file_info, self.root / "reparse file")
        directory = mock.Mock()
        directory.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755,
                                                       st_file_attributes=reparse)
        with self.assertRaisesRegex(generation.UpdateError, "non-directory or symlink"):
            generation.real_directory(directory)

    def test_windows_directory_sync_has_no_posix_open_requirement(self) -> None:
        with mock.patch.object(generation, "IS_WINDOWS", True), \
                mock.patch.object(generation.os, "open", side_effect=AssertionError("directory open")):
            generation.sync_directory(self.root)

    def test_mode_setting_without_fchmod_checks_stage_identity(self) -> None:
        stage = self.root / "mode stage"
        limited_os = SimpleNamespace(path=os.path, chmod=os.chmod, fstat=os.fstat)
        with stage.open("xb") as stream:
            with mock.patch.object(generation, "os", limited_os):
                generation.set_file_mode(stream.fileno(), stage, 0o640)
        self.assertEqual(stage.stat().st_mode & 0o777, 0o640)

    def test_publisher_waiting_on_a_retired_lock_cannot_mutate_the_install(self) -> None:
        lock_path = self.installed.with_name(self.installed.name + ".update.lock")
        exclusive = generation.exclusive_lock
        for recreate in (False, True):
            with self.subTest(recreated=recreate):
                retired = self.root / f"retired update lock {recreate}"

                @contextlib.contextmanager
                def acquired_retired_lock(descriptor):
                    with exclusive(descriptor):
                        # Model an uninstall completing while this process was
                        # queued on the old inode; another install may recreate
                        # the pathname before this waiter gets the lock.
                        lock_path.rename(retired)
                        if recreate:
                            lock_path.write_bytes(b"")
                        yield

                with mock.patch.object(generation, "exclusive_lock", acquired_retired_lock):
                    with self.assertRaisesRegex(generation.UpdateError, "lock was (removed|replaced)"):
                        self.publish()
                self.assert_old_intact()
                self.assertFalse((self.cache / generation.GENERATION_DIRECTORY).exists())

    def test_generation_waiter_rejects_a_recreated_lock_path(self) -> None:
        container = self.cache / generation.GENERATION_DIRECTORY
        exclusive = generation.exclusive_lock

        @contextlib.contextmanager
        def acquired_retired_lock(descriptor):
            with exclusive(descriptor):
                (container / ".prepare.lock").rename(container / ".retired.lock")
                (container / ".prepare.lock").write_bytes(b"")
                yield

        with mock.patch.object(generation, "exclusive_lock", acquired_retired_lock):
            with self.assertRaisesRegex(generation.UpdateError, "lock was replaced"):
                self.prepare()
        self.assert_old_intact()
        self.assertFalse(generation.generation_path(self.cache, self.manifest).exists())


if __name__ == "__main__":
    unittest.main()
