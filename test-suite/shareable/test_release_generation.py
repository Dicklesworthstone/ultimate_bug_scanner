#!/usr/bin/env python3
"""Deterministic update transaction/fault tests, without network or live installs.

These unit fixtures are intentionally small. They supplement, not substitute
for, the released-v5.4.17 upgrade/real-scan cases in test_installed_contract.py.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/release_generation.py"
spec = importlib.util.spec_from_file_location("release_generation", SOURCE)
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)


def fixture_runner(version: str, assets: dict[str, bytes]) -> bytes:
    modules = []
    helpers = []
    for name, data in sorted(assets.items()):
        sha = hashlib.sha256(data).hexdigest()
        if name.startswith("ubs-") and name.endswith(".sh"):
            modules.append(f"  [{name[4:-3]}]='{sha}'")
        else:
            helpers.append(f"  ['{name}']='{sha}'")
    return ("#!/usr/bin/env bash\n" + f'UBS_VERSION="{version}"\n'
            + "UBS_RELEASE_GENERATIONS=1\ndeclare -A MODULE_CHECKSUMS=(\n"
            + "\n".join(modules) + "\n)\ndeclare -A HELPER_CHECKSUMS=(\n"
            + "\n".join(helpers) + "\n)\n").encode()


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
    while True:
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
        # Use a different candidate identity so it cannot select the first generation.
        self.candidate.write_bytes(self.candidate.read_bytes() + b"# different runner\n")
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


if __name__ == "__main__":
    unittest.main()
