#!/usr/bin/env python3
"""Issue #129: installed detection consumes only a checksum-verified contract.

The installed runner has no modules/ sibling and starts with an empty cache.
A file:// mirror supplies the real repository assets, with deterministic curl/
wget shims that refuse all network access. Only optional doctor tool probes are
stubbed; scans execute the real language modules with Rust builds disabled.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"
# modules/contract.json exactly as v5.4.17 shipped it (sha256 406ecd66...).
OLDER_CONTRACT = Path(__file__).resolve().parent / "fixtures" / "contract-v5.4.17.json"
# Byte-for-byte source-tag fixtures: v5.5.3 at 41a5b6d0b4d33d818d83afa997bf0c174faa8973;
# v5.5.26 at 43986ad8936c9319bc2040d85f9a0fec9e0cb586. Tests assert full SHA-256 pins.
V553_CONTRACT = OLDER_CONTRACT.with_name("contract-v5.5.3.json")
V5526_CONTRACT = OLDER_CONTRACT.with_name("contract-v5.5.26.json")

_generation_spec = importlib.util.spec_from_file_location(
    "installed_release_generation", REPO_ROOT / "scripts/release_generation.py")
generation = importlib.util.module_from_spec(_generation_spec)
_generation_spec.loader.exec_module(generation)

FETCH_SHIM = r'''#!/usr/bin/env python3
import os
import pathlib
import sys
import time
import urllib.parse
args = sys.argv[1:]
url = next((a for a in args if "://" in a), "")
out = None
for flag in ("-o", "-O"):
    if flag in args and args.index(flag) + 1 < len(args):
        out = args[args.index(flag) + 1]
with open(os.environ["CONTRACT_FETCH_LOG"], "a", encoding="utf-8") as log:
    log.write(url + "\n")
if not url.startswith("file://") or out is None:
    sys.exit(22)
try:
    source = pathlib.Path(urllib.parse.unquote(urllib.parse.urlparse(url).path))
    if source.name == os.environ.get("CONTRACT_BLOCK_ASSET"):
        pathlib.Path(os.environ["CONTRACT_BLOCK_READY"]).write_text("blocked")
        while not pathlib.Path(os.environ["CONTRACT_BLOCK_RELEASE"]).exists():
            time.sleep(0.02)
    if source.name == os.environ.get("CONTRACT_MISSING_ASSET"):
        sys.exit(22)
    data = source.read_bytes()
    if source.name == os.environ.get("CONTRACT_BAD_ASSET"):
        data += b"\nmaliciously modified transport bytes\n"
    pathlib.Path(out).write_bytes(data)
except OSError:
    sys.exit(22)
'''

# A protocol double for the external minisign executable. The updater must
# invoke it with the configured trusted key and the exact downloaded manifest;
# the tests do not claim to exercise minisign's cryptographic implementation.
SIGNATURE_SHIM = r'''#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import sys
args = sys.argv[1:]
try:
    manifest = Path(args[args.index("-Vm") + 1]).read_bytes()
    signature = Path(args[args.index("-x") + 1]).read_text().strip()
    key = args[args.index("-P") + 1]
except (OSError, ValueError, IndexError):
    raise SystemExit(1)
valid = key == "ubs-upgrade-test-trusted-key" and signature == hashlib.sha256(manifest).hexdigest()
raise SystemExit(0 if valid and os.environ.get("CONTRACT_BAD_SIGNATURE") != "1" else 1)
'''


class InstalledContract(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-installed-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runner = self.bin / "ubs"
        shutil.copy2(UBS_BIN, self.runner)
        self.runner.chmod(0o755)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.target = self.root / "project"
        self.target.mkdir()
        (self.target / "Cargo.toml").write_text(
            '[package]\nname="manifest_only"\nversion="0.0.0"\nedition="2021"\n',
            encoding="utf-8",
        )
        self.contract = (REPO_ROOT / "modules/contract.json").read_bytes()
        match = re.search(r'^UBS_VERSION="([^"]+)"', self.runner.read_text(), re.M)
        self.assertIsNotNone(match)
        self.mirror = self.root / "mirror"
        self.contract_sources = []
        for ref in (f"v{match.group(1)}", "main"):
            modules = self.mirror / ref / "modules"
            modules.mkdir(parents=True)
            for entry in (REPO_ROOT / "modules").iterdir():
                dest = modules / entry.name
                if entry.name == "contract.json":
                    dest.write_bytes(self.contract)
                    self.contract_sources.append(dest)
                else:
                    dest.symlink_to(entry, target_is_directory=entry.is_dir())
        for name in ("curl", "wget"):
            tool = self.bin / name
            tool.write_text(FETCH_SHIM, encoding="utf-8")
            tool.chmod(0o755)
        self.fetch_log = self.root / "fetch.log"
        self.env = os.environ.copy()
        # Tests must not inherit opt-outs or module/detection overrides.
        for name in tuple(self.env):
            if name.startswith("UBS_") or name in ("BASH_ENV", "ENV", "TOON_TRU_BIN", "PYTHONPATH"):
                self.env.pop(name)
        self.env.update({
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(self.root / "home"),
            "XDG_CACHE_HOME": str(self.root / "xdg-cache"),
            "XDG_CONFIG_HOME": str(self.root / "xdg-config"),
            "XDG_DATA_HOME": str(self.root / "xdg-data"),
            "NO_COLOR": "1",
            "UBS_ENABLE_AUTO_UPDATE": "0",
            "UBS_NO_AUTO_UPDATE": "1",
            "UBS_SKIP_RUST_BUILD": "1",
            "UBS_REPO_RAW_BASE": self.mirror.as_uri(),
            "CONTRACT_FETCH_LOG": str(self.fetch_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        Path(self.env["HOME"]).mkdir()
        self.assertFalse((self.bin / "modules").exists())
        self.assertEqual(list(self.cache.iterdir()), [])

    def run_ubs(self, *args: str, runner: Path | None = None,
                extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(runner or self.runner), *args, f"--module-dir={self.cache}", "--format=json"],
            cwd=self.root, env={**self.env, **(extra_env or {})}, capture_output=True,
            text=True, check=False, timeout=180,
        )

    def parsed_report(self, result: subprocess.CompletedProcess[str]) -> dict:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'Invalid scanner JSON: {exc}\n{result.stdout}\n{result.stderr}')

    def scanned_rust(self, result: subprocess.CompletedProcess[str]) -> dict:
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 3, output)
        self.assertNotIn("command not found", output)
        payload = self.parsed_report(result)
        self.assertNotEqual(payload.get("result"), "no-supported-languages", payload)
        self.assertIn("rust", {s.get("language") for s in payload.get("scanners", [])}, output)
        return payload

    def rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, output)
        self.assertIn("contract.json", output)
        self.assertIn("refusing to scan", output)
        self.assertNotIn("no-supported-languages", result.stdout)
        self.assertFalse((self.cache / "ubs-rust.sh").exists(), "module dispatched before verification")

    def doctor(self, *, fix: bool = False) -> tuple[subprocess.CompletedProcess[str], dict]:
        # Optional external encoders are unrelated to asset integrity. Their
        # probes may warn, but the doctor helper record itself must be exact.
        ast = self.bin / "ast-grep-probe"
        ast.write_text('#!/bin/sh\necho "ast-grep 0.41.0"\n', encoding="utf-8")
        ast.chmod(0o755)
        toon = self.bin / "toon-probe"
        toon.write_text('#!/bin/sh\necho "toon_rust 0.1.0 --encode --decode"\n', encoding="utf-8")
        toon.chmod(0o755)
        result = self.run_ubs("doctor", *( ["--fix"] if fix else []), extra_env={
            "UBS_AST_GREP_BIN": str(ast), "TOON_TRU_BIN": str(toon),
        })
        payload = self.parsed_report(result)
        checks = {item["id"]: item for item in payload["checks"]}
        self.assertIn("helper:contract.json", checks, result.stdout + result.stderr)
        return result, checks["helper:contract.json"]

    def test_cold_manifest_matches_checkout_then_works_offline(self) -> None:
        baseline = self.scanned_rust(self.run_ubs(str(self.target), runner=UBS_BIN))
        # A checkout may pre-cache helpers, so use a genuinely new module dir.
        self.cache = self.root / "cold-cache"
        self.cache.mkdir()
        installed = self.scanned_rust(self.run_ubs(str(self.target)))
        self.assertEqual(
            {s.get("language") for s in installed["scanners"]},
            {s.get("language") for s in baseline["scanners"]},
        )
        self.assertEqual((self.cache / "contract.json").read_bytes(), self.contract)
        self.scanned_rust(self.run_ubs(str(self.target), extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        }))
        _, check = self.doctor()
        self.assertEqual(check["status"], "ok", check)
        self.assertIn("checksum verified", check["detail"])

    def test_targeted_manifest_uses_verified_contract(self) -> None:
        self.scanned_rust(self.run_ubs(str(self.target / "Cargo.toml")))
        self.assertEqual((self.cache / "contract.json").read_bytes(), self.contract)

    def test_doctor_precaches_and_repairs_contract(self) -> None:
        _, check = self.doctor(fix=True)
        self.assertEqual(check["status"], "ok", check)
        manifest = generation.parse_manifest(self.runner.read_bytes())
        active = generation.generation_path(self.cache, manifest)
        generation.check_ready(active, manifest, complete=True)
        self.assertEqual((active / "contract.json").read_bytes(), self.contract)
        (active / "contract.json").write_bytes(b'{"modules":{}}\n')
        result = self.run_ubs("doctor")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("checksum mismatch", result.stderr)
        _, check = self.doctor(fix=True)
        self.assertEqual(check["status"], "ok", check)
        generation.check_ready(active, manifest, complete=True)
        self.assertEqual((active / "contract.json").read_bytes(), self.contract)

    def test_corrupt_cache_is_fatal_even_with_unverified_override(self) -> None:
        damaged = b'{"modules":{}}\n'
        (self.cache / "contract.json").write_bytes(damaged)
        for base in (self.mirror, self.root / "offline"):
            self.rejected(self.run_ubs(str(self.target), extra_env={
                "UBS_REPO_RAW_BASE": base.as_uri(), "UBS_ALLOW_UNVERIFIED_HELPERS": "1",
            }))
            self.assertEqual((self.cache / "contract.json").read_bytes(), damaged)

    def test_contract_left_by_an_earlier_release_is_refreshed(self) -> None:
        # Issue #174: `ubs --update` from 5.4.x replaces the runner but leaves
        # the cached contract of the old release; the first scan refreshes it.
        older = OLDER_CONTRACT.read_bytes()
        self.assertNotEqual(older, self.contract)
        (self.cache / "contract.json").write_bytes(older)
        result = self.run_ubs(str(self.target))
        self.scanned_rust(result)
        self.assertIn("is the v5.4.16 release's", result.stderr)
        manifest = generation.parse_manifest(self.runner.read_bytes())
        active = generation.generation_path(self.cache, manifest)
        generation.check_ready(active, manifest, complete=True)
        self.assertEqual((active / "contract.json").read_bytes(), self.contract)
        self.assertEqual((self.cache / "contract.json").read_bytes(), older)
        self.scanned_rust(self.run_ubs(str(self.target), extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        }))

    def test_earlier_release_contract_fails_closed_when_it_cannot_be_refreshed(self) -> None:
        older = OLDER_CONTRACT.read_bytes()
        (self.cache / "contract.json").write_bytes(older)
        self.rejected(self.run_ubs(str(self.target), extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        }))
        self.assertEqual((self.cache / "contract.json").read_bytes(), older)
        for source in self.contract_sources:
            source.write_bytes(b'{"modules":{}}\n')
        self.rejected(self.run_ubs(str(self.target)))
        self.assertEqual((self.cache / "contract.json").read_bytes(), older)

    def test_corrupt_downloads_and_empty_payloads_fail_closed(self) -> None:
        for damaged in (b'{"modules":{}}\n', b''):
            with self.subTest(payload=damaged):
                for source in self.contract_sources:
                    source.write_bytes(damaged)
                self.rejected(self.run_ubs(str(self.target)))
                self.assertFalse((self.cache / "contract.json").exists())

    def test_bad_release_only_recovers_with_exact_pinned_main(self) -> None:
        self.contract_sources[0].write_bytes(b'{"modules":{}}\n')
        self.scanned_rust(self.run_ubs(str(self.target)))
        self.assertEqual((self.cache / "contract.json").read_bytes(), self.contract)

    def test_bad_release_with_offline_main_is_not_an_offline_fallback(self) -> None:
        self.contract_sources[0].write_bytes(b'{"modules":{}}\n')
        self.contract_sources[1].rename(self.contract_sources[1].with_suffix(".parked"))
        self.rejected(self.run_ubs(str(self.target)))
        self.assertFalse((self.cache / "contract.json").exists())

    def test_checksum_tool_failure_is_fatal(self) -> None:
        (self.cache / "contract.json").write_bytes(self.contract)
        for name in ("sha256sum", "shasum", "openssl"):
            tool = self.bin / name
            tool.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            tool.chmod(0o755)
        self.rejected(self.run_ubs(str(self.target)))

    def test_existing_no_contract_fallback_unchanged_and_offline(self) -> None:
        path = REPO_ROOT / "test-suite/shareable/test_meta_runner_modes.py"
        spec = importlib.util.spec_from_file_location("ubs_meta_modes", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update(self.env)
            os.environ["UBS_REPO_RAW_BASE"] = (self.root / "offline").as_uri()
            module.check_detection_without_contract(self.root)
        finally:
            os.environ.clear()
            os.environ.update(original_env)
        # The shared scenario finishes by restoring an authentic contract and
        # proving the same two-language scan recovers. Preserve that final
        # recovery assertion, after its unavailable/tampered-asset controls.
        self.assertEqual((self.root / "installed_layout/moddir/contract.json").read_bytes(), self.contract)


class InstalledUpgrade(unittest.TestCase):
    """Exercise the shipped updater and scanner with isolated, real assets.

    Historical contract files are byte-for-byte release fixtures. The runners
    contain the current implementation with explicit old/target version labels
    and contract pins, so these regressions exercise the fix on every revision;
    they do not pretend the immutable old release contained the new updater.
    """

    setUp = InstalledContract.setUp
    parsed_report = InstalledContract.parsed_report

    def run(self, result=None):
        case_id = "issue199:" + self._testMethodName
        print(f"[{case_id}] RUN", flush=True)
        started = time.monotonic()
        self.commands = []
        result = result or self.defaultTestResult()
        failures = len(result.failures) + len(result.errors)
        skips = len(result.skipped)
        super().run(result)
        failed = len(result.failures) + len(result.errors) > failures
        status = "FAIL" if failed else "SKIP" if len(result.skipped) > skips else "PASS"
        artifact = REPO_ROOT / "test-suite/artifacts/issue199" / self._testMethodName
        artifact.mkdir(parents=True, exist_ok=True)
        for stream in ("stdout", "stderr"):
            text = "\n".join(f"$ {command!r} [exit {item.returncode}]\n{getattr(item, stream)}"
                             for command, item in self.commands)
            (artifact / (stream + ".log")).write_text(text)
            if failed:
                print(f"[{case_id}] {stream}:\n{text}", flush=True)
        print(f"[{case_id}] {status} ({time.monotonic() - started:.3f}s)", flush=True)
        return result

    def run_ubs(self, *args: str, **kwargs) -> subprocess.CompletedProcess[str]:
        result = InstalledContract.run_ubs(self, *args, **kwargs)
        self.commands.append((list(args), result))
        return result

    def populate_legacy_cache(self, *, contract: bytes) -> None:
        # Cron has no --module-dir argument. Use precisely the normal default
        # location under this test user's XDG_DATA_HOME.
        self.cache = Path(self.env["XDG_DATA_HOME"]) / "ubs/modules"
        shutil.copytree(REPO_ROOT / "modules", self.cache)
        (self.cache / "contract.json").write_bytes(contract)

    def release(self, *, old_version: str = "5.5.3", target_version: str = "5.5.26",
                old_contract: bytes | None = None) -> bytes:
        old_contract = old_contract if old_contract is not None else V553_CONTRACT.read_bytes()
        self.populate_legacy_cache(contract=old_contract)
        source = UBS_BIN.read_text()
        current_version = re.search(r'^UBS_VERSION="([^"]+)"$', source, re.M).group(1)
        candidate = source.replace(f'UBS_VERSION="{current_version}"', f'UBS_VERSION="{target_version}"')
        installed = source.replace(f'UBS_VERSION="{current_version}"', f'UBS_VERSION="{old_version}"')
        installed = installed.replace(
            f"['contract.json']='{hashlib.sha256(self.contract).hexdigest()}'",
            f"['contract.json']='{hashlib.sha256(old_contract).hexdigest()}'",
        )
        self.runner.write_text(installed)
        self.runner.chmod(0o755)
        self.before_runner = self.runner.read_bytes()
        self.before_cache = self.cache_snapshot()
        target_modules = self.mirror / f"v{target_version}/modules"
        if not target_modules.exists():
            shutil.copytree(REPO_ROOT / "modules", target_modules)
        self.release_dir = self.root / "signed release"
        self.release_dir.mkdir()
        (self.release_dir / "ubs").write_text(candidate)
        shutil.copy2(REPO_ROOT / "ubs-daemon", self.release_dir / "ubs-daemon")
        self.sign_release()
        verifier = self.bin / "minisign"
        verifier.write_text(SIGNATURE_SHIM)
        verifier.chmod(0o755)
        self.env.update(UBS_RELEASE_BASE=self.release_dir.as_uri(),
                        UBS_MINISIGN_PUBKEY="ubs-upgrade-test-trusted-key")
        return candidate.encode()

    def sign_release(self) -> None:
        manifest = "".join(f"{hashlib.sha256((self.release_dir / name).read_bytes()).hexdigest()}  {name}\n"
                           for name in ("ubs", "ubs-daemon"))
        (self.release_dir / "SHA256SUMS").write_text(manifest)
        (self.release_dir / "SHA256SUMS.minisig").write_text(hashlib.sha256(manifest.encode()).hexdigest())

    def managed_release(self, *, change_helper: bool = False) -> tuple[bytes, set[str]]:
        """Stage a later release above a fresh, generation-only installation.

        The raw origin deliberately contains only changed assets. Unchanged
        authentic bytes exist exclusively in the currently leased generation,
        never in the legacy root or a caller-provided local source directory.
        """
        self.cache = Path(self.env["XDG_DATA_HOME"]) / "ubs/modules"
        self.cache.mkdir(parents=True)
        self.before_runner = self.runner.read_bytes()
        self.previous_manifest = generation.parse_manifest(self.before_runner)
        self.previous_generation = generation.prepare(
            self.runner, self.cache, "https://offline.invalid", allow_override=False,
            local_source=REPO_ROOT / "modules",
        )
        self.before_cache = self.cache_snapshot()
        self.assertEqual(self.before_cache, {})
        version_parts = self.previous_manifest.version.split(".")
        version_parts[-1] = str(int(version_parts[-1]) + 1)
        next_version = ".".join(version_parts)
        candidate = self.before_runner.replace(
            f'UBS_VERSION="{self.previous_manifest.version}"'.encode(),
            f'UBS_VERSION="{next_version}"'.encode(),
        )
        changed = {}
        if change_helper:
            relative = "helpers/ubs_core/cache.py"
            changed[relative] = (REPO_ROOT / "modules" / relative).read_bytes() + b"\n# Next-release fixture.\n"
            library = (REPO_ROOT / "modules/lib/ubs-common.sh").read_bytes()
            changed["lib/ubs-common.sh"] = library.replace(
                self.previous_manifest.assets[relative].encode(),
                hashlib.sha256(changed[relative]).hexdigest().encode(),
            )
            old_library_pin = self.previous_manifest.assets["lib/ubs-common.sh"]
            new_library_pin = hashlib.sha256(changed["lib/ubs-common.sh"]).hexdigest()
            for name in self.previous_manifest.assets:
                if re.fullmatch(r"ubs-[a-z]+\.sh", name):
                    changed[name] = (REPO_ROOT / "modules" / name).read_bytes().replace(
                        f'UBS_LIB_CHECKSUM="{old_library_pin}"'.encode(),
                        f'UBS_LIB_CHECKSUM="{new_library_pin}"'.encode(),
                    )
            for name, data in changed.items():
                key = name[4:-3] if re.fullmatch(r"ubs-[a-z]+\.sh", name) else f"'{name}'"
                old_pin = f"[{key}]='{self.previous_manifest.assets[name]}'".encode()
                new_pin = f"[{key}]='{hashlib.sha256(data).hexdigest()}'".encode()
                self.assertEqual(candidate.count(old_pin), 1, name)
                candidate = candidate.replace(old_pin, new_pin)
        self.next_modules = self.mirror / f"v{next_version}/modules"
        for name, data in changed.items():
            destination = self.next_modules / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        self.release_dir = self.root / "signed release"
        self.release_dir.mkdir()
        (self.release_dir / "ubs").write_bytes(candidate)
        shutil.copy2(REPO_ROOT / "ubs-daemon", self.release_dir / "ubs-daemon")
        self.sign_release()
        verifier = self.bin / "minisign"
        verifier.write_text(SIGNATURE_SHIM)
        verifier.chmod(0o755)
        self.env.update(UBS_RELEASE_BASE=self.release_dir.as_uri(),
                        UBS_MINISIGN_PUBKEY="ubs-upgrade-test-trusted-key")
        (self.target / "src").mkdir()
        (self.target / "src/main.rs").write_text("fn main() {}\n")
        return candidate, set(changed)

    def cache_snapshot(self) -> dict[str, str]:
        return {str(path.relative_to(self.cache)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.cache.rglob("*")
                if path.is_file() and ".ubs-releases" not in path.relative_to(self.cache).parts}

    def assert_legacy_intact(self) -> None:
        self.assertEqual(self.cache_snapshot(), self.before_cache)

    def active_generation(self) -> Path:
        manifest = generation.parse_manifest(self.runner.read_bytes())
        target = generation.generation_path(self.cache, manifest)
        generation.check_ready(target, manifest, complete=True)
        return target

    def update(self, *, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        # Exactly the arguments written by the unattended installer cron job.
        command = [str(self.runner), "--update", "--quiet", "--non-interactive"]
        result = subprocess.run(command, cwd=self.root, env={**self.env, **(extra_env or {})},
                                capture_output=True, text=True, timeout=180)
        self.commands.append((command, result))
        return result

    def scan_usable(self, *, offline: bool = True) -> dict:
        result = self.run_ubs(str(self.target), "--ci", extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        } if offline else {})
        output = result.stdout + result.stderr
        self.assertIn(result.returncode, (0, 1), output)
        payload = self.parsed_report(result)
        self.assertEqual(payload.get("status"), "ok", output)
        self.assertIn("rust", {s.get("language") for s in payload.get("scanners", [])}, output)
        return payload

    def managed_refresh_fixture(self) -> tuple[Path, generation.Manifest]:
        self.cache = Path(self.env["XDG_DATA_HOME"]) / "ubs/modules"
        self.cache.mkdir(parents=True)
        manifest = generation.parse_manifest(self.runner.read_bytes())
        target = generation.prepare(self.runner, self.cache, self.mirror.as_uri(),
                                    allow_override=True, local_source=REPO_ROOT / "modules")
        (self.target / "src").mkdir()
        (self.target / "src/main.rs").write_text("fn main() {}\n")
        return target, manifest

    def assert_flat_refresh_transaction(self, contract: bytes) -> None:
        self.populate_legacy_cache(contract=contract)
        self.before_cache = self.cache_snapshot()
        identities = {name: (self.cache / name).stat() for name in self.before_cache}
        before_runner = self.runner.read_bytes()
        manifest = generation.parse_manifest(before_runner)
        target = generation.generation_path(self.cache, manifest)
        self.assertFalse((self.cache / generation.GENERATION_DIRECTORY).exists())
        (self.target / "src").mkdir()
        (self.target / "src/main.rs").write_text("fn main() {}\n")
        refreshed = self.run_ubs("--update-modules", str(self.target), "--ci")
        self.assertIn(refreshed.returncode, (0, 1), refreshed.stdout + refreshed.stderr)
        self.assertEqual(self.parsed_report(refreshed).get("status"), "ok")
        self.assertTrue((target / generation.READY_FILE).is_file(),
                        "standalone installed refresh did not publish a complete generation")
        generation.check_ready(target, manifest, complete=True)
        self.assertEqual(self.runner.read_bytes(), before_runner)
        self.assert_legacy_intact()
        for name, before in identities.items():
            after = (self.cache / name).stat()
            self.assertTrue(os.path.samestat(before, after), name)
            self.assertEqual((before.st_mode, before.st_mtime_ns, before.st_ctime_ns),
                             (after.st_mode, after.st_mtime_ns, after.st_ctime_ns), name)
        expected = {f"{self.mirror.as_uri()}/v{manifest.version}/modules/{name}" for name in manifest.assets}
        requested = self.fetch_log.read_text().splitlines()
        self.assertEqual(set(requested), expected)
        self.assertEqual(len(requested), len(expected))
        self.scan_usable()

    def test_flat_installed_refresh_preserves_legacy_files_and_publishes_complete_generation(self) -> None:
        self.assert_flat_refresh_transaction(self.contract)

    def test_v553_flat_cache_refresh_uses_one_complete_transaction_before_detection(self) -> None:
        self.assert_flat_refresh_transaction(V553_CONTRACT.read_bytes())

    def test_failed_flat_refresh_preserves_working_legacy_cache_and_publishes_no_generation(self) -> None:
        self.populate_legacy_cache(contract=self.contract)
        self.before_cache = self.cache_snapshot()
        identities = {name: (self.cache / name).stat() for name in self.before_cache}
        manifest = generation.parse_manifest(self.runner.read_bytes())
        target = generation.generation_path(self.cache, manifest)
        (self.target / "src").mkdir()
        (self.target / "src/main.rs").write_text("fn main() {}\n")
        self.scan_usable()
        for override in ("CONTRACT_MISSING_ASSET", "CONTRACT_BAD_ASSET"):
            with self.subTest(transport=override):
                refreshed = self.run_ubs("--update-modules", str(self.target), "--ci",
                                         extra_env={override: "ubs-swift.sh"})
                self.assertEqual(refreshed.returncode, 2, refreshed.stdout + refreshed.stderr)
                self.assertIn("ubs-swift.sh", refreshed.stderr)
                self.assertFalse(target.exists(), "failed refresh published an active generation")
                self.assert_legacy_intact()
                for name, before in identities.items():
                    after = (self.cache / name).stat()
                    self.assertTrue(os.path.samestat(before, after), name)
                    self.assertEqual((before.st_mode, before.st_mtime_ns, before.st_ctime_ns),
                                     (after.st_mode, after.st_mtime_ns, after.st_ctime_ns), name)
                self.scan_usable()

    @unittest.skipUnless(os.name == "posix", "POSIX executable permissions and process groups")
    def test_managed_refresh_never_publishes_a_nonexecutable_module(self) -> None:
        target, manifest = self.managed_refresh_fixture()
        self.scan_usable()
        module = target / "ubs-rust.sh"
        marker = self.root / "nonexecutable-publication"
        real_mv = shutil.which("mv")
        self.assertIsNotNone(real_mv)
        shim = self.bin / "mv"
        # Exercise the legacy publication boundary with the real mv. A process
        # interruption after publishing a nonexecutable module must not strand
        # a complete managed installation. Safe publication never triggers it.
        shim.write_text(r'''#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys
args = sys.argv[1:]
result = subprocess.run([os.environ["REFRESH_REAL_MV"], *args], check=False)
if result.returncode == 0 and args and args[-1] == os.environ["REFRESH_MODULE"]:
    if not os.access(args[-1], os.X_OK):
        Path(os.environ["REFRESH_UNSAFE_MARKER"]).write_text(oct(Path(args[-1]).stat().st_mode & 0o777))
        os.killpg(os.getpgrp(), signal.SIGKILL)
raise SystemExit(result.returncode)
''')
        shim.chmod(0o755)
        self.env.update(REFRESH_REAL_MV=real_mv, REFRESH_MODULE=str(module),
                        REFRESH_UNSAFE_MARKER=str(marker))
        command = [str(self.runner), "--update-modules", "--only=rust", "--ci", "--format=json",
                   f"--module-dir={self.cache}", str(self.target)]
        refreshed = subprocess.run(
            command, cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=180, start_new_session=True,
        )
        self.commands.append((command, refreshed))
        self.assertFalse(marker.exists(), "refresh published a nonexecutable module before interruption")
        self.assertIn(refreshed.returncode, (0, 1), refreshed.stdout + refreshed.stderr)
        self.assertEqual(self.parsed_report(refreshed).get("status"), "ok")
        generation.check_ready(target, manifest, complete=True)
        self.scan_usable()

    @unittest.skipUnless(os.name == "posix", "POSIX executable permissions")
    def test_managed_refresh_downloads_every_asset_and_repairs_module_permissions(self) -> None:
        target, manifest = self.managed_refresh_fixture()
        identity = target.stat().st_ino
        (target / "ubs-rust.sh").chmod(0o600)
        refused = self.run_ubs(str(self.target), "--ci")
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
        self.assertIn("not readable/executable", refused.stderr)
        refreshed = self.run_ubs("--update-modules", str(self.target), "--ci")
        self.assertIn(refreshed.returncode, (0, 1), refreshed.stdout + refreshed.stderr)
        self.assertEqual(self.parsed_report(refreshed).get("status"), "ok")
        self.assertEqual(target.stat().st_ino, identity)
        expected = {f"{self.mirror.as_uri()}/v{manifest.version}/modules/{name}" for name in manifest.assets}
        requested = self.fetch_log.read_text().splitlines()
        self.assertEqual(set(requested), expected)
        self.assertEqual(len(requested), len(expected))
        generation.check_ready(target, manifest, complete=True)
        self.scan_usable()

    def test_managed_refresh_late_download_failure_or_tampering_preserves_active_files(self) -> None:
        target, manifest = self.managed_refresh_fixture()
        identities = {name: (target / name).stat() for name in (*manifest.assets, generation.READY_FILE)}
        for override in ("CONTRACT_MISSING_ASSET", "CONTRACT_BAD_ASSET"):
            with self.subTest(transport=override):
                refreshed = self.run_ubs("--update-modules", str(self.target), "--ci",
                                         extra_env={override: "ubs-swift.sh"})
                self.assertEqual(refreshed.returncode, 2, refreshed.stdout + refreshed.stderr)
                self.assertIn("ubs-swift.sh", refreshed.stderr)
                for name, before in identities.items():
                    after = (target / name).stat()
                    self.assertTrue(os.path.samestat(before, after), name)
                    self.assertEqual((before.st_mode, before.st_mtime_ns, before.st_ctime_ns),
                                     (after.st_mode, after.st_mtime_ns, after.st_ctime_ns), name)
                generation.check_ready(target, manifest, complete=True)
                self.scan_usable()

    @unittest.skipUnless(os.name == "posix", "POSIX process-group interruption")
    def test_interrupted_managed_refresh_preserves_concurrent_scans_and_retry(self) -> None:
        target, manifest = self.managed_refresh_fixture()
        ready = self.root / "refresh-download-ready"
        release = self.root / "refresh-download-release"
        command = [str(self.runner), "--update-modules", "--ci", "--format=json",
                   f"--module-dir={self.cache}", str(self.target)]
        process = subprocess.Popen(
            command, cwd=self.root, env={**self.env, "CONTRACT_BLOCK_ASSET": "cache.py",
                                        "CONTRACT_BLOCK_READY": str(ready),
                                        "CONTRACT_BLOCK_RELEASE": str(release)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 30
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "refresh did not reach the controlled download boundary")
            generation.check_ready(target, manifest, complete=True)
            self.scan_usable()
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=10)
            self.commands.append((command, subprocess.CompletedProcess(command, process.returncode, stdout, stderr)))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
        generation.check_ready(target, manifest, complete=True)
        self.scan_usable()
        retried = self.run_ubs("--update-modules", str(self.target), "--ci")
        self.assertIn(retried.returncode, (0, 1), retried.stdout + retried.stderr)
        self.assertEqual(self.parsed_report(retried).get("status"), "ok")
        generation.check_ready(target, manifest, complete=True)
        self.scan_usable()

    def test_next_managed_release_reuses_unchanged_assets_with_module_origin_offline(self) -> None:
        candidate, changed = self.managed_release()
        self.assertEqual(changed, set())
        before = self.scan_usable()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.assertNotEqual(self.active_generation(), self.previous_generation)
        generation.check_ready(self.previous_generation, self.previous_manifest, complete=True)
        after = self.scan_usable()
        self.assertEqual(before["totals"], after["totals"])
        self.assertGreaterEqual(after["totals"]["files"], 1)
        self.assertFalse(any("/modules/" in url for url in self.fetch_log.read_text().splitlines()))
        self.assert_legacy_intact()

    def test_next_managed_release_downloads_only_changed_authenticated_assets(self) -> None:
        candidate, changed = self.managed_release(change_helper=True)
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        requested = [url.split("/modules/", 1)[1] for url in self.fetch_log.read_text().splitlines()
                     if "/modules/" in url]
        self.assertCountEqual(requested, changed)
        self.active_generation()
        generation.check_ready(self.previous_generation, self.previous_manifest, complete=True)
        self.scan_usable()
        self.assert_legacy_intact()

    def test_next_managed_release_never_reuses_modified_old_helper_and_recovers(self) -> None:
        candidate, _ = self.managed_release()
        relative = "helpers/ubs_core/cache.py"
        sentinel = self.root / "modified-old-helper-executed"
        malicious = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n".encode()
        (self.previous_generation / relative).write_bytes(malicious)
        failed = self.update()
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        target_manifest = generation.parse_manifest(candidate)
        self.assertFalse(generation.generation_path(self.cache, target_manifest).exists())
        self.assertFalse(sentinel.exists())
        source = self.next_modules / relative
        source.parent.mkdir(parents=True)
        source.write_bytes((REPO_ROOT / "modules" / relative).read_bytes())
        recovered = self.update()
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.scan_usable()
        self.assertFalse(sentinel.exists())
        self.assertEqual((self.previous_generation / relative).read_bytes(), malicious)
        self.assert_legacy_intact()

    def test_next_managed_release_preserves_concurrent_old_generation_scan(self) -> None:
        candidate, _ = self.managed_release(change_helper=True)
        blocked = self.root / "next-generation-download-blocked"
        release = self.root / "next-generation-download-release"
        command = [str(self.runner), "--update", "--quiet", "--non-interactive"]
        updater = subprocess.Popen(
            command, cwd=self.root, env={**self.env, "CONTRACT_BLOCK_ASSET": "cache.py",
                                        "CONTRACT_BLOCK_READY": str(blocked),
                                        "CONTRACT_BLOCK_RELEASE": str(release)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            deadline = time.monotonic() + 15
            while not blocked.exists() and updater.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(blocked.exists(), "updater never reached the changed-asset download")
            self.assertEqual(self.runner.read_bytes(), self.before_runner)
            self.scan_usable()
            generation.check_ready(self.previous_generation, self.previous_manifest, complete=True)
            release.write_text("continue")
            stdout, stderr = updater.communicate(timeout=90)
            result = subprocess.CompletedProcess(command, updater.returncode, stdout, stderr)
            self.commands.append((command, result))
            self.assertEqual(updater.returncode, 0, stdout + stderr)
            self.assertEqual(self.runner.read_bytes(), candidate)
            self.active_generation()
            self.scan_usable()
            generation.check_ready(self.previous_generation, self.previous_manifest, complete=True)
        finally:
            release.write_text("continue")
            if updater.poll() is None:
                updater.kill()
            updater.communicate(timeout=10)

    def test_v553_to_v5526_unattended_update_verifies_all_assets_before_success(self) -> None:
        self.assertEqual(hashlib.sha256(V553_CONTRACT.read_bytes()).hexdigest(),
                         "b3fee512c49997b09cb12faf749d350fdcbed8583f39e0c19340557afb14ecaa")
        self.assertEqual(hashlib.sha256(V5526_CONTRACT.read_bytes()).hexdigest(),
                         "90b82afcc916b8f4608f1561be59fc874228028c40e957b42fba2791991ba970")
        candidate = self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.assertEqual((self.active_generation() / "contract.json").read_bytes(), self.contract)
        self.assert_legacy_intact()
        self.scan_usable()

    def test_older_supported_release_update_keeps_its_cache_available(self) -> None:
        candidate = self.release(old_version="5.4.17", old_contract=OLDER_CONTRACT.read_bytes())
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.assert_legacy_intact()
        self.scan_usable()

    @unittest.skipUnless(shutil.which("ast-grep"), "ast-grep is required for the real pre-commit scan")
    def test_unattended_upgrade_leaves_real_precommit_hook_usable_offline(self) -> None:
        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.active_generation()
        self.env.update(UBS_TEST_INSTALLED_RUNNER=str(self.runner),
                        UBS_REPO_RAW_BASE=(self.root / "offline").as_uri())
        source = self.target / "src/main.rs"
        source.parent.mkdir()
        source.write_text("fn main() {}\n")
        for arguments in (("init", "-b", "main"),
                          ("config", "user.name", "UBS upgrade regression"),
                          ("config", "user.email", "upgrade-test@example.invalid"),
                          ("add", "Cargo.toml", "src/main.rs")):
            result = subprocess.run(["git", *arguments], cwd=self.target, env=self.env,
                                    capture_output=True, text=True, check=False, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        hook = self.target / ".git/hooks/pre-commit"
        hook.write_text('#!/usr/bin/env bash\nexec "$UBS_TEST_INSTALLED_RUNNER" --staged --fail-on-warning --ci --format=json\n')
        hook.chmod(0o755)
        command = ["git", "-c", "commit.gpgsign=false", "commit", "-m", "clean change after unattended upgrade"]
        result = subprocess.run(command, cwd=self.target, env=self.env,
                                capture_output=True, text=True, check=False, timeout=180)
        self.commands.append((command, result))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"rust"', result.stdout + result.stderr)
        self.assertNotIn("refusing to scan", result.stdout + result.stderr)

    def test_known_v553_cache_left_by_old_updater_migrates_on_real_scan(self) -> None:
        self.populate_legacy_cache(contract=V553_CONTRACT.read_bytes())
        self.before_cache = self.cache_snapshot()
        self.scan_usable(offline=False)
        self.active_generation()
        self.assert_legacy_intact()
        self.scan_usable()

    def test_modified_historical_contract_is_not_authorized_as_an_upgrade(self) -> None:
        damaged = V553_CONTRACT.read_bytes() + b"\n"
        self.populate_legacy_cache(contract=damaged)
        self.before_cache = self.cache_snapshot()
        result = self.run_ubs(str(self.target), "--ci")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("contract.json", result.stderr)
        self.assert_legacy_intact()
        self.assertFalse((self.cache / ".ubs-releases").exists())
        self.assertFalse(self.fetch_log.exists(), "unknown contract triggered network repair")

    def test_migration_never_executes_modified_cached_modules_or_helpers(self) -> None:
        self.populate_legacy_cache(contract=V553_CONTRACT.read_bytes())
        marker = self.root / "unverified-code-executed"
        (self.cache / "ubs-rust.sh").write_text(
            f"#!/bin/sh\nprintf 'executed' > '{marker}'\nexit 0\n")
        (self.cache / "helpers/ubs_core/__init__.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
        self.before_cache = self.cache_snapshot()
        self.scan_usable(offline=False)
        self.active_generation()
        self.assertFalse(marker.exists(), "unverified cached code executed during migration")
        self.assert_legacy_intact()

    def test_missing_download_preserves_working_installation_and_retry_recovers(self) -> None:
        candidate = self.release()
        result = self.update(extra_env={"CONTRACT_MISSING_ASSET": "contract.json"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Updated successfully", result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        self.scan_usable()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.scan_usable()

    def test_tampered_download_cannot_activate_a_partial_cache(self) -> None:
        self.release()
        result = self.update(extra_env={"CONTRACT_BAD_ASSET": "contract.json"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("checksum", result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        self.scan_usable()

    def test_late_helper_failure_cannot_publish_the_already_staged_contract(self) -> None:
        candidate = self.release()
        relative = "helpers/ubs_core/__init__.py"
        helper = self.cache / relative
        before = helper.read_bytes()
        older = before + b"\n# older, independently pinned helper build\n"
        helper.write_bytes(older)
        runner = self.runner.read_text().replace(
            f"['{relative}']='{hashlib.sha256(before).hexdigest()}'",
            f"['{relative}']='{hashlib.sha256(older).hexdigest()}'")
        self.runner.write_text(runner)
        self.before_runner = self.runner.read_bytes()
        self.before_cache = self.cache_snapshot()
        result = self.update(extra_env={"CONTRACT_MISSING_ASSET": "__init__.py"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        self.scan_usable()
        urls = self.fetch_log.read_text().splitlines()
        self.assertTrue(any(url.endswith("/contract.json") for url in urls), urls)
        self.assertTrue(any(url.endswith("/helpers/ubs_core/__init__.py") for url in urls), urls)
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.scan_usable()

    def test_bad_signature_prevents_runner_and_module_downloads(self) -> None:
        self.release()
        result = self.update(extra_env={"CONTRACT_BAD_SIGNATURE": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        urls = self.fetch_log.read_text().splitlines()
        self.assertTrue(urls)
        self.assertTrue(all(url.endswith(("/SHA256SUMS", "/SHA256SUMS.minisig")) for url in urls), urls)

    def real_signer(self, name: str = "trusted") -> tuple[str, Path]:
        executable = shutil.which("minisign")
        if executable is None:
            self.skipTest("minisign is required for real cryptographic signature tests")
        # Replace only this test's protocol double, never a system executable.
        shutil.copy2(executable, self.bin / "minisign")
        secret = self.root / f"{name}.key"
        public = self.root / f"{name}.pub"
        result = subprocess.run([executable, "-G", "-W", "-p", str(public), "-s", str(secret)],
                                capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return public.read_text().splitlines()[-1], secret

    def sign_with_real_key(self, secret: Path) -> None:
        result = subprocess.run([str(self.bin / "minisign"), "-S", "-s", str(secret),
                                 "-m", str(self.release_dir / "SHA256SUMS"),
                                 "-x", str(self.release_dir / "SHA256SUMS.minisig")],
                                capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_minisign_authenticated_upgrade_and_offline_scan(self) -> None:
        candidate = self.release()
        public, secret = self.real_signer()
        self.env["UBS_MINISIGN_PUBKEY"] = public
        self.sign_with_real_key(secret)
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.scan_usable()

    def test_attacker_signed_matching_checksums_do_not_authorize_an_update(self) -> None:
        self.release()
        trusted, _ = self.real_signer()
        self.env["UBS_MINISIGN_PUBKEY"] = trusted
        _, attacker_secret = self.real_signer("attacker")
        runner = self.release_dir / "ubs"
        runner.write_bytes(runner.read_bytes() + b"\n# attacker-controlled release payload\n")
        self.sign_release()
        self.sign_with_real_key(attacker_secret)
        result = self.update()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("signature", result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()

    def test_unconfigured_key_uses_published_trust_anchor_and_rejects_test_signer(self) -> None:
        self.release()
        _, secret = self.real_signer()
        self.sign_with_real_key(secret)
        self.env.pop("UBS_MINISIGN_PUBKEY")
        result = self.update()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("signature", result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()

    def test_missing_signature_cannot_fall_back_to_matching_checksums(self) -> None:
        self.release()
        result = self.update(extra_env={"CONTRACT_MISSING_ASSET": "SHA256SUMS.minisig"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()

    def test_missing_verifier_fails_closed_before_publishing(self) -> None:
        self.release()
        restricted = self.root / "no-verifier-bin"
        restricted.mkdir()
        required = ("bash", "env", "python3", "dirname", "basename", "date", "mkdir", "mktemp", "cat",
                    "grep", "head", "tail", "awk", "sed", "cut", "tr", "stat", "readlink",
                    "uname", "id", "wc", "cp", "mv", "rm", "rmdir", "chmod", "sha256sum",
                    "shasum", "openssl", "jq", "git", "rg", "sort", "find", "sleep")
        for name in required:
            executable = shutil.which(name)
            if executable is not None:
                (restricted / name).symlink_to(executable)
        for name in ("curl", "wget"):
            (restricted / name).symlink_to(self.bin / name)
        result = self.update(extra_env={"PATH": str(restricted)})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("minisign", result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()

    def test_authenticated_manifest_with_ambiguous_runner_entry_is_rejected(self) -> None:
        self.release()
        manifest = (self.release_dir / "SHA256SUMS").read_bytes()
        runner_row = next(row for row in manifest.splitlines(keepends=True) if row.endswith(b"  ubs\n"))
        ambiguous = manifest + runner_row
        (self.release_dir / "SHA256SUMS").write_bytes(ambiguous)
        (self.release_dir / "SHA256SUMS.minisig").write_text(hashlib.sha256(ambiguous).hexdigest())
        result = self.update()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()

    def test_target_without_generation_support_cannot_break_working_scans(self) -> None:
        candidate = self.release()
        self.assertIn(b"UBS_RELEASE_GENERATIONS=1\n", candidate)
        (self.release_dir / "ubs").write_bytes(candidate.replace(b"UBS_RELEASE_GENERATIONS=1\n", b""))
        self.sign_release()
        result = self.update()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        self.scan_usable()

    def test_same_version_update_completes_a_runner_only_installation(self) -> None:
        candidate = self.release(old_version="5.5.26")
        # Model the old updater's result: the new runner is already installed,
        # but its predecessor's old contract and modules are still cached.
        self.runner.write_bytes(candidate)
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.active_generation()
        self.assert_legacy_intact()
        self.scan_usable()

    def test_completed_generation_rejects_contract_tampering_offline(self) -> None:
        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.active_generation()
        (target / "contract.json").write_bytes(V553_CONTRACT.read_bytes())
        result = self.run_ubs(str(self.target), "--ci", extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        })
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual((target / "contract.json").read_bytes(), V553_CONTRACT.read_bytes())

    def test_completed_generation_rejects_unpinned_python_startup_offline(self) -> None:
        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.active_generation()
        manifest = generation.parse_manifest(self.runner.read_bytes())
        marker = self.root / "unpinned-startup-executed"
        (target / "helpers/sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
        # This attack leaves every authenticated source file unchanged.
        for relative, expected in manifest.assets.items():
            self.assertEqual(hashlib.sha256((target / relative).read_bytes()).hexdigest(), expected)
        result = self.run_ubs(str(self.target), "--ci", extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        })
        self.assertFalse(marker.exists(), "scan executed an unpinned Python startup file")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_completed_generation_rejects_forged_valid_timestamp_bytecode(self) -> None:
        import marshal
        import struct

        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.active_generation()
        source = target / "helpers/ubs_core/__init__.py"
        original = source.read_bytes()
        info = source.stat()
        marker = self.root / "forged-bytecode-executed"
        payload = source.read_text() + (
            f"\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
        bytecode = Path(importlib.util.cache_from_source(str(source)))
        bytecode.parent.mkdir()
        # Supply the unchanged source's real timestamp and length. Python's
        # ordinary bytecode freshness check therefore accepts this payload,
        # even when PYTHONDONTWRITEBYTECODE disables new cache writes.
        bytecode.write_bytes(importlib.util.MAGIC_NUMBER
                             + struct.pack("<III", 0, int(info.st_mtime), info.st_size)
                             + marshal.dumps(compile(payload, str(source), "exec")))
        result = self.run_ubs(str(self.target), "--ci", extra_env={
            "UBS_REPO_RAW_BASE": (self.root / "offline").as_uri(),
        })
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse(marker.exists(), "scan loaded unauthenticated cached bytecode")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_repeated_scans_work_without_inherited_bytecode_suppression(self) -> None:
        # Real cron and Git hook environments need not contain this setting.
        # Remove it from the actual subprocess environment, not just its value.
        self.env.pop("PYTHONDONTWRITEBYTECODE", None)
        self.assertNotIn("PYTHONDONTWRITEBYTECODE", self.env)
        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.active_generation()
        for _ in range(2):
            self.scan_usable()
            self.active_generation()
        self.assertEqual(list(target.rglob("__pycache__")), [])
        self.assertEqual(list(target.rglob("*.pyc")), [])

    def test_doctor_repairs_unpinned_startup_without_executing_quarantine(self) -> None:
        self.env.pop("PYTHONDONTWRITEBYTECODE", None)
        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.active_generation()
        marker = self.root / "quarantined-startup-executed"
        payload = (f"from pathlib import Path\n"
                   f"Path({str(marker)!r}).write_text('executed')\n").encode()
        injected = target / "helpers/sitecustomize.py"
        injected.write_bytes(payload)

        self.env["UBS_REPO_RAW_BASE"] = (self.root / "offline").as_uri()
        result, check = InstalledContract.doctor(self, fix=True)
        self.assertFalse(marker.exists(), "doctor --fix executed unauthenticated startup code")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(check["status"], "ok", check)
        repaired = self.active_generation()
        self.assertFalse((repaired / "helpers/sitecustomize.py").exists())
        quarantined = [path for path in target.parent.rglob("sitecustomize.py")
                       if repaired not in path.parents]
        self.assertEqual(len(quarantined), 1, "repair must retain the unexpected bytes outside the generation")
        self.assertEqual(quarantined[0].read_bytes(), payload)
        self.scan_usable()
        self.assertFalse(marker.exists(), "scan imported the quarantined startup file")

    def test_doctor_never_imports_tampered_helpers_and_explicit_repair_recovers(self) -> None:
        self.release()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.active_generation()
        marker = self.root / "unverified-doctor-code-executed"
        (target / "helpers/ubs_core/__init__.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
        result = self.run_ubs("doctor")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("checksum", result.stderr)
        self.assertFalse(marker.exists(), "doctor imported the unverified cache statistics package")
        _, check = InstalledContract.doctor(self, fix=True)
        self.assertEqual(check["status"], "ok", check)
        self.active_generation()
        self.assertFalse(marker.exists(), "doctor --fix executed the damaged helper")
        self.scan_usable()

    def test_doctor_rejects_tampered_adjacent_helpers_before_import(self) -> None:
        # Legacy standalone installations may have modules/ beside the runner
        # as well as an independent XDG cache. Diagnose the selected siblings,
        # not merely the healthy helpers in MODULE_DIR.
        self.populate_legacy_cache(contract=self.contract)
        siblings = self.bin / "modules/helpers"
        shutil.copytree(REPO_ROOT / "modules/helpers", siblings)
        startup_marker = self.root / "unverified-adjacent-startup-executed"
        startup = (f"from pathlib import Path\n"
                   f"Path({str(startup_marker)!r}).write_text('executed')\n").encode()
        self.assertFalse((siblings / "sitecustomize.py").exists())
        (siblings / "sitecustomize.py").write_bytes(startup)
        # All pinned helpers still match. Extra source files must neither run
        # at Python startup nor disable diagnostics from the verified helpers.
        healthy, _ = InstalledContract.doctor(self)
        self.assertFalse(startup_marker.exists(), "doctor executed unpinned adjacent startup code")
        self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)
        healthy_checks = {item["id"]: item for item in self.parsed_report(healthy)["checks"]}
        self.assertEqual(healthy_checks["scan-cache"]["status"], "ok", healthy_checks)
        marker = self.root / "unverified-adjacent-doctor-code-executed"
        damaged = (f"from pathlib import Path\n"
                   f"Path({str(marker)!r}).write_text('executed')\n").encode()
        (siblings / "ubs_core/__init__.py").write_bytes(damaged)
        self.assertFalse((self.bin / ".git").exists())

        result, _ = InstalledContract.doctor(self)
        self.assertFalse(marker.exists(), "doctor imported the unverified adjacent package")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        checks = {item["id"]: item for item in self.parsed_report(result)["checks"]}
        self.assertEqual(checks["scan-cache-helpers"]["status"], "err", checks)
        self.assertIn("checksum mismatch", checks["scan-cache-helpers"]["detail"])

        result, check = InstalledContract.doctor(self, fix=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(check["status"], "ok", check)
        self.active_generation()
        self.assertFalse(marker.exists(), "doctor --fix imported the unverified adjacent package")
        self.assertFalse(startup_marker.exists(), "doctor --fix executed unpinned adjacent startup code")
        self.assertEqual((siblings / "ubs_core/__init__.py").read_bytes(), damaged)
        self.assertEqual((siblings / "sitecustomize.py").read_bytes(), startup)
        self.scan_usable()

    def blocked_update(self) -> tuple[subprocess.Popen[str], Path]:
        blocked = self.root / "update-blocked"
        release = self.root / "update-release"
        process = subprocess.Popen(
            [str(self.runner), "--update", "--quiet", "--non-interactive"],
            cwd=self.root, env={**self.env, "CONTRACT_BLOCK_ASSET": "contract.json",
                                "CONTRACT_BLOCK_READY": str(blocked), "CONTRACT_BLOCK_RELEASE": str(release)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )

        def finish() -> None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)

        self.addCleanup(finish)
        deadline = time.monotonic() + 15
        while not blocked.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if not blocked.exists():
            finish()
            stdout, stderr = process.communicate()
            self.fail("Updater did not reach the module download barrier:\n" + stdout + stderr)
        return process, release

    def test_concurrent_scan_remains_usable_during_update(self) -> None:
        candidate = self.release()
        process, release = self.blocked_update()
        self.scan_usable()
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        release.write_text("continue")
        stdout, stderr = process.communicate(timeout=180)
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.scan_usable()

    def test_interrupted_update_preserves_old_scans_and_retry_recovers(self) -> None:
        candidate = self.release()
        process, _ = self.blocked_update()
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=10)
        self.assertEqual(self.runner.read_bytes(), self.before_runner)
        self.assert_legacy_intact()
        self.scan_usable()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.runner.read_bytes(), candidate)
        self.active_generation()
        self.scan_usable()


if __name__ == "__main__":
    unittest.main()
