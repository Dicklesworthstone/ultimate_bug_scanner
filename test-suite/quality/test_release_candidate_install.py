"""Qualify assembled source with real Minisign and disposable installations.

Only HTTPS transport is doubled. Signatures, digests, installer, runner and all
runtime files are real. No production signing key or network service is used.
The historical cases require the immutable v5.5.26 source commit in local Git.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_COMMIT = "fcecdd8af1ff745b79592b63e65ff8efa15e8333"
HISTORICAL_RUNNER_SHA256 = "db9ce86687ca6992109583329c3e77decd4990122bc6d11840f8c2ff443fcdd5"
MINISIGN = shutil.which("minisign")
_spec = importlib.util.spec_from_file_location("candidate_generation", ROOT / "scripts/release_generation.py")
generation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generation)

TRANSPORT = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
url = next((arg for arg in args if arg.startswith('https://')), '')
with open(os.environ['CANDIDATE_FETCH_LOG'], 'a', encoding='utf-8') as stream:
    stream.write(url + '\n')
mapping = json.loads(pathlib.Path(os.environ['CANDIDATE_URL_MAP']).read_text())
if url not in mapping or url == os.environ.get('CANDIDATE_MISSING_URL'):
    sys.exit(22)
source = pathlib.Path(mapping[url])
if not source.is_file() or source.is_symlink():
    sys.exit(22)
data = source.read_bytes()
if url == os.environ.get('CANDIDATE_CORRUPT_URL'):
    data += b'\n# altered transport bytes\n'
output_flag = next((flag for flag in ('-o', '-O') if flag in args), None)
if output_flag:
    pathlib.Path(args[args.index(output_flag) + 1]).write_bytes(data)
else:
    sys.stdout.buffer.write(data)
'''


@unittest.skipUnless(MINISIGN, "real Minisign is required for release candidate qualification")
class ReleaseCandidateInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="ubs-candidate-signing-")
        cls.addClassCleanup(cls.work.cleanup)
        cls.shared = Path(cls.work.name)
        cls.candidate = cls.shared / "candidate"
        cls.version = (ROOT / "VERSION").read_text().strip()
        cls.manifest = generation.parse_manifest((ROOT / "ubs").read_bytes())
        subprocess.run(
            ["python3", str(ROOT / "scripts/build_release_candidate.py"),
             "--version", cls.version, "--output", str(cls.candidate)],
            cwd=cls.shared, check=True, capture_output=True, text=True, timeout=60,
        )
        cls.key = cls.shared / "disposable-test.key"
        public = cls.shared / "disposable-test.pub"
        subprocess.run([MINISIGN, "-G", "-W", "-s", str(cls.key), "-p", str(public)],
                       check=True, capture_output=True, text=True, timeout=30)
        cls.public_key = public.read_text().splitlines()[1]
        cls.sign(cls.candidate)

    @classmethod
    def sign(cls, bundle):
        subprocess.run(
            [MINISIGN, "-S", "-s", str(cls.key), "-m", str(bundle / "SHA256SUMS"),
             "-x", str(bundle / "SHA256SUMS.minisig"),
             "-t", "Disposable UBS candidate test; not a production release"],
            check=True, capture_output=True, text=True, timeout=30,
        )

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="ubs-candidate-install-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.destination = self.home / "bin"
        self.cache = self.home / ".local/share/ubs/modules"
        self.bundle = self.root / "bundle"
        shutil.copytree(self.candidate, self.bundle)
        self.bin = self.root / "transport-bin"
        self.bin.mkdir()
        for name in ("curl", "wget"):
            shim = self.bin / name
            shim.write_text(TRANSPORT)
            shim.chmod(0o755)
        self.log = self.root / "fetch.log"
        self.url_map = self.root / "urls.json"
        self.artifact_base = f"https://candidate.invalid/releases/v{self.version}"
        self.raw_base = "https://candidate.invalid/source"
        mapping = {f"{self.artifact_base}/{path.name}": str(path)
                   for path in self.bundle.iterdir() if path.is_file()}
        mapping.update({f"{self.raw_base}/v{self.version}/modules/{name}":
                        str(self.bundle / "modules" / name) for name in self.manifest.assets})
        self.url_map.write_text(json.dumps(mapping))
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("UBS_", "GIT_", "XDG_", "PYTHON"))}
        self.env.update(
            HOME=str(self.home), XDG_DATA_HOME=str(self.home / ".local/share"),
            XDG_CONFIG_HOME=str(self.home / ".config"), XDG_CACHE_HOME=str(self.home / ".cache"),
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            UBS_VERSION=self.version, UBS_ARTIFACT_BASE=self.artifact_base,
            UBS_REPO_RAW_BASE=self.raw_base, UBS_VERIFY_WITH="minisign",
            UBS_MINISIGN_PUBKEY=self.public_key, UBS_NO_AUTO_UPDATE="1",
            UBS_INSTALLER_SELF_UPDATED="1", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
            CANDIDATE_FETCH_LOG=str(self.log), CANDIDATE_URL_MAP=str(self.url_map),
        )
        self.flags = ["--non-interactive", "--skip-ast-grep", "--skip-ripgrep", "--skip-jq",
                      "--skip-bun", "--skip-type-narrowing", "--skip-typos", "--skip-toon",
                      "--skip-doctor", "--skip-hooks", "--skip-version-check", "--no-path-modify",
                      "--install-dir", str(self.destination)]

    def run_install(self, *, standalone=False, expected=0):
        if standalone:
            command = ["bash", "-s", "--", *self.flags]
            script = (ROOT / "install.sh").read_text()
        else:
            command = ["bash", str(ROOT / "scripts/verify.sh"), "--version", self.version,
                       "--artifact-dir", str(self.bundle), "--with-modules", "--", *self.flags]
            script = None
        result = subprocess.run(command, input=script, cwd=self.project, env=self.env,
                                capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def fetches(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assert_complete_install(self):
        runner = self.destination / "ubs"
        self.assertEqual(runner.read_bytes(), (self.bundle / "ubs").read_bytes())
        prepared = generation.generation_path(self.cache, self.manifest)
        generation.check_ready(prepared, self.manifest, complete=True)
        generation.verify_dependency_pins(prepared, self.manifest)
        daemon = self.destination / ("ubs.daemon." + generation.daemon_pin(runner.read_bytes()) + ".py")
        self.assertEqual(daemon.read_bytes(), (self.bundle / "ubs-daemon").read_bytes())
        result = subprocess.run([str(runner), "--version"], cwd=self.project, env=self.env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.version, result.stdout)
        return prepared

    def snapshot_install(self):
        # Installation state, not incidental installer logs/configuration.
        return {str(path.relative_to(self.home)): path.read_bytes()
                for root in (self.destination, self.cache) if root.exists()
                for path in root.rglob("*") if path.is_file() and not path.name.endswith(".lock")}

    def seed_historical(self):
        present = subprocess.run(["git", "cat-file", "-e", HISTORICAL_COMMIT + "^{commit}"],
                                 cwd=ROOT, capture_output=True, timeout=20)
        if present.returncode:
            self.skipTest("immutable v5.5.26 commit unavailable; use a full-history checkout")
        archive = subprocess.run(
            ["git", "archive", HISTORICAL_COMMIT, "ubs", "ubs-daemon", "modules"],
            cwd=ROOT, check=True, capture_output=True, timeout=30,
        ).stdout
        self.destination.mkdir()
        self.cache.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            for member in source:
                if not member.isfile():
                    self.assertTrue(member.isdir(), member.name)
                    continue
                relative = Path(member.name)
                self.assertFalse(relative.is_absolute() or ".." in relative.parts, member.name)
                target = (self.cache / Path(*relative.parts[1:]) if relative.parts[0] == "modules"
                          else self.destination / member.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.extractfile(member).read())
                target.chmod(member.mode & 0o777)
        self.assertEqual(hashlib.sha256((self.destination / "ubs").read_bytes()).hexdigest(),
                         HISTORICAL_RUNNER_SHA256)
        result = subprocess.run([str(self.destination / "ubs"), "--version"], cwd=self.project,
                                env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("5.5.26", result.stdout)

    def resign_flat_payload(self):
        names = [line.split()[1] for line in (self.bundle / "SHA256SUMS").read_text().splitlines()]
        (self.bundle / "SHA256SUMS").write_text("".join(
            hashlib.sha256((self.bundle / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in names))
        self.sign(self.bundle)

    def test_standalone_fresh_install_verifies_all_runtime_downloads(self):
        self.assertFalse(self.cache.exists())
        self.run_install(standalone=True)
        self.assert_complete_install()
        fetched = self.fetches()
        module_urls = {f"{self.raw_base}/v{self.version}/modules/{name}" for name in self.manifest.assets}
        # A pin for the empty byte string needs no download: its complete
        # content is already known. Every other file must come from the mirror
        # on this cold install; assert_complete_install authenticates all files.
        empty_digest = hashlib.sha256(b"").hexdigest()
        required_downloads = {f"{self.raw_base}/v{self.version}/modules/{name}"
                              for name, pin in self.manifest.assets.items() if pin != empty_digest}
        module_fetches = {url for url in fetched if "/modules/" in url}
        self.assertLessEqual(required_downloads, module_fetches)
        self.assertLessEqual(module_fetches, module_urls)
        self.assertEqual(fetched.count(self.artifact_base + "/SHA256SUMS"), 1)
        self.assertIn(self.artifact_base + "/SHA256SUMS.minisig", fetched)

    def test_complete_signed_bundle_installs_into_an_empty_cache_offline(self):
        self.assertFalse(self.cache.exists())
        self.run_install()
        self.assert_complete_install()
        self.assertEqual(self.fetches(), [])

    def test_actual_v5526_upgrade_preserves_legacy_cache(self):
        self.seed_historical()
        before = self.snapshot_install()
        self.run_install(standalone=True)
        self.assert_complete_install()
        after = self.snapshot_install()
        for name, data in before.items():
            if name.startswith(".local/share/ubs/modules/") or name == "bin/ubs-daemon":
                self.assertEqual(after[name], data, name)

    def test_failed_runtime_download_preserves_actual_v5526_installation(self):
        self.seed_historical()
        before = self.snapshot_install()
        # Select a genuinely changed asset, so a valid old cache cannot satisfy
        # the candidate's pin and accidentally turn a failure test into reuse.
        changed = next(name for name, pin in self.manifest.assets.items()
                       if not (self.cache / name).is_file()
                       or hashlib.sha256((self.cache / name).read_bytes()).hexdigest() != pin)
        self.env["CANDIDATE_CORRUPT_URL"] = f"{self.raw_base}/v{self.version}/modules/{changed}"
        result = self.run_install(standalone=True, expected=1)
        self.assertIn("previous runner and module cache remain available", result.stdout + result.stderr)
        self.assertEqual(self.snapshot_install(), before)

    def test_signature_failure_preserves_existing_installation(self):
        self.run_install()
        before = self.snapshot_install()
        signature = self.bundle / "SHA256SUMS.minisig"
        rows = signature.read_text().splitlines()
        altered = bytearray(base64.b64decode(rows[1], validate=True))
        altered[20] ^= 1  # Corrupt the signature while preserving its key ID and encoding.
        rows[1] = base64.b64encode(altered).decode("ascii")
        signature.write_text("\n".join(rows) + "\n")
        self.run_install(standalone=True, expected=1)
        self.assertEqual(self.snapshot_install(), before)
        self.assertNotIn(self.artifact_base + "/ubs", self.fetches())

    def test_runner_tampering_preserves_existing_installation(self):
        self.run_install()
        before = self.snapshot_install()
        runner = self.bundle / "ubs"
        runner.write_bytes(runner.read_bytes() + b"\n# changed after signing\n")
        self.run_install(standalone=True, expected=1)
        self.assertEqual(self.snapshot_install(), before)

    def test_authenticated_wrong_daemon_preserves_existing_installation(self):
        self.run_install()
        before = self.snapshot_install()
        daemon = self.bundle / "ubs-daemon"
        daemon.write_bytes(daemon.read_bytes() + b"\n# mismatched signed daemon\n")
        self.resign_flat_payload()
        self.run_install(standalone=True, expected=1)
        self.assertEqual(self.snapshot_install(), before)

    def test_incomplete_bundle_preserves_existing_installation_without_fallback(self):
        self.run_install()
        before = self.snapshot_install()
        helper = self.bundle / "modules/helpers/ubs_core/__init__.py"
        helper.rename(helper.with_suffix(".missing"))
        self.run_install(expected=1)
        self.assertEqual(self.snapshot_install(), before)
        self.assertEqual(self.fetches(), [])

    def test_signed_markerless_runner_is_still_rejected(self):
        self.run_install()
        before = self.snapshot_install()
        runner = self.bundle / "ubs"
        runner.write_text(runner.read_text().replace("\nUBS_RELEASE_GENERATIONS=1\n", "\n", 1))
        self.resign_flat_payload()
        result = self.run_install(standalone=True, expected=1)
        self.assertIn("does not support verified cache publication", result.stdout + result.stderr)
        self.assertEqual(self.snapshot_install(), before)

    def test_bundle_export_is_reproducible_and_reverifiable(self):
        outputs = [self.root / "first.tar.gz", self.root / "second.tar.gz"]
        for output in outputs:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/verify.sh"), "--version", self.version,
                 "--artifact-dir", str(self.bundle), "--bundle-output", str(output)],
                cwd=self.project, env=self.env, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/verify.sh"), "--version", self.version,
             "--artifact-archive", str(outputs[0]), "--verify-only", "--with-modules"],
            cwd=self.project, env=self.env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.fetches(), [])


if __name__ == "__main__":
    unittest.main()
