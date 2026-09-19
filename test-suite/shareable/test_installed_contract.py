#!/usr/bin/env python3
"""Issue #129: installed detection consumes only a checksum-verified contract.

The installed runner has no modules/ sibling and starts with an empty cache.
A file:// mirror supplies the real repository assets, with deterministic curl/
wget shims that refuse all network access. Only optional doctor tool probes are
stubbed; scans execute the real language modules with Rust builds disabled.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"

FETCH_SHIM = r'''#!/usr/bin/env python3
import os
import pathlib
import sys
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
    pathlib.Path(out).write_bytes(source.read_bytes())
except OSError:
    sys.exit(22)
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

    def scanned_rust(self, result: subprocess.CompletedProcess[str]) -> dict:
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 3, output)
        self.assertNotIn("command not found", output)
        payload = json.loads(result.stdout)
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
        payload = json.loads(result.stdout)
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
        self.assertEqual((self.cache / "contract.json").read_bytes(), self.contract)
        (self.cache / "contract.json").write_bytes(b'{"modules":{}}\n')
        result, check = self.doctor()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(check["status"], "err", check)
        self.assertIn("checksum mismatch", check["detail"])
        _, check = self.doctor(fix=True)
        self.assertEqual(check["status"], "ok", check)
        self.assertEqual((self.cache / "contract.json").read_bytes(), self.contract)

    def test_corrupt_cache_is_fatal_even_with_unverified_override(self) -> None:
        damaged = b'{"modules":{}}\n'
        (self.cache / "contract.json").write_bytes(damaged)
        for base in (self.mirror, self.root / "offline"):
            self.rejected(self.run_ubs(str(self.target), extra_env={
                "UBS_REPO_RAW_BASE": base.as_uri(), "UBS_ALLOW_UNVERIFIED_HELPERS": "1",
            }))
            self.assertEqual((self.cache / "contract.json").read_bytes(), damaged)

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
        self.assertFalse((self.root / "installed_layout/moddir/contract.json").exists())


if __name__ == "__main__":
    unittest.main()
