#!/usr/bin/env python3
"""Issue #129: pin the detection contract through the complete checksum chain."""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ContractChecksums(unittest.TestCase):
    def make_tree(self, root: Path, *, contract: bool = True) -> None:
        (root / "scripts").mkdir()
        (root / "modules/lib").mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "scripts/update_checksums.py", root / "scripts/update_checksums.py")
        (root / "ubs").write_text(
            "#!/usr/bin/env bash\n"
            "declare -A MODULE_CHECKSUMS=(\n)\n"
            "declare -A HELPER_CHECKSUMS=(\n)\n"
            "HELPER_ASSETS=(\n)\n", encoding="utf-8",
        )
        (root / "install.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (root / "modules/lib/ubs-common.sh").write_text(
            "declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(\n)\n", encoding="utf-8",
        )
        for name in ("modules/ubs-rust.sh", "scripts/new-module.sh"):
            (root / name).write_text('UBS_LIB_CHECKSUM="old"\n', encoding="utf-8")
        if contract:
            (root / "modules/contract.json").write_text(
                '{"modules":{"rust":{"extensions":["rs"],"manifest_files":["Cargo.toml"]}}}\n',
                encoding="utf-8",
            )

    def generate(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(root / "scripts/update_checksums.py")],
            cwd=root, text=True, capture_output=True, check=False, timeout=30,
        )

    def assert_chain(self, root: Path) -> None:
        runner = (root / "ubs").read_text(encoding="utf-8")
        common = (root / "modules/lib/ubs-common.sh").read_text(encoding="utf-8")
        pin = f"['contract.json']='{digest(root / 'modules/contract.json')}'"
        self.assertIn(pin, runner)
        self.assertIn(pin, common)
        assets = re.search(r"HELPER_ASSETS=\(\n(.*?)\n\)", runner, re.S)
        self.assertIsNotNone(assets)
        self.assertEqual(assets.group(1).count('"contract.json"'), 1)
        lib_digest = digest(root / "modules/lib/ubs-common.sh")
        self.assertIn(f"['lib/ubs-common.sh']='{lib_digest}'", runner)
        self.assertNotIn("['lib/ubs-common.sh']", common)  # no self-referential digest
        for name in ("modules/ubs-rust.sh", "scripts/new-module.sh"):
            self.assertIn(f'UBS_LIB_CHECKSUM="{lib_digest}"', (root / name).read_text())
        self.assertIn(f"[rust]='{digest(root / 'modules/ubs-rust.sh')}'", runner)
        expected = "".join(f"{digest(root / name)}  {name}\n" for name in ("install.sh", "ubs"))
        self.assertEqual((root / "SHA256SUMS").read_text(), expected)

    def test_contract_propagates_and_generation_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-contract-pins-") as tmp:
            root = Path(tmp)
            self.make_tree(root)
            for contract_bytes in (None, b'{"modules":{"rust":{"manifest_files":["Cargo.toml","Cargo.lock"]}}}\n'):
                if contract_bytes is not None:
                    (root / "modules/contract.json").write_bytes(contract_bytes)
                result = self.generate(root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_chain(root)
                before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                result = self.generate(root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                self.assertEqual(before, after)

    def test_missing_contract_fails_before_modifying_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-contract-missing-") as tmp:
            root = Path(tmp)
            self.make_tree(root, contract=False)
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            result = self.generate(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required module contract not found", result.stderr)
            after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            self.assertEqual(before, after)

    def test_local_tool_caches_are_not_pinned(self) -> None:
        # d58f0f2 pinned modules/helpers/ubs_core/analyzers/.ruff_cache/* into
        # HELPER_CHECKSUMS and HELPER_ASSETS. Those files are gitignored, so an
        # installed ubs tried to download them on every scan and got 404s.
        with tempfile.TemporaryDirectory(prefix="ubs-contract-caches-") as tmp:
            root = Path(tmp)
            self.make_tree(root)
            core = root / "modules/helpers/ubs_core"
            (core / "analyzers/.ruff_cache/0.16.9").mkdir(parents=True)
            (core / "analyzers/__pycache__").mkdir(parents=True)
            (core / "analyzers/real.py").write_text("X = 1\n", encoding="utf-8")
            (core / "analyzers/.ruff_cache/CACHEDIR.TAG").write_text("tag\n", encoding="utf-8")
            (core / "analyzers/.ruff_cache/0.16.9/123").write_bytes(b"\x00cache")
            (core / "analyzers/__pycache__/real.cpython-314.pyc").write_bytes(b"\x00pyc")
            (core / ".pytest_cache").mkdir()
            (core / ".pytest_cache/README.md").write_text("cache\n", encoding="utf-8")
            result = self.generate(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            runner = (root / "ubs").read_text(encoding="utf-8")
            common = (root / "modules/lib/ubs-common.sh").read_text(encoding="utf-8")
            for text in (runner, common):
                self.assertIn("'helpers/ubs_core/analyzers/real.py'", text)
                for cache in (".ruff_cache", "__pycache__", ".pytest_cache"):
                    self.assertNotIn(cache, text)

    def test_checkout_pins_only_tracked_helpers(self) -> None:
        # Every HELPER_ASSETS entry is downloaded from the repository by an
        # installed ubs, so each one must be a tracked file.
        try:
            tracked = subprocess.run(
                ["git", "ls-files", "-z", "--", "modules"], cwd=REPO_ROOT,
                capture_output=True, check=True, timeout=30,
            ).stdout.decode("utf-8").split("\0")
        except (OSError, subprocess.CalledProcessError) as exc:
            self.skipTest(f"not a git checkout: {exc}")
        tracked_set = {path[len("modules/"):] for path in tracked if path}
        if not tracked_set:
            self.skipTest("no tracked modules (exported tree)")
        runner = (REPO_ROOT / "ubs").read_text(encoding="utf-8")
        assets = re.search(r"HELPER_ASSETS=\(\n(.*?)\n\)", runner, re.S)
        self.assertIsNotNone(assets)
        listed = re.findall(r'^\s*"([^"]+)"', assets.group(1), re.M)
        self.assertTrue(listed)
        untracked = sorted(rel for rel in listed if rel not in tracked_set)
        self.assertEqual(untracked, [], "HELPER_ASSETS lists files that are not in the repository")

    def test_verifier_rejects_pin_for_file_not_in_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-contract-stale-pin-") as tmp:
            root = Path(tmp)
            self.make_tree(root)
            helper = root / "modules/helpers/ubs_core/gone.py"
            helper.parent.mkdir(parents=True)
            helper.write_text("X = 1\n", encoding="utf-8")
            verifier = root / "scripts/verify_checksums.sh"
            shutil.copy2(REPO_ROOT / "scripts/verify_checksums.sh", verifier)
            result = self.generate(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            def verify() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(verifier)], cwd=root, text=True,
                    capture_output=True, check=False, timeout=30,
                )

            result = verify()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            helper.unlink()
            result = verify()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("PINNED HELPER NOT IN TREE: modules/helpers/ubs_core/gone.py", result.stdout)

    def test_verifier_rejects_contract_drift_and_missing_asset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-contract-verify-") as tmp:
            root = Path(tmp)
            self.make_tree(root)
            (root / "modules/helpers").mkdir()
            verifier = root / "scripts/verify_checksums.sh"
            shutil.copy2(REPO_ROOT / "scripts/verify_checksums.sh", verifier)
            result = self.generate(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            def verify() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(verifier)], cwd=root, text=True,
                    capture_output=True, check=False, timeout=30,
                )

            result = verify()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("modules/contract.json", result.stdout)
            contract = root / "modules/contract.json"
            contract.write_bytes(b'{"modules":{}}\n')
            result = verify()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHARED-LIBRARY HELPER CHECKSUM MISMATCH: modules/contract.json", result.stdout)
            self.assertIn("CHECKSUM MISMATCH: modules/contract.json", result.stdout)
            contract.rename(contract.with_suffix(".parked"))
            result = verify()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CHECKSUM FILE MISSING: modules/contract.json", result.stdout)


if __name__ == "__main__":
    unittest.main()
