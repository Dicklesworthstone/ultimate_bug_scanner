"""scripts/new-module.sh (bead A3c) scaffolds a contract-v2 module.

The scaffold runs against a throwaway root that holds only the shared library
and an empty manifest. The generated module must: pass bash -n and
shellcheck -S error; report the buggy fixture as critical (exit 1) and the
clean one as clean (exit 0) in json; produce SARIF with results; refuse
--format=toon with exit 2 (contract); list its categories; and the scaffold
must refuse to overwrite on a second run and write nothing outside the paths
it announces. When scripts/contract_conformance.py (bead A8) exists the
generated module is run through it as well.
"""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAFFOLD = REPO_ROOT / "scripts" / "new-module.sh"
LIB = REPO_ROOT / "modules" / "lib" / "ubs-common.sh"


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)  # ubs:ignore


class NewModuleScaffoldTest(unittest.TestCase):
    def parse_json_output(self, text: str) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            self.fail(f"scaffold output is not valid JSON: {exc}")

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="ubs-scaffold-"))
        (self.root / "modules" / "lib").mkdir(parents=True)
        (self.root / "test-suite").mkdir()
        shutil.copy2(LIB, self.root / "modules" / "lib" / "ubs-common.sh")
        (self.root / "test-suite" / "manifest.json").write_text('{"cases": []}\n')
        before = {str(p.relative_to(self.root)) for p in self.root.rglob("*")}
        proc = run([str(SCAFFOLD), "zig", "--extensions", "zig", "--display", "Zig", "--root", str(self.root)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        after = {str(p.relative_to(self.root)) for p in self.root.rglob("*")}
        self.created = sorted(after - before)
        self.module = self.root / "modules" / "ubs-zig.sh"

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_only_announced_paths_are_written(self) -> None:
        expected = {
            "modules/ubs-zig.sh", "test-suite/zig", "test-suite/zig/README.md",
            "test-suite/zig/buggy", "test-suite/zig/buggy/sample.zig",
            "test-suite/zig/clean", "test-suite/zig/clean/sample.zig",
        }
        self.assertEqual(set(self.created), expected, self.created)
        cases = self.parse_json_output((self.root / "test-suite" / "manifest.json").read_text())["cases"]
        self.assertEqual([c["id"] for c in cases], ["zig-buggy", "zig-clean"])
        self.assertEqual(cases[0]["expect"]["totals"]["critical"]["min"], 1)

    def test_generated_module_is_lint_clean(self) -> None:
        self.assertEqual(run(["bash", "-n", str(self.module)]).returncode, 0)
        if shutil.which("shellcheck"):
            proc = run(["shellcheck", "-S", "error", str(self.module)])
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_verifier_rejects_stale_nested_library_pins(self) -> None:
        scripts = self.root / "scripts"
        scripts.mkdir()
        (self.root / "modules" / "helpers").mkdir()
        verifier = scripts / "verify_checksums.sh"
        shutil.copy2(REPO_ROOT / "scripts" / "verify_checksums.sh", verifier)
        scaffold = scripts / "new-module.sh"
        shutil.copy2(SCAFFOLD, scaffold)
        library_hash = hashlib.sha256(LIB.read_bytes()).hexdigest()

        def refresh_outer_digests() -> None:
            module_hash = hashlib.sha256(self.module.read_bytes()).hexdigest()
            (self.root / "ubs").write_text(
                f"declare -A MODULE_CHECKSUMS=(\n  [zig]='{module_hash}'\n)\n"
                f"declare -A HELPER_CHECKSUMS=(\n  ['lib/ubs-common.sh']='{library_hash}'\n)\n",
                encoding="utf-8",
            )

        refresh_outer_digests()
        result = run(["bash", str(verifier)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for target in [self.module, scaffold]:
            with self.subTest(entrypoint=target.name):
                original = target.read_text(encoding="utf-8")
                pinned = f'UBS_LIB_CHECKSUM="{library_hash}"'
                self.assertIn(pinned, original)
                target.write_text(original.replace(pinned, 'UBS_LIB_CHECKSUM="' + "0" * 64 + '"'),
                                  encoding="utf-8")
                # The outer module hash is valid; only its nested pin is stale.
                refresh_outer_digests()
                result = run(["bash", str(verifier)])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(f"LIBRARY CHECKSUM MISMATCH: {target.relative_to(self.root)}", result.stdout)
                target.write_text(original, encoding="utf-8")

    def test_fixture_pair_and_formats(self) -> None:
        buggy = self.root / "test-suite" / "zig" / "buggy"
        clean = self.root / "test-suite" / "zig" / "clean"
        proc = run([str(self.module), "--ci", "--format=json", str(buggy)])
        self.assertEqual(proc.returncode, 1, proc.stderr)
        doc = self.parse_json_output(proc.stdout)
        self.assertEqual(doc["language"], "zig")
        self.assertEqual(doc["files"], 1)
        self.assertGreaterEqual(doc["critical"], 1)
        self.assertEqual(doc["status"], "ok")
        rules = {f["rule"] for f in doc["findings"]}
        self.assertIn("zig.security.eval", rules)
        self.assertTrue(all(s["file"] and isinstance(s["line"], int) for f in doc["findings"] for s in f["samples"]))
        proc = run([str(self.module), "--ci", "--format=json", str(clean)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.parse_json_output(proc.stdout)["critical"], 0)
        proc = run([str(self.module), "--ci", "--format=sarif", str(buggy)])
        sarif = self.parse_json_output(proc.stdout)
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)
        levels = {r["level"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(levels, {"error", "note"}, "the eval hit renders as error, the TODO marker as note")
        proc = run([str(self.module), "--format=toon", str(buggy)])
        self.assertEqual(proc.returncode, 2, "toon must be refused by a module (meta-runner format)")
        proc = run([str(self.module), "--list-categories"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Dangerous calls", proc.stdout)
        proc = run([str(self.module), "--ci", "--skip=2", "--format=json", str(buggy)])
        self.assertEqual(proc.returncode, 0, "skipping category 2 removes the only critical")
        proc = run([str(self.module), "--help"])
        self.assertIn("contract: v2", proc.stdout)

    def test_verifier_rejects_stale_or_missing_shared_library_helper_pins(self) -> None:
        scripts = self.root / "scripts"
        scripts.mkdir()
        helpers = self.root / "modules" / "helpers"
        helpers.mkdir()
        helper = helpers / "probe.py"
        helper.write_text("value = 1\n", encoding="utf-8")
        helper_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
        verifier = scripts / "verify_checksums.sh"
        shutil.copy2(REPO_ROOT / "scripts" / "verify_checksums.sh", verifier)
        library = self.root / "modules" / "lib" / "ubs-common.sh"
        original_library = library.read_text(encoding="utf-8")
        original_library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
        original_module = self.module.read_text(encoding="utf-8")
        original_scaffold = SCAFFOLD.read_text(encoding="utf-8")
        declaration = "declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(\n"
        self.assertIn(declaration, original_library)

        for pin in (helper_hash, "0" * 64, None):
            with self.subTest(pin=pin):
                entry = f"  ['helpers/probe.py']='{pin}'\n" if pin is not None else ""
                library.write_text(original_library.replace(declaration, declaration + entry), encoding="utf-8")
                library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
                old_pin = f'UBS_LIB_CHECKSUM="{original_library_hash}"'
                new_pin = f'UBS_LIB_CHECKSUM="{library_hash}"'
                self.module.write_text(original_module.replace(old_pin, new_pin), encoding="utf-8")
                (scripts / "new-module.sh").write_text(original_scaffold.replace(old_pin, new_pin), encoding="utf-8")
                module_hash = hashlib.sha256(self.module.read_bytes()).hexdigest()
                (self.root / "ubs").write_text(
                    f"declare -A MODULE_CHECKSUMS=(\n  [zig]='{module_hash}'\n)\n"
                    f"declare -A HELPER_CHECKSUMS=(\n  ['lib/ubs-common.sh']='{library_hash}'\n"
                    f"  ['helpers/probe.py']='{helper_hash}'\n)\n", encoding="utf-8",
                )
                result = run(["bash", str(verifier)])
                self.assertEqual(result.returncode, 0 if pin == helper_hash else 1, result.stdout + result.stderr)
                if pin != helper_hash:
                    self.assertIn("SHARED-LIBRARY HELPER CHECKSUM MISMATCH: modules/helpers/probe.py", result.stdout)

    def test_second_run_refuses_to_overwrite(self) -> None:
        stamp = self.module.read_text()
        proc = run([str(SCAFFOLD), "zig", "--extensions", "zig", "--root", str(self.root)])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("refusing to overwrite", proc.stderr)
        self.assertEqual(self.module.read_text(), stamp)

    def test_conformance_when_available(self) -> None:
        conformance = REPO_ROOT / "scripts" / "contract_conformance.py"
        if not conformance.exists():
            self.skipTest("scripts/contract_conformance.py (bead A8) does not exist yet")
        proc = run([os.environ.get("PYTHON", "python3"), str(conformance), str(self.module)])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
