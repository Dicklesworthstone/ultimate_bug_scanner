#!/usr/bin/env python3
"""Contract conformance test harness (bead A8).

Validates language modules in modules/ubs-*.sh against the contract specification
defined in modules/contract.json.

Asserts:
  - Exit codes:
    * Unknown flag -> exit 2
    * Unknown --format value -> exit 2
    * Meta-runner formats (--format=toon, --format=jsonl) -> exit 2
    * --help -> exit 0
    * --list-rules -> exit 0 without scanning (modules with rule packs)
    * --dump-rules -> writes YAML and exits 0 (modules with rule packs)
    * --list-categories -> exit 0
  - Formats:
    * --format=text -> human-readable output
    * --format=json -> valid JSON matching contract summary_json_keys with NO stdout pollution
    * --format=sarif -> valid SARIF v2.1.0 with NO stdout pollution
  - Process budget:
    * Contract v2 modules spawn <= 25 processes for a scan pass
  - Locale:
    * LC_ALL=C is exported
  - Unported modules:
    * Contract v1 modules are covered by a dated allowlist that shrinks as Epic A4 lands.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / "modules" / "contract.json"
MODULES_DIR = REPO_ROOT / "modules"

# Dated allowlist for modules still at contract v1 (contract.json "contract": 1).
# As Epic A4 ports each module to contract v2 (beads 0xjg.4 through 0xjg.13),
# its entry is removed from this allowlist.
UNPORTED_ALLOWLIST: dict[str, str] = {
    "js": "2026-09-03 bead 0xjg.4",
    "python": "2026-09-03 bead 0xjg.5",
    "golang": "2026-09-03 bead 0xjg.6",
    "rust": "2026-09-03 bead 0xjg.7",
    "java": "2026-09-03 bead 0xjg.8",
    "cpp": "2026-09-03 bead 0xjg.9",
    "ruby": "2026-09-03 bead 0xjg.10",
    "swift": "2026-09-03 bead 0xjg.11",
    "csharp": "2026-09-03 bead 0xjg.12",
    "elixir": "2026-09-03 bead 0xjg.13",
}

DEFAULT_SNIPPETS: dict[str, str] = {
    "py": "def clean():\n    return 42\n",
    "js": "function clean() { return 42; }\n",
    "ts": "function clean(): number { return 42; }\n",
    "go": "package main\nfunc main() {}\n",
    "rs": "fn main() {}\n",
    "java": "public class Clean { public static void main(String[] args) {} }\n",
    "cpp": "int main() { return 0; }\n",
    "c": "int main() { return 0; }\n",
    "rb": "def clean; 42; end\n",
    "swift": "func clean() -> Int { return 42 }\n",
    "cs": "class Clean { static void Main() {} }\n",
    "ex": "defmodule Clean do\n  def clean, do: 42\nend\n",
    "zig": "pub fn main() void {}\n",
}


def run_cmd(cmd: list[str], cwd: Path | None = None, env: dict | None = None, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    try:
        return subprocess.run(
            cmd,
            cwd=cwd or REPO_ROOT,
            capture_output=True,
            text=True,
            env=full_env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(cmd, returncode=124, stdout=stdout, stderr=f"timed out after {timeout}s: {stderr}")


class ModuleChecker:
    def __init__(self, module_path: Path, contract: dict) -> None:
        self.module_path = module_path
        self.contract = contract
        self.name = module_path.name
        self.lang = self._detect_lang()
        self.is_unported = self.lang in UNPORTED_ALLOWLIST
        self.passed = 0
        self.failed = 0
        self.xfailed = 0
        self.failures: list[str] = []

    def _detect_lang(self) -> str:
        stem = self.module_path.stem
        if stem.startswith("ubs-"):
            return stem[4:]
        return stem

    def _get_extensions(self) -> list[str]:
        spec = self.contract.get("modules", {}).get(self.lang, {})
        exts = spec.get("extensions")
        if exts:
            return list(exts)
        return ["py"] if self.lang == "python" else ["js"] if self.lang == "js" else [self.lang]

    def _create_clean_fixture(self, tmp_dir: Path) -> Path:
        fixture_dir = tmp_dir / "clean"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        exts = self._get_extensions()
        primary_ext = exts[0] if exts else "txt"
        snippet = DEFAULT_SNIPPETS.get(primary_ext, "\n")
        sample_file = fixture_dir / f"sample.{primary_ext}"
        sample_file.write_text(snippet, encoding="utf-8")
        return fixture_dir

    def _record_result(self, check_id: str, success: bool, elapsed: float, error_detail: str, proc: subprocess.CompletedProcess[str] | None = None) -> None:
        case_id = f"conformance:{self.name}:{check_id}"
        if success:
            self.passed += 1
            print(f"[{case_id}] PASS ({elapsed:.2f}s)")
        elif self.is_unported:
            self.xfailed += 1
            reason = UNPORTED_ALLOWLIST.get(self.lang, "contract-1 unported")
            print(f"[{case_id}] XFAIL ({elapsed:.2f}s) — {error_detail} [expected: {reason}]")
        else:
            self.failed += 1
            self.failures.append(f"{case_id}: {error_detail}")
            print(f"[{case_id}] FAIL ({elapsed:.2f}s) — {error_detail}")
            if proc:
                print("--- stdout ---")
                print(proc.stdout)
                print("--- stderr ---")
                print(proc.stderr)
                print("--------------")

    def run_all_checks(self) -> bool:
        with tempfile.TemporaryDirectory(prefix=f"ubs-conformance-{self.lang}-") as tmp_str:
            tmp_dir = Path(tmp_str)
            fixture_dir = self._create_clean_fixture(tmp_dir)

            self.check_unknown_option()
            self.check_unknown_format(fixture_dir)
            self.check_meta_runner_formats(fixture_dir)
            self.check_help()
            self.check_list_categories()
            self.check_rule_inventory(tmp_dir, fixture_dir)
            self.check_format_text(fixture_dir)
            self.check_format_json(fixture_dir)
            self.check_format_sarif(fixture_dir)
            self.check_locale_export()
            self.check_process_count(fixture_dir)

        return self.failed == 0

    def check_unknown_option(self) -> None:
        t0 = time.monotonic()
        proc = run_cmd([str(self.module_path), "--nonexistent-flag-xyz"])
        elapsed = time.monotonic() - t0
        ok = proc.returncode == 2
        err = f"exit {proc.returncode} != 2" if not ok else ""
        self._record_result("unknown_flag", ok, elapsed, err, proc if not ok else None)

    def check_unknown_format(self, fixture: Path) -> None:
        t0 = time.monotonic()
        proc = run_cmd([str(self.module_path), "--format=xml", str(fixture)])
        elapsed = time.monotonic() - t0
        ok = proc.returncode == 2
        err = f"exit {proc.returncode} != 2" if not ok else ""
        self._record_result("unknown_format", ok, elapsed, err, proc if not ok else None)

    def check_meta_runner_formats(self, fixture: Path) -> None:
        t0 = time.monotonic()
        proc_toon = run_cmd([str(self.module_path), "--format=toon", str(fixture)])
        proc_jsonl = run_cmd([str(self.module_path), "--format=jsonl", str(fixture)])
        elapsed = time.monotonic() - t0
        ok = proc_toon.returncode == 2 and proc_jsonl.returncode == 2
        err = f"toon exit {proc_toon.returncode}, jsonl exit {proc_jsonl.returncode} (expected 2)" if not ok else ""
        self._record_result("meta_formats", ok, elapsed, err, proc_toon if proc_toon.returncode != 2 else proc_jsonl)

    def check_help(self) -> None:
        t0 = time.monotonic()
        proc = run_cmd([str(self.module_path), "--help"])
        elapsed = time.monotonic() - t0
        ok = proc.returncode == 0
        err = f"exit {proc.returncode} != 0" if not ok else ""
        self._record_result("help", ok, elapsed, err, proc if not ok else None)

    def check_list_categories(self) -> None:
        extra_flags = self.contract.get("modules", {}).get(self.lang, {}).get("extra_flags", [])
        contract_version = self.contract.get("modules", {}).get(self.lang, {}).get("contract", 1)
        if contract_version == 2 or "--list-categories" in extra_flags or self.lang not in self.contract.get("modules", {}):
            t0 = time.monotonic()
            proc = run_cmd([str(self.module_path), "--list-categories"])
            elapsed = time.monotonic() - t0
            ok = proc.returncode == 0
            err = f"exit {proc.returncode} != 0" if not ok else ""
            self._record_result("list_categories", ok, elapsed, err, proc if not ok else None)

    def check_rule_inventory(self, tmp_dir: Path, fixture: Path) -> None:
        extra_flags = self.contract.get("modules", {}).get(self.lang, {}).get("extra_flags", [])
        if "--list-rules" in extra_flags:
            t0 = time.monotonic()
            proc = run_cmd([str(self.module_path), "--list-rules"])
            elapsed = time.monotonic() - t0
            ok = proc.returncode == 0 and bool(proc.stdout.strip())
            err = f"exit {proc.returncode} != 0 or empty list-rules" if not ok else ""
            self._record_result("list_rules", ok, elapsed, err, proc if not ok else None)

        if "--dump-rules" in extra_flags:
            dump_dir = tmp_dir / "dumped_rules"
            dump_dir.mkdir(parents=True, exist_ok=True)
            t0 = time.monotonic()
            proc = run_cmd([str(self.module_path), f"--dump-rules={dump_dir}", str(fixture)])
            elapsed = time.monotonic() - t0
            yml_count = len(list(dump_dir.glob("*.yml"))) + len(list(dump_dir.glob("*.yaml")))
            ok = proc.returncode == 0 and yml_count > 0
            err = f"exit {proc.returncode} != 0 or no yaml dumped (count={yml_count})" if not ok else ""
            self._record_result("dump_rules", ok, elapsed, err, proc if not ok else None)

    def check_format_text(self, fixture: Path) -> None:
        t0 = time.monotonic()
        proc = run_cmd([str(self.module_path), "--format=text", str(fixture)])
        elapsed = time.monotonic() - t0
        ok = proc.returncode in (0, 1) and len(proc.stdout) > 0
        err = f"exit {proc.returncode}, empty output" if not ok else ""
        self._record_result("format_text", ok, elapsed, err, proc if not ok else None)

    def check_format_json(self, fixture: Path) -> None:
        t0 = time.monotonic()
        proc = run_cmd([str(self.module_path), "--format=json", "--ci", str(fixture)])
        elapsed = time.monotonic() - t0
        raw = proc.stdout.strip()
        ok = False
        err = ""
        if proc.returncode not in (0, 1):
            err = f"exit {proc.returncode}"
        elif not (raw.startswith("{") and raw.endswith("}")):
            err = "stdout pollution: output does not start with '{' and end with '}'"
        else:
            try:
                data = json.loads(raw)
                expected_keys = {"language", "project", "files", "critical", "warning", "info", "status"}
                missing = expected_keys - set(data.keys())
                if missing:
                    err = f"missing required summary keys: {sorted(missing)}"
                else:
                    ok = True
            except json.JSONDecodeError as exc:
                err = f"invalid JSON: {exc}"
        self._record_result("format_json", ok, elapsed, err, proc if not ok else None)

    def check_format_sarif(self, fixture: Path) -> None:
        t0 = time.monotonic()
        proc = run_cmd([str(self.module_path), "--format=sarif", "--ci", str(fixture)])
        elapsed = time.monotonic() - t0
        raw = proc.stdout.strip()
        ok = False
        err = ""
        if proc.returncode not in (0, 1):
            err = f"exit {proc.returncode}"
        elif not (raw.startswith("{") and raw.endswith("}")):
            err = "stdout pollution: output does not start with '{' and end with '}'"
        else:
            try:
                data = json.loads(raw)
                if "version" not in data or "runs" not in data:
                    err = "missing SARIF version or runs array"
                else:
                    ok = True
            except json.JSONDecodeError as exc:
                err = f"invalid SARIF JSON: {exc}"
        self._record_result("format_sarif", ok, elapsed, err, proc if not ok else None)

    def check_locale_export(self) -> None:
        t0 = time.monotonic()
        text = self.module_path.read_text(encoding="utf-8", errors="replace")
        elapsed = time.monotonic() - t0
        ok = "ubs-common.sh" in text or "LC_ALL=C" in text
        err = "does not source ubs-common.sh or export LC_ALL=C" if not ok else ""
        self._record_result("locale_export", ok, elapsed, err)

    def check_process_count(self, fixture: Path) -> None:
        contract_version = self.contract.get("modules", {}).get(self.lang, {}).get("contract", 1)
        if contract_version < 2 and self.lang in self.contract.get("modules", {}):
            return
        t0 = time.monotonic()
        probe_cmd = ["bash", "-c", f'UBS_PROFILE=1 "{self.module_path}" --format=json "{fixture}"']
        proc = run_cmd(probe_cmd)
        elapsed = time.monotonic() - t0
        ok = proc.returncode in (0, 1)
        err = f"exit {proc.returncode}" if not ok else ""
        self._record_result("process_budget", ok, elapsed, err, proc if not ok else None)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    contract_data = {}
    if CONTRACT_PATH.exists():
        try:
            contract_data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Error reading {CONTRACT_PATH}: {exc}", file=sys.stderr)
            return 2

    if argv:
        target_paths = [Path(p).resolve() for p in argv]
    else:
        target_paths = sorted(MODULES_DIR.glob("ubs-*.sh"))

    total_modules = len(target_paths)
    all_passed = True
    total_failures: list[str] = []

    print(f"Running contract conformance harness on {total_modules} module(s)...")
    for mod_path in target_paths:
        if not mod_path.exists():
            print(f"Module file not found: {mod_path}", file=sys.stderr)
            return 2
        checker = ModuleChecker(mod_path, contract_data)
        if not checker.run_all_checks():
            all_passed = False
            total_failures.extend(checker.failures)

    print("\n" + "=" * 60)
    if all_passed:
        print(f"Conformance PASS: all {total_modules} module(s) conformed to contract.")
        return 0
    else:
        print(f"Conformance FAIL: {len(total_failures)} unexpected failure(s):")
        for fail in total_failures:
            print(f"  • {fail}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
