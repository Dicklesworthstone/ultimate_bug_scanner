#!/usr/bin/env python3
"""Supply-chain fail-closed checks (bridge-plan beads E2/E6).

The meta-runner must never execute a helper whose digest does not match the
pinned HELPER_CHECKSUMS table. These checks run a copy of `ubs` outside the git
checkout (so modules and helpers come from a --module-dir cache, which is the
only location the runner verifies) and serve "downloads" from a local file://
tree via UBS_REPO_RAW_BASE, so no network is involved and the refresh path can
be forced to return tampered bytes.

Each check prints `[supply-chain:<name>] PASS/FAIL`; failures dump the captured
output so the log alone is enough to diagnose them.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS = REPO_ROOT / "ubs"
MODULES = REPO_ROOT / "modules"
PY_FIXTURE = REPO_ROOT / "test-suite" / "python" / "security" / "parser_token_compare_clean.py"
TAMPERED_HELPER = "helpers/resource_lifecycle_py.py"

FAILURES: list[str] = []


def ubs_version() -> str:
    match = re.search(r'^UBS_VERSION="([^"]+)"', UBS.read_text(encoding="utf-8"), re.M)
    if not match:
        raise RuntimeError("UBS_VERSION not found in ubs")
    return match.group(1)


def report(name: str, ok: bool, detail: str = "", proc: subprocess.CompletedProcess | None = None) -> None:
    print(f"[supply-chain:{name}] {'PASS' if ok else 'FAIL'}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        FAILURES.append(name)
        if proc is not None:
            print(f"  exit={proc.returncode}\n  stdout:\n{textwrap.indent(proc.stdout[-2500:], '    ')}\n  stderr:\n{textwrap.indent(proc.stderr[-2500:], '    ')}")


class Sandbox:
    """A ubs copy outside the checkout + a module cache + a local raw base."""

    def __init__(self, tmp: Path, *, tamper: bool, serve_tampered: bool, missing_helper: bool = False) -> None:
        self.tmp = tmp
        self.bin_dir = tmp / "bin"
        self.module_dir = tmp / "cache"
        self.raw_base = tmp / "raw"
        self.bin_dir.mkdir()
        shutil.copy2(UBS, self.bin_dir / "ubs")
        (self.module_dir / "helpers").mkdir(parents=True)
        shutil.copy2(MODULES / "ubs-python.sh", self.module_dir / "ubs-python.sh")
        for helper in (MODULES / "helpers").iterdir():
            if helper.is_file():
                shutil.copy2(helper, self.module_dir / "helpers" / helper.name)
        tampered = self.module_dir / TAMPERED_HELPER
        if missing_helper:
            tampered.unlink()
        elif tamper:
            tampered.write_text(tampered.read_text(encoding="utf-8") + "\n# tampered by test_supply_chain\n", encoding="utf-8")
        # Local "raw.githubusercontent.com": both the release tag and main paths.
        for ref in (f"v{ubs_version()}", "main"):
            dest = self.raw_base / ref / "modules" / "helpers"
            dest.mkdir(parents=True)
            for helper in (MODULES / "helpers").iterdir():
                if helper.is_file():
                    shutil.copy2(helper, dest / helper.name)
            if serve_tampered:
                served = dest / Path(TAMPERED_HELPER).name
                served.write_text(served.read_text(encoding="utf-8") + "\n# tampered by test_supply_chain\n", encoding="utf-8")

    def run(self, *extra_env: tuple[str, str]) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update({
            "NO_COLOR": "1",
            "UBS_NO_AUTO_UPDATE": "1",
            "UBS_SKIP_SIZE_CHECK": "1",
            "UBS_REPO_RAW_BASE": f"file://{self.raw_base}",
            "PATH": "/usr/local/bin:/usr/bin:/bin" + (":" + os.environ.get("PATH", "") if os.environ.get("PATH") else ""),
        })
        env.update(dict(extra_env))
        cmd = [str(self.bin_dir / "ubs"), f"--module-dir={self.module_dir}", "--only=python", "--ci", "--format=json", str(PY_FIXTURE)]
        return subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300)


def check_healthy_cache_scans() -> None:
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=False, serve_tampered=False).run()
        ok = proc.returncode in (0, 1) and '"totals"' in proc.stdout and "refusing" not in (proc.stdout + proc.stderr)
        report("healthy_cache_scans", ok, f"exit={proc.returncode}", proc)


def check_tampered_helper_refreshed_from_clean_source() -> None:
    # A corrupted cache entry is repaired from the (clean) source and the scan proceeds.
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        sb = Sandbox(Path(tmp), tamper=True, serve_tampered=False)
        proc = sb.run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode in (0, 1) and "failed verification" in combined and "refusing" not in combined
        report("tampered_helper_refreshed_from_clean_source", ok, f"exit={proc.returncode}", proc)


def check_tampered_helper_refused() -> None:
    # The refreshed download is tampered too: the scan must refuse (exit 2).
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=True).run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode == 2 and "refusing to scan with unverified helpers" in combined and "doctor --fix" in combined
        report("tampered_helper_refused", ok, f"exit={proc.returncode}", proc)


def check_override_allows_unverified() -> None:
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=True).run(("UBS_ALLOW_UNVERIFIED_HELPERS", "1"))
        combined = proc.stdout + proc.stderr
        ok = proc.returncode in (0, 1) and "UBS_ALLOW_UNVERIFIED_HELPERS=1" in combined
        report("override_allows_unverified", ok, f"exit={proc.returncode}", proc)


def check_download_failure_only_warns() -> None:
    # A missing helper that cannot be downloaded is not tampering: warn and continue.
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        sb = Sandbox(Path(tmp), tamper=False, serve_tampered=False, missing_helper=True)
        shutil.rmtree(sb.raw_base)  # nothing to download from
        proc = sb.run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode in (0, 1) and "continuing with reduced accuracy" in combined and "refusing" not in combined
        report("download_failure_only_warns", ok, f"exit={proc.returncode}", proc)


def main() -> int:
    for check in (
        check_healthy_cache_scans,
        check_tampered_helper_refreshed_from_clean_source,
        check_tampered_helper_refused,
        check_override_allows_unverified,
        check_download_failure_only_warns,
    ):
        try:
            check()
        except Exception as exc:  # noqa: BLE001
            report(check.__name__, False, f"raised {exc!r}")
    if FAILURES:
        print(f"\n[supply-chain] {len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("\n[supply-chain] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
