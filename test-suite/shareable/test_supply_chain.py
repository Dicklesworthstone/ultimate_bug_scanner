#!/usr/bin/env python3
"""Supply-chain fail-closed checks (bridge-plan beads E2/E6, extended by A6).

The meta-runner must never execute a helper whose digest does not match the
pinned HELPER_CHECKSUMS table. These checks run a copy of `ubs` outside the git
checkout (so modules and helpers come from a --module-dir cache, which is the
only location the runner verifies) and serve "downloads" from a local file://
tree via UBS_REPO_RAW_BASE, so no network is involved and the refresh path can
be forced to return tampered bytes.

A6 extends coverage to the shared module library (lib/ubs-common.sh) and every
file of the ubs_core package: tampering any of them in the cache must be
repaired from a clean source, and tampering on both sides must fail closed.

Each check prints `[supply-chain:<name>] PASS/FAIL`; failures dump the captured
output so the log alone is enough to diagnose them.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS = REPO_ROOT / "ubs"
MODULES = REPO_ROOT / "modules"
PY_FIXTURE = REPO_ROOT / "test-suite" / "python" / "security" / "parser_token_compare_clean.py"
TAMPERED_HELPER = "helpers/resource_lifecycle_py.py"
LIB_ASSET = "lib/ubs-common.sh"
CORE_ASSET = "helpers/ubs_core/io.py"
TAMPER_SUFFIX = "\n# tampered by test_supply_chain\n"

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


def iter_shipped_files(root: Path) -> list[Path]:
    """Files under `root` that ship and are checksum-pinned (no pycache)."""
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


class Sandbox:
    """A ubs copy outside the checkout + a module cache + a local raw base."""

    def __init__(
        self,
        tmp: Path,
        *,
        tamper: bool = False,
        serve_tampered: bool = False,
        missing_helper: bool = False,
        tamper_targets: tuple[str, ...] = (TAMPERED_HELPER,),
    ) -> None:
        self.tmp = tmp
        self.bin_dir = tmp / "bin"
        self.module_dir = tmp / "cache"
        self.raw_base = tmp / "raw"
        self.bin_dir.mkdir()
        shutil.copy2(UBS, self.bin_dir / "ubs")
        (self.module_dir / "helpers").mkdir(parents=True)
        (self.module_dir / "lib").mkdir()
        shutil.copy2(MODULES / "ubs-python.sh", self.module_dir / "ubs-python.sh")
        for helper in (MODULES / "helpers").iterdir():
            if helper.is_file():
                shutil.copy2(helper, self.module_dir / "helpers" / helper.name)
        # The shared module library and the ubs_core package ship through the
        # same helper channel (beads A1/A2) and must be cached recursively.
        (self.module_dir / "helpers" / "ubs_core").mkdir(parents=True, exist_ok=True)
        for asset in (LIB_ASSET,):
            shutil.copy2(MODULES / asset, self.module_dir / asset)
        for core_file in iter_shipped_files(MODULES / "helpers" / "ubs_core"):
            rel = core_file.relative_to(MODULES)
            (self.module_dir / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(core_file, self.module_dir / rel)
        tampered = self.module_dir / TAMPERED_HELPER
        if missing_helper:
            tampered.unlink()
        elif tamper:
            for rel in tamper_targets:
                target = self.module_dir / rel
                target.write_text(target.read_text(encoding="utf-8") + TAMPER_SUFFIX, encoding="utf-8")
        # Local "raw.githubusercontent.com": both the release tag and main paths.
        for ref in (f"v{ubs_version()}", "main"):
            mod_raw_dir = self.raw_base / ref / "modules"
            mod_raw_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(MODULES / "ubs-python.sh", mod_raw_dir / "ubs-python.sh")
            dest = mod_raw_dir / "helpers"
            dest.mkdir(parents=True, exist_ok=True)
            for helper in (MODULES / "helpers").iterdir():
                if helper.is_file():
                    shutil.copy2(helper, dest / helper.name)
            lib_dest = mod_raw_dir / "lib"
            lib_dest.mkdir(parents=True, exist_ok=True)
            for lib in (MODULES / "lib").glob("*.sh"):
                shutil.copy2(lib, lib_dest / lib.name)
            core_dest = mod_raw_dir / "helpers" / "ubs_core"
            core_dest.mkdir(parents=True, exist_ok=True)
            for core_file in iter_shipped_files(MODULES / "helpers" / "ubs_core"):
                shutil.copy2(core_file, core_dest / core_file.name)
            if serve_tampered:
                for rel in tamper_targets:
                    served = mod_raw_dir / rel
                    served.write_text(served.read_text(encoding="utf-8") + TAMPER_SUFFIX, encoding="utf-8")

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
        return subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied UBS argv scans the fixed Python fixture using a local raw tree.


class CheckoutSandbox(Sandbox):
    """Retained source checkout plus a separate installed runner and file:// mirror.

    Unlike the ordinary cache controls, source-owned bytes must never be
    repaired by downloading over them. All mutation targets belong to this
    test fixture; the actual repository's executable is only copied, never run.
    """

    targets = (TAMPERED_HELPER, CORE_ASSET, LIB_ASSET)

    def __init__(self, name: str, *, tracked: bool = False):
        artifacts = REPO_ROOT / "test-suite/artifacts/supply-chain-checkout"
        artifacts.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=name + "-", dir=artifacts))
        super().__init__(temporary)
        self.checkout = temporary / "checkout"
        self.checkout.mkdir()
        shutil.copy2(self.bin_dir / "ubs", self.checkout / "ubs")
        shutil.copytree(self.module_dir, self.checkout / "modules")
        self.module_dir = self.checkout / "modules"
        # Include the manifest and all modules: doctor must inspect this
        # complete source fixture without trying to install missing modules.
        for source in [MODULES / "contract.json", *MODULES.glob("ubs-*.sh")]:
            shutil.copy2(source, self.module_dir / source.name)
            for ref in (f"v{ubs_version()}", "main"):
                shutil.copy2(source, self.raw_base / ref / "modules" / source.name)
        self.fixture = temporary / "input.py"
        self.fixture.write_text("value = 1\n", encoding="utf-8")
        self.download_log = temporary / "downloads.log"
        self.download_log.write_text("", encoding="utf-8")
        self.tools = temporary / "fixture-tools"
        self.tools.mkdir()
        real_curl = shutil.which("curl")
        if real_curl is None:
            raise RuntimeError("curl is required by the source-checkout integrity fixture")
        curl = self.tools / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            'for argument in "$@"; do\n'
            '  case "$argument" in\n'
            '    file://*) printf "%s\\n" "$argument" >> "$UBS_TEST_SOURCE_DOWNLOAD_LOG" ;;\n'
            '    http://*|https://*) echo "external URLs are unavailable in this fixture" >&2; exit 22 ;;\n'
            '  esac\n'
            'done\n'
            "exec " + shlex.quote(real_curl) + ' --user-agent "OpenAI File Downloader, XaiImageApiFetch/1.0" "$@"\n',
            encoding="utf-8",
        )
        curl.chmod(0o755)
        if tracked:
            subprocess.run(["git", "init", "-q", "-b", "main", str(self.checkout)], check=True, capture_output=True, text=True, timeout=60)
            subprocess.run(["git", "-C", str(self.checkout), "add", "ubs", "modules"], check=True, capture_output=True, text=True, timeout=60)

    def edit(self, targets: tuple[str, ...] = targets) -> None:
        for relative in targets:
            path = self.module_dir / relative
            with path.open("a", encoding="utf-8") as stream:
                stream.write(TAMPER_SUFFIX)

    def snapshot(self):
        return {relative: {
            "sha256": hashlib.sha256((self.module_dir / relative).read_bytes()).hexdigest(),
            "inode": (self.module_dir / relative).stat().st_ino,
            "mtime_ns": (self.module_dir / relative).stat().st_mtime_ns,
        } for relative in self.targets}

    def requested_source_helpers(self):
        requests = self.download_log.read_text(encoding="utf-8").splitlines()
        return [url for url in requests if any(url.endswith("/modules/" + relative) for relative in self.targets)]

    def run_checkout(self, *, mode="scan", update=False, installed=False):
        runner = self.bin_dir / "ubs" if installed else self.checkout / "ubs"
        arguments = (["doctor", "--fix", "--format=json"] if mode == "doctor" else
                     ["--only=python", "--ci", "--format=json"])
        arguments.append("--module-dir=" + str(self.module_dir))
        if update:
            arguments.append("--update-modules")
        if mode != "doctor":
            arguments.append(str(self.fixture))
        env = dict(os.environ, NO_COLOR="1", UBS_NO_AUTO_UPDATE="1", UBS_NO_CACHE="1", UBS_SKIP_SIZE_CHECK="1",
                   UBS_ALLOW_UNVERIFIED_HELPERS="0", PYTHONDONTWRITEBYTECODE="1",
                   UBS_REPO_RAW_BASE="file://" + str(self.raw_base),
                   UBS_TEST_SOURCE_DOWNLOAD_LOG=str(self.download_log),
                   XDG_CACHE_HOME=str(self.tmp / "user-cache"), XDG_CONFIG_HOME=str(self.tmp / "user-config"),
                   PATH=str(self.tools) + os.pathsep + os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"))
        env.pop("UBS_VERIFIED_ASSET_DIR", None)
        command = [str(runner), *arguments]
        before = self.snapshot()
        started = time.monotonic()
        proc = subprocess.run(command, cwd=self.tmp, env=env, capture_output=True, text=True, timeout=300)
        (self.tmp / "stdout.log").write_text(proc.stdout, encoding="utf-8")
        (self.tmp / "stderr.log").write_text(proc.stderr, encoding="utf-8")
        (self.tmp / "result.json").write_text(json.dumps({
            "command": command, "cwd": str(self.tmp), "returncode": proc.returncode,
            "elapsed": time.monotonic() - started, "before": before, "after": self.snapshot(),
            "download_requests": self.requested_source_helpers(),
        }, indent=2) + "\n", encoding="utf-8")
        return proc


def check_checkout_helper_scan_preserves_edits() -> None:
    for relative in CheckoutSandbox.targets:
        name = "checkout_scan_preserves_" + relative.replace("/", "_")
        print(f"[supply-chain:{name}] RUN", flush=True)
        sb = CheckoutSandbox(name)
        sb.edit((relative,))
        before = sb.snapshot()
        proc = sb.run_checkout()
        combined = proc.stdout + proc.stderr
        ok = (proc.returncode == 2 and sb.snapshot() == before and not sb.requested_source_helpers()
              and "checkout" in combined.lower() and relative in combined)
        report(name, ok, f"exit={proc.returncode} source_preserved={sb.snapshot() == before} artifacts={sb.tmp}", proc)


def check_checkout_update_preserves_source_helpers() -> None:
    for edited in (False, True):
        name = "checkout_update_preserves_" + ("edited" if edited else "healthy") + "_helpers"
        print(f"[supply-chain:{name}] RUN", flush=True)
        sb = CheckoutSandbox(name)
        if edited:
            sb.edit()
        before = sb.snapshot()
        proc = sb.run_checkout(update=True)
        expected_exit = proc.returncode == 2 if edited else proc.returncode in (0, 1)
        ok = expected_exit and sb.snapshot() == before and not sb.requested_source_helpers()
        if not edited:
            try:
                payload = json.loads(proc.stdout)
                ok = ok and payload.get("status") == "ok" and payload.get("totals", {}).get("files") == 1
            except ValueError:
                ok = False
        report(name, ok, f"exit={proc.returncode} source_preserved={sb.snapshot() == before} artifacts={sb.tmp}", proc)


def check_checkout_doctor_fix_preserves_source_helpers() -> None:
    name = "checkout_doctor_fix_preserves_edited_helpers"
    print(f"[supply-chain:{name}] RUN", flush=True)
    sb = CheckoutSandbox(name)
    sb.edit()
    before = sb.snapshot()
    proc = sb.run_checkout(mode="doctor")
    try:
        payload = json.loads(proc.stdout)
        checks = {check["id"]: check for check in payload.get("checks", [])}
    except (ValueError, KeyError):
        checks = {}
    targets_reported = all(checks.get("helper:" + relative, {}).get("status") == "err" and
                           "checkout" in checks.get("helper:" + relative, {}).get("detail", "").lower()
                           for relative in sb.targets)
    ok = proc.returncode == 2 and sb.snapshot() == before and not sb.requested_source_helpers() and targets_reported
    report(name, ok, f"exit={proc.returncode} source_preserved={sb.snapshot() == before} artifacts={sb.tmp}", proc)


def check_installed_runner_preserves_tracked_module_dir_helpers() -> None:
    name = "installed_runner_preserves_tracked_module_dir_helpers"
    print(f"[supply-chain:{name}] RUN", flush=True)
    sb = CheckoutSandbox(name, tracked=True)
    sb.edit()
    before = sb.snapshot()
    proc = sb.run_checkout(installed=True)
    combined = proc.stdout + proc.stderr
    ok = (proc.returncode == 2 and sb.snapshot() == before and not sb.requested_source_helpers()
          and all(relative in combined for relative in sb.targets) and "checkout" in combined.lower())
    report(name, ok, f"exit={proc.returncode} source_preserved={sb.snapshot() == before} artifacts={sb.tmp}", proc)


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


def check_tampered_lib_refreshed_from_clean_source() -> None:
    # A6: a tampered cached copy of lib/ubs-common.sh is repaired from a clean
    # source and the scan proceeds (the library ships through the helper channel).
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=False, tamper_targets=(LIB_ASSET,)).run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode in (0, 1) and "failed verification" in combined and "refusing" not in combined
        report("tampered_lib_refreshed_from_clean_source", ok, f"exit={proc.returncode}", proc)


def test_tampered_lib_refused() -> None:
    # A6 acceptance: tampering lib/ubs-common.sh on BOTH sides fails closed (exit 2).
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=True, tamper_targets=(LIB_ASSET,)).run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode == 2 and "refusing to scan with unverified helpers" in combined
        report("test_tampered_lib_refused", ok, f"exit={proc.returncode}", proc)


def check_tampered_core_refreshed_from_clean_source() -> None:
    # A6: a tampered cached ubs_core file is repaired from a clean source.
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=False, tamper_targets=(CORE_ASSET,)).run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode in (0, 1) and "failed verification" in combined and "refusing" not in combined
        report("tampered_core_refreshed_from_clean_source", ok, f"exit={proc.returncode}", proc)


def check_tampered_core_refused() -> None:
    # A6: tampering a ubs_core file on BOTH sides fails closed (exit 2).
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=True, tamper_targets=(CORE_ASSET,)).run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode == 2 and "refusing to scan with unverified helpers" in combined
        report("tampered_core_refused", ok, f"exit={proc.returncode}", proc)


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


# ── Hashing subprocess killed mid-checksum ─────────────────────────────────
# Checksums are taken as `x="$(compute_sha256 f)"`. If that substitution
# subshell dies (bash's lastpipe SIGCHLD race segfaults it; OOM kills do the
# same), the runner used to report a missing sha256sum and delete the helper.
# A `sha256sum` stub first on PATH reproduces that deterministically: for the
# target file it kills its parent (the substitution subshell) with SIGSEGV, or
# in "fail" mode simply exits 1, then otherwise execs the real tool.
MISSING_TOOL_ADVICE = "install sha256sum, shasum, or openssl"
KILLER_STUB = """#!/bin/bash
for arg in "$@"; do
  if [[ "$arg" == *"$UBS_TEST_STUB_TARGET"* ]]; then
    case "$UBS_TEST_STUB_MODE" in
      fail) echo "stub: simulated read error" >&2; exit 1 ;;
      always) echo fired >> "$UBS_TEST_STUB_LOG"; kill -SEGV "$PPID"; sleep 2 ;;
      once)
        if [[ ! -s "$UBS_TEST_STUB_LOG" ]]; then
          echo fired >> "$UBS_TEST_STUB_LOG"; kill -SEGV "$PPID"; sleep 2
        fi ;;
    esac
  fi
done
exec "$UBS_TEST_REAL_SHA256SUM" "$@"
"""


def killer_stub_env(tmp: Path, target: str, mode: str) -> list[tuple[str, str]]:
    real = shutil.which("sha256sum", path="/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin")
    if real is None:
        raise RuntimeError("no real sha256sum found to wrap")
    stub_dir = tmp / "stub-bin"
    stub_dir.mkdir()
    stub = stub_dir / "sha256sum"
    stub.write_text(KILLER_STUB, encoding="utf-8")
    stub.chmod(0o755)
    log = tmp / "stub.log"
    log.write_text("", encoding="utf-8")
    return [
        ("PATH", f"{stub_dir}:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin:{os.environ.get('PATH', '')}"),
        ("UBS_TEST_REAL_SHA256SUM", real),
        ("UBS_TEST_STUB_TARGET", target),
        ("UBS_TEST_STUB_MODE", mode),
        ("UBS_TEST_STUB_LOG", str(log)),
    ]


def check_helper_checksum_signal_death_is_retried() -> None:
    """One killed hashing subshell is retried; the scan proceeds on a good helper."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp_s:
        tmp = Path(tmp_s)
        sb = Sandbox(tmp)
        proc = sb.run(*killer_stub_env(tmp, TAMPERED_HELPER, "once"))
        combined = proc.stdout + proc.stderr
        fired = "fired" in (tmp / "stub.log").read_text(encoding="utf-8")
        ok = (
            fired
            and proc.returncode in (0, 1)
            and '"totals"' in proc.stdout
            and "refusing" not in combined
            and MISSING_TOOL_ADVICE not in combined
            and (sb.module_dir / TAMPERED_HELPER).is_file()
        )
        report("helper_checksum_signal_death_is_retried", ok, f"exit={proc.returncode} fired={fired}", proc)


def check_helper_checksum_persistent_signal_death_keeps_helper() -> None:
    """A hashing subshell that keeps dying fails closed with a truthful reason
    and never deletes the (unjudged, byte-correct) cached helper."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp_s:
        tmp = Path(tmp_s)
        sb = Sandbox(tmp)
        helper = sb.module_dir / TAMPERED_HELPER
        before = helper.read_bytes()
        proc = sb.run(*killer_stub_env(tmp, TAMPERED_HELPER, "always"))
        combined = proc.stdout + proc.stderr
        ok = (
            proc.returncode == 2
            and "refusing to scan with unverified helpers" in combined
            and "signal 11" in combined
            and MISSING_TOOL_ADVICE not in combined
            and helper.is_file()
            and helper.read_bytes() == before
        )
        report("helper_checksum_persistent_signal_death_keeps_helper", ok, f"exit={proc.returncode} helper_kept={helper.is_file()}", proc)


def check_helper_checksum_tool_failure_is_not_missing_tool() -> None:
    """A hash tool that is present but fails is reported as such, not as absent."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp_s:
        tmp = Path(tmp_s)
        sb = Sandbox(tmp)
        proc = sb.run(*killer_stub_env(tmp, TAMPERED_HELPER, "fail"))
        combined = proc.stdout + proc.stderr
        ok = (
            proc.returncode == 2
            and "checksum tool sha256sum failed" in combined
            and MISSING_TOOL_ADVICE not in combined
            and (sb.module_dir / TAMPERED_HELPER).is_file()
        )
        report("helper_checksum_tool_failure_is_not_missing_tool", ok, f"exit={proc.returncode}", proc)


def check_module_checksum_signal_death_is_retried() -> None:
    """Same for the cached language module's own checksum."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp_s:
        tmp = Path(tmp_s)
        sb = Sandbox(tmp)
        proc = sb.run(*killer_stub_env(tmp, "cache/ubs-python.sh", "once"))
        combined = proc.stdout + proc.stderr
        fired = "fired" in (tmp / "stub.log").read_text(encoding="utf-8")
        ok = fired and proc.returncode in (0, 1) and '"totals"' in proc.stdout and MISSING_TOOL_ADVICE not in combined
        report("module_checksum_signal_death_is_retried", ok, f"exit={proc.returncode} fired={fired}", proc)


def setup_module_sandbox(dest: Path) -> None:
    (dest / "helpers").mkdir(parents=True, exist_ok=True)
    (dest / "lib").mkdir(parents=True, exist_ok=True)
    shutil.copy2(MODULES / "ubs-python.sh", dest / "ubs-python.sh")
    shutil.copy2(MODULES / LIB_ASSET, dest / LIB_ASSET)
    for helper in (MODULES / "helpers").iterdir():
        if helper.is_file():
            shutil.copy2(helper, dest / "helpers" / helper.name)
    (dest / "helpers" / "ubs_core").mkdir(parents=True, exist_ok=True)
    for core_file in iter_shipped_files(MODULES / "helpers" / "ubs_core"):
        rel = core_file.relative_to(MODULES)
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(core_file, dest / rel)


def standalone_scan_completed(proc: subprocess.CompletedProcess) -> bool:
    if proc.returncode not in (0, 1):
        return False
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return False
    return isinstance(doc, dict) and doc.get("language") == "python" and doc.get("files") == 1 and doc.get("status") == "ok"


def test_tampered_helper_refused() -> None:
    """Tamper the standalone v2 scanner's core helper -> exit 2 with remediation."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-standalone-") as tmp:
        mod_dir = Path(tmp)
        setup_module_sandbox(mod_dir)
        # resource_lifecycle_py.py belongs to the legacy meta-runner helper
        # inventory; the standalone v2 scanner imports ubs_core.io instead.
        target = mod_dir / CORE_ASSET
        target.write_text(target.read_text(encoding="utf-8") + TAMPER_SUFFIX, encoding="utf-8")

        env = os.environ.copy()
        env.update({
            "NO_COLOR": "1",
            "UBS_ALLOW_UNVERIFIED_HELPERS": "0",
            "PATH": "/usr/local/bin:/usr/bin:/bin" + (":" + os.environ.get("PATH", "") if os.environ.get("PATH") else ""),
        })
        env.pop("UBS_VERIFIED_ASSET_DIR", None)

        cmd = [str(mod_dir / "ubs-python.sh"), "--ci", "--format=json", str(PY_FIXTURE)]
        proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied module argv and fixed fixture exercise tampered-core refusal.
        combined = proc.stdout + proc.stderr
        ok = (
            proc.returncode == 2
            and "failed checksum verification" in combined
            and CORE_ASSET in combined
            and "doctor --fix" in combined
            and "UBS_ALLOW_UNVERIFIED_HELPERS=1" in combined
        )
        report("test_tampered_helper_refused", ok, f"exit={proc.returncode}", proc)


def test_standalone_checksum_signal_death() -> None:
    """lib/ubs-common.sh (standalone module run): a killed hashing subshell is
    retried once, and a persistent one fails closed without blaming the tool."""
    for mode in ("once", "always"):
        with tempfile.TemporaryDirectory(prefix="ubs-sc-standalone-") as tmp_s:
            tmp = Path(tmp_s)
            mod_dir = tmp / "mods"
            setup_module_sandbox(mod_dir)
            env = os.environ.copy()
            env.update({"NO_COLOR": "1", "UBS_ALLOW_UNVERIFIED_HELPERS": "0"})
            env.pop("UBS_VERIFIED_ASSET_DIR", None)
            env.update(dict(killer_stub_env(tmp, CORE_ASSET, mode)))
            cmd = [str(mod_dir / "ubs-python.sh"), "--ci", "--format=json", str(PY_FIXTURE)]
            proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied module argv scans the fixed fixture with a stub hash tool.
            combined = proc.stdout + proc.stderr
            fired = (tmp / "stub.log").stat().st_size > 0
            if mode == "once":
                ok = fired and standalone_scan_completed(proc) and MISSING_TOOL_ADVICE not in combined
            else:
                ok = (
                    fired
                    and proc.returncode == 2
                    and "signal 11" in combined
                    and CORE_ASSET in combined
                    and MISSING_TOOL_ADVICE not in combined
                    and (mod_dir / CORE_ASSET).is_file()
                )
            report(f"standalone_checksum_signal_death_{mode}", ok, f"exit={proc.returncode} fired={fired}", proc)


def test_standalone_module_verifies() -> None:
    """Standalone module run verifies against embedded checksum table."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-standalone-") as tmp:
        mod_dir = Path(tmp)
        setup_module_sandbox(mod_dir)

        env = os.environ.copy()
        env.update({
            "NO_COLOR": "1",
            "UBS_ALLOW_UNVERIFIED_HELPERS": "0",
            "PATH": "/usr/local/bin:/usr/bin:/bin" + (":" + os.environ.get("PATH", "") if os.environ.get("PATH") else ""),
        })
        env.pop("UBS_VERIFIED_ASSET_DIR", None)

        cmd = [str(mod_dir / "ubs-python.sh"), "--ci", "--format=json", str(PY_FIXTURE)]

        # 1. Clean standalone run succeeds (verifies embedded checksum table)
        proc_clean = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60)  # ubs:ignore[python.taint.command] - trusted test-runner env; pristine copied module argv scans the fixed Python fixture.
        clean_ok = (
            standalone_scan_completed(proc_clean)
            and "failed checksum verification" not in (proc_clean.stdout + proc_clean.stderr)
        )

        # 2. Tampered helper + UBS_ALLOW_UNVERIFIED_HELPERS=1 warns and proceeds
        target = mod_dir / CORE_ASSET
        target.write_text(target.read_text(encoding="utf-8") + TAMPER_SUFFIX, encoding="utf-8")
        env["UBS_ALLOW_UNVERIFIED_HELPERS"] = "1"
        proc_override = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied module argv tests the explicit override for a test-owned comment mutation.
        override_ok = (
            standalone_scan_completed(proc_override)
            and f"warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified helpers dir at {mod_dir / 'helpers'}" in proc_override.stderr
        )

        # 3. UBS_VERIFIED_ASSET_DIR set to empty dir refuses unverified fallback
        empty_dir = mod_dir / "empty_verified"
        empty_dir.mkdir()
        env["UBS_ALLOW_UNVERIFIED_HELPERS"] = "0"
        env["UBS_VERIFIED_ASSET_DIR"] = str(empty_dir)
        proc_refuse = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60)  # ubs:ignore[python.taint.command] - trusted test-runner env; fixed module argv tests refusal with a test-owned empty verified directory.
        refuse_ok = proc_refuse.returncode == 2 and (
            "unverified location" in (proc_refuse.stdout + proc_refuse.stderr)
            or "refusing" in (proc_refuse.stdout + proc_refuse.stderr)
        )

        ok = clean_ok and override_ok and refuse_ok
        report(
            "test_standalone_module_verifies",
            ok,
            f"clean={clean_ok} override={override_ok} refuse={refuse_ok}",
            proc_clean if not clean_ok else (proc_override if not override_ok else proc_refuse),
        )


def check_tampered_module_refreshed_from_clean_source() -> None:
    # A corrupted cached module is repaired from the (clean) source and scan proceeds.
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        sb = Sandbox(Path(tmp), tamper=True, serve_tampered=False, tamper_targets=("ubs-python.sh",))
        proc = sb.run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode in (0, 1) and "failed verification" in combined and "refusing" not in combined
        report("tampered_module_refreshed_from_clean_source", ok, f"exit={proc.returncode}", proc)


def test_tampered_module_refused() -> None:
    # A corrupted cached module where download is also tampered fails closed (exit 2).
    with tempfile.TemporaryDirectory(prefix="ubs-sc-") as tmp:
        proc = Sandbox(Path(tmp), tamper=True, serve_tampered=True, tamper_targets=("ubs-python.sh",)).run()
        combined = proc.stdout + proc.stderr
        ok = proc.returncode == 2 and "failed verification" in combined and "failed to ensure module" in combined
        report("test_tampered_module_refused", ok, f"exit={proc.returncode}", proc)


def test_corrupted_ast_grep_zip_refused() -> None:
    """Corrupted ast-grep zip served from local fixture -> refusal with exit 2."""
    machine = platform.machine().lower()
    arch = "x86_64" if machine in ("x86_64", "amd64") else ("aarch64" if machine in ("arm64", "aarch64") else machine)
    sys_name = platform.system().lower()
    os_target = "apple-darwin" if sys_name == "darwin" else "unknown-linux-gnu"
    target = f"{arch}-{os_target}"

    js_fixture = REPO_ROOT / "test-suite" / "js" / "clean" / "security.js"

    with tempfile.TemporaryDirectory(prefix="ubs-sc-astgrep-") as tmp:
        p = Path(tmp)
        bin_dir = p / "bin"
        bin_dir.mkdir()
        shutil.copy2(UBS, bin_dir / "ubs")

        cache_dir = p / "cache"
        cache_dir.mkdir()
        (cache_dir / "helpers").mkdir()
        (cache_dir / "lib").mkdir()
        shutil.copy2(MODULES / "ubs-js.sh", cache_dir / "ubs-js.sh")
        shutil.copy2(MODULES / "lib" / "ubs-common.sh", cache_dir / "lib" / "ubs-common.sh")

        tools_dir = p / "tools"
        tools_dir.mkdir()

        ast_grep_dir = p / "ast_grep_fixtures"
        ast_grep_dir.mkdir()
        (ast_grep_dir / f"app-{target}.zip").write_bytes(b"PK\x03\x04corrupted_ast_grep_zip_payload")

        env = os.environ.copy()
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        env["NO_COLOR"] = "1"
        env["UBS_AST_GREP_BASE_URL"] = f"file://{ast_grep_dir}"
        env["UBS_TOOLS_DIR"] = str(tools_dir)
        env["UBS_NO_AUTO_UPDATE"] = "1"
        env["UBS_ALLOW_UNVERIFIED_HELPERS"] = "1"

        cmd = [str(bin_dir / "ubs"), f"--module-dir={cache_dir}", "--only=js", "--ci", "--format=json", str(js_fixture)]
        proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied UBS argv checks a test-owned corrupt archive served through file://.
        combined = proc.stdout + proc.stderr
        ok = (
            proc.returncode == 2
            and ("ast-grep checksum mismatch" in combined or "ast-grep-missing" in combined)
        )
        report("test_corrupted_ast_grep_zip_refused", ok, f"exit={proc.returncode}", proc)


def test_self_update_bad_signature_refused() -> None:
    """ubs --update against fixture server with bad SHA256SUMS signature -> nonzero and binary untouched."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-update-") as tmp:
        p = Path(tmp)
        bin_dir = p / "bin"
        bin_dir.mkdir()
        installed_ubs = bin_dir / "ubs"
        shutil.copy2(UBS, installed_ubs)
        installed_ubs.chmod(0o755)
        orig_sha = hashlib.sha256(installed_ubs.read_bytes()).hexdigest()

        release_dir = p / "release"
        release_dir.mkdir()
        (release_dir / "SHA256SUMS").write_text("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ubs\n", encoding="utf-8")
        (release_dir / "SHA256SUMS.minisig").write_text(
            "untrusted comment: signature\nRWTe1234567890\ntrusted comment: timestamp:1234\ncorrupted\n",
            encoding="utf-8",
        )
        (release_dir / "ubs").write_text("#!/usr/bin/env bash\necho evil\n", encoding="utf-8")

        env = os.environ.copy()
        env["UBS_RELEASE_BASE"] = f"file://{release_dir}"
        env["UBS_MINISIGN_PUBKEY"] = "RWS+jJ7psytzl3v4znpraY9VWBQrICXBFmT3VwvxpTzbuV2Q/CBTDmVJ"
        env["FORCE_SELF_UPDATE"] = "1"
        env["NO_COLOR"] = "1"

        proc = subprocess.run([str(installed_ubs), "--update"], cwd=p, env=env, capture_output=True, text=True, timeout=60)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied UBS --update checks a test-owned local release with a bad signature.
        new_sha = hashlib.sha256(installed_ubs.read_bytes()).hexdigest()

        combined = proc.stdout + proc.stderr
        ok = (
            proc.returncode != 0
            and "minisign signature verification failed" in combined
            and orig_sha == new_sha
        )
        report(
            "test_self_update_bad_signature_refused",
            ok,
            f"exit={proc.returncode} binary_untouched={orig_sha == new_sha}",
            proc,
        )


def _self_update_release(p: Path, marker: Path) -> tuple[Path, Path, dict[str, str]]:
    """Install a ubs copy plus a verified fake release under a scratch HOME.

    The release payload is a stub "newer" ubs that records its argv in
    `marker` and exits 7, so a test can tell whether (and how) the updated
    binary was re-executed. HOME/XDG_CACHE_HOME point into `p` so nothing
    touches the real user's cache or installed binaries.
    """
    home = p / "home"
    home.mkdir()
    bin_dir = p / "bin"
    bin_dir.mkdir()
    installed_ubs = bin_dir / "ubs"
    shutil.copy2(UBS, installed_ubs)
    installed_ubs.chmod(0o755)

    release_dir = p / "release"
    release_dir.mkdir()
    payload = (
        "#!/usr/bin/env bash\n"
        'UBS_VERSION="99.0.0"\n'
        f"printf '%s\\n' \"argc=$#\" \"$@\" > {shlex.quote(str(marker))}\n"
        "exit 7\n"
    )
    (release_dir / "ubs").write_text(payload, encoding="utf-8")
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    (release_dir / "SHA256SUMS").write_text(f"{digest}  ubs\n", encoding="utf-8")

    env = os.environ.copy()
    for key in ("UBS_MINISIGN_PUBKEY", "UBS_NO_AUTO_UPDATE", "CI", "FORCE_SELF_UPDATE", "UBS_ENABLE_AUTO_UPDATE"):
        env.pop(key, None)
    env.update({
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "UBS_RELEASE_BASE": f"file://{release_dir}",
        "NO_COLOR": "1",
    })
    return installed_ubs, release_dir / "ubs", env


def test_self_update_only_exits_zero_without_rerun() -> None:
    """`ubs --update` that installs a new version exits 0 and does not re-run (scan) with the new binary."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-update-ok-") as tmp:
        p = Path(tmp)
        marker = p / "rerun-argv"
        installed_ubs, payload, env = _self_update_release(p, marker)
        work = p / "work"
        work.mkdir()
        proc = subprocess.run([str(installed_ubs), "--update"], cwd=work, env=env, capture_output=True, text=True, timeout=120)  # ubs:ignore[python.taint.command] - trusted test-runner env; copied UBS --update installs a test-owned local release in a scratch HOME.
        replaced = installed_ubs.read_bytes() == payload.read_bytes()
        ok = (
            proc.returncode == 0
            and replaced
            and not marker.exists()
            and "Updated successfully" in proc.stderr
        )
        report(
            "test_self_update_only_exits_zero_without_rerun",
            ok,
            f"exit={proc.returncode} replaced={replaced} reran={marker.exists()}",
            proc,
        )


def test_auto_update_reexecs_with_original_args() -> None:
    """Opt-in auto-update ahead of real work re-execs the new binary with the user's original argv."""
    with tempfile.TemporaryDirectory(prefix="ubs-sc-autoupdate-") as tmp:
        p = Path(tmp)
        marker = p / "rerun-argv"
        installed_ubs, payload, env = _self_update_release(p, marker)
        env["UBS_ENABLE_AUTO_UPDATE"] = "1"
        target = p / "target dir"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n", encoding="utf-8")
        argv = ["--format=json", "--only=python", str(target)]
        proc = subprocess.run([str(installed_ubs), *argv], cwd=p, env=env, capture_output=True, text=True, timeout=120)  # ubs:ignore[python.taint.command] - trusted test-runner env; auto-update against a test-owned local release in a scratch HOME.
        replaced = installed_ubs.read_bytes() == payload.read_bytes()
        recorded = marker.read_text(encoding="utf-8").splitlines() if marker.exists() else []
        expected = [f"argc={len(argv)}", *argv]
        ok = proc.returncode == 7 and replaced and recorded == expected
        report(
            "test_auto_update_reexecs_with_original_args",
            ok,
            f"exit={proc.returncode} replaced={replaced} argv={recorded!r}",
            proc,
        )


def test_sha256sums_coverage() -> None:
    """Assert SHA256SUMS exists, covers required release files, and all digests match."""
    sums_file = REPO_ROOT / "SHA256SUMS"
    if not sums_file.is_file():
        report("test_sha256sums_coverage", False, "SHA256SUMS file missing")
        return

    content = sums_file.read_text(encoding="utf-8").strip()
    if not content:
        report("test_sha256sums_coverage", False, "SHA256SUMS is empty")
        return

    required = {"install.sh", "ubs"}
    found_entries: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            sha, name = parts
            name = name.strip()
            found_entries[name] = sha

    missing = required - set(found_entries.keys())
    if missing:
        report("test_sha256sums_coverage", False, f"Missing required entries: {missing}")
        return

    mismatches = []
    for name, expected_sha in found_entries.items():
        file_path = REPO_ROOT / name
        if not file_path.is_file():
            mismatches.append(f"{name} (file not found)")
            continue
        actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            mismatches.append(f"{name} (expected {expected_sha}, got {actual_sha})")

    ok = len(mismatches) == 0
    report(
        "test_sha256sums_coverage",
        ok,
        f"verified {len(found_entries)} file(s)" if ok else f"mismatches: {mismatches}",
    )


def main() -> int:
    for check in (
        check_checkout_helper_scan_preserves_edits,
        check_checkout_update_preserves_source_helpers,
        check_checkout_doctor_fix_preserves_source_helpers,
        check_installed_runner_preserves_tracked_module_dir_helpers,
        check_healthy_cache_scans,
        check_tampered_helper_refreshed_from_clean_source,
        check_tampered_helper_refused,
        check_tampered_lib_refreshed_from_clean_source,
        test_tampered_lib_refused,
        check_tampered_core_refreshed_from_clean_source,
        check_tampered_core_refused,
        check_override_allows_unverified,
        check_download_failure_only_warns,
        check_helper_checksum_signal_death_is_retried,
        check_helper_checksum_persistent_signal_death_keeps_helper,
        check_helper_checksum_tool_failure_is_not_missing_tool,
        check_module_checksum_signal_death_is_retried,
        test_standalone_checksum_signal_death,
        test_tampered_helper_refused,
        test_standalone_module_verifies,
        check_tampered_module_refreshed_from_clean_source,
        test_tampered_module_refused,
        test_corrupted_ast_grep_zip_refused,
        test_self_update_bad_signature_refused,
        test_self_update_only_exits_zero_without_rerun,
        test_auto_update_reexecs_with_original_args,
        test_sha256sums_coverage,
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
