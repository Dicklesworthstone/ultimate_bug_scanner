#!/usr/bin/env python3
"""GH #170: cache publication must never rewrite a running executable.

The unit cases use native executable fixtures, the real provisioning functions
read from ubs, and slow extraction to make torn writes observable. --integration
also runs real, uncached JS/TS scans using the pinned ast-grep release supplied
by UBS_CACHE_TEST_AST_ARCHIVE (not a fake scanner). All scratch data is outside
the checkout. UBS_CACHE_TEST_RUNNER selects an unmodified runner for negative
controls; no implementation is copied into this test.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNNER = Path(os.environ.get("UBS_CACHE_TEST_RUNNER", ROOT / "ubs")).resolve()
SOURCE = RUNNER.read_text()
TARGET = "x86_64-unknown-linux-gnu"
AST_ASSET = f"app-{TARGET}.zip"
INTEGRATION = "--integration" in sys.argv
if INTEGRATION:
    sys.argv.remove("--integration")


def function(name: str, optional: bool = False) -> str:
    match = re.search(r"^" + re.escape(name) + r"\(\)\{\n.*?^\}\n", SOURCE, re.M | re.S)
    if not match:
        if optional:
            return ""
        raise AssertionError(f"production function not found: {name}")
    return match.group(0)


FUNCTIONS = "\n".join(function(name) for name in (
    "checksum_tool_name", "compute_sha256", "sha256_into",
    "download_url_to_file", "extract_zip_member", "verify_ast_grep_bin",
    "looks_like_toon_rust_encoder", "ensure_ast_grep_tool_cache", "ensure_toon_tool_cache",
)) + function("install_tool_cache_binary", optional=True)


def fingerprint(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


class PublicationObserver:
    """Read through the public name, rejecting anything but old or complete bytes."""

    def __init__(self, path: Path, complete: bytes):
        self.path = path
        self.allowed = {complete}
        self.seen = path.exists()
        if self.seen:
            self.allowed.add(path.read_bytes())
        self.errors: list[str] = []
        self.samples = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.observe, daemon=True)

    def observe(self) -> None:
        while not self.stop.is_set():
            try:
                data = self.path.read_bytes()
                self.seen = True
                if data not in self.allowed:
                    self.errors.append(f"TRUNCATED_EXECUTABLE: {self.path}: {len(data)} bytes")
                    return
            except FileNotFoundError:
                if self.seen:
                    self.errors.append(f"EXECUTABLE_DISAPPEARED: {self.path}")
                    return
            except OSError as exc:
                self.errors.append(f"cannot inspect executable: {exc}")
                return
            self.samples += 1
            self.stop.wait(0.001)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise AssertionError("publication observer did not stop")


class CacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="ubs-cache-native-")
        cls.addClassCleanup(cls.build.cleanup)
        root = Path(cls.build.name)
        # An actual executable triggers ETXTBSY on Linux when rewritten in place.
        (root / "tool.c").write_text(r'''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--hold")) {
        puts("ready"); fflush(stdout); sleep(30); return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--version")) puts("ast-grep 0.45.3");
    if (argc > 1 && !strcmp(argv[1], "--help"))
        puts("TOON reference implementation in Rust (JSON <-> TOON)");
    return 0;
}
''')
        compiler = shutil.which("cc")
        if not compiler:
            raise RuntimeError("cc is required for the native executable regression")
        subprocess.run([compiler, str(root / "tool.c"), "-o", str(root / "tool")], check=True)
        cls.binary = (root / "tool").read_bytes() + b"UBS-CACHE-PADDING\n" * 32768

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs-cache-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.mirror = self.root / "mirror"
        self.mirror.mkdir()
        self.tools = self.root / "tools"
        self.ast_root = self.tools / "ast-grep/test" / TARGET
        self.ast_bin = self.ast_root / "ast-grep"
        self.ast_zip = self.ast_root / AST_ASSET
        self.toon_asset = "toon-linux-amd64.tar.xz"
        self.make_archives()
        self.overrides = ""
        self.env = os.environ.copy()
        self.driver = self.root / "driver.sh"

    def make_archives(self, binary: bytes | None = None, member: str = "ast-grep"):
        data = self.binary if binary is None else binary
        with zipfile.ZipFile(self.mirror / AST_ASSET, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr(member, data)
        with tarfile.open(self.mirror / "toon-linux-amd64.tar.xz", "w:xz") as archive:
            info = tarfile.TarInfo("toon")
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))
        with zipfile.ZipFile(self.mirror / "toon-windows-amd64.zip", "w") as archive:
            archive.writestr("toon.exe", data)
        self.ast_sha = hashlib.sha256((self.mirror / AST_ASSET).read_bytes()).hexdigest()

    def toon_bin(self) -> Path:
        name = "toon.exe" if self.toon_asset.endswith(".zip") else "toon"
        return self.tools / "toon/test" / self.toon_asset.split(".")[0] / name

    def write_driver(self):
        toon_sha = hashlib.sha256((self.mirror / self.toon_asset).read_bytes()).hexdigest()
        values = {
            "TOOLS_DIR": str(self.tools), "AST_GREP_BASE_URL": self.mirror.as_uri(),
            "TOON_BASE_URL": self.mirror.as_uri(), "UBS_TEST_AST_GREP_SHA256": self.ast_sha,
            "TEST_TOON_ASSET": self.toon_asset, "TEST_TOON_BIN": str(self.toon_bin()),
        }
        setup = "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items())
        self.driver.write_text("""#!/usr/bin/env bash
set -Eeuo pipefail
need_cmd(){ command -v "$1" >/dev/null 2>&1; }
ensure_dir(){ mkdir -p "$1"; }
say_err(){ printf '%s\\n' "$*" >&2; }
RED= RESET= DIM= INFO= X= SHA256_ERR= QUIET=1
AST_GREP_VERSION=test TOON_VERSION=test
ast_grep_target_triple(){ echo x86_64-unknown-linux-gnu; }
toon_asset_name(){ echo "$TEST_TOON_ASSET"; }
toon_cached_bin_path(){ echo "$TEST_TOON_BIN"; }
declare -A AST_GREP_ASSET_SHA256=()
""" + setup + f"\ndeclare -A TOON_ASSET_SHA256=([{shlex.quote(self.toon_asset)}]={toon_sha})\n"
            + FUNCTIONS + "\n" + self.overrides + "\n"
            # Match the real caller: errexit is disabled inside this conditional.
            + 'if result="$("$@")"; then printf "%s\\n" "$result"; else exit $?; fi\n')

    def run_tool(self, *args):
        self.write_driver()
        return subprocess.run(["bash", str(self.driver), *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=60)

    def seed(self, path: Path, data: bytes):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755)

    def seed_ast(self, data: bytes | None = None):
        self.seed(self.ast_bin, self.binary if data is None else data)
        shutil.copyfile(self.mirror / AST_ASSET, self.ast_zip)

    def assert_clean(self):
        self.assertEqual(list(self.tools.rglob(".ubs-*")), [], "private staging files leaked")

    def slow_extractor(self, executable: str):
        """Slow only the output stream; run the real unzip/tar parser and status."""
        real = shutil.which(executable)
        self.assertIsNotNone(real)
        shim = self.root / "shim"
        shim.mkdir(exist_ok=True)
        (shim / executable).write_text(f"#!{sys.executable}\n" + """
import subprocess, sys, time
p = subprocess.Popen([REAL, *sys.argv[1:]], stdout=subprocess.PIPE)
while True:
    data = p.stdout.read(8192)
    if not data:
        break
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    time.sleep(0.002)
sys.exit(p.wait())
""".replace("REAL", repr(real)))
        (shim / executable).chmod(0o755)
        self.env["PATH"] = str(shim) + os.pathsep + self.env["PATH"]
        if executable == "unzip":
            self.overrides += '\nneed_cmd(){ [[ "$1" != python3 ]] && command -v "$1" >/dev/null 2>&1; }\n'

    def parallel(self, tool: str, path: Path, workers: int = 12):
        self.write_driver()
        gate = threading.Barrier(workers)

        def provision(_):
            gate.wait(timeout=30)
            return subprocess.run(["bash", str(self.driver), tool], cwd=self.root,
                                  env=self.env, capture_output=True, text=True, timeout=90)

        with PublicationObserver(path, self.binary) as observer:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(provision, range(workers)))
        self.assertEqual(observer.errors, [], "public executable was modified in place")
        self.assertGreater(observer.samples, 0)
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(path))
        self.assertEqual(path.read_bytes(), self.binary)
        self.assert_clean()

    def test_warm_ast_cache_is_read_only(self):
        self.seed_ast()
        before = fingerprint(self.ast_bin)
        self.parallel("ensure_ast_grep_tool_cache", self.ast_bin)
        self.assertEqual(fingerprint(self.ast_bin), before, "CACHE_REWRITTEN")

    def test_warm_running_native_binary_is_reused(self):
        self.seed_ast()
        process = subprocess.Popen([str(self.ast_bin), "--hold"], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "ready")
            result = self.run_tool("ensure_ast_grep_tool_cache")
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()

    def test_parallel_cold_ast_cache(self):
        self.parallel("ensure_ast_grep_tool_cache", self.ast_bin)

    def test_parallel_ast_repair_unzip(self):
        self.seed_ast(b"broken old executable\n")
        self.slow_extractor("unzip")
        self.parallel("ensure_ast_grep_tool_cache", self.ast_bin)

    def test_bad_archive_cannot_bypass_integrity_with_good_binary(self):
        self.seed_ast()
        before = fingerprint(self.ast_bin)
        self.ast_zip.write_bytes(b"corrupt cached archive")
        (self.mirror / AST_ASSET).write_bytes(b"corrupt downloaded archive")
        result = self.run_tool("ensure_ast_grep_tool_cache")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(fingerprint(self.ast_bin), before)
        self.assertEqual(self.ast_bin.read_bytes(), self.binary)
        self.assert_clean()

    def test_archive_repair_does_not_rewrite_good_binary(self):
        self.seed_ast()
        before = fingerprint(self.ast_bin)
        self.ast_zip.write_bytes(b"corrupt archive")
        result = self.run_tool("ensure_ast_grep_tool_cache")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fingerprint(self.ast_bin), before, "CACHE_REWRITTEN")
        self.assertEqual(hashlib.sha256(self.ast_zip.read_bytes()).hexdigest(), self.ast_sha)
        self.assert_clean()

    def test_bad_candidate_preserves_existing_target(self):
        for tool in ("ensure_ast_grep_tool_cache", "ensure_toon_tool_cache"):
            with self.subTest(tool=tool):
                self.make_archives(b"not an executable\n")
                path = self.ast_bin if "ast_grep" in tool else self.toon_bin()
                self.seed(path, b"existing broken executable\n")
                before = fingerprint(path)
                result = self.run_tool(tool)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fingerprint(path), before)
                self.assert_clean()

    def test_missing_zip_member_is_failure_with_unzip(self):
        self.make_archives(member="not-ast-grep")
        self.slow_extractor("unzip")
        result = self.run_tool("extract_zip_member", str(self.mirror / AST_ASSET),
                               "ast-grep", str(self.root / "unpacked"))
        self.assertNotEqual(result.returncode, 0, "unzip error was swallowed")

    def test_download_failures_are_not_reported_as_success(self):
        for command in ("curl", "wget"):
            with self.subTest(command=command):
                self.overrides = f'\nneed_cmd(){{ [[ "$1" == {command} ]]; }}\n{command}(){{ return 23; }}\n'
                result = self.run_tool("download_url_to_file", "unused", str(self.root / "download"))
                self.assertEqual(result.returncode, 23)

    def test_hash_failure_is_closed_without_rewriting_binary(self):
        self.seed_ast()
        before = fingerprint(self.ast_bin)
        self.overrides = '\nsha256_into(){ SHA256_ERR="injected read error"; return 3; }\n'
        result = self.run_tool("ensure_ast_grep_tool_cache")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(fingerprint(self.ast_bin), before)
        self.assert_clean()

    def test_publish_and_permission_failures_preserve_target(self):
        self.seed_ast(b"old broken binary\n")
        for command in ("mv", "chmod"):
            with self.subTest(command=command):
                before = fingerprint(self.ast_bin)
                self.overrides = f'\n{command}(){{ return 1; }}\n'
                result = self.run_tool("ensure_ast_grep_tool_cache")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fingerprint(self.ast_bin), before)
                self.assert_clean()

    def test_parallel_toon_tar_repair(self):
        self.seed(self.toon_bin(), b"broken old toon\n")
        self.slow_extractor("tar")
        self.parallel("ensure_toon_tool_cache", self.toon_bin())

    def test_parallel_toon_zip_cold(self):
        self.toon_asset = "toon-windows-amd64.zip"
        self.slow_extractor("unzip")
        self.parallel("ensure_toon_tool_cache", self.toon_bin())

    def test_warm_toon_cache_is_read_only(self):
        self.seed(self.toon_bin(), self.binary)
        before = fingerprint(self.toon_bin())
        self.parallel("ensure_toon_tool_cache", self.toon_bin())
        self.assertEqual(fingerprint(self.toon_bin()), before, "CACHE_REWRITTEN")

    def test_toon_bad_archive_preserves_target(self):
        self.seed(self.toon_bin(), b"existing broken toon\n")
        before = fingerprint(self.toon_bin())
        self.overrides = '\nTOON_ASSET_SHA256["$TEST_TOON_ASSET"]=' + "0" * 64 + '\n'
        result = self.run_tool("ensure_toon_tool_cache")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(fingerprint(self.toon_bin()), before)
        self.assert_clean()


@unittest.skipUnless(INTEGRATION, "pass --integration and UBS_CACHE_TEST_AST_ARCHIVE for real scans")
class ParallelScans(unittest.TestCase):
    def test_real_parallel_js_scans(self):
        archive_path = Path(os.environ["UBS_CACHE_TEST_AST_ARCHIVE"]).resolve()
        expected = re.search(r"\[x86_64-unknown-linux-gnu\]='([a-f0-9]{64})'", SOURCE)
        self.assertIsNotNone(expected, "pinned release checksum missing")
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), expected[1])
        version = re.search(r'^AST_GREP_VERSION="([^"]+)"', SOURCE, re.M)[1]
        with zipfile.ZipFile(archive_path) as archive:
            binary = archive.read("ast-grep")
        with tempfile.TemporaryDirectory(prefix="ubs-real-parallel-") as tmp:
            root = Path(tmp)
            mirror = root / "mirror"
            mirror.mkdir()
            shutil.copyfile(archive_path, mirror / AST_ASSET)
            projects = []
            for i in range(3):
                project = root / f"p{i}"
                project.mkdir()
                (project / "a.tsx").write_text(f"export const A{i} = () => <div>{{{i}}}</div>;\n")
                projects.append(project)
            for state in ("warm", "cold", "repair"):
                with self.subTest(state=state):
                    tools = root / state / "tools"
                    tool_root = tools / "ast-grep" / version / TARGET
                    path = tool_root / "ast-grep"
                    if state != "cold":
                        tool_root.mkdir(parents=True)
                        shutil.copyfile(archive_path, tool_root / AST_ASSET)
                        path.write_bytes(binary if state == "warm" else b"broken executable\n")
                        path.chmod(0o755)
                    before = fingerprint(path) if state == "warm" else None
                    env = {k: v for k, v in os.environ.items()
                           if not k.startswith(("UBS_", "TOON_", "XDG_"))}
                    env.update(UBS_TEST_NO_PATH_AST_GREP="1", UBS_TOOLS_DIR=str(tools),
                               UBS_AST_GREP_BASE_URL=mirror.as_uri(), UBS_NO_AUTO_UPDATE="1",
                               UBS_NO_CACHE="1", XDG_DATA_HOME=str(root / state / "data"),
                               XDG_CACHE_HOME=str(root / state / "cache"), NO_COLOR="1")
                    env.pop("FORCE_SELF_UPDATE", None)

                    def scan(i):
                        project = projects[i % len(projects)]
                        return subprocess.run(["bash", str(RUNNER), "--only=js", "--format=json",
                                               "--ci", "--no-cache", "--no-auto-update", "."],
                                              cwd=project, env=env, capture_output=True,
                                              text=True, timeout=180)

                    with PublicationObserver(path, binary) as observer:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                            results = list(pool.map(scan, range(12)))
                    self.assertEqual(observer.errors, [])
                    self.assertGreater(observer.samples, 0)
                    for i, result in enumerate(results):
                        self.assertEqual(result.returncode, 0,
                                         f"{state} scan {i}: {result.stderr}\n{result.stdout}")
                        report = json.loads(result.stdout)
                        self.assertTrue(report.get("scanners"), report)
                        self.assertNotEqual(report.get("status"), "partial", report)
                    self.assertEqual(path.read_bytes(), binary)
                    if before:
                        self.assertEqual(fingerprint(path), before, "CACHE_REWRITTEN")
                    self.assertEqual(list(tools.rglob(".ubs-*")), [])
                    print(f"{state}: 12/12 real uncached JS scans passed; "
                          f"{observer.samples} publication observations", flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
