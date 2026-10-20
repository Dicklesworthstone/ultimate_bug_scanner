#!/usr/bin/env python3
"""Version-bound module generations for the UBS self-updater (issue #174).

This standard-library-only source is embedded in the standalone runner by
scripts/embed_release_generation.py. It is not downloaded or imported at run
time: the existing release checksum/signature gate authenticates the runner
before its target manifest is read. No downloaded shell code is evaluated.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterator, NamedTuple

MAX_ASSET_BYTES = 32 * 1024 * 1024
MAX_RUNNER_BYTES = 4 * 1024 * 1024
GENERATION_DIRECTORY = ".ubs-releases"
READY_FILE = ".ubs-ready.json"
# This is the literal contract pin in the released v5.4.17 runner. Recognizing
# a known old contract permits migration, NOT execution of old/unverified
# assets. An arbitrary damaged contract must still fail the ordinary gate.
LEGACY_CONTRACTS = frozenset({
    "406ecd66239cf0c23b2611c98bf1732114934e416c60d0edac6e20ca716129f8",
})


class UpdateError(ValueError):
    """An update cannot safely be prepared or selected."""


class Manifest(NamedTuple):
    version: str
    runner_sha256: str
    assets: dict[str, str]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, limit: int = MAX_ASSET_BYTES) -> bytes:
    """Hash/read the same opened regular file; never block on a FIFO."""
    # The built-in opener owns the descriptor even if stream initialization
    # fails (for example for a directory); fdopen(os.open(...)) can leak it.
    with open(path, "rb", opener=lambda name, flags: os.open(
            name, flags | os.O_NONBLOCK | os.O_NOFOLLOW)) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise UpdateError(f"not a bounded regular file: {path}")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise UpdateError(f"asset exceeds size limit: {path}")
    return data


def valid_asset_path(name: str) -> bool:
    return bool(name) and all(
        re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part)
        for part in name.split("/")
    )


def parse_manifest(source: bytes) -> Manifest:
    """Accept only the runner's literal checksum tables, never shell syntax."""
    if not source or len(source) > MAX_RUNNER_BYTES:
        raise UpdateError("empty or oversized runner")
    text = source.decode("utf-8")
    versions = re.findall(r'^UBS_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"$', text, re.M)
    if len(versions) != 1:
        raise UpdateError("missing or ambiguous runner version")
    assets: dict[str, str] = {}
    for table in ("MODULE_CHECKSUMS", "HELPER_CHECKSUMS"):
        blocks = re.findall(r"^declare -A " + table + r"=\(\n(.*?)^\)", text, re.M | re.S)
        if len(blocks) != 1:
            raise UpdateError(f"missing or ambiguous {table}")
        count = 0
        for line in blocks[0].splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"\[(?:'([^']+)'|([A-Za-z0-9_-]+))\]='([0-9a-f]{64})'", line)
            if match is None:
                raise UpdateError(f"malformed entry in {table}: {line}")
            key = match[1] or match[2]
            if table == "MODULE_CHECKSUMS":
                if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
                    raise UpdateError(f"invalid language name: {key}")
                key = f"ubs-{key}.sh"
            if not valid_asset_path(key) or key in assets:
                raise UpdateError(f"unsafe or duplicate asset path: {key}")
            assets[key] = match[3]
            count += 1
        if not count:
            raise UpdateError(f"empty {table}")
    if "contract.json" not in assets or hmac.compare_digest(assets["contract.json"], digest(b"")):
        raise UpdateError("target runner does not pin contract.json")
    return Manifest(versions[0], digest(source), assets)


def ready_bytes(manifest: Manifest) -> bytes:
    return (json.dumps({
        "schema": 1,
        "version": manifest.version,
        "runner_sha256": manifest.runner_sha256,
        "assets": manifest.assets,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def generation_path(root: Path, manifest: Manifest) -> Path:
    return root / GENERATION_DIRECTORY / manifest.runner_sha256


def real_directory(path: Path, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o755)
        except FileExistsError:
            pass
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise UpdateError(f"refusing non-directory or symlink: {path}")


def check_parents(root: Path, relative: str) -> Path:
    current = root
    for part in relative.split("/")[:-1]:
        current = current / part
        real_directory(current)
    return root / relative


def check_ready(path: Path, manifest: Manifest, *, complete: bool) -> None:
    real_directory(path.parent)
    real_directory(path)
    if not hmac.compare_digest(read_regular(path / READY_FILE, MAX_RUNNER_BYTES), ready_bytes(manifest)):
        raise UpdateError(f"incomplete or mismatched generation: {path}")
    if complete:
        for relative, expected in manifest.assets.items():
            data = read_regular(check_parents(path, relative))
            if not hmac.compare_digest(digest(data), expected):
                raise UpdateError(f"checksum mismatch in prepared generation: {relative}")
            if relative.startswith("ubs-") and relative.endswith(".sh"):
                if not os.access(path / relative, os.R_OK | os.X_OK):
                    raise UpdateError(f"module is not readable/executable: {relative}")


def sync_directory(path: Path) -> None:
    with contextlib.ExitStack() as resources:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        resources.callback(os.close, descriptor)
        try:
            os.fsync(descriptor)
        except OSError as exc:
            # Some POSIX filesystems do not implement directory fsync. The
            # rename is still atomic; do not claim power-loss durability there.
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise


def write_verified(path: Path, data: bytes, expected: str, *, executable: bool) -> None:
    if not hmac.compare_digest(digest(data), expected):
        raise UpdateError(f"checksum mismatch for {path.name}")
    with open(path, "xb", opener=lambda name, flags: os.open(
            name, flags | os.O_NOFOLLOW, 0o600)) as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), 0o755 if executable else 0o644)
        os.fsync(stream.fileno())


def download(url: str, destination: Path, *, allow_override: bool) -> bytes:
    proto = "=https,http,file" if allow_override else "=https"
    if not allow_override and not url.startswith("https://"):
        raise UpdateError("non-HTTPS asset source requires UBS_REPO_RAW_BASE")
    try:
        if shutil.which("curl"):
            result = subprocess.run(
                ["curl", "-fsSL", "--proto", proto, "--proto-redir", proto,
                 "--connect-timeout", "10", "--max-time", "30", "--max-filesize",
                 str(MAX_ASSET_BYTES), "--retry", "2", "--retry-delay", "1",
                 "-o", str(destination), "--", url],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, check=False, timeout=100)
        elif shutil.which("wget"):
            result = subprocess.run(
                ["wget", "-q", "--timeout=30", "--tries=3",
                 *([] if allow_override else ["--https-only", "--max-redirect=0"]),
                 "-O", str(destination), "--", url],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, check=False, timeout=100)
        else:
            raise UpdateError("neither curl nor wget is available")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateError(f"could not fetch {url}: {exc}") from exc
    if result.returncode:
        raise UpdateError(f"could not fetch {url} (exit {result.returncode})")
    return read_regular(destination)


@contextlib.contextmanager
def generation_lock(container: Path) -> Iterator[None]:
    real_directory(container, create=True)
    with contextlib.ExitStack() as resources:
        descriptor = os.open(container / ".prepare.lock",
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        resources.callback(os.close, descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UpdateError("generation lock is not a regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield


def prepare(runner: Path, root: Path, raw_base: str, *, allow_override: bool) -> Path:
    """Publish one complete generation, without changing any active file.

    The caller authenticates runner before calling this function and atomically
    publishes it ONLY after this function succeeds. SIGKILL before the directory
    rename leaves an unselectable .stage-* directory; after it, the generation
    is complete but inactive until that runner is published. Old generations
    and the legacy module directory are deliberately retained.
    """
    source = read_regular(runner, MAX_RUNNER_BYTES)
    manifest = parse_manifest(source)
    if source.splitlines().count(b"UBS_RELEASE_GENERATIONS=1") != 1:
        raise UpdateError("target runner does not support version-bound module generations")
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    target = generation_path(root, manifest)
    container = root / GENERATION_DIRECTORY
    with generation_lock(container):
        if target.exists() or target.is_symlink():
            check_ready(target, manifest, complete=True)
            return target
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=container))
        try:
            scratch = stage / ".download"
            for relative, expected in sorted(manifest.assets.items()):
                try:
                    data = read_regular(check_parents(root, relative))
                except (OSError, UpdateError):
                    data = b""
                if not hmac.compare_digest(digest(data), expected):
                    url = f"{raw_base.rstrip('/')}/v{manifest.version}/modules/{relative}"
                    data = download(url, scratch, allow_override=allow_override)
                    # Never retry a bad digest against main, disable integrity,
                    # or fall back to a stale installed file.
                    if not hmac.compare_digest(digest(data), expected):
                        raise UpdateError(f"checksum mismatch for downloaded {relative}")
                    scratch.unlink()
                destination = stage / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                write_verified(destination, data, expected,
                               executable=relative.startswith("ubs-") and relative.endswith(".sh"))
            marker = ready_bytes(manifest)
            write_verified(stage / READY_FILE, marker, digest(marker), executable=False)
            # tempfile/umask must not produce an owner-only installation.
            for directory, _, _ in os.walk(stage, topdown=False):
                os.chmod(directory, 0o755)
                sync_directory(Path(directory))
            check_ready(stage, manifest, complete=True)
            os.rename(stage, target)
            sync_directory(container)
            return target
        finally:
            # stage is uniquely owned by this invocation, never an active path.
            if stage.exists():
                shutil.rmtree(stage)


def select(runner: Path, root: Path, raw_base: str, *, migrate_legacy: bool,
           allow_override: bool) -> Path:
    manifest = parse_manifest(read_regular(runner, MAX_RUNNER_BYTES))
    root = root.resolve()
    target = generation_path(root, manifest)
    if target.exists() or target.is_symlink():
        # Ordinary scan/doctor gates still verify the bytes they use. Do not
        # block doctor --fix by attempting to repair/check every asset here.
        check_ready(target, manifest, complete=False)
        return target
    if migrate_legacy:
        try:
            contract_sha = digest(read_regular(root / "contract.json"))
        except (OSError, UpdateError):
            contract_sha = ""
        if contract_sha in LEGACY_CONTRACTS and contract_sha != manifest.assets["contract.json"]:
            print("ubs: completing the installed release upgrade with verified module assets", file=sys.stderr)
            return prepare(runner, root, raw_base, allow_override=allow_override)
    return root


def main() -> int:
    try:
        if len(sys.argv) != 6 or sys.argv[1] not in ("prepare", "select"):
            raise UpdateError("expected: prepare|select RUNNER MODULE_ROOT RAW_BASE MIGRATE_LEGACY")
        _, command, runner, root, base, migrate = sys.argv
        override = bool(os.environ.get("UBS_REPO_RAW_BASE"))
        if command == "prepare":
            result = prepare(Path(runner), Path(root), base, allow_override=override)
        else:
            result = select(Path(runner), Path(root), base, migrate_legacy=migrate == "1",
                            allow_override=override)
        print(result)
        return 0
    except (OSError, UnicodeError, UpdateError) as exc:
        print(f"ubs: release assets could not be verified: {exc}; refusing to use a mixed installation", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
