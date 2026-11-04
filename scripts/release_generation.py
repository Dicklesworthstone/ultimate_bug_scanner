#!/usr/bin/env python3
"""Version-bound module generations for the UBS self-updater (issues #174/#199).

This standard-library-only source is embedded verbatim in the standalone
runner, with source-parity regression coverage. It is not downloaded or
imported at run time: the release authentication gate authenticates the runner
before its target manifest is read. No downloaded shell code is evaluated.
Running scans pass their loaded
checksum tables, rather than reopening a runner another updater can replace.
"""
from __future__ import annotations

import contextlib
import errno
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
from typing import Iterator, NamedTuple, Optional

try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import msvcrt
except ImportError:
    msvcrt = None

MAX_ASSET_BYTES = 32 * 1024 * 1024
MAX_RUNNER_BYTES = 4 * 1024 * 1024
MAX_DAEMON_BYTES = 512 * 1024
GENERATION_DIRECTORY = ".ubs-releases"
READY_FILE = ".ubs-ready.json"
USER_AGENT = "ultimate_bug_scanner-agent"
IS_WINDOWS = os.name == "nt"
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
OPEN_BINARY = getattr(os, "O_BINARY", 0)
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


def is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def require_regular(info: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(info.st_mode) or is_reparse(info):
        raise OSError(errno.ELOOP, "refusing a symlink or reparse point", str(path))
    if stat.S_ISDIR(info.st_mode):
        raise IsADirectoryError(errno.EISDIR, "expected a regular file", str(path))
    if not stat.S_ISREG(info.st_mode):
        raise UpdateError(f"not a regular file: {path}")


def open_regular(path: Path, flags: int, mode: int = 0o600) -> int:
    """No-follow open, with identity checks for native Windows without that flag.

    Creation is exclusive even for a persistent lock's first open. Existing
    files must remain the same non-reparse regular file across lstat/open/fstat;
    the returned descriptor, never another pathname open, is read and hashed.
    """
    before = None
    if flags & os.O_CREAT:
        try:
            descriptor = os.open(path, flags | os.O_EXCL | OPEN_NOFOLLOW | OPEN_NONBLOCK | OPEN_BINARY, mode)
        except FileExistsError:
            if flags & os.O_EXCL:
                raise
            return open_regular(path, flags & ~(os.O_CREAT | os.O_EXCL), mode)
    else:
        before = path.lstat()
        require_regular(before, path)
        descriptor = os.open(path, flags | OPEN_NOFOLLOW | OPEN_NONBLOCK | OPEN_BINARY, mode)
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        require_regular(opened, path)
        require_regular(after, path)
        if ((before is not None and not os.path.samestat(before, opened))
                or not os.path.samestat(opened, after)
                or (not OPEN_NOFOLLOW and not opened.st_ino)):
            raise UpdateError(f"file identity changed or unavailable while opening: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def set_file_mode(descriptor: int, path: Path, mode: int) -> None:
    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, mode)
    else:
        # Native Windows before Python 3.13 has no fchmod. These paths are
        # exclusively created private stage files; check identity around chmod.
        before = path.lstat()
        require_regular(before, path)
        if not os.path.samestat(before, os.fstat(descriptor)):
            raise UpdateError(f"staged file changed before setting mode: {path}")
        os.chmod(path, mode)
        after = path.lstat()
        require_regular(after, path)
        if not os.path.samestat(after, os.fstat(descriptor)):
            raise UpdateError(f"staged file changed while setting mode: {path}")


def read_regular(path: Path, limit: int = MAX_ASSET_BYTES) -> bytes:
    """Hash/read the same opened regular file; never block on a FIFO."""
    # The built-in opener owns the descriptor even if stream initialization
    # fails (for example for a directory); fdopen(os.open(...)) can leak it.
    with open(path, "rb", opener=lambda name, flags: open_regular(Path(name), flags)) as stream:
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


def literal_table(text: str, declaration: str) -> dict[str, str]:
    if len(re.findall(r"^" + re.escape(declaration[:-1]) + r".*$", text, re.M)) != 1:
        raise UpdateError(f"missing or ambiguous {declaration}")
    blocks = re.findall(r"^" + re.escape(declaration) + r"\n(.*?)^\)", text, re.M | re.S)
    if len(blocks) != 1:
        raise UpdateError(f"missing or ambiguous {declaration}")
    entries: dict[str, str] = {}
    for line in blocks[0].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"\[(?:'([^']+)'|([A-Za-z0-9_-]+))\]='([0-9a-f]{64})'", line)
        if match is None:
            raise UpdateError(f"malformed entry in {declaration}: {line}")
        key = match[1] or match[2]
        if key in entries:
            raise UpdateError(f"duplicate checksum: {key}")
        entries[key] = match[3]
    if not entries:
        raise UpdateError(f"empty {declaration}")
    return entries


def validate_asset_map(assets: dict[str, str]) -> None:
    if not {"contract.json", "lib/ubs-common.sh"} <= assets.keys():
        raise UpdateError("manifest must pin contract.json and lib/ubs-common.sh")
    if hmac.compare_digest(assets["contract.json"], digest(b"")):
        raise UpdateError("target runner pins an empty contract.json")
    folded: set[str] = set()
    modules = 0
    for name, expected in assets.items():
        if not valid_asset_path(name) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise UpdateError(f"unsafe asset pin: {name}")
        if re.fullmatch(r"ubs-[a-z]+\.sh", name):
            modules += 1
        elif name != "contract.json" and not name.startswith(("helpers/", "lib/")):
            raise UpdateError(f"invalid helper path: {name}")
        key = name.casefold()
        if key in folded:
            raise UpdateError(f"colliding asset paths: {name}")
        folded.add(key)
    if not modules:
        raise UpdateError("manifest must pin at least one module")
    for name in folded:
        parts = name.split("/")
        if any("/".join(parts[:i]) in folded for i in range(1, len(parts))):
            raise UpdateError(f"asset file/directory collision: {name}")


def runner_version(source: bytes) -> str:
    if not source or len(source) > MAX_RUNNER_BYTES:
        raise UpdateError("empty or oversized runner")
    versions = re.findall(r'^UBS_VERSION=(.*)$', source.decode("utf-8"), re.M)
    if len(versions) != 1 or not re.fullmatch(r'"[0-9]+\.[0-9]+\.[0-9]+"', versions[0]):
        raise UpdateError("missing or ambiguous runner version")
    return versions[0][1:-1]


def parse_manifest(source: bytes) -> Manifest:
    """Accept only the runner's literal checksum tables, never shell syntax."""
    version = runner_version(source)
    text = source.decode("utf-8")
    modules = literal_table(text, "declare -A MODULE_CHECKSUMS=(")
    helpers = literal_table(text, "declare -A HELPER_CHECKSUMS=(")
    inventories = re.findall(r"^HELPER_ASSETS=\(\n(.*?)^\)", text, re.M | re.S)
    if len(inventories) != 1 or len(re.findall(r"^HELPER_ASSETS=.*$", text, re.M)) != 1:
        raise UpdateError("missing or ambiguous HELPER_ASSETS")
    listed = []
    for line in inventories[0].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(['\"])([A-Za-z0-9_./-]+)\1", line)
        if match is None:
            raise UpdateError(f"nonliteral helper inventory entry: {line}")
        listed.append(match[2])
    if len(listed) != len(set(listed)) or set(listed) != set(helpers):
        raise UpdateError("helper inventory does not match its checksum table")
    languages = re.findall(r"^ALL_LANGS=\(([a-z ]+)\)$", text, re.M)
    if (len(languages) != 1 or len(re.findall(r"^ALL_LANGS=.*$", text, re.M)) != 1
            or len(languages[0].split()) != len(set(languages[0].split()))
            or set(languages[0].split()) != set(modules)):
        raise UpdateError("module inventory does not match its checksum table")
    assets: dict[str, str] = {}
    for language, expected in modules.items():
        if not re.fullmatch(r"[a-z]+", language):
            raise UpdateError(f"invalid language name: {language}")
        assets[f"ubs-{language}.sh"] = expected
    for name, expected in helpers.items():
        if name in assets:
            raise UpdateError(f"duplicate asset path: {name}")
        assets[name] = expected
    validate_asset_map(assets)
    return Manifest(version, digest(source), assets)


def manifest_from_arguments(version: str, entries: list[str]) -> Manifest:
    """Consume the current shell's literal pins without rereading its pathname."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise UpdateError("invalid runner version")
    assets: dict[str, str] = {}
    for entry in entries:
        name, separator, expected = entry.partition("=")
        if (not separator or not valid_asset_path(name) or name in assets
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise UpdateError(f"unsafe, duplicate or malformed asset pin: {entry}")
        assets[name] = expected
    validate_asset_map(assets)
    # The runtime manifest does not claim a runner-byte digest. That digest is
    # used only when authenticating and publishing an actual candidate file.
    return Manifest(version, "", assets)


def manifest_bytes(manifest: Manifest) -> bytes:
    return json.dumps({"version": manifest.version, "assets": manifest.assets},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_identity(manifest: Manifest) -> str:
    """Stable for the loaded pins even after the runner pathname is replaced."""
    return digest(manifest_bytes(manifest))


def ready_bytes(manifest: Manifest) -> bytes:
    return (json.dumps({
        "schema": 2,
        "version": manifest.version,
        "manifest_sha256": manifest_identity(manifest),
        "assets": manifest.assets,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def generation_path(root: Path, manifest: Manifest) -> Path:
    return root / GENERATION_DIRECTORY / manifest_identity(manifest)


def real_directory(path: Path, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o755)
        except FileExistsError:
            pass
        else:
            # Ignore a restrictive caller umask only for our newly created
            # directories; never broaden permissions on an existing cache.
            path.chmod(0o755)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or is_reparse(info):
        raise UpdateError(f"refusing non-directory or symlink: {path}")


def check_parents(root: Path, relative: str) -> Path:
    current = root
    for part in relative.split("/")[:-1]:
        current = current / part
        real_directory(current)
    return root / relative


def read_cached_asset(root: Path, relative: str, limit: int = MAX_ASSET_BYTES) -> bytes:
    """Read cache bytes without admitting a changed or symlinked source tree.

    Cache contents are only candidates: the caller must still authenticate
    these exact bytes against the target release's pin. Keep directory
    identities around the no-follow file read so a source-directory swap is
    not mistaken for an ordinary missing or valid historical asset.
    """
    parents = [root.parent, root]
    current = root
    for part in relative.split("/")[:-1]:
        current = current / part
        parents.append(current)
    identities = []
    for parent in parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or is_reparse(info)
                or (not OPEN_NOFOLLOW and not info.st_ino)):
            raise UpdateError(f"unsafe cached asset directory: {parent}")
        identities.append((parent, info))
    data = read_regular(root / relative, limit)
    for parent, before in identities:
        after = parent.lstat()
        if (not stat.S_ISDIR(after.st_mode) or is_reparse(after)
                or not os.path.samestat(before, after)):
            raise UpdateError(f"cached asset directory changed while reading: {parent}")
    return data


def unexpected_entries(path: Path, files: set[str]) -> list[tuple[str, os.stat_result]]:
    """Find topmost unpinned entries without traversing unknown trees or links.

    Authentic Python sources alone are insufficient: an extra sitecustomize,
    bytecode cache or importable sibling can execute before those sources.
    Managed generations therefore contain only pinned files, their parent
    directories, and the ready marker. Directory placement grants no trust.
    """
    directories = {parent.as_posix() for name in files for parent in Path(name).parents
                   if parent.as_posix() != "."}
    pending = [""]
    unexpected = []
    while pending:
        relative = pending.pop()
        directory = check_parents(path, relative) if relative else path
        real_directory(directory)
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                name = f"{relative}/{entry.name}" if relative else entry.name
                info = entry.stat(follow_symlinks=False)
                if is_reparse(info):
                    unexpected.append((name, info))
                elif name in directories and stat.S_ISDIR(info.st_mode):
                    pending.append(name)
                elif name in files and stat.S_ISREG(info.st_mode):
                    continue
                else:
                    unexpected.append((name, info))
    return unexpected


def check_inventory(path: Path, files: set[str]) -> None:
    unexpected = unexpected_entries(path, files)
    if unexpected:
        raise UpdateError(f"unexpected entry in verified generation: {unexpected[0][0]}")


def quarantine_unexpected(path: Path, manifest: Manifest) -> None:
    """Retain untrusted extras outside an active generation before repair.

    Called only under the generation lock, after the complete replacement set
    has verified. Moving topmost entries preserves unknown bytes and symlinks
    without importing, following or deleting them. Interrupted moves leave
    either a still-refused generation or one containing only pinned assets.
    """
    unexpected = unexpected_entries(path, set(manifest.assets) | {READY_FILE})
    if not unexpected:
        return
    quarantine = Path(tempfile.mkdtemp(prefix=".quarantine-" + path.name[:12] + "-",
                                       dir=path.parent))
    for relative, observed in unexpected:
        source = check_parents(path, relative)
        if not os.path.samestat(observed, source.lstat()):
            raise UpdateError(f"unexpected entry changed during quarantine: {relative}")
        destination = quarantine / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.rename(source, destination)
        sync_directory(source.parent)
        sync_directory(destination.parent)
    sync_directory(quarantine)
    sync_directory(path.parent)


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
                # Windows chmod/access do not implement POSIX executable bits;
                # Git Bash executes the verified script through its interpreter.
                access = os.R_OK if IS_WINDOWS else os.R_OK | os.X_OK
                if not os.access(path / relative, access):
                    raise UpdateError(f"module is not readable/executable: {relative}")
        verify_dependency_pins(path, manifest)
        check_inventory(path, set(manifest.assets) | {READY_FILE})


def snapshot_helpers(manifest: Manifest, source: Path, destination: Path) -> Path:
    """Copy only verified helper pins into an exclusively created private tree.

    Doctor may inspect a legacy or sibling source tree with additional files.
    Importing directly from it would authorize those files and race the digest
    checks. The caller imports this snapshot with isolated Python only after
    the command succeeds; partial snapshots are never returned for execution.
    """
    validate_asset_map(manifest.assets)
    real_directory(source)
    real_directory(destination.parent)
    destination.mkdir(mode=0o700)
    assets = {name.removeprefix("helpers/"): expected
              for name, expected in manifest.assets.items() if name.startswith("helpers/")}
    if not assets:
        raise UpdateError("manifest has no pinned diagnostic helpers")
    for relative, expected in sorted(assets.items()):
        data = read_regular(check_parents(source, relative))
        if not hmac.compare_digest(digest(data), expected):
            raise UpdateError(f"diagnostic helper checksum mismatch: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        write_verified(target, data, expected, executable=False)
    check_inventory(destination, set(assets))
    return destination


def verify_dependency_pins(path: Path, manifest: Manifest) -> None:
    """A set of individually authentic files must also agree with each other."""
    library = manifest.assets["lib/ubs-common.sh"]
    for name in manifest.assets:
        if not re.fullmatch(r"ubs-[a-z]+\.sh", name):
            continue
        source = read_regular(path / name).decode("utf-8")
        declarations = re.findall(r"^UBS_LIB_CHECKSUM=(.*)$", source, re.M)
        if len(declarations) != 1 or declarations[0] != f'"{library}"':
            raise UpdateError(f"module has an inconsistent shared-library pin: {name}")
    common = read_regular(check_parents(path, "lib/ubs-common.sh")).decode("utf-8")
    transitive = literal_table(common, "declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(")
    expected = {name: checksum for name, checksum in manifest.assets.items()
                if name != "lib/ubs-common.sh" and not re.fullmatch(r"ubs-[a-z]+\.sh", name)}
    if transitive != expected:
        raise UpdateError("shared-library helper pins do not match the authenticated runner")


def sync_directory(path: Path) -> None:
    real_directory(path)
    if IS_WINDOWS:
        # Python cannot portably open/fsync Windows directories. File contents
        # are flushed and os.replace stays atomic; no power-loss claim is made.
        return
    with contextlib.ExitStack() as resources:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | OPEN_NOFOLLOW)
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
    with open(path, "xb", opener=lambda name, flags: open_regular(Path(name), flags)) as stream:
        stream.write(data)
        stream.flush()
        set_file_mode(stream.fileno(), path, 0o755 if executable else 0o644)
        os.fsync(stream.fileno())


def download(url: str, destination: Path, *, allow_override: bool,
             max_bytes: int = MAX_ASSET_BYTES) -> bytes:
    proto = "=https,http,file" if allow_override else "=https"
    if not allow_override and not url.startswith("https://"):
        raise UpdateError("non-HTTPS asset source requires UBS_REPO_RAW_BASE")
    try:
        if shutil.which("curl"):
            result = subprocess.run(
                ["curl", "-fsSL", "--proto", proto, "--proto-redir", proto,
                 "--user-agent", USER_AGENT,
                 "--connect-timeout", "10", "--max-time", "30", "--max-filesize",
                 str(max_bytes), "--retry", "2", "--retry-delay", "1",
                 "-o", str(destination), "--", url],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, check=False, timeout=100)
        elif shutil.which("wget"):
            result = subprocess.run(
                ["wget", "-q", "--timeout=30", "--tries=3", "--user-agent", USER_AGENT,
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
    return read_regular(destination, max_bytes)


@contextlib.contextmanager
def exclusive_lock(descriptor: int) -> Iterator[None]:
    if IS_WINDOWS:
        if msvcrt is None:
            raise UpdateError("native Windows update locking requires msvcrt")
        # locking() starts at the current offset and may extend beyond EOF.
        # LK_LOCK retries contention for ten seconds, then fails safely.
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        if fcntl is None:
            raise UpdateError("this platform has no supported update lock implementation")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextlib.contextmanager
def generation_lock(container: Path) -> Iterator[None]:
    real_directory(container, create=True)
    with contextlib.ExitStack() as resources:
        descriptor = open_regular(container / ".prepare.lock", os.O_RDWR | os.O_CREAT)
        resources.callback(os.close, descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UpdateError("generation lock is not a regular file")
        with exclusive_lock(descriptor):
            verify_lock_identity(descriptor, container / ".prepare.lock")
            yield


def verify_lock_identity(descriptor: int, path: Path) -> None:
    """Reject a waiter whose lock was removed/recreated by a completed uninstall."""
    try:
        current = path.lstat()
    except FileNotFoundError as exc:
        raise UpdateError("update lock was removed while waiting; retry the operation") from exc
    require_regular(current, path)
    if not os.path.samestat(current, os.fstat(descriptor)):
        raise UpdateError("update lock was replaced while waiting; retry the operation")


def prepare_manifest(manifest: Manifest, root: Path, raw_base: str, *, allow_override: bool,
                     local_source: Optional[Path] = None, repair: bool = False,
                     previous_generation: Optional[Path] = None,
                     force_download: bool = False) -> Path:
    """Publish one complete generation, without changing any active file.

    The caller authenticates runner before calling this function and atomically
    publishes it ONLY after this function succeeds. SIGKILL before the directory
    rename leaves an unselectable .stage-* directory; after it, the generation
    is complete but inactive until that runner is published. Old generations
    and the legacy module directory are deliberately retained.

    Explicit module refresh bypasses every reusable source, including a valid
    existing generation, but retains the same complete-stage verification and
    atomic same-pin repair protocol. Failed downloads never disturb readers.
    """
    validate_asset_map(manifest.assets)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    target = generation_path(root, manifest)
    container = root / GENERATION_DIRECTORY
    with generation_lock(container):
        existing = target.exists() or target.is_symlink()
        if existing:
            # Never replace or traverse a symlinked generation, even for repair.
            real_directory(target)
            try:
                check_ready(target, manifest, complete=True)
                if not force_download:
                    return target
            except (OSError, UpdateError):
                if not repair:
                    raise
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=container))
        try:
            scratch = stage / ".download"
            for relative, expected in sorted(manifest.assets.items()):
                data = b""
                sources = []
                if not force_download:
                    sources.append(root)
                    if previous_generation is not None and previous_generation != target:
                        sources.insert(0, previous_generation)
                    if local_source is not None:
                        sources.insert(0, local_source)
                    if existing:
                        sources.insert(0, target)
                for source_root in sources:
                    try:
                        data = read_cached_asset(source_root, relative)
                    except (OSError, UpdateError):
                        data = b""
                    if hmac.compare_digest(digest(data), expected):
                        break
                if force_download or not hmac.compare_digest(digest(data), expected):
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
            if existing:
                # Explicit repair replaces only same-manifest assets, each by
                # atomic rename after the ENTIRE repair set was verified. A
                # healthy concurrent reader still sees the same pinned bytes;
                # a damaged reader fails closed until its asset is repaired.
                # The generation directory itself never disappears or moves.
                quarantine_unexpected(target, manifest)
                parents = {target}
                for relative in sorted(manifest.assets):
                    parent = target
                    for part in relative.split("/")[:-1]:
                        parent = parent / part
                        real_directory(parent, create=True)
                        parents.add(parent)
                    os.replace(stage / relative, target / relative)
                for parent in sorted(parents, key=lambda path: len(path.parts), reverse=True):
                    os.chmod(parent, 0o755)
                    sync_directory(parent)
                os.replace(stage / READY_FILE, target / READY_FILE)
                sync_directory(target)
            else:
                os.rename(stage, target)
            sync_directory(container)
            check_ready(target, manifest, complete=True)
            return target
        finally:
            # stage is uniquely owned by this invocation, never an active path.
            if stage.exists():
                shutil.rmtree(stage)


def prepare(runner: Path, root: Path, raw_base: str, *, allow_override: bool,
            local_source: Optional[Path] = None, repair: bool = False) -> Path:
    source = read_regular(runner, MAX_RUNNER_BYTES)
    manifest = parse_manifest(source)
    if source.splitlines().count(b"UBS_RELEASE_GENERATIONS=1") != 1:
        raise UpdateError("target runner does not support version-bound module generations")
    return prepare_manifest(manifest, root, raw_base, allow_override=allow_override,
                            local_source=local_source, repair=repair)


def select_manifest(manifest: Manifest, root: Path) -> Path:
    root = root.resolve()
    container = root / GENERATION_DIRECTORY
    if container.exists() or container.is_symlink():
        real_directory(container)
    target = generation_path(root, manifest)
    if target.exists() or target.is_symlink():
        # A ready marker is never an executable-byte authorization. Verify the
        # complete graph before any scan/doctor consumer can import a helper.
        # Explicit doctor repair runs prepare_manifest(repair=True) first.
        check_ready(target, manifest, complete=True)
        return target
    return root


def select(runner: Path, root: Path, raw_base: str, *, migrate_legacy: bool,
           allow_override: bool) -> Path:
    manifest = parse_manifest(read_regular(runner, MAX_RUNNER_BYTES))
    root = root.resolve()
    target = select_manifest(manifest, root)
    if target != root:
        return target
    if migrate_legacy:
        try:
            contract_sha = digest(read_regular(root / "contract.json"))
        except (OSError, UpdateError):
            contract_sha = ""
        if contract_sha in LEGACY_CONTRACTS and not hmac.compare_digest(contract_sha, manifest.assets["contract.json"]):
            print("ubs: completing the installed release upgrade with verified module assets", file=sys.stderr)
            return prepare(runner, root, raw_base, allow_override=allow_override)
    return root


def daemon_pin(source: bytes) -> str:
    declarations = re.findall(r"^UBS_DAEMON_SHA256=(.*)$", source.decode("utf-8"), re.M)
    if not declarations:
        return ""
    if len(declarations) != 1 or not re.fullmatch(r'"[0-9a-f]{64}"', declarations[0]):
        raise UpdateError("missing or ambiguous daemon checksum")
    return declarations[0][1:-1]


@contextlib.contextmanager
def publication_lock(installed: Path) -> Iterator[None]:
    """Serialize generation preparation AND runner publication for one install."""
    real_directory(installed.parent)
    with contextlib.ExitStack() as resources:
        descriptor = open_regular(installed.with_name(installed.name + ".update.lock"),
                                  os.O_RDWR | os.O_CREAT)
        resources.callback(os.close, descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UpdateError("update lock is not a regular file")
        with exclusive_lock(descriptor):
            verify_lock_identity(descriptor, installed.with_name(installed.name + ".update.lock"))
            yield


def publish_file(destination: Path, data: bytes, *, mode: int) -> None:
    """Durably stage on the destination filesystem, then replace one pathname."""
    descriptor, name = tempfile.mkstemp(prefix="." + destination.name + ".stage-",
                                        dir=destination.parent)
    stage = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            set_file_mode(stream.fileno(), stage, mode)
            os.fsync(stream.fileno())
        os.replace(stage, destination)
        sync_directory(destination.parent)
    finally:
        if stage.exists():
            stage.unlink()


def daemon_target(installed: Path, expected: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateError("invalid loaded daemon checksum")
    return installed.with_name(installed.name + ".daemon." + expected + ".py")


def check_daemon(installed: Path, expected: str) -> Path:
    """Verify exactly the companion the service loader will select, without imports.

    The checksum comes from the already-running shell, never a reopened runner.
    A present but damaged digest-named sidecar cannot authorize falling back to
    a healthy adjacent source file; normal service startup refuses that case.
    """
    installed = installed.absolute()
    target = daemon_target(installed, expected)
    try:
        target.lstat()
    except FileNotFoundError:
        target = installed.with_name("ubs-daemon")
    data = read_cached_asset(installed.parent, target.name, MAX_DAEMON_BYTES)
    if not hmac.compare_digest(digest(data), expected):
        raise UpdateError(f"daemon companion checksum mismatch: {target}")
    return target


def require_installed_daemon_repair(installed: Path) -> None:
    """Do not overwrite or shadow a source/exported checkout's companion.

    The shell additionally rejects Git-tracked runners and companions, even
    when they live below a checkout root. These adjacent markers cover source
    exports without Git as well, before creating any lock or staging files.
    """
    real_directory(installed.parent)
    for name in (".git", "modules"):
        marker = installed.parent / name
        try:
            marker.lstat()
        except FileNotFoundError:
            continue
        raise UpdateError("source-owned daemon companion cannot be automatically repaired")


def require_safe_daemon_target(target: Path) -> None:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    require_regular(info, target)


def repair_daemon(installed: Path, version: str, expected: str, raw_base: str, *,
                  allow_override: bool) -> Path:
    """Repair only the loaded release's installed companion, under its update lock.

    The installed runner is reread only as a compare-and-swap lease. It cannot
    supply a new trusted pin or version. All bytes are authenticated before an
    atomic replacement on the destination filesystem; adjacent source bytes,
    old companions and the runner itself are never replaced by this repair.
    """
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise UpdateError("invalid loaded runner version")
    installed = installed.absolute()
    target = daemon_target(installed, expected)
    require_installed_daemon_repair(installed)
    with publication_lock(installed):
        require_installed_daemon_repair(installed)
        current = read_regular(installed, MAX_RUNNER_BYTES)
        if (runner_version(current) != version
                or not hmac.compare_digest(daemon_pin(current), expected)):
            raise UpdateError("installed runner no longer matches the loaded release; retry doctor")
        current_sha = digest(current)
        try:
            return check_daemon(installed, expected)
        except (OSError, UpdateError):
            pass
        require_safe_daemon_target(target)
        data = None
        try:
            adjacent = read_cached_asset(installed.parent, "ubs-daemon", MAX_DAEMON_BYTES)
        except (OSError, UpdateError):
            pass
        else:
            if hmac.compare_digest(digest(adjacent), expected):
                data = adjacent
        if data is None:
            # This directory is private and owned solely by this invocation.
            # No candidate code is imported or executed, even for diagnosis.
            with tempfile.TemporaryDirectory(prefix="." + installed.name + ".daemon-repair-",
                                             dir=installed.parent) as temporary:
                url = f"{raw_base.rstrip('/')}/v{version}/ubs-daemon"
                data = download(url, Path(temporary) / "companion", allow_override=allow_override,
                                max_bytes=MAX_DAEMON_BYTES)
                if not hmac.compare_digest(digest(data), expected):
                    raise UpdateError("downloaded daemon companion checksum mismatch")
        if not hmac.compare_digest(digest(read_regular(installed, MAX_RUNNER_BYTES)), current_sha):
            raise UpdateError("installed runner changed during daemon repair; retry doctor")
        require_installed_daemon_repair(installed)
        require_safe_daemon_target(target)
        publish_file(target, data, mode=0o644)
        return check_daemon(installed, expected)


def publish(candidate: Path, root: Path, raw_base: str, installed: Path,
            expected_current_sha: str, *, allow_override: bool,
            daemon_source: Optional[Path] = None, local_source: Optional[Path] = None) -> Path:
    """Publish an authenticated candidate only after all dependencies are ready.

    Authentication belongs to the caller. The expected-current digest is a
    compare-and-swap lease, not authentication of the candidate. Holding the
    persistent publication lock prevents two cooperating updaters from mixing
    generations; an external replacement invalidates the final lease check.
    """
    if expected_current_sha != "absent" and not re.fullmatch(r"[0-9a-f]{64}", expected_current_sha):
        raise UpdateError("invalid expected installed runner digest")
    source = read_regular(candidate, MAX_RUNNER_BYTES)
    manifest = parse_manifest(source)
    if source.splitlines().count(b"UBS_RELEASE_GENERATIONS=1") != 1:
        raise UpdateError("target runner does not support version-bound module generations")
    installed = installed.absolute()
    with publication_lock(installed):
        try:
            current = read_regular(installed, MAX_RUNNER_BYTES)
            current_sha = digest(current)
        except FileNotFoundError:
            current = None
            current_sha = "absent"
        if (not hmac.compare_digest(current_sha, expected_current_sha)
                and (expected_current_sha == "absent" or not hmac.compare_digest(current_sha, manifest.runner_sha256))):
            raise UpdateError("installed runner changed during update; retry with the current release")
        mode = 0o755
        previous_generation = None
        if current is not None:
            previous_version = runner_version(current)
            if tuple(map(int, manifest.version.split("."))) < tuple(map(int, previous_version.split("."))):
                raise UpdateError("refusing to downgrade the installed runner")
            mode = stat.S_IMODE(installed.stat().st_mode)
            if current.splitlines().count(b"UBS_RELEASE_GENERATIONS=1") == 1:
                try:
                    previous_manifest = parse_manifest(current)
                except (UnicodeError, UpdateError):
                    # An old/malformed manifest cannot identify a reusable
                    # generation. The authenticated target can still repair
                    # the install from its own verified downloads.
                    pass
                else:
                    # Read only the generation named by the leased runner,
                    # never arbitrary staging/quarantine/ready-marker data.
                    # Every reused byte is checked against the TARGET pin.
                    previous_generation = generation_path(root.resolve(), previous_manifest)
        daemon_expected = daemon_pin(source)
        daemon_data = None
        daemon_target = None
        if daemon_expected:
            daemon_target = installed.with_name(installed.name + ".daemon." + daemon_expected + ".py")
            daemon_path = daemon_source if daemon_source is not None else daemon_target
            daemon_data = read_regular(daemon_path, MAX_DAEMON_BYTES)
            if not hmac.compare_digest(digest(daemon_data), daemon_expected):
                raise UpdateError("release daemon checksum mismatch")
            if daemon_target.is_symlink() or (daemon_target.exists() and not daemon_target.is_file()):
                raise UpdateError("unsafe daemon installation path")
        target = prepare_manifest(manifest, root, raw_base, allow_override=allow_override,
                                  local_source=local_source, repair=True,
                                  previous_generation=previous_generation)
        # Recheck after downloads: a non-cooperating older updater may not use
        # our lock. Never overwrite a runner that changed while we prepared.
        try:
            final_current_sha = digest(read_regular(installed, MAX_RUNNER_BYTES))
        except FileNotFoundError:
            final_current_sha = "absent"
        if not hmac.compare_digest(final_current_sha, current_sha):
            raise UpdateError("installed runner changed during preparation; verified assets retained for retry")
        if daemon_data is not None and daemon_target is not None:
            publish_file(daemon_target, daemon_data, mode=0o644)
        check_ready(target, manifest, complete=True)
        if not hmac.compare_digest(current_sha, manifest.runner_sha256):
            publish_file(installed, source, mode=mode)
        return target


def main() -> int:
    try:
        override = bool(os.environ.get("UBS_REPO_RAW_BASE"))
        args = sys.argv[1:]
        if not args:
            raise UpdateError("expected a release generation command")
        command = args.pop(0)
        if command == "select-manifest" and len(args) >= 3:
            root, version, *entries = args
            result = select_manifest(manifest_from_arguments(version, entries), Path(root))
        elif command == "check-daemon" and len(args) == 2:
            installed, expected = args
            result = check_daemon(Path(installed), expected)
        elif command == "repair-daemon" and len(args) == 4:
            installed, version, expected, base = args
            result = repair_daemon(Path(installed), version, expected, base, allow_override=override)
        elif command == "snapshot-helpers" and len(args) >= 4:
            source, destination, version, *entries = args
            result = snapshot_helpers(manifest_from_arguments(version, entries),
                                      Path(source), Path(destination))
        elif command in ("prepare-manifest", "repair-manifest", "refresh-manifest") and len(args) >= 4:
            root, version, base, *entries = args
            local_source = None
            if entries and entries[0].startswith("--local-source="):
                local_source = Path(entries.pop(0).partition("=")[2])
            result = prepare_manifest(manifest_from_arguments(version, entries), Path(root), base,
                                      allow_override=override, local_source=local_source,
                                      repair=command != "prepare-manifest",
                                      force_download=command == "refresh-manifest")
        elif command == "publish" and 5 <= len(args) <= 7:
            candidate, root, base, installed, expected, *optional = args
            daemon = Path(optional[0]) if optional and optional[0] != "-" else None
            local_source = Path(optional[1]) if len(optional) > 1 and optional[1] != "-" else None
            result = publish(Path(candidate), Path(root), base, Path(installed), expected,
                             allow_override=override, daemon_source=daemon, local_source=local_source)
        elif command in ("prepare", "select") and 3 <= len(args) <= 4:
            runner, root, base, *optional = args
            if command == "prepare":
                local_source = Path(optional[0]) if optional and optional[0] not in ("0", "1", "-") else None
                result = prepare(Path(runner), Path(root), base, allow_override=override,
                                 local_source=local_source)
            else:
                result = select(Path(runner), Path(root), base,
                                migrate_legacy=bool(optional and optional[0] == "1"),
                                allow_override=override)
        else:
            raise UpdateError("invalid release generation command or arguments")
        print(result)
        return 0
    except (OSError, UnicodeError, UpdateError) as exc:
        print(f"ubs: release assets could not be verified: {exc}; refusing to use a mixed installation", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
