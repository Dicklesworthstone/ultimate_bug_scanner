#!/usr/bin/env python3
"""Validate and assemble an unsigned release candidate without publishing it.

The source checkout is read as data: no runner, installer, module, or candidate
helper is executed. Authentication, the self-scan gate, signing, and publication
remain separate release steps. The destination must not already exist.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# Importing the reviewed validator must not leave bytecode in the checkout.
sys.dont_write_bytecode = True
if __package__:
    from . import release_generation as generation
else:
    import release_generation as generation


ROOT = Path(__file__).resolve().parents[1]
FLAT_PAYLOAD = {
    "install.sh": "install.sh",
    "ubs": "ubs",
    "ubs-daemon": "ubs-daemon",
    "verify.sh": "scripts/verify.sh",
    "git_safety_guard.py": ".claude/hooks/git_safety_guard.py",
    "minisign.pub": "minisign.pub",
}
SOURCE_CHECKSUM_ASSETS = {"install.sh", "ubs", "ubs-daemon"}
EXECUTABLES = set(FLAT_PAYLOAD) - {"minisign.pub"}


class CandidateError(ValueError):
    """The source cannot form a complete, consistent release candidate."""


class GitSource:
    """Read raw blobs from one immutable tree, never the working tree or index.

    Release preparation can leave runtime changes unstaged. Validating their
    working-tree bytes says nothing about the tree that a commit will ship.
    Resolve the requested tree once and retain its modes, sizes and blob IDs;
    neither export filters nor a later index edit can change these inputs.
    """

    def __init__(self, source: Path, reference: str):
        self.source = source
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.tree = self.git("rev-parse", "--verify", "--end-of-options", reference + "^{tree}").decode().strip()
        self.entries: dict[str, tuple[str, str, str, str]] = {}
        for entry in self.git("ls-tree", "-r", "-l", "-z", "--full-tree", self.tree).split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, kind, blob, size = metadata.decode("ascii").split()
            self.entries[name.decode("utf-8", errors="surrogateescape")] = (mode, kind, blob, size)

    def git(self, *args: str) -> bytes:
        try:
            result = subprocess.run(
                ["git", "--no-replace-objects", *args], cwd=self.source, env=self.env,
                check=False, capture_output=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CandidateError(f"could not read release Git tree: {exc}") from exc
        if result.returncode:
            diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
            raise CandidateError(f"could not read release Git tree: {diagnostic}")
        return result.stdout

    def read(self, relative: str, limit: int) -> bytes:
        entry = self.entries.get(relative)
        if entry is None:
            raise CandidateError(f"release Git tree is missing required input: {relative}")
        mode, kind, blob, size = entry
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise CandidateError(f"release Git tree input is not a regular file: {relative}")
        if not size.isdigit() or int(size) > limit:
            raise CandidateError(f"release Git tree input exceeds size limit: {relative}")
        data = self.git("cat-file", "blob", blob)
        if len(data) != int(size):
            raise CandidateError(f"release Git tree input size changed: {relative}")
        return data


def validate_dependency_pins(manifest: generation.Manifest, payload: dict[str, bytes]) -> None:
    """Check the nested pin graph on the same retained bytes we will assemble.

    The generation helper's filesystem validator is for an installed tree.
    Reopening checkout paths here could validate different bytes after a
    concurrent source edit. Reuse its literal table parser without rereading.
    """
    modules = {name for name in manifest.assets if re.fullmatch(r"ubs-[a-z]+\.sh", name)}
    library = manifest.assets["lib/ubs-common.sh"]
    for name in sorted(modules):
        declarations = re.findall(r"^UBS_LIB_CHECKSUM=(.*)$", payload["modules/" + name].decode("utf-8"), re.M)
        if declarations != [f'"{library}"']:
            raise CandidateError(f"module has an inconsistent shared-library pin: {name}")
    common = payload["modules/lib/ubs-common.sh"].decode("utf-8")
    transitive = generation.literal_table(common, "declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(")
    expected = {name: pin for name, pin in manifest.assets.items()
                if name not in modules and name != "lib/ubs-common.sh"}
    if transitive != expected:
        raise CandidateError("shared-library helper pins do not match the candidate runner")


def validate_source(source: Path, version: str, *,
                    git_source: GitSource | None = None) -> tuple[generation.Manifest, dict[str, bytes]]:
    """Retain the verified bytes so later copies cannot read different inputs."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise CandidateError("candidate version must be X.Y.Z (the generation protocol requires a stable version)")
    source = source.absolute()
    inputs: dict[str, bytes] = {}

    def read(relative: str, limit: int = generation.MAX_ASSET_BYTES) -> bytes:
        if relative not in inputs:
            inputs[relative] = (git_source.read(relative, limit) if git_source is not None
                                else generation.read_cached_asset(source, relative, limit))
        return inputs[relative]

    if read("VERSION", 128).decode("utf-8").strip() != version:
        raise CandidateError("VERSION does not match the requested candidate version")
    runner = read("ubs", generation.MAX_RUNNER_BYTES)
    manifest = generation.parse_manifest(runner)
    if manifest.version != version:
        raise CandidateError("UBS_VERSION does not match VERSION and the requested candidate version")
    declarations = [line for line in runner.splitlines() if line.startswith(b"UBS_RELEASE_GENERATIONS=")]
    if declarations != [b"UBS_RELEASE_GENERATIONS=1"]:
        raise CandidateError("runner must declare exactly one literal UBS_RELEASE_GENERATIONS=1")
    badges = re.findall(r"badge/version-(.+?)-blue\.svg", read("README.md").decode("utf-8"))
    if badges != [version]:
        raise CandidateError("README version badge does not uniquely match the candidate version")

    start, end = b"<<'PYRELEASEGENERATION'\n", b"\nPYRELEASEGENERATION\n"
    if runner.count(start) != 1 or runner.count(end) != 1:
        raise CandidateError("runner has a missing or ambiguous embedded generation helper")
    embedded = runner.split(start, 1)[1].split(end, 1)[0] + b"\n"
    if embedded != read("scripts/release_generation.py"):
        raise CandidateError("embedded generation helper differs from scripts/release_generation.py")

    payload = {}
    for name, relative in FLAT_PAYLOAD.items():
        limit = generation.MAX_DAEMON_BYTES if name == "ubs-daemon" else generation.MAX_ASSET_BYTES
        data = read(relative, limit)
        if not data:
            raise CandidateError(f"empty release payload: {relative}")
        payload[name] = data
    daemon = generation.daemon_pin(runner)
    if not daemon or not hmac.compare_digest(daemon, generation.digest(payload["ubs-daemon"])):
        raise CandidateError("ubs-daemon does not match the runner's required daemon pin")

    keys = [line for line in payload["minisign.pub"].decode("utf-8").splitlines()
            if line and not line.startswith("untrusted comment:")]
    if len(keys) != 1:
        raise CandidateError("minisign public key file must contain exactly one key")
    try:
        public_key = base64.b64decode(keys[0], validate=True)
    except ValueError as exc:
        raise CandidateError("malformed minisign public key") from exc
    if len(public_key) != 42 or public_key[:2] != b"Ed":
        raise CandidateError("malformed minisign public key")
    runner_keys = re.findall(r"^UBS_RELEASE_PUBKEY=(.*)$", runner.decode("utf-8"), re.M)
    installer_keys = re.findall(r"^MINISIGN_PUBKEY=(.*)$", payload["install.sh"].decode("utf-8"), re.M)
    default_key = '"${UBS_MINISIGN_PUBKEY:-' + keys[0] + '}"'
    if runner_keys != [f'"{keys[0]}"'] or installer_keys != [default_key]:
        raise CandidateError("distributed minisign public key does not match runner and installer trust defaults")

    for name, expected in sorted(manifest.assets.items()):
        data = read("modules/" + name)
        if not hmac.compare_digest(generation.digest(data), expected):
            raise CandidateError(f"checksum mismatch for modules/{name}")
        payload["modules/" + name] = data
    validate_dependency_pins(manifest, payload)

    sums: dict[str, str] = {}
    for line in read("SHA256SUMS").decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or not generation.valid_asset_path(match[2]) or match[2] in sums:
            raise CandidateError("source SHA256SUMS contains a malformed, unsafe or duplicate entry")
        sums[match[2]] = match[1]
    if not SOURCE_CHECKSUM_ASSETS <= sums.keys():
        raise CandidateError("source SHA256SUMS must cover install.sh, ubs and ubs-daemon")
    for relative, expected in sums.items():
        if not hmac.compare_digest(generation.digest(read(relative)), expected):
            raise CandidateError(f"source SHA256SUMS mismatch: {relative}")

    payload["VERSION"] = read("VERSION", 128)
    payload["SHA256SUMS"] = "".join(
        f"{generation.digest(payload[name])}  {name}\n" for name in FLAT_PAYLOAD
    ).encode("ascii")
    return manifest, payload


def prepare_candidate(source: Path, version: str, source_ref: str | None = None
                      ) -> tuple[generation.Manifest, dict[str, bytes], dict[str, object]]:
    git_source = GitSource(source, source_ref) if source_ref is not None else None
    if git_source is None:
        manifest, payload = validate_source(source, version)
    else:
        manifest, payload = validate_source(source, version, git_source=git_source)
    report: dict[str, object] = {
        "version": version,
        "runtime_assets": len(manifest.assets),
        "manifest_sha256": generation.manifest_identity(manifest),
        "runner_sha256": manifest.runner_sha256,
        "sha256sums_sha256": generation.digest(payload["SHA256SUMS"]),
    }
    if git_source is not None:
        report["source_tree"] = git_source.tree
    return manifest, payload, report


def build_candidate(source: Path, version: str, output: Path,
                    source_ref: str | None = None) -> dict[str, object]:
    """Create a new unsigned directory only after all source checks succeed."""
    output = output.absolute()
    try:
        try:
            output.lstat()
        except FileNotFoundError:
            pass
        else:
            raise CandidateError(f"output already exists; refusing to replace it: {output}")
        generation.real_directory(output.parent)
        _, payload, report = prepare_candidate(source, version, source_ref)
        # mkdir is exclusive. A racing creator cannot turn this into an update
        # of an existing directory. Individual files are exclusive as well.
        output.mkdir(mode=0o755)
        output.chmod(0o755)
        for name, data in payload.items():
            destination = output / name
            parent = output
            for part in Path(name).parts[:-1]:
                parent = parent / part
                generation.real_directory(parent, create=True)
            executable = name in EXECUTABLES or bool(re.fullmatch(r"modules/ubs-[a-z]+\.sh", name))
            generation.write_verified(destination, data, generation.digest(data), executable=executable)
        return {**report, "status": "unsigned", "output": str(output)}
    except (OSError, UnicodeError, generation.UpdateError) as exc:
        raise CandidateError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="expected stable version, X.Y.Z")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="new candidate directory (parent must exist)")
    mode.add_argument("--check-only", action="store_true", help="validate without writing any candidate files")
    parser.add_argument("--source-ref", help="read an immutable Git tree instead of working-tree files")
    parser.add_argument("--require-working-tree-match", action="store_true",
                        help="with --check-only --source-ref, require identical working-tree payloads")
    args = parser.parse_args()
    if args.require_working_tree_match and (not args.check_only or not args.source_ref):
        parser.error("--require-working-tree-match requires --check-only and --source-ref")
    try:
        if args.check_only:
            _, payload, report = prepare_candidate(ROOT, args.version, args.source_ref)
            if args.require_working_tree_match:
                _, working_payload = validate_source(ROOT, args.version)
                differences = sorted(name for name in payload.keys() | working_payload.keys()
                                     if payload.get(name) != working_payload.get(name))
                if differences:
                    raise CandidateError("release Git tree differs from the working candidate: "
                                         + ", ".join(differences))
            report["status"] = "validated"
        else:
            report = build_candidate(ROOT, args.version, args.output, args.source_ref)
    except (CandidateError, OSError, UnicodeError, generation.UpdateError) as exc:
        print(f"release candidate rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
