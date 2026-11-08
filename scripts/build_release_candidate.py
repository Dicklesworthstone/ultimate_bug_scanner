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
from pathlib import Path
import re
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


def validate_source(source: Path, version: str) -> tuple[generation.Manifest, dict[str, bytes]]:
    """Retain the verified bytes so later copies cannot read different inputs."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise CandidateError("candidate version must be X.Y.Z (the generation protocol requires a stable version)")
    source = source.absolute()
    inputs: dict[str, bytes] = {}

    def read(relative: str, limit: int = generation.MAX_ASSET_BYTES) -> bytes:
        if relative not in inputs:
            inputs[relative] = generation.read_cached_asset(source, relative, limit)
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


def build_candidate(source: Path, version: str, output: Path) -> dict[str, object]:
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
        manifest, payload = validate_source(source, version)
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
        return {
            "status": "unsigned",
            "version": version,
            "output": str(output),
            "runtime_assets": len(manifest.assets),
            "manifest_sha256": generation.manifest_identity(manifest),
            "runner_sha256": manifest.runner_sha256,
            "sha256sums_sha256": generation.digest(payload["SHA256SUMS"]),
        }
    except (OSError, UnicodeError, generation.UpdateError) as exc:
        raise CandidateError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="expected stable version, X.Y.Z")
    parser.add_argument("--output", required=True, type=Path, help="new candidate directory (parent must exist)")
    args = parser.parse_args()
    try:
        report = build_candidate(ROOT, args.version, args.output)
    except CandidateError as exc:
        print(f"release candidate rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
