# Security & Integrity Model

This document captures the threat model for the UBS installer, module downloads, and OCI images, plus the controls we ship to protect users.

## Threat model

- **Tampered release artifacts** (MITM or compromised GitHub asset).
- **Mutable image tags** (`latest` overwritten with malicious content).
- **Module supply chain attacks** during lazy downloads of language helpers.
- **Installer auto-updates** fetching unverified content.
- **Compromised signing keys** (minisign or Sigstore identity).

## Controls

- **Authenticated release installation**: `scripts/verify.sh` authenticates one `SHA256SUMS` with minisign or Cosign, then verifies `install.sh`, `ubs`, and `git_safety_guard.py` against that same manifest before executing any release code. The verified runner and hook are staged beside the installer in a private directory, so the installer does not re-fetch an unsigned manifest or select a planted runner in the caller's directory.
- **Release-pinned installs**: `install.sh` downloads `ubs` from the release artifacts (never raw `main`) and verifies it against the release `SHA256SUMS` before installing. When `UBS_MINISIGN_PUBKEY` is set, the checksum manifest's minisign signature is verified as well and any failure aborts. The only opt-out is the explicit `--insecure` / `--skip-verification` flag.
- **Verified self-update**: `ubs --update` (and the opt-in background check) pulls the latest **release** artifacts, verifies the payload against the release `SHA256SUMS` (plus minisign when `UBS_MINISIGN_PUBKEY` is set), and replaces the binary atomically. `ubs --update` exits nonzero when the update cannot be fetched or verified.
- **Cosign keyless signing for OCI**: Images are signed by digest (not tag) and stored in the Rekor transparency log. SBOM + SLSA provenance attestations are attached to the same digest.
- **Cosign keyless signatures for the release blobs**: `install.sh`, `ubs`, `SHA256SUMS` and `git_safety_guard.py` each get a Sigstore bundle (`<asset>.sigstore.json`) produced by `cosign sign-blob` in the release workflow, plus GitHub build-provenance attestations (`gh attestation verify <asset> --repo Dicklesworthstone/ultimate_bug_scanner`). `scripts/verify.sh` requires the exact certificate identity `https://github.com/Dicklesworthstone/ultimate_bug_scanner/.github/workflows/release.yml@refs/tags/vX.Y.Z` for the selected release and issuer `https://token.actions.githubusercontent.com`; a signature for another tag is not sufficient. `UBS_VERIFY_WITH=cosign|minisign` forces a path. Without an explicit choice, a configured minisign key selects minisign; otherwise Cosign is required. There is no signature-failure fallback to bare checksums.
- **Immutable references in workflows**: release and OCI workflows sign by digest and avoid mutable tag signing.
- **Module integrity**: the `ubs` meta-runner embeds SHA-256 checksums for each language module and helper asset. Downloads are verified before execution; invalid checksums fail closed. `ubs doctor --fix` redownloads verified modules and helpers.
- **Nix reproducibility**: `nix flake check` runs in CI to keep packaging deterministic.
- **No silent auto-update**: UBS auto-update is **opt-in** via `UBS_ENABLE_AUTO_UPDATE=1`. Set `UBS_NO_AUTO_UPDATE=1` (or pass `--no-auto-update`) to force-disable updates in strict environments and CI.

## Verification guide

1. **Installer / release assets**
   ```bash
   export UBS_MINISIGN_PUBKEY="<public-key-line>"  # from maintainer
   scripts/verify.sh --version vX.Y.Z
   ```
   This authenticates the manifest and checks all three release executables before installing the private verified copies. The signed runner's literal `UBS_VERSION` must also match the requested version, including on the minisign path. Pass installer options after `--` to preserve argument boundaries, for example `scripts/verify.sh --version vX.Y.Z -- --non-interactive --skip-hooks`.

2. **OCI image** (release pipelines sign with Cosign v3, which stores the
   Sigstore bundle as an OCI 1.1 referring artifact; verify with Cosign v3 or
   newer)
   ```bash
   DIGEST=ghcr.io/<owner>/ubs-tools@sha256:<hash>
   cosign verify $DIGEST
   cosign verify-attestation --type spdx $DIGEST
   cosign verify-attestation --type https://slsa.dev/provenance/v1 $DIGEST
   ```

3. **Module cache**
   ```bash
   UBS_NO_AUTO_UPDATE=1 ubs doctor --fix
   ```
   Ensures cached modules match embedded checksums; corrupt modules are rejected and redownloaded.

## Verify without executing, or use a local release bundle

Use `--verify-only` to authenticate and hash the complete release without running
the installer, runner, or hook. This mode rejects `--insecure` and installer
arguments rather than reporting an unverified success or silently discarding
installation options.

```bash
scripts/verify.sh --version vX.Y.Z --verify-only
scripts/verify.sh --version vX.Y.Z --artifact-dir ./release-bundle --verify-only
```

A local bundle contains `SHA256SUMS`, its `SHA256SUMS.minisig` or
`SHA256SUMS.sigstore.json` signature, and the flat files `install.sh`, `ubs`, and
`git_safety_guard.py`. Only regular, non-symlink asset files are accepted. Files
are copied to private staging before authentication; the input bundle is never
modified or executed in place. A changed input manifest cannot replace the
already authenticated staged manifest. Unknown extra files are not consumed.

`--artifact-dir` performs no artifact downloads and needs no downloader. Cosign
may still refresh its trust metadata; a local bundle does not promise an offline
Sigstore trust bootstrap. Omitting `--verify-only` installs the verified local
release and may fetch third-party dependencies through the installer's existing
dependency setup. The caller's working directory is preserved for project hooks.

Missing, malformed, or duplicate required checksum entries fail closed, as do
missing signatures or assets. Older releases without a signed hook entry cannot
satisfy this complete-payload verification contract. Standalone copies of the
verifier require `--version` or `UBS_VERSION`; they do not silently install a
hardcoded old release. `UBS_ARTIFACT_BASE` can select an HTTPS mirror without
changing which signing identity or release version is trusted. Broad
`UBS_COSIGN_IDENTITY_RE` overrides are rejected.

The verifier itself and the installed signature-verification tool must come from
a trusted source. Direct `install.sh` invocation retains its existing separate
policy: checksums are enforced, but manifest authentication requires a configured
minisign key. Use `scripts/verify.sh` for the authenticated Cosign installation
path. The verifier's explicit `--insecure` mode is not an authenticated install.

## Complete runtime verification and portable bundles

The three release executables alone do not provide an offline scanner: the
runner also needs its language modules, shared library, contract, and helper
package. Verify all of those before deployment with:

```bash
scripts/verify.sh --version vX.Y.Z --verify-only --with-modules
scripts/verify.sh --version vX.Y.Z --artifact-dir ./release-bundle \
  --verify-only --with-modules
```

The authenticated runner's literal `MODULE_CHECKSUMS`, `HELPER_CHECKSUMS`, and
`HELPER_ASSETS` define the complete inventory. They are parsed as data; neither
the runner nor any module/helper is executed during verification. Every listed
asset must have exactly one checksum, and every helper checksum must be listed.
The module-to-library pins and library-to-helper pins must agree with the
authenticated runner as well. Duplicate/nonliteral metadata, unsafe paths,
case-insensitive path collisions, symlinks, special files, missing assets, and
checksum mismatches fail closed. Runtime assets are read in bounded chunks and
limited to 64 MiB each.

Remote runtime files are fetched from the selected `vX.Y.Z` tag, with no fallback
to mutable `main`. `UBS_MODULE_ARTIFACT_BASE` can point to an HTTPS mirror of the
tag's `modules/` directory without weakening any checksum checks. A local bundle
must contain all required files under `modules/`; missing local files are never
downloaded. `--with-modules` requires a nonexecuting verification mode, and it
does not silently install a module cache into an existing scanner installation.

To retain and transfer the verified runtime instead of discarding private
staging, export it as a portable archive:

```bash
scripts/verify.sh --version vX.Y.Z --bundle-output ./ubs-runtime.tar.gz

# Or export from a complete local bundle without artifact downloads:
scripts/verify.sh --version vX.Y.Z --artifact-dir ./release-bundle \
  --bundle-output ./ubs-runtime.tar.gz
```

`--bundle-output` implies `--verify-only --with-modules` and rejects `--insecure`
and installer arguments. Its parent directory must exist and its destination
must not exist. Compression finishes in a private temporary file on the same
filesystem, then an atomic hard link publishes the complete archive. A file,
directory, or symlink created concurrently at the destination is not replaced;
filesystems without hard-link support fail rather than falling back to a
partial output. Repeated exports of identical inputs with the same toolchain
are byte-identical: archive ordering, ownership, timestamps, and gzip headers
are normalized. Only verified payloads, the original signed manifest/signature,
and the derived version and hook-layout files are included, not arbitrary files
from the input bundle or private staging diagnostics.

Transfer the archive and extract it into an empty directory. Using a separately
trusted copy of the verifier, authenticate it again before running its scanner:

```bash
mkdir ./ubs-runtime
tar -xzf ./ubs-runtime.tar.gz -C ./ubs-runtime
scripts/verify.sh --version vX.Y.Z --artifact-dir ./ubs-runtime \
  --verify-only --with-modules
UBS_NO_AUTO_UPDATE=1 ./ubs-runtime/ubs --module-dir="$PWD/ubs-runtime/modules" \
  /path/to/project --ci --format=json
```

The explicit module directory avoids dependence on a prewarmed user cache.
The signature inside the archive authenticates the release manifest, and the
runner authenticated by that manifest pins the runtime assets. The archive is
not independently signed, so do not treat successful decompression as
verification. Host dependencies (Bash, Python, jq, ripgrep, Git, optional language
tools) must be provisioned separately; this is not a hermetic OS image. Cosign
may still need trust-metadata access. Preparing, verifying, and exporting a
bundle never runs the installer, scanner, or hook.

## Key handling

- **Minisign public key** (current, key id `97732BB3E99E8CBE`):

  ```
  RWS+jJ7psytzl3v4znpraY9VWBQrICXBFmT3VwvxpTzbuV2Q/CBTDmVJ
  ```

  ```bash
  export UBS_MINISIGN_PUBKEY="RWS+jJ7psytzl3v4znpraY9VWBQrICXBFmT3VwvxpTzbuV2Q/CBTDmVJ"
  minisign -Vm SHA256SUMS -P "$UBS_MINISIGN_PUBKEY" -x SHA256SUMS.minisig
  ```

  Superseded: `3168292A2B33FA20`, used for releases up to v4.6.5.

  Publish the current key line in the README example (`UBS_MINISIGN_PUBKEY`) and here. Rotate via `minisign -G` and update secrets + docs; keep old keys listed until releases signed with them are deprecated.
- **Minisign private key**: store offline; never commit. The GitHub secret should be a base64 of the private key file.
- **Cosign**: uses OIDC keyless signing. Revocation is handled by transparency (Rekor) and by removing trust in the GitHub identity if compromised.

## Reporting

If you suspect tampering or key leakage, open a security issue via the repository’s security policy or email the maintainers. Include the release tag, digest, and verification output.
