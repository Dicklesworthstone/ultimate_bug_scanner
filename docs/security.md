# Security & Integrity Model

This document captures the threat model for the UBS installer, module downloads, and OCI images, plus the controls we ship to protect users.

## Threat model

- **Tampered release artifacts** (MITM or compromised GitHub asset).
- **Mutable image tags** (`latest` overwritten with malicious content).
- **Module supply chain attacks** during lazy downloads of language helpers.
- **Installer auto-updates** fetching unverified content.
- **Compromised signing keys** (minisign or Sigstore identity).

## Controls

- **Signed checksums for installers**: `SHA256SUMS` is signed with minisign. `scripts/verify.sh` verifies the signature + checksum before executing `install.sh`.
- **Cosign keyless signing for OCI**: Images are signed by digest (not tag) and stored in the Rekor transparency log. SBOM + SLSA provenance attestations are attached to the same digest.
- **Immutable references in workflows**: release and OCI workflows sign by digest and avoid mutable tag signing.
- **Module integrity**: the `ubs` meta-runner embeds SHA-256 checksums for each language module. Downloads are verified before execution; invalid checksums fail closed. `ubs doctor --fix` redownloads verified modules.
- **Nix reproducibility**: `nix flake check` runs in CI to keep packaging deterministic.
- **No silent auto-update**: module updates require either explicit `--update-modules` or user acceptance via installer prompts. Set `UBS_NO_AUTO_UPDATE=1` (default in CI hooks) to enforce pinned modules.

## Verification guide

1. **Installer / release assets**
   ```bash
   export UBS_MINISIGN_PUBKEY="<public-key-line>"  # from maintainer
   scripts/verify.sh --version vX.Y.Z
   ```
   This downloads `SHA256SUMS` + signature from the release, validates them, then checks `install.sh`.

2. **OCI image**
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

## Key handling

- **Minisign public key**: publish the current key line in the README example (`UBS_MINISIGN_PUBKEY`) and here. Rotate via `minisign -G` and update secrets + docs; keep old keys listed until releases signed with them are deprecated.
- **Minisign private key**: store offline; never commit. The GitHub secret should be a base64 of the private key file.
- **Cosign**: uses OIDC keyless signing. Revocation is handled by transparency (Rekor) and by removing trust in the GitHub identity if compromised.

## Reporting

If you suspect tampering or key leakage, open a security issue via the repository’s security policy or email the maintainers. Include the release tag, digest, and verification output.
