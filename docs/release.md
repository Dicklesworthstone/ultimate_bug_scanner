# Release Playbook

This playbook documents how to cut and publish a signed UBS release. The release workflow (`.github/workflows/release.yml`) runs automatically on git tags that start with `v` (for example `v5.1.0`).

## Prerequisites

- Maintainer with push rights to `master` and tags.
- `MINISIGN_SECRET_KEY` stored as an org/repo secret (base64 of the minisign secret key). The matching public key is published for users (see `docs/security.md`).
- OIDC-enabled GitHub Actions (default) for keyless Cosign signing.
- GHCR write access (uses `${GITHUB_REPOSITORY_OWNER,,}/ubs-tools`).

## One-time setup

1. Generate minisign keys locally (run from a secure machine):
   ```bash
   minisign -G -p minisign.pub -s minisign.key
   ```
2. Base64-encode `minisign.key` and store it as the `MINISIGN_SECRET_KEY` GitHub secret. Keep the private key offline; rotate if leaked.
3. Publish the public key string in `docs/security.md` and the README example env var.
4. Confirm OIDC trust for GitHub Actions with Sigstore (default trust policy works for keyless signing).

## Release steps

1. **Bump version**
   - Update `VERSION` to the new semantic version (for example `5.1.0`).
   - Update docs/readme snippets if they mention the version.
2. **Commit and tag**
   ```bash
   git commit -am "chore: bump version to 5.1.0"
   git tag v5.1.0
   git push origin master --tags
   ```
3. **Workflow runs automatically** on the pushed tag:
   - `nix-check`: runs `nix flake check` for determinism.
   - `build-artifacts`: installs pinned toolchain (jq 1.7.1, ripgrep 13.0.0, uv 0.4.20), generates `SHA256SUMS`, signs it with minisign, builds `ubs.rb` Homebrew formula, and produces `dist/sbom.spdx.json` for the repo snapshot.
   - `oci-image`: builds and pushes `ghcr.io/<owner>/ubs-tools:{sha,tag,latest}`, signs the digest with Cosign keyless, attaches SBOM + provenance attestations, and uploads the SBOM/provenance artifacts.
   - `publish`: attaches `install.sh`, `ubs`, `SHA256SUMS`, `SHA256SUMS.minisig`, `ubs.rb`, repo SBOM, and OCI SBOM/provenance to the GitHub Release for the tag.
4. **Validate release artifacts**
   - Download the release assets locally and run:
     ```bash
     UBS_MINISIGN_PUBKEY="<public-key-line>" scripts/verify.sh --version 5.1.0 --install-args "--dry-run"
     ```
   - Verify OCI signature and attestations:
     ```bash
     cosign verify $IMAGE_DIGEST
     cosign verify-attestation --type spdx $IMAGE_DIGEST
     cosign verify-attestation --type https://slsa.dev/provenance/v1 $IMAGE_DIGEST
     ```

## Key management

- **Rotation**: generate a new minisign keypair, update the GitHub secret, and publish the new public key. Keep the old public key listed in `docs/security.md` until all releases signed with it are retired.
- **Revocation**: if a key is compromised, remove it from secrets immediately, publish a revocation notice in `docs/security.md`, and cut a new release signed with the new key.
- **Access**: restrict `MINISIGN_SECRET_KEY` secret to maintainers only. Do not reuse this key for other projects.

## Troubleshooting

- Missing secret: the release workflow fails early with `MINISIGN_SECRET_KEY is required for releases`.
- Tag/version mismatch: the workflow stops if `VERSION` in the repo does not match the pushed tag.
- GHCR failures: ensure the owner name is lowercase and the `packages: write` permission is present (both handled in the workflow).
