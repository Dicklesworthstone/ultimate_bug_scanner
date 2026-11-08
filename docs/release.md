# Release Playbook

Use **DSR (Doodlestein Self-Releaser)** directly for release automation, as
required by `AGENTS.md`. GitHub Actions execution is prohibited, including on
self-hosted Actions runners. `.github/workflows/release.yml` remains a build,
signing, and asset specification for DSR/local execution; retaining its YAML
does not authorize dispatching it through Actions.

Candidate qualification does not publish anything. Before creating or pushing a
tag, creating a release, promoting a draft, or publishing an OCI image, show the
maintainer the exact source commit, version, commands, assets, and destinations
and obtain explicit approval. Keep repository Actions execution disabled before
pushing: the retained YAML still contains tag triggers.

## Prerequisites

- A configured DSR host and UBS release job, with its exact artifact mapping
  reviewed. The retained workflow alone is not a DSR configuration. Run
  `dsr doctor` on that host and resolve missing tools or credentials before
  publication. Do not substitute GitHub Actions when DSR is unavailable.
- A clean `main` checkout at the reviewed commit, an unused release version, and
  passing quality gates: ShellCheck, checksum verification, the test suite,
  the complete strict self-scan, and `nix flake check`. Retain these gates when
  routing execution through DSR.
- Bash, Python, jq, ripgrep, Minisign, and the pinned build tooling in the recipe;
  Syft for the project SBOM. Host and optional scanner dependencies must be
  provisioned before offline installation tests.
- The existing UBS Minisign private key on a trusted signer, matching
  `minisign.pub` and the key embedded in the installer (see `docs/security.md`).
  A disposable test key is not a production signing credential. DSR may use
  `DSR_MINISIGN_KEY`; the retained YAML expects `MINISIGN_SECRET_KEY` containing
  base64-encoded private-key bytes. Never print or commit either secret.
- Maintainer permissions to push the approved commit/tag and create, upload, and
  promote the approved GitHub Release. GHCR write permission is additionally
  required if OCI publication is included in the approved plan.

### Sigstore and provenance under DSR

The existing Cosign verifier requires the exact certificate identity
`https://github.com/Dicklesworthstone/ultimate_bug_scanner/.github/workflows/release.yml@refs/tags/vX.Y.Z`
and issuer `https://token.actions.githubusercontent.com`. Running the YAML with
DSR/`act` does not supply that Actions OIDC identity or GitHub build provenance.
Do not weaken either identity check or describe locally generated provenance as
Actions provenance. If those specific signatures/attestations are required,
their issuance remains a maintainer policy and infrastructure prerequisite.

The existing Minisign verification path works with DSR and preserves release
authentication. When a release lacks the Actions Sigstore bundles, document the
explicit trusted-key command below; `scripts/verify.sh` defaults to Cosign when
no Minisign key is configured. OCI signing and provenance must be qualified
separately before any image is pushed.

## Qualify without creating a tag or release

Run the release-focused tests as part of the DSR qualification job:

```bash
export PYTHONDONTWRITEBYTECODE=1
python3 test-suite/quality/test_release_candidate.py -v
python3 test-suite/quality/test_release_candidate_install.py -v
python3 test-suite/shareable/test_release_generation.py -v
python3 test-suite/shareable/test_installed_contract.py -v
python3 test-suite/quality/test_verified_release.py -v
python3 test-suite/quality/test_release_self_scan.py -v
bash scripts/verify_checksums.sh
bash scripts/verify_sha256sums.sh
python3 scripts/check_self_scan.py
```

These supplement the full test suite, lint, and Nix gates. Record any missing
tool, skipped test, partial self-scan, or failure as an unmet prerequisite; it is
not a passing release qualification. Fresh-install and upgrade tests must check
that signature failures, corrupt/missing runtime assets, and targets without
`UBS_RELEASE_GENERATIONS=1` preserve the previous runner, companion, and cache.

Build a complete unsigned candidate in a new directory:

```bash
candidate_version="$(tr -d '\r\n' < VERSION)"
candidate_parent="$(mktemp -d "${TMPDIR:-/tmp}/ubs-candidate.XXXXXX")"
python3 scripts/build_release_candidate.py \
  --version "$candidate_version" --output "$candidate_parent/dist"
```

The builder checks `VERSION`, the literal runner version, and the README badge;
the unique generation declaration; the embedded generation helper; runner and
daemon digests; and every runtime digest and transitive dependency pin. It
refuses symlink inputs and an existing output destination. It copies the six
flat payloads (`install.sh`, `ubs`, `ubs-daemon`, `verify.sh`,
`git_safety_guard.py`, `minisign.pub`), `VERSION`, and exactly the runner-pinned
`modules/` files. Its generated `SHA256SUMS` covers the six flat payloads; the
authenticated runner pins the runtime files.

The builder does not execute candidate code, alter version/checksum files,
create a tag, sign, or upload anything. It does not replace the self-scan gate
or prove that the checkout is clean. Record the source commit, builder JSON
result, manifest digest, and test logs with the candidate.

## Prepare the release version

Use `scripts/cut-release.sh` to synchronize the version, checksum tables, and
changelog. It requires a **new** version: passing the current `VERSION` is an
error. Versions must be numeric `X.Y.Z`; the generation protocol does not accept
prerelease suffixes such as `-rc1`, so the cutter refuses them before scanning or
changing files. Qualify a candidate privately without inventing an unsupported
runner version. For a source tree at 5.5.43, 5.5.44 is the next patch candidate
only if that version/tag has not already been used.

```bash
scripts/cut-release.sh 5.5.44 --dry-run
scripts/cut-release.sh 5.5.44 --no-commit
```

The first command previews; the second prepares reviewable working-tree edits
without committing or tagging. Both require the strict self-scan first. The
script synchronizes `VERSION`, `UBS_VERSION`, the README badge, module/helper
checksums, and `SHA256SUMS`, then rolls the Unreleased changelog section. Rebuild
and requalify the resulting candidate; version changes change authenticated
bytes. Review and commit the prepared edits before selecting the final release
commit. Do not rerun the cutter with the same version after preparing it.

The self-scan validator requires complete, nonempty machine-readable results
with no critical findings or warnings, not merely exit zero. A failed gate
leaves the version files untouched. Reproduce with
`./ubs . --ci --fail-on-warning`, fix the cause, and rerun; there is no release
opt-out. Maintainers can enable `.githooks` with
`git config core.hooksPath .githooks` for the existing push-time backstop.

The cutter's normal `--yes` mode commits and creates an annotated tag. Use it
only after that exact action has been approved; it never pushes. When preparing
with `--no-commit`, create the reviewed tag separately only after approval.

## Sign and authenticate the complete candidate

On the configured signer, use the existing private key and verify the result
against the independently trusted repository public key:

```bash
minisign -S -s "$UBS_SIGNING_KEY" -m "$candidate_parent/dist/SHA256SUMS" \
  -x "$candidate_parent/dist/SHA256SUMS.minisig"
minisign -Vm "$candidate_parent/dist/SHA256SUMS" -p minisign.pub \
  -x "$candidate_parent/dist/SHA256SUMS.minisig"

trusted_ubs_key='RWS+jJ7psytzl3v4znpraY9VWBQrICXBFmT3VwvxpTzbuV2Q/CBTDmVJ'
UBS_VERIFY_WITH=minisign UBS_MINISIGN_PUBKEY="$trusted_ubs_key" \
  scripts/verify.sh --version "$candidate_version" \
  --artifact-dir "$candidate_parent/dist" --verify-only --with-modules
```

`UBS_SIGNING_KEY` is a private-key pathname on that host. The public key above is
the current UBS key documented in `docs/security.md`; verify its trust before
using it. Downloading a new key next to an artifact does not establish trust.
Keep disposable test signatures separate from production artifacts.

To retain the authenticated runtime as a portable archive:

```bash
UBS_VERIFY_WITH=minisign UBS_MINISIGN_PUBKEY="$trusted_ubs_key" \
  scripts/verify.sh --version "$candidate_version" \
  --artifact-dir "$candidate_parent/dist" \
  --bundle-output "$candidate_parent/ubs-runtime.tar.gz"
```

Export authenticates every pinned file and includes the original signed
manifest/signature. The archive is not independently signed. A separately
trusted verifier must authenticate it again with `--artifact-archive` before
installation. See `docs/security.md` for complete bundle and offline-install
commands.

## Publication after explicit approval

Present the full commit SHA, exact unused tag, candidate hashes, qualification
results, DSR command/configuration, signing identity, and asset list. Include
draft creation, asset upload, promotion to latest, any OCI publication, and any
package-manager notification as explicit actions. An absent DSR configuration
or production signing key is a remaining prerequisite, not permission to skip
verification or use another execution path.

If the candidate was prepared with `--no-commit`, the approved tag command is
`git tag -a vX.Y.Z <reviewed-commit-sha> -m "UBS vX.Y.Z"`. Verify its target, then
push only the reviewed branch and tag after confirming Actions remains disabled:

```bash
git push origin main
git push origin refs/tags/vX.Y.Z:refs/tags/vX.Y.Z
```

Use the configured DSR job to sign and upload a draft containing `install.sh`,
`ubs`, `ubs-daemon`, `verify.sh`, `git_safety_guard.py`, `minisign.pub`,
`SHA256SUMS`, and `SHA256SUMS.minisig`, plus the generated Homebrew formula and
project SBOM. Include a complete runtime archive if it is part of the approved
asset list. Thin installations fetch pinned modules from the exact version's
git tag; that tag must contain the bytes checked by the candidate builder.

Download and authenticate the uploaded artifacts, exercise fresh installs and
upgrades in disposable environments, and confirm failure preserves existing
installations before promoting the draft. Publish Sigstore bundles or
OCI/provenance artifacts only when they were actually produced and verified
under the approved identity. Keep existing Nix, signature, and provenance
requirements explicit in the approval plan; DSR does not waive them.

After a toolchain or recipe change, qualify signatures and installation end to
end before announcing the release. If a published version is defective, fix
forward with a new patch version; never move or re-tag a published version.

## Changelog discipline

Every change lands under `## [Unreleased]` in `CHANGELOG.md` with its source change.
`scripts/cut-release.sh` rolls that section under the new version header and
re-creates an empty one; retain the lint check that rejects a missing section.

## Key management

- **Rotation**: use an explicitly reviewed key-rotation plan to update the
  trusted installer key, signer configuration, and public documentation. Keep
  old public keys listed until the releases they authenticate are retired.
- **Revocation**: remove compromised key material from signing hosts/secrets,
  publish a revocation notice, and cut a new release with the replacement key.
- **Access**: restrict production private keys to maintainers and trusted DSR
  signing hosts; retain 0600 file permissions. Do not reuse this key for other
  projects or expose private-key bytes in logs.

## Troubleshooting

- Missing signer: provision the existing UBS key on the trusted DSR host. The
  retained recipe fails with `MINISIGN_SECRET_KEY is required for releases` when
  its secret input is absent, and verifies the produced signature with
  `minisign.pub` to catch the wrong key.
- Version or inventory mismatch: fix the source inconsistency and regenerate
  checksums through the existing tooling; never edit an artifact to evade its
  pin or remove the generation requirement.
- Existing candidate directory: choose a new output directory. The assembler
  intentionally refuses to overwrite a prior candidate.
- Missing Actions OIDC: use the supported Minisign verification path. Local
  execution cannot mint the exact Actions identity expected by the Cosign path.
- GHCR failures: verify lowercase owner/image names and the approved signer's
  registry permissions; do not silently skip OCI verification or attestations.
