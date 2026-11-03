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
- **Release-pinned installs**: `install.sh` downloads `ubs` from release artifacts and authenticates `SHA256SUMS` with the embedded Minisign public key before installing. `UBS_MINISIGN_PUBKEY` selects an explicitly trusted alternate key; omitting it does not disable signatures. A missing verifier or invalid signature aborts. Only the explicit `--insecure` / `--skip-verification` installer option bypasses this gate. Trusted local source installations remain an explicit `--local` operation.
- **Transactional self-update**: `ubs --update` (and the opt-in background check) authenticates the latest release manifest with Minisign, verifies the runner and companion, then prepares and verifies the entire module cache before atomically replacing the runner. It exits nonzero when a forced update cannot complete, including same-version cache repair. There is no unsigned updater fallback.
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

The verifier reads local release files without a downloader. When installing a
bundle containing `modules/`, it also verifies and privately stages that complete
runtime before invoking the installer. Missing or damaged runtime files abort
before installation; they never trigger a network fallback. A thin bundle with
no `modules/` retains the installer's normal tagged runtime-download path.
Cosign may still refresh its trust metadata, and installation may fetch
third-party dependencies through the existing dependency setup. The caller's
working directory is preserved for project hooks.

Archive import and runtime verification require Python >= 3.9. The verifier
honors `UBS_PYTHON`, or discovers `python3`, `python`, then the `py -3` launcher;
these modes reject an unusable explicit override before verification. Interpreter probes and
the verifier's standard-library helpers use isolated startup (`-I -S`). Project
modules, `PYTHONPATH`, `PYTHONHOME`, and site startup files cannot execute during
these steps, including archive inspection before signature authentication.
Interpreter paths are fixed before staging, preserving paths with spaces and
the final symlink of a selected virtual environment.

Missing, malformed, or duplicate required checksum entries fail closed, as do
missing signatures or assets. Older releases without a signed hook entry cannot
satisfy this complete-payload verification contract. Standalone copies of the
verifier require `--version` or `UBS_VERSION`; they do not silently install a
hardcoded old release. `UBS_ARTIFACT_BASE` can select an HTTPS mirror without
changing which signing identity or release version is trusted. Broad
`UBS_COSIGN_IDENTITY_RE` overrides are rejected.

The verifier itself and the installed signature-verification tool must come from
a trusted source. Direct `install.sh` invocation requires Minisign and uses the
published key by default. Use `scripts/verify.sh` for the authenticated Cosign
installation path. The installer's optional raw-main self-refresh is disabled
unless `--insecure` was explicitly requested. An explicit `--insecure` mode is
not an authenticated install.

## Runner and cache publication

A managed installation stores complete module generations below
`$XDG_DATA_HOME/ubs/modules/.ubs-releases/` (normally
`~/.local/share/ubs/modules/.ubs-releases/`). Their identities derive from the
runner version and its literal asset pins. Scans select with their already
loaded pins, so replacing the installed runner pathname cannot switch an
in-flight scan to another version's dependencies. A selected generation takes
precedence over stale sibling modules or language commands on `PATH`.

The updater parses the authenticated candidate as data. It requires a complete,
unambiguous language/helper inventory and matching module-to-library and
library-to-helper pins. Cached or local source files are reused only when their
bytes match the target digest; downloads use the target release tag and have
no mutable-main fallback. Every module, helper, library, and contract must pass
before publication. Ready markers describe a generation; they do not replace
verification of its actual bytes. A generation must also contain exactly the
pinned files, its ready marker, and their parent directories. Unexpected files,
Python bytecode caches, and symlinks fail validation before helper startup.
Managed scans disable bytecode writes so normal imports preserve this inventory.

Later updates can reuse assets from the generation named by the currently
installed runner, while holding that runner's publication lock. Each reused
file must match the new release's exact pin; previous ready markers and version
labels grant no trust. Unchanged assets need no module download. Changed,
missing, or damaged assets still require a verified replacement, and a failed
fetch preserves the previous installation. Release signature authentication
remains mandatory even when every module byte is already cached.

Preparation occurs in a private directory on the cache filesystem. Publication
locks serialize writers, and an expected-runner digest prevents an updater or
installer from overwriting a peer's newer installation. The complete generation
is renamed into place before the runner's final atomic replacement. Previous
generations and the original legacy cache are retained for concurrent readers.
Interrupted staging directories are never selected. A failed fetch, invalid
signature, corrupt asset, or failed prepublication check cannot activate a
partial replacement. Files are flushed before publication; directory flushing
is used where supported, without claiming power-loss durability on filesystems
that cannot provide it.

`ubs doctor --fix` prepares a fully verified replacement before repairing an
installed generation. Repairs replace only files with the same pinned target
bytes, publish the ready marker last, and keep the generation directory stable
for concurrent readers. After the complete replacement has been verified,
unexpected entries are moved to a private quarantine outside the active
generation and retained for inspection. Doctor's cache diagnostics execute
from a private snapshot containing only verified helper sources, using isolated
Python startup; adjacent startup files and previously compiled bytecode cannot
authorize diagnostic code. Ordinary scans reject damaged generations; they never
authorize an arbitrary checksum mismatch as an old release.

For installed runners, `ubs --update-modules` forces a fresh download of
every pinned runtime asset into private staging. It verifies the entire graph
before applying the same atomic, same-pin replacements used by repair. Module
permissions are set before publication, so an interrupted refresh cannot leave
a healthy active module non-executable. Failed or corrupt downloads preserve
the existing generation; concurrent scans continue to use its pinned bytes.
An explicit refresh can repair damaged assets or permissions, while ordinary
scans continue to fail closed. Standalone runners with flat legacy caches
prepare a new complete generation and leave the legacy files intact for older
readers. Source checkouts and exported trees with bundled modules retain their
existing source-owned refresh behavior.

Older runner-only updaters cannot acquire these transaction guarantees
retroactively. The installed runner recognizes exact released contract digests
from the supported v5.4.x releases, v5.5.3, and v5.5.26, then prepares its own
complete verified generation on first use. The old bytes are not executed or
overwritten during migration. A modified historical contract still fails closed.
Offline migration fails explicitly while retaining the original cache; retry
once the matching release assets are available, or use `ubs doctor --fix` for
explicit repair.

The installer's cron job invokes this same transaction and preserves its public
verification key, cache location, and Bash executable. It does not need a second
`doctor --fix` command after an apparently successful runner-only update.
Keep Minisign available on the recorded `PATH`; an unattended verification
failure leaves the existing release in service. Old generations are retained
deliberately; automatic pruning of assets potentially used by running scans is
not part of the update operation.

Uninstall holds the runner publication locks until removal finishes and refuses
to start while an updater owns them. This lock handoff currently requires
POSIX; native Windows uninstall refuses before removing files. Native Windows
and macOS publication behavior still requires validation on those platforms.

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
downloaded. Use `--verify-only --with-modules` to inspect without changing an
installation. Without `--verify-only`, `--with-modules` stages the complete
verified runtime before executing the verified installer:

```bash
scripts/verify.sh --version vX.Y.Z --with-modules -- --non-interactive
scripts/verify.sh --version vX.Y.Z --artifact-dir ./release-bundle \
  --with-modules -- --non-interactive
```

Installing a local directory or archive that contains a `modules/` entry enables
this complete verification automatically. The explicit flag also requires a
runtime when the bundle has no such entry. An incomplete directory, a symlink
(including a dangling one), or a special file cannot silently select a thinner
installation path. Unlisted extras, including Python startup files and bytecode,
are not copied into the installer's source directory. The current installer
publishes the runner only after its complete module generation is ready; failed
bundle verification never executes it or changes an existing runner/cache.
`--with-modules` rejects `--insecure` in both verification and installation modes.

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

Alternatively, install an archive through the separately trusted verifier:

```bash
scripts/verify.sh --version vX.Y.Z --artifact-archive ./ubs-runtime.tar.gz \
  --with-modules -- --non-interactive
```

This authenticates the archive's release and every pinned runtime file before
running its installer; a fresh user cache is sufficient. To keep the host fully
offline, provision the desired host dependencies beforehand and use the
installer's existing `--skip-*` flags for optional tools you choose to omit.
For example, `--skip-bun --skip-type-narrowing --skip-typos --skip-toon` avoids
installing those optional tools. Signature verification still needs a trusted
host verifier; minisign with an explicitly trusted key needs no online trust
metadata.

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
