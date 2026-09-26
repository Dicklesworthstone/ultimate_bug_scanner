#!/usr/bin/env bash
set -euo pipefail

# Authenticate one release manifest, then stage every release executable the installer
# consumes. The downloaded installer must not re-fetch an unsigned manifest or
# install a different runner after its own signature has been checked.

info() { printf '→ %s\n' "$*"; }
ok() { printf '✓ %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage_error() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

usage() {
  cat <<'USAGE'
Usage: verify.sh [--version X.Y.Z|vX.Y.Z]
                 [--artifact-dir DIR | --artifact-archive FILE.tar.gz] [--verify-only]
                 [--with-modules] [--bundle-output FILE.tar.gz]
                 [--insecure] [-- INSTALLER_ARGS...]

Authenticate SHA256SUMS, verify install.sh, ubs and git_safety_guard.py against
that same manifest, and install the verified local payload. The caller's
working directory is preserved for project hook setup. Missing signatures,
missing or ambiguous checksums, and different release versions fail closed.

Options:
  --version VERSION       Select an exact release, including prerelease tags.
  --artifact-dir DIR      Read a local release bundle; do not download assets.
  --artifact-archive FILE Read a gzip-compressed release tar archive privately.
                          Reject unsafe paths, links, duplicates and oversized input.
  --verify-only           Verify the complete release WITHOUT running it.
  --with-modules          Also verify every pinned module/helper (requires --verify-only).
  --bundle-output FILE    Export a complete verified portable runtime as .tar.gz.
                          Implies --verify-only --with-modules; never overwrites FILE.
  --install-args "ARGS"   Legacy whitespace-separated arguments (no shell eval).
  -- ARGS...              Pass installer arguments without splitting or eval.
  --insecure              Explicitly skip ALL signature and checksum checks.
  -h, --help              Show help without downloading or installing anything.

Environment:
  UBS_VERSION             Version; otherwise use the checkout's VERSION file.
                          A standalone verifier requires an explicit version.
  UBS_ARTIFACT_BASE       HTTPS mirror containing the selected release assets.
  UBS_MODULE_ARTIFACT_BASE HTTPS mirror of modules/; defaults to the selected vVERSION tag.
  UBS_MINISIGN_PUBKEY     Trusted minisign key; selects minisign when provided.
  UBS_VERIFY_WITH         minisign | cosign; default is cosign without a key.

Cosign requires this repository's release.yml certificate on the EXACT selected
vVERSION tag, issued by GitHub Actions. Minisign additionally binds the requested
version to the authenticated runner's literal UBS_VERSION declaration.

Local bundles contain SHA256SUMS, its .minisig or .sigstore.json signature,
install.sh, ubs, and git_safety_guard.py. Only regular, non-symlink files are
accepted; private copies are authenticated, never executed from the input
directory. Cosign may still refresh its trust metadata. Installing a local
bundle can fetch third-party dependencies; --verify-only never runs installers.
With --with-modules, local bundles must also contain modules/ with every asset
listed in the authenticated runner. Missing assets never fall back to a network
download. Remote runtime assets come only from the selected release tag (or the
explicit module mirror), never mutable main. Runtime metadata is parsed as data,
not sourced as shell code. Host dependencies are not part of this verification.
Bundle export includes the original signature, manifest, runner, installer,
hook and verified modules. It never executes them. Extract into an empty
directory, re-verify with --artifact-dir DIR --verify-only --with-modules, then
run DIR/ubs --module-dir=DIR/modules PROJECT. Bash, Python, jq, ripgrep and other
host tools must already be installed. Export is deterministic for identical
inputs, and the final archive appears only after validation and compression.
Use --artifact-archive FILE --verify-only --with-modules to authenticate an
exported archive without extracting it yourself. Archive import never executes
archive members while unpacking or falls back to network assets. It accepts at
most 128 MiB compressed, 512 MiB expanded, 16,384 entries and 64 MiB per file.
Archive import cannot be combined with --artifact-dir or --insecure. Signature
verification still requires the selected version and a trusted host verifier.
USAGE
}

normalize_version() { printf '%s' "${1#v}"; }
VERSION_FILE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/VERSION"
VERSION="${UBS_VERSION:-$(cat "$VERSION_FILE" 2>/dev/null || true)}"
MINISIGN_PUBKEY="${UBS_MINISIGN_PUBKEY:-}"
VERIFY_WITH="${UBS_VERIFY_WITH:-}"
INSECURE=0
VERIFY_ONLY=0
WITH_MODULES=0
BUNDLE_OUTPUT=''
ARTIFACT_DIR=''
ARTIFACT_ARCHIVE=''
INSTALL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 && -n "$2" ]] || usage_error '--version requires a value'
      VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --artifact-dir)
      [[ $# -ge 2 && -n "$2" ]] || usage_error '--artifact-dir requires a directory'
      ARTIFACT_DIR="$2"; shift 2 ;;
    --artifact-dir=*)
      ARTIFACT_DIR="${1#*=}"
      [[ -n "$ARTIFACT_DIR" ]] || usage_error '--artifact-dir requires a directory'
      shift ;;
    --artifact-archive)
      [[ $# -ge 2 && -n "$2" ]] || usage_error '--artifact-archive requires a file'
      ARTIFACT_ARCHIVE="$2"; shift 2 ;;
    --artifact-archive=*)
      ARTIFACT_ARCHIVE="${1#*=}"
      [[ -n "$ARTIFACT_ARCHIVE" ]] || usage_error '--artifact-archive requires a file'
      shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    --with-modules) WITH_MODULES=1; shift ;;
    --bundle-output)
      [[ $# -ge 2 && -n "$2" ]] || usage_error '--bundle-output requires an output file'
      BUNDLE_OUTPUT="$2"; shift 2 ;;
    --bundle-output=*)
      BUNDLE_OUTPUT="${1#*=}"
      [[ -n "$BUNDLE_OUTPUT" ]] || usage_error '--bundle-output requires an output file'
      shift ;;
    --install-args)
      [[ $# -ge 2 ]] || usage_error '--install-args requires a value'
      legacy_args=()
      IFS=' ' read -r -a legacy_args <<<"$2" || true
      INSTALL_ARGS+=("${legacy_args[@]}"); shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --) shift; INSTALL_ARGS+=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "Unknown flag: $1" ;;
  esac
done

if [[ -n "$ARTIFACT_ARCHIVE" ]]; then
  [[ -z "$ARTIFACT_DIR" ]] || usage_error '--artifact-archive and --artifact-dir are mutually exclusive'
  [[ "$INSECURE" -eq 0 ]] || usage_error '--artifact-archive requires authenticated verification'
  [[ -f "$ARTIFACT_ARCHIVE" && ! -L "$ARTIFACT_ARCHIVE" ]] \
    || usage_error '--artifact-archive must name a regular non-symlink file'
  command -v python3 >/dev/null 2>&1 || die 'python3 is required to import a release archive'
fi
if [[ -n "$BUNDLE_OUTPUT" ]]; then
  [[ ! -e "$BUNDLE_OUTPUT" && ! -L "$BUNDLE_OUTPUT" ]] || usage_error '--bundle-output must not already exist'
  [[ -d "$(dirname -- "$BUNDLE_OUTPUT")" ]] || usage_error '--bundle-output parent directory must exist'
  VERIFY_ONLY=1
  WITH_MODULES=1
fi
if [[ "$WITH_MODULES" -eq 1 ]]; then
  [[ "$VERIFY_ONLY" -eq 1 ]] || usage_error '--with-modules requires --verify-only'
  command -v python3 >/dev/null 2>&1 || die 'python3 is required to verify the runtime asset graph'
fi
if [[ "$VERIFY_ONLY" -eq 1 ]]; then
  [[ "$INSECURE" -eq 0 ]] || usage_error '--verify-only cannot be combined with --insecure'
  [[ "${#INSTALL_ARGS[@]}" -eq 0 ]] || usage_error '--verify-only does not accept installer arguments'
fi
if [[ -n "$ARTIFACT_DIR" ]]; then
  [[ -d "$ARTIFACT_DIR" ]] || usage_error '--artifact-dir must name an existing directory'
  ARTIFACT_DIR="$(cd -- "$ARTIFACT_DIR" && pwd -P)" || usage_error 'Cannot read artifact directory'
fi
VERSION="$(normalize_version "$VERSION")"
version_pattern='^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.+-]*)?$'
[[ "$VERSION" =~ $version_pattern ]] \
  || usage_error 'Select a release with --version X.Y.Z (or set UBS_VERSION)'
ARTIFACT_BASE="${UBS_ARTIFACT_BASE:-https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/download/v${VERSION}}"
ARTIFACT_BASE="${ARTIFACT_BASE%/}"
[[ "$ARTIFACT_BASE" == https://* && "$ARTIFACT_BASE" != *$'\n'* && "$ARTIFACT_BASE" != *$'\r'* ]] \
  || usage_error 'UBS_ARTIFACT_BASE must be an HTTPS release URL'
COSIGN_IDENTITY="https://github.com/Dicklesworthstone/ultimate_bug_scanner/.github/workflows/release.yml@refs/tags/v${VERSION}"
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'
MODULE_ARTIFACT_BASE="${UBS_MODULE_ARTIFACT_BASE:-https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/v${VERSION}/modules}"
MODULE_ARTIFACT_BASE="${MODULE_ARTIFACT_BASE%/}"
if [[ "$WITH_MODULES" -eq 1 && -z "$ARTIFACT_DIR" && -z "$ARTIFACT_ARCHIVE" ]]; then
  [[ "$MODULE_ARTIFACT_BASE" == https://* && "$MODULE_ARTIFACT_BASE" != *$'\n'* && "$MODULE_ARTIFACT_BASE" != *$'\r'* ]] \
    || usage_error 'UBS_MODULE_ARTIFACT_BASE must be an HTTPS module URL'
fi

if [[ "$INSECURE" -eq 0 ]]; then
  [[ -z "${UBS_COSIGN_IDENTITY_RE:-}" ]] \
    || usage_error 'UBS_COSIGN_IDENTITY_RE is not supported: verification requires the exact release identity'
  for argument in "${INSTALL_ARGS[@]}"; do
    case "$argument" in
      --local|--insecure|--skip-verification)
        usage_error "$argument would bypass the authenticated release; use the verifier's explicit --insecure opt-out instead" ;;
    esac
  done
  if [[ -z "$VERIFY_WITH" ]]; then
    if [[ -n "$MINISIGN_PUBKEY" ]]; then VERIFY_WITH=minisign; else VERIFY_WITH=cosign; fi
  fi
  case "$VERIFY_WITH" in
    minisign)
      command -v minisign >/dev/null 2>&1 || die 'minisign is required for this verification path'
      [[ -n "$MINISIGN_PUBKEY" ]] || die 'UBS_MINISIGN_PUBKEY must contain a trusted minisign public key' ;;
    cosign)
      command -v cosign >/dev/null 2>&1 || die 'Install cosign for keyless verification, or configure minisign and UBS_MINISIGN_PUBKEY' ;;
    *) die "UBS_VERIFY_WITH must be minisign or cosign (got '$VERIFY_WITH')" ;;
  esac
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 \
    || die 'Need sha256sum, shasum, or openssl to verify payload digests'
fi
# curl is already a UBS runtime dependency. Restrict both the initial URL and
# redirects: a nominal HTTPS URL must not redirect an executable to HTTP/FTP.
if [[ -z "$ARTIFACT_DIR" && -z "$ARTIFACT_ARCHIVE" ]]; then
  command -v curl >/dev/null 2>&1 || die 'curl is required to download release artifacts'
fi

mktemp_dir() {
  local base="${TMPDIR:-/tmp}"
  (umask 077; mktemp -d "${base%/}/ubs-verify.XXXXXXXX")
}
VERIFY_DIR="$(mktemp_dir)" || die 'Could not create private release staging directory'
cleanup() {
  # Only this invocation's randomly created directory is ever removed.
  [[ -n "${VERIFY_DIR:-}" && "$VERIFY_DIR" != / ]] || return 0
  rm -rf -- "$VERIFY_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -n "$ARTIFACT_ARCHIVE" ]]; then
  # Unpack only into our private staging directory. Authenticate the copied
  # manifest and payloads afterwards through the same path as directory input.
  python3 - "$ARTIFACT_ARCHIVE" "$VERIFY_DIR" <<'PY'
import gzip
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import zlib

source, stage = Path(sys.argv[1]), Path(sys.argv[2])
root = stage / 'archive-input'
max_compressed, max_expanded = 128 * 1024 * 1024, 512 * 1024 * 1024
max_member, max_entries = 64 * 1024 * 1024, 16384


class BoundedReads:
    """Cap metadata allocations and optionally total compressed bytes read."""
    def __init__(self, stream, remaining=None):
        self.stream = stream
        self.remaining = remaining

    def read(self, size):
        if not 0 <= size <= 1024 * 1024:
            raise ValueError('oversized archive metadata')
        data = self.stream.read(size)
        if self.remaining is not None:
            self.remaining -= len(data)
            if self.remaining < 0:
                raise ValueError('archive exceeds 128 MiB compressed')
        return data

    def seek(self, *args):
        return self.stream.seek(*args)

    def tell(self):
        return self.stream.tell()


try:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(source, flags)
    # Decompression is bounded independently of tar headers. Finish the gzip
    # stream before verification so a damaged trailer cannot be ignored.
    with os.fdopen(descriptor, 'rb') as packed, (stage / 'input.tar').open('xb') as expanded:
        metadata = os.fstat(packed.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_compressed:
            raise ValueError('archive must be a regular file of at most 128 MiB')
        size = 0
        with gzip.GzipFile(fileobj=BoundedReads(packed, max_compressed), mode='rb') as compressed:
            while chunk := compressed.read(1024 * 1024):
                size += len(chunk)
                if size > max_expanded:
                    raise ValueError('archive exceeds 512 MiB expanded')
                expanded.write(chunk)
    root.mkdir(mode=0o700)
    entries, paths = set(), {}
    with (stage / 'input.tar').open('rb') as incoming:
        with tarfile.open(fileobj=BoundedReads(incoming), mode='r:') as archive:
            for member in archive:
                name = member.name
                if member.isdir() and name.endswith('/'):
                    name = name[:-1]
                parts = name.split('/')
                if (len(name) > 4096 or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None
                        or any(part in {'', '.', '..'} or part.endswith('.')
                               or re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', part)
                               for part in parts)):
                    raise ValueError('unsafe archive path: ' + name)
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or member.sparse is not None:
                    raise ValueError('archive links, sparse and special files are not allowed: ' + name)
                if any(key.startswith('GNU.sparse') for key in member.pax_headers):
                    raise ValueError('sparse archive metadata is not allowed')
                if not 0 <= member.size <= max_member or (member.isdir() and member.size):
                    raise ValueError('archive member exceeds 64 MiB or has an invalid size: ' + name)
                key = name.casefold()
                if key in entries or len(entries) >= max_entries:
                    raise ValueError('duplicate archive path or more than 16384 entries: ' + name)
                entries.add(key)
                for index in range(1, len(parts) + 1):
                    prefix = '/'.join(parts[:index])
                    kind = 'directory' if index < len(parts) or member.isdir() else 'file'
                    previous = paths.get(prefix.casefold())
                    if previous is not None and previous != (prefix, kind):
                        raise ValueError('colliding archive paths: ' + name)
                    paths[prefix.casefold()] = (prefix, kind)
                target = root.joinpath(*parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as payload, target.open('xb') as output:
                    while chunk := payload.read(1024 * 1024):
                        output.write(chunk)
                target.chmod(0o600)
    if not entries:
        raise ValueError('empty release archive')
except (OSError, EOFError, ValueError, RecursionError, tarfile.TarError, zlib.error) as error:
    print('ERROR: release archive rejected: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
  ARTIFACT_DIR="$VERIFY_DIR/archive-input"
fi

fetch_asset() {
  local name="$1"
  if [[ -n "$ARTIFACT_DIR" ]]; then
    [[ -f "$ARTIFACT_DIR/$name" && ! -L "$ARTIFACT_DIR/$name" ]] \
      || die "Local release asset must be a regular non-symlink file: $name"
    cp -- "$ARTIFACT_DIR/$name" "$VERIFY_DIR/$name" || die "Could not stage local release asset: $name"
    return 0
  fi
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 180 --retry 3 --retry-delay 1 --compressed \
    -o "$VERIFY_DIR/$name" "$ARTIFACT_BASE/$name" \
    || die "Failed to download release asset: $name"
}

compute_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

expected_digest() {
  # Fixed, flat asset names only. Accept GNU text/binary markers and CRLF, but
  # never pick the first of duplicate entries or tolerate a malformed digest.
  LC_ALL=C awk -v name="$1" '
    { sub(/\r$/, "") }
    $2 == name || $2 == "*" name || $2 == "./" name || $2 == "*./" name {
      count++
      if (NF != 2 || length($1) != 64 || $1 ~ /[^[:xdigit:]]/) bad = 1
      digest = tolower($1)
    }
    END { if (count != 1 || bad) exit 1; print digest }
  ' "$VERIFY_DIR/SHA256SUMS"
}

verify_asset() {
  local expected actual
  expected="$(expected_digest "$1")" || die "Missing, malformed or duplicate checksum entry: $1"
  actual="$(compute_sha256 "$VERIFY_DIR/$1")" || die "Could not hash release asset: $1"
  [[ "$expected" == "$actual" ]] || die "Checksum verification failed for $1"
  ok "Checksum verified: $1"
}

verify_runtime() {
  # Only invoke the host Python, never the downloaded runner or its helpers.
  # Its signed checksum tables are a restricted literal format, not a script.
  python3 - "$VERIFY_DIR" "$ARTIFACT_DIR" "$MODULE_ARTIFACT_BASE" "$BUNDLE_OUTPUT" "$VERIFY_WITH" <<'PY'
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

stage, local, base = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
bundle_output, signature_kind = sys.argv[4], sys.argv[5]
MAX_ASSET_BYTES = 64 * 1024 * 1024


def array_lines(text, header):
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == header]
    if len(starts) != 1:
        raise ValueError('missing or ambiguous runtime declaration: ' + header)
    for line in lines[starts[0] + 1:]:
        if line.strip() == ')':
            return
        if line.strip() and not line.lstrip().startswith('#'):
            yield line
    raise ValueError('unterminated runtime declaration: ' + header)


def pins(text, header):
    result = {}
    pattern = re.compile(r'''\s*\[(?:'([^']+)'|"([^"]+)"|([a-z]+))\]\s*=\s*(['"])([0-9a-fA-F]{64})\4\s*(?:#.*)?''')
    for line in array_lines(text, header):
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError('nonliteral runtime checksum entry: ' + line.strip())
        name = next(item for item in match.group(1, 2, 3) if item is not None)
        if name in result:
            raise ValueError('duplicate runtime checksum: ' + name)
        result[name] = match.group(5).lower()
    if not result:
        raise ValueError('empty runtime checksum table: ' + header)
    return result


def runtime_graph():
    text = (stage / 'ubs').read_text(encoding='utf-8')
    modules = pins(text, 'declare -A MODULE_CHECKSUMS=(')
    helpers = pins(text, 'declare -A HELPER_CHECKSUMS=(')
    listed = []
    for line in array_lines(text, 'HELPER_ASSETS=('):
        match = re.fullmatch(r'''\s*(['"])([A-Za-z0-9_./-]+)\1\s*(?:#.*)?''', line)
        if match is None:
            raise ValueError('nonliteral runtime asset: ' + line.strip())
        listed.append(match.group(2))
    if len(listed) != len(set(listed)) or set(listed) != set(helpers):
        raise ValueError('runtime helper inventory does not match its checksum table')
    if not {'contract.json', 'lib/ubs-common.sh'} <= helpers.keys():
        raise ValueError('runtime lacks its contract or shared library pin')
    files = {}
    for language, checksum in modules.items():
        if re.fullmatch('[a-z]+', language) is None:
            raise ValueError('invalid runtime module name: ' + language)
        files[f'ubs-{language}.sh'] = checksum
    for name, checksum in helpers.items():
        if name != 'contract.json' and not name.startswith(('helpers/', 'lib/')):
            raise ValueError('invalid runtime helper path: ' + name)
        files[name] = checksum
    folded = set()
    for name in files:
        if (re.fullmatch('[A-Za-z0-9_./-]+', name) is None
                or any(part in {'', '.', '..'} for part in name.split('/'))):
            raise ValueError('unsafe runtime path: ' + name)
        key = name.casefold()
        if key in folded:
            raise ValueError('colliding runtime paths: ' + name)
        folded.add(key)
    for name in folded:
        parts = name.split('/')
        if any('/'.join(parts[:i]) in folded for i in range(1, len(parts))):
            raise ValueError('runtime file/directory collision: ' + name)
    return modules, helpers, files


def copy_local(name, target):
    # Check every component, not just the leaf: a symlinked helpers directory
    # is not a local bundle. Reject special files before attempting any read.
    source = Path(local)
    for part in ('modules/' + name).split('/'):
        source = source / part
        mode = source.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError('runtime asset is not a regular non-symlink file: ' + name)
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(source, flags)
    with os.fdopen(fd, 'rb') as incoming, target.open('xb') as outgoing:
        if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
            raise ValueError('runtime asset is not a regular file: ' + name)
        size = 0
        while chunk := incoming.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ASSET_BYTES:
                raise ValueError('runtime asset exceeds 64 MiB: ' + name)
            outgoing.write(chunk)


def verify_nested_pins(modules, helpers):
    root = stage / 'modules'
    library = helpers['lib/ubs-common.sh']
    for language in modules:
        text = (root / f'ubs-{language}.sh').read_text(encoding='utf-8')
        matches = re.findall(r'^UBS_LIB_CHECKSUM="([0-9a-fA-F]{64})"\s*$', text, re.MULTILINE)
        if len(matches) != 1 or matches[0].lower() != library:
            raise ValueError('runtime module has an inconsistent library pin: ' + language)
    text = (root / 'lib/ubs-common.sh').read_text(encoding='utf-8')
    inner = pins(text, 'declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(')
    if inner != {name: checksum for name, checksum in helpers.items() if name != 'lib/ubs-common.sh'}:
        raise ValueError('runtime shared-library helper pins do not match the authenticated runner')


def export_bundle(files):
    destination = Path(bundle_output).absolute()
    signature = 'SHA256SUMS.minisig' if signature_kind == 'minisign' else 'SHA256SUMS.sigstore.json'
    names = ['SHA256SUMS', signature, 'install.sh', 'ubs', 'git_safety_guard.py',
             'VERSION', '.claude/hooks/git_safety_guard.py']
    names.extend('modules/' + name for name in files)
    # Build in the destination filesystem. Atomic hard-link publication refuses
    # an existing file, directory or symlink, including one created after argv
    # validation. Never fall back to overwriting or partially copying the output.
    with tempfile.NamedTemporaryFile(prefix='.ubs-bundle-', suffix='.tmp', dir=destination.parent) as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name in sorted(names):
                    path = stage / name
                    with path.open('rb') as payload:
                        metadata = os.fstat(payload.fileno())
                        if not stat.S_ISREG(metadata.st_mode):
                            raise ValueError('cannot export a nonregular runtime asset: ' + name)
                        member = tarfile.TarInfo(name)
                        member.size = metadata.st_size
                        member.mode = 0o755 if name == 'ubs' or name.endswith(('.sh', '.py', '.js')) else 0o644
                        member.mtime = 0
                        archive.addfile(member, payload)
        output.flush()
        os.fsync(output.fileno())
        os.link(output.name, destination)
    print('Portable runtime bundle written: ' + str(destination), flush=True)


try:
    modules, helpers, files = runtime_graph()
    for name, expected in sorted(files.items()):
        target = stage / 'modules' / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if local:
            copy_local(name, target)
        else:
            subprocess.run(['curl', '--fail', '--location', '--proto', '=https',
                            '--proto-redir', '=https', '--tlsv1.2', '--connect-timeout', '20',
                            '--max-time', '180', '--max-filesize', str(MAX_ASSET_BYTES),
                            '--retry', '3', '--retry-delay', '1', '--compressed',
                            '-o', str(target), base + '/' + name], check=True, timeout=800)
        if target.stat().st_size > MAX_ASSET_BYTES:
            raise ValueError('runtime asset exceeds 64 MiB: ' + name)
        actual = hashlib.sha256()
        with target.open('rb') as incoming:
            for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                actual.update(chunk)
        if actual.hexdigest() != expected:
            raise ValueError('runtime checksum mismatch: ' + name)
        target.chmod(0o700 if name.endswith(('.sh', '.py', '.js')) else 0o600)
    verify_nested_pins(modules, helpers)
    (stage / 'runtime-assets.json').write_text(json.dumps(files, sort_keys=True) + '\n', encoding='utf-8')
    print(f'Runtime verified: {len(modules)} modules, {len(helpers)} helper assets', flush=True)
    if bundle_output:
        export_bundle(files)
except (OSError, UnicodeError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
    print('ERROR: runtime verification failed: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
}

info "Version: $VERSION"
if [[ -n "$ARTIFACT_DIR" ]]; then
  info "Local release bundle: $ARTIFACT_DIR"
else
  info "Release base: $ARTIFACT_BASE"
fi
if [[ "$INSECURE" -eq 0 ]]; then
  fetch_asset SHA256SUMS
  case "$VERIFY_WITH" in
    minisign)
      fetch_asset SHA256SUMS.minisig
      minisign -Vm "$VERIFY_DIR/SHA256SUMS" -P "$MINISIGN_PUBKEY" \
        -x "$VERIFY_DIR/SHA256SUMS.minisig" >/dev/null \
        || die 'Signature verification failed for SHA256SUMS (minisign)' ;;
    cosign)
      fetch_asset SHA256SUMS.sigstore.json
      cosign verify-blob --bundle "$VERIFY_DIR/SHA256SUMS.sigstore.json" \
        --certificate-identity "$COSIGN_IDENTITY" \
        --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
        "$VERIFY_DIR/SHA256SUMS" >/dev/null \
        || die 'Signature verification failed for SHA256SUMS (cosign)' ;;
  esac
  ok "Release manifest authenticated with $VERIFY_WITH"
  # Validate all required entries before fetching any executable payload.
  for asset in install.sh ubs git_safety_guard.py; do
    expected_digest "$asset" >/dev/null || die "Missing, malformed or duplicate checksum entry: $asset"
  done
  for asset in install.sh ubs git_safety_guard.py; do
    fetch_asset "$asset"
    verify_asset "$asset"
  done
  runner_version="$(awk '/^UBS_VERSION=/ { sub(/\r$/, ""); count++; value=$0 }
    END { if (count != 1) exit 1; print value }' "$VERIFY_DIR/ubs")" \
    || die 'Authenticated runner has no unique literal UBS_VERSION declaration'
  case "$runner_version" in
    "UBS_VERSION=\"${VERSION}\""|"UBS_VERSION='${VERSION}'"|"UBS_VERSION=${VERSION}") ;;
    *) die "Authenticated runner does not match requested version $VERSION" ;;
  esac
  # The installer recognizes ubs + VERSION next to itself as an explicit local
  # release source. The hook is likewise taken from the authenticated copy.
  # Keep the caller's cwd so project hooks are not installed into this staging
  # directory, and never pass --local (which would prefer a planted cwd/ubs).
  printf '%s\n' "$VERSION" > "$VERIFY_DIR/VERSION"
  mkdir -p "$VERIFY_DIR/.claude/hooks"
  cp "$VERIFY_DIR/git_safety_guard.py" "$VERIFY_DIR/.claude/hooks/git_safety_guard.py"
else
  warn 'Explicit insecure mode: signature and checksum verification are disabled'
  fetch_asset install.sh
fi

if [[ "$WITH_MODULES" -eq 1 ]]; then
  verify_runtime || die 'The complete runtime could not be verified'
fi
if [[ "$VERIFY_ONLY" -eq 1 ]]; then
  ok "Release v${VERSION} verified; no installer or scanner was executed"
  exit 0
fi
ok 'Executing installer'
status=0
if [[ "$INSECURE" -eq 0 ]]; then
  # UBS_NO_AUTO_UPDATE guards the scanner, not install.sh. The installer's
  # update check can otherwise exec unsigned main/install.sh before parsing
  # its arguments, including in --easy-mode. Its existing re-exec sentinel
  # also survives install.conf overriding the early --skip-version-check flag.
  export UBS_INSTALLER_SELF_UPDATED=1
fi
UBS_ARTIFACT_BASE="$ARTIFACT_BASE" UBS_NO_AUTO_UPDATE=1 \
  bash "$VERIFY_DIR/install.sh" "${INSTALL_ARGS[@]}" || status=$?
# Do not exec: the parent owns staging cleanup on both success and failure.
exit "$status"
