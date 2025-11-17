#!/usr/bin/env bash
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

# Ultimate Bug Scanner - Installation Script
# https://github.com/Dicklesworthstone/ultimate_bug_scanner

VERSION="4.6.0"

# Global copy of original args (needed in update re-exec; must not be local)
ORIGINAL_ARGS=()

# Validate bash version (requires 4.0+)
if ((BASH_VERSINFO[0] < 4)); then
  echo "Error: This installer requires Bash 4.0 or later (you have $BASH_VERSION)" >&2
  echo "Please upgrade bash or install manually." >&2
  exit 1
fi
SCRIPT_NAME="ubs"
INSTALL_NAME="ubs"
REPO_URL="https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main"

# TTY-aware color initialization
COLOR_ENABLED=1
init_colors() {
  if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ] || [ "${TERM:-dumb}" = "dumb" ]; then COLOR_ENABLED=0; fi
  if [ "$COLOR_ENABLED" -eq 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
  else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
  fi
}
init_colors

# Symbols
CHECK="${GREEN}✓${RESET}"
CROSS="${RED}✗${RESET}"
ARROW="${BLUE}→${RESET}"
WARN="${YELLOW}⚠${RESET}"

# Flags
NON_INTERACTIVE=0
EASY_MODE=0
QUIET=0
SYSTEM_WIDE=0
NO_PATH_MODIFY=0
SKIP_AST_GREP=0
SKIP_RIPGREP=0
SKIP_JQ=0
SKIP_TYPOS=0
SKIP_HOOKS=0
INSTALL_DIR=""
FORCE_REINSTALL=0
SKIP_VERSION_CHECK=0
RUN_VERIFICATION=1
DRY_RUN=0
RUN_SELF_TEST=0

# Temporary files tracking for cleanup
TEMP_FILES=()
# Temporary working directory for this run (isolates artifacts; pruned on EXIT)
WORKDIR="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-install)"
TEMP_FILES+=("$WORKDIR")
# Lock file for concurrent execution prevention (MUST be fixed name, not $$)
LOCK_FILE="/tmp/ubs-install.lock"
# Track if we own the lock (only remove it if we created it)
LOCK_OWNED=0
LOCK_METHOD="dir"
LOCK_FD=""

dry_run_enabled() { [ "$DRY_RUN" -eq 1 ]; }

log_dry_run() {
  local message="$1"
  log "[dry-run] $message"
}

log_section() {
  local title="$1"
  echo ""
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${BLUE}   ${title}${RESET}"
  echo ""
}

print_help_option() {
  local flag="$1"
  local description="$2"
  printf "  %-24s %s\n" "$flag" "$description"
}

show_help() {
  cat <<'HELP'
Usage: install.sh [OPTIONS]

Options:
HELP
  print_help_option "--easy-mode" "Accept all prompts, install deps, and wire integrations"
  print_help_option "--non-interactive" "Skip all prompts (use defaults)"
  print_help_option "--update" "Force reinstall to latest version"
  print_help_option "--dry-run" "Log every action without modifying the system"
  print_help_option "--self-test" "Run installer smoke tests after install"
  print_help_option "--install-dir DIR" "Custom installation directory"
  print_help_option "--system" "Install to /usr/local/bin (uses sudo if needed)"
  print_help_option "--no-path-modify" "Skip shell RC edits and alias creation"
  print_help_option "--skip-ast-grep" "Skip ast-grep installation"
  print_help_option "--skip-ripgrep" "Skip ripgrep installation"
  print_help_option "--skip-jq" "Skip jq installation"
  print_help_option "--skip-typos" "Skip typos installation"
  print_help_option "--skip-hooks" "Skip hook/setup prompts"
  print_help_option "--skip-version-check" "Do not check GitHub for newer releases"
  print_help_option "--skip-verification" "Skip post-install verification banner"
  print_help_option "--quiet" "Reduce installer output"
  print_help_option "--no-color" "Disable ANSI colors"
  print_help_option "--setup-git-hook" "Only (re)install git hook"
  print_help_option "--setup-claude-hook" "Only install Claude on-save hook"
  print_help_option "--generate-config" "Create ~/.config/ubs/install.conf"
  print_help_option "--diagnose" "Print environment + dependency diagnostics"
  print_help_option "--uninstall" "Remove UBS and integrations"
  print_help_option "--help" "Show this help"
  echo ""
}

register_temp_path() {
  local path="$1"
  TEMP_FILES+=("$path")
}

mktemp_in_workdir() {
  local template="${1:-ubs.XXXXXX}"
  local path
  path="$(mktemp -p "$WORKDIR" "$template" 2>/dev/null || mktemp "${WORKDIR}/${template}")"
  register_temp_path "$path"
  echo "$path"
}

cleanup_on_exit() {
  # Clean up temporary files
  if [ ${#TEMP_FILES[@]} -gt 0 ]; then
    for temp_file in "${TEMP_FILES[@]}"; do
      rm -rf "$temp_file" 2>/dev/null || true
    done
  fi
  if [ -n "${WORKDIR:-}" ]; then
    rm -rf "$WORKDIR" 2>/dev/null || true
  fi
  release_lock
}

release_lock() {
  if [ "$LOCK_OWNED" -eq 1 ]; then
    if [ "$LOCK_METHOD" = "flock" ] && [ -n "$LOCK_FD" ]; then
      flock -u "$LOCK_FD" 2>/dev/null || true
      eval "exec ${LOCK_FD}>&-"
    else
      rmdir "$LOCK_FILE" 2>/dev/null || true
    fi
    LOCK_OWNED=0
  fi
}

acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    LOCK_METHOD="flock"
    exec {LOCK_FD}> "$LOCK_FILE"
    if flock -n "$LOCK_FD"; then
      LOCK_OWNED=1
      return 0
    else
      error "Another installation is already in progress."
      error "If this is incorrect, delete $LOCK_FILE and retry."
      exit 1
    fi
  fi

  LOCK_METHOD="dir"
  if mkdir "$LOCK_FILE" 2>/dev/null; then
    LOCK_OWNED=1
  else
    error "Another installation is already in progress."
    error "If this is incorrect, delete $LOCK_FILE and retry."
    exit 1
  fi
}

# Set up cleanup traps
trap 'cleanup_on_exit; exit 130' INT   # 130 = 128 + SIGINT (2)
trap 'cleanup_on_exit; exit 143' TERM  # 143 = 128 + SIGTERM (15)
trap cleanup_on_exit EXIT

print_header() {
  [ "$QUIET" -eq 1 ] && return 0
  echo -e "${BOLD}${BLUE}"
  cat << 'HEADER'
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     ██╗   ██╗██████╗ ███████╗    ██╗███╗   ██╗███████╗████████╗ ║
    ║     ██║   ██║██╔══██╗██╔════╝    ██║████╗  ██║██╔════╝╚══██╔══╝ ║
    ║     ██║   ██║██████╔╝███████╗    ██║██╔██╗ ██║███████╗   ██║    ║
    ║     ██║   ██║██╔══██╗╚════██║    ██║██║╚██╗██║╚════██║   ██║    ║
    ║     ╚██████╔╝██████╔╝███████║    ██║██║ ╚████║███████║   ██║    ║
    ║      ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝    ║
    ║                                                                  ║
HEADER
  echo -e "    ║         ${GREEN}🔬 ULTIMATE BUG SCANNER INSTALLER v${VERSION} 🔬${BLUE}         ║"
  cat << 'HEADER'
    ║                                                                  ║
    ║   Industrial-Grade Static Analysis for Polyglot AI Codebases    ║
    ║              Catch 1000+ Bug Patterns Before Production         ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
HEADER
  echo -e "${RESET}"
}

print_with_icon() {
  local icon="$1"
  shift || true
  local message="$*"
  if [ -z "$message" ]; then
    printf "%b\n" "$icon"
    return 0
  fi

  local prefix="$icon"
  local indent="   "
  while IFS= read -r line || [ -n "$line" ]; do
    printf "%b %s%s\n" "$prefix" "$indent" "$line"
    prefix=" "
  done <<<"$message"
}

log() { print_with_icon "${ARROW}" "$*"; }
success() { print_with_icon "${CHECK}" "$*"; }
error() { print_with_icon "${CROSS}" "$*" >&2; }
warn() { print_with_icon "${WARN}" "$*"; }

log_network_failure() {
  local context="$1"
  local err_file="$2"
  warn "$context"
  if [ -n "$err_file" ] && [ -s "$err_file" ]; then
    warn "  Last error: $(tail -n 1 "$err_file")"
  fi
}

warn_path_shadow() {
  local expected="$1"
  local actual="$2"
  warn "PATH resolves 'ubs' to $actual, but installer just wrote $expected."
  warn "Update PATH or remove old binaries so the new version is used."
}

ask() {
  local prompt="$1"
  if [ "$EASY_MODE" -eq 1 ]; then
    log "Easy mode: auto-accepting prompt -> ${prompt}"
    return 0
  fi
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    return 1  # Default to "no" in non-interactive mode
  fi
  local response
  read -p "$(echo -e "${YELLOW}?${RESET} ${prompt} (y/N): ")" response
  [[ "$response" =~ ^[Yy]$ ]]
}

with_backoff() {
  # with_backoff <max_attempts> <cmd...>
  local max="${1:-3}"; shift || true
  local n=1 delay=1
  while true; do
    if "$@"; then return 0; fi
    if (( n >= max )); then return 1; fi
    sleep "$delay"
    n=$((n+1)); delay=$((delay*2))
  done
}

maybe_sudo() { local path="$1"; if [ -w "$path" ]; then echo ""; elif can_use_sudo; then echo "sudo"; else echo ""; fi }

can_use_sudo() {
  # Check if sudo is available and can be used without password prompt
  if ! command -v sudo >/dev/null 2>&1; then
    return 1
  fi
  # Check if we can run sudo -n (non-interactive)
  if sudo -n true 2>/dev/null; then
    return 0
  fi
  # If interactive mode, we can potentially use sudo with password
  if [ "$NON_INTERACTIVE" -eq 0 ]; then
    return 0
  fi
  return 1
}

safe_timeout() {
  # Cross-platform timeout wrapper
  # Usage: safe_timeout <seconds> <command> [args...]
  # Returns: command exit code, or 124 if timeout occurred
  local timeout_duration="$1"
  shift

  # Try GNU timeout first (Linux, some BSD with coreutils)
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_duration" "$@"
    return $?
  fi

  # Try gtimeout (macOS with coreutils via brew)
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$timeout_duration" "$@"
    return $?
  fi

  # Fallback: bash-based timeout implementation for macOS/BSD
  "$@" &
  local pid=$!

  # Wait for process with timeout
  local count=0
  while kill -0 $pid 2>/dev/null; do
    if [ $count -ge "$timeout_duration" ]; then
      # Kill the process group in case the tool spawned children
      kill -TERM -$pid 2>/dev/null || kill -TERM $pid 2>/dev/null
      sleep 1
      kill -KILL -$pid 2>/dev/null || kill -KILL $pid 2>/dev/null
      wait $pid 2>/dev/null
      return 124  # Standard timeout exit code
    fi
    sleep 1
    ((count++))
  done

  # Get actual exit status
  wait $pid
  return $?
}

detect_platform() {
  local os
  os="$(uname -s)"

  # WSL detection (uname shows Linux, but /proc/version mentions Microsoft)
  if [[ "$os" == "Linux" ]] && grep -qi microsoft /proc/version 2>/dev/null; then
    echo "wsl"
    return 0
  fi

  case "$os" in
    Linux*)   echo "linux" ;;
    Darwin*)  echo "macos" ;;
    FreeBSD*) echo "freebsd" ;;
    OpenBSD*) echo "openbsd" ;;
    NetBSD*)  echo "netbsd" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)        echo "unknown" ;;
  esac
}

detect_shell() {
  if [ -n "${BASH_VERSION:-}" ]; then
    echo "bash"
  elif [ -n "${ZSH_VERSION:-}" ]; then
    echo "zsh"
  elif [[ "${SHELL:-}" == *"fish"* ]]; then
    echo "fish"
  else
    # Check default shell
    basename "$SHELL"
  fi
}

get_rc_file() {
  local shell_type
  shell_type="$(detect_shell)"
  case "$shell_type" in
    bash)
      if [ -f "$HOME/.bashrc" ]; then
        echo "$HOME/.bashrc"
      else
        echo "$HOME/.bash_profile"
      fi
      ;;
    fish)
      echo "$HOME/.config/fish/config.fish"
      ;;
    zsh)
      echo "$HOME/.zshrc"
      ;;
    *)
      echo "$HOME/.profile"
      ;;
  esac
}

check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1 || command -v sg >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

install_ast_grep() {
  local platform
  platform="$(detect_platform)"

  log "Installing ast-grep..."

  if dry_run_enabled; then
    log_dry_run "Would install ast-grep (platform $platform)."
    return 0
  fi

  local log_file
  log_file="$(mktemp_in_workdir "ast-grep-install.log.XXXXXX")"

  case "$platform" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        if brew install ast-grep 2>&1 | tee "$log_file"; then
          success "ast-grep installed via Homebrew"
          return 0
        else
          error "Homebrew installation failed. Check $log_file"
          return 1
        fi
      else
        error "Homebrew not found. Please install from: https://ast-grep.github.io/guide/quick-start.html"
        return 1
      fi
      ;;
    wsl|linux)
      if [ "$platform" = "wsl" ]; then
        log "Detected WSL environment - using Linux package managers"
      fi
      if command -v cargo >/dev/null 2>&1; then
        log "Attempting installation via cargo..."
        if cargo install ast-grep 2>&1 | tee "$log_file"; then
          success "ast-grep installed via cargo"
          return 0
        else
          warn "Cargo installation failed, trying npm..."
        fi
      fi

      if command -v npm >/dev/null 2>&1; then
        log "Attempting installation via npm..."
        if npm install -g @ast-grep/cli 2>&1 | tee "$log_file"; then
          success "ast-grep installed via npm"
          return 0
        else
          warn "npm installation failed"
        fi
      fi

      warn "Package managers failed. Trying binary download..."
      if download_binary_release "ast-grep" "$platform"; then
        return 0
      fi

      error "All installation methods failed"
      log "Download manually from: https://github.com/ast-grep/ast-grep/releases"
      return 1
      ;;
    freebsd|openbsd|netbsd)
      log "BSD platform detected: $platform"
      if command -v cargo >/dev/null 2>&1; then
        log "Attempting installation via cargo..."
        if cargo install ast-grep 2>&1 | tee "$log_file"; then
          success "ast-grep installed via cargo"
          return 0
        fi
      fi

      if command -v npm >/dev/null 2>&1; then
        log "Attempting installation via npm..."
        if npm install -g @ast-grep/cli 2>&1 | tee "$log_file"; then
          success "ast-grep installed via npm"
          return 0
        fi
      fi

      warn "Package managers failed. Trying binary download..."
      if download_binary_release "ast-grep" "$platform"; then
        return 0
      fi

      error "All installation methods failed for BSD"
      log "Download manually from: https://github.com/ast-grep/ast-grep/releases"
      return 1
      ;;
    windows)
      if command -v cargo >/dev/null 2>&1; then
        if cargo install ast-grep 2>&1 | tee "$log_file"; then
          success "ast-grep installed via cargo"
          return 0
        else
          error "Cargo installation failed"
          return 1
        fi
      else
        warn "Install Rust/Cargo or download from: https://ast-grep.github.io/"
        return 1
      fi
      ;;
    *)
      error "Unknown platform. Install manually from: https://ast-grep.github.io/"
      return 1
      ;;
  esac

  if check_ast_grep; then
    success "ast-grep installed successfully"
    return 0
  else
    error "ast-grep installation failed - command not found after install"
    return 1
  fi
}

check_ripgrep() { command -v rg >/dev/null 2>&1; }
check_jq() { command -v jq >/dev/null 2>&1; }
check_typos() { command -v typos >/dev/null 2>&1; }

# ==============================================================================
# TIER 1 ENHANCEMENTS: Version Checking, Binary Fallbacks, Verification
# ==============================================================================

version_compare() {
  # Compare two version strings using semantic versioning
  # Returns: 0 if $1 > $2, 1 if $1 <= $2
  local ver1="${1#v}"; local ver2="${2#v}"
  if [ "$ver1" = "$ver2" ]; then return 1; fi

  if echo -e "2.0\n1.0" | sort -V >/dev/null 2>&1; then
    local first
    first=$(printf '%s\n' "$ver1" "$ver2" | sort -V | head -n1)
    if [ "$first" = "$ver2" ] && [ "$ver1" != "$ver2" ]; then return 0; else return 1; fi
  fi

  # Fallback numeric-only compare: strip non-digits from components
  IFS='.' read -r -a v1 <<< "$(echo "$ver1" | sed 's/[^0-9.]/./g')"
  IFS='.' read -r -a v2 <<< "$(echo "$ver2" | sed 's/[^0-9.]/./g')"
  local n=${#v1[@]}; [ ${#v2[@]} -gt $n ] && n=${#v2[@]}
  for ((i=0;i<n;i++)); do
    local a="${v1[i]:-0}"; local b="${v2[i]:-0}"
    a=$((10#$a)); b=$((10#$b))
    if ((a>b)); then return 0; elif ((a<b)); then return 1; fi
  done
  return 1
}

check_for_updates() {
  [ "$SKIP_VERSION_CHECK" -eq 1 ] && return 0

  local current_version="$VERSION"
  local latest_url="$REPO_URL/VERSION"
  local err_log latest_file
  err_log="$(mktemp_in_workdir "update.err.XXXXXX")"
  latest_file="$(mktemp_in_workdir "version.latest.XXXXXX")"

  log "Checking for updates..."
  local latest_version
  if with_backoff 3 curl -fsSL --max-time 5 "$latest_url" -o "$latest_file" 2>"$err_log"; then
    latest_version=$(tr -d '[:space:]' < "$latest_file")
    if version_compare "$latest_version" "$current_version"; then
      warn "New version available: $latest_version (you have $current_version)"
      if ask "Update to latest version now?"; then
        log "Re-running installer with latest version..."
        release_lock
        if [ "${#ORIGINAL_ARGS[@]}" -gt 0 ]; then
          exec bash <(curl -fsSL "$REPO_URL/install.sh") "${ORIGINAL_ARGS[@]}"
        else
          exec bash <(curl -fsSL "$REPO_URL/install.sh")
        fi
        error "Failed to download or execute updated installer"
        exit 1
      fi
    else
      success "You have the latest version ($current_version)"
    fi
  else
    log_network_failure "Could not check for updates (network issue or rate limit)" "$err_log"
  fi
}

download_binary_release() {
  local tool="$1"  # ast-grep, ripgrep, or jq
  local platform="$2"
  local arch

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    armv7*) arch="armv7" ;;
    *) error "Unsupported architecture: $arch"; return 1 ;;
  esac

  local install_dir="$HOME/.local/bin"
  mkdir -p "$install_dir" 2>/dev/null || { error "Cannot create $install_dir"; return 1; }

  if dry_run_enabled; then
    log_dry_run "Would download binary for $tool ($platform-$arch)."
    return 0
  fi

  log "Attempting binary download for $tool ($platform-$arch)..."
  local err_log temp_dir
  err_log="$(mktemp_in_workdir "${tool}.download.err.XXXXXX")"
  temp_dir="$(mktemp -d -p "$WORKDIR" "${tool}.download.XXXXXX")"
  register_temp_path "$temp_dir"

  case "$tool" in
    ripgrep)
      local version="14.1.0"
      local asset tarball_dir
      case "$platform" in
        linux|wsl)
          asset="ripgrep-${version}-${arch}-unknown-linux-musl.tar.gz"
          tarball_dir="ripgrep-${version}-${arch}-unknown-linux-musl"
          ;;
        macos)
          asset="ripgrep-${version}-${arch}-apple-darwin.tar.gz"
          tarball_dir="ripgrep-${version}-${arch}-apple-darwin"
          ;;
        freebsd)
          asset="ripgrep-${version}-${arch}-unknown-freebsd.tar.gz"
          tarball_dir="ripgrep-${version}-${arch}-unknown-freebsd"
          ;;
        *) warn "No binary release for $platform"; return 1 ;;
      esac

      local url="https://github.com/BurntSushi/ripgrep/releases/download/${version}/${asset}"
      local tarball_path="$temp_dir/${asset}"

      if with_backoff 3 curl -fsSL "$url" -o "$tarball_path" 2>"$err_log"; then
        if tar -xzf "$tarball_path" -C "$temp_dir" >/dev/null 2>&1; then
          local rg_binary
          rg_binary=$(find "$temp_dir" -name "rg" -type f 2>/dev/null | head -1)
          if [ -n "$rg_binary" ] && [ -f "$rg_binary" ]; then
            chmod +x "$rg_binary" 2>/dev/null
            mv "$rg_binary" "$install_dir/rg"
            success "ripgrep binary installed to $install_dir/rg"
            return 0
          else
            warn "Could not locate rg binary in extracted archive"
          fi
        fi
      fi
      ;;

    ast-grep)
      local version="0.18.0"
      local asset
      case "$platform-$arch" in
        linux-x86_64|wsl-x86_64) asset="ast-grep-x86_64-unknown-linux-gnu.zip" ;;
        linux-aarch64|wsl-aarch64)        asset="ast-grep-aarch64-unknown-linux-gnu.zip" ;;
        macos-x86_64) asset="ast-grep-x86_64-apple-darwin.zip" ;;
        macos-aarch64) asset="ast-grep-aarch64-apple-darwin.zip" ;;
        *) warn "No binary release for $platform-$arch"; return 1 ;;
      esac

      local url="https://github.com/ast-grep/ast-grep/releases/download/${version}/${asset}"
      local zip_path="$temp_dir/${asset}"

      if with_backoff 3 curl -fsSL "$url" -o "$zip_path" 2>"$err_log"; then
        if command -v unzip >/dev/null 2>&1; then
          if unzip -q "$zip_path" -d "$temp_dir/ast-grep" 2>/dev/null; then
            local sg_binary
            sg_binary=$(find "$temp_dir/ast-grep" \( -name "ast-grep" -o -name "sg" \) -type f 2>/dev/null | head -1)
            if [ -n "$sg_binary" ] && [ -f "$sg_binary" ]; then
              chmod +x "$sg_binary" 2>/dev/null
              mv "$sg_binary" "$install_dir/ast-grep"
              success "ast-grep binary installed to $install_dir/ast-grep"
              export PATH="$install_dir:$PATH"
              return 0
            else
              warn "Could not find ast-grep binary in extracted archive"
            fi
          fi
        else
          warn "unzip not available, cannot extract ast-grep archive"
        fi
      fi
      ;;

    jq)
      local version="1.7.1"
      local asset
      case "$platform-$arch" in
        linux-x86_64|wsl-x86_64) asset="jq-linux-amd64" ;;
        linux-aarch64|wsl-aarch64) asset="jq-linux-arm64" ;;
        macos-x86_64) asset="jq-macos-amd64" ;;
        macos-aarch64) asset="jq-macos-arm64" ;;
        *) warn "No binary release for $platform-$arch"; return 1 ;;
      esac

      local url="https://github.com/jqlang/jq/releases/download/jq-${version}/${asset}"

      if with_backoff 3 curl -fsSL "$url" -o "$install_dir/jq" 2>"$err_log"; then
        chmod +x "$install_dir/jq"
        success "jq binary installed to $install_dir/jq"
        export PATH="$install_dir:$PATH"
        return 0
      fi
      ;;

    typos)
      local version="1.20.7"
      local asset type="tar"
      case "$platform-$arch" in
        linux-x86_64|wsl-x86_64)
          asset="typos-v${version}-x86_64-unknown-linux-gnu.tar.gz"
          ;;
        linux-aarch64|wsl-aarch64)
          asset="typos-v${version}-aarch64-unknown-linux-musl.tar.gz"
          ;;
        macos-x86_64)
          asset="typos-v${version}-x86_64-apple-darwin.tar.gz"
          ;;
        macos-aarch64)
          asset="typos-v${version}-aarch64-apple-darwin.tar.gz"
          ;;
        windows-x86_64)
          asset="typos-v${version}-x86_64-pc-windows-msvc.zip"
          type="zip"
          ;;
        windows-aarch64)
          asset="typos-v${version}-aarch64-pc-windows-msvc.zip"
          type="zip"
          ;;
        *)
          warn "No typos binary release available for $platform-$arch"
          return 1
          ;;
      esac

      local url="https://github.com/crate-ci/typos/releases/download/v${version}/${asset}"
      local archive="$temp_dir/${asset}"

      if with_backoff 3 curl -fsSL "$url" -o "$archive" 2>"$err_log"; then
        case "$type" in
          tar)
            if tar -xzf "$archive" -C "$temp_dir" >/dev/null 2>&1; then
              local typos_bin
              typos_bin=$(find "$temp_dir" -name typos -type f 2>/dev/null | head -1)
              if [ -n "$typos_bin" ]; then
                chmod +x "$typos_bin" 2>/dev/null
                local target="$install_dir/typos"
                [[ "$typos_bin" == *.exe ]] && target="$install_dir/typos.exe"
                mv "$typos_bin" "$target"
                success "typos binary installed to $target"
                export PATH="$install_dir:$PATH"
                return 0
              fi
            fi
            ;;
          zip)
            if command -v unzip >/dev/null 2>&1; then
              if unzip -q "$archive" -d "$temp_dir/typos" 2>/dev/null; then
                local exe
                exe=$(find "$temp_dir/typos" -name 'typos*' -type f 2>/dev/null | head -1)
                if [ -n "$exe" ]; then
                  chmod +x "$exe" 2>/dev/null || true
                  local target="$install_dir/typos"
                  [[ "$exe" == *.exe ]] && target="$install_dir/typos.exe"
                  mv "$exe" "$target"
                  success "typos binary installed to $target"
                  export PATH="$install_dir:$PATH"
                  return 0
                fi
              fi
            else
              warn "unzip not available, cannot extract typos archive"
            fi
            ;;
        esac
      fi
      ;;
  esac

  log_network_failure "Binary download failed for $tool" "$err_log"
  return 1
}


verify_installation() {
  [ "$RUN_VERIFICATION" -eq 0 ] && return 0
  if dry_run_enabled; then
    log_dry_run "Skipping post-install verification checks."
    return 0
  fi

  log_section "POST-INSTALL VERIFICATION"
  log "Running post-install verification..."
  local errors=0
  local had_ubs=0

  # Test 1: Command available
  if command -v ubs >/dev/null 2>&1; then
    success "ubs command available in PATH"
    log "   Location: $(command -v ubs)"
    had_ubs=1
  else
    error "ubs command not found in PATH"
    ((errors++))
  fi

  # Test 2: Can execute --help
  if ubs --help >/dev/null 2>&1 || ubs -h >/dev/null 2>&1; then
    success "ubs executes successfully"
  else
    error "ubs command fails to run"
    ((errors++))
  fi

  # Test 3: Dependencies
  echo ""
  log "Dependency check:"
  if check_ast_grep; then
    success "   ast-grep: $(command -v ast-grep || command -v sg)"
  else
    warn "   ast-grep: not available (scanner will use regex mode only)"
  fi

  if check_ripgrep; then
    success "   ripgrep: $(command -v rg)"
  else
    warn "   ripgrep: not available (will fallback to grep)"
  fi

  if check_jq; then
    success "   jq: $(command -v jq)"
  else
    warn "   jq: not available (JSON/SARIF merging disabled)"
  fi

  if check_typos; then
    success "   typos: $(command -v typos)"
  else
    warn "   typos: not available (spellcheck automation disabled)"
  fi

  # Test 4: Quick smoke test
  echo ""
  log "Running smoke test..."
  local test_file
  test_file="$(mktemp_in_workdir "ubs-smoke.js.XXXXXX")"
  cat > "$test_file" << 'SMOKE'
// Intentional bugs for smoke test
eval(userInput);
const x = null;
x.foo();
SMOKE

  if [ "$had_ubs" -eq 1 ] && safe_timeout 10 ubs "$test_file" --ci 2>&1 | grep -E -q "eval|null"; then
    success "Smoke test PASSED - scanner detects bugs correctly"
  else
    warn "Smoke test inconclusive - scanner may not be fully functional"
  fi

  # Test 5: Module cache directory
  echo ""
  local module_dir="${XDG_DATA_HOME:-$HOME/.local/share}/ubs/modules"
  if mkdir -p "$module_dir" 2>/dev/null && [ -w "$module_dir" ]; then
    success "Module cache directory writable: $module_dir"
  else
    warn "Module cache directory not writable - modules cannot be cached"
  fi

  # Test 6: Hooks
  echo ""
  log "Integration hooks:"
  [ -f ".git/hooks/pre-commit" ] && grep -q "ubs" ".git/hooks/pre-commit" 2>/dev/null && \
    success "   Git pre-commit hook installed" || \
    log "   Git hook: not installed"

  [ -f ".claude/hooks/on-file-write.sh" ] && \
    success "   Claude Code hook installed" || \
    log "   Claude hook: not installed"

  if [ $errors -eq 0 ]; then
    success "All verification checks passed."
    return 0
  else
    error "$errors critical verification checks failed"
    warn "Installation may be incomplete. Review errors above."
    return 1
  fi
}

run_self_tests_if_requested() {
  [ "$RUN_SELF_TEST" -eq 1 ] || return 0

  if dry_run_enabled; then
    log_dry_run "Would run installer self-test harness (--self-test)."
    return 0
  fi

  local script_dir test_script
  local -a candidates=()
  script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]:-${0}}")" 2>/dev/null && pwd || pwd)"
  candidates+=("$script_dir/test-suite/install/run_tests.sh")
  candidates+=("$PWD/test-suite/install/run_tests.sh")

  for candidate in "${candidates[@]}"; do
    if [ -f "$candidate" ]; then
      test_script="$candidate"
      break
    fi
  done

  if [ -z "${test_script:-}" ]; then
    error "--self-test requested but test-suite/install/run_tests.sh not found next to installer."
    error "Run installer from repository root or provide the test suite."
    return 1
  fi

  log_section "Installer Self-Test"
  if bash "$test_script"; then
    success "Installer self-test suite passed"
    echo ""
    return 0
  else
    error "Installer self-test suite failed"
    return 1
  fi
}

warn_if_stale_binary() {
  if dry_run_enabled; then
    log_dry_run "Would compare PATH-resolved ubs with freshly installed binary."
    return 0
  fi

  local install_dir expected actual
  install_dir="$(determine_install_dir)"
  expected="$install_dir/$INSTALL_NAME"
  actual="$(command -v ubs 2>/dev/null || true)"

  if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
    warn_path_shadow "$expected" "$actual"
  fi
}

# ==============================================================================
# TIER 2 ENHANCEMENTS: Configuration, Diagnostics, Uninstall, More AI Tools
# ==============================================================================

normalize_bool() {
  local val="$1"
  val=$(echo "$val" | tr '[:upper:]' '[:lower:]')
  case "$val" in
    1|yes|true|on|enabled|enable) echo "1" ;;
    0|no|false|off|disabled|disable|"") echo "0" ;;
    *)
      warn "Invalid boolean value '$1' in config file, treating as 0 (false)"
      echo "0"
      ;;
  esac
}

read_config_file() {
  local config_file="${XDG_CONFIG_HOME:-$HOME/.config}/ubs/install.conf"

  if [ ! -f "$config_file" ]; then
    return 0
  fi

  log "Reading configuration from $config_file..."

  while IFS='=' read -r key value; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$key" ]] && continue

    key=$(echo "$key" | tr -d '[:space:]')
    value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    case "$key" in
      install_dir)
        INSTALL_DIR="$value"
        ;;
      skip_ast_grep)
        SKIP_AST_GREP="$(normalize_bool "$value")"
        ;;
      skip_ripgrep)
        SKIP_RIPGREP="$(normalize_bool "$value")"
        ;;
      skip_jq)
        SKIP_JQ="$(normalize_bool "$value")"
        ;;
      skip_typos)
        SKIP_TYPOS="$(normalize_bool "$value")"
        ;;
      skip_hooks)
        SKIP_HOOKS="$(normalize_bool "$value")"
        ;;
      skip_version_check)
        SKIP_VERSION_CHECK="$(normalize_bool "$value")"
        ;;
      dry_run)
        DRY_RUN="$(normalize_bool "$value")"
        ;;
      self_test)
        RUN_SELF_TEST="$(normalize_bool "$value")"
        ;;
      easy_mode)
        local normalized="$(normalize_bool "$value")"
        EASY_MODE="$normalized"
        NON_INTERACTIVE="$normalized"
        ;;
      non_interactive)
        NON_INTERACTIVE="$(normalize_bool "$value")"
        ;;
      *)
        warn "Unknown config key '$key' in $config_file (ignored)"
        ;;
    esac
  done < "$config_file"

  success "Loaded configuration from $config_file"
}

generate_config() {
  local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/ubs"
  local config_file="$config_dir/install.conf"

  mkdir -p "$config_dir" 2>/dev/null || {
    error "Cannot create config directory: $config_dir"
    return 1
  }

  if [ -f "$config_file" ]; then
    warn "Config file already exists: $config_file"
    if ! ask "Overwrite existing configuration?"; then
      log "Keeping existing configuration"
      return 0
    fi
    cp "$config_file" "${config_file}.backup"
    log "Backed up existing config to ${config_file}.backup"
  fi

  cat > "$config_file" << 'CONFIG'
# Ultimate Bug Scanner Installation Configuration
# This file controls default behavior of install.sh
# Values: 0 = false/no, 1 = true/yes

# Installation directory (default: auto-detect ~/.local/bin or /usr/local/bin)
# Uncomment and set to customize:
# install_dir=/usr/local/bin

# Skip dependency installations (1=skip, 0=install if missing)
skip_ast_grep=0
skip_ripgrep=0
skip_jq=0
skip_typos=0

# Skip version checking on install
skip_version_check=0

# Dry-run mode (1 = log actions only, 0 = perform actions)
dry_run=0

# Run extended self-test after install
self_test=0

# Skip hook/integration setup (1=skip, 0=prompt or install in easy mode)
skip_hooks=0

# Easy mode: auto-accept all prompts and install everything (1=yes, 0=no)
easy_mode=0

# Non-interactive mode: skip all prompts, use defaults (1=yes, 0=no)
non_interactive=0
CONFIG

  success "Created configuration file: $config_file"
  log "Edit this file to customize future installations"
  log "Settings in this file will be used as defaults"

  if ask "Open config file in editor now?"; then
    local editor="${EDITOR:-${VISUAL:-nano}}"
    if command -v "$editor" >/dev/null 2>&1; then
      "$editor" "$config_file"
    else
      log "Set \$EDITOR environment variable to use your preferred editor"
      log "File location: $config_file"
    fi
  fi

  return 0
}

diagnostic_check() {
  log_section "ULTIMATE BUG SCANNER DIAGNOSTIC REPORT"

  # System info
  echo -e "${BOLD}System Information:${RESET}"
  command -v lsb_release >/dev/null 2>&1 && echo "  Distro: $(lsb_release -ds 2>/dev/null || true)"
  echo "  OS: $(uname -s) $(uname -r)"
  echo "  Platform: $(detect_platform)"
  echo "  Architecture: $(uname -m)"
  echo "  Shell: $(detect_shell) ($SHELL)"
  echo "  Bash Version: $BASH_VERSION"
  echo ""

  # UBS installation
  echo -e "${BOLD}UBS Installation:${RESET}"
  if command -v ubs >/dev/null 2>&1; then
    success "  ubs command available"
    echo "  Location: $(command -v ubs)"

    local ubs_version
    if ubs_version=$(ubs --version 2>/dev/null | head -n1); then
      echo "  Version: $ubs_version"
    elif ubs --help 2>&1 | head -n5 | grep -i version >/dev/null; then
      echo "  Version: $(ubs --help 2>&1 | grep -i version | head -n1)"
    else
      echo "  Version: unknown"
    fi

    if safe_timeout 5 ubs --help >/dev/null 2>&1; then
      success "  ubs runs successfully"
    else
      error "  ubs fails to execute"
    fi
  else
    error "  ubs command not found"
  fi
  echo ""

  # Dependencies
  echo -e "${BOLD}Dependencies:${RESET}"
  for dep in ast-grep sg rg jq; do
    if command -v "$dep" >/dev/null 2>&1; then
      success "  $dep: $(command -v $dep)"
    else
      warn "  $dep: not found"
    fi
  done
  echo ""

  # PATH analysis
  echo -e "${BOLD}PATH Entries (relevant):${RESET}"
  local IFS=':'
  for p in $PATH; do
    if [[ "$p" == *".local/bin"* ]] || [[ "$p" == *"/usr/local/bin"* ]] || [[ "$p" == *"ubs"* ]]; then
      if [ -d "$p" ]; then
        echo "  ✓ $p"
      else
        warn "  ✗ $p (directory doesn't exist)"
      fi
    fi
  done
  echo ""

  # Integration Hooks
  echo -e "${BOLD}Integration Hooks:${RESET}"
  [ -f ".git/hooks/pre-commit" ] && grep -q "ubs" ".git/hooks/pre-commit" 2>/dev/null && \
    success "  Git pre-commit hook installed" || \
    log "  Git hook: not installed"

  [ -f ".claude/hooks/on-file-write.sh" ] && \
    success "  Claude Code hook installed" || \
    log "  Claude hook: not installed"

  [ -f ".cursor/rules" ] && grep -q "Ultimate Bug Scanner" ".cursor/rules" 2>/dev/null && \
    success "  Cursor rules configured" || \
    log "  Cursor: not configured"

  [ -f ".codex/rules" ] && grep -q "Ultimate Bug Scanner" ".codex/rules" 2>/dev/null && \
    success "  Codex CLI rules configured" || \
    log "  Codex: not configured"

  [ -f ".gemini/rules" ] && grep -q "Ultimate Bug Scanner" ".gemini/rules" 2>/dev/null && \
    success "  Gemini rules configured" || \
    log "  Gemini: not configured"

  echo ""

  # Module cache
  local module_dir="${XDG_DATA_HOME:-$HOME/.local/share}/ubs/modules"
  echo -e "${BOLD}Module Cache:${RESET}"
  if [ -d "$module_dir" ]; then
    echo "  Location: $module_dir"
    if [ "$(ls -1 "$module_dir" 2>/dev/null | wc -l)" -gt 0 ]; then
      echo "  Cached modules:"
      ls -1 "$module_dir" 2>/dev/null | sed 's/^/    - /'
    else
      log "  (No modules cached yet)"
    fi
  else
    log "  Module directory not created yet"
    if mkdir -p "$module_dir" 2>/dev/null; then
      success "  Created module directory: $module_dir"
    else
      warn "  Cannot create module directory"
    fi
  fi
  echo ""

  # Test network connectivity
  echo -e "${BOLD}Network Connectivity:${RESET}"
  if safe_timeout 5 curl -fsSL --max-time 5 "https://api.github.com" >/dev/null 2>&1; then
    success "  Can reach GitHub API"
  else
    warn "  Cannot reach GitHub (check network/firewall)"
  fi
  echo ""

  # Permissions
  echo -e "${BOLD}Permissions:${RESET}"
  local install_dir="$(determine_install_dir)"
  if [ -w "$install_dir" ]; then
    success "  Install directory writable: $install_dir"
  else
    warn "  Install directory not writable: $install_dir"
  fi

  local rc_file="$(get_rc_file)"
  if [ -w "$rc_file" ]; then
    success "  RC file writable: $rc_file"
  else
    warn "  RC file not writable: $rc_file"
  fi
  echo ""

  # Configuration
  local config_file="${XDG_CONFIG_HOME:-$HOME/.config}/ubs/install.conf"
  echo -e "${BOLD}Configuration:${RESET}"
  if [ -f "$config_file" ]; then
    success "  Config file exists: $config_file"
  else
    log "  No config file (run with --generate-config to create)"
  fi
  echo ""

  echo ""
  echo -e "${BOLD}💡 To share this diagnostic report:${RESET}"
  echo "   Run: curl -fsSL ... | bash -s -- --diagnose > ubs-diagnostic.txt"
  echo "   Then attach ubs-diagnostic.txt to your issue report"
  echo ""
}

uninstall_ubs() {
  log_section "Uninstall Ultimate Bug Scanner"

  warn "This will remove Ultimate Bug Scanner and all integrations"
  if ! ask "Continue with uninstall?"; then
    log "Uninstall cancelled"
    return 0
  fi

  log "Uninstalling Ultimate Bug Scanner..."
  echo ""

  # Remove binary
  local install_dir="$(determine_install_dir)"
  local script_path="$install_dir/$INSTALL_NAME"

  if [ -f "$script_path" ]; then
    rm -f "$script_path"
    success "Removed binary: $script_path"
  else
    log "Binary not found at: $script_path"
  fi

  # Remove from PATH (restore RC file)
  local rc_file="$(get_rc_file)"
  if [ -f "$rc_file" ]; then
    if grep -q "Ultimate Bug Scanner" "$rc_file" 2>/dev/null; then
      cp "$rc_file" "${rc_file}.pre-uninstall-backup"
      log "Backed up $rc_file to ${rc_file}.pre-uninstall-backup"

      # Remove PATH and alias/function entries
      sed -i.bak '/# Ultimate Bug Scanner.*added/,+1d' "$rc_file" 2>/dev/null || true
      sed -i.bak '/# Ultimate Bug Scanner alias/,+1d' "$rc_file" 2>/dev/null || true
      rm -f "${rc_file}.bak" 2>/dev/null || true
      # Remove blank lines
      sed -i.bak '/^$/N;/^\n$/d' "$rc_file" 2>/dev/null && rm -f "${rc_file}.bak" 2>/dev/null || true
      success "Removed from $rc_file"
    fi
  fi

  # Remove hooks
  echo ""
  if ask "Remove git hooks?"; then
    if [ -f ".git/hooks/pre-commit" ] && grep -q "Ultimate Bug Scanner" ".git/hooks/pre-commit" 2>/dev/null; then
      if [ -f ".git/hooks/pre-commit.backup" ]; then
        mv ".git/hooks/pre-commit.backup" ".git/hooks/pre-commit"
        success "Restored backup git hook"
      else
        rm -f ".git/hooks/pre-commit"
        success "Removed git hook"
      fi
    fi
  fi

  if ask "Remove Claude Code hook?"; then
    if [ -f ".claude/hooks/on-file-write.sh" ]; then
      rm -f ".claude/hooks/on-file-write.sh"
      success "Removed Claude hook"
    fi
  fi

  if ask "Remove AI agent guardrails (.cursor/rules, etc.)?"; then
    for dir in .cursor .codex .gemini .windsurf .cline .opencode; do
      if [ -f "$dir/rules" ] && grep -q "Ultimate Bug Scanner" "$dir/rules" 2>/dev/null; then
        sed -i.bak '/# >>> Ultimate Bug Scanner/,/# <<< End Ultimate Bug Scanner/d' "$dir/rules" 2>/dev/null
        rm -f "$dir/rules.bak"
        success "Removed guardrails from $dir/rules"
      fi
    done
  fi

  echo ""
  if ask "Remove cached modules?"; then
    local module_dir="${XDG_DATA_HOME:-$HOME/.local/share}/ubs"
    if [ -d "$module_dir" ]; then
      rm -rf "$module_dir"
      success "Removed module cache: $module_dir"
    fi
  fi

  if ask "Remove configuration file?"; then
    local config_file="${XDG_CONFIG_HOME:-$HOME/.config}/ubs/install.conf"
    if [ -f "$config_file" ]; then
      rm -f "$config_file"
      success "Removed config file: $config_file"
    fi
  fi

  echo ""
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${GREEN}   UNINSTALL COMPLETE${RESET}"
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${RESET}"
  echo ""
  success "Ultimate Bug Scanner has been uninstalled"
  log "To reinstall: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash"
  echo ""
}

install_jq() {
  local platform log_file
  platform="$(detect_platform)"
  log "Installing jq..."

  if dry_run_enabled; then
    log_dry_run "Would install jq (platform $platform)."
    return 0
  fi

  log_file="$(mktemp_in_workdir "jq-install.log.XXXXXX")"

  case "$platform" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        if brew install jq 2>&1 | tee "$log_file"; then
          success "jq installed via Homebrew"; return 0
        else
          error "Homebrew installation failed. See $log_file"; return 1
        fi
      else
        error "Homebrew not found. Install jq manually."; return 1
      fi
      ;;
    wsl|linux)
      if [ "$platform" = "wsl" ]; then
        log "Detected WSL environment - using Linux package managers"
      fi
      if command -v apt-get >/dev/null 2>&1 && can_use_sudo; then
        if safe_timeout 300 sudo apt-get update -qq && ( safe_timeout 300 sudo apt-get install -y jq ) 2>&1 | tee "$log_file"; then
          success "jq installed via apt-get"; return 0
        fi
      fi
      if command -v dnf >/dev/null 2>&1 && can_use_sudo; then
        if safe_timeout 300 sudo dnf install -y jq 2>&1 | tee "$log_file"; then
          success "jq installed via dnf"; return 0
        fi
      fi
      if command -v pacman >/dev/null 2>&1 && can_use_sudo; then
        if safe_timeout 300 sudo pacman -S --noconfirm jq 2>&1 | tee "$log_file"; then
          success "jq installed via pacman"; return 0
        fi
      fi
      if command -v snap >/dev/null 2>&1 && can_use_sudo; then
        if safe_timeout 300 sudo snap install jq 2>&1 | tee "$log_file"; then
          success "jq installed via snap"; return 0
        fi
      fi
      warn "Package managers failed. Trying binary download..."
      if download_binary_release "jq" "$platform"; then
        return 0
      fi
      error "All installation methods failed"
      log "Download manually from: https://stedolan.github.io/jq/"
      return 1
      ;;
    freebsd|openbsd|netbsd)
      log "BSD platform detected: $platform"
      if command -v pkg >/dev/null 2>&1 && can_use_sudo; then
        if safe_timeout 300 sudo pkg install -y jq 2>&1 | tee "$log_file"; then
          success "jq installed via pkg"; return 0
        fi
      fi
      if command -v pkg_add >/dev/null 2>&1 && can_use_sudo; then
        if safe_timeout 300 sudo pkg_add jq 2>&1 | tee "$log_file"; then
          success "jq installed via pkg_add"; return 0
        fi
      fi
      warn "Package managers failed. Trying binary download..."
      if download_binary_release "jq" "$platform"; then
        return 0
      fi
      error "All installation methods failed for BSD"
      log "Download manually from: https://stedolan.github.io/jq/"
      return 1
      ;;
    windows)
      warn "Install jq with scoop/choco or your preferred package manager"
      return 1
      ;;
    *)
      error "Unknown platform for jq install"; return 1
      ;;
  esac
}

install_ripgrep() {
  local platform log_file
  platform="$(detect_platform)"

  log "Installing ripgrep..."

  if dry_run_enabled; then
    log_dry_run "Would install ripgrep (platform $platform)."
    return 0
  fi

  log_file="$(mktemp_in_workdir "ripgrep-install.log.XXXXXX")"

  case "$platform" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        if brew install ripgrep 2>&1 | tee "$log_file"; then
          success "ripgrep installed via Homebrew"
          return 0
        else
          error "Homebrew installation failed. Check $log_file"
          return 1
        fi
      else
        error "Homebrew not found. Please install from: https://github.com/BurntSushi/ripgrep#installation"
        return 1
      fi
      ;;
    wsl|linux)
      if [ "$platform" = "wsl" ]; then
        log "Detected WSL environment - using Linux package managers"
      fi
      if command -v cargo >/dev/null 2>&1; then
        log "Attempting installation via cargo..."
        if cargo install ripgrep 2>&1 | tee "$log_file"; then
          success "ripgrep installed via cargo"
          return 0
        else
          warn "Cargo installation failed, trying system package managers..."
        fi
      fi

      if command -v apt-get >/dev/null 2>&1; then
        if can_use_sudo; then
          log "Attempting installation via apt-get..."
          if safe_timeout 300 sudo apt-get update -qq && safe_timeout 300 sudo apt-get install -y ripgrep 2>&1 | tee "$log_file"; then
            success "ripgrep installed via apt-get"
            return 0
          else
            warn "apt-get installation failed, trying next method..."
          fi
        else
          warn "sudo not available or not configured, skipping apt-get..."
        fi
      fi

      if command -v dnf >/dev/null 2>&1; then
        if can_use_sudo; then
          log "Attempting installation via dnf..."
          if safe_timeout 300 sudo dnf install -y ripgrep 2>&1 | tee "$log_file"; then
            success "ripgrep installed via dnf"
            return 0
          else
            warn "dnf installation failed, trying next method..."
          fi
        else
          warn "sudo not available, skipping dnf..."
        fi
      fi

      if command -v pacman >/dev/null 2>&1; then
        if can_use_sudo; then
          log "Attempting installation via pacman..."
          if safe_timeout 300 sudo pacman -S --noconfirm ripgrep 2>&1 | tee "$log_file"; then
            success "ripgrep installed via pacman"
            return 0
          else
            warn "pacman installation failed, trying next method..."
          fi
        else
          warn "sudo not available, skipping pacman..."
        fi
      fi

      if command -v snap >/dev/null 2>&1; then
        if can_use_sudo; then
          log "Attempting installation via snap..."
          if safe_timeout 300 sudo snap install ripgrep --classic 2>&1 | tee "$log_file"; then
            success "ripgrep installed via snap"
            return 0
          else
            warn "snap installation failed"
          fi
        else
          warn "sudo not available, skipping snap..."
        fi
      fi

      warn "All package managers failed. Trying binary download..."
      if download_binary_release "ripgrep" "$platform"; then
        return 0
      fi

      error "All installation methods failed"
      log "Download manually from: https://github.com/BurntSushi/ripgrep/releases"
      return 1
      ;;
    freebsd|openbsd|netbsd)
      log "BSD platform detected: $platform"
      if command -v pkg >/dev/null 2>&1; then
        if can_use_sudo; then
          log "Attempting installation via pkg..."
          if safe_timeout 300 sudo pkg install -y ripgrep 2>&1 | tee "$log_file"; then
            success "ripgrep installed via pkg"
            return 0
          fi
        fi
      fi

      if command -v pkg_add >/dev/null 2>&1; then
        if can_use_sudo; then
          log "Attempting installation via pkg_add..."
          if safe_timeout 300 sudo pkg_add ripgrep 2>&1 | tee "$log_file"; then
            success "ripgrep installed via pkg_add"
            return 0
          fi
        fi
      fi

      warn "Package managers failed. Trying binary download..."
      if download_binary_release "ripgrep" "$platform"; then
        return 0
      fi
      error "All installation methods failed for BSD"
      log "Download manually from: https://github.com/BurntSushi/ripgrep/releases"
      return 1
      ;;
    windows)
      if command -v cargo >/dev/null 2>&1; then
        log "Attempting installation via cargo..."
        if cargo install ripgrep 2>&1 | tee "$log_file"; then
          success "ripgrep installed via cargo"
          return 0
        else
          warn "Cargo installation failed, trying Windows package managers..."
        fi
      fi

      if command -v scoop >/dev/null 2>&1; then
        log "Attempting installation via scoop..."
        if scoop install ripgrep 2>&1 | tee "$log_file"; then
          success "ripgrep installed via scoop"
          return 0
        else
          warn "scoop installation failed, trying choco..."
        fi
      fi

      if command -v choco >/dev/null 2>&1; then
        log "Attempting installation via chocolatey..."
        if choco install ripgrep 2>&1 | tee "$log_file"; then
          success "ripgrep installed via chocolatey"
          return 0
        else
          warn "chocolatey installation failed"
        fi
      fi

      warn "Install Rust/Cargo, Scoop, or Chocolatey"
      log "Download from: https://github.com/BurntSushi/ripgrep/releases"
      return 1
      ;;
    *)
      error "Unknown platform. Install manually from: https://github.com/BurntSushi/ripgrep#installation"
      return 1
      ;;
  esac

  if check_ripgrep; then
    success "ripgrep installed successfully"
    return 0
  else
    error "ripgrep installation failed - command not found after install"
    return 1
  fi
}

install_typos() {
  local platform log_file
  platform="$(detect_platform)"

  log "Installing typos (code-aware spellchecker)..."

  if dry_run_enabled; then
    log_dry_run "Would install typos (platform $platform)."
    return 0
  fi

  log_file="$(mktemp_in_workdir "typos-install.log.XXXXXX")"

  case "$platform" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        if brew install typos-cli 2>&1 | tee "$log_file"; then
          success "typos installed via Homebrew"
          return 0
        else
          warn "Homebrew installation failed"
        fi
      fi
      ;;
    wsl|linux)
      if [ "$platform" = "wsl" ]; then
        log "Detected WSL environment - treating as Linux"
      fi
      ;;
    windows)
      ;;
  esac

  if command -v cargo >/dev/null 2>&1; then
    log "Attempting installation via cargo..."
    if cargo install typos-cli 2>&1 | tee "$log_file"; then
      success "typos installed via cargo"
      return 0
    else
      warn "cargo installation failed"
    fi
  fi

  if download_binary_release "typos" "$platform"; then
    return 0
  fi

  error "All typos installation methods failed"
  warn "Install manually from https://github.com/crate-ci/typos or your package manager"
  return 1
}

validate_install_dir() {
  local dir="$1"
  case "$dir" in
    /|/bin|/sbin|/usr/bin|/usr/sbin|/boot|/dev|/proc|/sys)
      error "Refusing to install to system directory: $dir"
      return 1
      ;;
    /*/../*|*/..|../*|*/../*)
      error "Invalid path (contains ..): $dir"
      return 1
      ;;
    ""|" "*|*" "*)
      error "Invalid path (empty or contains spaces): $dir"
      return 1
      ;;
  esac
  if [[ "$dir" != /* ]]; then
    error "Installation directory must be an absolute path: $dir"
    return 1
  fi
  return 0
}

determine_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    if ! validate_install_dir "$INSTALL_DIR"; then
      error "Invalid installation directory: $INSTALL_DIR"
      exit 1
    fi
    echo "$INSTALL_DIR"
    return
  fi

  if [ "$SYSTEM_WIDE" -eq 1 ]; then
    echo "/usr/local/bin"; return
  fi

  if [ -d "$HOME/.local/bin" ] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
    echo "$HOME/.local/bin"
  elif [ -w "/usr/local/bin" ]; then
    echo "/usr/local/bin"
  else
    echo "$HOME/.local/bin"
  fi
}

install_scanner() {
  local install_dir
  install_dir="$(determine_install_dir)"
  local use_sudo=""
  use_sudo="$(maybe_sudo "$install_dir")"

  log "Installing Ultimate Bug Scanner to $install_dir..."

  if dry_run_enabled; then
    log_dry_run "Would create $install_dir, download $SCRIPT_NAME, and install as $install_dir/$INSTALL_NAME."
    return 0
  fi

  # Create directory if needed
  if [ -n "$use_sudo" ]; then
    $use_sudo mkdir -p "$install_dir" 2>/dev/null || true
  else
    mkdir -p "$install_dir" 2>/dev/null || true
  fi
  [ -d "$install_dir" ] || {
    error "Cannot create directory: $install_dir"
    return 1
  }

  # Download or copy script
  local script_path="$install_dir/$INSTALL_NAME"
  local temp_path="${script_path}.tmp"
  register_temp_path "$temp_path"

  local download_err
  download_err="$(mktemp_in_workdir "download-error.log.XXXXXX")"

  download_to_file() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
      with_backoff 3 curl -fsSL "$url" -o "$out" 2>"$download_err"
    else
      with_backoff 3 wget -q "$url" -O "$out" 2>"$download_err"
    fi
  }

  if [ -f "./$SCRIPT_NAME" ]; then
    log "Installing from local file..."
    if cp "./$SCRIPT_NAME" "$temp_path" 2>/dev/null; then
      if head -n 1 "$temp_path" | grep -q '^#!/.*bash'; then
        :
      else
        error "Local file doesn't appear to be a bash script"
        rm -f "$temp_path"
        return 1
      fi
    else
      error "Failed to copy local file"
      return 1
    fi
  else
    log "Downloading from GitHub..."
    local download_url="${REPO_URL}/${SCRIPT_NAME}"

    if download_to_file "$download_url" "$temp_path"; then
      log "Downloaded successfully"
    else
      error "Download failed. Check $download_err"
      rm -f "$temp_path"
      return 1
    fi
  fi

  if [ ! -s "$temp_path" ]; then
    error "Downloaded file is empty"
    rm -f "$temp_path"
    return 1
  fi

  local file_size
  file_size=$(wc -c < "$temp_path" 2>/dev/null || echo "0")
  if [ "$file_size" -lt 2048 ]; then
    warn "Downloaded file unusually small ($file_size bytes) - continuing cautiously"
  fi

  local first_line
  first_line=$(head -n 1 "$temp_path" | sed 's/^\o357\o273\o277//' | tr -d '\r\n\t ' | head -c 50)
  if [[ ! "$first_line" =~ ^#!.*bash ]]; then
    error "Downloaded file doesn't appear to be a bash script"
    log "First line: $(head -n 1 "$temp_path" | cat -v)"
    rm -f "$temp_path"
    return 1
  fi

  if ! grep -E -q "UBS Meta-Runner|Ultimate Bug Scanner" "$temp_path"; then
    warn "Downloaded file does not contain expected marker; continuing (marker may have changed)"
  fi

  if [ -n "$use_sudo" ]; then
    $use_sudo install -m 0755 "$temp_path" "$script_path"
    rm -f "$temp_path"
  else
    mv "$temp_path" "$script_path"
    chmod 0755 "$script_path" 2>/dev/null || true
  fi

  if [ -n "$use_sudo" ]; then
    $use_sudo chmod +x "$script_path" 2>/dev/null || true
  else
    chmod +x "$script_path" 2>/dev/null || true
  fi
  if [ ! -x "$script_path" ]; then
    error "Failed to make script executable"
    return 1
  fi

  if [ -x "$script_path" ] && [ -s "$script_path" ]; then
    success "Installed to: $script_path"
    if "$script_path" --help >/dev/null 2>&1 || "$script_path" -h >/dev/null 2>&1; then
      success "Installation verified - script is functional"
      return 0
    else
      warn "Script installed but may not be fully functional"
      return 0
    fi
  else
    error "Installation failed - file not executable or empty"
    return 1
  fi
}

is_in_path() {
  local dir="$1"
  local normalized_dir
  if command -v realpath >/dev/null 2>&1; then
    normalized_dir=$(realpath -s "$dir" 2>/dev/null || echo "$dir")
  else
    normalized_dir="${dir%/}"
  fi
  local IFS=':'
  for path_entry in $PATH; do
    local normalized_entry
    if command -v realpath >/dev/null 2>&1; then
      normalized_entry=$(realpath -s "$path_entry" 2>/dev/null || echo "$path_entry")
    else
      normalized_entry="${path_entry%/}"
    fi
    if [ "$normalized_dir" = "$normalized_entry" ]; then
      return 0
    fi
  done
  return 1
}

add_to_path() {
  local install_dir
  install_dir="$(determine_install_dir)"
  [ "$NO_PATH_MODIFY" -eq 1 ] && { log "Skipping PATH modification (per flag)"; return 0; }

  local rc_file
  rc_file="$(get_rc_file)"
  local shell_type="$(detect_shell)"

  if dry_run_enabled; then
    log_dry_run "Would update PATH in $rc_file for $install_dir."
    return 0
  fi

  if is_in_path "$install_dir"; then
    log "Directory already in PATH"
    return 0
  fi

  if [ ! -w "$rc_file" ] && [ ! -w "$(dirname "$rc_file")" ]; then
    error "Cannot write to $rc_file - check permissions"
    return 1
  fi

  log "Adding $install_dir to PATH in $rc_file..."

  if [ "$shell_type" = "fish" ]; then
    if ! grep -qF "set -gx PATH \$PATH $install_dir" "$rc_file" 2>/dev/null; then
      {
        echo ""
        echo "# Ultimate Bug Scanner (added $(date +%Y-%m-%d))"
        echo "set -gx PATH \$PATH $install_dir"
      } >> "$rc_file"
      success "Added to PATH in $rc_file (fish)"
    else
      log "PATH entry already exists in $rc_file (fish)"
    fi
  else
    if grep -qF "PATH=\"\$PATH:$install_dir\"" "$rc_file" 2>/dev/null || \
       grep -qF "PATH=\$PATH:$install_dir" "$rc_file" 2>/dev/null || \
       grep -qF "PATH=\"$install_dir:\$PATH\"" "$rc_file" 2>/dev/null || \
       grep -qF "PATH=$install_dir:\$PATH" "$rc_file" 2>/dev/null; then
      log "PATH entry already exists in $rc_file"
    else
      {
        echo ""
        echo "# Ultimate Bug Scanner (added $(date +%Y-%m-%d))"
        echo "export PATH=\"\$PATH:$install_dir\""
      } >> "$rc_file"
      success "Added to PATH in $rc_file"
    fi
  fi

  warn "⚠ IMPORTANT: Restart your shell or run: source $rc_file"
  return 0
}

create_alias() {
  local install_dir
  install_dir="$(determine_install_dir)"
  local script_path="$install_dir/$INSTALL_NAME"
  local shell_type
  shell_type="$(detect_shell)"

  local rc_file
  rc_file="$(get_rc_file)"

  log "Configuring 'ubs' command..."

  if dry_run_enabled; then
    log_dry_run "Would add alias/function for 'ubs' in $rc_file pointing to $script_path."
    return 0
  fi

  if command -v ubs >/dev/null 2>&1; then
    success "'ubs' command is already available"
    return 0
  fi

  if [ "$shell_type" = "fish" ]; then
    if ! grep -qF "function ubs" "$rc_file" 2>/dev/null; then
      {
        echo ""
        echo "# Ultimate Bug Scanner alias"
        echo "function ubs"
        echo "  $script_path \$argv"
        echo "end"
      } >> "$rc_file"
      success "Created 'ubs' function (fish) pointing to: $script_path"
    else
      log "Fish function 'ubs' already defined"
    fi
  else
    if grep -qF "alias ubs=" "$rc_file" 2>/dev/null; then
      log "Alias already exists, verifying..."
      if grep -qF "alias ubs='$script_path'" "$rc_file" 2>/dev/null || \
         grep -qF "alias ubs=\"$script_path\"" "$rc_file" 2>/dev/null; then
        log "Existing alias is correct"
        return 0
      else
        warn "Existing alias points to different location, updating..."
        sed -i.bak "/alias ubs=/d" "$rc_file" 2>/dev/null && rm -f "${rc_file}.bak" || {
          warn "Could not update existing alias - you may need to manually remove it"
        }
      fi
    fi

    echo "" >> "$rc_file"
    echo "# Ultimate Bug Scanner alias" >> "$rc_file"
    echo "alias ubs='$script_path'" >> "$rc_file"
    success "Created 'ubs' alias pointing to: $script_path"
  fi

  log "Restart your shell or run: source $rc_file"
}

setup_claude_code_hook() {
  if dry_run_enabled; then
    log_dry_run "Would configure Claude Code hook at .claude/hooks/on-file-write.sh."
    return 0
  fi
  if [ ! -d ".claude" ]; then
    mkdir -p ".claude"
    log "Created .claude directory for Claude Code integration."
  fi
  log "Setting up Claude Code hook..."

  local hook_dir=".claude/hooks"
  local hook_file="$hook_dir/on-file-write.sh"

  mkdir -p "$hook_dir"

  cat > "$hook_file" << 'HOOK_EOF'
#!/bin/bash
# Ultimate Bug Scanner - Claude Code Hook
# Runs on every file save for UBS-supported languages (JS/TS, Python, C/C++, Rust, Go, Java, Ruby)

if [[ "$FILE_PATH" =~ \.(js|jsx|ts|tsx|mjs|cjs|py|pyw|pyi|c|cc|cpp|cxx|h|hh|hpp|hxx|rs|go|java|rb)$ ]]; then
  echo "🔬 Running bug scanner..."
  if ! command -v ubs >/dev/null 2>&1; then
    echo "⚠️  'ubs' not found in PATH; install it before using this hook." >&2
    exit 0
  fi
  ubs "${PROJECT_DIR}" --ci 2>&1 | head -50
fi
HOOK_EOF

  chmod +x "$hook_file"
  success "Claude Code hook created: $hook_file"
}

append_agent_rule_block() {
  local agent_dir="$1"
  local friendly_name="$2"
  local file="$agent_dir/rules"
  local marker="Ultimate Bug Scanner Integration"

  if dry_run_enabled; then
    log_dry_run "Would update $file with $friendly_name guardrails."
    return 0
  fi

  mkdir -p "$agent_dir"
  if [ -f "$file" ] && grep -q "$marker" "$file"; then
    log "$friendly_name instructions already present at $file"
    return 0
  fi

  cat >> "$file" <<'RULE'
# >>> Ultimate Bug Scanner Integration
# Always run the unified scanner before finalizing work:
#   1. Execute: ubs --fail-on-warning .
#   2. Review and fix any findings (critical + warning) before marking a task complete.
#   3. Mention outstanding issues in your response if they remain.
# This keeps AI coding agents honest about quality.
# <<< End Ultimate Bug Scanner Integration

RULE
  success "Added $friendly_name quality instructions at $file"
}

setup_cursor_rules() { append_agent_rule_block ".cursor" "Cursor"; }
setup_codex_rules() { append_agent_rule_block ".codex" "Codex CLI"; }
setup_gemini_rules() { append_agent_rule_block ".gemini" "Gemini Code Assist"; }
setup_windsurf_rules() { append_agent_rule_block ".windsurf" "Windsurf"; }
setup_cline_rules()  { append_agent_rule_block ".cline"  "Cline"; }
setup_opencode_rules(){ append_agent_rule_block ".opencode" "OpenCode"; }

setup_aider_rules() {
  local aider_conf="${HOME}/.aider.conf.yml"

  log "Setting up Aider integration..."

  if dry_run_enabled; then
    log_dry_run "Would update $aider_conf for Aider integration."
    return 0
  fi

  if [ ! -f "$aider_conf" ]; then
    cat > "$aider_conf" << 'AIDER'
# Aider configuration with UBS integration
lint-cmd: "ubs --fail-on-warning ."
auto-lint: true
AIDER
    success "Created Aider config with UBS integration: $aider_conf"
  else
    if ! grep -q "ubs" "$aider_conf" 2>/dev/null; then
      echo "" >> "$aider_conf"
      echo "# Ultimate Bug Scanner integration" >> "$aider_conf"
      echo "lint-cmd: \"ubs --fail-on-warning .\"" >> "$aider_conf"
      echo "auto-lint: true" >> "$aider_conf"
      success "Added UBS to Aider config: $aider_conf"
    else
      log "Aider already configured with UBS"
    fi
  fi
}

setup_continue_rules() {
  local continue_dir=".continue"
  if dry_run_enabled; then
    log_dry_run "Would configure Continue integration at $continue_dir/config.json."
    return 0
  fi
  mkdir -p "$continue_dir"

  log "Setting up Continue integration..."

  local config="$continue_dir/config.json"
  if [ ! -f "$config" ]; then
    cat > "$config" << 'CONTINUE'
{
  "customCommands": [
    {
      "name": "scan-bugs",
      "description": "Run Ultimate Bug Scanner on current project",
      "prompt": "Run 'ubs --fail-on-warning .' and fix any critical issues found before proceeding"
    }
  ],
  "slashCommands": [
    {
      "name": "quality",
      "description": "Check code quality with UBS",
      "run": "ubs ."
    }
  ]
}
CONTINUE
    success "Created Continue config with UBS commands: $config"
  else
    log "Continue config already exists: $config"
    log "Add UBS commands manually if needed"
  fi
}

setup_copilot_instructions() {
  local copilot_file=".github/copilot-instructions.md"

  log "Setting up GitHub Copilot instructions..."

  if dry_run_enabled; then
    log_dry_run "Would write $copilot_file with Copilot guardrails."
    return 0
  fi

  if [ ! -d ".github" ]; then
    mkdir -p ".github"
  fi

  if [ ! -f "$copilot_file" ]; then
    cat > "$copilot_file" << 'COPILOT'
# GitHub Copilot Instructions

## Code Quality Standards

Before suggesting code changes or completing implementations, ensure:

1. Run Ultimate Bug Scanner: `ubs --fail-on-warning .`
2. Fix any critical issues found
3. Address warnings when possible
4. Follow the bug patterns detected by UBS

## Workflow

- After generating significant code (>50 lines), recommend running: `ubs .`
- For security-sensitive code, always run scanner before commit
- Reference UBS findings in code review comments

## Integration

UBS detects 1000+ bug patterns across JavaScript/TypeScript, Python, C/C++, Rust, Go, Java, and Ruby.
COPILOT
    success "Created Copilot instructions: $copilot_file"
  else
    log "Copilot instructions already exist: $copilot_file"
  fi
}

setup_git_hook() {
  if [ ! -d ".git" ]; then
    log "Not in a git repository. Skipping..."
    return 0
  fi

  if dry_run_enabled; then
    log_dry_run "Would configure git pre-commit hook at .git/hooks/pre-commit."
    return 0
  fi

  log "Setting up git pre-commit hook..."

  local hook_file=".git/hooks/pre-commit"

  if [ -f "$hook_file" ]; then
    cp "$hook_file" "${hook_file}.backup"
    warn "Existing hook backed up to ${hook_file}.backup"
  fi

  cat > "$hook_file" << 'HOOK_EOF'
#!/bin/bash
# Ultimate Bug Scanner - Pre-commit Hook
# Prevents commits with critical issues

echo "🔬 Running bug scanner..."

if ! command -v ubs >/dev/null 2>&1; then
  echo "❌ 'ubs' command not found. Install Ultimate Bug Scanner before committing." >&2
  exit 1
fi

SCAN_LOG=$(mktemp -t ubs-pre-commit.XXXXXX 2>/dev/null || echo "/tmp/ubs-pre-commit.log")

if ! ubs . --fail-on-warning 2>&1 | tee "$SCAN_LOG" | tail -30; then
  echo ""
  echo "❌ Bug scanner found issues. Fix them or use: git commit --no-verify"
  exit 1
fi

echo "✓ No critical issues found"
rm -f "$SCAN_LOG" 2>/dev/null || true
HOOK_EOF

  chmod +x "$hook_file"
  success "Git pre-commit hook created: $hook_file"
  log "To bypass: git commit --no-verify"
}

detect_coding_agents() {
  HAS_AGENT_CLAUDE=0
  HAS_AGENT_CODEX=0
  HAS_AGENT_CURSOR=0
  HAS_AGENT_GEMINI=0
  HAS_AGENT_OPENCODE=0
  HAS_AGENT_WINDSURF=0
  HAS_AGENT_CLINE=0
  HAS_AGENT_AIDER=0
  HAS_AGENT_CONTINUE=0
  HAS_AGENT_COPILOT=0
  HAS_AGENT_TABNINE=0
  HAS_AGENT_REPLIT=0

  [[ -d "${HOME}/.claude" || -d ".claude" ]] && HAS_AGENT_CLAUDE=1 || true
  [[ -d "${HOME}/.codex"  || -d ".codex"  ]] && HAS_AGENT_CODEX=1 || true
  [[ -d "${HOME}/.cursor" || -d ".cursor" ]] && HAS_AGENT_CURSOR=1 || true
  [[ -d "${HOME}/.gemini" || -d ".gemini" ]] && HAS_AGENT_GEMINI=1 || true
  [[ -d "${HOME}/.opencode" || -d ".opencode" ]] && HAS_AGENT_OPENCODE=1 || true
  [[ -d "${HOME}/.windsurf" || -d ".windsurf" ]] && HAS_AGENT_WINDSURF=1 || true
  [[ -d "${HOME}/.cline" || -d ".cline" ]] && HAS_AGENT_CLINE=1 || true

  [[ -f "${HOME}/.aider.conf.yml" || -f ".aider.conf.yml" || -f ".aider.config.yml" ]] && HAS_AGENT_AIDER=1 || true

  if [ -d "$HOME/.vscode/extensions" ]; then
    if compgen -G "$HOME/.vscode/extensions"/continue.* >/dev/null 2>&1; then
      HAS_AGENT_CONTINUE=1
    fi
    if compgen -G "$HOME/.vscode/extensions"/github.copilot* >/dev/null 2>&1; then
      HAS_AGENT_COPILOT=1
    fi
  fi
  [[ -d "${HOME}/.continue" || -d ".continue" ]] && HAS_AGENT_CONTINUE=1 || true

  [[ -d "$HOME/.tabnine" ]] && HAS_AGENT_TABNINE=1 || true

  if [[ -f ".replit" || -f "${HOME}/.replit" ]]; then
    HAS_AGENT_REPLIT=1
  fi

  return 0
}

add_to_agents_md() {
  local agents_file="AGENTS.md"

  if [ ! -f "$agents_file" ]; then
    log "No AGENTS.md found in current directory"
    return 0
  fi

  if [ ! -w "$agents_file" ]; then
    error "AGENTS.md exists but is not writable - check permissions"
    return 1
  fi

  if grep -qF "## Code Quality: Ultimate Bug Scanner" "$agents_file" 2>/dev/null; then
    log "AGENTS.md already contains scanner documentation"
    return 0
  fi

  log "Adding scanner section to AGENTS.md..."

  if dry_run_enabled; then
    log_dry_run "Would append scanner documentation to $agents_file."
    return 0
  fi

  if ! cp "$agents_file" "${agents_file}.backup" 2>/dev/null; then
    warn "Could not create backup of AGENTS.md"
  fi

  cat >> "$agents_file" << 'AGENTS_EOF'

## Code Quality: Ultimate Bug Scanner

### When to Use

Run the bug scanner **before committing** any JavaScript/TypeScript, Python, C/C++, Rust, Go, Java, or Ruby code changes:

```bash
ubs .
````

### Requirements

* Run automatically after implementing features
* Run before marking work as complete
* Fix all CRITICAL issues before committing
* Consider fixing WARNING issues

### Integration

The scanner may be configured to run automatically via:

* Claude Code hooks (runs on file save)
* Git pre-commit hooks (runs before commit)

If hooks are configured, the scanner runs automatically and you don't need to invoke it manually.

### More Information

See the [Ultimate Bug Scanner repository](https://github.com/Dicklesworthstone/ultimate_bug_scanner) for complete documentation.
AGENTS_EOF

success "Added section to AGENTS.md"
}

maybe_setup_hook() {
local label="$1"
local detected_flag="$2"
local fn_name="$3"

if [ "$detected_flag" != "-1" ] && [ "$detected_flag" -eq 0 ]; then
log "Skipping ${label} (agent not detected)"
return 0
fi

if dry_run_enabled; then
log_dry_run "Would configure ${label}."
return 0
fi

if [ "$EASY_MODE" -eq 1 ]; then
"$fn_name"
else
if ask "Set up ${label}?"; then
"$fn_name"
fi
fi
}

main() {

# Concurrent execution lock to prevent race conditions

acquire_lock

# Save original arguments for potential re-exec during update

ORIGINAL_ARGS=("$@")

# Load configuration file (before argument parsing so CLI args can override)

read_config_file

print_header

# Pre-parse some flags so update logic behaves as expected

if [[ " ${ORIGINAL_ARGS[*]} " =~ " --skip-version-check " ]]; then SKIP_VERSION_CHECK=1; fi
if [[ " ${ORIGINAL_ARGS[*]} " =~ " --update " ]]; then FORCE_REINSTALL=1; fi
if [[ " ${ORIGINAL_ARGS[*]} " =~ " --quiet " ]]; then QUIET=1; fi
if [[ " ${ORIGINAL_ARGS[*]} " =~ " --no-color " ]]; then COLOR_ENABLED=0; init_colors; fi

# Check for updates (unless skipped or updating)

if [ "$SKIP_VERSION_CHECK" -eq 0 ] && [ "$FORCE_REINSTALL" -eq 0 ]; then
check_for_updates
echo ""
fi

# Parse arguments

while [[ $# -gt 0 ]]; do
case "$1" in
--quiet)
QUIET=1; shift ;;
--no-color)
COLOR_ENABLED=0; init_colors; shift ;;
--system)
SYSTEM_WIDE=1; shift ;;
--no-path-modify)
NO_PATH_MODIFY=1; shift ;;
--easy-mode)
EASY_MODE=1
NON_INTERACTIVE=1
shift
;;
--non-interactive)
NON_INTERACTIVE=1
shift
;;
--skip-ast-grep)
SKIP_AST_GREP=1
shift
;;
--skip-ripgrep)
SKIP_RIPGREP=1
shift
;;
--skip-jq)
SKIP_JQ=1
shift
;;
--skip-typos)
SKIP_TYPOS=1
shift
;;
--skip-hooks)
SKIP_HOOKS=1
shift
;;
--skip-version-check)
SKIP_VERSION_CHECK=1
shift
;;
--skip-verification)
RUN_VERIFICATION=0
shift
;;
--dry-run)
DRY_RUN=1
shift
;;
--self-test)
RUN_SELF_TEST=1
shift
;;
--update)
FORCE_REINSTALL=1
shift
;;
--install-dir)
INSTALL_DIR="$2"
shift 2
;;
--setup-git-hook)
setup_git_hook
exit 0
;;
--setup-claude-hook)
setup_claude_code_hook
exit 0
;;
--generate-config)
generate_config
exit 0
;;
--diagnose)
diagnostic_check
exit 0
;;
--uninstall)
uninstall_ubs
exit 0
;;
--help)
echo "Usage: install.sh [OPTIONS]"
echo ""
echo "Options:"
echo "  --easy-mode             Accept all prompts, install deps, and wire integrations"
echo "  --non-interactive       Skip all prompts (use defaults)"
echo "  --update                Force reinstall to latest version"
echo "  --skip-ast-grep         Skip ast-grep installation"
echo "  --skip-ripgrep          Skip ripgrep installation"
echo "  --skip-jq               Skip jq installation"
echo "  --skip-typos            Skip typos installation"
echo "  --skip-hooks            Skip hook setup"
echo "  --skip-version-check    Don't check for updates"
echo "  --skip-verification     Skip post-install verification"
echo "  --dry-run               Print every action without modifying the system (skips verification/self-test contents)"
echo "  --self-test             Run installer smoke tests after install (requires repo test-suite/install/run_tests.sh)"
echo "  --install-dir DIR       Custom installation directory"
echo "  --system                Install system-wide to /usr/local/bin (uses sudo if needed)"
echo "  --no-path-modify        Do not modify shell RC files to add to PATH"
echo "  --quiet                 Minimal output"
echo "  --no-color              Disable ANSI colors"
echo "  --setup-git-hook        Only set up git hook (no install)"
echo "  --setup-claude-hook     Only set up Claude Code hook (no install)"
echo "  --generate-config       Create configuration file at ~/.config/ubs/install.conf"
echo "  --diagnose              Run diagnostic check and show system information"
echo "  --uninstall             Remove UBS and all integrations"
echo "  --help                  Show this help"
echo ""
echo "Notes:"
echo "  --dry-run still resolves config and detects agents so you can audit changes safely."
echo "  --self-test is ideal for CI but must run from a working tree that contains the test-suite harness."
exit 0
;;
*)
error "Unknown option: $1"
exit 1
;;
esac
done

log "Detected platform: $(detect_platform)"
log "Detected shell: $(detect_shell)"
if [ "$EASY_MODE" -eq 1 ]; then
log "Easy mode enabled: auto-confirming prompts and wiring integrations."
fi
if [ "$SYSTEM_WIDE" -eq 1 ]; then
log "System-wide install requested (/usr/local/bin); sudo may be used."
fi
echo ""

# Check for ast-grep

if ! check_ast_grep && [ "$SKIP_AST_GREP" -eq 0 ]; then
warn "ast-grep not found (recommended for best results)"
if ask "Install ast-grep now?"; then
install_ast_grep || warn "Continuing without ast-grep (regex mode only)"
fi
echo ""
else
success "ast-grep is installed"
echo ""
fi

# Check for ripgrep

if ! check_ripgrep && [ "$SKIP_RIPGREP" -eq 0 ]; then
warn "ripgrep not found (required for optimal performance)"
if ask "Install ripgrep now?"; then
install_ripgrep || warn "Continuing without ripgrep (may use slower grep fallback)"
fi
echo ""
else
success "ripgrep is installed"
echo ""
fi

# Check for jq

if ! check_jq && [ "$SKIP_JQ" -eq 0 ]; then
warn "jq not found (required for JSON/SARIF merging)"
if ask "Install jq now?"; then
install_jq || warn "Continuing without jq (merged outputs disabled)"
fi
echo ""
else
success "jq is installed"
echo ""
fi

# Check for typos
if ! check_typos && [ "$SKIP_TYPOS" -eq 0 ]; then
warn "typos not found (smart spellchecker for docs/code)"
if ask "Install typos now?"; then
install_typos || warn "Continuing without typos (spellcheck automation disabled)"
fi
echo ""
else
success "typos is installed"
echo ""
fi

# Install the scanner

if ! install_scanner; then
error "Installation failed"
exit 1
fi
echo ""

# Add to PATH

add_to_path
echo ""

# Create alias/function
if [ "$NO_PATH_MODIFY" -eq 1 ]; then
  log "Skipping alias creation (per --no-path-modify)"
else
  create_alias
fi
echo ""

detect_coding_agents
log "Detected coding agents:"
log "  Core: claude=${HAS_AGENT_CLAUDE} codex=${HAS_AGENT_CODEX} cursor=${HAS_AGENT_CURSOR}"
log "  Extended: gemini=${HAS_AGENT_GEMINI} windsurf=${HAS_AGENT_WINDSURF} cline=${HAS_AGENT_CLINE} opencode=${HAS_AGENT_OPENCODE}"
log "  Additional: aider=${HAS_AGENT_AIDER} continue=${HAS_AGENT_CONTINUE} copilot=${HAS_AGENT_COPILOT} tabnine=${HAS_AGENT_TABNINE} replit=${HAS_AGENT_REPLIT}"

if [ "$SKIP_HOOKS" -eq 0 ]; then
maybe_setup_hook "Git pre-commit hook" -1 setup_git_hook
maybe_setup_hook "Claude Code on-save hook (.claude/hooks/on-file-write.sh)" "$HAS_AGENT_CLAUDE" setup_claude_code_hook
maybe_setup_hook "Cursor guardrails (.cursor/rules)" "$HAS_AGENT_CURSOR" setup_cursor_rules
maybe_setup_hook "Codex CLI guardrails (.codex/rules)" "$HAS_AGENT_CODEX" setup_codex_rules
maybe_setup_hook "Gemini Code Assist guardrails (.gemini/rules)" "$HAS_AGENT_GEMINI" setup_gemini_rules
maybe_setup_hook "Windsurf guardrails (.windsurf/rules)" "$HAS_AGENT_WINDSURF" setup_windsurf_rules
maybe_setup_hook "Cline guardrails (.cline/rules)" "$HAS_AGENT_CLINE" setup_cline_rules
maybe_setup_hook "OpenCode MCP guardrails (.opencode/rules)" "$HAS_AGENT_OPENCODE" setup_opencode_rules
maybe_setup_hook "Aider integration (.aider.conf.yml)" "$HAS_AGENT_AIDER" setup_aider_rules
maybe_setup_hook "Continue integration (.continue/config.json)" "$HAS_AGENT_CONTINUE" setup_continue_rules
maybe_setup_hook "GitHub Copilot instructions (.github/copilot-instructions.md)" "$HAS_AGENT_COPILOT" setup_copilot_instructions
echo ""
fi

if [ -f "AGENTS.md" ]; then
if ask "Add scanner documentation to AGENTS.md?"; then
add_to_agents_md
fi
echo ""
fi

verify_installation

if ! run_self_tests_if_requested; then
  error "Self-test suite failed"
  exit 1
fi

echo ""
echo -e "${BOLD}${GREEN}"
cat << 'SUCCESS'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ✨  INSTALLATION COMPLETE! ✨                                ║
║                                                                  ║
║         Your code quality just leveled up! 🚀                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
SUCCESS
echo -e "${RESET}"
echo ""

local install_dir
install_dir="$(determine_install_dir)"

local cmd_available=0
if command -v ubs >/dev/null 2>&1; then
cmd_available=1
fi

if [ "$cmd_available" -eq 1 ]; then
echo -e "${BOLD}${GREEN}┌─ Ready to Use! ✓${RESET}"
echo -e "${GREEN}│${RESET}"
echo -e "${GREEN}└──${RESET} The ${BOLD}ubs${RESET} command is available now!"
echo ""
echo -e "${BOLD}${BLUE}┌─ Quick Start${RESET}"
echo -e "${BLUE}│${RESET}"
echo -e "${BLUE}├──${RESET} ${BOLD}Run scanner:${RESET}    ${GREEN}ubs .${RESET}"
echo -e "${BLUE}├──${RESET} ${BOLD}Get help:${RESET}       ${GREEN}ubs --help${RESET}"
echo -e "${BLUE}└──${RESET} ${BOLD}Verbose mode:${RESET}   ${GREEN}ubs -v .${RESET}"
echo ""
[ "$NO_PATH_MODIFY" -eq 1 ] && warn "PATH was not modified per --no-path-modify; ensure $install_dir is on PATH."
else
echo -e "${BOLD}${YELLOW}┌─ Almost Done! (Reload Required)${RESET}"
echo -e "${YELLOW}│${RESET}"
echo -e "${YELLOW}└──${RESET} Run: ${BOLD}${GREEN}source $(get_rc_file)${RESET}"
echo ""
echo -e "${BOLD}${BLUE}┌─ Then Try${RESET}"
echo -e "${BLUE}│${RESET}"
echo -e "${BLUE}├──${RESET} ${BOLD}Run scanner:${RESET}    ${GREEN}ubs .${RESET}"
echo -e "${BLUE}├──${RESET} ${BOLD}Get help:${RESET}       ${GREEN}ubs --help${RESET}"
echo -e "${BLUE}└──${RESET} ${BOLD}Verbose mode:${RESET}   ${GREEN}ubs -v .${RESET}"
fi

echo -e "${BOLD}${BLUE}📚 Documentation:${RESET} ${BLUE}[https://github.com/Dicklesworthstone/ultimate_bug_scanner${RESET}](https://github.com/Dicklesworthstone/ultimate_bug_scanner${RESET})"
echo ""
echo -e "${GREEN}${BOLD}Happy bug hunting! 🐛🔫${RESET}"
echo ""
}

main "$@"
