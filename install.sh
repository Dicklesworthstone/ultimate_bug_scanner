#!/usr/bin/env bash
set -euo pipefail

# Ultimate Bug Scanner - Installation Script
# https://github.com/yourusername/ultimate_bug_scanner

VERSION="4.4"
SCRIPT_NAME="bug-scanner.sh"
INSTALL_NAME="ubs"
REPO_URL="https://raw.githubusercontent.com/yourusername/ultimate_bug_scanner/main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Symbols
CHECK="${GREEN}✓${RESET}"
CROSS="${RED}✗${RESET}"
ARROW="${BLUE}→${RESET}"
WARN="${YELLOW}⚠${RESET}"

# Flags
NON_INTERACTIVE=0
SKIP_AST_GREP=0
SKIP_HOOKS=0
INSTALL_DIR=""

print_header() {
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
    ║         Industrial-Grade Static Analysis for JavaScript         ║
    ║              Catch 1000+ Bug Patterns Before Production         ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
HEADER
  echo -e "${RESET}"
}

log() { echo -e "${ARROW} $*"; }
success() { echo -e "${CHECK} $*"; }
error() { echo -e "${CROSS} $*" >&2; }
warn() { echo -e "${WARN} $*"; }

ask() {
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    return 1  # Default to "no" in non-interactive mode
  fi
  local prompt="$1"
  local response
  read -p "$(echo -e "${YELLOW}?${RESET} ${prompt} (y/N): ")" response
  [[ "$response" =~ ^[Yy]$ ]]
}

detect_platform() {
  local os
  os="$(uname -s)"
  case "$os" in
    Linux*)   echo "linux" ;;
    Darwin*)  echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)        echo "unknown" ;;
  esac
}

detect_shell() {
  if [ -n "${BASH_VERSION:-}" ]; then
    echo "bash"
  elif [ -n "${ZSH_VERSION:-}" ]; then
    echo "zsh"
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

  case "$platform" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        brew install ast-grep
      else
        error "Homebrew not found. Please install from: https://ast-grep.github.io/guide/quick-start.html"
        return 1
      fi
      ;;
    linux)
      # Try package managers
      if command -v cargo >/dev/null 2>&1; then
        cargo install ast-grep
      elif command -v npm >/dev/null 2>&1; then
        npm install -g @ast-grep/cli
      else
        warn "No package manager found (cargo, npm)"
        log "Download from: https://github.com/ast-grep/ast-grep/releases"
        return 1
      fi
      ;;
    windows)
      if command -v cargo >/dev/null 2>&1; then
        cargo install ast-grep
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
    error "ast-grep installation failed"
    return 1
  fi
}

determine_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    echo "$INSTALL_DIR"
    return
  fi

  # Prefer ~/.local/bin if it exists or can be created
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

  log "Installing Ultimate Bug Scanner to $install_dir..."

  # Create directory if needed
  mkdir -p "$install_dir" 2>/dev/null || {
    error "Cannot create directory: $install_dir"
    return 1
  }

  # Download or copy script
  local script_path="$install_dir/$INSTALL_NAME"

  if [ -f "./$SCRIPT_NAME" ]; then
    # Local installation
    cp "./$SCRIPT_NAME" "$script_path"
  else
    # Remote installation
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "${REPO_URL}/${SCRIPT_NAME}" -o "$script_path"
    elif command -v wget >/dev/null 2>&1; then
      wget -q "${REPO_URL}/${SCRIPT_NAME}" -O "$script_path"
    else
      error "Neither curl nor wget found. Cannot download script."
      return 1
    fi
  fi

  chmod +x "$script_path"

  if [ -x "$script_path" ]; then
    success "Installed to: $script_path"
    return 0
  else
    error "Installation failed"
    return 1
  fi
}

add_to_path() {
  local install_dir
  install_dir="$(determine_install_dir)"

  # Check if already in PATH
  if echo "$PATH" | grep -q "$install_dir"; then
    return 0
  fi

  local rc_file
  rc_file="$(get_rc_file)"

  log "Adding $install_dir to PATH in $rc_file..."

  # Add PATH export if not already present
  if ! grep -q "export PATH.*$install_dir" "$rc_file" 2>/dev/null; then
    echo "" >> "$rc_file"
    echo "# Ultimate Bug Scanner" >> "$rc_file"
    echo "export PATH=\"\$PATH:$install_dir\"" >> "$rc_file"
    success "Added to PATH in $rc_file"
  else
    log "Already in PATH"
  fi
}

create_alias() {
  local rc_file
  rc_file="$(get_rc_file)"

  log "Creating 'ubs' alias in $rc_file..."

  # Check if alias already exists
  if grep -q "alias ubs=" "$rc_file" 2>/dev/null; then
    log "Alias already exists"
    return 0
  fi

  # Add alias
  echo "" >> "$rc_file"
  echo "# Ultimate Bug Scanner alias" >> "$rc_file"
  echo "alias ubs='bug-scanner.sh'" >> "$rc_file"
  success "Created 'ubs' alias"

  log "Restart your shell or run: source $rc_file"
}

setup_claude_code_hook() {
  if [ ! -d ".claude" ]; then
    log "Not in a project with .claude directory. Skipping..."
    return 0
  fi

  log "Setting up Claude Code hook..."

  local hook_dir=".claude/hooks"
  local hook_file="$hook_dir/on-file-write.sh"

  mkdir -p "$hook_dir"

  cat > "$hook_file" << 'HOOK_EOF'
#!/bin/bash
# Ultimate Bug Scanner - Claude Code Hook
# Runs on every file save for JavaScript/TypeScript files

if [[ "$FILE_PATH" =~ \.(js|jsx|ts|tsx|mjs|cjs)$ ]]; then
  echo "🔬 Running bug scanner..."
  if command -v ubs >/dev/null 2>&1; then
    ubs "$PROJECT_DIR" --ci 2>&1 | head -50
  else
    bug-scanner.sh "$PROJECT_DIR" --ci 2>&1 | head -50
  fi
fi
HOOK_EOF

  chmod +x "$hook_file"
  success "Claude Code hook created: $hook_file"
}

setup_git_hook() {
  if [ ! -d ".git" ]; then
    log "Not in a git repository. Skipping..."
    return 0
  fi

  log "Setting up git pre-commit hook..."

  local hook_file=".git/hooks/pre-commit"

  # Backup existing hook if present
  if [ -f "$hook_file" ]; then
    cp "$hook_file" "${hook_file}.backup"
    warn "Existing hook backed up to ${hook_file}.backup"
  fi

  cat > "$hook_file" << 'HOOK_EOF'
#!/bin/bash
# Ultimate Bug Scanner - Pre-commit Hook
# Prevents commits with critical issues

echo "🔬 Running bug scanner..."

if command -v ubs >/dev/null 2>&1; then
  SCANNER="ubs"
else
  SCANNER="bug-scanner.sh"
fi

if ! $SCANNER . --fail-on-warning 2>&1 | tee /tmp/bug-scan.txt | tail -30; then
  echo ""
  echo "❌ Bug scanner found issues. Fix them or use: git commit --no-verify"
  exit 1
fi

echo "✓ No critical issues found"
HOOK_EOF

  chmod +x "$hook_file"
  success "Git pre-commit hook created: $hook_file"
  log "To bypass: git commit --no-verify"
}

add_to_agents_md() {
  local agents_file="AGENTS.md"

  if [ ! -f "$agents_file" ]; then
    log "No AGENTS.md found in current directory"
    return 0
  fi

  # Check if already added
  if grep -q "Ultimate Bug Scanner" "$agents_file" 2>/dev/null; then
    log "AGENTS.md already contains scanner documentation"
    return 0
  fi

  log "Adding scanner section to AGENTS.md..."

  cat >> "$agents_file" << 'AGENTS_EOF'

## Code Quality: Ultimate Bug Scanner

### When to Use

Run the bug scanner **before committing** any JavaScript/TypeScript code changes:

```bash
ubs .
```

### Requirements

- Run automatically after implementing features
- Run before marking work as complete
- Fix all CRITICAL issues before committing
- Consider fixing WARNING issues

### Integration

The scanner may be configured to run automatically via:
- Claude Code hooks (runs on file save)
- Git pre-commit hooks (runs before commit)

If hooks are configured, the scanner runs automatically and you don't need to invoke it manually.

### More Information

See the [Ultimate Bug Scanner repository](https://github.com/yourusername/ultimate_bug_scanner) for complete documentation.
AGENTS_EOF

  success "Added section to AGENTS.md"
}

main() {
  print_header

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --non-interactive)
        NON_INTERACTIVE=1
        shift
        ;;
      --skip-ast-grep)
        SKIP_AST_GREP=1
        shift
        ;;
      --skip-hooks)
        SKIP_HOOKS=1
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
      --help)
        echo "Usage: install.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --non-interactive    Skip all prompts (use defaults)"
        echo "  --skip-ast-grep      Skip ast-grep installation"
        echo "  --skip-hooks         Skip hook setup"
        echo "  --install-dir DIR    Custom installation directory"
        echo "  --setup-git-hook     Only set up git hook (no install)"
        echo "  --setup-claude-hook  Only set up Claude Code hook (no install)"
        echo "  --help               Show this help"
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

  # Install the scanner
  if ! install_scanner; then
    error "Installation failed"
    exit 1
  fi
  echo ""

  # Add to PATH
  add_to_path
  echo ""

  # Create alias
  create_alias
  echo ""

  # Setup hooks
  if [ "$SKIP_HOOKS" -eq 0 ]; then
    if ask "Set up Claude Code hook?"; then
      setup_claude_code_hook
    fi
    echo ""

    if ask "Set up git pre-commit hook?"; then
      setup_git_hook
    fi
    echo ""
  fi

  # Add to AGENTS.md
  if [ -f "AGENTS.md" ]; then
    if ask "Add scanner documentation to AGENTS.md?"; then
      add_to_agents_md
    fi
    echo ""
  fi

  # Final instructions
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
  echo -e "${BOLD}${BLUE}┌─ Quick Start${RESET}"
  echo -e "${BLUE}│${RESET}"
  echo -e "${BLUE}├──${RESET} ${BOLD}Run scanner:${RESET}    ${GREEN}ubs .${RESET}"
  echo -e "${BLUE}├──${RESET} ${BOLD}Get help:${RESET}       ${GREEN}ubs --help${RESET}"
  echo -e "${BLUE}└──${RESET} ${BOLD}Verbose mode:${RESET}   ${GREEN}ubs -v .${RESET}"
  echo ""
  echo -e "${BOLD}${YELLOW}┌─ Next Steps${RESET}"
  echo -e "${YELLOW}│${RESET}"
  echo -e "${YELLOW}├──${RESET} ${BOLD}1.${RESET} Reload shell:     ${BLUE}source $(get_rc_file)${RESET}"
  echo -e "${YELLOW}├──${RESET} ${BOLD}2.${RESET} Test scanner:     ${BLUE}ubs --help${RESET}"
  echo -e "${YELLOW}└──${RESET} ${BOLD}3.${RESET} Run first scan:   ${BLUE}ubs .${RESET}"
  echo ""
  echo -e "${BOLD}${BLUE}📚 Documentation:${RESET} ${BLUE}https://github.com/yourusername/ultimate_bug_scanner${RESET}"
  echo ""
  echo -e "${GREEN}${BOLD}Happy bug hunting! 🐛🔫${RESET}"
  echo ""
}

main "$@"
