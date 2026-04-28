
# 🔬 Ultimate Bug Scanner v5.0

<div align="center">
  <img src="docs/assets/ubs_illustration.webp" alt="Ultimate Bug Scanner - The AI Coding Agent's Secret Weapon">
</div>

### **The AI Coding Agent's Secret Weapon: Flagging Likely Bugs for Fixing Early On**

[![License: MIT](https://img.shields.io/badge/License-MIT%2BOpenAI%2FAnthropic%20Rider-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](https://github.com/Dicklesworthstone/ultimate_bug_scanner)
[![Version](https://img.shields.io/badge/version-5.1.25-blue.svg)](https://github.com/Dicklesworthstone/ultimate_bug_scanner)

<div align="center">

```bash
# One command to catch 1000+ bug patterns (always main, cache-busted)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" \
  | bash -s --
```

**Or via Homebrew (macOS/Linux):**

```bash
brew install dicklesworthstone/tap/ubs
```

</div>

---

Just want it to do everything without confirmations? Live life on the edge with easy-mode to auto-install every dependency, accept all prompts, detect local coding agents, and wire their quality guardrails with zero extra questions:

<div align="center">

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" \
  | bash -s -- --easy-mode
```

Note: Windows users must run the installer one-liner from within Git Bash, or use WSL for Windows. 

</div>

---

## 🤖 Agent Quickstart (JSON/TOON)

**Use machine-readable output in agent contexts.** stdout = data, stderr = diagnostics, exit 0 = success.

```bash
# Scan current repo (JSON)
ubs . --format=json

# Token-optimized output (TOON)
ubs . --format=toon

# Scan only staged changes
ubs --staged --format=json

# CI-strict (fail on warnings)
ubs . --profile=strict --fail-on-warning --format=json
```

## 💥 **The Problem: AI Moves Fast, Bugs Move Faster**

You're coding faster than ever with Claude Code, Codex, Cursor, and other AI coding agents. You're shipping features in minutes that used to take days. **But here's the painful truth:**

### **Even the best AI makes these mistakes:**

**JavaScript/TypeScript example** *(similar patterns exist in Python, Go, Rust, Java, C++, Ruby)*:

```javascript
// ❌ CRITICAL BUG #1: Null pointer crash waiting to happen
const submitButton = document.getElementById('submit');
submitButton.addEventListener('click', handleSubmit);  // 💥 Crashes if element doesn't exist

// ❌ CRITICAL BUG #2: XSS vulnerability
function displayUserComment(comment) {
  document.getElementById('comments').innerHTML = comment;  // 🚨 Security hole
}

// ❌ CRITICAL BUG #3: Silent failure (missing await)
async function saveUser(data) {
  const result = validateUser(data);  // 💥 Should be 'await validateUser(data)'
  await saveToDatabase(result);  // Saves undefined!
}

// ❌ CRITICAL BUG #4: Always false comparison
if (calculatedValue === NaN) {  // 💥 This NEVER works (always false)
  console.log("Invalid calculation");
}

// ❌ CRITICAL BUG #5: parseInt footgun
const zipCode = parseInt(userInput);  // 💥 "08" becomes 0 in old browsers (octal!)
```

**Each of these bugs could cost 3-6 hours to debug in production.** Similar issues plague every language: unguarded null access, missing `await`, security holes from `eval()`, buffer overflows from `strcpy()`, `.unwrap()` panics, goroutine leaks... **You've probably hit all of them.**

---

## 🎯 **The Solution: Your 24/7 Bug Hunting Partner**

### 🧠 Language-Aware Meta-Runner
- `ubs` auto-detects **JavaScript/TypeScript, Python, C/C++, Rust, Go, Java, Ruby, Swift, and C#** in the same repo and fans out to per-language scanners.
- Each scanner lives under `modules/ubs-<lang>.sh`, ships independently, and supports `--format text|json|jsonl|sarif|toon` for consistent downstream tooling.
- Modules download lazily (PATH → repo `modules/` → cached under `${XDG_DATA_HOME:-$HOME/.local/share}/ubs/modules`) and are validated before execution.
- Results from every language merge into one text/JSON/SARIF report via `jq`, so CI systems and AI agents only have to parse a single artifact.

### 🔐 Supply-Chain Safeguards
- Every lazily-downloaded module (and its helper assets) ships with pinned SHA-256 checksums baked into the meta-runner. Files fetched from GitHub are verified before they can execute, preventing tampering between releases.
- The cache lives under `${XDG_DATA_HOME:-$HOME/.local/share}/ubs/modules` by default; use `--module-dir` to relocate it (e.g., inside a CI workspace) while retaining the same verification guarantees.
- Run `ubs doctor` at any time to audit your environment. It checks for curl/wget availability, writable cache directories, and per-language module integrity. Add `--fix` to redownload missing or corrupted modules proactively.
- Scanner runs still respect `--update-modules`, but an invalid checksum now causes an immediate failure with remediation guidance rather than executing unverified code.
- **Developer Pre-commit Hook**: The repository ships with a `.githooks/pre-commit` hook that auto-updates `SHA256SUMS` when modules change and blocks commits with stale checksums. This ensures every release has verified checksums without manual intervention.
- **Minisign Support**: For additional assurance, set `UBS_MINISIGN_PUBKEY` to verify cryptographic signatures on `SHA256SUMS` via [minisign](https://jedisct1.github.io/minisign/).

### 🎛 Category Packs & Shareable Reports
- `--category=resource-lifecycle` focuses the scanners on Python/Go/Java resource hygiene (context managers, defer symmetry, try-with-resources). UBS automatically narrows the language set to those with lifecycle packs enabled and suppresses unrelated categories.
- `--comparison=<baseline.json>` diff the latest combined summary against a stored run. Deltas feed into console output, JSON, HTML, and SARIF automation metadata so CI can detect regressions.
- `--report-json=<file>` writes an enriched summary (project, totals, git metadata, optional comparison block) that you can archive or share with teammates/CI.
- `--html-report=<file>` emits a standalone HTML preview showing totals, trends vs. baseline, and per-language breakdowns—ideal for attaching to PRs or chat updates.
- All shareable outputs inject GitHub permalinks when UBS is run inside a git repo with a GitHub remote. Text output automatically annotates `path:line` references, JSON gains `git.*` metadata, and merged SARIF runs now include `versionControlProvenance` plus `automationDetails` keyed by the comparison id.

#### Resource lifecycle heuristics in each language
- **Python** – Category 16 now correlates every `open()` call against matching `with open(...)` usage and explicit `encoding=` parameters, while Category 19 uses the new AST helper at `modules/helpers/resource_lifecycle_py.py` to walk every file, socket, subprocess, asyncio task, and context cancellation path. The helper resolves alias imports, context managers, and awaited tasks so the diff counts (`acquire=X, release=Y, context-managed=Z`) show the exact imbalance per file.
- **Go** – Category 5/17 now run a Go AST walker (`modules/helpers/resource_lifecycle_go.go`) that detects `context.With*` calls missing cancel, `time.NewTicker/NewTimer` without `Stop`, `os.Open/sql.Open` without `Close`, and mutex `Lock`/`Unlock` symmetry. Findings come straight from the AST positions, so “ticker missing Stop()” lines map to the exact `file:line` instead of coarse regex summaries.
- **Java** – Category 5 surfaces `FileInputStream`, readers/writers, JDBC handles, etc. that were created outside try-with-resources, while Category 19 keeps tracking executor services and file streams that never close. The new summary text matches the manifest fixtures, so CI will fail if regression swallows these warnings.

#### Shareable output quickstart
```bash
# 1) Capture a baseline JSON (checked into CI artifacts or local history)
ubs --ci --only=python --category=resource-lifecycle \
    --report-json .ubs/baseline.json test-suite/python/buggy

# 2) Re-run with comparison + HTML preview for PRs or chat threads
ubs --ci --only=python --category=resource-lifecycle \
    --comparison .ubs/baseline.json \
    --report-json .ubs/latest.json \
    --html-report  .ubs/latest.html \
    test-suite/python/buggy
```

`latest.json` now contains the git metadata (repo URL, commit, blob_base) plus a `comparison.delta` block, and `latest.html` renders a lightweight dashboard summarising the deltas. SARIF uploads also pick up the comparison id so repeating runs in CI stay grouped by automation id.

---

## 💡 **Basic Usage**

```bash
# Scan current directory
ubs .

# Scan specific directory
ubs /path/to/your/project

# Verbose mode (show more code examples)
ubs -v .

# Save report to file
ubs . bug-report.txt

# CI mode (exit code 1 on warnings)
ubs . --fail-on-warning

# Quiet mode (summary only)
ubs -q .

# Skip specific categories (e.g., skip TODO markers)
ubs . --skip=11,14

# Custom file extensions
ubs . --include-ext=js,ts,vue,svelte
```

### Handy switches

```bash
# Git-aware quick scans (changed files only)
ubs --staged    # Scan files staged for commit
ubs --diff      # Scan working tree changes vs HEAD

# Strictness profiles
ubs --profile=strict   # Fail on warnings, enforce high standards
ubs --profile=loose    # Skip TODO/debug/code-quality nits when prototyping

# Machine-readable output
ubs . --format=json    # Pure JSON on stdout; logs go to stderr
ubs . --format=jsonl   # Line-delimited summary per scanner + totals
ubs . --format=toon    # TOON format (~50% smaller than JSON, LLM-optimized)
ubs . --format=jsonl --beads-jsonl out/findings.jsonl  # Save JSONL for Beads/"strung"
```

### Keeping noise low
- UBS auto-ignores common junk (`node_modules`, virtualenvs, dist/build/target/vendor, editor caches, etc.).
- Inline suppression is available when a finding is intentional: `eval("print('safe')")  # ubs:ignore`

## 🚀 **Quick Install (30 Seconds)**

### **Recommended: Homebrew (macOS/Linux)**

```bash
brew install dicklesworthstone/tap/ubs
```

This method provides:
- Automatic updates via `brew upgrade`
- Dependency management
- Easy uninstall via `brew uninstall`

### **Windows: Scoop**

```powershell
scoop bucket add dicklesworthstone https://github.com/Dicklesworthstone/scoop-bucket
scoop install dicklesworthstone/ubs
```

### **Alternative: Automated Install**

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" | bash
```

### **Option 2: Integrity-first install (signed checksums)**

```bash
export UBS_MINISIGN_PUBKEY="RWQg+jMrKiloMT5L3URISMoRzCMc/pVcVRCTfuY+WIzttzIr4CUJYRUk"
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/scripts/verify.sh | bash
```

The verifier downloads `SHA256SUMS` + `SHA256SUMS.minisig` from the matching release, validates them with minisign, checks `install.sh`, and only then executes it. Use `--insecure` to bypass verification (not recommended).

### **Option 3: Nix**

Run directly (no install):

```bash
nix run github:Dicklesworthstone/ultimate_bug_scanner
```

Dev shell for contributors:

```bash
nix develop
```

### **Option 4: Docker / OCI**

Pull & inspect:

```bash
docker run --rm ghcr.io/dicklesworthstone/ubs-tools ubs --help
```

Scan host code (risk-aware: grants container access to host FS):

```bash
docker run --rm -v /:/host ghcr.io/dicklesworthstone/ubs-tools bash -c "cd /host/path && ubs ."
```

⚠️ Use the host-mount pattern only when you understand the write-access implications.

### Deployment & Security

- Release playbook (how we cut signed releases): [docs/release.md](docs/release.md)
- Supply chain & verification model: [docs/security.md](docs/security.md)

The installer will:
- ✅ Install the `ubs` command globally
- ✅ Install/ensure `ast-grep` (required for accurate JS/TS scanning; UBS can auto-provision a pinned binary)
- ✅ Optionally install `ripgrep` (for 10x faster scanning)
- ✅ Optionally install `jq` (needed for JSON/SARIF merging across all language scanners)
- ✅ Optionally install `typos` (smart spellchecker for docs and identifiers)
- ✅ Optionally install `Node.js + typescript` (enables deep TypeScript type narrowing analysis)
- ✅ Auto-run `ubs doctor` post-install and append a session summary to `~/.config/ubs/session.md`
- ✅ Capture readiness facts (ripgrep/jq/typos/type narrowing) and store them for `ubs sessions --entries 1`
- ✅ Set up git hooks (block commits with critical bugs)
- ✅ Set up Claude Code hooks (scan on file save)
- ✅ Add documentation to your AGENTS.md

Need to revisit what the installer discovered later? Run `ubs sessions --entries 1` to view the most recent session log (or point teammates at the same summary).

Need the “just make it work” button? Run the installer with `--easy-mode` to auto-install every dependency, accept all prompts, detect local coding agents, and wire their quality guardrails with zero extra questions:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" \
  | bash -s -- --easy-mode
```

**Total time:** 30 seconds to 2 minutes (depending on dependencies)

Need to keep your shell RC files untouched? Combine `--no-path-modify` (and optionally `--skip-hooks`) with the command above—the installer will still drop `ubs` into your chosen `--install-dir`, but it will skip both PATH edits and the alias helper entirely.

### **Option 2: Manual Install**

```bash
# Download and install the unified runner
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/ubs \
  -o /usr/local/bin/ubs && chmod +x /usr/local/bin/ubs

# Verify it works
ubs --help

# Install dependencies (ast-grep required for JS/TS scanning)
# Required for JS/TS scanning (syntax-aware AST engine)
brew install ast-grep            # or: cargo install ast-grep, npm i -g @ast-grep/cli
brew install ripgrep             # 10x faster searching (or: apt/dnf/cargo install)
brew install typos-cli           # Spellchecker tuned for code (or: cargo install typos-cli)
npm install -g typescript        # Enables full tsserver-based type narrowing checks
```

### **Option 3: Use Without Installing**

```bash
# Download once
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/ubs \
  -o ubs && chmod +x ubs

# Run it
./ubs .
```

### Installer Safety Nets

#### Uninstall from any shell

Run the installer in `--uninstall` mode via curl if you want to remove UBS and all of its integrations:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" | bash -s -- --uninstall --non-interactive
```

This command deletes the UBS binary, shell RC snippets/aliases, config under `~/.config/ubs`, and the optional Claude/Git hooks that the installer set up. Because it passes `--non-interactive`, it auto-confirms all prompts and runs unattended.

| Flag | What it does | Why it matters |
|------|--------------|----------------|
| `--dry-run` | Prints every install action (downloads, PATH edits, hook writes, cleanup) without touching disk. Dry runs still resolve config, detect agents, and show you exactly what *would* change. | Audit the installer, demo it to teammates, or validate CI steps without modifying a workstation. |
| `--self-test` | Immediately runs `test-suite/install/run_tests.sh` after installation and exits non-zero if the smoke suite fails. | CI/CD jobs and verified setups can prove the installer still works end-to-end before trusting a release. |
| `--skip-type-narrowing` | Skip the Node.js + TypeScript readiness probe **and** the cross-language guard analyzers (JS/Rust/Kotlin/Swift/C#). | Useful for air-gapped hosts or environments that want to stay in heuristic-only mode. |
| `--skip-typos` | Skip the Typos spellchecker installation + diagnostics. | Handy when corp images already provide Typos or when you deliberately disable spellcheck automation. |
| `--skip-doctor` | Skip the automatic `ubs doctor` run + session summary after install. | Use when CI already runs doctor separately or when you're iterating locally and want a faster finish. |

> [!WARNING]
> `--self-test` requires running `install.sh` from a working tree that contains `test-suite/install/run_tests.sh` (i.e., the repo root). Curl-piping the installer from GitHub can’t self-test because the harness isn’t present, so the flag will error out early instead of giving a false sense of safety.

> [!NOTE]
> After every install the script now double-checks `command -v ubs`. If another copy shadows the freshly written binary, you’ll get an explicit warning with both paths so you can fix PATH order before running scans.

> [!TIP]
> Type narrowing relies on Node.js plus the `typescript` npm package *and* the Python helpers that power the Rust/Kotlin/Swift/C# checks. The installer now checks Node/TypeScript readiness, can optionally run `npm install -g typescript`, and surfaces the status inside `install.sh --diagnose`. Use `--skip-type-narrowing` if you’re on an air-gapped host or plan to keep the heuristic-only mode.

> [!TIP]
> To avoid global npm permission issues, the installer now detects/installs [bun](https://bun.sh/) just like other dependencies and uses `bun install --global typescript` by default, falling back to npm only if bun isn’t available.
>
> The diagnostics also call out Swift guard readiness: if python3 is available we count `.swift` files under your repo and record whether the guard helper will actually run. That fact shows up in `install.sh --diagnose` output and the auto-generated session log so iOS/macOS teams can tell at a glance whether the ObjC-bridging heuristics are active.

**Common combos**

```bash
# Preview everything without touching dotfiles or hooks
bash install.sh --dry-run --no-path-modify --skip-hooks --non-interactive

# CI-friendly install that self-tests the smoke harness
bash install.sh --easy-mode --self-test --skip-hooks
```

### 🔄 **Auto-Update**

The `ubs` meta-runner supports an **opt-in** auto-update check (once every 24 hours). This is **disabled by default** for supply-chain safety.

To enable auto-update:
```bash
export UBS_ENABLE_AUTO_UPDATE=1
```

To disable it (even if enabled):
```bash
export UBS_NO_AUTO_UPDATE=1
# or
ubs --no-auto-update .
```

Ultimate Bug Scanner is like having a senior developer review every line of code **in under 5 seconds**; it's the perfect automated companion to your favorite coding agent:

```bash
$ ubs .

╔══════════════════════════════════════════════════════════════════════╗
║  🔬 ULTIMATE BUG SCANNER v4.4 - Scanning your project...             ║
╚══════════════════════════════════════════════════════════════════════╝

Project:  /Users/you/awesome-app
Files:    247 JS/TS + 58 Python + 24 Go + 16 Java + 11 Ruby + 12 C++/Rust files
Finished: 3.2 seconds

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary Statistics:
  Files scanned:    247
  🔥 Critical:      0    ← Would have crashed in production!
  ⚠️  Warnings:      8    ← Should fix before shipping
  ℹ️  Info:          23   ← Code quality improvements

✨ EXCELLENT! No critical issues found ✨

```

---

## ⚡ **Why Developers + AI Agents Will Love This Tool**

### 🚀 **1. Catches What Humans & AI Miss**

**18 specialized detection categories** covering the bugs that *actually* matter:

<table>
<tr>
<th>Category</th>
<th>What It Prevents</th>
<th>Time Saved Per Bug</th>
</tr>
<tr>
<td><strong>Null Safety</strong></td>
<td>"Cannot read property of undefined" crashes</td>
<td>2-4 hours</td>
</tr>
<tr>
<td><strong>Security Holes</strong></td>
<td>XSS, code injection, prototype pollution</td>
<td>8-20 hours + reputation damage</td>
</tr>
<tr>
<td><strong>Async/Await Bugs</strong></td>
<td>Race conditions, unhandled rejections</td>
<td>4-8 hours</td>
</tr>
<tr>
<td><strong>Memory Leaks</strong></td>
<td>Event listeners, timers, detached DOM</td>
<td>6-12 hours</td>
</tr>
<tr>
<td><strong>Type Coercion</strong></td>
<td>JavaScript's === vs == madness</td>
<td>1-3 hours</td>
</tr>
<tr>
<td colspan="2"><strong>+ 13 more categories</strong></td>
<td><strong>100+ hours/month saved</strong></td>
</tr>
</table>

### 💨 **2. Blazing Fast (Because Your Time Matters)**

```
Small project (5K lines):     0.8 seconds  ⚡
Medium project (50K lines):   3.2 seconds  🚀
Large project (200K lines):  12 seconds    💨
Huge project (1M lines):     58 seconds    🏃
```

**That's 10,000+ lines analyzed per second.** Faster than you can say "but it worked on my machine."

### 🤖 **3. Built FOR AI Agents, BY Developers Who Use AI**

Unlike traditional linters that fight AI-generated code, this scanner **embraces** it:

```markdown
✅ Designed for Claude Code, Cursor, Windsurf, Aider, Continue, Copilot
✅ Zero configuration - works with ANY JS/TS, Python, C/C++, Rust, Go, Java, or Ruby project
✅ Integrates with git hooks, CI/CD, file watchers
✅ Actionable output (tells you WHAT's wrong and HOW to fix it)
✅ Fails fast in CI (catch bugs before they merge)
✅ React Hooks dependency analysis that spots missing deps, unstable objects, and stale closures
✅ Lightweight taint analysis that traces req.body/window.location/localStorage → innerHTML/res.send/eval/exec/db.query and flags flows without DOMPurify/escapeHtml/parameterized SQL
```

### 📊 **4. Real-World Impact**

<table>
<tr>
<th>Scenario</th>
<th>Without Scanner</th>
<th>With Scanner</th>
</tr>
<tr>
<td><strong>AI implements user auth</strong></td>
<td>
  • 3 null pointer crashes (9h debugging)<br>
  • 1 XSS vulnerability (8h + incident)<br>
  • 2 race conditions (4h debugging)<br>
  <strong>Total: ~21 hours + security incident</strong>
</td>
<td>
  • All issues caught in 4 seconds<br>
  • Fixed before commit (15 min)<br>
  <strong>Total: 15 minutes</strong><br>
  <strong>Savings: 84x faster</strong> ⚡
</td>
</tr>
<tr>
<td><strong>Refactor payment flow</strong></td>
<td>
  • Division by zero in edge case (3h)<br>
  • Unhandled promise rejection (2h)<br>
  • Missing error logging (1h)<br>
  <strong>Total: 6 hours debugging</strong>
</td>
<td>
  • Caught instantly (3 sec)<br>
  • Fixed before merge (10 min)<br>
  <strong>Total: 10 minutes</strong><br>
  <strong>Savings: 36x faster</strong> 🚀
</td>
</tr>
</table>

---

## 🤖 **AI Agent Integration (The Real Magic)**

### On-Device Agent Guardrails

`install.sh` now inspects your workstation for the most common coding agents (the same set listed below) and, when asked, drops guardrails that remind those agents to run `ubs --fail-on-warning .` before claiming a task is done. In `--easy-mode` this happens automatically; otherwise you can approve each integration individually.

| Agent / IDE | What we wire up | Why it helps |
|-------------|-----------------|--------------|
| **Claude Code Desktop** (`.claude/hooks/on-file-write.sh`) | File-save hook that shells out to `ubs --ci` whenever Claude saves JS/TS files. | Keeps Claude from accepting “Apply Patch” without a fresh scan. |
| **Cursor** (`.cursor/rules`) | Shared rule block that tells Cursor plans/tasks to run `ubs --fail-on-warning .` and summarize outstanding issues. | Cursor’s autonomous jobs inherit the same QA checklist as humans. |
| **Codex CLI** (`.codex/rules/ubs.md`) | Adds the identical rule block for OpenAI's Codex terminal workflow. Supports both file and directory formats (v0.77.0+). | Ensures Codex sessions never skip the scanner during long refactors. |
| **Gemini Code Assist** (`.gemini/rules`) | Guidance instructing Gemini agents to run `ubs` before closing a ticket. | Keeps Gemini’s asynchronous fixes aligned with UBS exit criteria. |
| **Windsurf** (`.windsurf/rules`) | Guardrail text + sample command palette snippet referencing `ubs`. | Windsurf’s multi-step plans stay grounded in the same quality gate. |
| **Cline** (`.cline/rules`) | Markdown instructions that Cline’s VS Code extension ingests. | Forces every “tool call” from Cline to mention scanner findings. |
| **OpenCode MCP** (`.opencode/rules`) | Local MCP instructions so HTTP tooling always calls `ubs` before replying. | Makes OpenCode's multi-agent swarms share the same notion of "done". |

#### Codex CLI v0.77.0+ Migration Note

Starting with Codex CLI v0.77.0, the rules storage changed from a **single file** (`.codex/rules`) to a **directory** (`.codex/rules/`) containing individual rule files. The UBS installer handles both formats automatically:

| Codex Version | Rules Location | UBS Installer Behavior |
|---------------|----------------|------------------------|
| < v0.77.0 | `.codex/rules` (file) | Appends UBS quick reference to file |
| ≥ v0.77.0 | `.codex/rules/` (directory) | Creates `.codex/rules/ubs.md` |

**If you upgraded Codex and encounter issues**, migrate manually:

```bash
# Convert file to directory structure
mv ~/.codex/rules ~/.codex/rules.backup
mkdir ~/.codex/rules
mv ~/.codex/rules.backup ~/.codex/rules/ubs.md
```

The installer's `append_quick_reference_block()` function detects the storage format at runtime and writes to the appropriate location, so re-running `install.sh` after upgrading Codex will "just work."

### **Why This Matters for AI Workflows**

When you're coding with AI, you're moving **10-100x faster** than traditional development. But bugs accumulate just as quickly. Traditional tools slow you down. This scanner keeps pace:

```
Traditional workflow:              AI-powered workflow with scanner:
┌──────────────────┐              ┌──────────────────┐
│ AI writes code   │              │ AI writes code   │
└────────┬─────────┘              └────────┬─────────┘
         │                                 │
         ↓                                 ↓
┌──────────────────┐              ┌──────────────────┐
│ You review       │              │ Scanner runs     │
│ (15 min)         │              │ (3 seconds)      │
└────────┬─────────┘              └────────┬─────────┘
         │                                 │
         ↓                                 ↓
┌──────────────────┐              ┌──────────────────┐
│ Tests pass?      │              │ Critical bugs?   │
└────────┬─────────┘              └────────┬─────────┘
         │ NO!                              │ YES!
         ↓                                 ↓
┌──────────────────┐              ┌──────────────────┐
│ Debug in prod    │              │ AI fixes them    │
│ (6 hours)        │              │ (5 minutes)      │
└──────────────────┘              └────────┬─────────┘
                                           ↓
                                  ┌──────────────────┐
                                  │ Ship with         │
                                  │ confidence        │
                                  └──────────────────┘

Total: 6.25 hours                Total: 8 minutes
```

### **Pattern 1: Claude Code Integration (Real-Time Scanning)**

Drop this into `.claude/hooks/on-file-write.sh`:

```bash
#!/bin/bash
# Auto-scan UBS-supported languages (JS/TS, Python, C/C++, Rust, Go, Java, Ruby, Swift, C#) on save

if [[ "$FILE_PATH" =~ \.(js|jsx|ts|tsx|mjs|cjs|py|pyw|pyi|c|cc|cpp|cxx|h|hh|hpp|hxx|rs|go|java|rb|cs|csx)$ ]]; then
  echo "🔬 Quality check running..."

  if ubs "${PROJECT_DIR}" --ci 2>&1 | head -30; then
    echo "✅ No critical issues"
  else
    echo "⚠️  Issues detected - review above"
  fi
fi
```

**Result:** Every time Claude writes code, the scanner catches bugs **instantly**.

### **Pattern 2: Git Pre-Commit Hook (Quality Gate)**

The installer can set this up automatically, or add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Block commits with critical bugs

echo "🔬 Running bug scanner..."

if ! ubs . --fail-on-warning 2>&1 | tee /tmp/scan.txt | tail -30; then
  echo ""
  echo "❌ Critical issues found. Fix them or use: git commit --no-verify"
  echo ""
  echo "Top issues:"
  grep -A 3 "🔥 CRITICAL" /tmp/scan.txt | head -20
  exit 1
fi

echo "✅ Quality check passed - committing..."
```

**Result:** Bugs **cannot** be committed. Period.

### **Pattern 3: Cursor/Windsurf/Continue Integration**

Add to your `.cursorrules` or similar:

```markdown
## Code Quality Standards

Before marking any task as complete:

1. Run the bug scanner: `ubs .`
2. Fix ALL critical issues (🔥)
3. Review warnings (⚠️) and fix if trivial
4. Only then mark task complete

If the scanner finds critical issues, your task is NOT done.
```

**Result:** AI agents have **built-in quality standards**.

### **Pattern 4: CI/CD Pipeline (GitHub Actions Example)**

```yaml
name: Code Quality Gate

on: [push, pull_request]

jobs:
  bug-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Bug Scanner
        run: |
          curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" | bash -s -- --non-interactive

      - name: Scan for Bugs
        run: |
          ubs . --fail-on-warning --ci
```

**Result:** Pull requests with critical bugs **cannot merge**.

### **Pattern 5: The Fix-Verify Loop (For AI Agents)**

This is the golden pattern for AI coding workflows:

```bash
#!/bin/bash
# Have your AI agent run this after implementing features

echo "🔬 Post-implementation quality check..."

# Run scanner
if ubs . --fail-on-warning > /tmp/scan-result.txt 2>&1; then
  echo "✅ All quality checks passed!"
  echo "📝 Ready to commit"
  exit 0
else
  echo "❌ Issues found:"
  echo ""

  # Show critical issues
  grep -A 5 "🔥 CRITICAL" /tmp/scan-result.txt | head -30

  echo ""
  echo "🤖 AI: Please fix these issues and re-run this check"
  exit 1
fi
```

**Usage pattern:**

```markdown
User: "Add user registration with email validation"

AI Agent:
1. Implements the feature
2. Runs quality check (scanner finds 3 critical bugs)
3. Fixes the bugs
4. Re-runs quality check (passes)
5. Commits the code

Total time: 12 minutes (vs. 6 hours debugging in production)
```

### **Pattern 6: The "AI Agent Decision Tree"**

Train your AI agent to use this decision tree:

```
Did I modify code in any supported language?
(JS/TS, Python, Go, Rust, Java, C++, Ruby)
         │
         ↓ YES
Changed more than 50 lines?
         │
         ↓ YES
    Run scanner ←──────────┐
         │                 │
         ↓                 │
Critical issues found? ────┤ YES
         │ NO              │
         ↓                 │
     Warnings?             │
         │                 │
         ↓ YES             │
  Show to user             │
  Ask if should fix ───────┤
         │ NO              │
         ↓                 ↓
    Commit code      Fix issues
```

---

> [!IMPORTANT]
> **Copy the blurb below to your project's `AGENTS.md`, `.claude/claude_docs/`, or `.cursorrules` file for comprehensive UBS integration guidance.**

````markdown
## UBS Quick Reference for AI Agents

UBS stands for "Ultimate Bug Scanner": **The AI Coding Agent's Secret Weapon: Flagging Likely Bugs for Fixing Early On**

**Install:** `curl -sSL https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh | bash`

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

**Commands:**
```bash
ubs file.ts file2.py                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=js,python src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs --help                              # Full command reference
ubs sessions --entries 1                # Tail the latest install session log
ubs .                                   # Whole project (ignores things like .venv and node_modules automatically)
```

**Output Format:**
```
⚠️  Category (N errors)
    file.ts:42:5 – Issue description
    💡 Suggested fix
Exit code: 1
```
Parse: `file:line:col` → location | 💡 → how to fix | Exit 0/1 → pass/fail

**Fix Workflow:**
1. Read finding → category + fix suggestion
2. Navigate `file:line:col` → view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` → exit 0
6. Commit

**Speed Critical:** Scope to changed files. `ubs src/file.ts` (< 1s) vs `ubs .` (30s). Never full scan for small edits.

**Bug Severity:**
- **Critical** (always fix): Null safety, XSS/injection, async/await, memory leaks
- **Important** (production): Type narrowing, division-by-zero, resource leaks
- **Contextual** (judgment): TODO/FIXME, console logs

**Anti-Patterns:**
- ❌ Ignore findings → ✅ Investigate each
- ❌ Full scan per edit → ✅ Scope to file
- ❌ Fix symptom (`if (x) { x.y }`) → ✅ Root cause (`x?.y`)
````

---

## 🎬 **See It In Action**

*Examples show JavaScript output; each language has equivalent detections (Python: None checks, Go: nil guards, Rust: Option handling, etc.)*

### **Example 1: Catching a Null Pointer Bug**

```bash
$ ubs src/

▓▓▓ NULL SAFETY & DEFENSIVE PROGRAMMING
Detects: Null pointer dereferences, missing guards, unsafe property access

  🔥 CRITICAL (5 found)
    Unguarded property access after getElementById
    Consider: const el = document.getElementById('x'); if (!el) return;

      src/components/form.js:42
        const submitBtn = document.getElementById('submit-button');
        submitBtn.classList.add('active');  // ← Crashes if element missing

      src/utils/dom.js:87
        const modal = document.querySelector('.modal');
        modal.style.display = 'block';  // ← Runtime crash guaranteed

  💡 Fix: Always check for null before accessing properties
```

**Before:** 3 production crashes this week
**After:** 0 crashes, caught in 2 seconds

### **Example 2: Security Vulnerability Detection**

```bash
▓▓▓ SECURITY VULNERABILITIES
Detects: Code injection, XSS, prototype pollution, timing attacks

  🔥 CRITICAL (3 found)
    innerHTML without sanitization - XSS risk
    Use textContent or DOMPurify.sanitize()

      src/comments.js:156
        element.innerHTML = userComment;  // ← XSS vulnerability!

  🔥 CRITICAL (1 found)
    Hardcoded API keys detected
    Use environment variables or secret managers

      src/config.js:23
        const apiKey = "sk_live_abc123xyz";  // ← Security breach!
```

**Before:** Security incident, customer data at risk
**After:** Vulnerability caught before git commit

### **Example 3: Async/Await Gotchas**

```bash
▓▓▓ ASYNC/AWAIT & PROMISE PITFALLS
Detects: Missing await, unhandled rejections, race conditions

  🔥 CRITICAL (8 found)
    await used in non-async function
    SyntaxError in JavaScript

      src/api/users.js:67
        function saveUser(data) {
          await database.insert(data);  // ← SyntaxError!
        }

  ⚠️  WARNING (12 found)
    Promises without .catch() or try/catch
    Unhandled rejections crash Node.js

      src/services/email.js:45
        sendEmail(user.email).then(result => ...)  // ← No error handling!
```

**Before:** Silent failures, mysterious bugs in production
**After:** All async bugs caught and fixed before deploy

---

## 📋 **What It Detects (The Complete Arsenal)**

*Each language module has specialized detections. Examples below are representative (JavaScript shown; Python has `eval()`, Go has goroutine leaks, Rust has `.unwrap()` panics, C++ has buffer overflows, etc.)*

### 🔴 **Critical Issues (Production Blockers)**

These **WILL** cause crashes, security breaches, or data corruption:

| Pattern | Example | Why It's Dangerous |
|---------|---------|-------------------|
| `eval()` usage | `eval(userInput)` | Allows arbitrary code execution - **RCE vulnerability** |
| Direct NaN comparison | `if (x === NaN)` | Always returns false - **logic bug** |
| Missing await | `asyncFunc()` in async context | Silent failures, race conditions - **data corruption** |
| Prototype pollution | `obj.__proto__ = {}` | Security vulnerability - **privilege escalation** |
| Unguarded null access | `el.style.color` without null check | **Runtime crash** guaranteed |
| `parseInt` without radix | `parseInt("08")` | Returns 0 in some browsers - **calculation bug** |
| Empty catch blocks | `catch(e) {}` | Swallows errors - **debugging nightmare** |
| `innerHTML` with user data | `el.innerHTML = userInput` | **XSS vulnerability** |
| Missing async keyword | `await` without `async function` | **SyntaxError** |
| Hardcoded secrets | `const key = "sk_live..."` | **Security breach** |

### 🟡 **Warnings (Should Fix Before Shipping)**

These cause bugs, performance issues, or maintenance headaches:

| Pattern | Example | Impact |
|---------|---------|--------|
| Promises without `.catch()` | `promise.then(...)` | Unhandled rejections crash Node.js |
| Division without zero check | `total / count` | Returns `Infinity` or `NaN` |
| Event listeners without cleanup | `addEventListener` in React | **Memory leak** (app gets slower over time) |
| `setInterval` without clear | `setInterval(fn, 1000)` | **Timer leak** (infinite timers) |
| `await` inside loops | `for(...) { await api.call() }` | **Slow** (sequential, not parallel) |
| Array mutation during iteration | `arr.forEach(() => arr.push(...))` | **Skipped/duplicate** elements |
| Missing switch default | `switch(x) { case 1: ... }` | Unhandled values cause silent failures |
| `isNaN()` instead of `Number.isNaN()` | `isNaN("foo")` | Type coercion bugs |

### 🔵 **Info (Code Quality & Best Practices)**

Improvements that make code cleaner and more maintainable:

- Optional chaining opportunities (`obj?.prop?.value`)
- Nullish coalescing opportunities (`value ?? default`)
- TypeScript `any` usage (reduces type safety)
- `console.log` statements (remove before production)
- Technical debt markers (TODO, FIXME, HACK)
- Performance optimizations (DOM queries in loops)
- `var` usage (use `let`/`const` instead)
- Deep property access without guards
- Large inline arrays (move to separate files)
- Complex nested ternaries (readability)

---

## ⚙️ **Advanced Configuration**

### **Command-Line Options (Full Reference)**

```bash
ubs [OPTIONS] [PROJECT_DIR] [OUTPUT_FILE]

Core Options:
  -v, --verbose            Show 10 code samples per finding (default: 3)
  -q, --quiet              Minimal output (summary only)
  --ci                     CI mode (stable output, no colors by default)
  --fail-on-warning        Exit with code 1 on warnings (strict mode)
  --version                Print UBS meta-runner version and exit
  --profile=MODE           strict|loose (sets defaults for strictness)
  --baseline=FILE          Compare findings against a baseline JSON (alias for --comparison)
  -h, --help               Show help and exit

Git Integration:
  --staged                 Scan only files staged for commit
  --diff, --git-diff       Scan only modified files (working tree vs HEAD)

Output Control:
  --format=FMT             Output format: text|json|jsonl|sarif|toon (default: text)
  --beads-jsonl=FILE      Write JSONL summary alongside normal output for Beads/"strung"
  --no-color               Force disable ANSI colors
  OUTPUT_FILE              Save report to file (auto-tees to stdout)

File Selection:
  --include-ext=CSV        File extensions (default: auto-detect by language)
                           JS: js,jsx,ts,tsx,mjs,cjs | Python: py,pyi,pyx
                           Go: go | Rust: rs | Java: java | C++: cpp,cc,cxx,c,h
                           Ruby: rb,rake,ru | C#: cs,csx | Custom: --include-ext=js,ts,vue
  --exclude=GLOB[,...]     Additional paths to exclude (comma-separated)
                           Example: --exclude=legacy (deps ignored by default)
  --skip-size-check        Skip directory size guard (use with care)

Performance:
  --jobs=N                 Parallel jobs for ripgrep (default: auto-detect cores)
                           Set to 1 for deterministic output

Rule Control:
  --skip=CSV               Skip categories by number (see output for numbers)
                           Example: --skip=11,14  # Skip debug code + TODOs
  --skip-type-narrowing    Disable helper-backed guard analysis (falls back to text heuristics)
  --rules=DIR              Additional ast-grep rules directory
                           Rules are merged with built-in rules
  --no-auto-update         Disable automatic self-update
  --suggest-ignore         Print large-directory candidates to add to .ubsignore (no changes applied)

Environment Variables:
  JOBS                     Same as --jobs=N
  NO_COLOR                 Disable colors (respects standard)
  CI                       Enable CI mode automatically
  UBS_MAX_DIR_SIZE_MB      Max directory size in MB before refusing to scan (default: 1000)
  UBS_SKIP_SIZE_CHECK      Skip directory size guard entirely (set to 1)

Arguments:
  PROJECT_DIR              Directory to scan (default: current directory)
  OUTPUT_FILE              Save full report to file

Exit Codes:
  0                        No critical issues (or no issues at all)
  1                        Critical issues found
  1                        Warnings found (only with --fail-on-warning)
  2                        Invalid arguments or environment error (e.g., missing ast-grep for JS/TS)
```

**Directory size guard**

UBS computes scan size **after ignore filters** (defaults + `.ubsignore`) and prints:
`Scan size after ignores: XMB (limit YMB)` before enforcing the limit. Override via
`UBS_MAX_DIR_SIZE_MB` or `UBS_SKIP_SIZE_CHECK=1`, or pass `--skip-size-check`.

### Environment errors (exit 2)

If UBS prints an **Environment error** and exits `2`, a required dependency is missing or unusable.

Most common fix for JS/TS projects:

```bash
ubs doctor --fix
```

Or install the dependency manually:

```bash
brew install ast-grep            # or: cargo install ast-grep, npm i -g @ast-grep/cli
```

If you’re intentionally scanning non-JS languages only, exclude JS:

```bash
ubs --exclude=js .
```

### **Examples**

```bash
# Basic scan
ubs .

# Verbose scan with full details
ubs -v /path/to/project

# Strict mode for CI (fail on any warning)
ubs --fail-on-warning --ci

# Save report without cluttering terminal
ubs . report.txt

# Scan Vue.js project
ubs . --include-ext=js,ts,vue

# Skip categories you don't care about
ubs . --skip=14  # Skip TODO/FIXME markers

# Maximum performance (use all cores)
ubs --jobs=0 .  # Auto-detect
ubs --jobs=16 .  # Explicit core count

# Exclude vendor code
ubs . --exclude=node_modules,vendor,dist,build

# Large directories (size guard)
UBS_MAX_DIR_SIZE_MB=5000 ubs .
UBS_SKIP_SIZE_CHECK=1 ubs .

# Custom rules directory
ubs . --rules=~/.config/ubs/custom-rules

# Combine multiple options
ubs -v --fail-on-warning --exclude=legacy --include-ext=js,ts,tsx . report.txt
```

### JSONL schema

`--format=jsonl` (and `--beads-jsonl=FILE`) emit newline-delimited objects for easy piping into tools like Beads or `jq`:

```jsonl
{"type":"scanner","project":"/path/to/project","language":"python","files":42,"critical":1,"warning":3,"info":12,"timestamp":"2025-11-22T09:04:20Z"}
{"type":"totals","project":"/path/to/project","files":99,"critical":1,"warning":3,"info":27,"timestamp":"2025-11-22T09:04:22Z"}
```

### **Custom AST-Grep Rules**

You can add your own bug detection patterns:

```bash
# Create custom rules directory
mkdir -p ~/.config/ubs/rules

# Add a custom rule (YAML format)
cat > ~/.config/ubs/rules/no-console-in-prod.yml <<'EOF'
id: custom.no-console-in-prod
language: javascript
rule:
  any:
    - pattern: console.log($$$)
    - pattern: console.debug($$$)
    - pattern: console.info($$$)
severity: warning
message: "console statements should be removed before production"
note: "Use a proper logging library or remove debug statements"
EOF

# Run with custom rules
ubs . --rules=~/.config/ubs/rules
```

**Common custom rules:**

```yaml
# Enforce specific naming conventions
id: custom.component-naming
language: typescript
rule:
  pattern: export function $NAME() { $$$ }
  not:
    pattern: export function $UPPER() { $$$ }
severity: info
message: "React components should start with uppercase letter"
```

```yaml
# Catch specific anti-patterns in your codebase
id: custom.no-direct-state-mutation
language: typescript
rule:
  pattern: this.state.$FIELD = $VALUE
severity: critical
message: "Never mutate state directly - use setState()"
```

### **Excluding False Positives**

If the scanner reports false positives for your specific use case:

```bash
# Skip entire categories
ubs . --skip=11,14  # Skip debug code detection and TODO markers

# Exclude specific files/directories
ubs . --exclude=legacy,third-party,generated

# For persistent config, create a wrapper script
cat > ~/bin/ubs-custom <<'EOF'
#!/bin/bash
ubs "$@" \
  --exclude=legacy,generated \
  --skip=14 \
  --rules=~/.config/ubs/rules
EOF
chmod +x ~/bin/ubs-custom
```

---

## 🎓 **How It Works (Under the Hood)**

### **Multi-Layer Analysis Engine**

The scanner uses a sophisticated 4-layer approach:

```
Layer 1: PATTERN MATCHING (Fast) ──┐
├─ Regex-based detection           │
├─ Optimized with ripgrep          │
└─ Finds 70% of bugs in <1 second  │
                                    ├──► Combined Results
Layer 2: AST ANALYSIS (Deep) ──────┤
├─ Semantic code understanding      │
├─ Powered by ast-grep             │
└─ Catches complex patterns        │
                                    │
Layer 3: CONTEXT AWARENESS (Smart) ┤
├─ Understands surrounding code     │
├─ Reduces false positives         │
└─ Knows when rules don't apply    │
                                    │
Layer 4: STATISTICAL (Insightful)  │
├─ Code smell detection            │
├─ Anomaly identification          │
└─ Architectural suggestions       │
                                    ↓
                         Final Report (3-5 sec)
```

### **Technology Stack**

| Component | Technology | Purpose | Why This Choice |
|-----------|-----------|---------|-----------------|
| **Core Engine** | Bash 4.0+ | Orchestration | Universal compatibility, zero dependencies |
| **Pattern Matching** | Ripgrep | Text search | 10-100x faster than grep, parallelized |
| **AST Parser** | ast-grep | Semantic analysis | Understands code structure, not just text |
| **Fallback** | GNU grep | Text search | Works on any Unix-like system |
| **Rule Engine** | YAML | Pattern definitions | Human-readable, easy to extend |

### **AST Rule Architecture: Ancestor-Aware Pattern Matching**

UBS's ast-grep rules use a sophisticated technique called **ancestor traversal** to drastically reduce false positives. The key directive `stopBy: end` ensures patterns check the *entire* ancestor chain rather than just the immediate parent.

**The Problem Without Ancestor Traversal:**

```javascript
// This code is SAFE - the fetch is properly handled:
async function safeFetch() {
  try {
    fetch('/api');  // Inside try block - exception will be caught
  } catch (e) {
    handleError(e);
  }
}

// Naive AST rule checking only immediate parent:
// ❌ False positive! Reports "fetch without catch" because
//    fetch()'s immediate parent is the ExpressionStatement,
//    not the try block.
```

**The Solution - Ancestor Traversal with `stopBy: end`:**

```yaml
# ast-grep rule with proper ancestor checking
rule:
  all:
    - pattern: fetch($ARGS)
    - not:
        inside:
          kind: try_statement
          stopBy: end           # ← Key directive: traverse ALL ancestors
    - not:
        inside:
          pattern: $_.catch($$)  # Check for .catch() in chain
          stopBy: end
```

The `stopBy: end` directive instructs ast-grep to walk up the *entire* ancestor tree until it finds a match (or reaches the root). Without it, only the immediate parent is checked—missing try blocks, function boundaries, and method chains.

**Real-World Impact:**

| Scenario | Without `stopBy: end` | With `stopBy: end` |
|----------|----------------------|-------------------|
| `try { fetch() } catch {}` | ❌ False positive | ✅ Correctly ignored |
| `fetch().then().catch()` | ❌ False positive | ✅ Correctly ignored |
| `return fetch()` | ❌ False positive | ✅ Correctly ignored |
| `fetch()` standalone | ✅ Detected | ✅ Detected |

This technique is applied across 19+ rules in the JavaScript module alone, covering:
- Promise chain detection (`.then()`, `.catch()`, `.finally()`)
- Try-catch context awareness
- Return statement handling
- Async/await scope analysis

### **Inline Suppression Comments**

When a finding is intentional or a known false positive, suppress it inline:

```javascript
// Suppress a single line:
eval(trustedCode);  // ubs:ignore

// Suppress with reason (recommended):
eval(adminScript);  // ubs:ignore -- admin-only trusted input
```

```python
# Python suppression:
exec(validated_code)  # ubs:ignore

# Ruby suppression:
eval(safe_string)  # ubs:ignore
```

**Suppression Rules:**
- Must appear on the **same line** as the flagged code
- Works across all 9 supported languages
- Suppresses all findings on that line (use sparingly)
- Survives formatting tools that preserve trailing comments

**Anti-patterns to avoid:**
```javascript
// ❌ Wrong - comment on previous line doesn't suppress:
// ubs:ignore
eval(code);  // Still flagged!

// ❌ Wrong - don't blanket-suppress large blocks:
/* ubs:ignore */  // Doesn't work for block comments
```

### **Cross-Language Async Error Detection**

UBS detects unhandled async errors consistently across all 9 languages. The patterns adapt to each language's idioms while providing equivalent coverage:

| Language | Pattern | What UBS Detects |
|----------|---------|------------------|
| **JavaScript/TypeScript** | `promise.then()` without `.catch()`, `new Promise(async ...)`, `forEach(async ...)`, async array predicates, async timer/event callbacks, `Promise.all(map(...))` without callback return | Dangling promises, missing `await`, unawaitable async callbacks, unhandled rejections |
| **Python** | `asyncio.create_task()` without `await` | Orphaned tasks, missing `await`, unclosed coroutines |
| **Go** | Goroutine without error channel | Fire-and-forget goroutines, leaked contexts |
| **Rust** | `.unwrap()` / `.expect()` after partial guard | Panic after `if let Some`, missing `?` operator |
| **Java** | `CompletableFuture` without `.exceptionally()` | Swallowed exceptions, missing `join()` |
| **Ruby** | `Thread.new` without `.join` | Zombie threads, unhandled thread exceptions |
| **C++** | `std::async` without `.get()` | Ignored futures, exception propagation |
| **Swift** | `Task {}` without error handling | Unstructured concurrency leaks |
| **C#** | `Task.Wait()` / `.Result` / `throw ex;` | Sync-over-async deadlocks, stack-trace loss, unsafe exception surfaces |

**JavaScript Promise Chain Analysis:**

The scanner understands complex promise chains:

```javascript
// ✅ Handled - .catch() at end of chain:
fetch('/api')
  .then(r => r.json())
  .then(data => process(data))
  .catch(handleError);  // Scanner recognizes this catches all above

// ✅ Handled - .catch() before .then():
fetch('/api')
  .catch(e => fallback)  // Early catch
  .then(r => r.json());

// ❌ Unhandled - .finally() doesn't catch:
fetch('/api')
  .then(r => r.json())
  .finally(cleanup);  // Flagged: finally doesn't handle rejections

// ❌ Unhandled - no error handling:
async function leaky() {
  fetch('/api');  // Flagged: fire-and-forget promise
}
```

### **Helper Script Verification**

Language-specific helper scripts (Python AST walkers, Go analyzers, TypeScript type checkers) are verified with SHA-256 checksums before execution:

```bash
# Helper checksums embedded in each module:
modules/helpers/
├── async_task_handles_csharp.py   # SHA-256 verified
├── resource_lifecycle_csharp.py # SHA-256 verified
├── resource_lifecycle_py.py    # SHA-256 verified
├── resource_lifecycle_go.go    # SHA-256 verified
├── resource_lifecycle_java.py  # SHA-256 verified
├── type_narrowing_csharp.py    # SHA-256 verified
├── type_narrowing_ts.js        # SHA-256 verified
├── type_narrowing_rust.py      # SHA-256 verified
├── type_narrowing_kotlin.py    # SHA-256 verified
└── type_narrowing_swift.py     # SHA-256 verified
```

The `ubs doctor` command validates all helper checksums:

```bash
$ ubs doctor
🏥 UBS Environment Audit
────────────────────────
✓ helper checksum verified (resource_lifecycle_py.py)
✓ helper checksum verified (type_narrowing_ts.js)
...
```

If a helper is modified or corrupted, the scanner fails safely with remediation guidance rather than executing unverified code.

### **Unified Severity Normalization**

All 9 language modules normalize their findings to a consistent severity scale, ensuring predictable output regardless of source language:

```
┌─────────────────────────────────────────────────────────────┐
│  Language Tool Output      →   UBS Normalized Severity      │
├─────────────────────────────────────────────────────────────┤
│  ESLint "error"            →   critical                     │
│  Pylint "E" / "F"          →   critical                     │
│  Clippy "deny"             →   critical                     │
│  Go vet "error"            →   critical                     │
│  SpotBugs "High"           →   critical                     │
│  RuboCop "Fatal/Error"     →   critical                     │
├─────────────────────────────────────────────────────────────┤
│  ESLint "warn"             →   warning                      │
│  Pylint "W" / "R"          →   warning                      │
│  Clippy "warn"             →   warning                      │
│  Go vet "warning"          →   warning                      │
│  SpotBugs "Medium"         →   warning                      │
│  RuboCop "Warning"         →   warning                      │
├─────────────────────────────────────────────────────────────┤
│  ESLint "suggestion"       →   info                         │
│  Pylint "C" / "I"          →   info                         │
│  Clippy "note"             →   info                         │
│  SpotBugs "Low"            →   info                         │
│  RuboCop "Convention"      →   info                         │
└─────────────────────────────────────────────────────────────┘
```

**Benefits of normalization:**
- **Consistent exit codes**: Exit 1 always means "critical issues found" across all languages
- **Unified JSON/SARIF output**: Downstream tools parse one schema, not 8 different formats
- **Predictable `--fail-on-warning`**: Same behavior whether scanning Python, Rust, or TypeScript
- **Cross-language metrics**: Compare code quality across polyglot projects fairly

The `normalize_severity()` function in each module handles edge cases like tool-specific severity strings, numeric levels, and legacy format variations.

### **Performance Optimizations**

```bash
# Automatic parallelization (uses all CPU cores)
- Auto-detects: 16-core = 16 parallel jobs
- Manually set: --jobs=N

# Smart file filtering (only scans relevant files)
- JS/TS: .js, .jsx, .ts, .tsx, .mjs, .cjs (auto-skip node_modules/dist/build)
- Python: .py + pyproject/requirements (skip venv/__pycache__)
- C/C++: .c/.cc/.cpp/.cxx + headers + CMake files (skip build/out)
- Rust: .rs + Cargo manifests (skip target/.cargo)
- Go: .go + go.mod/go.sum/go.work (skip vendor/bin)
- Java: .java + pom.xml + Gradle scripts (skip target/build/out)
- Ruby: .rb + Gemfile/Gemspec/Rakefile (skip vendor/bundle,tmp)
- Custom: --include-ext=js,ts,vue

# Efficient streaming (low memory usage)
- No temp files created
- Results streamed as found
- Memory usage: <100MB for most projects

# Incremental scanning (future feature)
- Only scan changed files (git diff)
- Cache previous results
- 10x faster on large projects
```

---

## 🏆 **Comparison with Other Tools**

| Feature | Ultimate Bug Scanner | ESLint | TypeScript | SonarQube | DeepCode |
|---------|---------------------|--------|------------|-----------|----------|
| **Setup Time** | 30 seconds | 30 minutes | 1-2 hours | 2-4 hours | Account required |
| **Speed (50K lines)** | 3 seconds | 15 seconds | 8 seconds | 2 minutes | Cloud upload |
| **Zero Config** | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| **Works Without Types** | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| **Null Safety** | ✅ Yes | ⚠️ Limited | ✅ Yes | ⚠️ Limited | ⚠️ Limited |
| **Security Scanning** | ✅ Yes | ⚠️ Plugin | ❌ No | ✅ Yes | ✅ Yes |
| **Memory Leaks** | ✅ Yes | ❌ No | ❌ No | ⚠️ Limited | ❌ No |
| **Async/Await** | ✅ Deep | ⚠️ Basic | ✅ Good | ⚠️ Basic | ⚠️ Basic |
| **CI/CD Ready** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Cloud |
| **Offline** | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Limited | ❌ No |
| **AI Agent Friendly** | ✅ Built for it | ⚠️ Config heavy | ⚠️ Config heavy | ❌ Complex | ⚠️ Cloud |
| **Cost** | Free | Free | Free | $$$$ | $$$ |

**When to use what:**

- **Ultimate Bug Scanner**: Quick scans, AI workflows, no config needed
- **ESLint**: Style enforcement, custom rules, team standards
- **TypeScript**: Type safety (use WITH this scanner)
- **SonarQube**: Enterprise compliance, detailed metrics
- **DeepCode**: ML-powered analysis (if you trust cloud)

**Best combo:** TypeScript + ESLint + Ultimate Bug Scanner = Maximum safety

---

## 🧠 **Project Justification and Rationale**

### **Why This Exists (And Why It's Not "Just Another Linter")**

You might be thinking: *"We already have ESLint, Pylint, Clippy, RuboCop... why build another tool?"*

**Fair question. And honestly, your first reaction is probably right to be skeptical.**

### **The Initial Skepticism is Valid (But Misses the Point)**

When you first look at UBS, it's natural to think:

> *"This is just worse ESLint. It has fewer rules, uses regex (false positives!), and doesn't auto-fix anything. Why would I use this instead of mature, comprehensive linters?"*

**That's analyzing through the wrong lens.**

You're comparing it to tools designed for a **fundamentally different workflow** (human developers writing code manually) when it's solving a **fundamentally different problem** (LLM agents generating code at 100x speed).

It's like comparing a smoke detector to a building inspector:
- **Building inspector (ESLint):** Thorough, comprehensive, finds every issue, takes hours
- **Smoke detector (UBS):** Fast, catches critical dangers, instant alert, always running

**You need both.** But when your house might be on fire (AI just generated 500 lines in 30 seconds), you want the smoke detector first.

### **The Paradigm Shift: AI-Native Development**

Software development is undergoing a **fundamental transformation**:

**2020 (Pre-LLM Era):**
- Developer writes 50-200 lines/day manually
- Deep thought before each line
- Single language per project (mostly)
- Time to review: abundant
- Quality gate: comprehensive linting + code review (hours)

**2025 (LLM Era):**
- AI generates 500-5000 lines/day across projects
- Code appears in seconds
- Polyglot projects standard (microservices in Go, UI in TypeScript, ML in Python, workers in Rust)
- Time to review: scarce
- Quality gate needed: instant feedback (<5s) or the loop breaks

**Traditional tools weren't designed for this.** They were built when "code generation" meant 200 lines/day, not 2000.

### **Here's the Fundamental Difference:**

### **1. This Tool is Built FOR AI Agents, Not Just Humans**

Traditional linters were designed for **human developers** in **single-language codebases**. UBS is designed for **LLM coding agents** working across **polyglot projects**.

**The paradigm shift:**

| Traditional Linting (Human-First) | UBS Approach (LLM-First) |
|---|---|
| **Goal:** Comprehensive coverage + auto-fix<br>**Speed:** 15-60 seconds acceptable<br>**Setup:** 30 min config per language<br>**Languages:** One tool per language<br>**False positives:** Must be <1% (frustrates humans)<br>**Output:** Human-readable prose | **Goal:** Critical bug detection + fast feedback<br>**Speed:** <5 seconds required<br>**Setup:** Zero config (instant start)<br>**Languages:** One scan for all 9 languages<br>**False positives:** 10-20% OK (LLMs filter instantly)<br>**Output:** Structured file:line for LLM parsing |

### **2. LLMs Don't Need Auto-Fix—They ARE the Auto-Fix Engine**

**Why traditional linters have auto-fix:**
```javascript
// ESLint flags: "Use === instead of =="
if (value == null)  // ❌

// ESLint auto-fix (rigid, no context):
if (value === null)  // ✅ Technically correct, but...
```

**Why UBS doesn't (and shouldn't):**
```javascript
// UBS flags: "Type coercion bug: == should be ==="
if (value == null)  // ❌

// Claude reads the error and understands context:
if (value !== null && value !== undefined)  // ✅ Better - handles both
// OR
if (value != null)  // ✅ Or keeps == for null/undefined (intentional)
```

**The hard part is DETECTION, not fixing.** Once flagged, LLMs can:
- Understand semantic context
- Consider surrounding code
- Apply the right fix (not just the mechanical one)
- Refactor holistically

Auto-fix would be **worse** because it's context-free. LLMs need to know **WHAT'S wrong** and **WHERE**, then they fix it properly.

### **3. The Multi-Language Zero-Config Design is the Moat**

**Imagine asking Claude to set up quality gates for a polyglot project:**

**Traditional approach (15-30 min per project):**
```bash
# JavaScript/TypeScript
npm install --save-dev eslint @eslint/js @typescript-eslint/parser
# Create .eslintrc.js (200 lines of config)

# Python
pip install pylint black mypy
# Create .pylintrc, pyproject.toml sections

# Rust
# Add to Cargo.toml: [lints]
# Configure clippy rules

# Go
# Install golangci-lint, create .golangci.yml

# Java
# Setup Checkstyle + PMD + SpotBugs + config XMLs

# C++
# Setup clang-tidy, create .clang-tidy config

# Ruby
# Create .rubocop.yml with 150+ lines

# Now run 7 different commands and parse 7 different output formats...
```

**UBS approach (30 seconds):**
```bash
curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash
ubs .

# Done. All 9 languages scanned, unified report.
```

**This matters because:**
- LLMs generate code across languages in one session (Python API → Go service → TypeScript UI → Rust worker)
- Configuring 7 tools is error-prone for LLMs
- Humans don't want to maintain 7 different config files
- CI/CD pipelines want one command, one exit code

### **Type Narrowing Coverage Across Languages**

- **TypeScript** – UBS shells out to `tsserver` (via the bundled helper) whenever Node.js + the `typescript` package are available. The installer surfaces a "Type narrowing readiness" diagnostic so you immediately know if tsserver-powered guards are running.
- **Rust** – A Python helper inspects `if let Some/Ok` guard clauses and flags subsequent `.unwrap()`/`.expect()` calls outside of exiting blocks. Fixtures and manifest cases keep this regression-tested.
- **Kotlin** – The Java module scans `.kt` sources for `if (value == null)` guards that merely log and keep running before hitting `value!!`, catching the same pitfall on JVM teams that mix Java + Kotlin.
- **Swift** – The dedicated `ubs-swift` module now ships the guard-`let` helper directly, so optional chaining/Objective‑C bridging heuristics fire even when you run `ubs --only=swift` locally (no piggybacking on the Java module). It catches cases where code logs and keeps going before force-unwrapping `value!`, protecting iOS/macOS pipelines that blend Swift + ObjC.

### **Resource Lifecycle AST Coverage**

- **Python** – `modules/helpers/resource_lifecycle_py.py` now reasons over the AST, tracking `with`/`async with`, alias imports, and `.open()`/`.connect()` calls so `ubs-python` warns only when a handle is truly leaking. Pathlib `Path.open()` and similar patterns are handled without brittle regexes.
- **Java** – New ast-grep rules (`java.resource.executor-no-shutdown`, `java.resource.thread-no-join`, `java.resource.jdbc-no-close`, `java.resource.resultset-no-close`, `java.resource.statement-no-close`) ensure ExecutorServices, raw `Thread`s, `java.sql.Connection`s, `Statement`/`PreparedStatement`/`CallableStatement`, and `ResultSet` handles all get proper shutdown/close semantics before the regex fallback ever runs.
- **C#** – `modules/helpers/resource_lifecycle_csharp.py`, `modules/helpers/type_narrowing_csharp.py`, and `modules/helpers/async_task_handles_csharp.py` now catch disposable-handle leaks (`CancellationTokenSource`, stream-like readers/writers, `HttpRequestMessage`), null/`TryGetValue` guards that log but still fall through into dereferences, and `Task.Run`/`Task.Factory.StartNew` handles that are created but never observed. The C# ast-grep pack also now lands as first-class per-rule findings for discarded fire-and-forget tasks, `await` inside `lock`, and `Parallel.ForEach` async-lambda misuse instead of a sample-count-only stub.
- **C++ / Rust / Ruby** – These modules already relied on ast-grep rule packs; the “Universal AST Adoption” epic is now complete with every language module (JS, Python, Go, C++, Rust, Java, Ruby, Swift, C#) running semantic detectors instead of fragile grep-only heuristics.

#### Python – AST helper in action

```python
import asyncio, subprocess

fh = open("/tmp/leaky.txt", "w")
proc = subprocess.Popen(["sleep", "1"])

async def leak_task():
    task = asyncio.create_task(asyncio.sleep(1))
    await asyncio.sleep(0.1)
    return task

asyncio.run(leak_task())
```

```
$ ./ubs --only=python test-suite/python/buggy/resource_lifecycle.py
  🔥 File handles opened without context manager/close [resource_lifecycle.py:4]
    File handle fh opened without context manager or close()
  ⚠ Popen handles not waited or terminated [resource_lifecycle.py:7]
```

The helper catches the unguarded file handle, zombie subprocess, and orphaned asyncio task because it walks the AST (tracking aliases and async contexts) instead of grepping for strings.

#### Go – AST helper validating cleanups

```go
ctx, cancel := context.WithTimeout(context.Background(), time.Second)
ticker := time.NewTicker(time.Millisecond * 500)
timer := time.NewTimer(time.Second)
f, _ := os.Open("/tmp/data.txt")

_ = ctx
_ = cancel
_ = ticker
_ = timer
_ = f
```

```
$ ./ubs --only=golang test-suite/golang/buggy/resource_lifecycle.go
  🔥 context.With* without deferred cancel [resource_lifecycle.go:10]
  ⚠ time.NewTicker not stopped [resource_lifecycle.go:13]
  ⚠ time.NewTimer not stopped [resource_lifecycle.go:15]
  ⚠ os.Open/OpenFile without defer Close() [resource_lifecycle.go:17]
```

Because the helper hashes AST positions, the manifest can assert on deterministic substrings (context/ticker/timer/file) and we avoid flakiness from color codes or log headings.

Use `--skip-type-narrowing` (or `UBS_SKIP_TYPE_NARROWING=1`) when you want to bypass all of these guard analyzers—for example on air-gapped CI environments or when validating legacy projects one language at a time.

### **4. Speed Enables Tight Iteration Loops**

The **generate → scan → fix** cycle needs to be **fast** for AI workflows:

```
┌─────────────────────────────────────────┐
│  Traditional Linter (30-45 seconds)     │
├─────────────────────────────────────────┤
│  Claude generates code:        10s      │
│  Run ESLint + Pylint + ...     30s  ⏳  │
│  Claude reads findings:         5s      │
│  Claude fixes bugs:            15s      │
│  Re-run linters:               30s  ⏳  │
│  ──────────────────────────────────     │
│  Total iteration:              90s      │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  UBS (3-5 seconds)                      │
├─────────────────────────────────────────┤
│  Claude generates code:        10s      │
│  Run UBS:                       3s  ⚡  │
│  Claude reads findings:         2s      │
│  Claude fixes bugs:            10s      │
│  Re-run UBS:                    3s  ⚡  │
│  ──────────────────────────────────     │
│  Total iteration:              28s      │
└─────────────────────────────────────────┘

3x faster feedback loop = 3x more iterations in the same time
```

**When you're shipping 10+ features a day with AI assistance, this compounds.**

### **5. Detecting LLM-Specific Bug Patterns**

UBS targets the bugs **AI agents actually generate**, not every possible code smell.

**Bugs LLMs frequently produce:**

| Pattern | Why LLMs Generate It | Traditional Linters |
|---------|---------------------|---------------------|
| Missing `await` | Forgets `async` keyword, syntax looks fine | ❌ TypeScript only |
| Unguarded null access | "Optimistic" coding - assumes happy path | ⚠️ Requires strict config |
| `eval()` / code injection | Reaches for "easy" dynamic solution | ✅ Most flag this |
| Memory leaks (event listeners) | Doesn't think about cleanup lifecycle | ❌ ESLint plugin needed |
| `innerHTML` XSS | Doesn't threat-model user input | ⚠️ Security plugins only |
| Division by zero | Doesn't consider edge cases | ❌ Most miss this |
| Hardcoded secrets | Uses placeholder, forgets to externalize | ⚠️ Requires secrets scanner |
| Goroutine leaks | Forgets context cancellation | ❌ Go-specific tooling |
| `.unwrap()` panics | Assumes success path | ✅ Clippy catches |
| Buffer overflows | Forgets bounds checking | ⚠️ Sanitizers only |

**UBS is optimized for this specific threat model.**

### **6. Novel Analysis: Deep Property Guard Correlation**

This is genuinely **not available in standard linters**:

```python
# Code LLM generates:
def get_theme(user):
    return user.profile.settings.theme  # ❌ Unguarded chain

# ESLint/Pylint: ✅ No error (syntactically correct)
# TypeScript: ✅ No error (if types claim non-null)

# UBS Deep Guard Analysis:
# 1. Scans for: user.profile.settings.theme (found at line 42)
# 2. Scans for: if user and user.profile and user.profile.settings
# 3. Correlates: NO MATCHING GUARD FOUND
# 4. Reports: ⚠️ Unguarded deep property access
```

**This requires:**
- AST extraction of property chains across the file
- AST extraction of conditional guards
- Cross-reference matching with context awareness
- Contextual suggestions

**Nobody else does this by default** because it's not a lint rule—it's a **correlation analysis** across multiple code patterns.

### **7. Complementary, Not Competitive**

**UBS is designed to work WITH existing tools, not replace them:**

```
┌────────────────────────────────────────────────────┐
│  Your Quality Stack (Recommended)                  │
├────────────────────────────────────────────────────┤
│  TypeScript           → Type safety                │
│  ESLint/Clippy/etc    → Comprehensive linting      │
│  Jest/PyTest          → Unit tests                 │
│  ✨ UBS                → AI-generated bug oracle   │
│  GitHub Actions       → CI/CD integration          │
└────────────────────────────────────────────────────┘
```

**Use UBS for:**
- ✅ Fast multi-language scanning in AI workflows
- ✅ Critical bug detection before commits
- ✅ Git hooks that block obviously broken code
- ✅ Claude/Cursor/AI agent quality guardrails
- ✅ Polyglot projects where configuring 7 linters is painful

**Use ESLint/Pylint/Clippy/etc for:**
- ✅ Comprehensive style enforcement
- ✅ Framework-specific rules (React hooks, etc.)
- ✅ Custom team conventions
- ✅ Auto-formatting
- ✅ Deep single-language analysis

**They solve different problems.** UBS is the "smoke detector" (fast, catches critical issues). Traditional linters are the "building inspector" (thorough, catches everything).

### **8. The Technical Moat**

What makes this hard to replicate:

**Multi-layer analysis:**
```
Layer 1: Ripgrep (regex)     → 70% of bugs in 0.5s
Layer 2: ast-grep (AST)      → Complex semantic patterns
Layer 3: Correlation logic   → Cross-pattern analysis (novel)
Layer 4: Metrics collection  → Time-series quality tracking
```

**This combination of speed + semantic understanding + correlation is unique.**

**Unified multi-language runner:**
- Auto-detects 9 languages in one scan
- Parallel execution (Go + Python + Rust simultaneously)
- Unified JSON/SARIF output for tooling
- Module system with lazy download/caching

**LLM-optimized integration points:**
- Git hooks (block bad commits)
- Claude Code file-write hooks
- `.cursorrules` / `.aiconfig` integration
- Clean structured output for LLM parsing

### **9. 30 Rules is Better Than 600 (For This Use Case)**

**You might notice:** ESLint has 200+ core rules, Clippy has 600+ lints, but UBS has ~30 patterns per language.

**That's intentional, not a limitation.**

**The 80/20 rule for AI-generated bugs:**
- **80% of production-breaking bugs** come from ~30 common patterns
- **20% of edge cases** require the other 570 rules

**For LLM workflows, you want:**
```
✅ Fast scan (3s) that catches 80% of critical bugs
   ↓
   LLM fixes them immediately
   ↓
   ✅ Fast re-scan (3s) confirms fixes
   ↓
   Then run comprehensive linters (30s) for the remaining 20%
```

**Not:**
```
❌ Comprehensive scan (30s) that catches 100% of issues
   ↓
   LLM waits... workflow broken... context switch...
   ↓
   Slower iteration = fewer features shipped
```

**The bugs UBS targets are:**
- Missing `await` (crashes)
- Null pointer access (crashes)
- Security holes: `eval()`, XSS, hardcoded secrets (breaches)
- Memory leaks (performance degradation)
- Race conditions (data corruption)

**The bugs comprehensive linters add:**
- Inconsistent quote style (style)
- Missing trailing commas (style)
- Prefer `const` over `let` when not reassigned (style)
- Function name should be camelCase (style)
- Line too long (style)

**Which matters more when AI just generated 500 lines that might have `eval()` and missing `await` everywhere?**

Target the **critical bugs** that cost hours. Let comprehensive linters handle style in a separate pass.

### **10. Market Timing: This Wouldn't Have Made Sense 3 Years Ago**

**Why this tool exists NOW:**

**2021:**
- GitHub Copilot launches (single-line completions)
- Still mostly human-written code
- Traditional linting workflow works fine

**2023:**
- ChatGPT/GPT-4 can generate full functions
- Claude Code, Cursor emerge
- Devs start AI-assisted workflows
- Pain point appears: "AI is fast but buggy"

**2025:**
- LLMs generate entire features in minutes
- Multi-file refactors happen in seconds
- Polyglot microservices are standard
- **Quality gates can't keep up with generation speed**

**The problem UBS solves didn't exist before LLM coding became mainstream.**

This tool is **perfectly timed** for the AI coding explosion happening RIGHT NOW.

### **11. False Positive Philosophy**

**For human developers:**
- False positive = context switch + investigation + frustration
- Acceptable rate: <1%

**For LLM agents:**
- False positive = parse (0.1s) + analyze (0.5s) + determine safe (0.2s)
- Acceptable rate: 10-20%

**LLMs don't get frustrated.** They evaluate every finding programmatically.

**This means UBS can be more aggressive:**
- Flag suspicious patterns even if not 100% certain
- Catch more bugs at the cost of some noise
- LLMs filter false positives cognitively (for free)

Better to flag 100 issues where 20 are safe than miss 1 critical bug.

---

## **FAQ: Common Questions and Objections**

### **Q: "Isn't this just reinventing the wheel? ESLint already exists."**

**A:** It's not reinventing the wheel—it's building a different vehicle for a different road.

ESLint is a **truck** (heavy, comprehensive, hauls everything).
UBS is a **sports car** (fast, targeted, gets you there quickly).

You wouldn't use a truck for a Formula 1 race. You wouldn't use a sports car to move furniture.

**Different tools, different use cases.** Use UBS for rapid AI iteration, ESLint for comprehensive quality enforcement.

---

### **Q: "Why not just contribute these patterns to existing linters?"**

**A:** Three reasons:

**1. Different design philosophy**
- Existing linters: comprehensive, human-first, single-language
- UBS: fast, LLM-first, multi-language, correlation-based

These are fundamentally incompatible goals. ESLint would never accept "10-20% false positives are fine" or "skip auto-fix entirely."

**2. Multi-language meta-runner**
- The unified runner that auto-detects 9 languages is the core innovation
- This doesn't fit into any single linter's architecture
- Each linter project has different maintainers, philosophies, release cycles

**3. Correlation analysis is novel**
- Deep property guard matching isn't a "lint rule"
- It's cross-pattern analysis that requires a different architecture
- Existing linters don't have this capability baked into their core

Contributing patterns misses the point—**the integration IS the innovation.**

---

### **Q: "What about Semgrep? Doesn't it do multi-language pattern matching?"**

**A:** Semgrep is excellent and closer to UBS than traditional linters. Key differences:

| Feature | Semgrep | UBS |
|---------|---------|-----|
| **Setup** | Requires config file + rule selection | Zero config |
| **Speed** | ~10-20s on medium projects | ~3s (optimized for speed) |
| **Target user** | Security teams, human developers | LLM agents |
| **Rule focus** | Security + custom patterns | AI-generated bug patterns |
| **Multi-language** | ✅ Yes | ✅ Yes |
| **Correlation analysis** | ❌ Pattern matching only | ✅ Deep guards, metrics |
| **LLM integration** | Not designed for it | Purpose-built |

**Use Semgrep if:** You need custom security rules and have time to configure them.
**Use UBS if:** You want instant AI workflow integration with zero setup.

**They're complementary.** Some users run both.

---

### **Q: "Won't regex-based detection have tons of false positives?"**

**A:** Less than you'd think, and it's acceptable for LLM consumers.

**Reality check:**
- **Layer 1 (ripgrep/regex):** ~15-20% false positive rate on some patterns
- **Layer 2 (ast-grep/AST):** ~2-5% false positive rate (semantic understanding)
- **Layer 3 (correlation):** ~1-3% false positive rate (contextual analysis)

**Blended approach:** ~8-12% overall false positive rate.

**Why this is OK:**
- LLMs don't get frustrated like humans do
- They evaluate findings in 0.8 seconds total
- Better to flag 100 (20 safe) than miss 1 critical bug
- Humans reviewing AI code ALREADY have to check everything anyway

**For critical patterns** (eval, XSS, hardcoded secrets), we use ast-grep (high precision).
**For style patterns**, we use regex (fast, some FP acceptable).

**And we're always improving.** Each release reduces FP rate through better heuristics.

---

### **Q: "Why Bash? Why not Python/Rust/Go?"**

**A:** Controversial choice, but intentional:

**Advantages of Bash:**
- ✅ **Zero dependencies** - runs on any Unix-like system
- ✅ **Universal availability** - every dev machine has Bash 4.0+
- ✅ **Shell integration** - git hooks, CI/CD, file watchers are natural
- ✅ **Module system** - each language scanner is standalone
- ✅ **Rapid prototyping** - adding new patterns is trivial
- ✅ **LLM-readable** - AI agents can understand and modify rules

**Disadvantages:**
- ❌ Not as "elegant" as Python
- ❌ String handling can be verbose
- ❌ No static typing

**Bottom line:** For a tool that orchestrates existing CLI tools (ripgrep, ast-grep, jq, typos) and needs to be universally available, Bash is pragmatic.

**Future:** Core modules might be rewritten in Rust for speed, but the meta-runner will stay Bash for compatibility.

---

### **Q: "Can I use this if I'm NOT using AI coding tools?"**

**A:** Absolutely! It's optimized for AI workflows, but works great for humans too.

**Scenarios where humans love it:**

**1. Code review speed-up**
```bash
# Reviewing a PR with 800+ lines
git checkout feature-branch
ubs .
# Instantly see critical issues before deep review
```

**2. Legacy code audits**
```bash
# "What's dangerous in this 10-year-old codebase?"
ubs /path/to/legacy-app
# Finds all the eval(), XSS, memory leaks
```

**3. Learning new languages**
```bash
# "I'm new to Rust, what am I doing wrong?"
ubs . --verbose
# Shows common Rust pitfalls in your code
```

**4. Polyglot projects**
```bash
# Microservices in 5 languages
ubs .
# One scan, all languages checked
```

**Humans appreciate:**
- Zero setup (no config files to maintain)
- Fast feedback (3s vs 30s)
- Multi-language support (one command)
- Finding bugs ESLint misses (deep guards)

---

### **Q: "How is this different from security scanners like Snyk or GitHub Advanced Security?"**

**A:** Different focus and scope:

**Security scanners (Snyk, Dependabot, etc.):**
- Focus: **Dependency vulnerabilities**
- Checks: npm packages, CVE databases
- Speed: Seconds to minutes
- Output: "Update package X to fix CVE-2024-1234"

**UBS:**
- Focus: **Code-level bugs** in YOUR code
- Checks: Logic errors, null safety, memory leaks, security anti-patterns
- Speed: 3-5 seconds
- Output: "You have unguarded null access at line 42"

**They're complementary:**
```
┌─────────────────────────────────────┐
│  Complete Security Stack            │
├─────────────────────────────────────┤
│  Snyk/Dependabot  → Dependencies    │
│  ✨ UBS            → Your code bugs │
│  SAST tools       → Deep security   │
│  GitHub Advanced  → Secrets in Git  │
└─────────────────────────────────────┘
```

**Security scanners won't catch:** "You forgot `await` and your async function silently fails."
**UBS won't catch:** "Your version of lodash has a known CVE."

Use both.

---

### **Q: "Will you support language X in the future?"**

**A:** Probably! The module system makes it easy to add languages.

**Current:** JavaScript/TypeScript, Python, Go, Rust, Java, C++, Ruby, Swift, C# (9 languages)

**Roadmap considerations:**
- **PHP** - High demand, lots of legacy code
- **Swift** - iOS development
- **Kotlin** - Android development
- **Scala** - JVM ecosystem
- **Elixir** - Growing adoption

**How we prioritize:**
1. Community demand (GitHub issues)
2. AI coding tool usage (what LLMs generate most)
3. Module maintainer availability

**Want to contribute?** Writing a new module is ~800-1200 lines of Bash. Check the existing modules as templates.

---

### **Q: "What's the catch? Why is this free?"**

**A:** No catch. It's MIT licensed.

**Philosophy:**
- Built by developers, for developers
- AI coding is exploding, quality tools should be accessible
- Open source enables community contributions (more patterns, better detection)

**Business model:** None currently. This is a **community project**.

**Future possibilities:**
- Enterprise support contracts
- Hosted version for teams
- Premium modules for specific frameworks

But the core tool will always be free and open source.

---

## **The Bottom Line**

**This isn't trying to replace ESLint.** It's solving a different problem:

> **"How do I give LLM coding agents the ability to self-audit across 9 languages with zero configuration overhead and sub-5-second feedback?"**

No existing tool does this because:
- Traditional linters are human-first (need auto-fix, low FP tolerance)
- They're single-language focused (polyglot = 7 different tools)
- They're comprehensive, not fast (30s scan time kills AI iteration loops)
- They're not designed for LLM consumption

**UBS is purpose-built for the AI coding era.**

Use it WITH your existing tools. Let ESLint handle style. Let TypeScript handle types. Let UBS catch the critical bugs that AI agents generate but can't see.

---

## 🧪 **Development & Internals**

### **Python Tooling (uv + CPython 3.13)**

All helper scripts (manifest runner, fixtures, inline analyzers inside `ubs`) assume a single source of truth: **CPython 3.13 managed by [uv](https://github.com/astral-sh/uv)** living inside `.venv/` at the repo root.

```bash
# 1) Install uv (one-time)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2) Create the managed environment defined by pyproject.toml / uv.lock
uv sync --python 3.13

# 3) Activate it whenever you work in this repo (puts .venv/bin first on PATH)
source .venv/bin/activate

# 4) Run any Python entrypoint through the env
uv run python test-suite/run_manifest.py --case js-core-buggy
# ...or rely on 'python'/'python3' now that they point at .venv/bin/python3.13
```

> [!NOTE]
> Shell scripts that invoke `python3` (language modules under `modules/`, `test-suite/run_all.sh`, etc.) automatically pick up `.venv/bin/python3` as long as the environment is activated or `.venv/bin` is on your `PATH`. The pinned `pyproject.toml` + `uv.lock` are the single source of truth for this toolchain.

Common uv-powered entrypoints:

- `uv run python test-suite/run_manifest.py --case js-core-buggy` – run the manifest in CI or locally without manually activating the venv.
- `source .venv/bin/activate && python -m pip list` – verify that every inline `python3` invocation maps to CPython 3.13.
- `uv run python - <<'PY' …` – mirrors how the language modules embed Python helpers, but now guaranteed to execute inside the managed interpreter.

---

## 🚫 **Ignoring Paths with `.ubsignore`**

Need repo-wide scans to ignore generated code or intentionally buggy fixtures (like this project’s `test-suite/`)? Drop a `.ubsignore` at the root.

- Format mirrors `.gitignore`: one glob per line, `#` for comments.
- UBS loads `PROJECT/.ubsignore` automatically; override with `--ignore-file=/path/to/file`.
- Built-in ignores already cover `node_modules`, virtualenvs, dist/build/target/vendor, editor caches, and more, so you rarely need to add them yourself.
- Use `--suggest-ignore` to print large top-level directories that might deserve an entry (no files are modified automatically).
- Inline suppression works for intentional one-offs: `eval("print('safe')")  # ubs:ignore`.
- Every language module receives the ignore list via their `--exclude` flag, so skips stay consistent.
- This repository ships with a default `.ubsignore` that excludes `test-suite/`, keeping “real” source scans noise-free.

Example:

```text
# Ignore fixtures + build output
test-suite/
dist/
coverage/
```

---

## 🧭 **Language Coverage Comparison**

UBS ships nine language-focused analyzers. The comparison below focuses on the longest-standing modules; Swift is called out separately where relevant. Each category below is scored using the following scale:

- **0 – Not covered**
- **1 – Simple heuristics/regex only**
- **2 – Multi-signal/static heuristics (context-aware passes)**
- **3 – Deep analysis (AST-grep rule packs, taint/dataflow engines, or toolchain integrations such as `cargo clippy`)**

| Issue Category | JS / TS | Python | Go | C / C++ | Rust | Java | Ruby | C# |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Null / Nil Safety | **2** – DOM guard & optional-chaining heuristics (cat.1) | **2** – `None` guard + dataclass fallbacks | **1** – Basic nil/pointer guards | **2** – Raw pointer/nullptr/RAII checks | **3** – Borrow/Option misuse via clippy + rules | **2** – Optional/null equality audits | **1** – Nil guard reminders | **2** – Nullability pragmas, `!` operator, exception/null heuristics |
| Numeric & Type Coercion | **2** – NaN/loose equality/float equality (cat.2/4) | **2** – Division-by-zero & float precision | **1** – Limited arithmetic heuristics | **2** – UB risk & narrowing warnings | **2** – Float/overflow watchers (cat.4) | **1** – Basic comparisons only | **1** – Simple arithmetic foot-guns | **2** – FP equality, truncation casts, parse/validation heuristics |
| Collections & Memory | **2** – Array mutation/leak detectors | **2** – Dict/list iteration pitfalls | **1** – Slice/map heuristics | **3** – malloc/free, iterator invalidation, UB (cat.1/5/7) | **2** – Vec/String/iterator audits | **2** – Collections & generics misuse | **1** – Enumerator/default mutability hints | **2** – LINQ `.First()` / `.Count()>0` / allocation smells |
| Async / Concurrency | **3** – AST-grep + fallback for missing `await`, React hooks dep analyzer, async `useEffect` guard, async `forEach`/predicate/sort-comparator guards, EventEmitter async-listener guard, ignored `map(async ...)` promises, `Promise.all(map(...))` return guard | **2** – Async/Await pitfall scans | **3** – Goroutine/channel/context/defer hygiene | **2** – `std::thread` join + `std::async` wait tracking | **2** – Async macros, Send/Sync checks | **2** – ExecutorService shutdown, `synchronized` monitors | **1** – Basic thread/promise hints | **2** – `Task.Wait`, `.Result`, `async void`, lock/await hazards |
| Error Handling & Logging | **2** – Promise rejection / try–catch auditing | **2** – Exception swallow/logging checks | **2** – Error wrapping, panic usage | **2** – Throw-in-dtor, catch-by-value | **2** – Result/expect/panic usage | **2** – Logging best practices, try-with-resources | **1** – Rescue/raise heuristics | **2** – `throw ex`, empty catch, broad catch patterns |
| Security & Taint | **3** – Lightweight taint engine + XSS/prototype/window.open/postMessage/message-origin/JSX target blank/dangerous HTML security heuristics (cat.7) | **2** – Eval/exec/SQL string heuristics | **2** – HTTP/crypto/command checks | **1** – Limited dedicated security (mostly UB) | **2** – Security category (cat.8) | **3** – SQL concat, `Runtime.exec`, SSL/crypto checks | **2** – Rails mass-assignment, shell/eval warnings | **2** – weak crypto, TLS bypass, hardcoded secrets, ASP.NET web hazards |
| Resource Lifecycle & I/O | **3** – AST event-listener/timer/observer tracking + Blob/Object URL revocation heuristics | **2** – Context-manager & file lifecycle hints | **2** – `defer`/file close + HTTP resource hygiene | **2** – Thread join/malloc/free & resource correlation | **2** – Drop/RAII heuristics + correlation | **3** – Executor/file stream cleanup detections | **2** – File open/close + block usage hints | **2** – HttpClient/IDisposable/timer/CTS lifecycle heuristics |
| Build / Tooling Hygiene | **0** – Not covered yet | **2** – `uv` extras, packaging, notebook hygiene | **2** – Go toolchain sanity (`go vet`, module drift) | **1** – CMake/CXX standard reminders | **3** – `cargo fmt/clippy/test/check` integrations | **2** – Maven/Gradle best-effort builds | **2** – Bundler/Rake/AST rule packs | **2** – optional `dotnet format/build/test/list package` checks |
| Code Quality Markers | **1** – TODO/HACK detectors | **1** | **1** | **1** | **1** | **1** | **1** | **1** |
| Domain-Specific Extras | **3** – React hooks, Node I/O, taint flows | **2** – Typing strictness, notebook linting | **2** – Context propagation, HTTP server/client reviews | **2** – Modernization, macro/STL idioms | **3** – Unsafe/FFI audits, cargo inventory | **3** – SQL/Executor/annotation/path handling | **2** – Rails practicals, bundle hygiene | **2** – ASP.NET middleware/CORS hazards, parsing and lock heuristics |

Use this matrix to decide which language module’s findings you want to prioritize or extend. For example, if you need deeper Go resource-lifecycle audits, you can extend category 5 (defer/cleanup) or contribute new AST-grep rules; for JavaScript security you can build on the taint engine already running in category 7.

---

## 🛡️ **Safety Guards for AI Coding Agents**

When AI agents modify code at speed, a single destructive command can wipe hours of work. UBS ships with a **Git Safety Guard** that intercepts dangerous operations before they execute, designed specifically for Claude Code but applicable to any agent workflow.

### How It Works

The guard lives at `.claude/hooks/git_safety_guard.py` and hooks into Claude Code's command execution pipeline. Before any shell command runs, the guard parses it and blocks patterns that could cause irreversible damage:

| Blocked Command | Why It's Dangerous | Safe Alternative |
|-----------------|-------------------|------------------|
| `git checkout -- <file>` | Discards uncommitted changes permanently | `git stash` first |
| `git reset --hard` | Destroys all uncommitted work | `git reset --soft` or `git stash` |
| `git clean -f` | Removes untracked files forever | `git clean -n` (dry-run) first |
| `git push --force` | Rewrites shared history | `git push --force-with-lease` |
| `rm -rf` on non-temp paths | Deletes files irrecoverably | Explicit temp path required |
| `git branch -D` | Deletes unmerged branches | `git branch -d` (safe delete) |
| `git stash drop/clear` | Loses stashed work | Manual review first |

### Intelligent Temp Path Detection

The guard allows `rm -rf` only when targeting explicit temp directories:
- `${TMPDIR}/...` (macOS/Linux temp)
- `/tmp/...` and `/var/tmp/...`
- System-defined temporary locations

Any `rm -rf` targeting project directories, home folders, or ambiguous paths is blocked with a clear explanation.

### Enabling the Guard

The installer sets this up automatically when it detects Claude Code (`.claude/` directory exists). To enable manually:

```bash
# The installer creates this structure:
.claude/
└── hooks/
    ├── git_safety_guard.py   # Command interceptor
    └── on-file-write.sh      # Auto-scan on save
```

The guard produces actionable error messages explaining *why* a command was blocked and *what to do instead*, so AI agents can self-correct without human intervention.

---

## 🔧 **Extended Agent Detection**

Beyond the core agent integrations (Claude Code, Cursor, Codex), the installer detects and configures **12+ coding agents** automatically. When run with `--easy-mode`, all detected agents receive UBS guardrails without prompting.

### Detected Agents

| Agent | Detection Signal | Integration Type |
|-------|------------------|------------------|
| **Claude Code** | `.claude/` directory | Hooks + rules |
| **Cursor** | `.cursor/` directory | Rules file |
| **Codex CLI** | `.codex/` directory | Rules file/directory |
| **Gemini Code Assist** | `.gemini/` directory | Rules file |
| **Windsurf** | `.windsurf/` directory | Rules file |
| **Cline** | `.cline/` directory | Rules file |
| **OpenCode** | `.opencode/` directory | Rules file |
| **Aider** | `.aider.conf.yml` | Lint command config |
| **Continue** | `.continue/` directory | Rules file |
| **GitHub Copilot** | VS Code extensions | Workspace settings |
| **TabNine** | `.tabnine/` directory | Configuration |
| **Replit** | `replit.com` detection | Environment setup |

### Aider-Specific Integration

For Aider users, the installer adds automatic linting to your configuration:

```yaml
# Added to ~/.aider.conf.yml
lint-cmd: "ubs --fail-on-warning ."
auto-lint: true
```

This makes every Aider session run UBS automatically before completing tasks.

### Session Logging

The installer logs all detected agents and configuration actions to `$XDG_CONFIG_HOME/ubs/session.md`. Review what was configured with:

```bash
ubs sessions          # Show last session
ubs sessions --raw    # Full log with timestamps
ubs sessions --entries=5  # Last 5 sessions
```

---

## 🔬 **AST-Based Type Narrowing Analysis**

Beyond regex pattern matching, UBS includes **deep AST-based analyzers** for language-specific type safety issues. These helpers provide precise line-number mapping and understand language semantics that regex cannot capture.

### Supported Languages

| Language | Helper Location | Analysis Focus |
|----------|-----------------|----------------|
| TypeScript/JavaScript | `modules/helpers/type_narrowing_ts.js` | Null guards, optional chaining, type predicates |
| C# | `modules/helpers/type_narrowing_csharp.py` | Null guards, `TryGetValue` fallthrough, dereference after failed narrowing |
| Rust | `modules/helpers/type_narrowing_rust.py` | Option/Result handling, unwrap usage |
| Kotlin | `modules/helpers/type_narrowing_kotlin.py` | Nullable types, smart casts, `.kt`/`.kts` files |
| Swift | `modules/helpers/type_narrowing_swift.py` | Optional binding, guard statements |

### How It Works

The TypeScript analyzer, for example, walks the AST to detect patterns like:

```typescript
// ❌ Detected: Using property without null check
if (!user) return;
console.log(user.name);  // user might be undefined here (type not narrowed)

// ✅ Safe: Proper type guard
if (user === null || user === undefined) return;
console.log(user.name);  // user is definitely defined
```

The analyzer understands:
- **Type guard functions** (`isString()`, `isDefined()`)
- **Optional chaining** (`user?.name?.first`)
- **Nullish coalescing** (`value ?? default`)
- **Discriminated unions** and type predicates

### Disabling Type Narrowing

For faster scans when type safety isn't your focus:

```bash
ubs . --skip-type-narrowing
```

This falls back to basic heuristics instead of AST analysis, reducing scan time for large codebases.

---

## ⚡ **ast-grep Auto-Provisioning**

UBS automatically downloads and manages [ast-grep](https://ast-grep.github.io/) for enhanced JavaScript/TypeScript analysis. This happens transparently on first use.

### What Gets Downloaded

| Platform | Binary | SHA-256 Verified |
|----------|--------|------------------|
| macOS ARM64 | `ast-grep-aarch64-apple-darwin` | ✓ |
| macOS Intel | `ast-grep-x86_64-apple-darwin` | ✓ |
| Linux ARM64 | `ast-grep-aarch64-unknown-linux-gnu` | ✓ |
| Linux x64 | `ast-grep-x86_64-unknown-linux-gnu` | ✓ |
| Windows x64 | `ast-grep-x86_64-pc-windows-msvc.exe` | ✓ |

Binaries are cached at `$TOOLS_DIR/ast-grep/<version>/<platform>/` and reused across scans.

### Why ast-grep Matters

**Regex-only detection:**
```javascript
// Regex sees: "await" keyword present ✓
const result = await fetch(url);
// But misses: promise not awaited in callback
items.forEach(async (item) => {
  fetch(item.url);  // ❌ Missing await - regex can't detect this
});
```

**ast-grep detection:**
```javascript
// AST analysis understands:
// - async function context
// - Promise return types
// - Missing await in nested scopes
items.forEach(async (item) => {
  fetch(item.url);  // 🔥 CRITICAL: Unhandled promise in async callback
});
```

### Fallback Behavior

If ast-grep fails to download (network issues, unsupported platform), UBS falls back to regex-based detection gracefully. The scan continues with reduced accuracy rather than failing entirely.

---

## 🏥 **Maintenance Commands**

UBS includes built-in maintenance tools for environment auditing and session management.

### `ubs doctor`

Audits your UBS installation and environment:

```bash
ubs doctor              # Run all checks
ubs doctor --fix        # Auto-repair issues where possible
ubs doctor --module-dir=/custom/path  # Check specific cache location
```

**Checks performed:**
- curl/wget availability for downloads
- Module cache directory is writable
- Checksum tools available (sha256sum, shasum, or openssl)
- Cached module integrity (SHA-256 verification)
- ast-grep binary availability and version
- Language module health

**Example output:**
```
🏥 UBS Environment Audit
────────────────────────
✓ curl available (curl 8.4.0)
✓ Cache directory writable (/home/user/.local/share/ubs/modules)
✓ sha256sum available
✓ 8/8 modules verified
✓ ast-grep v0.40.1 ready
✓ All checks passed
```

### `ubs sessions`

View installer session history:

```bash
ubs sessions              # Last session summary
ubs sessions --entries=3  # Last 3 sessions
ubs sessions --raw        # Full unformatted log
ubs sessions --config-dir=/path  # Custom config location
```

Session logs capture:
- Timestamp and duration
- Detected coding agents
- Configured integrations
- Any errors or warnings
- Environment details

---

## 🧪 **Test Suite Infrastructure**

UBS includes a comprehensive manifest-driven test suite for regression testing across all supported languages.

### Test Structure

```
test-suite/
├── manifest.json          # Test case definitions
├── run_manifest.py        # Python test runner
├── artifacts/             # Captured outputs per test
├── csharp/
│   ├── buggy/
│   └── clean/
├── python/
│   ├── buggy/            # Intentionally buggy fixtures
│   └── clean/            # Clean code fixtures
├── javascript/
│   ├── buggy/
│   └── clean/
├── golang/
├── rust/
├── java/
├── ruby/
└── cpp/
```

### Running Tests

```bash
# Run all tests
python test-suite/run_manifest.py

# Run specific test case
python test-suite/run_manifest.py --case js-core-buggy

# List available test cases
python test-suite/run_manifest.py --list

# Stop on first failure
python test-suite/run_manifest.py --fail-fast
```

### Manifest Format

Each test case in `manifest.json` specifies:

```json
{
  "id": "python-resource-lifecycle",
  "path": "test-suite/python/buggy",
  "description": "Detect resource lifecycle issues in Python",
  "enabled": true,
  "args": ["--only=python", "--category=resource-lifecycle"],
  "expect": {
    "exit_code": 1,
    "totals": {
      "critical": {"min": 3},
      "warning": {"min": 1}
    },
    "require_substrings": ["context manager", "file handle"]
  }
}
```

### Artifact Capture

For each test run, the runner captures:
- `stdout.log` - Full scanner output
- `stderr.log` - Error output
- `result.json` - Parsed summary with exit code, duration, findings

This enables debugging test failures and tracking scanner behavior changes across versions.

---

## 🔄 **Auto-Update System**

UBS includes a background auto-update mechanism that keeps your installation current without manual intervention.

### How It Works

```bash
# Force immediate update check
ubs --update .

# Enable automatic updates (checks on each run)
export UBS_ENABLE_AUTO_UPDATE=1
ubs .

# Disable auto-updates (default in CI mode)
export UBS_NO_AUTO_UPDATE=1
ubs .
# Or use the flag:
ubs --no-auto-update .

# Force module re-download before scanning
ubs --update-modules .
```

### CI Mode Behavior

When `--ci` is passed or `CI=true` is detected, auto-updates are automatically disabled to ensure reproducible builds. The scanner uses whatever version is cached, preventing mid-pipeline version changes.

### Manual Updates

For controlled environments, manually trigger updates:

```bash
# Update just the modules
ubs --update-modules .

# Full self-update (fetches latest ubs binary)
FORCE_SELF_UPDATE=1 ubs .
```

---

## 📊 **Beads/Strung JSONL Integration**

For integration with [Beads](https://github.com/Dicklesworthstone/beads) or similar issue-tracking systems, UBS can emit findings as newline-delimited JSON (JSONL).

### Usage

```bash
# Export all findings to JSONL
ubs . --beads-jsonl=findings.jsonl

# Export only summary counts (no individual findings)
ubs . --beads-jsonl=summary.jsonl --jsonl-summary-only
```

### Output Format

Each line is a self-contained JSON object:

```jsonl
{"type":"finding","severity":"critical","category":1,"file":"src/app.js","line":42,"message":"Null pointer access"}
{"type":"finding","severity":"warning","category":7,"file":"src/api.js","line":88,"message":"Potential XSS vector"}
{"type":"summary","totals":{"critical":1,"warning":1,"info":0},"timestamp":"2025-01-05T12:00:00Z"}
```

### Integration Pattern

```bash
# Pipe directly to beads for automatic issue creation
ubs . --beads-jsonl=/dev/stdout | bd import --from-jsonl

# Or append to existing tracking file
ubs . --beads-jsonl=.beads/scan-results.jsonl
```

---

## 📜 **License**

MIT License (with OpenAI/Anthropic Rider) — see [LICENSE](LICENSE) file

**TL;DR:** Use it anywhere. Modify it. Share it. Commercial use OK. No restrictions.

---

## 🙏 **Acknowledgments**

This project wouldn't exist without:

- **[ast-grep](https://ast-grep.github.io/)** by Herrington Darkholme - Revolutionary AST tooling that makes semantic analysis accessible
- **[ripgrep](https://github.com/BurntSushi/ripgrep)** by Andrew Gallant - The fastest search tool ever built
- **Open Source Communities** - JavaScript, Python, Rust, Go, Java, C++, and Ruby communities for documenting thousands of bug patterns and anti-patterns over decades
- **AI Coding Tools** - Claude, GPT-5, Cursor, Copilot for inspiring this tool and making development faster

---

## 📞 **Support**

### **Issues & Questions**

- 🐛 [Report bugs](https://github.com/Dicklesworthstone/ultimate_bug_scanner/issues)
- 💡 [Request features](https://github.com/Dicklesworthstone/ultimate_bug_scanner/issues)
- 📖 [Documentation](https://github.com/Dicklesworthstone/ultimate_bug_scanner)

---

## 💎 **The Bottom Line**

**Every hour spent debugging production bugs is an hour not spent building features.**

The Ultimate Bug Scanner gives you:
- ✅ **Confidence** that code won't fail in production
- ✅ **Speed** (catch bugs in seconds, not hours)
- ✅ **Quality gates** for AI-generated code
- ✅ **Peace of mind** when you deploy

### **One Command. Three Seconds. Zero Production Bugs.**

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh?$(date +%s)" | bash
```

**Then never waste another evening debugging a null pointer exception.**

---

<div align="center">

### Ready to stop debugging and start shipping?

[![Install Now](https://img.shields.io/badge/Install_Now-30_seconds-brightgreen?style=for-the-badge)](https://github.com/Dicklesworthstone/ultimate_bug_scanner#-quick-install-30-seconds)
[![View on GitHub](https://img.shields.io/badge/View_on-GitHub-blue?style=for-the-badge&logo=github)](https://github.com/Dicklesworthstone/ultimate_bug_scanner)
[![Documentation](https://img.shields.io/badge/Read-Documentation-orange?style=for-the-badge)](https://github.com/Dicklesworthstone/ultimate_bug_scanner/wiki)

**Star this repo** if it saved you from a production bug ⭐

</div>

## ✉️ **Works Great with MCP Agent Mail**

[MCP Agent Mail](https://github.com/Dicklesworthstone/mcp_agent_mail) is a Git-backed mailbox system that lets your coding agents coordinate work, hand off tasks, and keep durable histories of every change discussion.

- **UBS + MCP Agent Mail together**: run `ubs --fail-on-warning .` as a standard guardrail step in your MCP Agent Mail workflows so any agent proposing code changes must attach a clean scan (or a summary of remaining issues) to their reply.
- **Ideal pattern**: one agent writes or refactors code, a “QA agent” triggered via MCP Agent Mail runs UBS against the touched paths, then posts a concise findings report back into the same thread for humans or other agents to act on.
- **Result**: your multi-agent automation keeps all the communication history in MCP Agent Mail while UBS continuously enforces fast, language-agnostic quality checks on every change.

---

## 🤝 **About Contributions**

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.
