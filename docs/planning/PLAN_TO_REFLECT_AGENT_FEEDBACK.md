# Plan: Reflecting Agent Feedback into UBS Evolution

**Status:** Draft
**Target Version:** 5.0
**Objective:** Transform Ultimate Bug Scanner (UBS) from a "powerful but noisy" tool into a "high-precision, agent-native" quality assurance partner.

Based on detailed feedback from 6 distinct AI agents across various tech stacks (iOS, Python, Mixed, Rust), this plan outlines the roadmap to address common pain points: **Noise**, **False Positives**, **Integration Friction**, and **Configuration Overhead**.

---

## 1. 🔇 Epic: The "Silence the Noise" Initiative (Signal-to-Noise Ratio)
*The #1 complaint was excessive noise from dependencies, build artifacts, and non-source files.*

### 1.1 Universal Dependency & Artifact Exclusion
**Problem:** Agents reported scans taking 20+ minutes and generating 1000+ warnings by scanning `venv`, `node_modules`, `vendor`, and build dirs.
**Solution:**
- **Centralized Ignore Logic:** Move exclusion logic from individual language modules to the core `ubs` runner.
- **Hardened Defaults:** Enforce strict default ignores for:
  - **Deps:** `node_modules`, `venv`, `.venv`, `env`, `site-packages`, `vendor`, `bundle`, `.gem`, `target` (Rust), `go/pkg`.
  - **Builds:** `dist`, `build`, `out`, `DerivedData`, `.gradle`, `.pytest_cache`, `__pycache__`.
  - **Docs/Config:** `*.plist` (prevents DTD noise), `*.lock`, `*.json` (prevent regex false matches on data).
- **Mechanism:** Ensure these are passed to `rg` (glob ignores) and `find` (prune) consistently across ALL modules.

### 1.2 Context-Aware Test Scanning
**Problem:** Security rules (e.g., `assert` usage, hardcoded values) flag valid patterns in test files, creating noise.
**Solution:**
- **Test Detection:** Identify test files (`*_test.go`, `test_*.py`, `*.spec.ts`, `tests/`).
- **Rule Scoping:** Modify language modules to automatically suppress specific rules (like `B101`/Asserts) when scanning identified test contexts.

---

## 2. 🎯 Epic: From Heuristic to Semantic (False Positive Reduction)
*Regex is fast but brittle. Agents complained about Swift `!` negation being flagged as force-unwraps and Python variables looking like secrets.*

### 2.1 Accelerate AST Adoption
**Problem:** Regex cannot distinguish between `if !isValid` (negation) and `value!` (unwrap), or `config = "$VAR"` (shell var) vs secrets.
**Solution:**
- **Deprecate Regex for Ambiguous Syntax:** Identify high-noise regex patterns and replace them with `ast-grep` rules.
- **Priorities:**
  - **Swift:** Migrate force-unwrap detection to AST to distinguish negation.
  - **Python:** Migrate secret detection to AST to verify assignment context.
  - **Rust:** Better distinction between safe `unwrap()` (in tests/examples) and unsafe ones.

### 2.2 Inline Suppression Support
**Problem:** Agents cannot suppress a single false positive without configuring global excludes.
**Solution:**
- **Standardize Comments:** Support inline ignores consistent with widely used linters.
  - Format: `# ubs:ignore [rule-id]` or `// ubs:ignore`.
- **Implementation:** Update the unified runner to post-process findings and filter out lines containing these markers if the underlying tool doesn't support it.

---

## 3. 🤖 Epic: Agent-Native Integration (Machine Readability)
*Agents struggle to parse output when ASCII banners or logs mix with JSON.*

### 3.1 Strict JSON Purity
**Problem:** "ASCII art banner breaks naive json.load". Agents need pure data streams.
**Solution:**
- **Stream Separation:** When `--format=json` is active:
  - **STDOUT:** MUST contain ONLY the valid JSON payload.
  - **STDERR:** All banners, progress logs, debug info, and ASCII art go here.
- **Structure:** Ensure the root JSON object contains a `status` field and a `summary` object for easier parsing.

### 3.2 "Diff Mode" / Baseline Support
**Problem:** "Too many issues to fix at once." Agents working on legacy code need to see *only* the problems they introduced.
**Solution:**
- **First-Class Baseline:** Enhance `--comparison` to be more prominent.
  - `ubs --save-baseline .ubs-baseline.json`
  - `ubs --diff-only` (automatically compares against saved baseline).
- **Output:** In Diff Mode, report ONLY new findings.

### 3.3 Quick Scan (Staged/Changed Files)
**Problem:** Full repo scans are too slow for "pre-commit" checks in large repos.
**Solution:**
- **Git Integration:** Add a `--staged` or `--changed` flag.
  - `ubs --staged`: Automatically runs `git diff --name-only --cached` and passes those files to scanners.
  - Optimization: Skip project-wide analysis steps (like unused code) when in this mode.

---

## 4. ⚙️ Epic: Configuration & Profiles
*Agents requested "Library vs App" modes and easier config management.*

### 4.1 Persistent Configuration
**Problem:** Passing CLI flags (`--exclude=...`) every time is brittle for agents.
**Solution:**
- **Config File:** Support `.ubs.conf` (YAML/TOML) or `pyproject.toml` configuration.
  - Allow defining excludes, enabled languages, and rule overrides persistently.

### 4.2 Strictness Profiles
**Problem:** "One size fits all" doesn't work for throwaway scripts vs. high-assurance libraries.
**Solution:**
- **Profiles:**
  - `--profile=strict` (Library/Production): Fail on warnings, no TODOs allowed.
  - `--profile=loose` (Prototype/Script): Ignore TODOs, allow some print statements, focus only on CRITICAL security/crash bugs.

---

## 5. 🧪 Validation Strategy

To ensure these changes effectively address the feedback, we will add a **Reflexive Test Suite**:
1.  **The "Venv" Test:** Create a dummy `venv` with buggy code and ensure UBS ignores it by default.
2.  **The "JSON" Test:** Run `ubs --format=json | jq .` to verify zero stdout pollution.
3.  **The "Test-In-Test" Test:** Place an assert in a `test_*.py` file and ensure it does *not* trigger a warning.
