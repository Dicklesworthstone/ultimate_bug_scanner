# UBS Language Modules

Each `ubs-<lang>.sh` provides a consistent CLI (current modules: `js`, `python`, `cpp`, `rust`, `golang`, `java` (also scans Kotlin), `ruby`, `swift`, `csharp`, `elixir`):

```
ubs-<lang>.sh [PROJECT_DIR] [options] [OUTPUT_FILE]

Options:
<!-- contract:options -->
--format=FMT       text|json|sarif (default: text). jsonl and toon are produced by the
                   meta-runner from the module's json output, not by the module itself
--ci               stable timestamps (UTC ISO8601)
--fail-on-warning  exit non-zero if any warnings or critical
-v, --verbose      print more samples in text mode
--jobs=N           parallel hint (propagated to ripgrep/child tools)
--exclude=GLOBS    additional path globs to skip (forwarded by the meta-runner)
--include-ext=CSV  extra file extensions to scan
--skip=CSV         skip category numbers (numbers differ per module)
--rules=DIR        merge custom ast-grep rules into the built-in pack (all modules except elixir)
--list-rules       print generated ast-grep rule ids and exit (js, golang, rust, java, ruby, swift, csharp)
--dump-rules=DIR   write the generated ast-grep rules to DIR (same modules as --list-rules)
--list-categories  print the category table and exit (python, rust, cpp, swift, csharp)
-h, --help         this help
<!-- /contract:options -->
```

The block above is rendered from `modules/contract.json` by `scripts/gen_module_readme.py` (the machine-readable contract: flags with their module lists, formats, exit codes, environment, summary keys, and per-module extensions and manifest files). `scripts/check_docs_claims.py` verifies the contract against every module's argument parser and fails when the block or the contract drifts. Flags a single module adds beyond the shared set are listed per module in the contract (`extra_flags`); `ubs-<lang>.sh --help` prints them. Contract v2 (shared library, `--files-from`, one findings schema) lands module by module with the A4 ports and is recorded per module as `contract: 2`.

New module: `scripts/new-module.sh <lang> --extensions a,b` scaffolds a contract-v2 module with fixtures and manifest cases (see AGENTS.md, "Adding a language module").

Responsibilities:
- Detect files for the given language
- Apply fast heuristics using ripgrep/grep (or language-native tooling)
- Emit native JSON/SARIF where possible so the meta-runner never needs to parse text
- Exit non-zero on critical issues (or warnings when `--fail-on-warning` is set)

Modules are auto-downloaded by the `ubs` meta-runner with this priority:
1. User PATH (`ubs-<lang>` available globally)
2. Local repository `modules/ubs-<lang>.sh`
3. Cached modules under `${XDG_DATA_HOME:-$HOME/.local/share}/ubs/modules`

When a module is missing, `ubs` fetches it from the release tag matching its own
`UBS_VERSION` (`https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/v<version>/modules/ubs-<lang>.sh`,
falling back to `main`), verifies it against the SHA-256 table embedded in `ubs`
(`MODULE_CHECKSUMS`; helpers use `HELPER_CHECKSUMS`), marks it executable, and caches
it for future runs. A cached module or helper that fails verification is
re-downloaded once and, if it still does not match, refused (exit 2) — `ubs doctor --fix`
repairs the cache. Modules found on `PATH` or in this repository's `modules/` directory
are trusted as-is and not checksum-verified.
