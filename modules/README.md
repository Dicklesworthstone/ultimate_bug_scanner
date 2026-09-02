# UBS Language Modules

Each `ubs-<lang>.sh` provides a consistent CLI (current modules: `js`, `python`, `cpp`, `rust`, `golang`, `java` (also scans Kotlin), `ruby`, `swift`, `csharp`, `elixir`):

```
ubs-<lang>.sh [PROJECT_DIR] [options] [OUTPUT_FILE]

Options:
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
```

Contract v2 (one flag set, one findings schema, shared library) is tracked as bead `ultimate_bug_scanner-0xjg.3`; until it lands, run `ubs-<lang>.sh --help` for the exact flags a module accepts.

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
