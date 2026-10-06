
<!-- >>> Ultimate Bug Scanner quick reference (written by install.sh; removed by install.sh --uninstall) -->
````markdown
## UBS Quick Reference for AI Agents

UBS stands for "Ultimate Bug Scanner": **The AI Coding Agent's Secret Weapon: Flagging Likely Bugs for Fixing Early On**

**Install:** `curl -sSL https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/main/install.sh | bash`

**Golden Rule:** `ubs --client --repo . --format=text -- <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

Service commands require POSIX. On Windows Git Bash/MSYS/Cygwin, use `ubs <changed-files>` and `ubs . --fail-on-warning`; installed hooks choose ordinary scans automatically. WSL can use the Linux service.

**Commands:**
```bash
ubs --client --repo . --format=text -- file.ts file2.py # Specific files, with one-shot fallback
ubs serve --repo .                      # Start the optional service explicitly
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=js,python src/               # Language filter (3-5x faster)
ubs --client --repo . --format=text --fail-on-warning -- . # Full project — before PR
ubs --help                              # Full command reference
ubs sessions --entries 1                # Tail the latest install session log
ubs --client --repo . --format=text -- . # Whole project (respects scanner exclusions)
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
5. Re-run `ubs --client --repo . --format=text -- <file>` → exit 0
6. Commit

**Per-edit feedback:** Pass the changed files. Keep the full-project warning gate before a PR. Edited-file latency is measured; the daemon does not yet meet the <100 ms goal.

**Not verified:** Exit 2 means an environment, authentication, or scan failure; exit 3 means nothing was scanned. Resolve either before treating the result as a pass.

**Bug Severity:**
- **Critical** (always fix): Null safety, XSS/injection, async/await, memory leaks
- **Important** (production): Type narrowing, division-by-zero, resource leaks
- **Contextual** (judgment): TODO/FIXME, console logs

**Anti-Patterns:**
- ❌ Ignore findings → ✅ Investigate each
- ❌ Full scan per edit → ✅ Scope to file
- ❌ Fix symptom (`if (x) { x.y }`) → ✅ Root cause (`x?.y`)
````
<!-- <<< End Ultimate Bug Scanner quick reference -->
