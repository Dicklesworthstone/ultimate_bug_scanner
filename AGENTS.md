# 🤖 AI Agent Instructions: Ultimate Bug Scanner

## Purpose

The Ultimate Bug Scanner (`ubs`) is a static analysis tool that **must be run proactively** during code development to catch bugs before they reach production. As an AI coding agent, you should integrate this scanner into your workflow automatically.

## When to Run

### ✅ ALWAYS Run Before:
- Committing code changes
- Completing a feature implementation
- Finishing a bug fix
- Responding to "done" or "ready to commit"
- After writing more than 50 lines of new JavaScript/TypeScript code

### ✅ Run Upon Request:
- User asks "check code quality"
- User mentions "scan", "lint", or "analyze code"
- User requests "review my code"
- Before creating a pull request

### ❌ NEVER Run:
- For documentation-only changes (README, comments)
- For non-code files (JSON, YAML, Markdown)
- Multiple times in same session without code changes
- During active debugging sessions (unless requested)

## How to Run

### Basic Usage

```bash
# From project root
ubs .

# Verbose mode (show more examples)
ubs -v .

# Strict mode (fail on warnings)
ubs . --fail-on-warning
```

### Integration Pattern

**Recommended workflow:**

1. **After Code Changes**: Run scanner immediately
   ```bash
   ubs . 2>&1 | head -100
   ```

2. **Before Commit**: Run with strict mode
   ```bash
   if ! ubs . --fail-on-warning; then
     echo "Fix issues before committing"
   fi
   ```

3. **Show Summary**: Display findings to user
   ```bash
   ubs . 2>&1 | tail -30
   ```

## Interpreting Results

### Exit Codes

- `0` = No critical issues (safe to proceed)
- `1` = Critical issues found (MUST fix before committing)

### Severity Levels

```
🔥 CRITICAL  → Fix IMMEDIATELY (crashes, security, data corruption)
⚠  Warning   → Fix before commit (bugs, performance, maintenance)
ℹ  Info      → Consider improvements (code quality, best practices)
```

### Output Format

```
Summary Statistics:
  Files scanned:    61
  Critical issues:  12     ← BLOCK commits if > 0
  Warning issues:   156    ← Should fix before commit
  Info items:       423    ← Optional improvements
```

## Required Actions

###if Critical Issues Found (Exit Code 1)

1. **Read the findings** in the output
2. **Fix the critical issues** before proceeding
3. **Re-run the scanner** to verify fixes
4. **Only then** proceed with commit/completion

Example response to user:
```
I've completed the implementation, but the bug scanner found 12 critical
issues that need to be fixed:

- 5 unguarded null pointer accesses in user-input.js:42-87
- 3 potential XSS vulnerabilities in render.js:156-203
- 4 missing await keywords in async-handler.js:23-67

Let me fix these issues before committing...
```

### If Only Warnings Found (Exit Code 0)

1. **Mention** the warnings to the user
2. **Offer to fix** if time permits
3. **Proceed** with commit if user approves

Example:
```
Implementation complete! The scanner found 23 warnings (no critical issues):
- 15 opportunities for optional chaining (?.)
- 8 potential division-by-zero edge cases

Would you like me to address these warnings before committing?
```

## Common Patterns

### Pattern 1: Post-Implementation Scan

```bash
# After writing feature
echo "Running bug scanner..."
if ubs . --fail-on-warning > /tmp/scan.txt 2>&1; then
  echo "✓ No issues found"
else
  # Show critical issues
  grep -A 3 "🔥 CRITICAL" /tmp/scan.txt | head -20
fi
```

### Pattern 2: Pre-Commit Check

```bash
# Before git commit
if ! ubs . 2>&1 | tail -20; then
  echo "Scanner found issues - reviewing..."
  # Fix issues, then retry
fi
```

### Pattern 3: Incremental Fix

```bash
# Fix issues in batches
while ! ubs . --fail-on-warning; do
  # Fix one category at a time
  # Re-run until clean
done
```

## Best Practices

### DO:
- ✅ Run scanner **automatically** after significant code changes
- ✅ Show scanner output to user (especially critical findings)
- ✅ Fix critical issues **before** marking work as complete
- ✅ Mention scanner results in commit messages
- ✅ Re-run after fixes to verify resolution

### DON'T:
- ❌ Skip scanner to save time
- ❌ Ignore critical findings
- ❌ Hide scanner results from user
- ❌ Commit code with critical issues
- ❌ Run scanner on every minor change

## Integration Examples

### Claude Code Hook

If using Claude Code, the scanner runs automatically on file saves via hooks:

```.claude/hooks/on-file-write.sh
#!/bin/bash
if [[ "$FILE_PATH" =~ \.(js|jsx|ts|tsx)$ ]]; then
  ubs "$PROJECT_DIR" --ci 2>&1 | head -20
fi
```

You don't need to manually run it if hooks are configured.

### Git Pre-Commit Hook

If git hooks are configured, the scanner runs automatically:

```.git/hooks/pre-commit
#!/bin/bash
ubs . --fail-on-warning || exit 1
```

Commits will be blocked if issues are found.

## Troubleshooting

### Scanner Not Found

```bash
# Check if installed
which ubs

# If not found, suggest installation
echo "Install with: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash"
```

### Too Many Findings

```bash
# Focus on critical only
ubs . 2>&1 | grep -A 5 "🔥 CRITICAL"

# Show summary only
ubs . 2>&1 | tail -30
```

### False Positives

- Review the finding in context
- If truly false positive, mention to user
- Consider adding exclusion to scanner config

## Example Workflow

```bash
# 1. User requests feature
# 2. You implement the feature
# 3. Run scanner automatically

echo "Feature implemented. Running quality checks..."
if ubs . > /tmp/scan-result.txt 2>&1; then
  echo "✓ All quality checks passed"
  git add . && git commit -m "feat: implement user feature"
else
  # Extract and fix critical issues
  echo "Found issues, fixing..."
  grep "🔥 CRITICAL" /tmp/scan-result.txt

  # After fixes
  ubs . --fail-on-warning && git commit -m "feat: implement user feature"
fi
```

## Key Principle

**The scanner is not optional**. It's a critical part of the development workflow that prevents bugs from reaching production. As an AI agent, you should treat scanner failures the same as compiler errors - they MUST be fixed before proceeding.

---

**Remember**: Running the scanner and fixing issues demonstrates thoroughness and professionalism. Users trust agents that proactively catch and prevent bugs.
