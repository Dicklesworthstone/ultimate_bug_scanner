#!/usr/bin/env python3
"""
Git/filesystem safety guard for Claude Code.

Blocks destructive commands that can lose uncommitted work or delete files.
This hook runs before Bash commands execute and can deny dangerous operations.

Exit behavior:
  - Exit 0 with JSON {"hookSpecificOutput": {"permissionDecision": "deny", ...}} = block
  - Exit 0 with no output = allow
"""
import json
import os
import re
import shlex
import sys

# Destructive patterns to block - tuple of (regex, reason)
DESTRUCTIVE_PATTERNS = [
    # Git commands that discard uncommitted changes
    (
        r"git\s+checkout\s+--\s+",
        "git checkout -- discards uncommitted changes permanently. Use 'git stash' first."
    ),
    (
        r"git\s+checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
        "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first."
    ),
    (
        r"git\s+restore\s+(?!--staged\b)[^\s]*\s*$",
        "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first."
    ),
    (
        r"git\s+restore\s+--worktree",
        "git restore --worktree discards uncommitted changes permanently."
    ),
    # Git reset variants
    (
        r"git\s+reset\s+--hard",
        "git reset --hard destroys uncommitted changes. Use 'git stash' first."
    ),
    (
        r"git\s+reset\s+--merge",
        "git reset --merge can lose uncommitted changes."
    ),
    # Git clean
    (
        r"git\s+clean\s+-[a-z]*f",
        "git clean -f removes untracked files permanently. Review with 'git clean -n' first."
    ),
    # Force operations
    (
        r"git\s+push\s+.*--force(?!-with-lease)",
        "Force push can destroy remote history. Use --force-with-lease if necessary."
    ),
    (
        r"git\s+push\s+-f\b",
        "Force push (-f) can destroy remote history. Use --force-with-lease if necessary."
    ),
    (
        r"git\s+branch\s+-D\b",
        "git branch -D force-deletes without merge check. Use -d for safety."
    ),
    # Destructive filesystem commands
    (
        r"rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r",
        "rm -rf is destructive. List files first, then delete individually with permission."
    ),
    (
        r"rm\s+-rf\s+[/~]",
        "rm -rf on root or home paths is extremely dangerous."
    ),
    # Git stash drop/clear without explicit permission
    (
        r"git\s+stash\s+drop",
        "git stash drop permanently deletes stashed changes. List stashes first."
    ),
    (
        r"git\s+stash\s+clear",
        "git stash clear permanently deletes ALL stashed changes."
    ),
]

RM_RF_ALLOWED_PREFIXES = (
    os.path.join(os.sep, "tmp", ""),
    os.path.join(os.sep, "var", "tmp", ""),
    "${TMPDIR:-/tmp}/",
    "${TMPDIR:-/var/tmp}/",
)

RM_SEPARATORS = {"&&", "||", ";", "|"}


def _is_rm_command(token: str) -> bool:
    """Check if a token is the rm command (handles full paths like /bin/rm)."""
    if token == "rm":
        return True
    # Handle absolute paths: /bin/rm, /usr/bin/rm, etc.
    if token.endswith("/rm"):
        return True
    return False


def has_rm_recursive_force(command: str) -> bool:
    """Check if command contains rm with both recursive and force flags.

    Handles all variants:
    - rm -rf, rm -fr (combined short flags)
    - rm -r -f, rm -f -r (separate short flags)
    - rm --recursive --force (long flags)
    - rm -r --force, rm --recursive -f (mixed)
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False

    i = 0
    while i < len(tokens):
        if not _is_rm_command(tokens[i]):
            i += 1
            continue

        i += 1
        has_recursive = False
        has_force = False

        while i < len(tokens):
            tok = tokens[i]
            if tok == "--":
                i += 1
                break
            if tok in RM_SEPARATORS:
                break
            if not tok.startswith("-"):
                break

            # Check for flags
            if tok == "--recursive":
                has_recursive = True
            elif tok == "--force":
                has_force = True
            elif tok.startswith("--"):
                pass  # Other long options
            else:
                # Short options like -r, -f, -rf, -ri, etc.
                if "r" in tok.lower():
                    has_recursive = True
                if "f" in tok.lower():
                    has_force = True
            i += 1

        if has_recursive and has_force:
            return True

        # Skip to next command separator or end
        while i < len(tokens) and tokens[i] not in RM_SEPARATORS:
            i += 1
        if i < len(tokens):
            i += 1  # Skip the separator

    return False


def rm_rf_targets_are_safe(command: str) -> bool:
    """Allow `rm -rf` only when *all* targets are clearly temp paths.

    IMPORTANT: We intentionally avoid trying to evaluate variables like `$TMPDIR`
    (it can be set to `/`). Only the explicit fallbacks `${TMPDIR:-/tmp}/...`
    and `${TMPDIR:-/var/tmp}/...` are allowed.
    """

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False

    i = 0
    while i < len(tokens):
        if not _is_rm_command(tokens[i]):
            i += 1
            continue

        i += 1
        flags = set()
        end_of_opts = False

        while i < len(tokens) and not end_of_opts:
            tok = tokens[i]
            if tok == "--":
                end_of_opts = True
                i += 1
                break
            if tok in RM_SEPARATORS:
                break
            if not tok.startswith("-"):
                break
            # Short options like -rf / -fr, plus long --recursive/--force variants.
            if tok.startswith("--"):
                if tok == "--recursive":
                    flags.add("r")
                elif tok == "--force":
                    flags.add("f")
            else:
                # Use .lower() to catch both -r and -R (both valid for rm)
                if "r" in tok.lower():
                    flags.add("r")
                if "f" in tok.lower():
                    flags.add("f")
            i += 1

        targets: list[str] = []
        while i < len(tokens) and tokens[i] not in RM_SEPARATORS:
            targets.append(tokens[i])
            i += 1

        if "r" in flags and "f" in flags:
            if not targets:
                return False
            for target in targets:
                if not any(target.startswith(prefix) for prefix in RM_RF_ALLOWED_PREFIXES):
                    return False

    return True


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Can't parse input, allow by default
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    # Only check Bash commands
    if tool_name != "Bash" or not command:
        sys.exit(0)

    # Check if command matches any destructive pattern
    for pattern, reason in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            if pattern.startswith("rm\\s+"):
                if rm_rf_targets_are_safe(command):
                    # rm targets are safe temp paths, allow this pattern
                    continue
                reason = (
                    "rm -rf is destructive. Only explicit temp paths are allowed "
                    f"({', '.join(RM_RF_ALLOWED_PREFIXES)})."
                )
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"BLOCKED by git_safety_guard.py\n\n"
                        f"Reason: {reason}\n\n"
                        f"Command: {command}\n\n"
                        f"If this operation is truly needed, ask the user for explicit "
                        f"permission and have them run the command manually."
                    )
                }
            }
            print(json.dumps(output))
            sys.exit(0)

    # Catch rm with recursive+force that bypassed the regex patterns
    # (e.g., "rm -r -f /path" or "rm --recursive --force /path")
    if has_rm_recursive_force(command) and not rm_rf_targets_are_safe(command):
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"BLOCKED by git_safety_guard.py\n\n"
                    f"Reason: rm -rf is destructive. Only explicit temp paths are allowed "
                    f"({', '.join(RM_RF_ALLOWED_PREFIXES)}).\n\n"
                    f"Command: {command}\n\n"
                    f"If this operation is truly needed, ask the user for explicit "
                    f"permission and have them run the command manually."
                )
            }
        }
        print(json.dumps(output))
        sys.exit(0)

    # Allow all other commands
    sys.exit(0)


if __name__ == "__main__":
    main()
