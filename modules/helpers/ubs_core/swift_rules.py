"""ubs_core.swift_rules — ast-grep rule-pack generation for the Swift module.

The legacy write_ast_rules (modules/ubs-swift.sh 770-798) emits exactly ONE
generated rule — swift.urlsession.task-no-resume — plus an optional copy of
the user's --rules=DIR. The YAML below is byte-identical to the heredoc.

Metadata maps mirror the module's consume side: AG_RULE_CATEGORY derives the
category from the c04- filename prefix (category 4, URLSession/Networking),
the YAML severity is info, and run_urlsession_task_correlation +
run_ast_rules both consume the same consolidated `scan --json=stream` output.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

__all__ = ["generate", "CATEGORY_MAP", "SEVERITY_MAP", "SUMMARY_MAP", "REMEDIATION_MAP"]

SEVERITY_MAP: dict[str, str] = {
    "swift.urlsession.task-no-resume": "info",
    "swift.force-try": "warning",
    "swift.force-cast": "warning",
    "swift.task-sleep-blocking": "warning",
    "swift.fatal-error": "warning",
    "swift.precondition-failure": "warning",
    "swift.assertion-failure": "info",
    "swift.keyed-unarchiver": "critical",
    "swift.md5-digest": "warning",
    "swift.sha1-digest": "warning",
    "swift.process-run": "warning",
    "swift.thread-sleep": "warning",
    "swift.dispatch-sync-main": "critical",
    "swift.timer-scheduled": "info",
    "swift.print-call": "info",
    "swift.debug-print": "info",
    "swift.unsafe-bitcast": "warning",
    "swift.unmanaged-pass-unretained": "warning",
    "swift.unmanaged-take-unretained": "warning",
    "swift.exit-call": "warning",
    "swift.abort-call": "warning",
    "swift.ns-assert": "info",
}

CATEGORY_MAP: dict[str, int] = {
    "swift.force-try": 1,
    "swift.force-cast": 1,
    "swift.task-sleep-blocking": 2,
    "swift.urlsession.task-no-resume": 4,
    "swift.fatal-error": 5,
    "swift.precondition-failure": 5,
    "swift.assertion-failure": 5,
    "swift.keyed-unarchiver": 6,
    "swift.md5-digest": 7,
    "swift.sha1-digest": 7,
    "swift.process-run": 8,
    "swift.thread-sleep": 9,
    "swift.dispatch-sync-main": 9,
    "swift.timer-scheduled": 10,
    "swift.print-call": 11,
    "swift.debug-print": 11,
    "swift.unsafe-bitcast": 14,
    "swift.unmanaged-pass-unretained": 14,
    "swift.unmanaged-take-unretained": 14,
    "swift.exit-call": 15,
    "swift.abort-call": 15,
    "swift.ns-assert": 22,
}

SUMMARY_MAP: dict[str, str] = {
    "swift.urlsession.task-no-resume": (
        "URLSession task created (correlation will check resume/cancel); "
        "ensure lifecycle management."
    ),
    "swift.force-try": "Force try (try!) causes runtime crash on error",
    "swift.force-cast": "Force cast (as!) causes runtime crash if type mismatch",
    "swift.task-sleep-blocking": "Synchronous sleep() in async context blocks thread pool",
    "swift.fatal-error": "fatalError terminates the process unconditionally",
    "swift.precondition-failure": "preconditionFailure unconditionally halts execution",
    "swift.assertion-failure": "assertionFailure left in code",
    "swift.keyed-unarchiver": "Insecure NSKeyedUnarchiver without allowed classes",
    "swift.md5-digest": "Insecure MD5 digest algorithm used",
    "swift.sha1-digest": "Insecure SHA1 digest algorithm used",
    "swift.process-run": "Process.run invocation without sanitization",
    "swift.thread-sleep": "Thread.sleep blocks thread pool",
    "swift.dispatch-sync-main": "DispatchQueue.main.sync causes deadlock on main thread",
    "swift.timer-scheduled": "Timer.scheduledTimer retains target",
    "swift.print-call": "print statement left in code",
    "swift.debug-print": "debugPrint statement left in code",
    "swift.unsafe-bitcast": "unsafeBitCast bypasses type safety",
    "swift.unmanaged-pass-unretained": "Unmanaged.passUnretained risks dangling pointer",
    "swift.unmanaged-take-unretained": "Unmanaged.takeUnretainedValue risks use-after-free",
    "swift.exit-call": "exit() terminates process bypassing lifecycle",
    "swift.abort-call": "abort() terminates process abruptly",
    "swift.ns-assert": "NSAssert macro used instead of Swift assert",
}

REMEDIATION_MAP: dict[str, str] = {
    "swift.urlsession.task-no-resume": (
        "Store the task and call .resume(); cancel on teardown if needed."
    ),
    "swift.force-try": "Use do-catch or try? with optional binding",
    "swift.force-cast": "Use as? with optional binding or pattern matching",
    "swift.task-sleep-blocking": "Use Task.sleep(nanoseconds:) or Task.sleep(for:)",
    "swift.fatal-error": "Throw a custom error or return an Optional/Result",
    "swift.precondition-failure": "Return an error or fallback value gracefully",
    "swift.assertion-failure": "Handle edge cases explicitly with logging",
    "swift.keyed-unarchiver": "Use unarchivedObject(ofClass:from:) with NSSecureCoding",
    "swift.md5-digest": "Use SHA256.hash or CryptoKit modern digest",
    "swift.sha1-digest": "Use SHA256.hash or CryptoKit modern digest",
    "swift.process-run": "Validate arguments and avoid passing raw user input to Process",
    "swift.thread-sleep": "Use Task.sleep or dispatch timer",
    "swift.dispatch-sync-main": "Use DispatchQueue.main.async or check Thread.isMainThread",
    "swift.timer-scheduled": "Ensure timer is invalidated when owner is deallocated",
    "swift.print-call": "Use Logger or OSLog for structured logging",
    "swift.debug-print": "Use Logger or OSLog for structured logging",
    "swift.unsafe-bitcast": "Use standard Swift casting or memory-safe conversions",
    "swift.unmanaged-pass-unretained": "Use passRetained or standard ARC references",
    "swift.unmanaged-take-unretained": "Use takeRetainedValue or standard ARC references",
    "swift.exit-call": "Return from main or trigger graceful shutdown",
    "swift.abort-call": "Throw error or trigger graceful shutdown",
    "swift.ns-assert": "Use Swift assert() or assertionFailure()",
}

_GRAMMAR = "swift"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)

# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack — Swift ast-grep rules.
# ─────────────────────────────────────────────────────────────────────────────

_RULES: tuple[tuple[str, str], ...] = (
    (
        "c01-force-try.yml",
        """id: swift.force-try
language: swift
rule:
  pattern: try! $EXPR
severity: warning
message: "Force try (try!) causes an unrecoverable runtime crash on error; handle errors with do-catch or try?."
""",
    ),
    (
        "c01-force-cast.yml",
        """id: swift.force-cast
language: swift
rule:
  pattern: $EXPR as! $TYPE
severity: warning
message: "Force cast (as!) will trap and crash at runtime if the cast fails; use as? with optional binding."
""",
    ),
    (
        "c02-task-sleep-blocking.yml",
        """id: swift.task-sleep-blocking
language: swift
rule:
  pattern: sleep($$$)
severity: warning
message: "Synchronous sleep() blocks the thread pool; in async contexts prefer Task.sleep()."
""",
    ),
    (
        "c04-urlsession-task-no-resume.yml",
        """id: swift.urlsession.task-no-resume
language: swift
rule:
  pattern: $SESSION.$METHOD($$$)
constraints:
  METHOD:
    regex: '^(dataTask|uploadTask|downloadTask)$'
severity: info
message: "URLSession task created (correlation will check resume/cancel); ensure lifecycle management."
""",
    ),
    (
        "c05-fatal-error.yml",
        """id: swift.fatal-error
language: swift
rule:
  pattern: fatalError($$$)
severity: warning
message: "fatalError unconditionally terminates the process; use proper error throwing or recovery in production."
""",
    ),
    (
        "c05-precondition-failure.yml",
        """id: swift.precondition-failure
language: swift
rule:
  pattern: preconditionFailure($$$)
severity: warning
message: "preconditionFailure unconditionally halts execution; throw errors or return nil instead."
""",
    ),
    (
        "c05-assertion-failure.yml",
        """id: swift.assertion-failure
language: swift
rule:
  pattern: assertionFailure($$$)
severity: info
message: "assertionFailure triggers in debug builds; handle the failure condition explicitly."
""",
    ),
    (
        "c06-keyed-unarchiver.yml",
        """id: swift.keyed-unarchiver
language: swift
rule:
  pattern: NSKeyedUnarchiver.unarchiveObject($$$)
severity: error
message: "Insecure NSKeyedUnarchiver.unarchiveObject without required secure coding classes allows arbitrary object injection."
""",
    ),
    (
        "c07-md5-digest.yml",
        """id: swift.md5-digest
language: swift
rule:
  pattern: Insecure.MD5.hash($$$)
severity: warning
message: "MD5 is cryptographically broken and vulnerable to collisions; use SHA256 or stronger."
""",
    ),
    (
        "c07-sha1-digest.yml",
        """id: swift.sha1-digest
language: swift
rule:
  pattern: Insecure.SHA1.hash($$$)
severity: warning
message: "SHA1 is deprecated for security-sensitive applications; use SHA256 or SHA512."
""",
    ),
    (
        "c08-process-run.yml",
        """id: swift.process-run
language: swift
rule:
  pattern: Process.run($$$)
severity: warning
message: "Process.run spawns subprocesses; ensure arguments and environment variables are strictly sanitized."
""",
    ),
    (
        "c09-thread-sleep.yml",
        """id: swift.thread-sleep
language: swift
rule:
  pattern: Thread.sleep($$$)
severity: warning
message: "Thread.sleep blocks the underlying thread; use Task.sleep or dispatch timers."
""",
    ),
    (
        "c09-dispatch-sync-main.yml",
        """id: swift.dispatch-sync-main
language: swift
rule:
  pattern: DispatchQueue.main.sync { $$$ }
severity: error
message: "DispatchQueue.main.sync from the main thread causes immediate deadlock; use async or check Thread.isMainThread."
""",
    ),
    (
        "c10-timer-scheduled.yml",
        """id: swift.timer-scheduled
language: swift
rule:
  pattern: Timer.scheduledTimer($$$)
severity: info
message: "Timer.scheduledTimer retains target on the run loop; ensure invalidation to avoid retain cycles."
""",
    ),
    (
        "c11-print-call.yml",
        """id: swift.print-call
language: swift
rule:
  pattern: print($$$)
severity: info
message: "print() left in production code; prefer unified logging (Logger / OSLog)."
""",
    ),
    (
        "c11-debug-print.yml",
        """id: swift.debug-print
language: swift
rule:
  pattern: debugPrint($$$)
severity: info
message: "debugPrint() left in production code; prefer unified logging."
""",
    ),
    (
        "c14-unsafe-bitcast.yml",
        """id: swift.unsafe-bitcast
language: swift
rule:
  pattern: unsafeBitCast($$$)
severity: warning
message: "unsafeBitCast bypasses type safety and can cause undefined behavior if types differ in layout."
""",
    ),
    (
        "c14-unmanaged-pass-unretained.yml",
        """id: swift.unmanaged-pass-unretained
language: swift
rule:
  pattern: Unmanaged.passUnretained($$$)
severity: warning
message: "Unmanaged.passUnretained creates unretained reference; danger of dangling pointer/use-after-free."
""",
    ),
    (
        "c14-unmanaged-take-unretained.yml",
        """id: swift.unmanaged-take-unretained
language: swift
rule:
  pattern: $U.takeUnretainedValue($$$)
severity: warning
message: "Unmanaged.takeUnretainedValue accesses memory without ARC retain; risk of use-after-free."
""",
    ),
    (
        "c15-exit-call.yml",
        """id: swift.exit-call
language: swift
rule:
  pattern: exit($$$)
severity: warning
message: "Direct exit() bypasses application lifecycle teardown; avoid in app frameworks."
""",
    ),
    (
        "c15-abort-call.yml",
        """id: swift.abort-call
language: swift
rule:
  pattern: abort()
severity: warning
message: "Direct abort() terminates the process abruptly without cleanup."
""",
    ),
    (
        "c22-ns-assert.yml",
        """id: swift.ns-assert
language: swift
rule:
  pattern: NSAssert($$$)
severity: info
message: "NSAssert macro used; prefer Swift assert() or assertionFailure()."
""",
    ),
)


def _map_severity(raw: str) -> str:
    """Legacy parser severity map (error/critical/fatal -> critical)."""
    s = (raw or "").lower().strip()
    if s in ("error", "fatal", "critical", "high", "serious"):
        return "critical"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "info"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, the sgconfig, and the manifest."""
    # The sgconfig lives at the pack root and points at ./rules: ast-grep
    # treats every file under ruleDirs as a rule, so a config inside its own
    # ruleDir would fail to parse itself (empty AG stream).
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    if user_rules_dir and Path(user_rules_dir).is_dir():
        shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)

    manifest: dict[str, dict] = {}
    for filename, body in _RULES:
        (rules_dir / filename).write_text(body, encoding="utf-8")
        rid = _first_match(_ID_RE, body)
        if not rid:
            continue
        grammar = _first_match(_LANGUAGE_RE, body) or _GRAMMAR
        severity = _map_severity(_first_match(_SEVERITY_RE, body))
        cat_match = re.match(r"^c(\d{2})-", filename)
        category = int(cat_match.group(1)) if cat_match else 0
        manifest[rid] = {
            "file": f"rules/{filename}",
            "language": grammar,
            "severity": severity,
            "category": category,
        }

    config = rule_dir / "sgconfig-swift.yml"
    config.write_text("ruleDirs:\n- rules\n", encoding="utf-8")
    (rule_dir / "manifest.json").write_text(
        json_dumps(manifest), encoding="utf-8"
    )
    return manifest
def json_dumps(obj: dict) -> str:
    import json

    return json.dumps(obj, indent=1, sort_keys=True)
