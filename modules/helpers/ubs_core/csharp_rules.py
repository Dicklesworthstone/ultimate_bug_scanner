"""ubs_core.csharp_rules — ast-grep rule-pack generation for the C# module (bead 0xjg.12).

C# port of the runtime ast-grep rule GENERATION in modules/ubs-csharp.sh
``write_ast_rules`` (522-593): the four concurrency rules (legacy cat 17
"AST-Grep Rule Pack"), byte-identical to the module heredocs.

``generate(rule_dir)`` writes::

    <rule_dir>/rules/*.yml        the 4 base rules (byte-identical to the
                                  legacy heredocs)
    <rule_dir>/sgconfig-csharp.yml  single-grammar config listing every rule
                                    file (one ``scan -c`` invocation total)
    <rule_dir>/manifest.json      rule_id -> {severity, language, file}

Unlike ruby/java, EVERY rule in the C# pack joins the legacy counters: cat
17 ingests the whole scan through ``ast_scan_json_to_tsv`` and bumps
counters per deduped match, with severity and title coming from the
module's AST_RULE_SEVERITY / AST_RULE_SUMMARY tables (all four rules are
warning-tier). Those tables live here as SEVERITY_MAP / SUMMARY_MAP and
csharp_ast consumes them.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

__all__ = [
    "CATEGORY_MAP",
    "SEVERITY_MAP",
    "SUMMARY_MAP",
    "REMEDIATION_MAP",
    "generate",
]

# Legacy AST_RULE_SEVERITY / AST_RULE_SUMMARY (ubs-csharp.sh 510-521): the
# severity the shell applied on ingest regardless of the YAML tier, and the
# print titles the per-rule summary (and add_finding) used.
SEVERITY_MAP: dict[str, str] = {
    "cs-async-discarded-task-run": "warning",
    "cs-async-discarded-startnew": "warning",
    "cs-await-in-lock": "warning",
    "cs-parallel-foreach-async-lambda": "warning",
    "cs-task-delay-no-await": "warning",
    "cs-task-result-deadlock": "warning",
    "cs-task-getawaiter-getresult": "warning",
    "cs-task-wait-blocking": "warning",
    "cs-threadpool-queue": "warning",
    "cs-thread-sleep": "warning",
    "cs-new-thread": "warning",
    "cs-md5-create": "warning",
    "cs-sha1-create": "warning",
    "cs-des-crypto": "critical",
    "cs-binary-formatter": "critical",
    "cs-weak-random": "warning",
    "cs-xml-document": "warning",
    "cs-empty-catch": "warning",
    "cs-rethrow-ex": "warning",
    "cs-gc-collect": "info",
    "cs-process-start": "warning",
    "cs-goto-statement": "info",
    "cs-console-writeline": "info",
    "cs-httpclient-instantiation": "warning",
}

SUMMARY_MAP: dict[str, str] = {
    "cs-async-discarded-task-run": "Task.Run result discarded without observation",
    "cs-async-discarded-startnew": "Task.Factory.StartNew result discarded without observation",
    "cs-await-in-lock": "Await used while holding a lock",
    "cs-parallel-foreach-async-lambda": "Parallel.ForEach async lambda drops asynchronous work",
    "cs-task-delay-no-await": "Task.Delay called without await has no effect and ignores delay",
    "cs-task-result-deadlock": "Synchronous .Result access on Task can deadlock",
    "cs-task-getawaiter-getresult": "GetAwaiter().GetResult() blocking wait can deadlock",
    "cs-task-wait-blocking": "Synchronous .Wait() on Task can deadlock",
    "cs-threadpool-queue": "ThreadPool.QueueUserWorkItem bypasses async/await error propagation",
    "cs-thread-sleep": "Thread.Sleep blocks OS thread; use await Task.Delay instead",
    "cs-new-thread": "Direct Thread instantiation bypasses ThreadPool / Task scheduler",
    "cs-md5-create": "MD5 hash algorithm is cryptographically weak",
    "cs-sha1-create": "SHA1 hash algorithm is cryptographically weak",
    "cs-des-crypto": "DES encryption is insecure and broken",
    "cs-binary-formatter": "BinaryFormatter deserialization is vulnerable to remote code execution",
    "cs-weak-random": "System.Random is predictable; use RandomNumberGenerator for security",
    "cs-xml-document": "XmlDocument is vulnerable to XML external entity (XXE) injection",
    "cs-empty-catch": "Empty catch block swallows exceptions silently",
    "cs-rethrow-ex": "throw ex resets exception stack trace; use throw; instead",
    "cs-gc-collect": "Manual GC.Collect() call degrades garbage collector efficiency",
    "cs-process-start": "Process.Start invocation requires strict argument validation",
    "cs-goto-statement": "goto statement harms code maintainability and control flow",
    "cs-console-writeline": "Console.WriteLine in production code should use structured logging",
    "cs-httpclient-instantiation": "Direct HttpClient instantiation can lead to socket exhaustion",
}

REMEDIATION_MAP: dict[str, str] = {
    "cs-async-discarded-task-run": "Await or retain the Task so failures are observed",
    "cs-async-discarded-startnew": "Await or retain the Task so failures are observed",
    "cs-await-in-lock": "Move async work outside the lock",
    "cs-parallel-foreach-async-lambda": "Use Parallel.ForEachAsync or gather Tasks",
    "cs-task-delay-no-await": "Use await Task.Delay() instead of discarding the delay task",
    "cs-task-result-deadlock": "Use await instead of .Result",
    "cs-task-getawaiter-getresult": "Use await instead of GetAwaiter().GetResult()",
    "cs-task-wait-blocking": "Use await instead of .Wait()",
    "cs-threadpool-queue": "Use Task.Run() or async/await for proper error handling",
    "cs-thread-sleep": "Use await Task.Delay() for asynchronous pauses",
    "cs-new-thread": "Use Task.Run() or ThreadPool.QueueUserWorkItem()",
    "cs-md5-create": "Use SHA256.Create() or stronger algorithms",
    "cs-sha1-create": "Use SHA256.Create() or stronger algorithms",
    "cs-des-crypto": "Use Aes.Create() for symmetric encryption",
    "cs-binary-formatter": "Use System.Text.Json or secure serializers",
    "cs-weak-random": "Use System.Security.Cryptography.RandomNumberGenerator",
    "cs-xml-document": "Use XmlReaderSettings with DtdProcessing = DtdProcessing.Prohibit",
    "cs-empty-catch": "Log or properly handle caught exceptions",
    "cs-rethrow-ex": "Use throw; to preserve stack trace",
    "cs-gc-collect": "Let the CLR manage memory collection automatically",
    "cs-process-start": "Use ProcessStartInfo with ArgumentList and validate inputs",
    "cs-goto-statement": "Refactor using structured loops and conditionals",
    "cs-console-writeline": "Use ILogger<T> or structured logging framework",
    "cs-httpclient-instantiation": "Use IHttpClientFactory to manage HttpClient instances",
}

CATEGORY_MAP: dict[str, int] = {
    "cs-async-discarded-task-run": 17,
    "cs-async-discarded-startnew": 17,
    "cs-await-in-lock": 17,
    "cs-parallel-foreach-async-lambda": 17,
    "cs-task-delay-no-await": 17,
    "cs-task-result-deadlock": 17,
    "cs-task-getawaiter-getresult": 17,
    "cs-task-wait-blocking": 17,
    "cs-threadpool-queue": 17,
    "cs-thread-sleep": 17,
    "cs-new-thread": 17,
    "cs-md5-create": 17,
    "cs-sha1-create": 17,
    "cs-des-crypto": 17,
    "cs-binary-formatter": 17,
    "cs-weak-random": 17,
    "cs-xml-document": 17,
    "cs-empty-catch": 17,
    "cs-rethrow-ex": 17,
    "cs-gc-collect": 17,
    "cs-process-start": 17,
    "cs-goto-statement": 17,
    "cs-console-writeline": 17,
    "cs-httpclient-instantiation": 17,
}

_GRAMMAR = "csharp"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)


def _map_severity(raw: str) -> str:
    """Legacy parser severity map (normalize_ast_severity, 606-613)."""
    raw = (raw or "").lower().strip()
    if raw in ("critical", "error", "fatal"):
        return "critical"
    if raw in ("info", "note", "hint"):
        return "info"
    return "warning"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack — heredoc bodies of C# ast-grep rules.
# ─────────────────────────────────────────────────────────────────────────────

_RULES: tuple[tuple[str, str], ...] = (
    (
        "cs-async-discarded-task-run",
        r'''id: cs-async-discarded-task-run
message: "Task.Run result discarded; await or retain the Task so failures are observed."
severity: warning
language: csharp
rule:
  any:
    - pattern: Task.Run($ARG);
    - pattern: _ = Task.Run($ARG);
''',
    ),
    (
        "cs-async-discarded-startnew",
        r'''id: cs-async-discarded-startnew
message: "Task.Factory.StartNew result discarded; await or retain the Task so failures are observed."
severity: warning
language: csharp
rule:
  any:
    - pattern: Task.Factory.StartNew($ARG);
    - pattern: _ = Task.Factory.StartNew($ARG);
''',
    ),
    (
        "cs-await-in-lock",
        r'''id: cs-await-in-lock
message: "Await inside lock can deadlock or break monitor assumptions; move async work outside the lock."
severity: warning
language: csharp
rule:
  pattern: |
    lock ($OBJ) { await $EXPR; }
''',
    ),
    (
        "cs-parallel-foreach-async-lambda",
        r'''id: cs-parallel-foreach-async-lambda
message: "Parallel.ForEach with async lambda does not await the async work; use Parallel.ForEachAsync or gather Tasks."
severity: warning
language: csharp
rule:
  any:
    - pattern: Parallel.ForEach($SRC, async $ITEM => $EXPR);
    - pattern: Parallel.ForEach($SRC, async ($ITEM) => $EXPR);
    - pattern: |
        Parallel.ForEach($SRC, async $ITEM => { await $EXPR; });
''',
    ),
    (
        "cs-task-delay-no-await",
        r'''id: cs-task-delay-no-await
message: "Task.Delay called without await has no effect and ignores the delay."
severity: warning
language: csharp
rule:
  pattern: Task.Delay($$$);
''',
    ),
    (
        "cs-task-result-deadlock",
        r'''id: cs-task-result-deadlock
message: "Synchronous .Result access on Task can deadlock; use await instead."
severity: warning
language: csharp
rule:
  pattern: $TASK.Result
''',
    ),
    (
        "cs-task-getawaiter-getresult",
        r'''id: cs-task-getawaiter-getresult
message: "GetAwaiter().GetResult() blocking wait can deadlock; use await instead."
severity: warning
language: csharp
rule:
  pattern: $TASK.GetAwaiter().GetResult()
''',
    ),
    (
        "cs-task-wait-blocking",
        r'''id: cs-task-wait-blocking
message: "Synchronous .Wait() on Task can deadlock; use await instead."
severity: warning
language: csharp
rule:
  pattern: $TASK.Wait($$$)
''',
    ),
    (
        "cs-threadpool-queue",
        r'''id: cs-threadpool-queue
message: "ThreadPool.QueueUserWorkItem bypasses async/await error propagation."
severity: warning
language: csharp
rule:
  pattern: ThreadPool.QueueUserWorkItem($$$)
''',
    ),
    (
        "cs-thread-sleep",
        r'''id: cs-thread-sleep
message: "Thread.Sleep blocks OS thread; use await Task.Delay instead."
severity: warning
language: csharp
rule:
  pattern: Thread.Sleep($TIME)
''',
    ),
    (
        "cs-new-thread",
        r'''id: cs-new-thread
message: "Direct Thread instantiation bypasses ThreadPool; use Task.Run instead."
severity: warning
language: csharp
rule:
  pattern: new Thread($$$)
''',
    ),
    (
        "cs-md5-create",
        r'''id: cs-md5-create
message: "MD5 hash algorithm is cryptographically weak; use SHA256 instead."
severity: warning
language: csharp
rule:
  pattern: MD5.Create($$$)
''',
    ),
    (
        "cs-sha1-create",
        r'''id: cs-sha1-create
message: "SHA1 hash algorithm is cryptographically weak; use SHA256 instead."
severity: warning
language: csharp
rule:
  pattern: SHA1.Create($$$)
''',
    ),
    (
        "cs-des-crypto",
        r'''id: cs-des-crypto
message: "DES encryption is insecure and broken; use Aes.Create() instead."
severity: error
language: csharp
rule:
  pattern: new DESCryptoServiceProvider($$$)
''',
    ),
    (
        "cs-binary-formatter",
        r'''id: cs-binary-formatter
message: "BinaryFormatter deserialization is vulnerable to remote code execution; use System.Text.Json."
severity: error
language: csharp
rule:
  pattern: new BinaryFormatter($$$)
''',
    ),
    (
        "cs-weak-random",
        r'''id: cs-weak-random
message: "System.Random is predictable; use RandomNumberGenerator for security-sensitive operations."
severity: warning
language: csharp
rule:
  pattern: new Random($$$)
''',
    ),
    (
        "cs-xml-document",
        r'''id: cs-xml-document
message: "XmlDocument is vulnerable to XML external entity (XXE) injection; disable DTD processing."
severity: warning
language: csharp
rule:
  pattern: new XmlDocument($$$)
''',
    ),
    (
        "cs-empty-catch",
        r'''id: cs-empty-catch
message: "Empty catch block swallows exceptions silently; log or handle the exception."
severity: warning
language: csharp
rule:
  pattern: try { $$$TRY } catch ($$$PARAMS) {}
''',
    ),
    (
        "cs-rethrow-ex",
        r'''id: cs-rethrow-ex
message: "throw ex resets exception stack trace; use throw; instead."
severity: warning
language: csharp
rule:
  pattern: throw $EX;
''',
    ),
    (
        "cs-gc-collect",
        r'''id: cs-gc-collect
message: "Manual GC.Collect() call degrades garbage collector efficiency."
severity: info
language: csharp
rule:
  pattern: GC.Collect($$$)
''',
    ),
    (
        "cs-process-start",
        r'''id: cs-process-start
message: "Process.Start invocation requires strict input validation to prevent command injection."
severity: warning
language: csharp
rule:
  pattern: Process.Start($$$)
''',
    ),
    (
        "cs-goto-statement",
        r'''id: cs-goto-statement
message: "goto statement harms code maintainability; refactor with structured control flow."
severity: info
language: csharp
rule:
  pattern: goto $LABEL;
''',
    ),
    (
        "cs-console-writeline",
        r'''id: cs-console-writeline
message: "Console.WriteLine in production code; use structured logging framework."
severity: info
language: csharp
rule:
  pattern: Console.WriteLine($$$)
''',
    ),
    (
        "cs-httpclient-instantiation",
        r'''id: cs-httpclient-instantiation
message: "Direct HttpClient instantiation can cause socket exhaustion; use IHttpClientFactory."
severity: warning
language: csharp
rule:
  pattern: new HttpClient($$$)
''',
    ),
)


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, the sgconfig, and the manifest.

    Returns the manifest dict (rule_id -> {severity, language, file}); the
    same document is written to ``<rule_dir>/manifest.json``. Re-running on
    the same ``rule_dir`` reproduces the identical tree.
    """
    rule_dir = Path(rule_dir)
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # User rules (--rules DIR) are copied verbatim next to the base rules,
    # mirroring the legacy sgconfig extra ruleDirs entries (580-587).
    user_rule_files: list[Path] = []
    if user_rules_dir is not None:
        user_rules_dir = Path(user_rules_dir)
        if user_rules_dir.is_dir():
            import shutil

            shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)
            user_rule_files = sorted(
                path
                for path in rules_dir.iterdir()
                if path.is_file() and path.suffix in (".yml", ".yaml")
                and not any(stem == path.stem for stem, _ in _RULES)
            )

    manifest: dict[str, dict[str, str]] = {}
    config_entries: list[str] = []

    for stem, rule_text in _RULES:
        name = f"{stem}.yml"
        (rules_dir / name).write_text(rule_text, encoding="utf-8")
        rule_id = _first_match(_ID_RE, rule_text)
        manifest[rule_id] = {
            "severity": SEVERITY_MAP.get(
                rule_id, _map_severity(_first_match(_SEVERITY_RE, rule_text))
            ),
            "language": _first_match(_LANGUAGE_RE, rule_text),
            "file": f"rules/{name}",
        }
        config_entries.append(f"  - rules/{name}")

    for user_file in user_rule_files:
        config_entries.append(f"  - rules/{user_file.name}")

    (rule_dir / f"sgconfig-{_GRAMMAR}.yml").write_text(
        "ruleDirs:\n" + "\n".join(config_entries) + "\n", encoding="utf-8"
    )

    manifest_path = rule_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
