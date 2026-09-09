"""ubs_core.elixir_rules — ast-grep rule-pack generation for the Elixir module (bead 1b9j.5)."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

__all__ = [
    "CATEGORY_MAP",
    "REMEDIATION_MAP",
    "SEVERITY_MAP",
    "SUMMARY_MAP",
    "generate",
]

SEVERITY_MAP: dict[str, str] = {
    "elixir.code-eval-string": "critical",
    "elixir.code-eval-file": "critical",
    "elixir.system-cmd-shell": "warning",
    "elixir.system-shell": "warning",
    "elixir.process-sleep": "warning",
    "elixir.io-inspect": "info",
    "elixir.io-puts": "info",
    "elixir.file-rm-rf": "warning",
    "elixir.file-rm-rf-bang": "warning",
    "elixir.string-to-atom": "warning",
    "elixir.string-to-existing-atom": "info",
    "elixir.binary-to-term-unsafe": "critical",
    "elixir.crypto-md5": "warning",
    "elixir.crypto-sha1": "warning",
    "elixir.send-unhandled": "info",
    "elixir.spawn-unlinked": "warning",
    "elixir.spawn-link": "info",
    "elixir.jason-decode-bang": "warning",
    "elixir.poison-decode-bang": "warning",
    "elixir.repo-query": "warning",
    "elixir.repo-query-bang": "warning",
    "elixir.kernel-exit": "warning",
    "elixir.kernel-throw": "warning",
    "elixir.process-exit": "warning",
    "elixir.system-halt": "warning",
    "elixir.node-spawn": "warning",
}

CATEGORY_MAP: dict[str, int] = {
    "elixir.kernel-exit": 2,
    "elixir.kernel-throw": 2,
    "elixir.spawn-unlinked": 3,
    "elixir.spawn-link": 3,
    "elixir.process-exit": 3,
    "elixir.process-sleep": 3,
    "elixir.node-spawn": 3,
    "elixir.code-eval-string": 4,
    "elixir.code-eval-file": 4,
    "elixir.system-shell": 4,
    "elixir.system-cmd-shell": 4,
    "elixir.binary-to-term-unsafe": 4,
    "elixir.crypto-md5": 4,
    "elixir.crypto-sha1": 4,
    "elixir.system-halt": 4,
    "elixir.repo-query": 6,
    "elixir.repo-query-bang": 6,
    "elixir.send-unhandled": 7,
    "elixir.file-rm-rf": 8,
    "elixir.file-rm-rf-bang": 8,
    "elixir.io-inspect": 9,
    "elixir.io-puts": 9,
    "elixir.string-to-atom": 10,
    "elixir.string-to-existing-atom": 10,
    "elixir.jason-decode-bang": 15,
    "elixir.poison-decode-bang": 15,
}

SUMMARY_MAP: dict[str, str] = {
    "elixir.code-eval-string": "Code.eval_string evaluates dynamic code",
    "elixir.code-eval-file": "Code.eval_file executes external code",
    "elixir.system-cmd-shell": "System.cmd executing sh shell",
    "elixir.system-shell": "System.shell executes raw shell command",
    "elixir.process-sleep": "Process.sleep blocks the Erlang process",
    "elixir.io-inspect": "IO.inspect left in production code",
    "elixir.io-puts": "IO.puts left in production code",
    "elixir.file-rm-rf": "File.rm_rf recursively deletes files",
    "elixir.file-rm-rf-bang": "File.rm_rf! recursively deletes files and raises",
    "elixir.string-to-atom": "String.to_atom can exhaust BEAM atom table",
    "elixir.string-to-existing-atom": "String.to_existing_atom raises ArgumentError on unknown atom",
    "elixir.binary-to-term-unsafe": ":erlang.binary_to_term without [:safe] allows code execution",
    "elixir.crypto-md5": "MD5 hash algorithm is cryptographically weak",
    "elixir.crypto-sha1": "SHA-1 hash algorithm is deprecated",
    "elixir.send-unhandled": "send/2 without backpressure or receiver check",
    "elixir.spawn-unlinked": "spawn creates unlinked process whose crash is unobserved",
    "elixir.spawn-link": "spawn_link used without supervisor",
    "elixir.jason-decode-bang": "Jason.decode! raises on invalid JSON",
    "elixir.poison-decode-bang": "Poison.decode! raises on invalid JSON",
    "elixir.repo-query": "Repo.query raw SQL execution",
    "elixir.repo-query-bang": "Repo.query! raw SQL execution and raises",
    "elixir.kernel-exit": "exit/1 terminates process abruptly",
    "elixir.kernel-throw": "throw/1 used for control flow",
    "elixir.process-exit": "Process.exit terminates another process",
    "elixir.system-halt": "System.halt immediately stops the BEAM node",
    "elixir.node-spawn": "Node.spawn executes work on remote node without supervision",
}

REMEDIATION_MAP: dict[str, str] = {
    "elixir.code-eval-string": "Avoid Code.eval_string with untrusted input",
    "elixir.code-eval-file": "Avoid Code.eval_file with untrusted input",
    "elixir.system-cmd-shell": "Invoke executables directly without shell wrapper",
    "elixir.system-shell": "Use System.cmd with argument lists",
    "elixir.process-sleep": "Use Process.send_after or GenServer timeouts",
    "elixir.io-inspect": "Remove IO.inspect or use Logger",
    "elixir.io-puts": "Use Logger.info or structured logging",
    "elixir.file-rm-rf": "Ensure path is strictly validated before deletion",
    "elixir.file-rm-rf-bang": "Ensure path is strictly validated",
    "elixir.string-to-atom": "Use String.to_existing_atom with known atoms",
    "elixir.string-to-existing-atom": "Handle ArgumentError or validate inputs",
    "elixir.binary-to-term-unsafe": "Use [:safe] option with binary_to_term",
    "elixir.crypto-md5": "Use SHA-256 (:sha256) or stronger",
    "elixir.crypto-sha1": "Use SHA-256 (:sha256) or stronger",
    "elixir.send-unhandled": "Ensure receiving process is alive and handles message",
    "elixir.spawn-unlinked": "Use Task.start_link or Supervisor",
    "elixir.spawn-link": "Use Task.Supervisor or GenServer",
    "elixir.jason-decode-bang": "Use Jason.decode to handle parse failures gracefully",
    "elixir.poison-decode-bang": "Use Poison.decode to handle parse failures gracefully",
    "elixir.repo-query": "Ensure parameters are parameterized, not interpolated",
    "elixir.repo-query-bang": "Ensure parameters are parameterized",
    "elixir.kernel-exit": "Handle failure gracefully with {:error, reason}",
    "elixir.kernel-throw": "Use structured control flow instead of throw",
    "elixir.process-exit": "Allow supervisor to manage process lifecycle",
    "elixir.system-halt": "Allow graceful shutdown through application controller",
    "elixir.node-spawn": "Use distributed Tasks or GenServer",
}

_GRAMMAR = "elixir"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)

_RULES: tuple[tuple[str, str], ...] = (
    (
        "c02-kernel-exit.yml",
        r"""id: elixir.kernel-exit
message: "exit/1 terminates process abruptly; return {:error, reason} instead."
severity: warning
language: elixir
rule:
  pattern: exit($$$)
""",
    ),
    (
        "c02-kernel-throw.yml",
        r"""id: elixir.kernel-throw
message: "throw/1 used for control flow; prefer structured error handling."
severity: warning
language: elixir
rule:
  pattern: throw($$$)
""",
    ),
    (
        "c03-spawn-unlinked.yml",
        r"""id: elixir.spawn-unlinked
message: "spawn creates unlinked process whose crash is unobserved; use Task.start_link."
severity: warning
language: elixir
rule:
  pattern: spawn($$$)
""",
    ),
    (
        "c03-spawn-link.yml",
        r"""id: elixir.spawn-link
message: "spawn_link used without supervisor; use Task.Supervisor."
severity: info
language: elixir
rule:
  pattern: spawn_link($$$)
""",
    ),
    (
        "c03-process-exit.yml",
        r"""id: elixir.process-exit
message: "Process.exit terminates another process; allow supervisor to manage lifecycle."
severity: warning
language: elixir
rule:
  pattern: Process.exit($$$)
""",
    ),
    (
        "c03-process-sleep.yml",
        r"""id: elixir.process-sleep
message: "Process.sleep blocks the Erlang process; use Process.send_after."
severity: warning
language: elixir
rule:
  pattern: Process.sleep($$$)
""",
    ),
    (
        "c03-node-spawn.yml",
        r"""id: elixir.node-spawn
message: "Node.spawn executes work on remote node without supervision."
severity: warning
language: elixir
rule:
  pattern: Node.spawn($$$)
""",
    ),
    (
        "c04-code-eval-string.yml",
        r"""id: elixir.code-eval-string
message: "Code.eval_string evaluates dynamic code; potential code injection."
severity: error
language: elixir
rule:
  pattern: Code.eval_string($$$)
""",
    ),
    (
        "c04-code-eval-file.yml",
        r"""id: elixir.code-eval-file
message: "Code.eval_file executes external code; potential code injection."
severity: error
language: elixir
rule:
  pattern: Code.eval_file($$$)
""",
    ),
    (
        "c04-system-shell.yml",
        r"""id: elixir.system-shell
message: "System.shell executes raw shell command; danger of command injection."
severity: warning
language: elixir
rule:
  pattern: System.shell($$$)
""",
    ),
    (
        "c04-system-cmd-shell.yml",
        r"""id: elixir.system-cmd-shell
message: "System.cmd executing sh shell; invoke executables directly."
severity: warning
language: elixir
rule:
  pattern: System.cmd("sh", [$$$])
""",
    ),
    (
        "c04-binary-to-term-unsafe.yml",
        r"""id: elixir.binary-to-term-unsafe
message: ":erlang.binary_to_term without [:safe] allows arbitrary atom creation/execution."
severity: error
language: elixir
rule:
  pattern: :erlang.binary_to_term($$$)
""",
    ),
    (
        "c04-crypto-md5.yml",
        r"""id: elixir.crypto-md5
message: "MD5 hash algorithm is cryptographically weak; use SHA-256."
severity: warning
language: elixir
rule:
  pattern: :crypto.hash(:md5, $$$)
""",
    ),
    (
        "c04-crypto-sha1.yml",
        r"""id: elixir.crypto-sha1
message: "SHA-1 hash algorithm is deprecated; use SHA-256."
severity: warning
language: elixir
rule:
  pattern: :crypto.hash(:sha, $$$)
""",
    ),
    (
        "c04-system-halt.yml",
        r"""id: elixir.system-halt
message: "System.halt immediately stops the BEAM node; prefer graceful shutdown."
severity: warning
language: elixir
rule:
  pattern: System.halt($$$)
""",
    ),
    (
        "c06-repo-query.yml",
        r"""id: elixir.repo-query
message: "Repo.query raw SQL execution; ensure parameters are parameterized."
severity: warning
language: elixir
rule:
  pattern: Repo.query($$$)
""",
    ),
    (
        "c06-repo-query-bang.yml",
        r"""id: elixir.repo-query-bang
message: "Repo.query! raw SQL execution and raises; ensure parameters are parameterized."
severity: warning
language: elixir
rule:
  pattern: Repo.query!($$$)
""",
    ),
    (
        "c07-send-unhandled.yml",
        r"""id: elixir.send-unhandled
message: "send/2 without backpressure or receiver existence check."
severity: info
language: elixir
rule:
  pattern: send($PID, $$$)
""",
    ),
    (
        "c08-file-rm-rf.yml",
        r"""id: elixir.file-rm-rf
message: "File.rm_rf recursively deletes files; validate path strictly."
severity: warning
language: elixir
rule:
  pattern: File.rm_rf($$$)
""",
    ),
    (
        "c08-file-rm-rf-bang.yml",
        r"""id: elixir.file-rm-rf-bang
message: "File.rm_rf! recursively deletes files and raises; validate path strictly."
severity: warning
language: elixir
rule:
  pattern: File.rm_rf!($$$)
""",
    ),
    (
        "c09-io-inspect.yml",
        r"""id: elixir.io-inspect
message: "IO.inspect left in production code; remove or use Logger."
severity: info
language: elixir
rule:
  pattern: IO.inspect($$$)
""",
    ),
    (
        "c09-io-puts.yml",
        r"""id: elixir.io-puts
message: "IO.puts left in production code; use Logger.info."
severity: info
language: elixir
rule:
  pattern: IO.puts($$$)
""",
    ),
    (
        "c10-string-to-atom.yml",
        r"""id: elixir.string-to-atom
message: "String.to_atom can exhaust BEAM atom table; use String.to_existing_atom."
severity: warning
language: elixir
rule:
  pattern: String.to_atom($$$)
""",
    ),
    (
        "c10-string-to-existing-atom.yml",
        r"""id: elixir.string-to-existing-atom
message: "String.to_existing_atom raises ArgumentError on unknown atom."
severity: info
language: elixir
rule:
  pattern: String.to_existing_atom($$$)
""",
    ),
    (
        "c15-jason-decode-bang.yml",
        r"""id: elixir.jason-decode-bang
message: "Jason.decode! raises on invalid JSON; use Jason.decode."
severity: warning
language: elixir
rule:
  pattern: Jason.decode!($$$)
""",
    ),
    (
        "c15-poison-decode-bang.yml",
        r"""id: elixir.poison-decode-bang
message: "Poison.decode! raises on invalid JSON; use Poison.decode."
severity: warning
language: elixir
rule:
  pattern: Poison.decode!($$$)
""",
    ),
)


def _map_severity(raw: str) -> str:
    s = (raw or "").lower().strip()
    if s in ("error", "fatal", "critical", "high", "serious"):
        return "critical"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "info"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict[str, dict]:
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
        category = int(cat_match.group(1)) if cat_match else CATEGORY_MAP.get(rid, 0)
        manifest[rid] = {
            "file": f"rules/{filename}",
            "language": grammar,
            "severity": severity,
            "category": category,
        }

    config = rule_dir / "sgconfig-elixir.yml"
    config.write_text("ruleDirs:\n- rules\n", encoding="utf-8")
    (rule_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8"
    )
    return manifest
