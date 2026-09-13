"""ubs_core.ruby_rules — ast-grep rule-pack generation for the Ruby module (bead 0xjg.10).

Ruby port of the runtime ast-grep rule GENERATION in modules/ubs-ruby.sh:
``write_ast_rules`` (2119-2471) plus the run_async_error_checks rule
(3337-3352).

``generate(rule_dir, user_rules_dir=None)`` writes::

    <rule_dir>/rules/*.yml        the 29 base rules (legacy pack plus the
                                  corrected thread/rescue matcher)
    <rule_dir>/sgconfig-ruby.yml  single-grammar config listing every rule
                                  file (one ``scan -c`` invocation total)
    <rule_dir>/manifest.json      rule_id -> {severity, language, file}; also
                                  the dict ``generate`` returns

Manifest severity is the parser-mapped tier of the YAML severity
(error/critical/fatal -> critical, warn -> warning, else info) — the same
mapping the legacy parser applies. ``CATEGORY_MAP`` marks the ONE pack rule
that legacy counted into totals (``ruby.async.thread-no-rescue`` ran inside
category 16 via run_async_error_checks with an undeclared severity array,
so its effective tier is the parser's warning default); every other pack
rule was a cat-18 --json-out/--sarif-out passthrough with zero counter
impact. ruby_ast counts exactly the CATEGORY_MAP keys while retaining the
remaining records for the separate SARIF rule-pack report.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

__all__ = [
    "CATEGORY_MAP",
    "SEVERITY_MAP",
    "SUMMARY_MAP",
    "REMEDIATION_MAP",
    "generate",
]

# ─────────────────────────────────────────────────────────────────────────────
# Metadata maps — run_async_error_checks output contract (ubs-ruby.sh 3366-3372),
# keyed by rule id. ASYNC_ERROR_SEVERITY/ASYNC_ERROR_SUMMARY arrays are never
# declared in the module, so the shell defaults apply (warning + the fixed
# summary/description strings printed by the parser loop).
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, str] = {
    "ruby.async.thread-no-rescue": "warning",
}

CATEGORY_MAP: dict[str, int] = {
    # The only pack rule legacy counted (cat 16 heredoc driver).
    "ruby.async.thread-no-rescue": 16,
}

SUMMARY_MAP: dict[str, str] = {
    "ruby.async.thread-no-rescue": "Thread.new block lacks rescue",
}

REMEDIATION_MAP: dict[str, str] = {
    "ruby.async.thread-no-rescue": "Wrap thread bodies in begin/rescue to log or propagate errors",
}

_GRAMMAR = "ruby"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)


def _map_severity(raw: str) -> str:
    """Legacy parser severity map (error/critical/fatal -> critical)."""
    raw = (raw or "").lower().strip()
    if raw in ("critical", "error", "fatal"):
        return "critical"
    if raw in ("warning", "warn"):
        return "warning"
    return "info"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""

# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack from write_ast_rules (2119-2471), plus the corrected
# run_async_error_checks rule. Its legacy `contains` key and rescue node
# name were invalid and prevented the entire consolidated pack from loading.
# ─────────────────────────────────────────────────────────────────────────────

_RULES: tuple[tuple[str, str], ...] = (
    (
        "nil-eq-eq",
        r'''id: rb.nil-eq.eq
language: ruby
rule:
  pattern: $X == nil
severity: warning
message: "Prefer x.nil? instead of == nil"
fix: "{{X}}.nil?"
''',
    ),
    (
        "nil-eq-neq",
        r'''id: rb.nil-eq.neq
language: ruby
rule:
  pattern: $X != nil
severity: warning
message: "Prefer !x.nil? instead of != nil"
fix: "!{{X}}.nil?"
''',
    ),
    (
        "is-literal",
        r'''id: rb.equal-literal
language: ruby
rule:
  any:
    - pattern: $X.equal?(true)
    - pattern: $X.equal?(false)
    - pattern: $X.equal?(0)
severity: info
message: "Avoid identity checks with literals; use == (and nil? for nil)"
''',
    ),
    (
        "bare-rescue",
        r'''id: rb.bare-rescue
language: ruby
rule:
  pattern: |
    begin
      $A
    rescue
      $B
    end
severity: warning
message: "Bare rescue catches StandardError broadly; rescue specific errors"
''',
    ),
    (
        "rescue-exception",
        r'''id: rb.rescue-exception
language: ruby
rule:
  pattern: Exception
severity: error
message: "Rescuing Exception also catches system exits/interrupts; avoid"
''',
    ),
    (
        "raise-e",
        r'''id: rb.raise-e
language: ruby
rule:
  pattern: raise $ERR
constraints:
  ERR:
    regex: '^[a-z_][a-zA-Z0-9_]*$'
severity: warning
message: "Use 'raise' (without arg) to preserve original backtrace"
''',
    ),
    (
        "mutable-const",
        r'''id: rb.mutable-const
language: ruby
rule:
  any:
    - pattern: $C = []
    - pattern: $C = {}
constraints:
  C:
    regex: '^[A-Z][A-Z0-9_]*$'
severity: info
message: "Mutable constants may be modified; consider freezing or dup on read"
''',
    ),
    (
        "eval-exec",
        r'''id: rb.eval-exec
language: ruby
rule:
  any:
    - pattern: eval($ARG)
    - pattern: instance_eval($ARG)
    - pattern: class_eval($ARG)
severity: error
message: "eval*/_*eval with strings can lead to code injection"
''',
    ),
    (
        "marshal-load",
        r'''id: rb.marshal-load
language: ruby
rule:
  any:
    - pattern: Marshal.load($ANY)
    - pattern: Marshal.restore($ANY)
severity: error
message: "Unmarshalling untrusted data is insecure; prefer JSON or safer formats"
''',
    ),
    (
        "yaml-unsafe",
        r'''id: rb.yaml-unsafe
language: ruby
rule:
  pattern: YAML.load($ARG)
severity: warning
message: "YAML.load may instantiate objects; prefer YAML.safe_load with permitted_classes"
''',
    ),
    (
        "digest-weak",
        r'''id: rb.digest-weak
language: ruby
rule:
  any:
    - pattern: Digest::MD5.hexdigest($ARG)
    - pattern: Digest::SHA1.hexdigest($ARG)
    - pattern: OpenSSL::Digest::MD5.new($ARG)
    - pattern: OpenSSL::Digest::SHA1.new($ARG)
severity: warning
message: "Weak hash algorithm (MD5/SHA1); prefer SHA256/512"
''',
    ),
    (
        "random-insecure",
        r'''id: rb.random-insecure
language: ruby
rule:
  any:
    - pattern: rand($ARG)
    - pattern: Random.rand($ARG)
severity: info
message: "rand/Random are not cryptographic; use SecureRandom for secrets/tokens"
''',
    ),
    (
        "http-verify-none",
        r'''id: rb.http-verify-none
language: ruby
rule:
  any:
    - pattern: OpenSSL::SSL::VERIFY_NONE
    - pattern: $OBJ.verify_mode = OpenSSL::SSL::VERIFY_NONE
severity: warning
message: "SSL verification disabled; enable peer verification"
''',
    ),
    (
        "send-dynamic",
        r'''id: rb.send-dynamic
language: ruby
rule:
  any:
    - pattern: $OBJ.send($NAME, $ARG)
    - pattern: $OBJ.__send__($NAME, $ARG)
severity: info
message: "Dynamic dispatch via send; ensure $NAME is validated"
''',
    ),
    (
        "sql-interp",
        r'''id: rb.sql-interp
language: ruby
rule:
  all:
    - any:
        - pattern: ActiveRecord::Base.connection.execute($SQL)
        - pattern: $X.find_by_sql($SQL)
    - has:
        regex: '#\{.+\}'
severity: warning
message: "Interpolated SQL; prefer parameterized queries (e.g., where(name: ?))"
''',
    ),
    (
        "system-single-string",
        r'''id: rb.system-single-string
language: ruby
rule:
  any:
    - pattern: system($CMD)
    - pattern: exec($CMD)
constraints:
  CMD:
    kind: string
severity: error
message: "Shell invocation via single string; use argv array to avoid injection."
''',
    ),
    (
        "open-pipe",
        r'''id: rb.open-pipe
language: ruby
rule:
  pattern: open($STR)
constraints:
  STR:
    kind: string
    regex: "^\\s*[\"']\\|"
severity: warning
message: "Kernel#open with leading '|' spawns a subshell; avoid or validate inputs."
''',
    ),
    (
        "json-parse",
        r'''id: rb.json-parse
language: ruby
rule:
  pattern: JSON.parse($ARG)
severity: info
message: "Ensure JSON.parse is wrapped with rescue JSON::ParserError."
''',
    ),
    (
        "file-open-no-block",
        r'''id: rb.file-open-no-block
language: ruby
rule:
  any:
    - pattern: File.open($ARG)
    - pattern: File.open($ARG, $MODE)
  not:
    inside:
      kind: block
severity: warning
message: "File.open without a block; may leak descriptors; use a block to auto-close."
''',
    ),
    (
        "tempfile-no-block",
        r'''id: rb.tempfile-no-block
language: ruby
rule:
  any:
    - pattern: Tempfile.new($ARG)
    - pattern: Dir.mktmpdir($ARG)
  not:
    inside:
      kind: block
severity: info
message: "Tempfile/mktmpdir without block; ensure cleanup or use block form."
''',
    ),
    (
        "ruby-resource-thread",
        r'''id: ruby.resource.thread-no-join
language: ruby
rule:
  all:
    - pattern: $VAR = Thread.new { $BODY }
    - not:
        has:
          pattern: $VAR.join
severity: warning
message: "Thread handle created without join() in the same scope."
''',
    ),
    (
        "rails-constantize",
        r'''id: rails.constantize
language: ruby
rule:
  any:
    - pattern: $X.constantize
severity: info
message: "constantize may raise NameError; prefer safe_constantize when input is user-controlled."
''',
    ),
    (
        "rails-update-attributes",
        r'''id: rails.update-attributes
language: ruby
rule:
  any:
    - pattern: $REC.update_attributes($ARG)
severity: info
message: "update_attributes is deprecated; prefer update with strong params."
''',
    ),
    (
        "rails-permit-bang",
        r'''id: rails.permit-bang
language: ruby
rule:
  pattern: $P.permit!
severity: warning
message: "Strong params permit! found; review carefully."
''',
    ),
    (
        "rails-csrf-skip",
        r'''id: rails.csrf-skip
language: ruby
rule:
  any:
    - pattern: skip_before_action :verify_authenticity_token
severity: warning
message: "CSRF protections skipped in controllers."
''',
    ),
    (
        "float-eq",
        r'''id: rb.float-eq
language: ruby
rule:
  pattern: $LHS == $FLOAT
constraints:
  FLOAT:
    regex: '^[0-9]+\.[0-9]+$'
severity: warning
message: "Exact float equality; use tolerance (|(a-b).abs < EPS)."
''',
    ),
    (
        "and-or",
        r'''id: rb.and-or
language: ruby
rule:
  any:
    - pattern: $A and $B
    - pattern: $A or $B
severity: info
message: "'and'/'or' have lower precedence than &&/||; prefer &&/|| in expressions."
''',
    ),
    (
        "retry",
        r'''id: rb.retry
language: ruby
rule:
  pattern: retry
severity: info
message: "Ensure bounded retries with backoff."
''',
    ),
    (
        "ruby-async-thread-no-rescue",
        r'''id: ruby.async.thread-no-rescue
language: ruby
rule:
  kind: call
  all:
    - has:
        field: receiver
        pattern: Thread
    - has:
        field: method
        pattern: new
    - has:
        field: block
        any:
          - kind: block
          - kind: do_block
  not:
    any:
      - has:
          kind: rescue
          stopBy: end
      - inside:
          kind: call
          field: receiver
          has:
            field: method
            regex: '^(join|value)$'
      - inside:
          kind: assignment
          has:
            field: left
            pattern: $HANDLE
          precedes:
            any:
              - pattern: $HANDLE.join
              - pattern: $HANDLE.value
            stopBy:
              kind: assignment
      - inside:
          pattern: $HANDLES << $THREAD
          any:
            - precedes:
                any:
                  - pattern: $HANDLES.each(&:join)
                  - pattern: $HANDLES.each(&:value)
                stopBy:
                  kind: assignment
            - inside:
                kind: call
                has:
                  field: block
                  any:
                    - kind: block
                    - kind: do_block
                precedes:
                  any:
                    - pattern: $HANDLES.each(&:join)
                    - pattern: $HANDLES.each(&:value)
                  stopBy:
                    kind: assignment
                stopBy:
                  any:
                    - kind: method
                    - kind: singleton_method
severity: warning
message: "Rescue thread errors or observe them with join/value"
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

    # User rules (--rules DIR) are copied verbatim (ubs-ruby.sh 2123-2126).
    user_rule_files: list[Path] = []
    if user_rules_dir is not None:
        user_rules_dir = Path(user_rules_dir)
        if user_rules_dir.is_dir():
            shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)
            user_rule_files = sorted(
                path
                for path in user_rules_dir.iterdir()
                if path.is_file() and path.suffix in (".yml", ".yaml")
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
