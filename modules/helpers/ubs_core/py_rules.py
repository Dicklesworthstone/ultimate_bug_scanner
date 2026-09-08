"""ubs_core.py_rules — ast-grep rule-pack generation for the Python module (bead 0xjg.5).

Python port of the runtime ast-grep rule GENERATION in modules/ubs-python.sh:
``write_ast_rules`` (9339-10002) plus the ``run_async_error_checks`` rule
(686-698), and the run_ast_rules parser metadata (severity map 10102-10108,
``py.assert-used`` test-file suppression 10111).

``generate(rule_dir, user_rules_dir=None)`` writes::

    <rule_dir>/rules/*.yml        the 52 base rules (byte-identical to the
                                  legacy heredocs)
    <rule_dir>/sgconfig-python.yml  single-grammar config listing every rule
                                  file (one ``scan -c`` invocation total)
    <rule_dir>/manifest.json      rule_id -> {severity, language, file}; also
                                  the dict ``generate`` returns

Manifest severity is the parser-mapped tier of the YAML severity
(error/critical/fatal -> critical, warn -> warning, else info) — the same
mapping run_ast_rules applies at parse time. ``CATEGORY_MAP`` marks the ONE
pack rule that legacy category-gates (``py.async.task-no-await`` ran inside
category 5 via run_async_error_checks); every other pack rule counted in
totals only (legacy ``CURRENT_CATEGORY=0``), so --skip never removed them.
"""
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

# ─────────────────────────────────────────────────────────────────────────────
# Metadata maps — ubs-python.sh 159-190 (declared values), keyed by rule id.
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, str] = {
    # ASYNC_ERROR_SEVERITY (167-169)
    "py.async.task-no-await": "warning",
}

CATEGORY_MAP: dict[str, int] = {
    # The only pack rule legacy category-gated (cat 5 heredoc driver).
    "py.async.task-no-await": 5,
}

SUMMARY_MAP: dict[str, str] = {
    # ASYNC_ERROR_SUMMARY (161-163)
    "py.async.task-no-await": "asyncio.create_task result ignored",
}

REMEDIATION_MAP: dict[str, str] = {
    # ASYNC_ERROR_REMEDIATION (164-166)
    "py.async.task-no-await": "Await or cancel tasks created with asyncio.create_task",
}

# Rules this ast-grep build rejects at load time. The legacy per-rule scans
# swallowed exactly these errors (`scan -r ... 2>/dev/null || true`,
# ubs-python.sh 10068-10071), so these rules contribute no findings there
# either; listing them in the single sgconfig would instead abort the WHOLE
# consolidated scan.
_UNPARSEABLE_RULES = frozenset({
    "aiohttp-session-no-close",     # Fail to parse yaml as RuleConfig
    "except-broad",                 # Rule must specify a set of AST kinds
    "raise-e",                      # Rule must specify a set of AST kinds
    "re-catastrophic",              # Rule must specify a set of AST kinds
    "sql-fstring",                  # Rule must specify a set of AST kinds
    "sql-interpolation-fstring",    # Fail to parse yaml as RuleConfig
})

_GRAMMAR = "python"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)


def _map_severity(raw: str) -> str:
    """run_ast_rules parser severity map (ubs-python.sh 10102-10108)."""
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
# Base rule pack — verbatim heredoc bodies of write_ast_rules (9351-10000)
# plus the run_async_error_checks rule (686-698).
# (file stem, YAML text)
# ─────────────────────────────────────────────────────────────────────────────
_RULES: tuple[tuple[str, str], ...] = (
    (
        "none-eq",
        r'''id: py.none-eq
language: python
rule:
  any:
    - pattern: $X == None
    - pattern: $X != None
severity: warning
message: "Use 'is (not) None' instead of '== None' or '!= None"
''',
    ),
    (
        "is-literal",
        r'''id: py.is-literal
language: python
rule:
  any:
    - pattern: $X is True
    - pattern: $X is False
    - pattern: $X is 0
    - pattern: $X is 1
severity: warning
message: "Avoid 'is' for literal comparison; use '==' (except None uses 'is')"
''',
    ),
    (
        "except-broad",
        r'''id: py.except-broad
language: python
rule: { pattern: "except Exception as $E:\n  $B" }
severity: warning
message: "Catches broad Exception; consider narrowing"
''',
    ),
    (
        "bare-except",
        r'''id: py.bare-except
language: python
rule:
  pattern: |
    try:
      $A
    except:
      $B
severity: error
message: "Bare 'except' catches all exceptions including SystemExit/KeyboardInterrupt"
''',
    ),
    (
        "except-pass",
        r'''id: py.except-pass
language: python
rule:
  pattern: |
    try:
      $X
    except $E as $N:
      pass
severity: warning
message: "Exception swallowed with 'pass'; log or re-raise"
''',
    ),
    (
        "raise-e",
        r'''id: py.raise-e
language: python
rule:
  pattern: |
    except $E as $ex:
      raise $ex
severity: warning
message: "Use 'raise' to preserve traceback, not 'raise e'"
''',
    ),
    (
        "mutable-defaults",
        r'''id: py.mutable-defaults
language: python
rule:
  any:
    - pattern: |
        def $NAME($A = [], $$$):
          $BODY
    - pattern: |
        def $NAME($A = {}, $$$):
          $BODY
    - pattern: |
        def $NAME($A = set(), $$$):
          $BODY
severity: error
message: "Mutable default argument; use default=None and set in body"
''',
    ),
    (
        "eval-exec",
        r'''id: py.eval-exec
language: python
rule:
  any:
    - pattern: eval($$$)
    - pattern: exec($$$)
severity: error
message: "Avoid eval/exec; leads to code injection"
''',
    ),
    (
        "pickle-load",
        r'''id: py.pickle-load
language: python
rule:
  any:
    - pattern: pickle.load($$$)
    - pattern: pickle.loads($$$)
severity: error
message: "Unpickling untrusted data is insecure; prefer safer formats"
''',
    ),
    (
        "yaml-unsafe",
        r'''id: py.yaml-unsafe
language: python
rule:
  any:
    - pattern: yaml.load($STREAM)
    - pattern: yaml.load_all($STREAM)
severity: error
message: "yaml.load without a Loader argument; prefer yaml.safe_load (or Loader=yaml.SafeLoader)"
''',
    ),
    (
        "subprocess-shell",
        r'''id: py.subprocess-shell
language: python
rule:
  any:
    - pattern: subprocess.run($$$, shell=True)
    - pattern: subprocess.call($$$, shell=True)
    - pattern: subprocess.check_output($$$, shell=True)
    - pattern: subprocess.check_call($$$, shell=True)
    - pattern: subprocess.Popen($$$, shell=True)
    - pattern: $FN($$$, shell=True)
severity: error
message: "shell=True is dangerous; prefer exec array with shell=False"
''',
    ),
    (
        "os-system",
        r'''id: py.os-system
language: python
rule:
  pattern: os.system($$$)
severity: warning
message: "os.system is shell-invocation; prefer subprocess without shell"
''',
    ),
    (
        "requests-verify",
        r'''id: py.requests-verify
language: python
rule:
  any:
    - pattern: requests.$M($URL, $$$, verify=False)
    - pattern: requests.$M($URL, verify=False, $$$)
    - pattern: requests.$M($URL, verify = False, $$$)
severity: warning
message: "requests with verify=False disables TLS verification"
''',
    ),
    (
        "hashlib-weak",
        r'''id: py.hashlib-weak
language: python
rule:
  any:
    - pattern: hashlib.md5($$$)
    - pattern: hashlib.sha1($$$)
severity: warning
message: "Weak hash algorithm (md5/sha1); prefer sha256/sha512"
''',
    ),
    (
        "random-secrets",
        r'''id: py.random-secrets
language: python
rule:
  any:
    - pattern: random.random($$$)
    - pattern: random.randint($$$)
    - pattern: random.randrange($$$)
    - pattern: random.choice($$$)
    - pattern: random.choices($$$)
severity: info
message: "random module is not cryptographically secure; use secrets module"
''',
    ),
    (
        "open-no-with",
        r'''id: py.open-no-with
language: python
rule:
  pattern: open($$$)
  not:
    # A with_item ancestor means the handle is context-managed: covers
    # `with open(...) as f:` and wrappers like `contextlib.closing(open(...))`.
    # The old multi-line `inside: pattern:` never matched, so this rule fired
    # on every `with open(...) as f:` too (#64).
    inside:
      kind: with_item
      stopBy: end
severity: warning
message: "open() outside of a 'with' block; risk of leaking file handles"
''',
    ),
    (
        "open-no-encoding",
        r'''id: py.open-no-encoding
language: python
rule:
  all:
    - any:
        - pattern: open($$$)
        - pattern: pathlib.Path($P).open($$$)
    # `pattern: encoding=$ENC` parsed standalone as an *assignment statement*,
    # so it could never match a keyword_argument node -- the rule therefore
    # fired on every open() call, including single-line ones that pass
    # encoding= explicitly. Anchor the pattern with a call context and select
    # the keyword_argument, and look for it among the direct children of this
    # call's argument_list so a formatter-wrapped multi-line argument list is
    # seen exactly like a single-line one (#67).
    - not:
        has:
          kind: argument_list
          has:
            pattern:
              context: "f(encoding=$ENC)"
              selector: keyword_argument
    # Binary mode takes no encoding= at all (TypeError), so an explicit
    # binary mode -- positional ("rb"/"wb"/"ab"/"xb"/"rb+") or keyword
    # (mode="rb") -- must never be reported (#67).
    - not:
        has:
          kind: argument_list
          has:
            regex: "^(mode[[:space:]]*=[[:space:]]*)?[\"'][rwxa+tU]*b[rwxa+tU]*[\"']$"
severity: info
message: "open() without encoding=... may be non-deterministic across locales"
''',
    ),
    (
        "resource-open-no-close",
        r'''id: py.resource.open-no-close
language: python
rule:
  all:
    - pattern: |
        def $FN($$$):
          $BODY
    - has:
        pattern: $VAR = open($$$)
    - not:
        has:
          pattern: $VAR.close()
severity: warning
message: "open() assigned to a variable without close() in the same function."
''',
    ),
    (
        "resource-popen-no-wait",
        r'''id: py.resource.Popen-no-wait
language: python
rule:
  all:
    - pattern: |
        def $FN($$$):
          $BODY
    - has:
        pattern: $PROC = subprocess.Popen($$$)
    - not:
        any:
          - has: { pattern: $PROC.wait() }
          - has: { pattern: $PROC.communicate($$$) }
          - has: { pattern: $PROC.terminate() }
          - has: { pattern: $PROC.kill() }
severity: warning
message: "subprocess.Popen handle created without wait/communicate/terminate in the same function."
''',
    ),
    (
        "resource-asyncio-task",
        r'''id: py.resource.asyncio-task-no-await
language: python
rule:
  all:
    - pattern: |
        def $FN($$$):
          $BODY
    - has:
        pattern: $TASK = asyncio.create_task($$$)
    - not:
        any:
          - has: { pattern: await $TASK }
          - has: { pattern: $TASK.cancel() }
severity: warning
message: "asyncio.create_task result neither awaited nor cancelled."
''',
    ),
    (
        "assert-used",
        r'''id: py.assert-used
language: python
rule:
  pattern: assert $COND
severity: info
message: "assert is stripped with -O; avoid for runtime checks"
''',
    ),
    (
        "datetime-naive",
        r'''id: py.datetime-naive
language: python
rule:
  any:
    - pattern: datetime.datetime.utcnow($$$)
    - pattern: datetime.datetime.now()
severity: info
message: "Naive datetime; prefer timezone-aware (e.g., datetime.now(tz=UTC))"
''',
    ),
    (
        "type-equality",
        r'''id: py.type-equality
language: python
rule:
  any:
    - pattern: type($X) == $T
    - pattern: type($X) is $T
severity: warning
message: "Use isinstance(x, T) instead of type(x) == T"
''',
    ),
    (
        "wildcard-import",
        r'''id: py.wildcard-import
language: python
rule:
  pattern: from $M import *
severity: warning
message: "Wildcard import pollutes namespace; import names explicitly"
''',
    ),
    (
        "importlib-dynamic",
        r'''id: py.importlib-dynamic
language: python
rule:
  any:
    - pattern: __import__($NAME)
    - pattern: importlib.import_module($NAME)
severity: info
message: "Dynamic imports hinder static analysis and packaging"
''',
    ),
    (
        "async-blocking",
        r'''id: py.async-blocking
language: python
rule:
  pattern: |
    async def $FN($$$):
      $STMTS
  has:
    any:
      - pattern: time.sleep($$$)
      - pattern: requests.$M($$$)
      - pattern: subprocess.run($$$)
      - pattern: open($$$)
severity: warning
message: "Blocking call inside async function; consider async equivalent"
''',
    ),
    (
        "await-in-loop",
        r'''id: py.await-in-loop
language: python
rule:
  pattern: |
    for $I in $IT:
      await $CALL
severity: info
message: "await inside loops may be slow; consider gathering with asyncio.gather"
''',
    ),
    (
        "tempfile-mktemp",
        r'''id: py.tempfile-mktemp
language: python
rule:
  pattern: tempfile.mktemp($$$)
severity: error
message: "tempfile.mktemp is insecure; use NamedTemporaryFile or mkstemp"
''',
    ),
    (
        "sql-fstring",
        r'''id: py.sql-fstring
language: python
rule:
  regex: 'f"\\s*SELECT\\s+.*"'
severity: warning
message: "Interpolated SQL; prefer parameterized queries"
''',
    ),
    (
        "type-ignore-heavy",
        r'''id: py.type-ignore
language: python
rule:
  pattern: "# type: ignore$REST"
severity: info
message: "Frequent 'type: ignore' may hide type issues"
''',
    ),
    (
        "any-typing",
        r'''id: py.any-typing
language: python
rule:
  any:
    - pattern: Any
    - pattern: typing.Any
severity: info
message: "Use precise types; 'Any' weakens type guarantees"
''',
    ),
    (
        "re-catastrophic",
        r'''id: py.re-catastrophic
language: python
rule:
  any:
    - regex: 're\\.compile\\("(.+\\+)+.+"\\)'
    - regex: 're\\.compile\\("(.\\*)\\+"\\)'
severity: warning
message: "Potential catastrophic backtracking; check regex"
''',
    ),
    (
        "subprocess-no-check",
        r'''id: py.subprocess-no-check
language: python
rule:
  pattern: subprocess.run($$$)
  not:
    any:
      - has:
          pattern: check=$C
      - regex: 'check\s*='
      - regex: 'shell\s*='
severity: info
message: "subprocess.run without check=... may silently ignore failures; consider check=True"
''',
    ),
    (
        "logging-secrets",
        r'''id: py.logging-secrets
language: python
rule:
  pattern: logging.$L($MSG)
  has:
    any:
      - regex: "(?i)(password|token|secret|apikey|api_key|authorization|bearer)"
severity: warning
message: "Sensitive-looking value referenced in logging call; mask or avoid"
''',
    ),
    (
        "path-join-plus",
        r'''id: py.path-join-plus
language: python
rule:
  pattern: "$BASE + '/' + $NAME"
severity: info
message: "Use os.path.join or pathlib.Path instead of string concatenation for paths"
''',
    ),
    (
        "floating-task",
        r'''id: py.floating-task
language: python
rule:
  pattern: asyncio.create_task($CALL)
  not:
    inside:
      pattern: |
        $VAR = asyncio.create_task($CALL)
severity: warning
message: "create_task() result unused; keep a reference and handle exceptions"
''',
    ),
    (
        "requests-timeout-missing",
        r'''id: py.requests-timeout-missing
language: python
rule:
  pattern: requests.$M($URL, $$$)
  not:
    any:
      - has:
          pattern: timeout=$T
      - regex: 'timeout\s*='
severity: info
message: "requests call without timeout=... may hang"
''',
    ),
    (
        "json-loads-no-try",
        r'''id: py.json.loads-no-try
language: python
rule:
  pattern: json.loads($DATA)
  not:
    inside:
      # Any try statement with at least one except clause; the earlier
      # single-statement pattern ($A / $B) missed every multi-statement try
      # body and reported well-guarded json.loads calls (GH self-scan).
      kind: try_statement
      stopBy: end
      has:
        kind: except_clause
severity: warning
message: "json.loads without exception handling"
''',
    ),
    (
        "sql-interpolation-percent",
        r'''id: py.sql-string-format-percent
language: python
rule:
  pattern: $CURSOR.$EXEC("SELECT " + $QS % $ARGS)
severity: warning
message: "Interpolated SQL via % operator; use parameters"
''',
    ),
    (
        "sql-interpolation-fstring",
        r'''id: py.sql-fstring-params
language: python
rule:
  regex: 'execute\\(f["\\\']\\s*(SELECT|UPDATE|INSERT|DELETE)\\b'
severity: warning
message: "Interpolated SQL via f-string; use parameters"
''',
    ),
    (
        "contextlib-suppress-broad",
        r'''id: py.contextlib-suppress-broad
language: python
rule:
  pattern: contextlib.suppress(Exception)
severity: info
message: "contextlib.suppress(Exception) hides all errors"
''',
    ),
    (
        "aiohttp-session-no-close",
        r'''id: py.aiohttp-session-no-close
language: python
rule:
  pattern: $S = aiohttp.ClientSession($$$)
  not:
    inside:
      any:
        - pattern: await $S.close()
        - pattern: async with aiohttp.ClientSession($$$) as $S:
severity: warning
message: "aiohttp ClientSession not closed/used as async context manager"
''',
    ),
    (
        "logging-exc-info",
        r'''id: py.logging-exception-no-exc-info
language: python
rule:
  pattern: logging.$L($MSG)
  not:
    has:
      pattern: exc_info=True
severity: info
message: "logging call missing exc_info=True when reporting exceptions"
''',
    ),
    (
        "asyncio-get-event-loop-legacy",
        r'''id: py.asyncio.get_event_loop-legacy
language: python
rule:
  pattern: asyncio.get_event_loop()
severity: info
message: "get_event_loop() legacy usage; prefer get_running_loop() or asyncio.run()"
''',
    ),
    (
        "imp-module",
        r'''id: py.imp-module
language: python
rule: { pattern: import imp }
severity: warning
message: "imp is deprecated; use importlib"
''',
    ),
    (
        "json-load-no-try",
        r'''id: py.json-load-no-try
language: python
rule:
  pattern: json.load($F)
  not:
    inside:
      kind: try_statement
severity: warning
message: "json.load() without try/except crashes on malformed JSON or empty files"
''',
    ),
    (
        "stub-function-pass",
        r'''id: py.stub-function-pass
language: python
rule:
  pattern: |
    def $NAME($$$):
        pass
severity: info
message: "Function body is just 'pass'; will silently do nothing at runtime"
''',
    ),
    (
        "stub-function-ellipsis",
        r'''id: py.stub-function-ellipsis
language: python
rule:
  pattern: |
    def $NAME($$$):
        ...
severity: info
message: "Function body is just '...'; will silently do nothing at runtime"
''',
    ),
    (
        "env-get-empty-truthy",
        r'''id: py.env-get-empty-string
language: python
rule:
  any:
    - pattern: os.environ.get($KEY)
    - pattern: os.getenv($KEY)
  inside:
    kind: if_statement
severity: info
message: "os.getenv returns '' for set-but-empty vars (falsy); verify empty-string handling is intentional"
''',
    ),
    (
        "retry-missing-decorator",
        r'''id: py.sqlite-no-retry
language: python
rule:
  any:
    - pattern: cursor.execute($$$)
    - pattern: conn.execute($$$)
  not:
    inside:
      kind: try_statement
severity: info
message: "Database execute without exception handling; consider retry logic for OperationalError/SQLITE_BUSY"
''',
    ),
    (
        "signal-handler-too-complex",
        r'''id: py.signal-handler-io
language: python
rule:
  pattern: signal.signal($SIG, $HANDLER)
severity: info
message: "Signal handlers should be minimal (set a flag); avoid I/O, locks, or complex logic inside them"
''',
    ),
    (
        "async-task-no-await",
        # run_async_error_checks (ubs-python.sh 686-698) — the one pack rule
        # legacy category-gates (cat 5) via CATEGORY_MAP above.
        r'''id: py.async.task-no-await
language: python
rule:
  pattern: $TASK = asyncio.create_task($$$)
  not:
    any:
      - inside: { pattern: await $TASK }
      - inside: { pattern: $TASK.cancel() }
      - inside: { pattern: $TASK.add_done_callback($CB) }
severity: warning
message: "asyncio.create_task result neither awaited nor cancelled"
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

    # User rules (--rules DIR) are copied verbatim (ubs-python.sh 9346-9348).
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
        # Invalid under this ast-grep build: kept on disk for fidelity, but
        # NOT listed in the sgconfig (see _UNPARSEABLE_RULES above) — legacy
        # per-rule scans dropped them silently at scan time.
        if stem not in _UNPARSEABLE_RULES:
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
