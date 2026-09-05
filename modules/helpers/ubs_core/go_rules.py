"""ubs_core.go_rules — ast-grep rule-pack generation for the Go module (bead 0xjg.6).

Go port of the runtime ast-grep rule GENERATION in modules/ubs-golang.sh:
``write_ast_rules`` (2986-3407) plus ``write_ast_rules_v7_extras`` (3409-4447),
the ``run_async_error_checks`` rule (608-628), and the async metadata
declarations (111-121). Every YAML body below is byte-identical to the legacy
heredoc (all rule heredocs are quoted ``<<'YAML'``).

``generate(rule_dir, user_rules_dir=None)`` writes::

    <rule_dir>/rules/*.yml            the 64 base rules plus the async rule
                                      (byte-identical to the legacy heredocs)
    <rule_dir>/sgconfig-go.yml        single-grammar config listing every base
                                      rule file — one ``scan -c`` invocation
                                      total, mirroring the legacy consolidated
                                      scan over AST_RULE_DIR (2885, sgconfig
                                      2990-2993)
    <rule_dir>/sgconfig-go-async.yml  config listing ONLY the async rule
                                      (legacy scanned it in its own pass with
                                      ``scan --rule``, 632)
    <rule_dir>/manifest.json          rule_id -> {severity, language, file};
                                      also the dict ``generate`` returns

Manifest severity is the parser-mapped tier of the YAML severity
(error/critical/fatal -> critical, warn -> warning, else info) — the same
mapping py_rules applies from the legacy run_ast_rules parser
(ubs-python.sh 10102-10108). ``CATEGORY_MAP`` marks the ONE pack rule that
legacy category-gates (``go.async.goroutine-err-no-check`` ran inside
category 1 via run_async_error_checks); every other pack rule counted in
totals only, so --skip never removed them.
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
# Metadata maps — ubs-golang.sh 111-121 (declared values), keyed by rule id.
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, str] = {
    # ASYNC_ERROR_SEVERITY (119-121)
    "go.async.goroutine-err-no-check": "warning",
}

CATEGORY_MAP: dict[str, int] = {
    # The only pack rule legacy category-gated (cat 1 block 4945-4996 ran
    # run_async_error_checks).
    "go.async.goroutine-err-no-check": 1,
}

SUMMARY_MAP: dict[str, str] = {
    # ASYNC_ERROR_SUMMARY (113-115)
    "go.async.goroutine-err-no-check": "goroutine body ignores returned error",
}

REMEDIATION_MAP: dict[str, str] = {
    # ASYNC_ERROR_REMEDIATION (116-118)
    "go.async.goroutine-err-no-check": "Handle errors inside goroutines or pass them to an error channel/errgroup",
}

# Rules this ast-grep build rejects at load time. The legacy Go scanner ran
# ONE consolidated scan over the whole rule dir (sgconfig pointing at
# AST_RULE_DIR, 2990-2993, scanned at 2885), so a single unparseable rule
# file aborted the ENTIRE AST scan — legacy then disabled every AST rule
# ("ast-grep scan failed (exit N); AST-based rules disabled", 2900). These
# stems are kept on disk for fidelity but NOT listed in sgconfig-go.yml;
# the consolidated legacy pack could only have failed the same way.
_UNPARSEABLE_RULES = frozenset({
})

_GRAMMAR = "go"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)


def _map_severity(raw: str) -> str:
    """Parser severity map (ubs-python.sh 10102-10108, via py_rules._map_severity)."""
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
# Async rule — verbatim heredoc body of run_async_error_checks (608-628).
# Scanned in its own pass (``scan --rule``, 632), never in the base sgconfig.
# ─────────────────────────────────────────────────────────────────────────────
_ASYNC_RULE: tuple[str, str] = (
    "go.async.goroutine-err-no-check",
    r'''id: go.async.goroutine-err-no-check
language: go
rule:
  all:
    - pattern: |
        go func($PARAMS) {
          $$$BODY
        }()
    - any:
        - has: { pattern: err := $CALL }
        - has: { pattern: $VAL, err := $CALL }
    - not:
        has:
          pattern: |
            if err != nil {
              $$$
            }
severity: warning
message: "goroutine body ignores returned error; handle it or propagate via channel/errgroup."
''',
)


# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack — verbatim heredoc bodies of write_ast_rules (2999-3400)
# plus write_ast_rules_v7_extras (3414-4446).
# (file stem, YAML text)
# ─────────────────────────────────────────────────────────────────────────────
_RULES: tuple[tuple[str, str], ...] = (
    (
        "go-defer-in-loop",
        r'''id: go.defer-in-loop
language: go
rule:
  all:
    - pattern: defer $CALL
    - inside:
        stopBy: end
        kind: for_statement
    - not:
        inside:
          stopBy: end
          kind: func_literal
severity: warning
message: "defer inside loop may delay cleanup and grow stack; consider explicit close or scoped function."
''',
    ),
    (
        "go-recover-not-in-defer",
        r'''id: go.recover-not-in-defer
language: go
rule:
  pattern: recover()
  not:
    inside:
      pattern: defer func($$) { $$ }
severity: warning
message: "recover() is only effective inside a deferred function."
''',
    ),
    (
        "go-panic-call",
        r'''id: go.panic-call
language: go
rule:
  pattern: panic($$$)
severity: warning
message: "panic used; prefer error returns in libraries and recover at process boundaries."
''',
    ),
    (
        "go-go-in-loop",
        r'''id: go.goroutine-in-loop
language: go
rule:
  kind: for_statement
  regex: "(?s)\\bgo\\s+"
severity: info
message: "goroutine launched inside loop; ensure captured values are correct and rate-limited."
''',
    ),
    (
        "go.loop-var-capture",
        r'''id: go.loop-var-capture
language: go
rule:
  kind: for_statement
  regex: "(?s)for\\s+[^\\n{]*range\\s+[^\\n{]*\\{.*\\bgo\\s+func\\s*\\(\\)\\s*\\{"
severity: warning
message: "Loop variable captured by goroutine closure; pass it as a parameter to avoid capture bugs."
''',
    ),
    (
        "go.select-no-default",
        r'''id: go.select-no-default
language: go
rule:
  kind: select_statement
  not:
    has:
      regex: "\\bdefault\\s*:"
severity: info
message: "select without a default may block indefinitely; confirm this is intended or add a timeout/default."
''',
    ),
    (
        "go-context-without-cancel",
        r'''id: go.context-without-cancel
language: go
rule:
  all:
    - any:
        - pattern: $CTX, $CANCEL := context.WithCancel($PARENT)
        - pattern: $CTX, $CANCEL := context.WithTimeout($PARENT, $DUR)
        - pattern: $CTX, $CANCEL := context.WithDeadline($PARENT, $DL)
        - pattern: $CTX, $CANCEL = context.WithCancel($PARENT)
        - pattern: $CTX, $CANCEL = context.WithTimeout($PARENT, $DUR)
        - pattern: $CTX, $CANCEL = context.WithDeadline($PARENT, $DL)
    - not:
        inside:
          has:
            pattern: defer $CANCEL()
severity: warning
message: "context.With* assigns a cancel func but no defer cancel() is present in the containing scope (heuristic)."
''',
    ),
    (
        "go-context-todo",
        r'''id: go.context-todo
language: go
rule:
  pattern: context.TODO()
severity: info
message: "context.TODO() present; replace with ctx or With* for production flows."
''',
    ),
    (
        "go-resource-ticker",
        r'''id: go.resource.ticker-no-stop
language: go
rule:
  kind: function_declaration
  regex: "(?s)time\\.NewTicker\\s*\\("
  not:
    regex: "(?s)time\\.NewTicker\\s*\\([^)]*\\).*\\.Stop\\s*\\("
severity: warning
message: "time.NewTicker result not stopped in the containing scope."
''',
    ),
    (
        "go-resource-timer",
        r'''id: go.resource.timer-no-stop
language: go
rule:
  all:
    - any:
        - pattern: $TIMER := time.NewTimer($ARGS)
        - pattern: $TIMER = time.NewTimer($ARGS)
    - not:
        inside:
          has:
            any:
              - pattern: $TIMER.Stop()
              - pattern: <-$TIMER.C
severity: warning
message: "time.NewTimer result not stopped/drained in the containing scope."
''',
    ),
    (
        "go-http-default-client",
        r'''id: go.http-default-client
language: go
rule:
  any:
    - kind: call_expression
      regex: "\\bhttp\\.Get\\s*\\("
    - kind: call_expression
      regex: "\\bhttp\\.Post\\s*\\("
    - kind: call_expression
      regex: "\\bhttp\\.Head\\s*\\("
    - kind: call_expression
      regex: "\\bhttp\\.DefaultClient\\.Do\\s*\\("
severity: info
message: "Default http.Client has no Timeout; prefer custom client with Timeout or context-aware requests."
''',
    ),
    (
        "go.http-newrequest-without-context",
        r'''id: go.http-newrequest-without-context
language: go
rule:
  kind: call_expression
  regex: "\\bhttp\\.NewRequest\\s*\\("
severity: info
message: "Prefer http.NewRequestWithContext(ctx, ...) to propagate cancellation."
''',
    ),
    (
        "go.exec-command-without-context",
        r'''id: go.exec-command-without-context
language: go
rule:
  kind: call_expression
  regex: "\\bexec\\.Command\\s*\\("
severity: info
message: "Prefer exec.CommandContext(ctx, ...) to enforce timeouts and cancellation."
''',
    ),
    (
        "go-http-client-without-timeout",
        r'''id: go.http-client-without-timeout
language: go
rule:
  pattern: http.Client{$$$}
  not:
    regex: "Timeout\\s*:"
severity: warning
message: "http.Client without Timeout configured."
''',
    ),
    (
        "go-http-server-no-timeouts",
        r'''id: go.http-server-no-timeouts
language: go
rule:
  pattern: http.Server{$$$}
  not:
    any:
      - has: { pattern: "ReadTimeout: $X" }
      - has: { pattern: "WriteTimeout: $X" }
      - has: { pattern: "IdleTimeout: $X" }
      - has: { pattern: "ReadHeaderTimeout: $X" }
severity: info
message: "http.Server constructed without timeouts; vulnerable to slowloris and resource exhaustion."
''',
    ),
    (
        "go.tls-minversion-missing",
        r'''id: go.tls-minversion-missing
language: go
rule:
  pattern: tls.Config{$$$}
  not:
    any:
      - has: { pattern: "MinVersion: tls.VersionTLS12" }
      - has: { pattern: "MinVersion: tls.VersionTLS13" }
severity: info
message: "tls.Config without MinVersion; set to at least tls.VersionTLS12 (prefer TLS 1.3)."
''',
    ),
    (
        "go-time-tick",
        r'''id: go.time-tick
language: go
rule:
  kind: call_expression
  regex: "\\btime\\.Tick\\s*\\("
severity: warning
message: "time.Tick leaks; prefer time.NewTicker and Stop() it."
''',
    ),
    (
        "go-time-after-in-loop",
        r'''id: go.time-after-in-loop
language: go
rule:
  kind: for_statement
  regex: "(?s)\\btime\\.After\\s*\\("
severity: warning
message: "time.After in loop leaks timers until they fire; use time.NewTimer with Stop/Reset"
''',
    ),
    (
        "go-json-decode-without-disallow",
        r'''id: go.json-decode-without-disallow
language: go
rule:
  any:
    - kind: call_expression
      pattern: json.NewDecoder($R).Decode($V)
    - kind: block
      pattern: |
        {
          $$$
          $DEC := json.NewDecoder($R)
          $DEC.Decode($V)
          $$$
        }
  not:
    has:
      kind: call_expression
      pattern: DisallowUnknownFields()
severity: info
message: "json.Decoder used without DisallowUnknownFields; may hide input mistakes (heuristic)."
''',
    ),
    (
        "go-exec-sh-c",
        r'''id: go.exec-sh-c
language: go
rule:
  any:
    - pattern: exec.Command("sh", "-c", $CMD)
    - pattern: exec.CommandContext($CTX, "sh", "-c", $CMD)
    - pattern: exec.Command("bash", "-c", $CMD)
    - pattern: exec.CommandContext($CTX, "bash", "-c", $CMD)
    - pattern: exec.Command("cmd", "/C", $CMD)
    - pattern: exec.CommandContext($CTX, "cmd", "/C", $CMD)
    - pattern: exec.Command("powershell", "-Command", $CMD)
    - pattern: exec.CommandContext($CTX, "powershell", "-Command", $CMD)
severity: error
message: "shell invocation via command interpreter; sanitize inputs or avoid shell."
''',
    ),
    (
        "go-tls-insecure-skip",
        r'''id: go.tls-insecure-skip
language: go
rule:
  kind: composite_literal
  regex: "(?s)http\\.Transport\\s*\\{.*InsecureSkipVerify\\s*:\\s*true"
severity: warning
message: "TLS InsecureSkipVerify=true disables cert verification."
''',
    ),
    (
        "go-dot-import",
        r'''id: go.dot-import
language: go
rule:
  kind: import_spec
  regex: "^\\.\\s"
severity: warning
message: "dot-import pollutes namespace; avoid except in tests/examples."
''',
    ),
    (
        "go-blank-import",
        r'''id: go.blank-import
language: go
rule:
  kind: import_spec
  regex: "^_\\s"
severity: info
message: "blank import; ensure side-effect import is intentional."
''',
    ),
    (
        "go-ioutil",
        r'''id: go.ioutil-deprecated
language: go
rule:
  kind: call_expression
  regex: "\\bioutil\\.[A-Za-z_][A-Za-z0-9_]*\\s*\\("
severity: info
message: "ioutil package is deprecated; prefer io/os equivalents."
''',
    ),
    (
        "go-interface-empty",
        r'''id: go.interface-empty
language: go
rule:
  pattern: interface{}
severity: info
message: "Prefer 'any' for empty interface in modern Go."
''',
    ),
    (
        "go-sort-slice-param",
        r'''id: go.sort-slice-mutates
language: go
rule:
  any:
    - pattern: sort.Slice($S, $$$)
    - pattern: sort.SliceStable($S, $$$)
severity: info
message: "sort.Slice mutates the slice in-place; if this is a parameter or shared slice, callers' data is modified"
''',
    ),
    (
        "go-content-type-prefix",
        r'''id: go.content-type-prefix-match
language: go
rule:
  any:
    - pattern: strings.HasPrefix($CT, "application/json")
severity: info
message: "Content-type prefix check matches application/jsonpatch+json; use mime.ParseMediaType() for precision"
''',
    ),
    (
        "go-remove-no-err",
        r'''id: go.os-remove-no-error-check
language: go
rule:
  kind: expression_statement
  regex: "^os\\.Remove\\s*\\("
  not:
    inside:
      any:
        - pattern: $ERR := os.Remove($PATH)
        - pattern: $ERR = os.Remove($PATH)
        - pattern: if $ERR := os.Remove($PATH); $$$
severity: warning
message: "os.Remove error ignored; handle or check for os.ErrNotExist at minimum"
''',
    ),
    (
        "go-sync-before-remove",
        r'''id: go.missing-sync-before-remove
language: go
rule:
  kind: source_file
  regex: '(?s)\.Close\(\)\s*\n\s*os\.(Remove|Rename)\('
severity: info
message: "Close without Sync before Remove/Rename; buffered data may be lost on crash. Call f.Sync() first"
''',
    ),
    (
        "go-fmt-errorf-no-w",
        r'''id: go.fmt-errorf-no-wrap
language: go
rule:
  kind: call_expression
  regex: "\\bfmt\\.Errorf\\s*\\("
  not:
    regex: "%w"
severity: info
message: "fmt.Errorf without %w loses error chain; use %w to wrap the original error"
''',
    ),
    (
        "go-json-decode-no-limit",
        r'''id: go.json-decode-no-limit
language: go
rule:
  pattern: json.NewDecoder($BODY).Decode($$$)
severity: info
message: "Unbounded JSON decode from request body; use io.LimitReader to prevent DoS via large payloads"
''',
    ),
    (
        "go-pgrep-unanchored",
        r'''id: go.exec-pgrep-unanchored
language: go
rule:
  any:
    - pattern: exec.Command("pgrep", $PATTERN)
    - pattern: exec.Command("pgrep", "-f", $PATTERN)
severity: info
message: "pgrep matches substrings by default; use -x (exact) or anchor the pattern to avoid false positives"
''',
    ),
    (
        "go.http.defer-body-before-err-check",
        r'''id: go.http.defer-body-before-err-check
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := $CLIENT.Do($REQ)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR = $CLIENT.Do($REQ)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := $CLIENT.Get($URL)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR = $CLIENT.Get($URL)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Get($URL)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR = http.Get($URL)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Head($URL)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR = http.Head($URL)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Post($$)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR = http.Post($$)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.PostForm($URL, $DATA)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR = http.PostForm($URL, $DATA)
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := $CLIENT.Do($REQ)
          defer func() { _ = $RESP.Body.Close() }()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Get($URL)
          defer func() { _ = $RESP.Body.Close() }()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Post($$)
          defer func() { _ = $RESP.Body.Close() }()
          $$$
        }
    - kind: block
      regex: "(?s)(http\\.(Get|Head|Post|PostForm)|[A-Za-z_][A-Za-z0-9_]*\\.(Do|Get))\\s*\\([^\\n]*\\)\\s*\\n\\s*defer\\s+[A-Za-z_][A-Za-z0-9_]*\\.Body\\.Close\\s*\\(\\)"
severity: error
message: "defer resp.Body.Close() occurs before checking err; resp may be nil and will panic. Check err first, then defer Close()."
''',
    ),
    (
        "go.defer-close-before-err-check",
        r'''id: go.defer-close-before-err-check
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $F, $ERR := os.Open($P)
          defer $F.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $F, $ERR := os.Create($P)
          defer $F.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $F, $ERR := os.OpenFile($P, $M, $PERM)
          defer $F.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $F, $ERR = os.Open($P)
          defer $F.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $F, $ERR = os.Create($P)
          defer $F.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $F, $ERR = os.OpenFile($P, $M, $PERM)
          defer $F.Close()
          $$$
        }
severity: error
message: "defer f.Close() occurs before checking err; f may be nil or stale and will panic/close the wrong handle. Check err first, then defer Close()."
''',
    ),
    (
        "go.sql.defer-rows-close-before-err-check",
        r'''id: go.sql.defer-rows-close-before-err-check
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.Query($$)
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.QueryContext($CTX, $$)
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR = $DB.Query($$)
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR = $DB.QueryContext($CTX, $$)
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.Query($$)
          defer func() { _ = $ROWS.Close() }()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.QueryContext($CTX, $$)
          defer func() { _ = $ROWS.Close() }()
          $$$
        }
    - kind: block
      regex: "(?s)[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*err\\s*:=\\s*[A-Za-z_][A-Za-z0-9_]*\\.(Query|QueryContext)\\s*\\([^\\n]*\\)\\s*\\n\\s*defer\\s+[A-Za-z_][A-Za-z0-9_]*\\.Close\\s*\\(\\)"
severity: error
message: "defer rows.Close() occurs before checking err; rows may be nil and will panic. Check err first, then defer Close()."
''',
    ),
    (
        "go.sql.rows-err-not-checked",
        r'''id: go.sql.rows-err-not-checked
language: go
rule:
  all:
    - pattern: |
        for $ROWS.Next() {
          $$$
        }
    - not:
        has:
          pattern: |
            if err := $ROWS.Err(); err != nil {
              $$$
            }
severity: info
message: "rows.Next loop without rows.Err() check; errors may be missed after iteration."
''',
    ),
    (
        "go.sql.begin-without-defer-rollback",
        r'''id: go.sql.begin-without-defer-rollback
language: go
rule:
  all:
    - any:
        - kind: short_var_declaration
          pattern: $TX, $ERR := $DB.Begin($$$)
        - kind: short_var_declaration
          pattern: $TX, $ERR := $DB.BeginTx($$$)
        - kind: assignment_statement
          pattern: $TX, $ERR = $DB.Begin($$$)
        - kind: assignment_statement
          pattern: $TX, $ERR = $DB.BeginTx($$$)
    - not:
        inside:
          has:
            any:
              - kind: defer_statement
                pattern: defer $TX.Rollback()
              - kind: defer_statement
                pattern: defer func() { $TX.Rollback() }()
severity: warning
message: "Transaction begun without a deferred tx.Rollback() in the containing scope."
''',
    ),
    (
        "go.http-handler-background",
        r'''id: go.http-handler-background
language: go
rule:
  any:
    - kind: function_declaration
      regex: "(?s)http\\.ResponseWriter.*context\\.Background\\s*\\("
    - kind: func_literal
      regex: "(?s)http\\.ResponseWriter.*context\\.Background\\s*\\("
severity: warning
message: "HTTP handler uses context.Background(); prefer r.Context() for cancellation and deadlines."
''',
    ),
    (
        "go.http-transport-missing-timeouts",
        r'''id: go.http-transport-missing-timeouts
language: go
rule:
  pattern: http.Transport{$$$}
  not:
    all:
      - has: { pattern: "ResponseHeaderTimeout: $X" }
      - has: { pattern: "TLSHandshakeTimeout: $Y" }
severity: info
message: "http.Transport missing ResponseHeaderTimeout/TLSHandshakeTimeout (heuristic)."
''',
    ),
    (
        "go.http-client-without-transport",
        r'''id: go.http-client-without-transport
language: go
rule:
  pattern: http.Client{$$$}
  not:
    has:
      pattern: "Transport: $T"
severity: info
message: "http.Client created without explicit Transport; defaults may be fine but review for timeouts/proxy settings."
''',
    ),
    (
        "go.http-response-body-not-closed",
        r'''id: go.http-response-body-not-closed
language: go
rule:
  all:
    - any:
        - kind: short_var_declaration
          pattern: $RESP, $ERR := $CLIENT.Do($REQ)
        - kind: assignment_statement
          pattern: $RESP, $ERR = $CLIENT.Do($REQ)
        - kind: short_var_declaration
          pattern: $RESP, $ERR := http.Get($URL)
        - kind: assignment_statement
          pattern: $RESP, $ERR = http.Get($URL)
        - kind: short_var_declaration
          pattern: $RESP, $ERR := http.Head($URL)
        - kind: assignment_statement
          pattern: $RESP, $ERR = http.Head($URL)
        - kind: short_var_declaration
          pattern: $RESP, $ERR := http.Post($$)
        - kind: assignment_statement
          pattern: $RESP, $ERR = http.Post($$)
        - kind: short_var_declaration
          pattern: $RESP, $ERR := http.PostForm($URL, $DATA)
        - kind: assignment_statement
          pattern: $RESP, $ERR = http.PostForm($URL, $DATA)
        - kind: short_var_declaration
          pattern: $RESP, $ERR := $CLIENT.Get($URL)
        - kind: assignment_statement
          pattern: $RESP, $ERR = $CLIENT.Get($URL)
    - not:
        inside:
          has:
            any:
              - kind: defer_statement
                pattern: defer $RESP.Body.Close()
              - kind: defer_statement
                pattern: defer func() { $RESP.Body.Close() }()
              - kind: defer_statement
                pattern: defer func() { _ = $RESP.Body.Close() }()
severity: warning
message: "HTTP response body not obviously closed; defer resp.Body.Close() on success to avoid leaking connections."
''',
    ),
    (
        "go.http-client-close-idle-missing",
        r'''id: go.http-client-close-idle-missing
language: go
rule:
  all:
    - pattern: $C := &http.Client{$$$}
    - not:
        inside:
          has:
            pattern: $C.CloseIdleConnections()
severity: info
message: "http.Client created; consider CloseIdleConnections() during shutdown for long-running services."
''',
    ),
    (
        "go.resource.timer-not-drained",
        r'''id: go.resource.timer-not-drained
language: go
rule:
  all:
    - kind: short_var_declaration
      pattern: $T := time.NewTimer($$$)
    - not:
        inside:
          has:
            kind: expression_statement
            pattern: <-$T.C
severity: info
message: "time.NewTimer created but channel never drained; if Stop() fails, timer may fire later (heuristic)."
''',
    ),
    (
        "go.waitgroup-add-no-done",
        r'''id: go.waitgroup-add-no-done
language: go
rule:
  kind: function_declaration
  regex: "(?s)\\.[Aa]dd\\s*\\("
  not:
    regex: "\\.Done\\s*\\("
severity: info
message: "WaitGroup.Add without nearby Done in same function (heuristic)."
''',
    ),
    (
        "go.err-shadow",
        r'''id: go.err-shadow
language: go
rule:
  pattern: $X, err := $CALL
severity: info
message: "Potential err shadowing via ':='; ensure you check the correct err variable."
''',
    ),
    (
        "go.iferr-empty",
        r'''id: go.iferr-empty
language: go
rule:
  pattern: |
    if err != nil {
    }
severity: warning
message: "Empty if err != nil block; likely unfinished or swallowed error."
''',
    ),
    (
        "go.iferr-return-nil",
        r'''id: go.iferr-return-nil
language: go
rule:
  all:
    - pattern: |
        if err != nil {
          return nil
        }
    - not:
        regex: ','
severity: error
message: "Error checked but dropped (return nil). Likely should return err or wrap it."
''',
    ),
    (
        "go.exec-strings-fields",
        r'''id: go.exec-strings-fields
language: go
rule:
  any:
    - pattern: exec.Command($CMD, strings.Fields($ARGS)...)
    - pattern: exec.CommandContext($CTX, $CMD, strings.Fields($ARGS)...)
severity: warning
message: "exec.Command called with strings.Fields(...); verify argument safety and avoid shell-like parsing."
''',
    ),
    (
        "go.loop-var-capture-for",
        r'''id: go.loop-var-capture-for
language: go
rule:
  kind: for_statement
  regex: "(?s)for\\s+[A-Za-z_][A-Za-z0-9_]*\\s*:=\\s*[^;]+;[^;]+;[^\\{]+\\{.*\\bgo\\s+func\\s*\\(\\)\\s*\\{"
severity: warning
message: "For-loop variable captured by goroutine closure; pass it as a parameter to avoid capture bugs."
''',
    ),
    (
        "go.json.decoder-unbounded-body",
        r'''id: go.json.decoder-unbounded-body
language: go
rule:
  all:
    - pattern: json.NewDecoder($R.Body).Decode($V)
    - not:
        inside:
          has:
            pattern: http.MaxBytesReader($W, $R.Body, $N)
severity: info
message: "json.NewDecoder(r.Body) without http.MaxBytesReader; consider bounding request size."
''',
    ),
    (
        "go.sql-dynamic-string",
        r'''id: go.sql-dynamic-string
language: go
rule:
  any:
    - kind: call_expression
      regex: "\\.(Exec|Query)\\s*\\([^,\\n)]*\\+"
    - kind: call_expression
      regex: "\\.(ExecContext|QueryContext)\\s*\\([^,\\n)]*,\\s*[^,\\n)]*\\+"
severity: warning
message: "Potential dynamic SQL via string concatenation at Exec/Query sink; use placeholders/parameters."
''',
    ),
    (
        "go.close-error-ignored",
        r'''id: go.close-error-ignored
language: go
rule:
  pattern: defer $C.Close()
  not:
    inside:
      has:
        pattern: |
          if err := $C.Close(); err != nil {
            $$$
          }
severity: info
message: "Deferred Close() return value ignored; for writers/files, Close can fail (flush errors)."
''',
    ),
    (
        "go.sql.defer-rollback-before-err-check",
        r'''id: go.sql.defer-rollback-before-err-check
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR := $DB.Begin($$$)
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR := $DB.BeginTx($$$)
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR = $DB.Begin($$$)
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR = $DB.BeginTx($$$)
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR := $DB.BeginTx($$$)
          defer func() { _ = $TX.Rollback() }()
          $$$
        }
    - kind: block
      regex: "(?s)[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*err\\s*:?=\\s*[A-Za-z_][A-Za-z0-9_]*\\.(Begin|BeginTx)\\s*\\([^\\n]*\\)\\s*\\n\\s*defer\\s+[A-Za-z_][A-Za-z0-9_]*\\.Rollback\\s*\\(\\)"
severity: error
message: "defer tx.Rollback() occurs before checking err; tx may be nil/stale and will panic/rollback wrong tx. Check err first, then defer Rollback()."
''',
    ),
    (
        "go.sql.defer-rollback-delayed",
        r'''id: go.sql.defer-rollback-delayed
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR := $DB.Begin($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR := $DB.BeginTx($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR = $DB.Begin($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR = $DB.BeginTx($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $TX.Rollback()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $TX, $ERR := $DB.BeginTx($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer func() { _ = $TX.Rollback() }()
          $$$
        }
    - kind: block
      regex: "(?s)[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*err\\s*:?=\\s*[A-Za-z_][A-Za-z0-9_]*\\.(Begin|BeginTx)\\s*\\([^\\n]*\\)\\s*\\n\\s*if\\s+err\\s*!=\\s*nil\\s*\\{[^}]*\\}\\s*\\n\\s*[^\\r\\n]+\\s*\\n\\s*defer\\s+[A-Za-z_][A-Za-z0-9_]*\\.Rollback\\s*\\(\\)"
severity: warning
message: "defer tx.Rollback() is not placed immediately after a successful Begin; early returns between may leak/skip rollback."
''',
    ),
    (
        "go.sql.rows-not-closed",
        r'''id: go.sql.rows-not-closed
language: go
rule:
  all:
    - any:
        - kind: short_var_declaration
          pattern: $ROWS, $ERR := $DB.Query($$$)
        - kind: short_var_declaration
          pattern: $ROWS, $ERR := $DB.QueryContext($CTX, $$$)
        - kind: assignment_statement
          pattern: $ROWS, $ERR = $DB.Query($$$)
        - kind: assignment_statement
          pattern: $ROWS, $ERR = $DB.QueryContext($CTX, $$$)
    - not:
        inside:
          has:
            any:
              - kind: defer_statement
                pattern: defer $ROWS.Close()
              - kind: expression_statement
                pattern: $ROWS.Close()
              - kind: defer_statement
                pattern: defer func() { _ = $ROWS.Close() }()
              - kind: defer_statement
                pattern: defer func() { $ROWS.Close() }()
severity: warning
message: "sql.Rows from Query not obviously closed; defer rows.Close() after successful query."
''',
    ),
    (
        "go.sql.defer-rows-close-delayed",
        r'''id: go.sql.defer-rows-close-delayed
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.Query($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.QueryContext($CTX, $$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR = $DB.Query($$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR = $DB.QueryContext($CTX, $$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $ROWS.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $ROWS, $ERR := $DB.QueryContext($CTX, $$$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer func() { _ = $ROWS.Close() }()
          $$$
        }
    - kind: block
      regex: "(?s)[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*err\\s*:?=\\s*[A-Za-z_][A-Za-z0-9_]*\\.(Query|QueryContext)\\s*\\([^\\n]*\\)\\s*\\n\\s*if\\s+err\\s*!=\\s*nil\\s*\\{[^}]*\\}\\s*\\n\\s*[^\\r\\n]+\\s*\\n\\s*defer\\s+[A-Za-z_][A-Za-z0-9_]*\\.Close\\s*\\(\\)"
severity: info
message: "defer rows.Close() is not placed immediately after a successful Query; early returns between may leak rows/connections."
''',
    ),
    (
        "go.http.defer-body-close-delayed",
        r'''id: go.http.defer-body-close-delayed
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := $CLIENT.Do($REQ)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Get($URL)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Post($$)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Head($URL)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.PostForm($URL, $DATA)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer $RESP.Body.Close()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $RESP, $ERR := http.Get($URL)
          if $ERR != nil { $$$ }
          $S
          $$$
          defer func() { _ = $RESP.Body.Close() }()
          $$$
        }
    - kind: block
      regex: "(?s)(http\\.(Get|Head|Post|PostForm)|[A-Za-z_][A-Za-z0-9_]*\\.(Do|Get))\\s*\\([^\\n]*\\)\\s*\\n\\s*if\\s+err\\s*!=\\s*nil\\s*\\{[^}]*\\}\\s*\\n\\s*[^\\r\\n]+\\s*\\n\\s*defer\\s+[A-Za-z_][A-Za-z0-9_]*\\.Body\\.Close\\s*\\(\\)"
severity: info
message: "defer resp.Body.Close() is not placed immediately after a successful request; early returns between may leak connections."
''',
    ),
    (
        "go.context.cancel-defer-before-err-check",
        r'''id: go.context.cancel-defer-before-err-check
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          defer $CANCEL()
          if $ERR != nil { $$$ }
          $S
          $$$
          $CANCEL()
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          defer func() { $CANCEL() }()
          if $ERR != nil { $$$ }
          $S
          $$$
          $CANCEL()
          $$$
        }
    - kind: block
      regex: "(?s)defer\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\(\\)\\s*\\n\\s*if\\s+err\\s*!=\\s*nil\\s*\\{[^}]*\\}\\s*\\n\\s*[^\\r\\n]+\\s*\\n\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\(\\)"
severity: error
message: "defer cancel() occurs before checking err; you may be deferring the wrong cancel (shadowing/reassign bug)."
''',
    ),
    (
        "go.context.cancel-defer-in-if",
        r'''id: go.context.cancel-defer-in-if
language: go
rule:
  any:
    - kind: block
      pattern: |
        {
          $$$
          $CTX, $CANCEL := context.WithCancel($PARENT)
          if $COND {
            $$$
            defer $CANCEL()
            $$$
          }
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $CTX, $CANCEL := context.WithTimeout($PARENT, $DUR)
          if $COND {
            $$$
            defer $CANCEL()
            $$$
          }
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $CTX, $CANCEL := context.WithDeadline($PARENT, $DL)
          if $COND {
            $$$
            defer $CANCEL()
            $$$
          }
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $CTX, $CANCEL = context.WithCancel($PARENT)
          if $COND {
            $$$
            defer $CANCEL()
            $$$
          }
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $CTX, $CANCEL = context.WithTimeout($PARENT, $DUR)
          if $COND {
            $$$
            defer $CANCEL()
            $$$
          }
          $$$
        }
    - kind: block
      pattern: |
        {
          $$$
          $CTX, $CANCEL = context.WithDeadline($PARENT, $DL)
          if $COND {
            $$$
            defer $CANCEL()
            $$$
          }
          $$$
        }
    - kind: block
      regex: "(?s)context\\.With(Cancel|Timeout|Deadline)\\s*\\([^\\n]*\\)\\s*\\n\\s*if\\s+[^\\n{]+\\{[^}]*\\bdefer\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\(\\)"
severity: warning
message: "cancel() is deferred conditionally inside if; prefer unconditional defer cancel() immediately after With*."
''',
    ),
    (
        "go.write-error-ignored",
        r'''id: go.write-error-ignored
language: go
rule:
  any:
    - kind: short_var_declaration
      pattern: $N, _ := $W.Write($$$)
    - kind: assignment_statement
      pattern: $N, _ = $W.Write($$$)
    - kind: short_var_declaration
      pattern: _, _ := $W.Write($$$)
    - kind: assignment_statement
      pattern: _, _ = $W.Write($$$)
severity: info
message: "Write(...) error is ignored via blank identifier; consider handling/propagating the error."
''',
    ),
    (
        "go.http.responsewriter-write-ignored",
        r'''id: go.http.responsewriter-write-ignored
language: go
rule:
  all:
    - kind: expression_statement
      regex: "\\.Write\\s*\\("
    - inside:
        stopBy: end
        any:
          - kind: function_declaration
            regex: "\\bhttp\\.ResponseWriter\\b"
          - kind: func_literal
            regex: "\\bhttp\\.ResponseWriter\\b"
severity: info
message: "http.ResponseWriter.Write(...) return values ignored; consider checking error (or explicitly discarding with _, _ = ...)."
''',
    ),
    (
        "go.fmt.fprintf-error-ignored",
        r'''id: go.fmt.fprintf-error-ignored
language: go
rule:
  any:
    - kind: expression_statement
      regex: "\\bfmt\\.Fprintf\\s*\\("
    - kind: short_var_declaration
      regex: ",\\s*_\\s*:=\\s*fmt\\.Fprintf\\s*\\("
    - kind: assignment_statement
      regex: ",\\s*_\\s*=\\s*fmt\\.Fprintf\\s*\\("
    - kind: short_var_declaration
      regex: "^_\\s*,\\s*_\\s*:=\\s*fmt\\.Fprintf\\s*\\("
    - kind: assignment_statement
      regex: "^_\\s*,\\s*_\\s*=\\s*fmt\\.Fprintf\\s*\\("
severity: info
message: "fmt.Fprintf return error ignored; consider handling it (especially when writing to network/file)."
''',
    ),
    (
        "go.json.encode-error-ignored",
        r'''id: go.json.encode-error-ignored
language: go
rule:
  all:
    - pattern: json.NewEncoder($X).Encode($V)
    - inside:
        kind: expression_statement
severity: warning
message: "json.Encoder.Encode(...) return error ignored; consider handling it."
''',
    ),
    (
        "go.template.execute-error-ignored",
        r'''id: go.template.execute-error-ignored
language: go
rule:
  any:
    - all:
        - pattern: $T.Execute($W, $D)
        - inside:
            kind: expression_statement
    - all:
        - pattern: $T.ExecuteTemplate($W, $NAME, $D)
        - inside:
            kind: expression_statement
severity: warning
message: "template Execute(...) error ignored; consider handling it."
''',
    ),
)


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, the sgconfigs, and the manifest.

    Returns the manifest dict (rule_id -> {severity, language, file}); the
    same document is written to ``<rule_dir>/manifest.json``. Re-running on
    the same ``rule_dir`` reproduces the identical tree.
    """
    rule_dir = Path(rule_dir)
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # User rules (--rules DIR) are copied verbatim (ubs-golang.sh 2994-2996).
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
        # NOT listed in the sgconfig (see _UNPARSEABLE_RULES above) — the
        # legacy consolidated scan would have aborted on them.
        if stem not in _UNPARSEABLE_RULES:
            config_entries.append(f"  - rules/{name}")

    for user_file in user_rule_files:
        config_entries.append(f"  - rules/{user_file.name}")

    (rule_dir / f"sgconfig-{_GRAMMAR}.yml").write_text(
        "ruleDirs:\n" + "\n".join(config_entries) + "\n", encoding="utf-8"
    )

    # The async rule is written alongside the pack and manifest-tracked, but
    # scanned from its own single-rule sgconfig (legacy: separate `scan
    # --rule` pass, 632) so it never rides along in the consolidated scan.
    async_stem, async_text = _ASYNC_RULE
    async_name = f"{async_stem}.yml"
    (rules_dir / async_name).write_text(async_text, encoding="utf-8")
    async_id = _first_match(_ID_RE, async_text)
    manifest[async_id] = {
        "severity": SEVERITY_MAP.get(
            async_id, _map_severity(_first_match(_SEVERITY_RE, async_text))
        ),
        "language": _first_match(_LANGUAGE_RE, async_text),
        "file": f"rules/{async_name}",
    }
    (rule_dir / f"sgconfig-{_GRAMMAR}-async.yml").write_text(
        "ruleDirs:\n" + f"  - rules/{async_name}\n", encoding="utf-8"
    )

    manifest_path = rule_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
