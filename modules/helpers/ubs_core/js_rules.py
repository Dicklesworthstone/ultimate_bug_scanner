"""ubs_core.js_rules — ast-grep rule-pack generation for the JS/TS module (bead 0xjg.4).

Python port of the runtime ast-grep rule GENERATION in modules/ubs-js.sh:
``write_ast_rules`` (3134-3624), ``emit_rule_language_variants`` (3039-3065),
and the per-group severity/summary/remediation metadata maps (96-202).

``generate(rule_dir, user_rules_dir=None)`` writes::

    <rule_dir>/rules/*.yml   the 37 base rules (byte-identical to the legacy
                             heredocs) plus one file per language variant;
                             variants keep the base rule's id (GH #93) and
                             differ only in the rewritten `language:` line
    <rule_dir>/sgconfig-javascript.yml   one config per grammar, each listing
    <rule_dir>/sgconfig-typescript.yml   the rule files of its grammar — the
    <rule_dir>/sgconfig-tsx.yml          legacy __variants-<grammar>.yml
                             aggregates dissolved into per-language files, so
                             rule ids stay unique inside every single config
    <rule_dir>/manifest.json rule_id -> {severity, language, file} for the 37
                             base rules; also the dict ``generate`` returns

User rules (``user_rules_dir``) are copied verbatim under ``rules/``, listed in
the config of their declared grammar, and excluded from variant generation
(GH #93): their author controls language targeting.

Manifest severity is ``SEVERITY_MAP[rule_id]`` when mapped, else the YAML
severity — matching legacy report-time lookup (ubs-js.sh 522). The exported
maps carry the DECLARED values of 96-202; the ``--fail-on-warning`` runtime
downgrade of the async group (ubs-js.sh 293-296) stays a consumer concern.
``CATEGORY_MAP`` derives each id's category from its 96-202 group following the
contract category grammar ``<lang>.<family>`` (js.async, js.error, ...).
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
# Metadata maps — ubs-js.sh 96-202 (declared values), keyed by rule id.
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, str] = {
    # ASYNC_ERROR_SEVERITY
    "js.async.then-no-catch": "warning",
    "js.async.promiseall-no-try": "warning",
    # GH #93 calibration (ubs-js.sh 113-119): a bare await cannot see
    # caller-side handling, so it is style guidance, not evidence of an
    # unhandled rejection — info keeps it visible without failing
    # --fail-on-warning gates.
    "js.async.await-no-try": "info",
    "js.async.dangling-promise": "warning",
    # ERROR_RULE_SEVERITY
    "js.error.empty-catch": "warning",
    "js.error.throw-string": "warning",
    "js.json-parse-without-try": "warning",
    # RESOURCE_RULE_SEVERITY
    "js.resource.listener-no-remove": "warning",
    "js.resource.interval-no-clear": "warning",
    "js.resource.observer-no-disconnect": "warning",
    # HOOKS_SEVERITY
    "js.hooks.no-deps": "warning",
    "js.hooks.missing-critical": "critical",
    "js.hooks.missing-warning": "warning",
    "js.hooks.unstable": "critical",
    "js.hooks.unused": "info",
    # TAINT_SEVERITY
    "js.taint.xss": "critical",
    "js.taint.eval": "critical",
    "js.taint.command": "critical",
    "js.taint.sql": "critical",
}

CATEGORY_MAP: dict[str, str] = {
    # ASYNC_ERROR_RULE_IDS
    "js.async.then-no-catch": "js.async",
    "js.async.promiseall-no-try": "js.async",
    "js.async.await-no-try": "js.async",
    "js.async.dangling-promise": "js.async",
    # ERROR_RULE_IDS
    "js.error.empty-catch": "js.error",
    "js.error.throw-string": "js.error",
    "js.json-parse-without-try": "js.error",
    # RESOURCE_RULE_IDS
    "js.resource.listener-no-remove": "js.resource",
    "js.resource.interval-no-clear": "js.resource",
    "js.resource.observer-no-disconnect": "js.resource",
    # HOOKS_RULE_IDS
    "js.hooks.no-deps": "js.hooks",
    "js.hooks.missing-critical": "js.hooks",
    "js.hooks.missing-warning": "js.hooks",
    "js.hooks.unstable": "js.hooks",
    "js.hooks.unused": "js.hooks",
    # TAINT_RULE_IDS
    "js.taint.xss": "js.taint",
    "js.taint.eval": "js.taint",
    "js.taint.command": "js.taint",
    "js.taint.sql": "js.taint",
}

SUMMARY_MAP: dict[str, str] = {
    # ASYNC_ERROR_SUMMARY
    "js.async.then-no-catch": "Promise.then chain missing .catch()",
    "js.async.promiseall-no-try": "Promise.all without try/catch",
    "js.async.await-no-try": "await outside try/catch",
    "js.async.dangling-promise": "Possible unhandled promise (not awaited/returned)",
    # ERROR_RULE_SUMMARY
    "js.error.empty-catch": "Catch block swallows errors silently",
    "js.error.throw-string": "Throwing string literal instead of Error object",
    "js.json-parse-without-try": "JSON.parse without try/catch",
    # RESOURCE_RULE_SUMMARY
    "js.resource.listener-no-remove": "Global event listener missing removeEventListener",
    "js.resource.interval-no-clear": "setInterval without matching clearInterval",
    "js.resource.observer-no-disconnect": "MutationObserver without disconnect()",
    # HOOKS_SUMMARY
    "js.hooks.no-deps": "React hook missing dependency array",
    "js.hooks.missing-critical": "React hook dependency array missing props/context",
    "js.hooks.missing-warning": "React hook dependency array missing local state/refs",
    "js.hooks.unstable": "Dependency array contains unstable values that change every render",
    "js.hooks.unused": "Dependency array includes unused entries",
    # TAINT_SUMMARY
    "js.taint.xss": "Unsanitized data flows to HTML response sinks",
    "js.taint.eval": "User input reaches eval/Function without sanitization",
    "js.taint.command": "User input reaches command execution APIs",
    "js.taint.sql": "User input reaches SQL query builders without sanitization",
}

REMEDIATION_MAP: dict[str, str] = {
    # ASYNC_ERROR_REMEDIATION
    "js.async.then-no-catch": "Chain .catch() (or .finally()) to surface rejections",
    "js.async.promiseall-no-try": "Wrap Promise.all in try/catch to handle aggregate failures",
    "js.async.await-no-try": "Wrap awaited calls in try/catch to surface rejections",
    "js.async.dangling-promise": "Await the promise, return it, or add .catch()/.finally()",
    # ERROR_RULE_REMEDIATION
    "js.error.empty-catch": "Log or rethrow the caught error; empty catch hides bugs",
    "js.error.throw-string": 'Use throw new Error("message") so stack traces include context',
    "js.json-parse-without-try": "Wrap JSON.parse in try/catch or validate input",
    # RESOURCE_RULE_REMEDIATION
    "js.resource.listener-no-remove": "Store the handler and call removeEventListener during teardown",
    "js.resource.interval-no-clear": "Keep the interval id and clearInterval when disposing",
    "js.resource.observer-no-disconnect": "Call disconnect() on observers when they are no longer needed",
    # HOOKS_REMEDIATION
    "js.hooks.no-deps": "Provide a dependency array or intentionally document why it is omitted",
    "js.hooks.missing-critical": "Add the referenced props/context values to the dependency array to avoid stale data",
    "js.hooks.missing-warning": "Add local state/refs used inside the hook to its dependency array",
    "js.hooks.unstable": "Memoize objects/functions placed in dependency arrays (useMemo/useCallback) to avoid infinite loops",
    "js.hooks.unused": "Remove unused dependency entries to keep dependency arrays minimal and intentional",
    # TAINT_REMEDIATION
    "js.taint.xss": "Sanitize or escape user input (DOMPurify.sanitize/escapeHtml) before injecting into HTML",
    "js.taint.eval": "Avoid eval/Function on user input or whitelist commands explicitly",
    "js.taint.command": "Use allowlists or escape shell arguments before passing user input to exec/spawn",
    "js.taint.sql": "Use prepared statements or escape inputs with parameterized queries",
}

_GRAMMARS = ("javascript", "typescript", "tsx")

# emit_rule_language_variants (ubs-js.sh 3051-3055): extra grammars each base
# language re-parses under.
_VARIANT_TARGETS: dict[str, tuple[str, ...]] = {
    "javascript": ("typescript", "tsx"),
    "typescript": ("javascript", "tsx"),
    "tsx": ("javascript",),  # JSX parses under the javascript grammar (.jsx)
}

# TS-only syntax (non-null assertion `!`) cannot re-parse as javascript
# (ubs-js.sh 3057-3058, GH #93).
_TSX_ONLY_FILES = frozenset({"ts-non-null-chain.yml"})

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def _retarget(rule_text: str, source: str, target: str) -> str:
    """Rewrite the `language:` line exactly like the legacy sed (ubs-js.sh 3062)."""
    return re.sub(
        rf"^language:[ \t]*{source}[ \t]*$",
        f"language: {target}",
        rule_text,
        flags=re.MULTILINE,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack — verbatim heredoc bodies of write_ast_rules (3134-3624).
# (file stem, YAML text)
# ─────────────────────────────────────────────────────────────────────────────
_RULES: tuple[tuple[str, str], ...] = (
    # Core rules
    # (Keep file names arbitrary; ruleId is authoritative)
    (
        "parseInt-no-radix",
        r'''id: js.parseInt-no-radix
language: javascript
rule:
  kind: call_expression
  pattern: parseInt($ARG)
  not:
    has:
      pattern: parseInt($ARG, $RADIX)
severity: warning
message: "parseInt without radix; use parseInt(x, 10)"
''',
    ),
    (
        "nan-direct-compare",
        r'''id: js.nan-direct-compare
language: javascript
rule:
  any:
    - pattern: $X == NaN
    - pattern: $X === NaN
    - pattern: $X != NaN
    - pattern: $X !== NaN
severity: error
message: "Direct NaN comparison is always false; use Number.isNaN(x)"
''',
    ),
    (
        "innerHTML-assign",
        r'''id: js.innerHTML-assign
language: javascript
rule:
  pattern: $EL.innerHTML = $VAL
severity: warning
message: "Assigning innerHTML; ensure input is sanitized or use textContent"
''',
    ),
    (
        "then-without-catch",
        r'''id: js.then-without-catch
language: javascript
rule:
  all:
    - pattern: $P.then($ARGS)
    - not:
        inside:
          pattern: $_.catch($$$)
          stopBy: end
    - not:
        inside:
          kind: try_statement
          stopBy: end
    - not:
        inside:
          kind: return_statement
          stopBy: end
severity: warning
message: "Promise.then without catch/finally; handle rejections"
''',
    ),
    # Alias for async group compatibility
    (
        "async-then-no-catch",
        r'''id: js.async.then-no-catch
language: javascript
rule:
  all:
    - pattern: $P.then($ARGS)
    - not:
        inside:
          pattern: $_.catch($$$)
          stopBy: end
    - not:
        inside:
          kind: try_statement
          stopBy: end
    - not:
        inside:
          kind: return_statement
          stopBy: end
severity: warning
message: "Promise.then without .catch/.finally; add rejection handling"
''',
    ),
    (
        "async-promiseall-no-try",
        r'''id: js.async.promiseall-no-try
language: javascript
rule:
  all:
    - pattern: await Promise.all($ARGS)
    - not:
        inside:
          kind: try_statement
          stopBy: end
    - not:
        inside:
          kind: return_statement
          stopBy: end
severity: warning
message: "await Promise.all() without try/catch; wrap to handle aggregate failures"
''',
    ),
    (
        "async-await-no-try",
        r'''id: js.async.await-no-try
language: javascript
rule:
  all:
    - pattern: await $E
    - not:
        inside:
          kind: try_statement
          stopBy: end
    - not:
        inside:
          kind: return_statement
          stopBy: end
    - not:
        inside:
          pattern: await Promise.all($ARGS)
          stopBy: end
    - not:
        inside:
          pattern: await Promise.allSettled($ARGS)
          stopBy: end
    - not:
        inside:
          pattern: await Promise.race($ARGS)
          stopBy: end
severity: warning
message: "await without try/catch; wrap to handle rejections"
''',
    ),
    (
        "eval-call",
        r'''id: js.eval-call
language: javascript
rule:
  kind: call_expression
  pattern: eval($$$)
severity: error
message: "eval() allows arbitrary code execution"
''',
    ),
    (
        "new-function",
        r'''id: js.new-function
language: javascript
rule:
  kind: new_expression
  pattern: new Function($$$)
severity: error
message: "new Function() is equivalent to eval()"
''',
    ),
    (
        "document-write",
        r'''id: js.document-write
language: javascript
rule:
  pattern: document.write($$$)
severity: error
message: "document.write() is dangerous and breaks SPAs"
''',
    ),
    (
        "react-useeffect-cleanup",
        r'''id: react.useeffect-missing-cleanup
language: typescript
rule:
  pattern: useEffect(() => { $$$ }, $DEPS)
  not:
    has:
      pattern: return () => { $$$ }
severity: info
message: "useEffect without cleanup may leak subscriptions or timers"
''',
    ),
    # React / JSX expansions
    (
        "react-missing-key",
        r'''id: react.list-missing-key
language: tsx
rule:
  all:
    - kind: jsx_self_closing_element
    - pattern: <$COMP $$$ />
    - not:
        regex: "key\\s*="
severity: warning
message: "JSX list item missing key prop"
''',
    ),
    (
        "react-dangerously-set-html",
        r'''id: react.dangerously-set-html
language: tsx
rule:
  pattern: <$_ dangerouslySetInnerHTML={$OBJ} />
severity: warning
message: "dangerouslySetInnerHTML used; ensure the HTML is sanitized"
''',
    ),
    (
        "react-setstate-in-render",
        r'''id: react.setstate-in-render
language: tsx
rule:
  kind: method_definition
  regex: "render\\s*\\([^)]*\\)\\s*\\{[^}]*setState\\s*\\("
severity: error
message: "setState called inside render; causes infinite re-render"
''',
    ),
    # Node / security
    (
        "node-child-process",
        r'''id: node.child-process-exec
language: typescript
rule:
  any:
    - pattern: require('child_process').exec($$$)
    - pattern: import('child_process').then($MOD => $MOD.exec($$$))
    - pattern: exec($$$)
severity: warning
message: "child_process.exec used; sanitize inputs or prefer execFile/spawn"
''',
    ),
    (
        "insecure-crypto",
        r'''id: security.insecure-crypto
language: typescript
rule:
  any:
    - pattern: crypto.createHash("md5")
    - pattern: crypto.createHash('md5')
    - pattern: crypto.createHash("sha1")
    - pattern: crypto.createHash('sha1')
severity: warning
message: "Weak hash algorithm (md5/sha1); prefer SHA-256/512 or stronger"
''',
    ),
    (
        "insecure-random",
        r'''id: security.insecure-random
language: typescript
rule:
  pattern: Math.random()
severity: info
message: "Math.random used for security-sensitive randomness? Prefer crypto.randomUUID/randomBytes"
''',
    ),
    (
        "http-url",
        r'''id: security.http-url
language: typescript
rule:
  kind: string_fragment
  regex: "^http://"
severity: info
message: "Plain HTTP URL detected; ensure HTTPS is used for production"
''',
    ),
    # TypeScript strictness
    (
        "ts-non-null-chain",
        r'''id: ts.non-null-assertion-chain
language: typescript
rule:
  pattern: $X!.$Y
severity: warning
message: "Non-null assertion (!) in property chain; prefer guards or optional chaining"
''',
    ),
    # Error-handling rules
    (
        "error-empty-catch",
        r'''id: js.error.empty-catch
language: javascript
rule:
  kind: catch_clause
  regex: "catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}"
severity: warning
message: "Empty catch block hides errors; log or rethrow the exception"
''',
    ),
    (
        "error-throw-string",
        r'''id: js.error.throw-string
language: javascript
rule:
  kind: throw_statement
  regex: "throw\\s+['\\\"]"
severity: warning
message: "Throwing string literals loses stack traces; use throw new Error('message')"
''',
    ),
    # JSON.parse without try/catch
    (
        "json-parse-without-try",
        r'''id: js.json-parse-without-try
language: javascript
rule:
  all:
    - pattern: JSON.parse($X)
    - not:
        inside:
          kind: try_statement
          stopBy: end
severity: warning
message: "JSON.parse without try/catch; malformed input will throw"
''',
    ),
    # New: Dangling promises (heuristic)
    (
        "async-dangling-promise",
        r'''id: js.async.dangling-promise
language: javascript
rule:
  all:
    - pattern: $CALLEE($$$)
    - regex: "^(fetch\\b|axios(\\.[A-Za-z_][A-Za-z0-9_]*)?\\b|superagent\\b|request\\b|req\\b|http\\b|https\\b|api\\b|callApi\\b|post\\b|put\\b|get\\b|del\\b|head\\b|patch\\b|upload\\b|download\\b|Promise\\.[A-Za-z_][A-Za-z0-9_]*\\b|new\\s+Promise\\b|[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*(Async|Promise)\\b)"
    - not:
        inside:
          any:
            - pattern: await $EXPR
            - pattern: $EXPR.then($$$)
            - pattern: $EXPR.catch($$$)
            - pattern: $EXPR.finally($$$)
            - pattern: Promise.all($$$)
            - pattern: Promise.race($$$)
            - pattern: Promise.allSettled($$$)
            - kind: return_statement
            - kind: try_statement
          stopBy: end
    - not:
        regex: "^(document\\.|window\\.|console\\.|JSON\\.|Math\\.|Date\\.|Array\\.|Object\\.|Set\\.|Map\\.|WeakMap\\.|WeakSet\\.|Intl\\.|Number\\.|String\\.|Boolean\\.|parse\\b|encode\\b|decode\\b|transform\\b|render\\b|append\\b|push\\b|join\\b|filter\\b|map\\b|reduce\\b|forEach\\b|has\\b|get\\b|set\\b)"
    - not:
        regex: "\\.(catch|then|finally)\\s*\\("
severity: warning
message: "Possible unhandled/dangling promise; use await/then/catch"
''',
    ),
    # New: fetch without rejection handling
    (
        "fetch-no-catch",
        r'''id: js.fetch.no-catch
language: javascript
rule:
  all:
    - pattern: fetch($ARGS)
    - not:
        inside:
          kind: try_statement
          stopBy: end
    - not:
        inside:
          kind: return_statement
          stopBy: end
    - not:
        inside:
          pattern: $_.catch($$$)
          stopBy: end
    - not:
        inside:
          pattern: await $EXPR
          stopBy: end
severity: warning
message: "fetch() without catch/try; network failures will be unhandled"
''',
    ),
    # New: insecure cookie usage
    (
        "cookie-insecure",
        r'''id: security.cookie-insecure
language: typescript
rule:
  pattern: $OBJ.cookie($NAME, $VAL)
severity: warning
message: "Set-Cookie without httpOnly/secure/sameSite; add them to mitigate XSS/CSRF"
''',
    ),
    # New: header injection risk
    (
        "header-taint",
        r'''id: js.taint.header-injection
language: typescript
rule:
  pattern: res.set($NAME, $VAL)
severity: warning
message: "Headers set from variables; ensure input is sanitized to prevent header injection"
''',
    ),
    # New: insecure crypto params
    (
        "insecure-crypto-params",
        r'''id: security.insecure-crypto-params
language: typescript
rule:
  any:
    - pattern: crypto.pbkdf2($$$)
    - pattern: crypto.pbkdf2Sync($$$)
severity: info
message: "crypto.pbkdf2/Sync called; ensure iteration count and key length meet policy"
''',
    ),
    # New: env leak heuristic
    (
        "env-leak",
        r'''id: security.env-in-client
language: typescript
rule:
  pattern: process.env.$NAME
severity: info
message: "process.env used; ensure not bundled to client or prefixed (NEXT_PUBLIC_ etc.)"
''',
    ),
    # New: other DOM assignment surfaces
    (
        "innerText-outerHTML",
        r'''id: js.dom.innerText-outerHTML
language: typescript
rule:
  any:
    - pattern: $EL.innerText = $VAL
    - pattern: $EL.outerHTML = $VAL
severity: warning
message: "DOM text/html assignment; confirm the source is trusted or sanitized"
''',
    ),
    (
        "js-resource-add-listener",
        r'''id: js.resource.listener-no-remove
language: javascript
rule:
  pattern: $TARGET.addEventListener($EVENT, $HANDLER)
  not:
    inside:
      pattern: $TARGET.removeEventListener($EVENT, $HANDLER)
severity: warning
message: "addEventListener without matching removeEventListener in the same scope."
''',
    ),
    (
        "js-resource-interval",
        r'''id: js.resource.interval-no-clear
language: javascript
rule:
  pattern: $TIMER = setInterval($CALL)
  not:
    inside:
      pattern: clearInterval($TIMER)
severity: warning
message: "setInterval assigned to a variable without clearInterval on the same identifier."
''',
    ),
    (
        "js-resource-observer",
        r'''id: js.resource.observer-no-disconnect
language: javascript
rule:
  pattern: $OBS = new MutationObserver($CALLBACK)
  not:
    inside:
      pattern: $OBS.disconnect()
severity: warning
message: "MutationObserver created without disconnect()."
''',
    ),
    # ───── Session-mined bug patterns (cass flywheel) ──────────────────────────
    # Rules derived from 17+ TS/JS bugs found via iterative deep-audit sessions
    # in the jeffreys-skills-md SaaS codebase.
    (
        "js-nullish-chain",
        r'''id: js.nullish-coalescing-chain
language: typescript
rule:
  pattern: $A ?? $B ?? $C
severity: info
message: "Chained ?? operators have left-to-right precedence; add parentheses to clarify intent"
''',
    ),
    (
        "js-usememo-empty-deps",
        r'''id: js.react.useMemo-empty-deps
language: typescript
rule:
  any:
    - pattern: useMemo(() => $BODY, [])
    - pattern: useCallback(($$$) => $BODY, [])
severity: info
message: "Empty dependency array with non-trivial body; verify all referenced values are truly stable or add them to deps"
''',
    ),
    (
        "js-sort-undefined",
        r'''id: js.tanstack.sortUndefined-direction
language: typescript
rule:
  kind: pair
  regex: "sortUndefined:\\s*-1"
severity: info
message: "sortUndefined: -1 sorts nulls to top; use 1 to sort to bottom (common expectation)"
''',
    ),
    (
        "js-non-atomic-write",
        r'''id: js.fs.writeFileSync-not-atomic
language: typescript
rule:
  any:
    - pattern: fs.writeFileSync($PATH, $$$)
    - pattern: writeFileSync($PATH, $$$)
severity: info
message: "writeFileSync is not atomic; for durability, write to temp file and rename"
''',
    ),
    (
        "js-operator-precedence-nullish",
        r'''id: js.operator-precedence-ternary-nullish
language: typescript
rule:
  any:
    - pattern: "$A ?? $B ? $C : $D"
severity: warning
message: "?? and ternary have ambiguous precedence; add parentheses: ($A ?? $B) ? ... or $A ?? ($B ? ...)"
''',
    ),
)


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, per-grammar sgconfigs, and manifest.

    Returns the manifest dict (rule_id -> {severity, language, file}); the same
    document is written to ``<rule_dir>/manifest.json``. Re-running on the same
    ``rule_dir`` reproduces the identical tree.
    """
    rule_dir = Path(rule_dir)
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # User rules are copied verbatim and excluded from language-variant
    # generation (GH #93): a user rule may rely on language-specific syntax
    # and its author controls its language targeting. (ubs-js.sh 3142-3152)
    user_rule_files: list[Path] = []
    if user_rules_dir is not None:
        user_rules_dir = Path(user_rules_dir)
        if user_rules_dir.is_dir():
            shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)
            user_rule_files = sorted(
                path
                for path in user_rules_dir.iterdir()
                if path.is_file() and path.suffix == ".yml"
            )

    manifest: dict[str, dict[str, str]] = {}
    grammar_files: dict[str, list[str]] = {grammar: [] for grammar in _GRAMMARS}

    for stem, rule_text in _RULES:
        name = f"{stem}.yml"
        (rules_dir / name).write_text(rule_text, encoding="utf-8")
        language = _first_match(_LANGUAGE_RE, rule_text)
        rule_id = _first_match(_ID_RE, rule_text)
        manifest[rule_id] = {
            "severity": SEVERITY_MAP.get(rule_id, _first_match(_SEVERITY_RE, rule_text)),
            "language": language,
            "file": f"rules/{name}",
        }
        grammar_files[language].append(f"rules/{name}")
        targets = ("tsx",) if name in _TSX_ONLY_FILES else _VARIANT_TARGETS[language]
        for target in targets:
            variant = f"rules/{stem}.{target}.yml"
            (rule_dir / variant).write_text(
                _retarget(rule_text, language, target), encoding="utf-8"
            )
            grammar_files[target].append(variant)

    for user_file in user_rule_files:
        user_text = user_file.read_text(encoding="utf-8", errors="replace")
        language = _first_match(_LANGUAGE_RE, user_text)
        # An off-grammar (or undeclared) user rule cannot match under the three
        # JS grammars, so listing it in every config mirrors the legacy
        # scan-everything behavior without double counting.
        grammars = (language,) if language in _GRAMMARS else _GRAMMARS
        for grammar in grammars:
            grammar_files[grammar].append(f"rules/{user_file.name}")

    for grammar in _GRAMMARS:
        # ast-grep discovers rules per `ruleDirs` entry; a single entry accepts
        # an individual rule file, so each config lists exactly the files of
        # its grammar and rule ids stay unique inside every config (GH #93).
        # A whole-directory entry would trip ast-grep's duplicate-id check
        # because base rules and their same-id variants share the directory.
        lines = ["ruleDirs:"]
        lines.extend(f"  - {path}" for path in grammar_files[grammar])
        (rule_dir / f"sgconfig-{grammar}.yml").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        # Base-only config (bead A4-js): legacy TEXT/JSON counting scans each
        # base rule in its declared language (ensure_ast_rule_results loops
        # the base pack); the language variants are SARIF-only. js_scan uses
        # these so variant rules do not fire on extension-mismatched files.
        base_lines = ["ruleDirs:"]
        base_lines.extend(
            f"  - rules/{stem}.yml"
            for stem, _rule_text in _RULES
            if f"rules/{stem}.yml" in grammar_files[grammar]
        )
        (rule_dir / f"sgbase-{grammar}.yml").write_text(
            "\n".join(base_lines) + "\n", encoding="utf-8"
        )

    manifest_path = rule_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
