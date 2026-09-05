"""ubs_core.java_rules — ast-grep rule pack for the java/kotlin module (bead 0xjg.8).

Verbatim port of `write_ast_rules` (modules/ubs-java.sh 2609-3071) plus the two
async rules staged by `run_async_error_checks` (2401-2423). `generate` writes
every rule, one sgconfig-java.yml, one sgbase-java.yml and a manifest.json into
the rule dir so `ubs_core.java_ast.scan_all` can run the whole pack with a
single `ast-grep scan -c` invocation.

Counting calibration (legacy): the pack is staged for --sarif-out/--json-out
passthrough and category-15 staging notes only — the ONLY counted ids are the
five resource-lifecycle rules (emit_ast_rule_group RESOURCE_LIFECYCLE_RULE_IDS,
ubs-java.sh 286-313), the two async rules (ASYNC_ERROR_RULE_IDS, 148-160) and
the cat-1 isPresent()+get() probe (ast_search, 3439). SEVERITY_MAP pins their
legacy severities; everything else stays an informational dump.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

_ID_RE = re.compile(r"^id:\s*(\S+)", re.MULTILINE)
_LANGUAGE_RE = re.compile(r"^language:\s*(\S+)", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:\s*(\S+)", re.MULTILINE)

GRAMMARS: tuple[str, ...] = ("java",)

# Counted ids -> legacy severity (RESOURCE_LIFECYCLE_RULE_SEVERITY +
# ASYNC_ERROR_SEVERITY + the info-tier cat-1 ast_search probe).
SEVERITY_MAP: dict[str, str] = {
    "java.resource.executor-no-shutdown": "critical",
    "java.resource.thread-no-join": "warning",
    "java.resource.jdbc-no-close": "warning",
    "java.resource.resultset-no-close": "warning",
    "java.resource.statement-no-close": "warning",
    "java.async.future-get-no-try": "warning",
    "java.async.then-no-exceptionally": "warning",
    "java.optional-isPresent-then-get": "info",
    "java.secrets.string-decl": "warning",
}

# Counted ids -> legacy print_finding titles (SUMMARY/REMEDIATION maps).
SUMMARY_MAP: dict[str, str] = {
    "java.resource.executor-no-shutdown": "ExecutorService created without shutdown",
    "java.resource.thread-no-join": "Thread started without join()",
    "java.resource.jdbc-no-close": "JDBC connection acquired without close()",
    "java.resource.resultset-no-close": "ResultSet not closed after use",
    "java.resource.statement-no-close": "Statement/Prepared/CallableStatement not closed after use",
    "java.async.future-get-no-try": "CompletableFuture get()/join() without try/catch",
    "java.async.then-no-exceptionally": "CompletableFuture chains missing exceptionally()/handle()",
    "java.optional-isPresent-then-get": "isPresent()+get() pattern",
    "java.secrets.string-decl": "Potential hard-coded secrets found",
}

REMEDIATION_MAP: dict[str, str] = {
    "java.resource.executor-no-shutdown": "Store the ExecutorService and call shutdown()/shutdownNow() in finally blocks",
    "java.resource.thread-no-join": "Join threads or use executors to avoid orphaned workers",
    "java.resource.jdbc-no-close": "Use try-with-resources or explicitly close java.sql.Connection objects",
    "java.resource.resultset-no-close": "Close java.sql.ResultSet objects or wrap them in try-with-resources",
    "java.resource.statement-no-close": "Close Statement/PreparedStatement handles or wrap them in try-with-resources",
    "java.async.future-get-no-try": "Wrap blocking future.get()/join() calls in try/catch to handle ExecutionException",
    "java.async.then-no-exceptionally": "Attach .exceptionally(...) or .handle(...) to promise chains to surface errors",
}

# Rule ids whose matches are marker-suppressed at count time:
# run_async_error_checks's parser checks current+previous ubs:ignore lines
# (2462-2475). The resource emit group (emit_ast_rule_group PYRULE parser) and
# the cat-1 ast_search probe have NO marker check — richer placements stay
# with the A7 statement-interval engine in the meta-runner postprocess.
MARKER_SUPPRESSED_IDS: frozenset[str] = frozenset({
    "java.async.future-get-no-try",
    "java.async.then-no-exceptionally",
})

_RULES: tuple[tuple[str, str], ...] = (
    ("printStackTrace", """id: java.print-stacktrace
language: java
rule:
  pattern: $E.printStackTrace()
severity: warning
message: "printStackTrace() leaks sensitive details; use a logger"
"""),
    ("println", """id: java.system-println
language: java
rule:
  any:
    - pattern: System.out.println($ARG)
    - pattern: System.err.println($ARG)
severity: info
message: "System.out/err.println detected; prefer structured logging"
"""),
    ("optional-isPresent-then-get", """id: java.optional-isPresent-then-get
language: java
rule:
  pattern: |
    if ($O.isPresent()) {
      $$$PRE
      $T $V = $O.get();
      $$$POST
    }
severity: info
message: "Optional.isPresent() followed by get(); prefer ifPresent/map/orElseThrow"
"""),
    ("optional-orElse-null", """id: java.optional-orElse-null
language: java
rule:
  pattern: $O.orElse(null)
severity: info
message: "Optional.orElse(null) reintroduces null; reconsider design"
"""),
    ("optional-isEmpty-negation", """id: java.optional-isempty-negation
language: java
rule:
  pattern: if (!$O.isEmpty()) { $$$BODY }
severity: info
message: "Prefer isPresent() to !isEmpty() for clarity or use ifPresent(...)"
"""),
    # Cat-21 conjunct of the secrets check: legacy `ast_search
    # 'String $K = $V;'` counts every constrained String declaration.
    ("java-secrets-string-decl", """id: java.secrets.string-decl
language: java
rule:
  pattern: String $K = $V;
severity: warning
message: "Hardcoded secret-like identifier"
"""),
    ("logging-concat", """id: java.logging-concat
language: java
rule:
  any:
    - pattern: $L.debug($A + $B, $$)
    - pattern: $L.info($A + $B, $$)
    - pattern: $L.warn($A + $B, $$)
    - pattern: $L.error($A + $B, $$)
    - pattern: $L.debug($A + $B)
    - pattern: $L.info($A + $B)
    - pattern: $L.warn($A + $B)
    - pattern: $L.error($A + $B)
severity: info
message: "String concatenation in logging; prefer parameterized logging"
"""),
    ("paths-get-plus", """id: java.paths-get-plus
language: java
rule:
  any:
    - pattern: java.nio.file.Paths.get($A + $B)
    - pattern: Paths.get($A + $B)
    - pattern: java.nio.file.Paths.get($A, $B + $C)
    - pattern: Paths.get($A, $B + $C)
severity: info
message: "Paths.get with '+' concatenation; prefer resolve() or multiple args"
"""),
    ("hardcoded-secrets", """id: java.hardcoded-secrets
language: java
rule:
  pattern: String $K = $V;
constraints:
  K:
    regex: (?i).*(password|passwd|pwd|secret|token|api[-_]?key|auth|credential).*
  V:
    kind: string_literal
severity: warning
message: "Hardcoded secret-like identifier"
"""),
    ("optional-get", """id: java.optional-get
language: java
rule:
  pattern: $O.get()
severity: warning
message: "Optional.get() may throw NoSuchElementException; prefer orElse, orElseThrow, or ifPresent"
"""),
    ("string-eq-operator", """id: java.string-eq-operator
language: java
rule:
  any:
    - pattern: '"$X" == $Y'
    - pattern: $X == "$Y"
severity: warning
message: "String compared with '=='; use equals()/Objects.equals()"
"""),
    ("bigdecimal-equals", """id: java.bigdecimal-equals
language: java
rule:
  pattern: $BD.equals($OTHER)
severity: info
message: "BigDecimal.equals checks scale; prefer compareTo()==0 for numeric equality"
"""),
    ("synchronized-this", """id: java.synchronized-this
language: java
rule:
  pattern: synchronized (this) { $$$BODY }
severity: info
message: "synchronized(this) exposes lock to external code; prefer private lock"
"""),
    ("thread-start", """id: java.thread-start
language: java
rule:
  pattern: new Thread($ARG).start()
severity: info
message: "Manual Thread management; consider executors or virtual threads in Java 21+"
"""),
    ("executors-cached", """id: java.executors-cached
language: java
rule:
  any:
    - pattern: java.util.concurrent.Executors.newCachedThreadPool()
    - pattern: java.util.concurrent.Executors.newCachedThreadPool($ARG)
    - pattern: Executors.newCachedThreadPool()
    - pattern: Executors.newCachedThreadPool($ARG)
severity: warning
message: "newCachedThreadPool has unbounded threads; ensure backpressure"
"""),
    ("java-resource-executor", """id: java.resource.executor-no-shutdown
language: java
rule:
  all:
    - any:
        - pattern: java.util.concurrent.ExecutorService $EXEC = java.util.concurrent.Executors.$FACTORY();
        - pattern: java.util.concurrent.ExecutorService $EXEC = java.util.concurrent.Executors.$FACTORY($ARG);
        - pattern: ExecutorService $EXEC = Executors.$FACTORY();
        - pattern: ExecutorService $EXEC = Executors.$FACTORY($ARG);
    - not:
        inside:
          has:
            any:
              - pattern: $EXEC.shutdown()
              - pattern: $EXEC.shutdownNow()
            stopBy: end
          stopBy: end
severity: warning
message: "ExecutorService created without shutdown()/shutdownNow() in the same scope."
"""),
    ("java-resource-thread", """id: java.resource.thread-no-join
language: java
rule:
  any:
    - pattern: new Thread($ARG).start()
    - pattern: new java.lang.Thread($ARG).start()
    - all:
        - pattern: $THREAD.start()
        - inside:
            has:
              any:
                - pattern: Thread $THREAD = new Thread($ARG);
                - pattern: java.lang.Thread $THREAD = new java.lang.Thread($ARG);
              stopBy: end
            stopBy: end
        - not:
            inside:
              has:
                pattern: $THREAD.join()
                stopBy: end
              stopBy: end
severity: warning
message: "Thread started without a matching join(); join threads or await termination."
"""),
    ("java-resource-jdbc", """id: java.resource.jdbc-no-close
language: java
rule:
  all:
    - any:
        - pattern: java.sql.Connection $C = java.sql.DriverManager.getConnection($ARG);
        - pattern: Connection $C = DriverManager.getConnection($ARG);
    - not:
        inside:
          kind: resource
          stopBy: end
severity: warning
message: "JDBC Connection acquired without close(); wrap in try-with-resources or close in finally."
"""),
    ("thread-sleep-in-sync", """id: java.thread-sleep-in-synchronized
language: java
rule:
  pattern: java.lang.Thread.sleep($D)
  inside:
    pattern: synchronized($LOCK) { $$$BODY }
    stopBy: end
severity: info
message: "Thread.sleep inside synchronized block may block other threads unnecessarily"
"""),
    ("notify", """id: java.notify
language: java
rule:
  pattern: $O.notify()
severity: info
message: "notify() wakes a single waiter; ensure this is intended (notifyAll?)"
"""),
    ("insecure-random", """id: java.insecure-random
language: java
rule:
  any:
    - pattern: new java.util.Random()
    - pattern: new java.util.Random($ARG)
    - pattern: new Random()
    - pattern: new Random($ARG)
severity: info
message: "java.util.Random is not cryptographically secure; prefer SecureRandom for secrets"
"""),
    ("trust-all-cert", """id: java.insecure-ssl
language: java
rule:
  any:
    - pattern: javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier($VERIFIER)
    - pattern: $X.setHostnameVerifier($VERIFIER)
severity: error
message: "SSL/TLS verification disabled; enables MITM"
"""),
    ("weak-hash", """id: java.weak-hash
language: java
rule:
  any:
    - pattern: java.security.MessageDigest.getInstance("MD5")
    - pattern: java.security.MessageDigest.getInstance("SHA-1")
severity: warning
message: "Weak hash algorithm detected (MD5/SHA-1); prefer SHA-256/512"
"""),
    ("plain-http", """id: java.plain-http
language: java
rule:
  all:
    - kind: string_literal
    - regex: '^"http://'
severity: info
message: "Plain HTTP URL detected; ensure HTTPS for production"
"""),
    ("deserialization", """id: java.insecure-deserialization
language: java
rule:
  any:
    - pattern: new java.io.ObjectInputStream($ARG).readObject()
    - pattern: $IN.readObject()
severity: warning
message: "Java deserialization can be dangerous; validate types or avoid if possible"
"""),
    ("inputstreamreader-no-charset", """id: java.inputstreamreader-no-charset
language: java
rule:
  any:
    - pattern: new java.io.InputStreamReader($S)
    - pattern: new InputStreamReader($S)
severity: info
message: "InputStreamReader without explicit charset uses platform default; specify charset"
"""),
    ("string-no-charset", """id: java.string-bytes-no-charset
language: java
rule:
  any:
    - pattern: new String($B)
    - pattern: $S.getBytes()
severity: info
message: "String/bytes without charset; specify StandardCharsets.UTF_8 (or required encoding)"
"""),
    ("parallel-foreach", """id: java.parallel-foreach-side-effects
language: java
rule:
  pattern: $SRC.parallel().forEach($ARG)
severity: info
message: "parallel().forEach may reorder and run side effects concurrently; ensure thread-safety"
"""),
    ("reflection", """id: java.reflection
language: java
rule:
  any:
    - pattern: Class.forName($$)
    - pattern: $C.getDeclaredField($$)
    - pattern: $C.getDeclaredMethod($$)
    - pattern: $M.invoke($$)
    - pattern: $F.setAccessible(true)
severity: info
message: "Reflection reduces type safety; ensure strict validation"
"""),
    ("regex-nested-quant", """id: java.regex-redos
language: java
rule:
  any:
    - all:
        - kind: string_literal
        - regex: '(".*(\\(\\?:?[^"]*[+*][^"]*\\)[+*][^"]*)+")'
    - pattern: String $R = "(a+)+";
severity: warning
message: "Regex with nested quantifiers; potential ReDoS"
"""),
    ("legacy-collections", """id: java.legacy-collections
language: java
rule:
  any:
    - pattern: new java.util.Vector()
    - pattern: new java.util.Vector($ARG)
    - pattern: new java.util.Vector<>()
    - pattern: new Vector()
    - pattern: new Vector($ARG)
    - pattern: new Vector<>()
    - pattern: new java.util.Hashtable()
    - pattern: new java.util.Hashtable($ARG)
    - pattern: new java.util.Hashtable<>()
    - pattern: new Hashtable()
    - pattern: new Hashtable($ARG)
    - pattern: new Hashtable<>()
severity: info
message: "Legacy synchronized collections; prefer java.util.concurrent alternatives"
"""),
    ("virtual-threads", """id: java.virtual-threads
language: java
rule:
  any:
    - pattern: java.lang.Thread.ofVirtual().start($ARG)
    - pattern: java.lang.Thread.ofVirtual().factory()
severity: info
message: "Virtual threads detected; ensure blocking I/O is appropriate or use async APIs"
"""),
    ("java-resource-resultset", """id: java.resource.resultset-no-close
language: java
rule:
  any:
    - pattern: java.sql.ResultSet $R = $EXPR.executeQuery($ARG);
    - pattern: ResultSet $R = $EXPR.executeQuery($ARG);
severity: warning
message: "ResultSet acquired without close(); wrap in try-with-resources or close explicitly."
"""),
    ("java-resource-statement", """id: java.resource.statement-no-close
language: java
rule:
  any:
    - pattern: java.sql.Statement $S = $EXPR.createStatement();
    - pattern: Statement $S = $EXPR.createStatement();
    - pattern: java.sql.PreparedStatement $S = $EXPR.prepareStatement($ARG);
    - pattern: PreparedStatement $S = $EXPR.prepareStatement($ARG);
    - pattern: java.sql.CallableStatement $S = $EXPR.prepareCall($ARG);
    - pattern: CallableStatement $S = $EXPR.prepareCall($ARG);
severity: warning
message: "Statement/PreparedStatement acquired without close(); wrap in try-with-resources or close explicitly."
"""),
    ("closeable-no-twr", """id: java.closeable-no-twr
language: java
rule:
  pattern: |
    $T $V = new $C($ARG);
constraints:
  C:
    regex: '.*(Stream|Reader|Writer|Scanner|Connection|Channel).*'
severity: info
message: "Closeable created outside try-with-resources; ensure it is closed"
"""),
    # ── Async rules (run_async_error_checks, ubs-java.sh 2401-2423) ─────────
    ("java.async.future-get-no-try", """id: java.async.future-get-no-try
language: java
rule:
  pattern: $F.get()
  not:
    inside:
      pattern: try { $$$BODY } catch ($E $EX) { $$$CATCH }
      stopBy: end
severity: warning
message: "CompletableFuture get()/join() without try/catch"
"""),
    ("java.async.then-no-exceptionally", """id: java.async.then-no-exceptionally
language: java
rule:
  any:
    - pattern: $CF.thenApply($ARG)
    - pattern: $CF.thenCompose($ARG)
    - pattern: $CF.thenAccept($ARG)
  not:
    inside:
      pattern: $CF.exceptionally($HANDLER)
severity: warning
message: "CompletableFuture chains missing exceptionally()/handle()"
"""),
)


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, sgconfig, sgbase config and manifest.

    Returns the manifest dict (rule_id -> {severity, language, file}); the same
    document is written to ``<rule_dir>/manifest.json``. Re-running on the same
    ``rule_dir`` reproduces the identical tree. Java is a single grammar, so
    both configs list every rule (the legacy pack scans the whole directory).
    """
    rule_dir = Path(rule_dir)
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    if user_rules_dir is not None:
        user_rules_dir = Path(user_rules_dir)
        if user_rules_dir.is_dir():
            shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)

    manifest: dict[str, dict[str, str]] = {}
    rule_files: list[str] = []
    for stem, rule_text in _RULES:
        name = f"{stem}.yml"
        (rules_dir / name).write_text(rule_text, encoding="utf-8")
        rule_files.append(f"rules/{name}")
        rule_id = _first_match(_ID_RE, rule_text)
        manifest[rule_id] = {
            "severity": SEVERITY_MAP.get(rule_id, _first_match(_SEVERITY_RE, rule_text)),
            "language": _first_match(_LANGUAGE_RE, rule_text) or "java",
            "file": f"rules/{name}",
        }

    # User rules join the pack verbatim (legacy write_ast_rules copied the
    # --rules dir into AST_RULE_DIR before staging, 2619-2621).
    if user_rules_dir is not None and Path(user_rules_dir).is_dir():
        for user_file in sorted(Path(user_rules_dir).glob("*.yml")):
            user_text = user_file.read_text(encoding="utf-8", errors="replace")
            rule_id = _first_match(_ID_RE, user_text)
            manifest.setdefault(rule_id or user_file.stem, {
                "severity": _first_match(_SEVERITY_RE, user_text) or "warning",
                "language": _first_match(_LANGUAGE_RE, user_text) or "java",
                "file": f"rules/{user_file.name}",
            })

    config_lines = ["ruleDirs:"] + [f"  - {path}" for path in rule_files]
    (rule_dir / "sgconfig-java.yml").write_text("\n".join(config_lines) + "\n", encoding="utf-8")
    (rule_dir / "sgbase-java.yml").write_text("\n".join(config_lines) + "\n", encoding="utf-8")

    manifest_path = rule_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
