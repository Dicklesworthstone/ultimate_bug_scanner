# Ultimate Bug Scanner - Test Suite

This suite now spans **every language UBS supports**. JavaScript remains the template, but each directory (`python/`, `golang/`, `cpp/`, `rust/`, `java/`, `ruby/`, `swift/`, `csharp/`, `elixir/`) contains mirrored buggy/clean fixtures so we can regression-test the language modules with the same discipline.

## 📁 Directory Structure

```
test-suite/
├── buggy/                      # Core JS bug patterns (scanner SHOULD find issues)
│   ├── 01-null-safety.js              # Null pointer bugs, unguarded access
│   ├── 02-security.js                 # XSS, eval, hardcoded secrets
│   ├── 03-async-await.js              # Promise handling, missing await
│   ├── 04-memory-leaks.js             # Event listeners, timers, leaks
│   ├── 05-type-coercion.js            # Loose equality, NaN, typeof issues
│   ├── 06-math-errors.js              # Division by zero, parseInt bugs
│   ├── 07-error-handling.js           # Empty catch, throwing strings
│   ├── 08-control-flow.js             # Switch fallthrough, unreachable code
│   ├── 09-debugging-production.js     # debugger, console.log, TODOs
│   ├── 10-variable-scope.js           # var usage, global pollution
│   ├── 11-combined-issues.js          # Multiple bug types together
│   ├── 12-regex-vulnerabilities.js    # ReDoS, catastrophic backtracking
│   ├── 13-prototype-pollution.js      # __proto__ attacks, unsafe merge
│   ├── 14-injection-attacks.js        # SQL, NoSQL, command injection
│   ├── 15-race-conditions.js          # TOCTOU, data races, atomicity
│   ├── 16-crypto-mistakes.js          # Weak crypto, hardcoded keys
│   ├── 17-dom-manipulation.js         # DOM clobbering, layout thrashing
│   ├── 18-api-misuse.js               # Framework/library misuse
│   ├── 19-performance-anti-patterns.js # N+1 queries, blocking operations
│   └── 20-configuration-errors.js     # CORS, CSP, security headers
│
├── clean/                      # Best practices (minimal issues expected)
│   ├── 01-null-safety-clean.js        # Proper null checks, optional chaining
│   ├── 02-security-clean.js           # Secure coding, safe APIs
│   ├── 03-async-await-clean.js        # Proper async patterns, error handling
│   ├── 04-error-handling-clean.js     # Try-catch, Error objects, cleanup
│   ├── 05-memory-management-clean.js  # Event cleanup, WeakMap, streams
│   └── 06-performance-clean.js        # Optimization patterns, caching
│
├── frameworks/                 # Framework-specific tests
│   ├── react/
│   │   ├── buggy-component.jsx        # React anti-patterns (28 issues)
│   │   └── clean-component.jsx        # React best practices
│   └── node/
│       ├── buggy-api.js               # Express/Node bugs (35 issues)
│       └── clean-api.js               # Secure API patterns
│
├── realistic/                  # Real-world application scenarios
│   ├── buggy-ecommerce-checkout.js    # E-commerce bugs (35+ issues)
│   └── buggy-auth-system.js           # Authentication flaws (40+ issues)
│
├── edge-cases/                 # Specialized edge case categories
│   ├── unicode-bugs.js                # Unicode, encoding, graphemes
│   ├── timezone-date-bugs.js          # Dates, timezones, DST, leap years
│   └── floating-point-bugs.js         # Precision, money, rounding
│
├── js/type_narrowing/          # TS guard fixtures (buggy + clean)
├── python/                     # Python fixtures + manifest cases (+ helper unit tests)
├── golang/                     # Go fixtures + manifest cases
├── cpp/                        # C/C++ fixtures + manifest cases
├── rust/                       # Rust fixtures + manifest cases (includes type narrowing demo)
├── java/                       # Java fixtures + manifest cases
├── ruby/                       # Ruby fixtures + manifest cases
├── swift/                      # Swift security + type narrowing fixtures and manifest cases
├── csharp/                     # C# fixtures + manifest cases
├── elixir/                     # Elixir security fixtures + manifest cases
└── README.md                   # This file
```

The Python directory also includes `tests/test_resource_helper.py`, a lightweight unittest for the AST-based lifecycle helper so we can iterate without waiting for every module to run. Go fixtures pair with the helper-backed manifest case to prove ticker/timer/context/file findings stay stable.

## Resource Lifecycle Regression Coverage

Run the helper regression directly when touching the Python analyzer:

```
uv run python test-suite/python/tests/test_resource_helper.py
```

It should report leaks for file handles, subprocesses, sockets, and asyncio tasks in the buggy sample while remaining silent on the clean counterpart.

To exercise the Go helper + module integration end-to-end, stick with the manifest harness:

```
uv run python test-suite/run_manifest.py --case go-resource-lifecycle
```

`test-suite/manifest.json` now asserts on deterministic substrings for context/ticker/timer/file findings so we immediately notice if the helper output changes.

## 🧠 Pattern Authoring Philosophy

When expanding the JavaScript/TypeScript module (or any language module with AST support), favor **ast-grep-first** rules instead of brittle regex spot checks. Every new manifest fixture should document the AST shape you expect and include at least one "clean" counterpart proving the rule suppresses good code. Regex-only prototypes are fine for experiments, but before landing changes:

1. Build the detector in ast-grep (or the language’s semantic engine) so it reasons over syntax trees, not whitespace.
2. Add/update fixtures under `test-suite/js/` (buggy + clean) to cover the rule and hook them into `manifest.json` so `test-suite/run_all.sh` enforces the regression.
3. Use regex-based ripgrep passes only as a fast pre-filter feeding into AST verification—not as the primary signal.

This keeps the JS module maintainable and ensures future contributors extend structured analyzers instead of stacking fragile grep snippets.

## Cross-language quick reference

| Language | Buggy path | Clean path | Highlights |
|----------|------------|------------|------------|
| JavaScript/TypeScript | `test-suite/buggy/`, `test-suite/js/buggy/`, `test-suite/js/type_narrowing/` | `test-suite/clean/`, `test-suite/js/clean/`, `test-suite/js/type_narrowing/clean/` | 20 core files + framework + realistic + edge cases plus dedicated type-narrowing, SSRF, response header injection, request path traversal, host header poisoning, credentialed CORS, cookie security, security randomness, disabled TLS verification, fetch-cancellation, JWT verification, and archive extraction fixtures |
| Python | `test-suite/python/buggy/`, `test-suite/python/security/` | `test-suite/python/clean/`, `test-suite/python/security/` | Async/security/resource fixtures + mutable defaults, shell injection, command execution dataflow, subprocess timeout coverage, SQL/NoSQL injection sinks, request-controlled regex patterns, template injection sources, response header injection, email header injection, LDAP injection, archive traversal, open redirects, host header poisoning, SSRF, outbound HTTP timeouts, request/header path traversal and upload filename saves, JWT verification, credentialed CORS, session cookie flags, CSRF disables, template autoescape disables, safe-HTML XSS sinks, mass-assignment sinks, unsafe deserialization loaders, weak password hashers, ECB/static-IV crypto misuse, non-constant-time secret comparisons, security-sensitive asserts, world-writable file modes, debug/host configuration, unsafe XML parsing, insecure security randomness, disabled TLS verification |
| Go | `test-suite/golang/buggy/`, `test-suite/golang/security/` | `test-suite/golang/clean/`, `test-suite/golang/security/` | Concurrency, HTTP safety, context leaks, ticker/perf issues, request/header path traversal, response header injection, request-derived open redirects, host header poisoning, request-derived outbound URL/SSRF, archive extraction |
| C/C++ | `test-suite/cpp/buggy/`, `test-suite/cpp/security/` | `test-suite/cpp/clean/`, `test-suite/cpp/security/` | RAII vs leaks, unsafe `strcpy`, request/header path traversal, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction, overflow/memory hygiene |
| Rust | `test-suite/rust/buggy/` | `test-suite/rust/clean/` | `unwrap()` panics, async tasks, command injection, request-derived open redirects, host header poisoning, request-derived outbound URL/SSRF, archive extraction, predictable temp-file writes, float precision, type-narrowing demo |
| Java | `test-suite/java/buggy/`, `test-suite/java/security/` | `test-suite/java/clean/`, `test-suite/java/security/` | Executor leaks, blocking I/O, SQL/command injection, request/header path traversal, response header injection, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction |
| Kotlin (Java-family scanner) | `test-suite/kotlin/security_buggy/`, `test-suite/kotlin/path_traversal_buggy/`, `test-suite/kotlin/header_injection_buggy/`, `test-suite/kotlin/open_redirect_buggy/`, `test-suite/kotlin/ssrf_buggy/`, `test-suite/kotlin/archive_extraction_buggy/`, `test-suite/kotlin/type_narrowing/buggy/` | `test-suite/kotlin/security_clean/`, `test-suite/kotlin/path_traversal_clean/`, `test-suite/kotlin/header_injection_clean/`, `test-suite/kotlin/open_redirect_clean/`, `test-suite/kotlin/ssrf_clean/`, `test-suite/kotlin/archive_extraction_clean/`, `test-suite/kotlin/type_narrowing/clean/` | ProcessBuilder shell injection, request/header path traversal, response header injection, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction path traversal, nullable guard fallthrough |
| Ruby | `test-suite/ruby/buggy/`, `test-suite/ruby/path_traversal_buggy/`, `test-suite/ruby/open_redirect_buggy/`, `test-suite/ruby/archive_extraction_buggy/`, `test-suite/ruby/ssrf_buggy/` | `test-suite/ruby/clean/`, `test-suite/ruby/path_traversal_clean/`, `test-suite/ruby/open_redirect_clean/`, `test-suite/ruby/archive_extraction_clean/`, `test-suite/ruby/ssrf_clean/` | eval/YAML problems, thread leaks, file cleanup, request/header path traversal, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction |
| Swift | `test-suite/swift/buggy/`, `test-suite/swift/archive_extraction_buggy/`, `test-suite/swift/path_traversal_buggy/`, `test-suite/swift/open_redirect_buggy/`, `test-suite/swift/ssrf_buggy/`, `test-suite/swift/type_narrowing/buggy/` | `test-suite/swift/clean/`, `test-suite/swift/archive_extraction_clean/`, `test-suite/swift/path_traversal_clean/`, `test-suite/swift/open_redirect_clean/`, `test-suite/swift/ssrf_clean/`, `test-suite/swift/type_narrowing/clean/` | Shell-backed process execution, request/header path traversal, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction, optional guard fallthrough |
| C# | `test-suite/csharp/buggy/`, `test-suite/csharp/security/` | `test-suite/csharp/clean/`, `test-suite/csharp/security/` | Task blocking, weak crypto, request/header path traversal, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction, `throw ex`, `TryParse` vs `Parse`, null/type narrowing fallthrough, helper-backed resource lifecycle, unobserved `Task.Run`/`StartNew` handles |
| Elixir | `test-suite/elixir/buggy/` | `test-suite/elixir/clean/` | Shell-backed command execution, request/header path traversal, request-derived open redirects, request-derived outbound URL/SSRF, archive extraction |

Every directory has its own README summarizing the files and the scanner categories they exercise (security, async error coverage, resource lifecycle, math/precision, etc.).

## 🧪 Running Tests

### Prerequisite: uv + CPython 3.13

The repo ships a `pyproject.toml`/`uv.lock` pair that pins us to Python 3.13. Sync the environment once and either activate `.venv` or wrap commands with `uv run`:

```bash
cd ultimate_bug_scanner
uv sync --python 3.13
source .venv/bin/activate  # or: uv run python <command>

# smoke-test the manifest runner with the pinned interpreter
uv run python test-suite/run_manifest.py --case js-core-buggy
```

All subsequent examples below assume that `.venv/bin` is on your `PATH` so `python`/`python3` resolve to that managed interpreter.

> Tip: `test-suite/run_all.sh` automatically prefers `uv run python …` and falls back to `python3` only if `uv` is unavailable, so CI and local runs stay on CPython 3.13 without extra flags.

### Shareable-report regression
The manifest focuses on scanner findings, so we added `test-suite/shareable/test_shareable_reports.py` to sanity-check the new `--report-json/--html-report/--comparison` workflow. `test-suite/run_all.sh` already invokes it, but you can run it manually:

```bash
cd test-suite
uv run python shareable/test_shareable_reports.py
```

The script runs UBS twice against the Python buggy fixtures, verifies that the report JSON embeds git metadata and comparison deltas, and ensures the HTML preview renders correctly.

### Rule-quality gates for Rust, TypeScript, and Go

`test-suite/quality/rule_quality_harness.py` adds a focused quality gate for the three fastest-moving detector families: Rust, TypeScript/JavaScript, and Go. It invokes the real `ubs` binary or real module scripts against real fixtures, then checks:

- The tracked golden coverage matrix in `test-suite/goldens/rule_coverage.json` still matches the manifest's paired security fixtures, runtime scopes, robustness scopes, metamorphic transform matrix, default clean-fuzz budget, Rust/TypeScript/Go aggregate-clean budgets, the strict Rust/TypeScript/Go expectation-strength audit, and a broader all-supported-language expectation-strength snapshot.
- Every paired security fixture has both a buggy and clean manifest case, and every manifest path exists.
- Rust, TypeScript/JavaScript, and Go ast-grep rule packs all emit valid SARIF through the real module CLIs.
- Rust, TypeScript/JavaScript, and Go `--list-rules` inventory modes emit only stable machine-readable rule IDs, with no banners or project summaries mixed into stdout, and exactly match the rule IDs independently extracted from `--dump-rules` YAML.
- The canonical Rust/TypeScript/Go SARIF evidence in `test-suite/goldens/ast_grep_rule_pack_sarif.json` still matches the focused fixture outputs, broader language-corpus outputs, emitted rule IDs, result counts, driver rule list shape, and per-rule ast-grep YAML inventory.
- Every generated Rust, TypeScript/JavaScript, and Go ast-grep YAML rule parses when run directly through `ast-grep scan --rule` against its language fixture.
- The golden records which generated ast-grep rule IDs are actually covered by the broader Rust/TypeScript/Go fixture corpora. The intended steady state is zero uncovered generated rules; any uncovered-rule diff is reviewable test debt.
- The default robustness smoke slice keeps curated request-body, route-param, and TLS fixtures stable under benign comment/whitespace transforms.
- The optional campaign robustness scope runs comment and whitespace/CRLF metamorphic checks across every Rust, TypeScript/JavaScript, and Go security or behavior-rule campaign fixture, and deterministic fuzz checks across every clean campaign fixture.

Run it directly when changing Rust, TypeScript, or Go rules:

```bash
cd test-suite
uv run python quality/rule_quality_harness.py
uv run python quality/rule_quality_harness.py --runtime-scope=campaign
uv run python quality/rule_quality_harness.py --runtime-scope=campaign --robustness-scope=campaign --fuzz-iterations=1
uv run python quality/rule_quality_harness.py --runtime-scope=all --robustness-scope=all --fuzz-iterations=1
UPDATE_GOLDENS=1 uv run python quality/rule_quality_harness.py --skip-runtime
UPDATE_GOLDENS=1 uv run python quality/rule_quality_harness.py
```

The default runtime and robustness scopes keep `run_all.sh` quick by running Rust/TypeScript/Go ast-grep rule-pack validity checks plus request-body, route-param, and TLS metamorphic/fuzz checks. Use `--runtime-scope=campaign` to execute every Rust, TypeScript/JavaScript, and Go security or behavior-rule campaign fixture once. Add `--robustness-scope=campaign` to also run benign-comment and whitespace/CRLF metamorphic transforms over every Rust/TypeScript/Go campaign fixture and deterministic fuzz variants over every clean Rust/TypeScript/Go campaign fixture. Use `--runtime-scope=all` for every paired security fixture in the golden across all languages, and pair it with `--robustness-scope=all` when you also want benign metamorphic transforms and deterministic clean-fixture fuzz variants across that full security fixture matrix. The coverage golden freezes the case ids in each runtime and robustness scope, the exact metamorphic transforms applied per case, the default deterministic fuzz iteration budget, the aggregate clean-directory warning budgets for Rust/TypeScript/Go, the list of Rust/TypeScript/Go cases with weak expectation shape, and the all-supported-language weak-expectation inventory, so narrowing campaign/metamorphic/fuzz coverage, silently dropping a transform, weakening default fuzz breadth, adding aggregate clean slack, or changing expectation strength anywhere in the supported language matrix requires an intentional golden diff. `UPDATE_GOLDENS=1 ... --skip-runtime` updates only the coverage matrix; run without `--skip-runtime` when reviewing and updating the focused SARIF, corpus SARIF, per-rule rule-pack, and generated-rule corpus-coverage evidence golden. Only update goldens after reviewing the diffs and confirming the rule coverage or rule-pack evidence change is intentional.

`run_all.sh` defaults `TMPDIR`, `TMP`, and `TEMP` to `/data/tmp/ubs-test-suite/` when `/data/tmp` is available, or `/var/tmp/ubs-test-suite/` otherwise, when no usable `TMPDIR` is already set. Generated scanner temp files therefore do not depend on a healthy system `/tmp` mount or an ignored in-repo artifact path on normal Linux development hosts. Set `TMPDIR` explicitly to override that location.

### Scan Individual Buggy Files

```bash
# Test null safety detection
ubs test-suite/buggy/01-null-safety.js

# Test security vulnerability detection
ubs test-suite/buggy/02-security.js

# Test async/await issue detection
ubs test-suite/buggy/03-async-await.js
```

### Scan All Buggy Code

```bash
# Should find MANY issues
ubs test-suite/buggy/

# Verbose output with code samples
ubs -v test-suite/buggy/

# Save report
ubs test-suite/buggy/ test-results-buggy.txt
```

### Scan Clean Code

```bash
# Should find minimal or no critical issues
ubs test-suite/clean/

# Verbose output
ubs -v test-suite/clean/
```

### Comparison Test

```bash
# Scan buggy code and count issues
echo "=== BUGGY CODE ==="
ubs test-suite/buggy/ | grep -E "Critical|Warning|Info"

echo ""
echo "=== CLEAN CODE ==="
ubs test-suite/clean/ | grep -E "Critical|Warning|Info"
```

## 📊 Expected Results

### Buggy Code - Core Patterns (test-suite/buggy/)

Each file contains **intentional bugs** that the scanner should detect:

| File | Expected Issues | Primary Categories |
|------|----------------|-------------------|
| `01-null-safety.js` | 10+ CRITICAL | Unguarded property access, missing null checks |
| `02-security.js` | 14+ CRITICAL | eval(), XSS, hardcoded secrets, weak crypto |
| `03-async-await.js` | 14+ CRITICAL/WARNING | Missing await, no error handling, race conditions |
| `04-memory-leaks.js` | 13+ WARNING | Event listeners, timers, DOM queries in loops |
| `05-type-coercion.js` | 13+ CRITICAL/WARNING | Loose equality, NaN comparison, type confusion |
| `06-math-errors.js` | 14+ WARNING | Division by zero, parseInt without radix |
| `07-error-handling.js` | 14+ CRITICAL | Empty catch blocks, throwing strings, no try/catch |
| `08-control-flow.js` | 13+ WARNING | Missing breaks, nested ternaries, unreachable code |
| `09-debugging-production.js` | 12+ CRITICAL | debugger statements, console.log, sensitive data logging |
| `10-variable-scope.js` | 14+ WARNING/CRITICAL | var usage, global pollution, variable shadowing |
| `11-combined-issues.js` | 20+ MIXED | Realistic codebase with multiple bug types |
| `12-regex-vulnerabilities.js` | 15+ CRITICAL | ReDoS attacks, catastrophic backtracking, regex bombs |
| `13-prototype-pollution.js` | 18+ CRITICAL | __proto__ pollution, unsafe merge/clone operations |
| `14-injection-attacks.js` | 20+ CRITICAL | SQL, NoSQL, command, XPath, LDAP injection |
| `15-race-conditions.js` | 18+ CRITICAL/WARNING | TOCTOU bugs, non-atomic operations, data races |
| `16-crypto-mistakes.js` | 22+ CRITICAL | MD5/SHA1, hardcoded keys, weak random, ECB mode |
| `17-dom-manipulation.js` | 18+ WARNING/CRITICAL | DOM clobbering, layout thrashing, memory leaks |
| `18-api-misuse.js` | 20+ WARNING/CRITICAL | Array.forEach misuse, promise handling, this binding |
| `19-performance-anti-patterns.js` | 20+ WARNING | N+1 queries, blocking I/O, memory accumulation |
| `20-configuration-errors.js` | 18+ CRITICAL | CORS, CSP, missing security headers, weak sessions |

**Core Patterns Total:** 275+ issues

### Framework-Specific Tests

| File | Expected Issues | Description |
|------|----------------|-------------|
| `frameworks/react/buggy-component.jsx` | 28+ CRITICAL/WARNING | React anti-patterns, hooks violations, memory leaks |
| `frameworks/react/clean-component.jsx` | 0-2 | React best practices, proper hooks, memoization |
| `frameworks/node/buggy-api.js` | 35+ CRITICAL | Express security flaws, SQL injection, no validation |
| `frameworks/node/clean-api.js` | 0-2 | Secure API, validation, rate limiting, graceful shutdown |

**Frameworks Total:** 63+ issues in buggy files

### Feature-Specific Suites

| Manifest Case | Path | Purpose |
|----------------|------|---------|
| `js-taint-buggy` | `test-suite/js/buggy/taint_analysis.js` | Unsanitized req.body/req.query/window.location flows into `innerHTML`, `res.send`, `db.query`, and `child_process.exec` so taint analysis should emit CRITICAL findings. |
| `js-taint-clean` | `test-suite/js/clean/taint_analysis.js` | Mirrors the buggy flows but sanitizes with DOMPurify/escapeHtml/shellescape/parameterized SQL to prove the helper suppresses safe code. |
| `js-typescript-path-traversal-buggy` | `test-suite/js/security/path-traversal-buggy.ts` | Request query, params, body, upload filenames, Express header accessors, and framework `headers()` values flow into Node file read/download/write/upload sinks without containment checks. |
| `js-typescript-path-traversal-clean` | `test-suite/js/security/path-traversal-clean.ts` | Uses `path.resolve`/`path.relative` containment or basename filename sanitization before file sinks, including header-derived and `headers()` paths. |
| `python-taint-buggy` | `test-suite/python/buggy/taint_analysis.py` | Flask `request.args` hits HTML, `cursor.execute`, and `subprocess.run(shell=True)` without sanitization so new helper must warn. |
| `python-taint-clean` | `test-suite/python/clean/taint_analysis.py` | Same flows but escaped via `html.escape`, parameterized SQL, and `shlex.quote`, proving the helper stays quiet on safe code. |
| `golang-taint-buggy` | `test-suite/golang/buggy/taint_analysis.go` | `r.FormValue` is written to `fmt.Fprintf`, concatenated into SQL, and passed to `exec.Command("sh","-c", ...)`. |
| `golang-taint-clean` | `test-suite/golang/clean/taint_analysis.go` | Escapes comments with `html.EscapeString`, uses positional args in `db.Exec`, and passes cleaned paths into `exec.Command`. |
| `golang-header-injection-buggy` | `test-suite/golang/security/header_injection_buggy.go` | Request query, form, header, and framework values flow into response headers without CR/LF validation or header-safe formatting. |
| `golang-header-injection-clean` | `test-suite/golang/security/header_injection_clean.go` | Uses CR/LF stripping, `mime.FormatMediaType`, and reject-on-newline guards before setting response headers. |
| `golang-ssrf-buggy` | `test-suite/golang/security/ssrf_buggy.go` | Request query/form/header/route/host values flow into `http.Get`, `http.Post`, and `client.Do` without scheme and host allow-list validation. |
| `golang-ssrf-clean` | `test-suite/golang/security/ssrf_clean.go` | Uses a named `safeOutboundURL` helper with URL parsing and host allow-list checks before outbound HTTP calls, including URLs assembled from inbound host values. |
| `golang-request-path-traversal-buggy` | `test-suite/golang/security/path_traversal_buggy.go` | Request query, route, header, and upload filenames flow into `http.ServeFile` and `os.*` sinks without containment checks. |
| `golang-request-path-traversal-clean` | `test-suite/golang/security/path_traversal_clean.go` | Uses `filepath.Rel`/`filepath.IsAbs` containment and `filepath.Base` filename sanitization before file sinks, including header-derived paths. |
| `cpp-request-path-traversal-buggy` | `test-suite/cpp/security/path_traversal_buggy.cpp` | Request/query/header/path filenames flow into C and C++ file read/write/delete sinks without containment checks. |
| `cpp-request-path-traversal-clean` | `test-suite/cpp/security/path_traversal_clean.cpp` | Uses canonical root containment or `std::filesystem::path(...).filename()` before file sinks. |
| `cpp-open-redirect-buggy` | `test-suite/cpp/security/open_redirect_buggy.cpp` | Request/query/header/host redirect targets flow into redirect functions and `Location` headers without local-path or redirect host allow-list validation. |
| `cpp-open-redirect-clean` | `test-suite/cpp/security/open_redirect_clean.cpp` | Uses named safe redirect helpers, local path guards, or redirect host allow-lists before C/C++ redirect sinks. |
| `cpp-ssrf-buggy` | `test-suite/cpp/security/ssrf_buggy.cpp` | CGI query and header URL values flow into libcurl `CURLOPT_URL` without scheme and host allow-list validation. |
| `cpp-ssrf-clean` | `test-suite/cpp/security/ssrf_clean.cpp` | Uses a named safe outbound URL helper with explicit `https` and host allow-list checks before libcurl URL configuration. |
| `rust-open-redirect-buggy` | `test-suite/rust/buggy/open_redirect.rs` | Query params, headers, and inbound host values flow into Rust redirect responses or `Location` headers without local-path or redirect host allow-list validation. |
| `rust-open-redirect-clean` | `test-suite/rust/clean/open_redirect.rs` | Uses a named safe redirect helper, local path guard, or redirect host allow-list before redirect responses and `Location` headers. |
| `rust-ssrf-buggy` | `test-suite/rust/buggy/ssrf.rs` | Query params, headers, env vars, and CLI URL values flow into reqwest/ureq/http request sinks without scheme and host allow-list validation. |
| `rust-ssrf-clean` | `test-suite/rust/clean/ssrf.rs` | Uses a named safe outbound URL helper with `Url::parse`, HTTPS enforcement, and a host allow-list before HTTP client sinks. |
| `java-request-path-traversal-buggy` | `test-suite/java/security/path_traversal_buggy.java` | Request parameters, path info, annotated headers, and upload filenames flow into Java file read/write/delete sinks without containment checks. |
| `java-request-path-traversal-clean` | `test-suite/java/security/path_traversal_clean.java` | Uses `toRealPath().normalize()` plus `startsWith` containment or `Path.getFileName()` before file sinks, including annotated header paths. |
| `java-ssrf-buggy` | `test-suite/java/security/SsrfBuggy.java` | Request parameters, headers, and servlet host accessors flow into JDK `HttpClient`, `RestTemplate`, and `URL.openStream` without scheme and host allow-list validation. |
| `java-ssrf-clean` | `test-suite/java/security/SsrfClean.java` | Uses named safe outbound URL helpers with URL parsing and host allow-list checks before client request sinks, including URLs assembled from inbound host values. |
| `js-type-narrowing-buggy` | `test-suite/js/type_narrowing/buggy` | TypeScript fixtures that guard values (e.g., `if (!user) { ... }`) but keep running and later dereference/force unwrap, exercising the tsserver-powered narrowing analyzer. |
| `js-type-narrowing-clean` | `test-suite/js/type_narrowing/clean` | Guard clauses that exit early (return/throw) so the analyzer proves it suppresses safe code. |
| `rust-type-narrowing-buggy` | `test-suite/rust/buggy/type_narrowing.rs` | Rust fixtures where `if let Some/Ok` guards continue execution and later call `.unwrap()`/`.expect()` on the guarded value, feeding the cross-language narrowing heuristics. |
| `rust-type-narrowing-clean` | `test-suite/rust/clean/type_narrowing.rs` | Counterexamples that exit early or propagate via `?`, ensuring the heuristic does not report on safe code paths. |
| `kotlin-type-narrowing-buggy` | `test-suite/kotlin/type_narrowing/buggy` | Kotlin guards that log/continue instead of exiting, then dereference the nullable value with `!!`, ensuring the JVM module spots unsafe usage outside the guard. |
| `kotlin-type-narrowing-clean` | `test-suite/kotlin/type_narrowing/clean` | Kotlin fixtures that return/throw or use Elvis early so the analyzer proves it suppresses safe flows. |
| `kotlin-archive-extraction-buggy` | `test-suite/kotlin/archive_extraction_buggy` | Kotlin `ZipFile`/`ZipInputStream` flows that join `entry.name` into destination paths without validating containment. |
| `kotlin-archive-extraction-clean` | `test-suite/kotlin/archive_extraction_clean` | Kotlin zip extraction that normalizes the destination and verifies `target.startsWith(base)` before writing. |
| `kotlin-request-path-traversal-buggy` | `test-suite/kotlin/path_traversal_buggy` | Kotlin Ktor-style params, request paths, headers, and upload filenames flow into file read/write/serve/delete sinks without basename or root containment checks. |
| `kotlin-request-path-traversal-clean` | `test-suite/kotlin/path_traversal_clean` | Kotlin fixtures that use safe root containment or `Path.fileName` reduction before touching file sinks, including header-derived paths. |
| `kotlin-ssrf-buggy` | `test-suite/kotlin/ssrf_buggy` | Kotlin Ktor-style query and header URLs flow into HTTP client `get`/`post` calls without scheme and host allow-list validation. |
| `kotlin-ssrf-clean` | `test-suite/kotlin/ssrf_clean` | Kotlin fixtures that validate outbound URLs through a named safe helper before Ktor-style HTTP client calls. |
| `ruby-open-redirect-buggy` | `test-suite/ruby/open_redirect_buggy` | Rack/Rails params, headers, referers, and host values flow into `redirect_to`, Sinatra/Rack `redirect`, and `Location` headers without local-url or host allow-list checks. |
| `ruby-open-redirect-clean` | `test-suite/ruby/open_redirect_clean` | Ruby fixtures that use a named safe redirect helper, local path checks, Rails `url_from`, or `allow_other_host: false` before redirect sinks. |
| `swift-request-path-traversal-buggy` | `test-suite/swift/path_traversal_buggy` | Swift request query, headers, URL path, and upload filename values flow into file read/write/serve/delete sinks without basename or root containment checks. |
| `swift-request-path-traversal-clean` | `test-suite/swift/path_traversal_clean` | Swift fixtures that use `lastPathComponent` or standardized root containment before touching file sinks, including header-derived paths. |
| `swift-open-redirect-buggy` | `test-suite/swift/open_redirect_buggy` | Swift request query, headers, parameters, content, and inbound URL values flow into redirects or `Location` headers without local-url or host allow-list validation. |
| `swift-open-redirect-clean` | `test-suite/swift/open_redirect_clean` | Swift fixtures that use a named safe redirect helper, local path guards, or inline URL parsing plus host allow-list validation before redirect sinks. |
| `swift-ssrf-buggy` | `test-suite/swift/ssrf_buggy` | Swift request query, headers, parameters, and content values flow into URLSession, URLRequest handoffs, blocking URL reads, and HTTP clients without scheme and host allow-list checks. |
| `swift-ssrf-clean` | `test-suite/swift/ssrf_clean` | Swift fixtures that use a named safe outbound URL helper or inline URL parsing plus https scheme and host allow-list validation before outbound clients. |
| `swift-type-narrowing-buggy` | `test-suite/swift/type_narrowing/buggy` | Swift guard lets, Objective-C bridging casts, and optional-chain bridges that log/continue instead of returning before force-unwrapping, so the helper flags unsafe paths. |
| `swift-type-narrowing-clean` | `test-suite/swift/type_narrowing/clean` | Swift counterexamples that return/throw or fully bind optionals before use so the analyzer stays quiet on correct patterns. |
| `csharp-ssrf-buggy` | `test-suite/csharp/security/SsrfBuggy.cs` | ASP.NET request query, headers, route values, form values, and host fragments flow into `HttpClient`, `HttpRequestMessage`, `WebRequest`, and `WebClient` without scheme and host allow-list checks. |
| `csharp-ssrf-clean` | `test-suite/csharp/security/SsrfClean.cs` | C# fixtures that use a named safe outbound URL helper or inline `Uri.TryCreate` plus `https` scheme and host allow-list validation before outbound clients. |
| `csharp-open-redirect-buggy` | `test-suite/csharp/security/OpenRedirectBuggy.cs` | ASP.NET request query, headers, cookies, and route values flow into `Redirect`, `Response.Redirect`, `RedirectResult`, and `Location` headers without local-url or host allow-list checks. |
| `csharp-open-redirect-clean` | `test-suite/csharp/security/OpenRedirectClean.cs` | C# fixtures that use `LocalRedirect`, `Url.IsLocalUrl`, a named safe redirect helper, or inline `Uri.TryCreate` plus host allow-list validation before redirect sinks. |
| `elixir-request-path-traversal-buggy` | `test-suite/elixir/buggy/path_traversal.ex` | Plug/Phoenix params, request paths, headers, and upload filenames flow into `File.*`, `send_file`, and `send_download` sinks without basename or root containment checks. |
| `elixir-request-path-traversal-clean` | `test-suite/elixir/clean/path_traversal.ex` | Elixir fixtures that use `Path.basename` or `Path.expand` plus `String.starts_with?` containment before touching file sinks, including header-derived paths. |
| `elixir-open-redirect-buggy` | `test-suite/elixir/buggy/open_redirect.ex` | Plug/Phoenix params, query params, headers, host values, and `Location` header targets reach redirects without local-url or host allow-list validation. |
| `elixir-open-redirect-clean` | `test-suite/elixir/clean/open_redirect.ex` | Elixir fixtures that use a safe redirect helper, local path guards, or `URI.parse` plus host allow-list validation before redirect sinks. |
| `elixir-ssrf-buggy` | `test-suite/elixir/buggy/ssrf.ex` | Plug/Phoenix params, headers, host values, and query params flow into Req, HTTPoison, Finch, Tesla, and `:httpc` without scheme and host allow-list checks. |
| `elixir-ssrf-clean` | `test-suite/elixir/clean/ssrf.ex` | Elixir fixtures that use a named safe outbound URL helper or inline `URI.parse` plus `https` scheme and host allow-list validation before outbound clients. |

### Realistic Scenarios

| File | Expected Issues | Description |
|------|----------------|-------------|
| `realistic/buggy-ecommerce-checkout.js` | 35+ CRITICAL | Real e-commerce bugs: race conditions, price manipulation |
| `realistic/buggy-auth-system.js` | 40+ CRITICAL | Auth catastrophes: SQL injection, weak crypto, IDOR |

**Realistic Total:** 75+ issues

### Edge Cases

| File | Expected Issues | Description |
|------|----------------|-------------|
| `edge-cases/unicode-bugs.js` | 15+ WARNING | Unicode handling, grapheme clusters, homoglyphs |
| `edge-cases/timezone-date-bugs.js` | 18+ WARNING | Date arithmetic, DST, timezone handling, leap years |
| `edge-cases/floating-point-bugs.js` | 16+ WARNING | Money calculations, precision loss, rounding errors |

**Edge Cases Total:** 49+ issues

### Clean Code Examples (test-suite/clean/)

| File | Expected Issues | Notes |
|------|----------------|-------|
| `01-null-safety-clean.js` | 0-2 | Optional chaining, null checks, guard clauses |
| `02-security-clean.js` | 0-1 | textContent, env vars, strong crypto, parameterized queries |
| `03-async-await-clean.js` | 0-1 | try/catch, Promise.all, AbortController, cleanup |
| `04-error-handling-clean.js` | 0-1 | Error objects, try-finally, validation, retry logic |
| `05-memory-management-clean.js` | 0-2 | Event cleanup, WeakMap, streams, object pooling |
| `06-performance-clean.js` | 0-2 | Memoization, debouncing, virtual scrolling, lazy loading |

**Clean Code Total:** 0-10 minor issues (mostly INFO level)

---

### 📈 Overall Test Suite Summary

- **Total Buggy Files:** 32+ files
- **Total Expected Bugs:** 475+ issues across all categories
- **Total Clean Files:** 13 files
- **Coverage:** Security, Performance, Concurrency, Edge Cases, Framework Patterns, Type Narrowing

## 🎯 What Each File Tests

### Buggy Files

#### 01-null-safety.js
- Unguarded DOM queries (`getElementById` without null check)
- Deep property access without optional chaining
- Missing array length checks
- Chained method calls on potentially null objects

#### 02-security.js
- **CRITICAL:** `eval()` usage (RCE vulnerability)
- **CRITICAL:** XSS via `innerHTML` with user input
- **CRITICAL:** Hardcoded API keys and secrets
- Weak crypto (MD5, SHA1)
- HTTP URLs in production
- ReDoS vulnerable regex patterns

#### 03-async-await.js
- `await` in non-async function (SyntaxError)
- Missing `await` on async calls
- Promises without `.catch()` or error handling
- `await` inside loops (performance)
- Race conditions
- Floating promises

#### 04-memory-leaks.js
- Event listeners never removed
- `setInterval` without `clearInterval`
- React useEffect without cleanup
- DOM queries in loops
- String concatenation in loops
- Detached DOM nodes

#### 05-type-coercion.js
- Loose equality (`==` instead of `===`)
- Direct NaN comparison
- Wrong typeof string literals
- Global `isNaN()` instead of `Number.isNaN()`
- Implicit type conversions

#### 06-math-errors.js
- Division by zero
- `parseInt` without radix parameter
- Floating-point equality comparisons
- Modulo by zero
- Bitwise operations on non-integers

#### 07-error-handling.js
- Empty catch blocks (swallowing errors)
- Try without finally (resource leaks)
- Throwing strings instead of Error objects
- Generic error messages
- `JSON.parse` without try/catch

#### 08-control-flow.js
- Switch cases without break
- Switch without default case
- Nested ternaries (unreadable)
- Unreachable code
- Empty if/else blocks

#### 09-debugging-production.js
- **CRITICAL:** `debugger` statements left in code
- Excessive `console.log` statements
- Logging sensitive data (passwords, API keys)
- `alert/confirm/prompt` (blocking UI)
- TODO/FIXME markers

#### 10-variable-scope.js
- Using `var` instead of `let`/`const`
- Global variable pollution (missing declarations)
- Variable shadowing
- Loop variable leaking
- Attempting to reassign `const`

#### 11-combined-issues.js
- Realistic simulation of multiple bug types in one file
- Security + async + null safety + performance issues
- Tests scanner's ability to find diverse issues in real-world code

#### 12-regex-vulnerabilities.js
- **CRITICAL:** ReDoS (Regular Expression Denial of Service) attacks
- Catastrophic backtracking with nested quantifiers
- Regex bombs and performance killers
- Unsafe user input in regex patterns
- Global regex state bugs

#### 13-prototype-pollution.js
- **CRITICAL:** Object.prototype pollution via merge/clone
- `__proto__` and `constructor.prototype` manipulation
- Recursive merge vulnerabilities
- Path traversal in object property access
- Unsafe for...in loops without hasOwnProperty

#### 14-injection-attacks.js
- **CRITICAL:** SQL injection (string concatenation in queries)
- NoSQL injection (MongoDB operator injection)
- Command injection (exec, spawn with user input)
- LDAP, XPath, GraphQL injection
- CSV/Formula injection, XXE attacks

#### 15-race-conditions.js
- **CRITICAL:** TOCTOU (Time-of-Check Time-of-Use) bugs
- Non-atomic read-modify-write operations
- Database race conditions (check-then-insert)
- Shared mutable state in async contexts
- Double-checked locking without proper synchronization

#### 16-crypto-mistakes.js
- **CRITICAL:** MD5 and SHA1 usage (cryptographically broken)
- Hardcoded encryption keys and IVs
- ECB mode usage (leaks patterns)
- Weak random number generation (Math.random for security)
- No password salt, insufficient PBKDF2 iterations

#### 17-dom-manipulation.js
- DOM clobbering via form elements
- Layout thrashing (read-write-read-write)
- Detached DOM nodes causing memory leaks
- Setting dangerous attributes (href="javascript:")
- Creating elements in loops (performance)

#### 18-api-misuse.js
- Array.forEach with return (doesn't work)
- Modifying arrays while iterating
- Misunderstanding Promise.all behavior
- Using delete on arrays (leaves holes)
- Array.sort without comparator function

#### 19-performance-anti-patterns.js
- N+1 query problems (database)
- Blocking event loop (synchronous I/O)
- Regex compilation in loops
- String concatenation in loops (O(n²))
- Memory leaks (unbounded cache growth)

#### 20-configuration-errors.js
- **CRITICAL:** Wildcard CORS with credentials
- Missing security headers (CSP, X-Frame-Options, HSTS)
- Weak session configuration
- Exposing server version information
- No rate limiting on sensitive endpoints

### Clean Files

#### 01-null-safety-clean.js
- ✅ Null checks before property access
- ✅ Optional chaining (`?.`)
- ✅ Nullish coalescing (`??`)
- ✅ Guard clauses
- ✅ Array.isArray checks

#### 02-security-clean.js
- ✅ Using `textContent` instead of `innerHTML`
- ✅ Environment variables for secrets
- ✅ Strong crypto (SHA-256)
- ✅ HTTPS URLs
- ✅ Safe regex patterns

#### 03-async-await-clean.js
- ✅ Proper async/await usage
- ✅ Try/catch error handling
- ✅ `Promise.all()` for parallelization
- ✅ `.catch()` on promises
- ✅ Timeout handling

#### 04-error-handling-clean.js
- ✅ Specific error handling by type
- ✅ Error objects with context
- ✅ Try-catch with finally for cleanup
- ✅ Error boundaries and centralized handling
- ✅ Validation before risky operations

#### 05-memory-management-clean.js
- ✅ Event listener cleanup
- ✅ Timer cleanup (clearInterval/clearTimeout)
- ✅ WeakMap for metadata (allows GC)
- ✅ LRU cache with size limits
- ✅ Stream processing for large data
- ✅ Object pooling for performance

#### 06-performance-clean.js
- ✅ DocumentFragment for batch DOM updates
- ✅ Debouncing and throttling
- ✅ Memoization for expensive computations
- ✅ Virtual scrolling for large lists
- ✅ RequestAnimationFrame for animations
- ✅ Web Workers for heavy computation

### Framework-Specific Tests

#### frameworks/react/buggy-component.jsx
- Missing dependencies in useEffect
- Direct state mutation
- Using index as key
- Memory leaks (no cleanup)
- Calling hooks conditionally
- Not memoizing expensive computations
- Props mutation
- Infinite render loops

#### frameworks/react/clean-component.jsx
- Proper useEffect dependencies with cleanup
- Functional state updates
- Unique stable keys
- useMemo and useCallback for optimization
- Context to avoid prop drilling
- Error boundaries
- Custom hooks for reusable logic
- Lazy loading with Suspense

#### frameworks/node/buggy-api.js
- SQL injection vulnerabilities
- No input validation
- Exposing sensitive errors in responses
- No rate limiting
- Blocking synchronous operations
- Memory leaks (global variables growing)
- Hardcoded credentials
- No authentication/authorization checks

#### frameworks/node/clean-api.js
- Parameterized queries (SQL injection prevention)
- Input validation with express-validator
- Security middleware (helmet, CORS)
- Rate limiting
- Async/await with proper error handling
- Database connection pooling
- Environment variables for secrets
- Graceful shutdown handlers

### Realistic Scenarios

#### realistic/buggy-ecommerce-checkout.js
Real-world e-commerce checkout flow with critical flaws:
- Race conditions in inventory management
- Client-side price calculation (price manipulation!)
- No transaction handling (partial updates)
- TOCTOU bugs in stock checking
- Trusting client input for discounts
- Logging credit card data
- No idempotency (double charging)
- Decimal precision issues with money

#### realistic/buggy-auth-system.js
Catastrophic authentication system with 40+ security flaws:
- SQL injection in login/signup
- Weak password hashing (MD5, same salt)
- Predictable session IDs
- Session fixation vulnerabilities
- IDOR (viewing any user's data)
- Mass assignment (privilege escalation)
- No CSRF protection
- Password reset without verification
- Timing attacks
- JWT without signature verification

### Edge Cases

#### edge-cases/unicode-bugs.js
- Emoji and surrogate pair handling
- String length with grapheme clusters
- Unicode normalization (NFC vs NFD)
- Case conversion with different locales
- Homoglyph attacks
- Zero-width characters
- RTL override attacks
- File extension spoofing with unicode

#### edge-cases/timezone-date-bugs.js
- Timezone-aware date handling
- DST (Daylight Saving Time) transitions
- Leap year calculations
- Date arithmetic (month/day boundaries)
- Unix timestamp seconds vs milliseconds
- Date formatting for different locales
- Week number calculations
- Age calculation edge cases
- Midnight and date boundary issues

#### edge-cases/floating-point-bugs.js
- Floating-point precision (0.1 + 0.2 !== 0.3)
- Money calculations without proper rounding
- Accumulating floating-point errors
- Decimal to binary conversion issues
- Currency conversion precision
- Percentage calculations
- Comparing floats for equality
- JavaScript Number.MAX_SAFE_INTEGER limits

## 🔬 Validation Checklist

Use this checklist to verify the scanner is working correctly:

### Critical Issue Detection

- [ ] Detects `eval()` usage (02-security.js)
- [ ] Detects `new Function()` (02-security.js)
- [ ] Detects `innerHTML` XSS (02-security.js)
- [ ] Detects hardcoded secrets (02-security.js)
- [ ] Detects `debugger` statements (09-debugging-production.js)
- [ ] Detects NaN direct comparison (05-type-coercion.js, 06-math-errors.js)
- [ ] Detects `await` in non-async function (03-async-await.js)
- [ ] Detects unguarded DOM queries (01-null-safety.js)

### Warning Detection

- [ ] Detects division by zero risk (06-math-errors.js)
- [ ] Detects `parseInt` without radix (06-math-errors.js)
- [ ] Detects promises without `.catch()` (03-async-await.js)
- [ ] Detects event listeners without cleanup (04-memory-leaks.js)
- [ ] Detects `setInterval` without clear (04-memory-leaks.js)
- [ ] Detects loose equality (05-type-coercion.js)
- [ ] Detects empty catch blocks (07-error-handling.js)
- [ ] Detects switch without default (08-control-flow.js)

### Info Detection

- [ ] Detects `var` usage (10-variable-scope.js)
- [ ] Detects `console.log` statements (09-debugging-production.js)
- [ ] Detects TODO/FIXME markers (09-debugging-production.js)
- [ ] Detects optional chaining opportunities (01-null-safety.js)
- [ ] Suggests performance improvements (04-memory-leaks.js)

### Clean Code Recognition

- [ ] Passes clean null safety code (clean/01-null-safety-clean.js)
- [ ] Passes clean security code (clean/02-security-clean.js)
- [ ] Passes clean async code (clean/03-async-await-clean.js)

## 📈 Benchmark Commands

### Comprehensive Test

```bash
#!/bin/bash
# comprehensive-test.sh - Run full test suite validation

echo "=== ULTIMATE BUG SCANNER - TEST SUITE VALIDATION ==="
echo ""

echo "1. Testing buggy code detection..."
BUGGY_CRITICAL=$(ubs test-suite/buggy/ 2>&1 | grep "Critical:" | awk '{print $3}')
BUGGY_WARNING=$(ubs test-suite/buggy/ 2>&1 | grep "Warning:" | awk '{print $3}')
echo "   Buggy code: $BUGGY_CRITICAL critical, $BUGGY_WARNING warnings"

echo ""
echo "2. Testing clean code validation..."
CLEAN_CRITICAL=$(ubs test-suite/clean/ 2>&1 | grep "Critical:" | awk '{print $3}')
CLEAN_WARNING=$(ubs test-suite/clean/ 2>&1 | grep "Warning:" | awk '{print $3}')
echo "   Clean code: $CLEAN_CRITICAL critical, $CLEAN_WARNING warnings"

echo ""
echo "=== VALIDATION RESULTS ==="
if [ "$BUGGY_CRITICAL" -gt 50 ] && [ "$CLEAN_CRITICAL" -lt 3 ]; then
  echo "✅ PASS: Scanner correctly identifies bugs and validates clean code"
else
  echo "❌ FAIL: Scanner may need calibration"
fi
```

### Performance Test

```bash
# Test scanning speed
time ubs test-suite/buggy/

# Expected: < 2 seconds for all buggy files
```

## 🎓 Educational Use

This test suite is ideal for:

1. **Learning JavaScript Pitfalls** - Each buggy file shows real-world mistakes
2. **Testing AI Agents** - Verify AI coding agents can catch these issues
3. **Scanner Development** - Add new bug patterns and test detection
4. **Code Review Training** - Practice identifying common bugs

## 🔧 Adding New Test Cases

To add new test cases:

1. Create a new file in `buggy/` or `clean/`
2. Add clear comments explaining each bug or best practice
3. Include diverse examples
4. Test with scanner: `ubs test-suite/buggy/your-new-file.js`
5. Update this README with expected results

## 📝 Notes

- **Buggy files are intentionally broken** - Do NOT use this code in production!
- **All bugs are clearly commented** for educational purposes
- **Exit codes matter**: Buggy code should exit with code 1, clean code with 0
- **Some files may trigger 100+ issues** - this is expected and demonstrates the scanner's thoroughness

## 🎯 Success Criteria

The scanner passes validation if:

1. ✅ **Detection Rate:** Finds 80%+ of intentional bugs (360+ of 460+ total)
2. ✅ **False Positives:** <5% false positive rate on clean code (<10 issues)
3. ✅ **Performance:** Completes full suite scan in <10 seconds
4. ✅ **Categorization:** Correctly labels CRITICAL vs WARNING vs INFO
5. ✅ **Actionable Output:** Provides clear fix suggestions with line numbers
6. ✅ **Advanced Patterns:** Detects at least 70% of:
   - ReDoS vulnerabilities
   - Prototype pollution
   - Race conditions
   - Injection attacks (SQL, NoSQL, command)
   - Cryptographic failures
7. ✅ **Framework Awareness:** Identifies React and Node.js specific anti-patterns
8. ✅ **Edge Case Handling:** Flags unicode, timezone, and floating-point issues

### Benchmark Targets

| Category | Target Detection Rate | Critical Issues |
|----------|----------------------|-----------------|
| Security (files 02, 12-14, 16, 20) | >90% | >80 |
| Memory & Performance (04, 17, 19) | >75% | >40 |
| Async & Concurrency (03, 15) | >80% | >25 |
| Framework Patterns (React, Node) | >70% | >50 |
| Realistic Scenarios | >85% | >60 |
| Edge Cases | >60% | >30 |

---

## 🚀 Quick Start Commands

**Run comprehensive validation:**

```bash
# Full test suite (all 29 buggy files, 460+ expected issues)
ubs test-suite/

# Core patterns only (20 files, 275+ issues)
ubs test-suite/buggy/

# Framework-specific tests (63+ issues)
ubs test-suite/frameworks/

# Realistic scenarios (75+ issues)
ubs test-suite/realistic/

# Edge cases (49+ issues)
ubs test-suite/edge-cases/

# Clean code validation (<10 issues expected)
ubs test-suite/clean/
```

**Category-specific scans:**

```bash
# Security-focused
ubs test-suite/buggy/{02,12,13,14,16,20}*.js

# Performance-focused
ubs test-suite/buggy/{04,17,19}*.js

# Concurrency bugs
ubs test-suite/buggy/{03,15}*.js
```

**Before/after comparisons:**

```bash
# Null safety: before and after
ubs test-suite/buggy/01-null-safety.js test-suite/clean/01-null-safety-clean.js

# Security: before and after
ubs test-suite/buggy/02-security.js test-suite/clean/02-security-clean.js

# Async patterns: before and after
ubs test-suite/buggy/03-async-await.js test-suite/clean/03-async-await-clean.js
```

## Manifest-driven regression runner

In addition to ad-hoc scans you can execute a curated manifest of cases that
assert exit semantics and severity thresholds across the repo. The manifest
(`test-suite/manifest.json`) now includes **every language** (JS core + frameworks, Python, Go, C++, Rust, Java, Ruby, Swift, C#, Elixir, and the JS edge-case directories).

```bash
cd test-suite
./run_manifest.py                  # run every enabled case
./run_manifest.py --list           # inspect case ids / skip status
./run_manifest.py --case cpp-buggy # run one case
./run_manifest.py --case-timeout=120 # fail a hung case with artifacts
./run_all.sh --fail-fast           # convenience wrapper around run_manifest.py
```

Key behavior:

- Each case specifies the path to scan, additional UBS arguments (e.g.
  `--only=js`, `--fail-on-warning`), and expectations for `critical/warning/info`
  counts.
- Runs parse JSON, TOON, meta-runner text, or module text output depending on
  the case. Derived exit status is computed from severity totals where needed
  so we can still ensure “buggy” cases fail when a mode reports findings without
  a process-level nonzero exit.
- Artifacts for every case (stdout, stderr, parsed summary) land under
  `test-suite/artifacts/<case-id>/` to speed up debugging scanner regressions.
- Each case prints a flushed `RUN` line before execution and is capped by
  `--case-timeout` (or `UBS_MANIFEST_CASE_TIMEOUT`) so hangs become named
  failures instead of silent suite stalls.
- Disabled cases are recorded with skip reasons so we can track the backlog
  explicitly. See `test-suite/TODO.md` for the full punch list.

`run_all.sh` runs the rule-quality harness first, then forwards arguments to
`run_manifest.py`, followed by shareable-report and helper regression tests.

### CI automation

GitHub Actions now runs the manifest on every push and pull request via
`.github/workflows/manifest.yml`. The workflow installs `python3`, `jq`, and
`ripgrep`, exports `NO_COLOR=1` for stable logs, and executes:

```bash
cd test-suite && ./run_manifest.py --fail-fast
```

Failures bubble up exactly as they do locally because the workflow relies on
the same manifest runner and artifacts under `test-suite/artifacts/`.
