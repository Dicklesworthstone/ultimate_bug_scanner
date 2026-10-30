# 🧭 UBS Detector Coverage Matrix

> Generated automatically from [`detectors.yml`](../detectors.yml) by `scripts/generate_coverage_matrix.py`.
> Hand-maintained registry; validated by `test-suite/quality/rule_quality_harness.py`.

## Summary

- **Detector Families**: 21
- **Languages Supported**: 14
- **Implemented Cells**: 142 (48.3%)
- **Planned Cells**: 141 (48.0%)
- **N/A Cells**: 11 (3.7%)

## Matrix

Legend:
- **✓** Implemented (with verified buggy and clean regression fixture pairs)
- **○** Planned / In Progress
- **—** Not Applicable for language runtime/ecosystem

| Family | JS / TS | Python | Go | Rust | Java | Kotlin | C / C++ | Ruby | Swift | C# | Elixir | Bash | PHP | sql |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Archive Extraction (Zip Slip) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ |
| Async & Concurrency Hazards | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ✓ | ✓ | ○ | ✓ | ○ | ○ | ○ | ○ |
| Command Injection | ○ | ✓ | ○ | ✓ | ✓ | ✓ | ○ | ○ | ✓ | ○ | ✓ | ✓ | ✓ | ○ |
| Constant-Time Secret Comparison | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| Credentialed Wildcard CORS | ✓ | ✓ | ✓ | ✓ | ○ | ○ | — | ○ | ○ | ○ | ○ | — | ○ | ○ |
| Deep Guard Correlation | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | — | ○ | ○ |
| Disabled TLS Verification | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| HTTP Response Header Injection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ○ | ○ |
| Hardcoded Secrets & Default Fallbacks | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ○ | ○ | ○ |
| Insecure Cookie Flags | ✓ | ✓ | ✓ | ○ | ○ | ○ | — | ○ | ○ | ○ | ○ | — | ○ | ○ |
| Insecure Security Randomness | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ |
| JWT Verification Bypass | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | — | ○ | ○ |
| Open Redirect | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ○ | ○ |
| Path Traversal | ✓ | ✓ | ✓ | ○ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ✓ | ○ |
| PostgreSQL Function Privileges | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ |
| Resource Lifecycle & Cleanup | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ✓ | ✓ | ○ | ✓ | ○ | ○ | ○ | ○ |
| SQL Injection | ✓ | ✓ | ○ | ✓ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ | — | ✓ | ○ |
| Server-Side Request Forgery (SSRF) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ |
| Taint & Dataflow Engine | ✓ | ✓ | ✓ | ○ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ✓ | ○ |
| Type Narrowing & Safe Casting | ✓ | ○ | ○ | ✓ | ✓ | ✓ | ○ | ○ | ✓ | ✓ | ○ | — | ○ | ○ |
| Unsafe Deserialization | ○ | ✓ | ○ | ○ | ○ | ○ | ○ | ✓ | ○ | ○ | ○ | — | ✓ | ○ |

## Family Details

### Archive Extraction (Zip Slip) (`archive_extraction`)
Path traversal during archive decompression / tar / zip extraction

**Implemented:**
- **JS / TS**: `js.security.archive-extraction` (cases: `js-typescript-archive-extraction-buggy`, `js-typescript-archive-extraction-clean`)
- **Python**: `py.security.archive-extraction` (cases: `python-archive-extraction-buggy`, `python-archive-extraction-clean`)
- **Go**: `golang.security.archive_extraction` (cases: `golang-archive-extraction-buggy`, `golang-archive-extraction-clean`)
- **Rust**: `rust.security.archive_extraction` (cases: `rust-archive-extraction-buggy`, `rust-archive-extraction-clean`)
- **Java**: `java.security.archive_extraction` (cases: `java-archive-extraction-buggy`, `java-archive-extraction-clean`)
- **Kotlin**: `kotlin.security.archive_extraction` (cases: `kotlin-archive-extraction-buggy`, `kotlin-archive-extraction-clean`)
- **C / C++**: `cpp.security.archive_extraction` (cases: `cpp-archive-extraction-buggy`, `cpp-archive-extraction-clean`)
- **Ruby**: `ruby.security.archive_extraction` (cases: `ruby-archive-extraction-buggy`, `ruby-archive-extraction-clean`)
- **Swift**: `swift.security.archive_extraction` (cases: `swift-archive-extraction-buggy`, `swift-archive-extraction-clean`)
- **C#**: `csharp.security.archive_extraction` (cases: `csharp-archive-extraction-buggy`, `csharp-archive-extraction-clean`)
- **Elixir**: `elixir.security.archive_extraction` (cases: `elixir-archive-extraction-buggy`, `elixir-archive-extraction-clean`)

**Planned:** Bash, PHP

### Async & Concurrency Hazards (`async_errors`)
Unhandled rejections, missing await, deadlocks, or async loop pitfalls

**Implemented:**
- **JS / TS**: `js.async.pitfalls` (cases: `js-async-errors-buggy`, `js-async-errors-clean`)
- **Python**: `py.async.pitfalls` (cases: `python-async-errors-buggy`, `python-async-errors-clean`)
- **Go**: `golang.async.pitfalls` (cases: `golang-async-errors-buggy`, `golang-async-errors-clean`)
- **Rust**: `rust.async.pitfalls` (cases: `rust-async-errors-buggy`, `rust-async-errors-clean`)
- **Java**: `java.async.pitfalls` (cases: `java-async-errors-buggy`, `java-async-errors-clean`)
- **C / C++**: `cpp.async.pitfalls` (cases: `cpp-async-errors-buggy`, `cpp-async-errors-clean`)
- **Ruby**: `ruby.async.pitfalls` (cases: `ruby-async-errors-buggy`, `ruby-async-errors-clean`)
- **C#**: `csharp.async.task_handles` (cases: `csharp-async-task-handles-buggy`, `csharp-async-task-handles-clean`)

**Planned:** Kotlin, Swift, Elixir, Bash, PHP

### Command Injection (`command_injection`)
Shell or OS command execution using untrusted string arguments

**Implemented:**
- **Python**: `py.security.command_injection` (cases: `python-command-injection-buggy`, `python-command-injection-clean`)
- **Rust**: `rust.security.shell_command` (cases: `rust-security-shell-command-buggy`, `rust-security-shell-command-clean`)
- **Java**: `java.security.command` (cases: `java-buggy`, `java-clean`)
- **Kotlin**: `kotlin.security.command` (cases: `kotlin-security-command-buggy`, `kotlin-security-command-clean`)
- **Swift**: `swift.security.process` (cases: `swift-security-process-buggy`, `swift-security-process-clean`)
- **Elixir**: `elixir.security.command` (cases: `elixir-security-command-buggy`, `elixir-security-command-clean`)
- **Bash**: `bash.security.eval_variable`, `bash.security.curl_pipe_bash` (cases: `bash-buggy`, `bash-clean`)
- **PHP**: `php.security.command-injection`, `php.security.dynamic-code` (cases: `php-buggy`, `php-clean`)

**Planned:** JS / TS, Go, C / C++, Ruby, C#

### Constant-Time Secret Comparison (`ct_compare`)
Timing-attack vulnerable equality checks on HMAC, tokens, or hashes

**Implemented:**
- **JS / TS**: `js.security.constant-time-compare` (cases: `js-typescript-constant-time-compare-buggy`, `js-typescript-constant-time-compare-clean`)
- **Python**: `py.security.constant-time-compare` (cases: `python-constant-time-compare-buggy`, `python-constant-time-compare-clean`, `python-public-checksum-compare-buggy`, `python-public-checksum-compare-clean`)
- **Go**: `golang.security.constant_time_compare` (cases: `golang-constant-time-compare-buggy`, `golang-constant-time-compare-clean`)
- **Rust**: `rust.security.constant_time_compare` (cases: `rust-constant-time-compare-buggy`, `rust-constant-time-compare-clean`)

**Planned:** Java, Kotlin, C / C++, Ruby, Swift, C#, Elixir, Bash, PHP

### Credentialed Wildcard CORS (`cors`)
Insecure Access-Control-Allow-Origin: * combined with credentials: true

**Implemented:**
- **JS / TS**: `js.security.cors` (cases: `js-typescript-cors-credentials-buggy`, `js-typescript-cors-credentials-clean`)
- **Python**: `py.security.cors` (cases: `python-cors-misconfig-buggy`, `python-cors-misconfig-clean`)
- **Go**: `golang.security.cors` (cases: `golang-cors-credentials-buggy`, `golang-cors-credentials-clean`)
- **Rust**: `rust.security.cors` (cases: `rust-cors-credentials-buggy`, `rust-cors-credentials-clean`)

**Planned:** Java, Kotlin, Ruby, Swift, C#, Elixir, PHP

**N/A:** C / C++, Bash

### Deep Guard Correlation (`deep_guard`)
Multi-signal guard and null-check correlation before access

**Implemented:**
- **JS / TS**: `js.deep-guard` (cases: `js-core-buggy`, `js-deep-guard-membership-clean`)

**Planned:** Python, Go, Rust, Java, Kotlin, C / C++, Ruby, Swift, C#, Elixir, PHP

**N/A:** Bash

### Disabled TLS Verification (`tls_verification`)
TLS certificate verification disabled in HTTP clients / SSL contexts

**Implemented:**
- **JS / TS**: `js.security.tls-verification` (cases: `js-typescript-tls-verification-buggy`, `js-typescript-tls-verification-clean`)
- **Python**: `py.security.tls-verification` (cases: `python-tls-verification-buggy`, `python-tls-verification-clean`)
- **Go**: `golang.security.tls_verification` (cases: `golang-tls-verification-buggy`, `golang-tls-verification-clean`)
- **Rust**: `rust.security.tls_verification` (cases: `rust-tls-verification-buggy`, `rust-tls-verification-clean`)

**Planned:** Java, Kotlin, C / C++, Ruby, Swift, C#, Elixir, Bash, PHP

### HTTP Response Header Injection (`header_injection`)
CRLF injection / response header splitting from unvalidated input

**Implemented:**
- **JS / TS**: `js.security.header-injection` (cases: `js-typescript-header-injection-buggy`, `js-typescript-header-injection-clean`)
- **Python**: `py.security.header-injection` (cases: `python-header-injection-buggy`, `python-header-injection-clean`)
- **Go**: `golang.security.header_injection` (cases: `golang-header-injection-buggy`, `golang-header-injection-clean`)
- **Rust**: `rust.security.header_injection` (cases: `rust-header-injection-buggy`, `rust-header-injection-clean`)
- **Java**: `java.security.header_injection` (cases: `java-header-injection-buggy`, `java-header-injection-clean`)
- **Kotlin**: `kotlin.security.header_injection` (cases: `kotlin-header-injection-buggy`, `kotlin-header-injection-clean`)
- **C / C++**: `cpp.security.header_injection` (cases: `cpp-header-injection-buggy`, `cpp-header-injection-clean`)
- **Ruby**: `ruby.security.header_injection` (cases: `ruby-header-injection-buggy`, `ruby-header-injection-clean`)
- **Swift**: `swift.security.header_injection` (cases: `swift-header-injection-buggy`, `swift-header-injection-clean`)
- **C#**: `csharp.security.header_injection` (cases: `csharp-header-injection-buggy`, `csharp-header-injection-clean`)
- **Elixir**: `elixir.security.header_injection` (cases: `elixir-header-injection-buggy`, `elixir-header-injection-clean`)

**Planned:** PHP

**N/A:** Bash

### Hardcoded Secrets & Default Fallbacks (`secrets`)
Committed API keys, JWT secrets, or insecure hardcoded fallback credentials

**Implemented:**
- **JS / TS**: `js.security.hardcoded-secrets` (cases: `js-typescript-hardcoded-secrets-buggy`, `js-typescript-hardcoded-secrets-clean`, `js-error-code-constants-buggy`, `js-error-code-constants-clean`)
- **Python**: `py.security.hardcoded-secrets` (cases: `python-hardcoded-secrets-buggy`, `python-hardcoded-secrets-clean`)
- **Go**: `golang.security.hardcoded_secrets` (cases: `golang-hardcoded-secrets-buggy`, `golang-hardcoded-secrets-clean`)
- **Rust**: `rust.security.hardcoded_secrets` (cases: `rust-hardcoded-secrets-buggy`, `rust-hardcoded-secrets-clean`)
- **Elixir**: `elixir.security.hardcoded_secrets` (cases: `elixir-hardcoded-secrets-buggy`, `elixir-hardcoded-secrets-clean`)

**Planned:** Java, Kotlin, C / C++, Ruby, Swift, C#, Bash, PHP

### Insecure Cookie Flags (`cookies`)
Missing HttpOnly, Secure, or SameSite protection flags on session cookies

**Implemented:**
- **JS / TS**: `js.security.cookie` (cases: `js-typescript-cookie-security-buggy`, `js-typescript-cookie-security-clean`)
- **Python**: `py.security.cookie` (cases: `python-cookie-security-buggy`, `python-cookie-security-clean`)
- **Go**: `golang.security.cookie` (cases: `golang-cookie-security-buggy`, `golang-cookie-security-clean`)

**Planned:** Rust, Java, Kotlin, Ruby, Swift, C#, Elixir, PHP

**N/A:** C / C++, Bash

### Insecure Security Randomness (`security_randomness`)
Non-cryptographic PRNG used for security tokens, salts, or passwords

**Implemented:**
- **JS / TS**: `js.security.randomness` (cases: `js-typescript-random-security-buggy`, `js-typescript-random-security-clean`)
- **Python**: `py.security.randomness` (cases: `python-random-security-buggy`, `python-random-security-clean`)
- **Go**: `golang.security.randomness` (cases: `golang-random-security-buggy`, `golang-random-security-clean`)
- **Rust**: `rust.security.randomness` (cases: `rust-security-randomness-buggy`, `rust-security-randomness-clean`)
- **Java**: `java.security.randomness` (cases: `java-random-security-buggy`, `java-random-security-clean`)
- **Kotlin**: `kotlin.security.randomness` (cases: `kotlin-random-security-buggy`, `kotlin-random-security-clean`)
- **C / C++**: `cpp.security.randomness` (cases: `cpp-security-randomness-buggy`, `cpp-security-randomness-clean`)
- **Ruby**: `ruby.security.randomness` (cases: `ruby-security-randomness-buggy`, `ruby-security-randomness-clean`)
- **Swift**: `swift.security.randomness` (cases: `swift-security-randomness-buggy`, `swift-security-randomness-clean`)
- **C#**: `csharp.security.randomness` (cases: `csharp-random-security-buggy`, `csharp-random-security-clean`)
- **Elixir**: `elixir.security.randomness` (cases: `elixir-security-randomness-buggy`, `elixir-security-randomness-clean`)

**Planned:** Bash, PHP

### JWT Verification Bypass (`jwt`)
Unverified or algorithm-none signature checks on JSON Web Tokens

**Implemented:**
- **JS / TS**: `js.security.jwt` (cases: `js-typescript-jwt-verification-buggy`, `js-typescript-jwt-verification-clean`)
- **Python**: `py.security.jwt` (cases: `python-jwt-verification-buggy`, `python-jwt-verification-clean`)
- **Go**: `golang.security.jwt` (cases: `golang-jwt-verification-buggy`, `golang-jwt-verification-clean`)
- **Rust**: `rust.security.jwt` (cases: `rust-jwt-verification-buggy`, `rust-jwt-verification-clean`)

**Planned:** Java, Kotlin, C / C++, Ruby, Swift, C#, Elixir, PHP

**N/A:** Bash

### Open Redirect (`open_redirect`)
Unvalidated redirect targets derived from user request input

**Implemented:**
- **JS / TS**: `js.security.open-redirect` (cases: `js-typescript-open-redirect-buggy`, `js-typescript-open-redirect-clean`)
- **Python**: `py.security.open-redirect` (cases: `python-open-redirect-buggy`, `python-open-redirect-clean`)
- **Go**: `golang.security.open_redirect` (cases: `golang-open-redirect-buggy`, `golang-open-redirect-clean`)
- **Rust**: `rust.security.open_redirect` (cases: `rust-open-redirect-buggy`, `rust-open-redirect-clean`)
- **Java**: `java.security.open_redirect` (cases: `java-open-redirect-buggy`, `java-open-redirect-clean`)
- **Kotlin**: `kotlin.security.open_redirect` (cases: `kotlin-open-redirect-buggy`, `kotlin-open-redirect-clean`)
- **C / C++**: `cpp.security.open_redirect` (cases: `cpp-open-redirect-buggy`, `cpp-open-redirect-clean`)
- **Ruby**: `ruby.security.open_redirect` (cases: `ruby-open-redirect-buggy`, `ruby-open-redirect-clean`)
- **Swift**: `swift.security.open_redirect` (cases: `swift-open-redirect-buggy`, `swift-open-redirect-clean`)
- **C#**: `csharp.security.open_redirect` (cases: `csharp-open-redirect-buggy`, `csharp-open-redirect-clean`)
- **Elixir**: `elixir.security.open_redirect` (cases: `elixir-open-redirect-buggy`, `elixir-open-redirect-clean`)

**Planned:** PHP

**N/A:** Bash

### Path Traversal (`path_traversal`)
Arbitrary file read or write via unvalidated directory path parameters

**Implemented:**
- **JS / TS**: `js.security.path-traversal` (cases: `js-typescript-path-traversal-buggy`, `js-typescript-path-traversal-clean`)
- **Python**: `py.security.path-traversal` (cases: `python-path-traversal-buggy`, `python-path-traversal-clean`)
- **Go**: `golang.security.path_traversal` (cases: `golang-request-path-traversal-buggy`, `golang-request-path-traversal-clean`)
- **Java**: `java.security.path_traversal` (cases: `java-request-path-traversal-buggy`, `java-request-path-traversal-clean`)
- **Kotlin**: `kotlin.security.path_traversal` (cases: `kotlin-request-path-traversal-buggy`, `kotlin-request-path-traversal-clean`)
- **C / C++**: `cpp.security.path_traversal` (cases: `cpp-request-path-traversal-buggy`, `cpp-request-path-traversal-clean`)
- **Ruby**: `ruby.security.path_traversal` (cases: `ruby-path-traversal-buggy`, `ruby-path-traversal-clean`)
- **Swift**: `swift.security.path_traversal` (cases: `swift-request-path-traversal-buggy`, `swift-request-path-traversal-clean`)
- **C#**: `csharp.security.path_traversal` (cases: `csharp-request-path-traversal-buggy`, `csharp-request-path-traversal-clean`)
- **Elixir**: `elixir.security.path_traversal` (cases: `elixir-request-path-traversal-buggy`, `elixir-request-path-traversal-clean`)
- **PHP**: `php.security.dynamic-include` (cases: `php-buggy`, `php-clean`)

**Planned:** Rust, Bash

### PostgreSQL Function Privileges (`function_privileges`)
Selected migration SECURITY DEFINER search-path and PUBLIC EXECUTE exposure; function bodies and external catalog state are outside the analysis.

**Implemented:**
- **sql**: `sql.security.definer-search-path`, `sql.security.definer-public-execute` (cases: `sql-definer-buggy`, `sql-definer-clean`)

### Resource Lifecycle & Cleanup (`resource_lifecycle`)
Leak detection for unclosed handles, connections, timers, and streams

**Implemented:**
- **JS / TS**: `js.resource.lifecycle` (cases: `js-typescript-async-timer-buggy`, `js-typescript-async-timer-clean`)
- **Python**: `py.resource.lifecycle` (cases: `python-resource-lifecycle`, `python-clean`)
- **Go**: `golang.resource.lifecycle` (cases: `go-resource-lifecycle`, `golang-clean`)
- **Rust**: `rust.resource.lifecycle` (cases: `rust-resource-lifecycle`, `rust-clean`)
- **Java**: `java.resource.lifecycle` (cases: `java-resource-lifecycle`, `java-clean`)
- **C / C++**: `cpp.resource.lifecycle` (cases: `cpp-resource-lifecycle`, `cpp-clean`)
- **Ruby**: `ruby.resource.lifecycle` (cases: `ruby-resource-lifecycle`, `ruby-clean`)
- **C#**: `csharp.resource.lifecycle` (cases: `csharp-resource-lifecycle-buggy`, `csharp-resource-lifecycle-clean`)

**Planned:** Kotlin, Swift, Elixir, Bash, PHP

### SQL Injection (`sql_injection`)
Dynamic string concatenation in SQL database queries

**Implemented:**
- **JS / TS**: `js.security.sql` (cases: `js-typescript-sql-injection-buggy`, `js-typescript-sql-injection-clean`)
- **Python**: `py.security.sql` (cases: `python-sql-injection-buggy`, `python-sql-injection-clean`)
- **Rust**: `rust.security.sql` (cases: `rust-sql-injection-buggy`, `rust-sql-injection-clean`)
- **C#**: `cs.security.sql-injection` (cases: `csharp-dapper-buggy`, `csharp-dapper-clean`)
- **Elixir**: `ex.security.sql-interpolation` (cases: `elixir-callback-sql-buggy`, `elixir-callback-sql-clean`)
- **PHP**: `php.security.sql-injection` (cases: `php-buggy`, `php-clean`)

**Planned:** Go, Java, Kotlin, C / C++, Ruby, Swift

**N/A:** Bash

### Server-Side Request Forgery (SSRF) (`ssrf`)
Outbound HTTP requests constructed with untrusted user input

**Implemented:**
- **JS / TS**: `js.security.ssrf` (cases: `js-typescript-ssrf-fetch-buggy`, `js-typescript-ssrf-fetch-clean`)
- **Python**: `py.security.ssrf` (cases: `python-ssrf-buggy`, `python-ssrf-clean`)
- **Go**: `golang.security.ssrf` (cases: `golang-ssrf-buggy`, `golang-ssrf-clean`)
- **Rust**: `rust.security.ssrf` (cases: `rust-ssrf-buggy`, `rust-ssrf-clean`)
- **Java**: `java.security.ssrf` (cases: `java-ssrf-buggy`, `java-ssrf-clean`)
- **Kotlin**: `kotlin.security.ssrf` (cases: `kotlin-ssrf-buggy`, `kotlin-ssrf-clean`)
- **C / C++**: `cpp.security.ssrf` (cases: `cpp-ssrf-buggy`, `cpp-ssrf-clean`)
- **Ruby**: `ruby.security.ssrf` (cases: `ruby-ssrf-buggy`, `ruby-ssrf-clean`)
- **Swift**: `swift.security.ssrf` (cases: `swift-ssrf-buggy`, `swift-ssrf-clean`)
- **C#**: `csharp.security.ssrf` (cases: `csharp-ssrf-buggy`, `csharp-ssrf-clean`)
- **Elixir**: `elixir.security.ssrf` (cases: `elixir-ssrf-buggy`, `elixir-ssrf-clean`)

**Planned:** Bash, PHP

### Taint & Dataflow Engine (`taint`)
Source-to-sink dataflow propagation from user input to dangerous sinks

**Implemented:**
- **JS / TS**: `js.security.taint` (cases: `js-taint-buggy`, `js-taint-clean`)
- **Python**: `py.security.taint` (cases: `python-taint-buggy`, `python-taint-clean`)
- **Go**: `golang.security.taint` (cases: `golang-taint-buggy`, `golang-taint-clean`)
- **Java**: `java.taint.open_redirect`, `java.taint.path_traversal` (cases: `java-open-redirect-buggy`, `java-open-redirect-clean`)
- **Kotlin**: `kotlin.taint.open_redirect`, `kotlin.taint.path_traversal` (cases: `kotlin-open-redirect-buggy`, `kotlin-open-redirect-clean`)
- **C / C++**: `cpp.taint.open_redirect`, `cpp.taint.path_traversal` (cases: `cpp-open-redirect-buggy`, `cpp-open-redirect-clean`)
- **Ruby**: `ruby.security.taint` (cases: `ruby-taint-buggy`, `ruby-taint-clean`)
- **Swift**: `swift.taint.open_redirect`, `swift.taint.path_traversal` (cases: `swift-open-redirect-buggy`, `swift-open-redirect-clean`)
- **C#**: `csharp.taint.open_redirect`, `csharp.taint.path_traversal` (cases: `csharp-open-redirect-buggy`, `csharp-open-redirect-clean`)
- **Elixir**: `elixir.taint.open_redirect`, `elixir.taint.request_path_traversal` (cases: `elixir-open-redirect-buggy`, `elixir-open-redirect-clean`)
- **PHP**: `php.security.xss` (cases: `php-buggy`, `php-clean`)

**Planned:** Rust, Bash

### Type Narrowing & Safe Casting (`type_narrowing`)
Optional and nullability type narrowing analysis

**Implemented:**
- **JS / TS**: `js.typeof-invalid-string` (cases: `js-typeof-invalid-string-literals-detected`, `js-module-clean`)
- **Rust**: `rust.type_narrowing` (cases: `rust-type-narrowing-buggy`, `rust-type-narrowing-clean`)
- **Java**: `java.narrowing.negative_guard` (cases: `java-buggy`, `java-clean`)
- **Kotlin**: `kotlin.type_narrowing` (cases: `kotlin-type-narrowing-buggy`, `kotlin-type-narrowing-clean`)
- **Swift**: `swift.type_narrowing` (cases: `swift-type-narrowing-buggy`, `swift-type-narrowing-clean`)
- **C#**: `csharp.type_narrowing` (cases: `csharp-type-narrowing-buggy`, `csharp-type-narrowing-clean`)

**Planned:** Python, Go, C / C++, Ruby, Elixir, PHP

**N/A:** Bash

### Unsafe Deserialization (`deserialization`)
Deserialization of arbitrary code (pickle, YAML, marshal, etc.)

**Implemented:**
- **Python**: `py.security.deserialization`, `py.security.yaml-unsafe-loader`, `py.security.yaml-loader-unresolved` (cases: `python-unsafe-deserialization-buggy`, `python-unsafe-deserialization-clean`, `python-yaml-loader-buggy`, `python-yaml-loader-clean`)
- **Ruby**: `ruby.security.serialization` (cases: `ruby-serialization-buggy`, `ruby-serialization-clean`)
- **PHP**: `php.security.unsafe-deserialization` (cases: `php-buggy`, `php-clean`)

**Planned:** JS / TS, Go, Rust, Java, Kotlin, C / C++, Swift, C#, Elixir

**N/A:** Bash

