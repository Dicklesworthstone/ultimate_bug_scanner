# 🧭 UBS Detector Coverage Matrix

> Generated automatically from [`detectors.yml`](../detectors.yml) by `scripts/generate_coverage_matrix.py`.
> Hand-maintained registry; validated by `test-suite/quality/rule_quality_harness.py`.

## Summary

- **Detector Families**: 20
- **Languages Supported**: 10
- **Implemented Cells**: 118 (59.0%)
- **Planned Cells**: 80 (40.0%)
- **N/A Cells**: 2 (1.0%)

## Matrix

Legend:
- **✓** Implemented (with verified buggy and clean regression fixture pairs)
- **○** Planned / In Progress
- **—** Not Applicable for language runtime/ecosystem

| Family | JS / TS | Python | Go | Rust | Java | C / C++ | Ruby | Swift | C# | Elixir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Archive Extraction (Zip Slip) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Async & Concurrency Hazards | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ✓ | ○ |
| Command Injection | ○ | ✓ | ○ | ✓ | ✓ | ○ | ○ | ✓ | ○ | ○ |
| Constant-Time Secret Comparison | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ |
| Credentialed Wildcard CORS | ✓ | ✓ | ✓ | ✓ | ○ | — | ○ | ○ | ○ | ○ |
| Deep Guard Correlation | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| Disabled TLS Verification | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ |
| HTTP Response Header Injection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Hardcoded Secrets & Default Fallbacks | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ✓ |
| Insecure Cookie Flags | ✓ | ✓ | ✓ | ○ | ○ | — | ○ | ○ | ○ | ○ |
| Insecure Security Randomness | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| JWT Verification Bypass | ✓ | ✓ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ |
| Open Redirect | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Path Traversal | ✓ | ✓ | ✓ | ○ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Resource Lifecycle & Cleanup | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ | ✓ | ○ |
| SQL Injection | ✓ | ✓ | ○ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ |
| Server-Side Request Forgery (SSRF) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Taint & Dataflow Engine | ✓ | ✓ | ✓ | ○ | ○ | ○ | ✓ | ○ | ○ | ○ |
| Type Narrowing & Safe Casting | ✓ | ○ | ○ | ✓ | ✓ | ○ | ○ | ✓ | ✓ | ○ |
| Unsafe Deserialization | ○ | ✓ | ○ | ○ | ○ | ○ | ✓ | ○ | ○ | ○ |

## Family Details

### Archive Extraction (Zip Slip) (`archive_extraction`)
Path traversal during archive decompression / tar / zip extraction

**Implemented:**
- **JS / TS**: `js.security.archive-extraction` (cases: `js-typescript-archive-extraction-buggy`, `js-typescript-archive-extraction-clean`)
- **Python**: `py.security.archive-extraction` (cases: `python-archive-extraction-buggy`, `python-archive-extraction-clean`)
- **Go**: `golang.security.archive_extraction` (cases: `golang-archive-extraction-buggy`, `golang-archive-extraction-clean`)
- **Rust**: `rust.security.archive_extraction` (cases: `rust-archive-extraction-buggy`, `rust-archive-extraction-clean`)
- **Java**: `java.security.archive_extraction`, `kotlin.security.archive_extraction` (cases: `java-archive-extraction-buggy`, `java-archive-extraction-clean`)
- **C / C++**: `cpp.security.archive_extraction` (cases: `cpp-archive-extraction-buggy`, `cpp-archive-extraction-clean`)
- **Ruby**: `ruby.security.archive_extraction` (cases: `ruby-archive-extraction-buggy`, `ruby-archive-extraction-clean`)
- **Swift**: `swift.security.archive_extraction` (cases: `swift-archive-extraction-buggy`, `swift-archive-extraction-clean`)
- **C#**: `csharp.security.archive_extraction` (cases: `csharp-archive-extraction-buggy`, `csharp-archive-extraction-clean`)
- **Elixir**: `elixir.security.archive_extraction` (cases: `elixir-archive-extraction-buggy`, `elixir-archive-extraction-clean`)

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

**Planned:** Swift, Elixir

### Command Injection (`command_injection`)
Shell or OS command execution using untrusted string arguments

**Implemented:**
- **Python**: `py.security.command_injection` (cases: `python-command-injection-buggy`, `python-command-injection-clean`)
- **Rust**: `rust.security.shell_command` (cases: `rust-security-shell-command-buggy`, `rust-security-shell-command-clean`)
- **Java**: `kotlin.security.command` (cases: `kotlin-security-command-buggy`, `kotlin-security-command-clean`)
- **Swift**: `swift.security.process` (cases: `swift-security-process-buggy`, `swift-security-process-clean`)

**Planned:** JS / TS, Go, C / C++, Ruby, C#, Elixir

### Constant-Time Secret Comparison (`ct_compare`)
Timing-attack vulnerable equality checks on HMAC, tokens, or hashes

**Implemented:**
- **JS / TS**: `js.security.constant-time-compare` (cases: `js-typescript-constant-time-compare-buggy`, `js-typescript-constant-time-compare-clean`)
- **Python**: `py.security.constant-time-compare` (cases: `python-constant-time-compare-buggy`, `python-constant-time-compare-clean`)
- **Go**: `golang.security.constant_time_compare` (cases: `golang-constant-time-compare-buggy`, `golang-constant-time-compare-clean`)
- **Rust**: `rust.security.constant_time_compare` (cases: `rust-constant-time-compare-buggy`, `rust-constant-time-compare-clean`)

**Planned:** Java, C / C++, Ruby, Swift, C#, Elixir

### Credentialed Wildcard CORS (`cors`)
Insecure Access-Control-Allow-Origin: * combined with credentials: true

**Implemented:**
- **JS / TS**: `js.security.cors` (cases: `js-typescript-cors-credentials-buggy`, `js-typescript-cors-credentials-clean`)
- **Python**: `py.security.cors` (cases: `python-cors-misconfig-buggy`, `python-cors-misconfig-clean`)
- **Go**: `golang.security.cors` (cases: `golang-cors-credentials-buggy`, `golang-cors-credentials-clean`)
- **Rust**: `rust.security.cors` (cases: `rust-cors-credentials-buggy`, `rust-cors-credentials-clean`)

**Planned:** Java, Ruby, Swift, C#, Elixir

**N/A:** C / C++

### Deep Guard Correlation (`deep_guard`)
Multi-signal guard and null-check correlation before access

**Implemented:**
- **JS / TS**: `js.deep-guard` (cases: `js-core-buggy`, `js-deep-guard-membership-clean`)

**Planned:** Python, Go, Rust, Java, C / C++, Ruby, Swift, C#, Elixir

### Disabled TLS Verification (`tls_verification`)
TLS certificate verification disabled in HTTP clients / SSL contexts

**Implemented:**
- **JS / TS**: `js.security.tls-verification` (cases: `js-typescript-tls-verification-buggy`, `js-typescript-tls-verification-clean`)
- **Python**: `py.security.tls-verification` (cases: `python-tls-verification-buggy`, `python-tls-verification-clean`)
- **Go**: `golang.security.tls_verification` (cases: `golang-tls-verification-buggy`, `golang-tls-verification-clean`)
- **Rust**: `rust.security.tls_verification` (cases: `rust-tls-verification-buggy`, `rust-tls-verification-clean`)

**Planned:** Java, C / C++, Ruby, Swift, C#, Elixir

### HTTP Response Header Injection (`header_injection`)
CRLF injection / response header splitting from unvalidated input

**Implemented:**
- **JS / TS**: `js.security.header-injection` (cases: `js-typescript-header-injection-buggy`, `js-typescript-header-injection-clean`)
- **Python**: `py.security.header-injection` (cases: `python-header-injection-buggy`, `python-header-injection-clean`)
- **Go**: `golang.security.header_injection` (cases: `golang-header-injection-buggy`, `golang-header-injection-clean`)
- **Rust**: `rust.security.header_injection` (cases: `rust-header-injection-buggy`, `rust-header-injection-clean`)
- **Java**: `java.security.header_injection`, `kotlin.security.header_injection` (cases: `java-header-injection-buggy`, `java-header-injection-clean`)
- **C / C++**: `cpp.security.header_injection` (cases: `cpp-header-injection-buggy`, `cpp-header-injection-clean`)
- **Ruby**: `ruby.security.header_injection` (cases: `ruby-header-injection-buggy`, `ruby-header-injection-clean`)
- **Swift**: `swift.security.header_injection` (cases: `swift-header-injection-buggy`, `swift-header-injection-clean`)
- **C#**: `csharp.security.header_injection` (cases: `csharp-header-injection-buggy`, `csharp-header-injection-clean`)
- **Elixir**: `elixir.security.header_injection` (cases: `elixir-header-injection-buggy`, `elixir-header-injection-clean`)

### Hardcoded Secrets & Default Fallbacks (`secrets`)
Committed API keys, JWT secrets, or insecure hardcoded fallback credentials

**Implemented:**
- **JS / TS**: `js.security.hardcoded-secrets` (cases: `js-typescript-hardcoded-secrets-buggy`, `js-typescript-hardcoded-secrets-clean`)
- **Python**: `py.security.hardcoded-secrets` (cases: `python-hardcoded-secrets-buggy`, `python-hardcoded-secrets-clean`)
- **Go**: `golang.security.hardcoded_secrets` (cases: `golang-hardcoded-secrets-buggy`, `golang-hardcoded-secrets-clean`)
- **Rust**: `rust.security.hardcoded_secrets` (cases: `rust-hardcoded-secrets-buggy`, `rust-hardcoded-secrets-clean`)
- **Elixir**: `elixir.security.hardcoded_secrets` (cases: `elixir-hardcoded-secrets-buggy`, `elixir-hardcoded-secrets-clean`)

**Planned:** Java, C / C++, Ruby, Swift, C#

### Insecure Cookie Flags (`cookies`)
Missing HttpOnly, Secure, or SameSite protection flags on session cookies

**Implemented:**
- **JS / TS**: `js.security.cookie` (cases: `js-typescript-cookie-security-buggy`, `js-typescript-cookie-security-clean`)
- **Python**: `py.security.cookie` (cases: `python-cookie-security-buggy`, `python-cookie-security-clean`)
- **Go**: `golang.security.cookie` (cases: `golang-cookie-security-buggy`, `golang-cookie-security-clean`)

**Planned:** Rust, Java, Ruby, Swift, C#, Elixir

**N/A:** C / C++

### Insecure Security Randomness (`security_randomness`)
Non-cryptographic PRNG used for security tokens, salts, or passwords

**Implemented:**
- **JS / TS**: `js.security.randomness` (cases: `js-typescript-random-security-buggy`, `js-typescript-random-security-clean`)
- **Python**: `py.security.randomness` (cases: `python-random-security-buggy`, `python-random-security-clean`)
- **Go**: `golang.security.randomness` (cases: `golang-random-security-buggy`, `golang-random-security-clean`)
- **Rust**: `rust.security.randomness` (cases: `rust-security-randomness-buggy`, `rust-security-randomness-clean`)
- **Java**: `java.security.randomness`, `kotlin.security.randomness` (cases: `java-random-security-buggy`, `java-random-security-clean`)
- **C / C++**: `cpp.security.randomness` (cases: `cpp-security-randomness-buggy`, `cpp-security-randomness-clean`)
- **Ruby**: `ruby.security.randomness` (cases: `ruby-security-randomness-buggy`, `ruby-security-randomness-clean`)
- **Swift**: `swift.security.randomness` (cases: `swift-security-randomness-buggy`, `swift-security-randomness-clean`)
- **C#**: `csharp.security.randomness` (cases: `csharp-random-security-buggy`, `csharp-random-security-clean`)
- **Elixir**: `elixir.security.randomness` (cases: `elixir-security-randomness-buggy`, `elixir-security-randomness-clean`)

### JWT Verification Bypass (`jwt`)
Unverified or algorithm-none signature checks on JSON Web Tokens

**Implemented:**
- **JS / TS**: `js.security.jwt` (cases: `js-typescript-jwt-verification-buggy`, `js-typescript-jwt-verification-clean`)
- **Python**: `py.security.jwt` (cases: `python-jwt-verification-buggy`, `python-jwt-verification-clean`)
- **Go**: `golang.security.jwt` (cases: `golang-jwt-verification-buggy`, `golang-jwt-verification-clean`)
- **Rust**: `rust.security.jwt` (cases: `rust-jwt-verification-buggy`, `rust-jwt-verification-clean`)

**Planned:** Java, C / C++, Ruby, Swift, C#, Elixir

### Open Redirect (`open_redirect`)
Unvalidated redirect targets derived from user request input

**Implemented:**
- **JS / TS**: `js.security.open-redirect` (cases: `js-typescript-open-redirect-buggy`, `js-typescript-open-redirect-clean`)
- **Python**: `py.security.open-redirect` (cases: `python-open-redirect-buggy`, `python-open-redirect-clean`)
- **Go**: `golang.security.open_redirect` (cases: `golang-open-redirect-buggy`, `golang-open-redirect-clean`)
- **Rust**: `rust.security.open_redirect` (cases: `rust-open-redirect-buggy`, `rust-open-redirect-clean`)
- **Java**: `java.security.open_redirect`, `kotlin.security.open_redirect` (cases: `java-open-redirect-buggy`, `java-open-redirect-clean`)
- **C / C++**: `cpp.security.open_redirect` (cases: `cpp-open-redirect-buggy`, `cpp-open-redirect-clean`)
- **Ruby**: `ruby.security.open_redirect` (cases: `ruby-open-redirect-buggy`, `ruby-open-redirect-clean`)
- **Swift**: `swift.security.open_redirect` (cases: `swift-open-redirect-buggy`, `swift-open-redirect-clean`)
- **C#**: `csharp.security.open_redirect` (cases: `csharp-open-redirect-buggy`, `csharp-open-redirect-clean`)
- **Elixir**: `elixir.security.open_redirect` (cases: `elixir-open-redirect-buggy`, `elixir-open-redirect-clean`)

### Path Traversal (`path_traversal`)
Arbitrary file read or write via unvalidated directory path parameters

**Implemented:**
- **JS / TS**: `js.security.path-traversal` (cases: `js-typescript-path-traversal-buggy`, `js-typescript-path-traversal-clean`)
- **Python**: `py.security.path-traversal` (cases: `python-path-traversal-buggy`, `python-path-traversal-clean`)
- **Go**: `golang.security.path_traversal` (cases: `golang-request-path-traversal-buggy`, `golang-request-path-traversal-clean`)
- **Java**: `java.security.path_traversal`, `kotlin.security.path_traversal` (cases: `java-request-path-traversal-buggy`, `java-request-path-traversal-clean`)
- **C / C++**: `cpp.security.path_traversal` (cases: `cpp-request-path-traversal-buggy`, `cpp-request-path-traversal-clean`)
- **Ruby**: `ruby.security.path_traversal` (cases: `ruby-path-traversal-buggy`, `ruby-path-traversal-clean`)
- **Swift**: `swift.security.path_traversal` (cases: `swift-request-path-traversal-buggy`, `swift-request-path-traversal-clean`)
- **C#**: `csharp.security.path_traversal` (cases: `csharp-request-path-traversal-buggy`, `csharp-request-path-traversal-clean`)
- **Elixir**: `elixir.security.path_traversal` (cases: `elixir-request-path-traversal-buggy`, `elixir-request-path-traversal-clean`)

**Planned:** Rust

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

**Planned:** Swift, Elixir

### SQL Injection (`sql_injection`)
Dynamic string concatenation in SQL database queries

**Implemented:**
- **JS / TS**: `js.security.sql` (cases: `js-typescript-sql-injection-buggy`, `js-typescript-sql-injection-clean`)
- **Python**: `py.security.sql` (cases: `python-sql-injection-buggy`, `python-sql-injection-clean`)
- **Rust**: `rust.security.sql` (cases: `rust-sql-injection-buggy`, `rust-sql-injection-clean`)

**Planned:** Go, Java, C / C++, Ruby, Swift, C#, Elixir

### Server-Side Request Forgery (SSRF) (`ssrf`)
Outbound HTTP requests constructed with untrusted user input

**Implemented:**
- **JS / TS**: `js.security.ssrf` (cases: `js-typescript-ssrf-fetch-buggy`, `js-typescript-ssrf-fetch-clean`)
- **Python**: `py.security.ssrf` (cases: `python-ssrf-buggy`, `python-ssrf-clean`)
- **Go**: `golang.security.ssrf` (cases: `golang-ssrf-buggy`, `golang-ssrf-clean`)
- **Rust**: `rust.security.ssrf` (cases: `rust-ssrf-buggy`, `rust-ssrf-clean`)
- **Java**: `java.security.ssrf`, `kotlin.security.ssrf` (cases: `java-ssrf-buggy`, `java-ssrf-clean`)
- **C / C++**: `cpp.security.ssrf` (cases: `cpp-ssrf-buggy`, `cpp-ssrf-clean`)
- **Ruby**: `ruby.security.ssrf` (cases: `ruby-ssrf-buggy`, `ruby-ssrf-clean`)
- **Swift**: `swift.security.ssrf` (cases: `swift-ssrf-buggy`, `swift-ssrf-clean`)
- **C#**: `csharp.security.ssrf` (cases: `csharp-ssrf-buggy`, `csharp-ssrf-clean`)
- **Elixir**: `elixir.security.ssrf` (cases: `elixir-ssrf-buggy`, `elixir-ssrf-clean`)

### Taint & Dataflow Engine (`taint`)
Source-to-sink dataflow propagation from user input to dangerous sinks

**Implemented:**
- **JS / TS**: `js.security.taint` (cases: `js-taint-buggy`, `js-taint-clean`)
- **Python**: `py.security.taint` (cases: `python-taint-buggy`, `python-taint-clean`)
- **Go**: `golang.security.taint` (cases: `golang-taint-buggy`, `golang-taint-clean`)
- **Ruby**: `ruby.security.taint` (cases: `ruby-taint-buggy`, `ruby-taint-clean`)

**Planned:** Rust, Java, C / C++, Swift, C#, Elixir

### Type Narrowing & Safe Casting (`type_narrowing`)
Optional and nullability type narrowing analysis

**Implemented:**
- **JS / TS**: `js.typeof-invalid-string` (cases: `js-typeof-invalid-string-literals-detected`, `js-module-clean`)
- **Rust**: `rust.type_narrowing` (cases: `rust-type-narrowing-buggy`, `rust-type-narrowing-clean`)
- **Java**: `kotlin.type_narrowing` (cases: `kotlin-type-narrowing-buggy`, `kotlin-type-narrowing-clean`)
- **Swift**: `swift.type_narrowing` (cases: `swift-type-narrowing-buggy`, `swift-type-narrowing-clean`)
- **C#**: `csharp.type_narrowing` (cases: `csharp-type-narrowing-buggy`, `csharp-type-narrowing-clean`)

**Planned:** Python, Go, C / C++, Ruby, Elixir

### Unsafe Deserialization (`deserialization`)
Deserialization of arbitrary code (pickle, YAML, marshal, etc.)

**Implemented:**
- **Python**: `py.security.deserialization` (cases: `python-unsafe-deserialization-buggy`, `python-unsafe-deserialization-clean`)
- **Ruby**: `ruby.security.serialization` (cases: `ruby-serialization-buggy`, `ruby-serialization-clean`)

**Planned:** JS / TS, Go, Rust, Java, C / C++, Swift, C#, Elixir

