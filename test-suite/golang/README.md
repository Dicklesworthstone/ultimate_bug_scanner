# Go UBS Samples

| File | Category | Expected findings |
|------|----------|-------------------|
| `buggy/buggy_http.go` | HTTP client/server safety | missing timeouts, TLS defaults |
| `buggy/buggy_concurrency.go` | Concurrency handling | goroutines ignoring errors, WaitGroup misuse |
| `buggy/resource_lifecycle.go` | Resource lifecycle | context leaks, missing cancel() |
| `buggy/security_sql.go` | SQL/command injection + http.Client default | string concatenated SQL, exec.Command("sh -c"), no timeout |
| `buggy/taint_analysis.go` | Request taint analysis | request/form/header values reaching XSS, SQL execution/query-builder strings, and command sinks |
| `clean/taint_analysis.go` | Request taint analysis | escaped HTML, parameterized SQL/query-builder calls, and cleaned command args |
| `security/path_traversal_buggy.go` | Request path traversal | request/query/path/upload filenames reaching `os.*` and `http.ServeFile` sinks |
| `security/path_traversal_clean.go` | Request path traversal | `filepath.Rel` containment and `filepath.Base` filename sanitization before file sinks |
| `security/header_injection_buggy.go` | Response header injection | request query/form/header/framework values reaching response headers without CR/LF validation |
| `security/header_injection_clean.go` | Response header injection | CR/LF stripping, `mime.FormatMediaType`, and reject-on-newline guards before response headers |
| `security/open_redirect_buggy.go` | Open redirect security | request query/header/framework redirect targets reaching `http.Redirect`, framework redirects, and `Location` headers |
| `security/open_redirect_clean.go` | Open redirect security | redirect targets routed through same-origin/allow-list validation helpers before redirect sinks |
| `security/tls_verification_buggy.go` | TLS verification security | `tls.Config{InsecureSkipVerify: true}` directly or via true constants reaching HTTP/TLS clients |
| `security/tls_verification_clean.go` | TLS verification security | TLS clients using normal verification with `MinVersion`, `ServerName`, and root CAs |
| `security/archive_extraction_buggy.go` | Archive extraction security | tar/zip entry names written with `filepath.Join` without containment checks |
| `security/archive_extraction_clean.go` | Archive extraction security | `filepath.Rel`/absolute-path validation before tar/zip writes |
| `security/request_body_limit_buggy.go` | Request body size limits | unbounded `io.ReadAll`, `ioutil.ReadAll`, `json.NewDecoder(r.Body).Decode`, and raw body alias paths |
| `security/request_body_limit_clean.go` | Request body size limits | `http.MaxBytesReader`/`io.LimitReader` before direct or aliased body reads and JSON decode |
| `buggy/performance.go` | Timers + defer in loops | `time.Tick` leaks, defer inside loop |
| Clean counterparts | Defensive examples | context.WithTimeout, prepared statements, ticker.Stop |

```bash
ubs --only=golang --fail-on-warning test-suite/golang/buggy
ubs --only=golang test-suite/golang/clean
```
