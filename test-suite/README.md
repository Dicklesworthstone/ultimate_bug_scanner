# Ultimate Bug Scanner - Test Suite

This suite now spans **every language UBS supports**. JavaScript remains the template, but each directory (`python/`, `golang/`, `cpp/`, `rust/`, `java/`, `ruby/`) contains mirrored buggy/clean fixtures so we can regression-test the language modules with the same discipline.

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
├── python/                     # Python fixtures + manifest cases
├── golang/                     # Go fixtures + manifest cases
├── cpp/                        # C/C++ fixtures + manifest cases
├── rust/                       # Rust fixtures + manifest cases
├── java/                       # Java fixtures + manifest cases
├── ruby/                       # Ruby fixtures + manifest cases
└── README.md                   # This file
```

## Cross-language quick reference

| Language | Buggy path | Clean path | Highlights |
|----------|------------|------------|------------|
| JavaScript/TypeScript | `test-suite/buggy/`, `test-suite/js/buggy/` | `test-suite/clean/`, `test-suite/js/clean/` | 20 core files + framework + realistic + edge-case coverage |
| Python | `test-suite/python/buggy/` | `test-suite/python/clean/` | Async/security/resource fixtures + mutable defaults, shell injection |
| Go | `test-suite/golang/buggy/` | `test-suite/golang/clean/` | Concurrency, HTTP safety, context leaks, ticker/perf issues |
| C/C++ | `test-suite/cpp/buggy/` | `test-suite/cpp/clean/` | RAII vs leaks, unsafe `strcpy`, overflow/memory hygiene |
| Rust | `test-suite/rust/buggy/` | `test-suite/rust/clean/` | `unwrap()` panics, async tasks, command injection, float precision |
| Java | `test-suite/java/buggy/` | `test-suite/java/clean/` | Executor leaks, blocking I/O, SQL and command injection |
| Ruby | `test-suite/ruby/buggy/` | `test-suite/ruby/clean/` | eval/YAML problems, thread leaks, file cleanup |

Every directory has its own README summarizing the files and the scanner categories they exercise (security, async error coverage, resource lifecycle, math/precision, etc.).

## 🧪 Running Tests

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

- **Total Buggy Files:** 29 files
- **Total Expected Bugs:** 460+ issues across all categories
- **Total Clean Files:** 10 files
- **Coverage:** Security, Performance, Concurrency, Edge Cases, Framework Patterns

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
(`test-suite/manifest.json`) now includes **every language** (JS core + frameworks, Python, Go, C++, Rust, Java, Ruby, and the JS edge-case directories).

```bash
cd test-suite
./run_manifest.py                  # run every enabled case
./run_manifest.py --list           # inspect case ids / skip status
./run_manifest.py --case cpp-buggy # run one case
./run_all.sh --fail-fast           # convenience wrapper around run_manifest.py
```

Key behavior:

- Each case specifies the path to scan, additional UBS arguments (e.g.
  `--only=js`, `--fail-on-warning`), and expectations for `critical/warning/info`
  counts.
- Runs use `--format=json` for reliable parsing; derived exit status is computed
  from the severity totals so we can still ensure “buggy” cases fail even when
  UBS returns `0` in JSON mode.
- Artifacts for every case (stdout, stderr, parsed summary) land under
  `test-suite/artifacts/<case-id>/` to speed up debugging scanner regressions.
- Disabled cases are recorded with skip reasons so we can track the backlog
  explicitly. See `test-suite/TODO.md` for the full punch list.

`run_all.sh` simply forwards to `run_manifest.py`, so CI and humans share the
same entry point.
