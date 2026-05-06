# Changelog

All notable changes to **Ultimate Bug Scanner (UBS)** are documented in this file, organized by capability rather than raw diff order.

Versions marked **[Release]** have a corresponding [GitHub Release](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases) with downloadable artifacts (installer, checksums, SBOM, Homebrew formula). Versions marked **[Tag]** are git-only tags without published release assets.

Repository: <https://github.com/Dicklesworthstone/ultimate_bug_scanner>

---

Scope window: full project history remains documented below; this update reconstructs `v5.1.2...v5.2.75` in detail and updates the open comparison target to `v5.2.75`.

## Version Timeline

| Marker | Date | Release state | Evidence |
|--------|------|---------------|----------|
| `v5.2.75` | 2026-05-06 | Latest git tag, tag-only | [`v5.2.75` tag](https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v5.2.75) |
| `v5.2.61` | 2026-05-06 | Latest GitHub Release observed | [`v5.2.61` release](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.2.61) |
| `v5.1.2` | 2026-04-25 | Previous changelog baseline release | [`v5.1.2` release](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.1.2) |
| `v5.0.7` | 2026-03-25 | Prior detailed release section | [`v5.0.7` release](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.7) |
| `v4.6.0` | 2025-11-17 | Early public tag | [`v4.6.0` tag](https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v4.6.0) |

## [v5.2.75] - 2026-05-06 **[Tag]**

> Current reconstruction point. This section covers the post-`v5.1.2` expansion train (`v5.1.3...v5.2.75`): 197 non-merge commits, 176 `v5.1.x`/`v5.2.x` tags, GitHub Release assets through `v5.2.61`, and git-only tags from `v5.2.62` through `v5.2.75`.

### Release and Tag State

- **Latest git tag:** [`v5.2.75`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v5.2.75), tagged at commit [`6cb0180`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6cb0180).
- **Latest GitHub Release:** [`v5.2.61`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.2.61), published 2026-05-06 and marked latest in GitHub release metadata.
- **Tag-only window:** `v5.2.62` through `v5.2.75` are git tags without corresponding GitHub Release assets at the time this changelog was reconstructed.
- **Research memo:** detailed evidence, tracker workstreams, and coverage ledger are in [`docs/reports/CHANGELOG_RESEARCH.md`](docs/reports/CHANGELOG_RESEARCH.md).

### Version Spine Since `v5.1.2`

| Version range | Dates | Status | Capability wave | Inspect first |
|---------------|-------|--------|-----------------|---------------|
| `v5.1.3` - `v5.1.11` | 2026-04-26 to 2026-04-27 | Release/tag mixed | Rust safety expansion plus runner checksum/fetch hardening after the `v5.1.2` module-download regression | [`fb7a68f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fb7a68f), [`4ef6c42`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4ef6c42), [`60f9c23`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/60f9c23) |
| `v5.1.12` - `v5.1.32` | 2026-04-27 to 2026-04-28 | Release/tag mixed | JavaScript/TypeScript browser, async, and trust-boundary rules | [`df1a38f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/df1a38f), [`8a8e9b5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8a8e9b5), [`144a80c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/144a80c) |
| `v5.1.33` - `v5.1.42` | 2026-04-28 | Release/tag mixed | Archive-extraction path traversal across Python, Go, Java, Ruby, C#, Swift, C++, Elixir, and Kotlin | [`75ea78c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/75ea78c), [`008f1ef`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/008f1ef), [`0cae370`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0cae370) |
| `v5.1.43` - `v5.1.75` | 2026-04-28 to 2026-04-29 | Release/tag mixed | Python web-security pack: Flask/Django/FastAPI sinks, deserialization, cookies, uploads, header/open-redirect/SSRF families | [`7bbee86`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7bbee86), [`1f3d436`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1f3d436), [`906edf6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/906edf6) |
| `v5.1.76` - `v5.1.87` | 2026-04-29 to 2026-04-30 | Release/tag mixed | JavaScript/TypeScript security hardening: JWT bypass, CORS, cookies, randomness, TLS, SSRF, response headers, path traversal | [`2c81897`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2c81897), [`ed9fcbd`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ed9fcbd), [`f2d7477`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f2d7477) |
| `v5.1.88` - `v5.2.20` | 2026-04-30 to 2026-05-02 | Release/tag mixed | Cross-language path traversal and SSRF: headers, route values, servlet/Rack/Ktor/ASP.NET/Swift/Elixir sources | [`39e40d7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/39e40d7), [`5310071`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5310071), [`20e3fe7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/20e3fe7) |
| `v5.2.21` - `v5.2.38` | 2026-05-02 to 2026-05-03 | Release/tag mixed | Open redirect and response header injection coverage across all supported language families | [`968fb3a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/968fb3a), [`b78839c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b78839c), [`c554c3e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c554c3e) |
| `v5.2.39` - `v5.2.48` | 2026-05-03 to 2026-05-04 | Release/tag mixed | Security-sensitive randomness and hardcoded-secret detectors across Elixir, Ruby, Java/Kotlin, C#, Swift, C++, JS/TS, Rust, and Go | [`2911f58`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2911f58), [`41c507b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/41c507b), [`c39b4b2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c39b4b2) |
| `v5.2.49` - `v5.2.57` | 2026-05-04 to 2026-05-05 | Release/tag mixed | Secret comparison, hardcoded-secret environment fallbacks, credentialed CORS, and insecure cookie expansion | [`7ad487e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7ad487e), [`61639f3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/61639f3), [`872ddeb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/872ddeb) |
| `v5.2.58` - `v5.2.67` | 2026-05-05 to 2026-05-06 | Release/tag mixed through `v5.2.61`, then tag-only | JWT verification and claim-binding, prototype pollution, reverse-proxy SSRF, and credentialed CORS follow-up | [`52be770`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/52be770), [`d23de5d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d23de5d), [`f3c36ec`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f3c36ec) |
| `v5.2.68` - `v5.2.75` | 2026-05-06 | **Tag-only** | Request-derived SQL injection taint and route parameter propagation for Rust, Go, and TypeScript | [`039e94e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/039e94e), [`3fc8537`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3fc8537), [`6cb0180`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6cb0180) |

### Representative commits

- **Latest tag:** [`6cb0180`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6cb0180) tracks destructured TypeScript route params as SQL taint sources.
- **Latest GitHub Release:** [`v5.2.61`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.2.61) is the newest published release asset set observed during reconstruction.
- **Rust SQL taint:** [`3fc8537`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3fc8537) detects request-derived SQL injection in Rust.
- **Go SQL taint:** [`933f440`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/933f440) treats `PathValue` route parameters as tainted SQL sources.
- **Cross-language header injection:** [`c554c3e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c554c3e) closes the response-header injection wave with C++ coverage and clearer TOON encoder errors.

### Rust Detector Expansion

UBS gained a broad Rust audit wave before the later cross-language security packs. This work moved the Rust module beyond obvious panics and unwraps into protocol and trust-boundary bugs that commonly appear in agent-written web services and CLI tools.

**Delivered capability**

- Detect request-derived SQL injection in raw query construction, including later placeholder-aware fixes so tainted SQL text is still flagged when a call uses bind placeholders ([`3fc8537`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3fc8537)).
- Detect credentialed wildcard CORS and JWT verification bypass or insufficient issuer/audience binding ([`88e881c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/88e881c), [`d23de5d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d23de5d), [`c10266b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c10266b)).
- Detect archive extraction path traversal and predictable temp-file writes ([`4a63349`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4a63349), [`96146c1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/96146c1)).
- Detect request-derived SSRF URLs, open redirects, response header injection, and path traversal sources shared with the larger web-security family ([`a8d859f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a8d859f), [`968fb3a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/968fb3a), [`9d54688`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9d54688)).
- Add Rust-specific bug patterns for iterator/unsafe-API filtering, panic-prone `Drop`, direct indexing panic surfaces, command/path trust boundaries, and unsafe initialization APIs ([`fb7a68f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fb7a68f), [`85b39c1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/85b39c1), [`86105bc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/86105bc), [`8c39136`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8c39136), [`d12814a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d12814a), [`b8b04a1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b8b04a1)).

**Closed workstreams**

- Lightweight taint analysis (`ultimate_bug_scanner-4jg`).
- Async error path coverage (`ultimate_bug_scanner-e3j`).
- Type-narrowing and resource lifecycle helper expansion (`ultimate_bug_scanner-4se`, `ultimate_bug_scanner-4sm`, `ultimate_bug_scanner-8d7`).

### JavaScript and TypeScript Detector Expansion

The JS/TS module received the densest single-language expansion: browser API misuse, Node/Express trust boundaries, cancellation leaks, token validation, route-parameter taint, and AST-backed false-positive controls.

**Delivered capability**

- Detect browser trust-boundary bugs such as unsafe `window.open` targets, unsafe JSX blank targets, unsanitized React HTML sinks, wildcard `postMessage` origins, and missing origin checks ([`df1a38f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/df1a38f), [`8a8e9b5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8a8e9b5), [`b2e8509`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b2e8509), [`11651c6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/11651c6), [`9fb2788`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9fb2788)).
- Add async callback misuse coverage for React effects, `forEach`, `map`, array predicates, timers, `addEventListener`, `new Promise`, EventEmitter listeners, sort/flatMap/reduce callbacks, direct `await` on `map(async ...)`, `Promise.all` over `forEach`, and async JSX handlers ([`5b679ec`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5b679ec), [`9761a4d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9761a4d), [`fe4254d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fe4254d), [`1fc0b34`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1fc0b34), [`e153597`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e153597), [`144a80c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/144a80c)).
- Add web security detectors for JWT verification bypass, insecure cookies, credentialed wildcard CORS, randomness, disabled TLS verification, SSRF, response header injection, open redirect, archive extraction traversal, and filesystem path traversal ([`2c81897`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2c81897), [`79aa5ac`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/79aa5ac), [`ed9fcbd`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ed9fcbd), [`cb47d26`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/cb47d26), [`8f3633a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8f3633a), [`f2d7477`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f2d7477)).
- Add TypeScript-specific prototype-pollution, proxy-target SSRF, raw SQL injection, and destructured route-parameter taint propagation ([`f3c36ec`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f3c36ec), [`5c8f4b8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5c8f4b8), [`039e94e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/039e94e), [`0a77f0a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0a77f0a), [`6cb0180`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6cb0180)).

**Closed workstreams**

- TS server narrowing analyzer (`ultimate_bug_scanner-stk`).
- JS/TS AST scanning guarantee and high-severity AST confirmation (`ultimate_bug_scanner-js-ts-ast-guarantee`, `ultimate_bug_scanner-js-highsev-ast-confirm`).
- JS global-pollution false-positive follow-up (`ultimate_bug_scanner-js-global-pollution-fp-fix2`).

### Python Web-Security Pack

Python coverage expanded from general static checks into framework-aware request/response flows. The detector set now covers bugs that appear in Flask, Django, FastAPI, Starlette-style middleware, `requests`/HTTPX integrations, CSV/Excel export paths, and upload handling.

**Delivered capability**

- Detect Python request-derived open redirects, path traversal, SSRF-prone outbound URLs, JWT verification bypasses, interpolated SQL sinks, and command-injection dataflow ([`7bbee86`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7bbee86), [`b4c9cbb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b4c9cbb), [`1f3d436`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1f3d436), [`ed1c12f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ed1c12f), [`0822f25`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0822f25), [`3308c97`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3308c97)).
- Add unsafe deserialization, missing HTTP timeout, unsafe upload path, cookie/CORS, response-header injection, Host-header poisoning, template/NoSQL/LDAP/email-header injection, and subprocess-timeout families ([`4e3b29e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4e3b29e), [`03314a5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/03314a5), [`a73be83`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a73be83), [`ad51dba`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ad51dba), [`8cb3c8d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8cb3c8d), [`e911430`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e911430), [`9fbf35a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9fbf35a), [`906edf6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/906edf6)).
- Improve helper-driven Python resource lifecycle analysis through AST migration and follow-up fixes, then propagate checksum updates so installed scanners accepted the helper changes.

**Closed workstreams**

- Python resource helper and lifecycle AST migration (`ultimate_bug_scanner-41t`, `ultimate_bug_scanner-mma`).
- Bandit `.ubsignore` forwarding and test coverage (`ultimate_bug_scanner-2yvh`).

### Cross-Language Web Vulnerability Families

After the single-language Rust, JS/TS, and Python waves, UBS moved into repeated cross-language vulnerability families. The project pattern became: introduce one detector family, add intentionally buggy and clean fixtures, update the manifest, then regenerate module checksums.

**Delivered capability**

- **Archive extraction traversal:** Python, Go, Java, Ruby, C#, Swift, C++, Elixir, Kotlin, JS/TS, and Rust received zip-slip style extraction checks ([`75ea78c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/75ea78c), [`008f1ef`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/008f1ef), [`0cae370`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0cae370), [`78c8f4e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/78c8f4e)).
- **Request-derived path traversal:** JS/TS, Python, Go, C/C++, Java, Ruby, C#, Swift, Elixir, and Kotlin now recognize common request/header/route-derived filesystem sinks ([`f2d7477`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f2d7477), [`39e40d7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/39e40d7), [`876b87a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/876b87a), [`d6ae4de`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d6ae4de), [`817c395`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/817c395)).
- **SSRF:** Go, Java/Kotlin, Ruby, C#, Swift, Elixir, C/C++, Rust, and JS/TS picked up request-derived outbound URL detection, including host/header sources and reverse proxy target flows ([`5310071`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5310071), [`6c96eeb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6c96eeb), [`64a6a22`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/64a6a22), [`a8d859f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a8d859f), [`868a781`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/868a781)).
- **Open redirects:** C/C++, Elixir, Swift, Ruby, C#, Java/Kotlin, Go, Rust, Python, and JS/TS now detect request-derived redirect targets ([`f66395a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f66395a), [`867146e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/867146e), [`42aa7ca`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/42aa7ca), [`5fadcc3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5fadcc3)).
- **Response header injection:** Rust, Go, Java/Kotlin, C#, Ruby, Swift, Elixir, C/C++, and JS/TS received request-derived header sink detection, plus follow-up fixes for multiline Java/Kotlin sinks ([`9d54688`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9d54688), [`3e0ef11`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3e0ef11), [`b78839c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b78839c), [`ccff15c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ccff15c), [`c554c3e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c554c3e)).

**Closed workstreams**

- Lightweight taint analysis (`ultimate_bug_scanner-4jg`) provided the underlying model for many of these request-derived sink rules.
- Resource lifecycle and type narrowing packs continued supplying helper coverage for languages where pure regex is too noisy.

### Secrets, Randomness, JWT, CORS, and Cookie Hardening

The next security wave targeted classes where simple grep is usually noisy unless narrowed by context: hardcoded credentials, security-sensitive randomness, secret comparisons, JWT parse/decode misuse, issuer/audience validation, cookie settings, and credentialed CORS.

**Delivered capability**

- Detect security-sensitive non-crypto randomness in Elixir, Ruby, Java/Kotlin, C#, Swift, C/C++, JS/TS, and related fixtures ([`2911f58`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2911f58), [`054d692`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/054d692), [`41c507b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/41c507b), [`a0f1e25`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a0f1e25)).
- Add hardcoded-secret detectors and environment-fallback follow-ups for JS/TS, Elixir, Rust, Go, Java/Kotlin, Ruby, Swift, and C# ([`1044a09`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1044a09), [`f72212b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f72212b), [`c39b4b2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c39b4b2), [`cdb6ffe`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/cdb6ffe)).
- Detect non-constant secret comparisons in JS/TS, Go, and Rust ([`7ad487e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7ad487e), [`61639f3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/61639f3), [`1eb42a3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1eb42a3)).
- Add JWT parse/decode verification bypass and issuer/audience binding checks for Go, Rust, and JS/TS ([`52be770`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/52be770), [`d23de5d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d23de5d), [`c823e4f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c823e4f), [`8a61546`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8a61546)).
- Expand credentialed wildcard CORS and insecure auth/session cookie checks in JS/TS, Go, Rust, and Python ([`ed9fcbd`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ed9fcbd), [`2e44bb5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2e44bb5), [`872ddeb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/872ddeb), [`88e881c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/88e881c)).

### SQL Injection and Route-Parameter Taint Follow-Up

The latest tag-only slice (`v5.2.68` - `v5.2.75`) focused on request-derived SQL injection in Rust, Go, and TypeScript. This is the newest capability area and should be inspected first when cutting the next GitHub Release.

**Delivered capability**

- TypeScript raw SQL detection now tracks tainted strings from request parameters, including destructured route params and `params.<name>` patterns common in modern app routers ([`039e94e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/039e94e), [`0a77f0a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0a77f0a), [`6cb0180`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6cb0180)).
- Go SQL injection detection now treats `r.PathValue(...)`, request fields, and related request-derived values as tainted SQL sources; follow-up fixes preserve detection even when placeholders are present ([`933f440`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/933f440), [`6c45624`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6c45624), [`bb9e705`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/bb9e705)).
- Rust SQL injection detection catches request-derived raw query construction and placeholder-masked tainted SQL strings ([`3fc8537`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3fc8537)).

### Runner, Installer, Output, and Integrity Work

While detector coverage expanded, the project also hardened distribution and agent-facing operation.

**Delivered capability**

- Pin module fetches to the installed release tag after the `v5.1.2` checksum mismatch regression, while preserving update checks against the current upstream version ([`v5.1.2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.1.2)).
- Keep module and helper SHA-256 checksums current after detector/helper edits; later work added version/tag drift checks and release closeout scripts.
- Add TOON output and `tru` integration with graceful fallback, plus README/help updates for token-efficient agent consumption.
- Improve CLI UX and automation surfaces such as `--version`, JSONL output, and Beads export helper behavior.
- Expand installer handling for `ast-grep` requirements, checksum auto-fix, install smoke tests, and secure distribution documentation.

**Closed workstreams**

- Runner and installer compatibility (`ultimate_bug_scanner-fbq`, `ultimate_bug_scanner-install-ast-grep-required`, `ultimate_bug_scanner-e3m`, `ultimate_bug_scanner-6q2`, `ultimate_bug_scanner-fln`).
- TOON output and encoder integration (`ultimate_bug_scanner-1tc`, `ultimate_bug_scanner-2kp`, `ultimate_bug_scanner-9vy`, `ultimate_bug_scanner-psu`).
- Release workflow and supply-chain docs (`ultimate_bug_scanner-1de`), with secure distribution work still tracked separately as in progress.

### Notes for Future Agents

- Do not infer release status from tags. `v5.2.75` is the newest tag; `v5.2.61` is the newest GitHub Release at the time of this update.
- The recent version train is intentionally granular: most tags represent one detector slice plus fixtures, manifest updates, version bump, and checksum refresh.
- For a release cut after this changelog, inspect `v5.2.62...v5.2.75` first because those commits are tag-only and not yet represented by GitHub Release assets.
- The Beads tracker captures the larger workstreams; the newest detector slices are mostly evidenced directly by git commits and tags.

**Full diff:** [`v5.1.2...v5.2.75`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.1.2...v5.2.75)

---

## [v5.1.2] - 2026-04-25 **[Release]**

### Bug fix

- **Module fetch URL pinned to release tag instead of `main`** — every installed copy of UBS broke as soon as `main` advanced past the release the user had installed (issue #43). The launcher pins per-language module checksums, but `REPO_RAW` pointed at `main/modules/…`, so the moment any module changed on `main` the checksum verification rejected the download and the scanner refused to start. Fixed by pinning `REPO_RAW` to `v${UBS_VERSION}/…` for module/helper fetches while keeping the self-update probe on `main` (so stale installs still discover newer releases). Resolves the "expected `<pin>`, got `<current main>`" failure reported on macOS / Homebrew installs.

---

## [v5.0.7] - 2026-03-25 **[Release]**

> 80 commits since v5.0.6 — biggest release since v5.0.0.

### 9th Language: C#

UBS now scans C# codebases, bringing the total to 9 supported languages.

- Add complete `ubs-csharp.sh` language module with test suite ([`7670efc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7670efc40040aba5d5c1ab9c72b969f257c048da))
- Add C# AST-level analysis helpers, test fixtures, and expand scanner coverage ([`908d307`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/908d30726f2391dfb4f3df2ab0fe0359df102532))
- Integrate async task-handle analysis, structured ast-grep ingestion, and Ruby/Swift resource lifecycle helpers for C# ([`7e755e8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7e755e8edca190eed561f05d3ca3b119cfdacf7f))
- Add C++ AST resource lifecycle helper; harden C#/Java modules; pass-through dotnet CLI flags ([`0f8f182`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0f8f1822c71a2f29f5665ca0f642aad051fa6a72))

### New Scanner Capabilities

- Multi-file scanning with `--files` flag for targeted analysis ([`9ce7471`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9ce7471b51e24c632e9b5ff4cc0f0ad938ed3bde))
- TOON format output (`--format=toon`) for ~50% smaller token cost via the `tru` encoder ([`5e9cee8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5e9cee81ab5241473fd0cf37fbed4668fe303f45))
- `TOON_BIN` env var support for `toon_rust` (`tru`) binary ([`6ab8f16`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6ab8f16))
- `--skip-size-check` flag and `load_ignore_patterns` for `.ubsignore`-aware size calculation ([`c27235e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c27235e219e40ea4acd99327fcd3d13b6cd1e983))
- Add Claude Code `SKILL.md` for automatic capability discovery ([`a59f7bb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a59f7bba4d66cc2759f074f89a35c66bb37cf470))

### False-Positive Reduction and Scanner Accuracy

- Eliminate false positives in JS credential detection and Python mutable default checks ([`c54c27c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c54c27c8c4383ba6a9d2768172e6194c003a5aaa))
- Bypass whole-repo size guards for targeted scan modes (`--files`, `--staged`) ([`4c3bd50`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4c3bd5071bb5d8db9050862014e98ad7ec34748c))
- Fall through to Python size-check when `.ubsignore` has path patterns (#16) ([`f90f948`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f90f948bba2e13c005e38614fa8ca5dca9df60b5))

### Installer and Platform Fixes

- Prevent Cellar path error in Homebrew installs (closes #29) ([`f00743a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f00743ad604bf82e1caeb9ccd54af54dc9bdcc00))
- Bash 4.0 version gate, `script_dir` symlink resolution, checksum refresh (#25, #26, #27) ([`c9a8316`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c9a831650c95b95c5a6bbb3cc70d48973f635de5))
- Correct module download URL to use main branch ([`97bb3c0`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/97bb3c0f3243a37324318322cf5ef39501f4a1ce))

### Suppression and Ignore System

- Implement inline `ubs:ignore` suppression and apply `.ubsignore` in `--staged` mode (#24) ([`4b8a111`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4b8a111261d3c5e6b47684759c916065ed78a401))
- Expand `.ubsignore` glob patterns for Bandit exclusions (#22) ([`9c81a5c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9c81a5c8ea7062bf6cd4f0df300b58d3a4c20502))
- Respect `.ubsignore` patterns when calculating directory size ([`d29ec78`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d29ec7807f39d43d460a7d314a40d2fd110fbf9d))

### Robustness

- Skip `du` on macOS/BSD when exclude patterns are needed ([`8cbb069`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8cbb069d4fc8ef96dd8b6adf87b41fc45dbe4eec))
- Escape backtick `` `as` `` in Rust module to prevent command substitution ([`b742cbc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b742cbc0ed5daf485523da143431d662362c52a9))
- Exclude `.venv` from language detection in `detect_lang()` ([`27a0d96`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/27a0d960f15816ff74ad03acae74a624498f080a))
- Remove nonexistent `ubs-c.sh` module reference from `ALL_LANGS` ([`11dd82a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/11dd82a85a11bd89e2568253f6b64c89a4e876ba))
- Improve shell script robustness and detection patterns ([`3d9dc12`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3d9dc127d4ae829203a83e93e71189515f78bbbe))
- Add safety guards to prevent disk exhaustion (#12) ([`b9f3982`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b9f39825f99b1eedd1d2be75a3b75ed9902c0f2f))
- Validate `du` output is numeric before size comparison ([`dbd1da0`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/dbd1da0))
- Initialize helpers before scan ([`b0228a4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b0228a4))
- Migrate Codex rules to directory format for v0.77.0+ ([`c8f2672`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c8f2672))

### Continuous Integration

- Add CI workflow for build, test, and lint ([`e58e2c2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e58e2c2958dc28d6c19f0b477eaa5955a6b8f0a2))
- Add ACFS notification workflow for installer changes ([`88464ea`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/88464ea))

### Session-Mined Bug Patterns

- Add 37 session-mined bug patterns for Go, Rust, Python, and JS/TS ([`1ed3c4c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1ed3c4c))
- Concurrent agent refinements to bug detection rules ([`6539a45`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6539a45))
- Refine Go and JS/TS ast-grep rules to reduce false positives ([`5f50e30`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5f50e30))

### Other

- Update license to MIT with OpenAI/Anthropic Rider ([`534c897`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/534c8977a2d13daa9206c408a46c6c8bb4f19971))
- Add MIT license file ([`3d6d7f3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3d6d7f341636220af6c56763371b0478f1c410a2))
- Add GitHub social preview image ([`b3bdbf8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b3bdbf8b51f812d25ab3a85242692b93d53195ac))
- Add Homebrew package manager installation option to README ([`22254dc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/22254dc))
- Prioritize Homebrew/Scoop installation methods in docs ([`883969c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/883969c))
- Add comprehensive CHANGELOG.md documenting project history ([`1149f8f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1149f8f))

**Full diff:** [`v5.0.6...v5.0.7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.6...v5.0.7)

---

## [v5.0.6] - 2026-01-05 **[Release]**

> Title: "Documentation Deep-Dive"

### AST Rule Architecture Documentation

Added 201 lines of technical deep-dive documentation covering scanner internals that were previously undocumented:

- AST rule architecture with ancestor-aware pattern matching and the critical `stopBy: end` directive for ast-grep rules ([`2b632f0`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2b632f0aadb6e7aa48bdb97495f959606868ea58))
- Inline suppression comment syntax documentation for JavaScript, Python, and Ruby
- Cross-language async error detection table mapping patterns across all 8 languages
- Helper script SHA-256 verification documentation
- Unified severity normalization ASCII table

### JS/TS AST Rule Accuracy

Three fixes to ast-grep rules that reduced false positives in promise chain analysis:

- Fix `then-without-catch` rules and `Promise.all` consistency ([`5fc2095`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5fc20955bfd88257ff38a50a2b43ef166f4eaff0))
- Improve `.catch()` chain detection in ast-grep rules ([`f89e0b5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f89e0b5eb85b18081fd6df34b4c3b9c6bca97526))
- Add `stopBy: end` to ast-grep rules for proper ancestor traversal ([`688ea6d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/688ea6d0e2fc407856440636ce8af7583b8c8379))

### Cross-Language Scanner Fixes

- Repair JS `typeof` detection and Go false positive ([`2377537`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2377537a1b78ec7feddf6ed5b131f3118a222ca8))
- Correctly parse UBS summary JSON from JSONL output in test suite ([`7868512`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/786851256046bb643dbcf93640a521df9c000d56))

**Full diff:** [`v5.0.5...v5.0.6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.5...v5.0.6)

---

## [v5.0.5] - 2026-01-05 **[Release]**

> Title: "Documentation Release"

Documentation-only release. No code changes; all features documented were already present in v5.0.4.

### Comprehensive Feature Documentation

Added documentation for 8 previously undocumented feature systems (~386 lines), growing the README from ~2,026 to ~2,410 lines ([`ff5b90f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ff5b90f91f575673a6680d8d385f9ce9bfaa739d)):

| System | What Was Documented |
|--------|---------------------|
| Safety Guards | `git_safety_guard.py` hook that blocks destructive commands |
| Agent Detection | All 12+ detected coding agents (Aider, Continue, Copilot, TabNine, Replit, etc.) |
| Type Narrowing | AST-based deep type safety for TS/JS, Rust, Kotlin, Swift |
| ast-grep Provisioning | Automatic binary download with SHA-256 verification |
| Maintenance Commands | `ubs doctor` and `ubs sessions` commands |
| Test Suite | Manifest-driven testing with `run_manifest.py` |
| Auto-Update | `--update`, `--no-auto-update`, CI mode behavior |
| Beads Integration | `--beads-jsonl` flag for issue tracking |

### Bug Fixes

- Multiple helper file bugs found via code exploration ([`61fdbde`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/61fdbdea9ab3ff4225b00319b36a50b7f9189b36))
- Use ast-grep for var declaration finding display ([`dc55bee`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/dc55bee01843e8b40fbbce3455ed1da3226e64e8))
- Use ast-grep for division finding display when available ([`aa834ee`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/aa834ee0b39de0bb78cf7129c92e64e27ed7f52d))

**Full diff:** [`v5.0.4...v5.0.5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.4...v5.0.5)

---

## [v5.0.4] - 2026-01-05 **[Release]**

> Security patch release.

### Security: `git_safety_guard.py` Bypass Fix

**Critical:** The git safety guard could be bypassed by using absolute paths to the `rm` command (e.g., `/bin/rm -rf /important`). Added `_is_rm_command()` helper that recognizes both `rm` and any path ending in `/rm` ([`8907eec`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8907eec8c0ca08e0c04bea467f07bb5d9ab7e65d)).

| Command | Before v5.0.4 | After v5.0.4 |
|---------|---------------|--------------|
| `rm -rf /important` | Blocked | Blocked |
| `/bin/rm -rf /important` | **Allowed** (bug) | Blocked |
| `/usr/bin/rm -rf /important` | **Allowed** (bug) | Blocked |

All users of Claude Code with the `git_safety_guard.py` hook should update.

### Supply-Chain Integrity

- Add defense-in-depth checksum monitoring CI workflow ([`55bdf23`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/55bdf23cb68f593bd5e12345b788f18f67b324ec))

### Bug Fixes

- Handle repos without git remote gracefully ([`3d20cc4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3d20cc47ff2bb0e6ac372b77cfa11a002d881a29))
- Resolve PATH issue in git pre-commit hook ([`c9779f7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c9779f7590934ccd018a8d760ce7e1f7a51473b1))
- Handle uppercase `-R`/`-F` flags in `rm_rf_targets_are_safe` ([`de62531`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/de625315421a03e363028411fdca78d0e9dd6230))
- Catch `rm` bypass variants in `git_safety_guard.py` ([`ec72ce7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ec72ce7de7a20275bcabdfa4c7df437cadd56387))
- Fix output variables bug in checksum-health workflow ([`f43f420`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f43f420ce594875db0ee3729819056439fb20d90))
- Fix GH workflow multi-line output bug and sync checksums ([`ce4e71d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ce4e71d0fa3c191075bc77d8d866f4995afda650))

**Full diff:** [`v5.0.3...v5.0.4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.3...v5.0.4)

---

## [v5.0.3] - 2025-12-30 **[Release]**

### Docker

- Include version tag in Docker image tags ([`162ed53`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/162ed537bc9e3fad534dc9a7846ff7db3af2dd8d))

**Full diff:** [`v5.0.2...v5.0.3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.2...v5.0.3)

---

## [v5.0.2] - 2025-12-30 **[Release]**

### Docker

- Skip SBOM generation for PR builds in OCI workflow ([`a468726`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a468726721380def2d96c82d0993eb18307d7594))

Version bump for ARM64 Docker release.

**Full diff:** [`v5.0.1...v5.0.2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.1...v5.0.2)

---

## [v5.0.1] - 2025-12-30 **[Release]**

### Docker: Multi-Architecture Support

- Add multi-platform Docker builds (amd64 + arm64) ([`420370a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/420370adf0fc40043aa5acbaa0f59d0716f19c98))

### Security Hardening

- Make `git_safety_guard` `rm -rf` allowlist non-bypassable ([`096e1ee`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/096e1ee24a9e10eabb42e2615339d4e9f3ea6f05))
- Harden supply-chain verification and machine output ([`f2e320a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f2e320ad18962cecaa995a6f6ab9f4058eb24b48))
- Allow `rm -rf` on temp directories in hooks ([`3a369ed`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3a369ed470c42bbf53b74f4d416774d6b4291f33))

### Scanner Accuracy

- Correct ripgrep TypeScript file detection in JS module ([`355a78d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/355a78d0afe2a34e05373e1281f77244e564fdd7))
- Address false positives in Go heuristics; add Bun runtime support ([`e7a6cd8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e7a6cd84d03aa57738f03db1364102d2c0dd341e))
- Remove tautological return expressions in type narrowing helpers ([`e401c5b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e401c5beee72339289f54bcc9ffef6ae5a711bf4))

### Installer

- Reduce installer noise and improve Node.js detection ([`e089b32`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e089b32ca1ec47a0aa58454a581408e68b8b69e5))
- Update typos binary download URL ([`ee41575`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ee41575c65bc82ec6da3bd5591702b4e2a8d33d5))

### AI Agent Ecosystem

- Convert `.codex/rules` to directory structure for Codex CLI v0.77.0+ ([`cc9c6a9`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/cc9c6a97ff5c866c7a61ea7dc48c48982ce1820c))
- Add Codex CLI v0.77.0+ migration guidance to README ([`72546dc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/72546dc0e328a8d9439dcf9db8d5cde25dace84f))
- Add contribution policy section to README ([`efa70e2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/efa70e26779c564da5858b6f1c4e05d66d42b4ce))

**Full diff:** [`v5.0.0...v5.0.1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.0.0...v5.0.1)

---

## [v5.0.0] - 2025-12-19 **[Release]**

> 105 commits, 10,600+ line additions across 50 files since v4.6.5.

### Breaking Changes

1. **ast-grep is now required** for JS/TS scanning. Install via `brew install ast-grep`, `cargo install ast-grep`, or `npm i -g @ast-grep/cli`.
2. **Exit code 2** now indicates environment errors (missing required tools), distinct from exit code 1 (findings detected).
3. **Windows paths** now parsed correctly (`C:/path:line:code`). Downstream tooling that depended on the old broken parsing may need adjustment.

### Windows Compatibility

Full Windows support via Git Bash / WSL:

- Add `.ubsignore` fallback chain when rsync unavailable: rsync -> tar -> Python ([`db01365`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/db013652d59ae2b3b3f490e446453609307a543d))
- Fix Windows path parsing across all 8 language modules with `parse_grep_line()` helper ([`50b23db`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/50b23dba869d40eda4d7cf06a9fc91172a131402), [`e647ca8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e647ca83cb8e8127a6096cd978ff07a56b458de5))
- Portable SHA-256 verification: sha256sum / shasum / openssl ([`be2dc39`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/be2dc399baf342f21535516463cb268fef83070e), [`dafce5f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/dafce5f519f47e805dbcedffcc0eee55d732056b))

### AST Accuracy Enforcement

JS/TS scanning now requires ast-grep to eliminate noisy grep-based false positives. Six key improvements:

- Enforce ast-grep; AST-confirm noisy JS/TS findings ([`a17b0f7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a17b0f74d845ac252d8804025808dd4413a41882))
- Type narrowing properly gated to TypeScript inputs only ([`fed9b86`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fed9b868ad8f1eef90a5494374cfc8136bdbc1a2))
- AST-based division/modulo detection with regex fallback ([`9583f87`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9583f87691585f584bd32d2127e0231237046ff8))
- AST-based bare `var` declaration detection ([`73202c9`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/73202c902eac72535fa03c63ff5ca914919cab2d))
- AST `await-without-try` rule for async false-positive reduction ([`24a67a0`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/24a67a0debd7006a1341f4e867883612cc14a7a5))
- Stricter async via AST: dangling-promise uses AST context ([`1f3cbd2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1f3cbd2fcd87a675da429610cb04b794202f07fd))
- Cut noisy false positives for division, var, JSX globals ([`5f8d235`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5f8d235feb6fa505d1fe1a1a5c9a9064ea9f5515))

### Module Upgrades to v3.0+ Standards

All 8 language modules upgraded to standardized v3.0+ architecture ([`0bc391f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0bc391f0a5b1aaebb061f7b86c391671bfc009fe), [`614461d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/614461db1606a954d38834cea404dd40120a1b52)):

| Module | Version | Highlights |
|--------|---------|------------|
| ubs-js.sh | v3.0 | React hook dependency analysis, full AST-powered detection |
| ubs-python.sh | v3.0 | Scope-aware resource lifecycle, AST-based mutation/json.loads |
| ubs-golang.sh | v7.1 | Return/defer handling, context leak detection, AST resource lifecycle |
| ubs-cpp.sh | v7.1 | Modern C++20 patterns, RAII checks, AST caching |
| ubs-rust.sh | v3.0 | Type narrowing, cargo integration, async detection |
| ubs-java.sh | v3.0 | JDBC lifecycle with CallableStatement, CompletableFuture checks |
| ubs-ruby.sh | v3.0 | Block/ensure analysis, command injection detection |
| ubs-swift.sh | v1.8.0 | Guard-let analysis, regex-based AST rules, 23 analysis categories |

### Scope-Aware Resource Lifecycle Analysis

Resource lifecycle analyzers upgraded to be scope-aware, properly handling return/yield/defer:

- Go resource lifecycle analyzer handles return/defer correctly ([`3d5ec19`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3d5ec190b15ef097906df148ac428e7a33c2edd5))
- Python resource lifecycle analyzer handles return/yield ([`9133d97`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9133d9704f475adcfff3f0dffa33fc08dfdcfb8a))
- React hook dependency analysis and TS type narrowing improvements ([`39e331e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/39e331eaf41c7f315b27f9021d026c6def4b7542))

### Security and Supply Chain

- Add Claude Code hook (`git_safety_guard.py`) to block destructive git commands ([`38d1038`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/38d1038bedfbb52d317a2346d20d6f8594b16636))
- SHA-256 checksums auto-synced via GitHub Action ([`9358e4f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9358e4fbda66e45b845b3b223105216f330eabb5))
- Multi-layered checksum verification system ([`4e61674`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4e616749210575adb072e94f6e1f087200b43053))
- Inline suppression: `ubs:ignore`, `nolint`, `noqa` markers respected ([`44c9899`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/44c9899d2610a9bd6f3264dcf44354c35e78654b))

### Installer Hardening

- Installer downloads from main and verifies checksums ([`bc461b0`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/bc461b008638fded5055547ef76374d6feb9db21))
- Installer handles piped-from-curl execution correctly ([`b317122`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b3171220e3fd1cbd904c180790ca64c4a28537c4))
- Installer rerun after checksum auto-fix via doctor ([`93d820e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/93d820e9ef92adab7df6892eaa7fe3289d3d7a7e))
- Smoke test uses detectable NaN bug for validation ([`5b2f0d8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5b2f0d8ecd13453f466536f87a59f3d1190efaa9))
- Portable `mktemp` fallback ([`501ace9`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/501ace93de46c08ea13024f76a4905ef99d29c21))

### AI Agent Quality Guardrails

- Add quality guardrails for Cursor, Codex, Gemini, Windsurf, Cline, and other coding assistants ([`fbb479a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fbb479a0d070263a8002553ef788ecd6e9fc3fca))

### CI / Test Infrastructure

- Run test/manifest via `uv` Python with `UBS_LOG_JSON` ([`c11c55e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c11c55e02d3904683034538c37db9775a4a1880f))
- Install ast-grep via npm for JS rule accuracy in CI ([`d364ac8`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d364ac84a93423a26931921970c67c89b62c715e))

**Full diff:** [`v4.6.5...v5.0.0`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.5...v5.0.0)

---

## [v4.6.5] - 2025-11-22 **[Release]**

CI release-pipeline fix only. No scanner changes.

- Avoid duplicate asset names in release publish ([`952df6f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/952df6f))

**Full diff:** [`v4.6.4...v4.6.5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.4...v4.6.5)

---

## [v4.6.4] - 2025-11-22 **[Release]**

CI release-pipeline fix only. No scanner changes.

- Disable uv cache to avoid missing cache path error ([`9135bb7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9135bb7))

**Full diff:** [`v4.6.3...v4.6.4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.3...v4.6.4)

---

## [v4.6.3] - 2025-11-22 **[Tag]**

CI release-pipeline fix only. No scanner changes.

- Fix setup-uv input name ([`c04abca`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c04abca))

**Full diff:** [`v4.6.2...v4.6.3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.2...v4.6.3)

---

## [v4.6.2] - 2025-11-22 **[Tag]**

CI release-pipeline fix only. No scanner changes.

- Fix jq download URL for release workflow ([`e10b60c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e10b60c))

**Full diff:** [`v4.6.1...v4.6.2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.1...v4.6.2)

---

## [v4.6.1] - 2025-11-22 **[Tag]**

- Fix release workflow YAML and bump version ([`592486d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/592486d6e139813362ee81fb1a1515be4e11cab3))

**Full diff:** [`v4.6.0...v4.6.1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.0...v4.6.1)

---

## [v4.6.0] - 2025-11-22 **[Tag]**

> First tagged version. Encompasses all development from the initial v4.4 commit (2025-11-16) through the polyglot architecture, 8-language module system, and full test suite.

### Multi-Language Scanner Architecture

Refactored from a monolithic JavaScript-only scanner into a modular polyglot system supporting 8 languages. Each language module runs as an independent shell script with standardized output ([`d392951`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d392951bc2dc67bd44b5502534f67f1768c23182), [`c24548e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c24548e0da1b2916e99406701502b32e4a9a7695)).

### Language Modules

- **JavaScript/TypeScript** (`ubs-js.sh`): 1000+ bug patterns including `=== NaN`, missing `await`, `innerHTML` XSS, `parseInt` radix, React hook dependencies, `var` declarations, dangling promises, taint analysis ([`3078280`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3078280)), scope-aware await detection ([`a9d5232`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a9d5232))
- **Python** (`ubs-python.sh`): Mutable defaults, bare `except`, `eval()`/`exec()`, taint analysis ([`449115f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/449115f)), AST-based resource lifecycle analyzer ([`242c25f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/242c25f169f110095fc7eecc5cd0fe03a7295dec)), AST-based mutation and `json.loads` detection ([`da870dc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/da870dc))
- **Go** (`ubs-golang.sh`): Goroutine leaks, context cancellation, `defer` in loops, `sync.Mutex` misuse, taint analysis ([`befe150`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/befe150)), AST-based resource lifecycle analyzer ([`790a968`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/790a96840860788f0add3e12dde6b497be96a08d))
- **Rust** (`ubs-rust.sh`): `.unwrap()` panics, async error detection, taint analysis metadata ([`f9647e4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f9647e4)), enhanced async detection with `UBS_SKIP_RUST_BUILD` support ([`9c6ac3b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9c6ac3b)), JSON export and finding recording system ([`0871e5b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0871e5b))
- **C++** (`ubs-cpp.sh`): `strcpy`/`sprintf` buffer overflows, raw pointer misuse, RAII checks, modern C++20 patterns, AST caching ([`a3f21f9`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a3f21f9))
- **Java** (`ubs-java.sh`): JDBC resource lifecycle with Statement/ResultSet/CallableStatement tracking ([`587187b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/587187b835916042169115eb51646a289fed0302), [`d38b00c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d38b00c74ac8727b3b9670e69b4cd045fa2555cd)), AST-grep integration via Python-based result parser ([`2b57508`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2b5750862ba37053e95cbe9a4c958550daf7a983))
- **Ruby** (`ubs-ruby.sh`): Unsafe YAML deserialization, command injection, block/ensure analysis, restructured code organization ([`b4ba59b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b4ba59b))
- **Swift** (`ubs-swift.sh`): Guard-let analysis, Objective-C bridging patterns, 23 analysis categories, integrated type narrowing ([`a0032c3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a0032c354f000dab4f3372f430e7151d5dd5522e), [`36b2666`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/36b26660ba7a39f2358ec2b9b333ab6880dd8316))

### Taint Analysis

Lightweight taint analysis added across multiple languages, tracking data flow from sources (user input, file reads, network) through code to sinks (SQL, exec, eval):

- JavaScript: Comprehensive taint analysis with sophisticated data flow tracking ([`3078280`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3078280), [`9639572`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/9639572))
- Python: Complete taint analysis for security checks ([`449115f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/449115f))
- Go: Taint analysis with SQL parameterization detection ([`befe150`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/befe150), [`0037e9d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0037e9d))

### Resource Lifecycle Detection

AST-powered resource lifecycle correlation detects unclosed files, sockets, connections, and context leaks:

- ast-grep resource lifecycle rules for all languages ([`7513b4f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7513b4f4192982f1acbcf6410d0246de938b407a))
- Resource lifecycle correlation in Java and Ruby modules ([`952d82a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/952d82a7429c0da0fa207641719378092f1beb9f))
- Resource lifecycle correlation across all languages ([`647264e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/647264e5f3980d405167594c1ee70d86a8d082e6))

### Async Error Path Coverage

Detection of unhandled async errors across all supported languages:

- JavaScript and Python async error path coverage ([`c846114`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c84611443c79d9518eec29bf67eb0a468f99d52b))
- C++/Go/Java/Rust async error path coverage ([`5bd168e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5bd168e2b212792c81bdd3b212bd32733dde3664))

### Type Narrowing Analysis

Deep type safety checks that detect missing null guards and type checks:

- TypeScript type narrowing safety analyzer ([`7cd2478`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7cd2478))
- Rust and Kotlin type narrowing with comprehensive test coverage ([`f13d305`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f13d305))
- Swift type narrowing support ([`6b5a0e3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6b5a0e3))
- Kotlin/Swift helpers with improved pattern detection ([`e934da3`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/e934da3b17cb18673ee409179185c01eb4e84269))

### Core Scanner Features

- Git-aware scanning: `--staged` mode for pre-commit checks, `--diff` for working tree changes
- Strictness profiles: `--profile=strict` (fail on warnings), `--profile=lenient`
- Machine-readable output: `--format=json`, `--format=jsonl`, `--format=sarif`
- Smart silence: suppress known-clean patterns
- `.ubsignore` support for project-specific exclusion patterns ([`363f857`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/363f857))
- `ubs doctor` diagnostics and `ubs sessions` session management
- Category packs: `--category=resource-lifecycle` for focused scanning
- Shareable reports with GitHub permalinks ([`6ad2017`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6ad2017))
- HTML report output ([`6ad2017`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6ad2017))
- Baseline comparison with `--comparison=<baseline.json>` ([`6ad2017`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6ad2017))

### Metrics Collection

- Comprehensive metrics collection infrastructure for tracking scan performance ([`76b5024`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/76b502417b04a7732940ccf0c671ded7e6afa1fe))
- Metrics collection in JS, Python, and Ruby modules ([`fd19ad4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fd19ad456988956dc549ea93eabc0a1b8d8368f7))

### Installer

- curl|bash one-liner installer with ripgrep auto-detection ([`6c5bf4a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6c5bf4a617724bf48bdacb70f5a70f35895d7e4a))
- `--easy-mode` flag for fully automated installation
- Fish shell support ([`8e0c0b4`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8e0c0b4))
- Homebrew bash detection and daily auto-updates ([`376feb6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/376feb611ec387dd8e2e3c10b361d9cc6624112b))
- Bun support for TypeScript installation ([`250fd82`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/250fd8280a17c4533ecb7a2345412013042c0ca3))
- Non-interactive uninstall support ([`81af909`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/81af9090b6fab6476e73c86aaa87ef3a30185e0a))
- Automatic bash upgrade on macOS ([`8b5b925`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8b5b925301f290bf476975b9a6daca0d7bc15266))
- WSL detection and BSD platform support ([`60949b1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/60949b11a07c208fa5f6af9296246fb024f280fc))
- Concurrency protection with `flock`-based locking and automatic fallback ([`0190606`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0190606), [`263479c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/263479cab581080fc9c9238a8f878b7d4e225b71))
- Dry-run mode, self-test, and stale binary detection ([`f09e7db`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f09e7db))
- `typos` CLI integration for spell-checking ([`0657dec`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0657dec))
- Swift guard readiness diagnostics ([`3485e76`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3485e76deb6c824c10675f29564f61ac5a6cf2b8))

### Test Suite

- Comprehensive polyglot test suite with buggy and clean code examples across all 8 languages ([`a06ebce`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/a06ebcee951c53f23757d3bc5dbbb1f3867b723d))
- 275+ additional bug patterns across 12 test files ([`2a7ac95`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2a7ac95d12a9d803deb57e0a288ab84a8dfa40df))
- Framework-specific anti-patterns for React and Node.js/Express ([`7fa23cf`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7fa23cf18ee60bdba947163865f6eb6b235f86c4))
- Realistic full-application scenarios (e-commerce + authentication) ([`db94400`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/db94400ff41c71407df4b09590c4f2bebf6229ec))
- Edge case tests for Unicode, timezones, floating-point arithmetic ([`7131633`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7131633d21abd673782bbf64ca1c42f95fb9f363))
- Manifest-driven test automation infrastructure ([`bd09105`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/bd09105498dea509e3c486282f6d035da213cad4))
- GitHub Actions workflow for automated manifest test suite ([`5d83279`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5d83279))
- Async error path coverage fixtures for all languages ([`12d3507`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/12d350725eafe1e87b3dd8f32e34ffd1ec56bc2b), [`f59787f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f59787f36547b65bf7240d3632406e1b570d0c01))
- Resource lifecycle test cases for all languages ([`5cfebca`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5cfebca97f24098c859e57f52b646e4181a0e128))
- Security vulnerability test fixtures ([`ed438eb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/ed438eb6047d02cb35a2a5018b7b0fa4abdbea36))
- Performance and resource management test cases ([`c2da421`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c2da421385ddc1e3afd1aa9a985702c36a58a9dc))

### Documentation

- 12 installer bugs fixed alongside major README improvements ([`92b0c85`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/92b0c85a3330d8e92664a45787098a3484b9376f))
- Project justification and rationale section with FAQ ([`c841e66`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c841e66432b30b2ff5fead6e33a681c2a6a78ee9))
- Language coverage comparison matrix ([`1a9f652`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1a9f652))
- Release workflows and supply chain documentation ([`8144864`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/81448644dfe9dabe9ffd2c4aa8334de4f54752b6))

---

## Pre-v4.6.0 (v4.4 initial commit)

- **2025-11-16**: Initial release of Ultimate Bug Scanner v4.4 as a JavaScript/TypeScript-focused bug scanner ([`689c581`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/689c58100a0bd40d8bef0357aaa50c7a3a19f6f2))

---

<!-- Link references -->
[Unreleased]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.2.75...HEAD
[v5.2.75]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v5.2.75
[v5.2.61]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.2.61
[v5.1.2]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.1.2
[v5.0.7]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.7
[v5.0.6]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.6
[v5.0.5]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.5
[v5.0.4]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.4
[v5.0.3]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.3
[v5.0.2]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.2
[v5.0.1]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.1
[v5.0.0]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.0.0
[v4.6.5]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v4.6.5
[v4.6.4]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v4.6.4
[v4.6.3]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.2...v4.6.3
[v4.6.2]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.1...v4.6.2
[v4.6.1]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v4.6.0...v4.6.1
[v4.6.0]: https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v4.6.0
