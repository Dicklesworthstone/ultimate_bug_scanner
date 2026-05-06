# Changelog Research Memo

This memo records the evidence behind the 2026-05-06 changelog reconstruction. It intentionally lives under `docs/reports/` rather than the repository root so the project root stays focused on source, packaging, and top-level user documentation.

## Scope

- Canonical changelog updated through git tag [`v5.2.75`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v5.2.75).
- Covered window: [`v5.1.2...v5.2.75`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/compare/v5.1.2...v5.2.75).
- Commit volume checked: 197 non-merge commits after `v5.1.2`.
- Release metadata checked with `gh release list --limit 200 --json tagName,name,isDraft,isPrerelease,publishedAt,isLatest`.
- Latest GitHub Release observed: [`v5.2.61`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.2.61), published 2026-05-06 and marked latest.
- Latest git tag observed: [`v5.2.75`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/tree/v5.2.75).

## Evidence Sources

| Source | Purpose | Result |
|--------|---------|--------|
| `AGENTS.md` | Repo rules, branch rules, quality checks, project architecture | Confirmed pure Bash scanner with helper assets and strict checksum requirements |
| `README.md` | Product intent and user-facing feature framing | Confirmed UBS as a multi-language, agent-oriented bug scanner |
| `CHANGELOG.md` | Existing historical baseline | Current content stopped at `v5.1.2` for modern history |
| `git describe --tags --abbrev=0` | Current tag spine | Returned `v5.2.75` |
| `git log v5.1.2..HEAD --date=short --pretty=... --no-merges` | Post-`v5.1.2` history | Returned 197 commits |
| `git tag --list 'v5.1.*'` and `git tag --list 'v5.2.*'` | Version density | Found 100 `v5.1.x` tags and 76 `v5.2.x` tags |
| `gh release list --limit 200 --json ...` | Release vs tag classification | Confirmed GitHub Release assets through `v5.2.61`; later tags are tag-only |
| `.beads/issues.jsonl` | Workstream and issue-tracker evidence | Confirmed detector, installer, TOON, lifecycle, AST, and release-workflow epics |

## Coverage Ledger

| Chunk | Range | Status | Major themes |
|-------|-------|--------|--------------|
| Baseline | `v5.1.2` | Distilled | Module fetch URL pinned to release tag after checksum mismatch regression |
| Rust safety | `v5.1.3` - `v5.1.11` | Distilled | Rust iterator and unsafe API filtering, panic-prone `Drop`, indexing panic surfaces, command/path trust boundaries, and unsafe initialization APIs |
| JS/TS browser and async | `v5.1.12` - `v5.1.32` | Distilled | Browser globals, storage, React lifecycle, fetch timeout, floating promises, `Promise.all`, `JSON.parse` |
| Archive extraction | `v5.1.33` - `v5.1.42` | Distilled | Zip-slip style extraction checks across Python, Go, Java, Ruby, C#, Swift, C++, Elixir, Kotlin |
| Python web security | `v5.1.43` - `v5.1.75` | Distilled | SQL, deserialization, temp files, uploads, path traversal, SSRF, headers, redirects, CORS, cookies |
| JS/TS security | `v5.1.76` - `v5.1.87` | Distilled | JWT, CORS, cookies, randomness, TLS, SSRF, response headers, open redirects, path traversal |
| Path and SSRF | `v5.1.88` - `v5.2.20` | Distilled | Cross-language request/header/route-derived path traversal and outbound URL sinks |
| Redirects and headers | `v5.2.21` - `v5.2.38` | Distilled | Open redirect and response header injection coverage across all language families |
| Secrets and randomness | `v5.2.39` - `v5.2.57` | Distilled | Security randomness, hardcoded secrets, environment fallbacks, secret comparisons, cookies, CORS |
| JWT and proxy security | `v5.2.58` - `v5.2.67` | Distilled | JWT parse/decode verification, issuer/audience binding, prototype pollution, reverse proxy SSRF |
| SQL taint | `v5.2.68` - `v5.2.75` | Distilled | Rust, Go, and TypeScript request-derived SQL taint and route-parameter propagation |

## Release vs Tag Findings

- `v5.2.61` is the latest GitHub Release returned by GitHub release metadata.
- `v5.2.62`, `v5.2.63`, `v5.2.64`, `v5.2.65`, `v5.2.66`, `v5.2.67`, `v5.2.68`, `v5.2.69`, `v5.2.70`, `v5.2.71`, `v5.2.72`, `v5.2.73`, `v5.2.74`, and `v5.2.75` are present as git tags and absent from the GitHub Release list checked during this pass.
- The changelog therefore marks the reconstructed top entry as **[Tag]**, not **[Release]**.
- The `v5.2.62...v5.2.75` slice should be inspected first before creating the next release asset set.

## Representative Commit Index

### Rust

- [`fb7a68f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/fb7a68f) - Rust iterator smell filtering.
- [`85b39c1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/85b39c1) - Rust AST-filtered unsafe API checks.
- [`86105bc`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/86105bc) - Rust panic-prone `Drop` implementations.
- [`8c39136`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8c39136) - Rust direct indexing panic surfaces.
- [`4ef6c42`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4ef6c42) - Rust shell-argument command injection.
- [`d12814a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d12814a) - Rust `mem::zeroed()` and `MaybeUninit::assume_init()` checks.
- [`4a63349`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/4a63349) - Rust archive extraction path traversal.
- [`96146c1`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/96146c1) - Rust predictable temp-file writes.
- [`3fc8537`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/3fc8537) - Rust request-derived SQL injection.

### JavaScript and TypeScript

- [`df1a38f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/df1a38f) - JS unsafe `window.open` targets.
- [`8a8e9b5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/8a8e9b5) - JS unsafe JSX blank targets.
- [`b2e8509`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b2e8509) - JS unsanitized React HTML sinks.
- [`11651c6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/11651c6) - JS wildcard `postMessage` origins.
- [`2c81897`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2c81897) - JS JWT verification bypass.
- [`f3c36ec`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/f3c36ec) - TypeScript prototype pollution.
- [`039e94e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/039e94e) - TypeScript raw SQL injection.
- [`6cb0180`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/6cb0180) - TypeScript destructured route parameter taint.

### Python

- [`7bbee86`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7bbee86) - Python request-derived open redirects.
- [`1f3d436`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1f3d436) - Python SSRF-prone outbound URLs.
- [`b4c9cbb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b4c9cbb) - Python request-derived path traversal.
- [`0822f25`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0822f25) - Python interpolated SQL sinks.
- [`906edf6`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/906edf6) - Python shell command injection and cleanup follow-up.

### Cross-Language Security Families

- [`75ea78c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/75ea78c) - Go archive extraction traversal.
- [`008f1ef`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/008f1ef) - Java archive extraction traversal.
- [`0cae370`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/0cae370) - Ruby archive extraction traversal.
- [`39e40d7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/39e40d7) - Python header-derived path traversal.
- [`5310071`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/5310071) - Go SSRF taint sources.
- [`20e3fe7`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/20e3fe7) - C/C++ SSRF via curl URL sinks.
- [`968fb3a`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/968fb3a) - Rust open redirects.
- [`b78839c`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/b78839c) - Java/Kotlin response header injection.
- [`c554c3e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c554c3e) - C++ response header injection and TOON error clarity release.

### Secrets, JWT, CORS, and Cookies

- [`1044a09`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/1044a09) - JS hardcoded secret detector.
- [`c39b4b2`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c39b4b2) - Rust and Go AST-driven hardcoded secret detector.
- [`2911f58`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2911f58) - Elixir security randomness.
- [`41c507b`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/41c507b) - Java/Kotlin security randomness.
- [`7ad487e`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/7ad487e) - JS non-constant secret comparisons.
- [`52be770`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/52be770) - Go JWT verification bypass.
- [`d23de5d`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/d23de5d) - Rust JWT verification bypass.
- [`c823e4f`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/c823e4f) - JS JWT claim binding.
- [`2e44bb5`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/2e44bb5) - Go credentialed wildcard CORS.
- [`872ddeb`](https://github.com/Dicklesworthstone/ultimate_bug_scanner/commit/872ddeb) - Go insecure auth cookies.

## Tracker Workstreams Used

Closed Beads records that informed the synthesis:

- `ultimate_bug_scanner-4jg` - Lightweight taint analysis.
- `ultimate_bug_scanner-e3j` - Async error path coverage.
- `ultimate_bug_scanner-4sm` - Resource Lifecycle Packs.
- `ultimate_bug_scanner-4se` - Type Narrowing Full Coverage.
- `ultimate_bug_scanner-8d7` - Cross-language type narrowing heuristics.
- `ultimate_bug_scanner-stk` - TypeScript tsserver narrowing analyzer.
- `ultimate_bug_scanner-5wx` - Go lifecycle AST pack.
- `ultimate_bug_scanner-41t` - Python resource helper.
- `ultimate_bug_scanner-mma` - Python lifecycle AST migration.
- `ultimate_bug_scanner-xju` - Go resource lifecycle analysis fixes.
- `ultimate_bug_scanner-fbq` - Runner/installer ast-grep compatibility and PATH validation.
- `ultimate_bug_scanner-install-ast-grep-required` - Installer treats `ast-grep` as required.
- `ultimate_bug_scanner-js-ts-ast-guarantee` - JS/TS AST scanning guarantee.
- `ultimate_bug_scanner-js-highsev-ast-confirm` - JS/TS AST-confirm high-severity regex findings.
- `ultimate_bug_scanner-8vc` - CLI UX improvements.
- `ultimate_bug_scanner-1tc`, `ultimate_bug_scanner-2kp`, `ultimate_bug_scanner-9vy`, `ultimate_bug_scanner-psu` - TOON output and `tru` integration.
- `ultimate_bug_scanner-2yvh` - Bandit receives `.ubsignore` exclusions.
- `ultimate_bug_scanner-6q2`, `ultimate_bug_scanner-e3m`, `ultimate_bug_scanner-fln` - Installer checksum repair and smoke-test follow-ups.
- `ultimate_bug_scanner-1de` - Release workflow and security docs.

Open or in-progress records noted but not described as closed:

- `ultimate_bug_scanner-juh` - Secure distribution channel work.
- `ultimate_bug_scanner-2hga` - Robot docs JSON.
- `ultimate_bug_scanner-a6ca` - `ubs --schema` output.
- `ultimate_bug_scanner-rqf` - TOON variant for JSONL output.
- `ultimate_bug_scanner-3a6` / `legacy-3a6` - Automated `toon_rust` binary installation.

## Validation Checklist

- Scope window explicit: yes, `v5.1.2...v5.2.75`.
- Release vs tag split explicit: yes, latest GitHub Release `v5.2.61`; latest git tag `v5.2.75`.
- Representative commits live-linked: yes.
- Tracker workstreams included where available: yes.
- Changelog organized by capability waves: yes.
- Raw chronology retained through version-spine table: yes.
- Root clutter avoided: yes, research memo stored in `docs/reports/`.

## Next Changelog Pass

Before publishing the next GitHub Release, inspect `v5.2.62...v5.2.75` directly and decide whether release notes should summarize the tag-only SQL/JWT/CORS/proxy follow-up slice or whether a newer tag supersedes it.
