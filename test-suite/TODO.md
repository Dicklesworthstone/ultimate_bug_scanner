# Test Suite TODO

- [x] Define manifest schema for UBS cases (paths, args, expectations, skip reasons).
- [x] Implement manifest-driven runner (`test-suite/run_manifest.py`) that executes UBS, parses JSON, and enforces expectations.
- [x] Seed manifest with JS coverage (core buggy/clean, framework scenarios, realistic cases) using `--only=js` where appropriate.
- [x] Connect the new runner to developer workflow (document usage in `test-suite/README.md`, wire optional helper script).
- [x] Capture run artifacts per case (stdout/stderr, parsed summary) to simplify debugging failed scanners.
- [x] Add substring/rule-id requirement checks so we can prove specific categories fire.
- [x] Extend manifest to Python fixtures once parser stabilizes; include both `test-suite/python/buggy` and `python/clean` directories.
- [x] Extend manifest to Go, Rust, C++, Java, Ruby fixtures in `test-suite/<lang>/`.
- [x] Investigate why `modules/ubs-js.sh` sometimes reports `Files scanned: 0` even when files exist.
- [x] Add threshold coverage for edge-case fixtures (unicode, floating-point, timezone).
- [x] Wire manifest runner into CI once other modules catch up.

## Resource lifecycle fixtures (ultimate_bug_scanner-6ig)
- [x] Investigate `modules/ubs-python.sh` single-file runs (resource_lifecycle) reporting zero files/warnings. _(Confirmed manifest case now reports `Files: 1` and warning threshold fires.)_
- [x] Do the same for Go and Java fixtures (confirm detection logic). _(Go fix required updating `ubs` parser fallback to capture `Files:` lines without “source files”; Java already non-zero.)_
- [x] Restore warnings so `--fail-on-warning` triggers and manifest passes. _(All three resource-lifecycle cases re-run via `run_manifest.py --fail-fast`.)_

## Non-JS manifest expansion & docs (ultimate_bug_scanner-ny5)
- [x] Update `test-suite/README.md` with a multi-language overview, manifest instructions, and tables listing every language’s buggy/clean directories.
  - [x] Add a quick-start matrix covering JS, Python, Go, C++, Rust, Java, and Ruby fixtures plus their expected categories.
  - [x] Document how `run_manifest.py` and `run_all.sh` interact so new contributors know which tool to run.
- [x] Flesh out per-language READMEs with file-level descriptions modeled after the JS documentation.
- [x] Expand fixture coverage in each non-JS directory to cover multiple categories (security, resource lifecycle, async, math/precision where applicable) with clean counterparts.
  - [x] Python: add security + precision fixtures (buggy & clean) and describe them in README.
  - [x] Go: add security/performance fixtures and README notes.
  - [x] C++: add unsafe string/math fixtures and README notes.
  - [x] Rust: add security/math fixtures and README notes.
  - [x] Java: add security fixture pair and README notes.
  - [x] Ruby: add performance/concurrency fixture pair and README notes.
- [x] Add manifest coverage for every language’s `buggy` and `clean` directories (cpp/rust/java/ruby still missing) with severity thresholds + substring checks for signature sections.
- [x] Add manifest cases for JS edge-case directories (unicode/timezone/floating-point) with warning thresholds so regressions surface.
- [x] Extend manifest expectations to include category substrings for the new cases so we prove specific analyzers fire.
- [x] Update `run_all.sh` to delegate to `run_manifest.py` (or drive manifest cases directly) instead of running bare directory scans.
- [x] Run the refreshed manifest end-to-end, capture artifacts, and record the date/result in `notes/` for future baselines.

## JS clean fixture follow-ups
- [x] Replace the remaining regex heuristics (async error coverage, try/finally bookkeeping, DOM listener cleanup) with ast-grep rules so clean fixtures run with zero warnings rather than noisy false positives.
- [ ] When the ast-grep coverage lands, restore the JS clean manifest case to run the full category set (no selective skipping) so we keep parity with real-world scans.

_Last updated: 2025-11-17 03:25 UTC_
