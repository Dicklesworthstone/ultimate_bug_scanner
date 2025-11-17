# Lightweight Taint Analysis TODO

## Research & Planning
- [x] Re-read Feature #4 section to enumerate sources, sinks, sanitizers.
- [x] Decide initial language scope (start with JS; list future targets for Python/Ruby/etc.).
- [x] Define metadata structures similar to async/hooks helpers (TAINT_RULE_IDS, summary, remediation, severity).

## Implementation (Phase 1: JS/Python)
- [x] Implement taint helper `run_taint_analysis_checks` in `modules/ubs-js.sh`:
  - [x] Detect taint sources (req.body, req.query, window.location, event.target.value, localStorage, FormData).
  - [x] Track flows through assignments, template literals, function args/returns (lightweight heuristics).
  - [x] Match sinks (innerHTML, document.write, eval, Function, exec, db.query, child_process.exec, etc.).
  - [x] Respect simple sanitizers (DOMPurify.sanitize, escapeHtml, parameterized SQL).
  - [x] Emit findings with source→sink path descriptions.
- [x] Mirror the helper in `modules/ubs-python.sh` (Flask/Django/FastAPI sources + cursor/subprocess/eval sinks).
- [x] Hook helpers into each language's security category so the output references "Lightweight taint analysis".

## Implementation (Phase 2: Remaining languages)
- [ ] Golang module (`modules/ubs-golang.sh`):
  - [x] Add metadata + helper skeleton.
  - [x] Create buggy/clean fixtures + manifest cases.
  - [ ] Fix clean-case false positive (parameterized `db.Exec("...?", args...)` still reported).
- [ ] Rust module: add helper + fixtures (sources: `req.body`, `std::env::var`; sinks: `HttpResponse::body`, `Command::new`, Diesel raw SQL).
- [ ] Java module: add helper + fixtures (servlet `request.getParameter`, `response.getWriter().print`, JDBC `Statement.execute`, `Runtime.exec`).
- [ ] Ruby module: add helper + fixtures (Rails `params`, ERB `render inline`, `` `cmd` ``/`system`, ActiveRecord interpolated SQL).

## Fixtures & Testing
- [x] JS: buggy + clean fixtures and manifest coverage.
- [x] Python: buggy + clean fixtures and manifest coverage.
- [x] JS/Python manifest runs (now green after meta-runner fix).
- [x] Golang fixtures/manifests created.
- [ ] Golang manifest clean case failing (needs helper tuning before marking done).
- [ ] Rust/Java/Ruby fixtures + manifest cases (pending helper work).

## Documentation & Follow-up
- [x] Mention new taint capability in README/test-suite docs.
- [x] Outline plan for expanding to other languages (TODO in doc).
- [ ] Update docs once Go/Rust/Java/Ruby helpers + manifests land.

## Expansion Roadmap
- [x] Python helper implemented (baseline coverage for Flask/Django patterns).
- [ ] Go helper tuning (clean manifest still noisy).
- [ ] Rust helper + fixtures.
- [ ] Java helper + fixtures.
- [ ] Ruby helper + fixtures.
