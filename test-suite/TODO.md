# Test Suite TODO

- [x] Define manifest schema for UBS cases (paths, args, expectations, skip reasons).
- [x] Implement manifest-driven runner (`test-suite/run_manifest.py`) that executes UBS, parses JSON, and enforces expectations.
- [x] Seed manifest with JS coverage (core buggy/clean, framework scenarios, realistic cases) using `--only=js` where appropriate.
- [x] Connect the new runner to developer workflow (document usage in `test-suite/README.md`, wire optional helper script).
- [x] Capture run artifacts per case (stdout/stderr, parsed summary) to simplify debugging failed scanners.
- [ ] Add substring/rule-id requirement checks so we can prove specific categories fire.
- [ ] Extend manifest to Python fixtures once parser stabilizes; include both `test-suite/python/buggy` and `python/clean` directories.
- [ ] Extend manifest to Go, Rust, C++, Java, Ruby fixtures in `test-suite/<lang>/`.
- [ ] Investigate why `modules/ubs-js.sh` sometimes reports `Files scanned: 0` even when files exist.
- [ ] Add threshold coverage for edge-case fixtures (unicode, floating-point, timezone).
- [ ] Wire manifest runner into CI once other modules catch up.
