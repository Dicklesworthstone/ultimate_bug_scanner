# React Hooks Dependency Analysis TODO

## Research & Planning
- [x] Re-read Feature #3 section in PLAN to capture detection goals (useEffect/useMemo/useCallback, missing deps, stale closures, circular refs).
- [x] Define shared metadata arrays (HOOK_RULE_IDS, summary, remediation, severity) similar to async/resource helpers.

## Implementation (JavaScript/TypeScript module)
- [x] Add AST-based helper in `modules/ubs-js.sh` (e.g., `run_hooks_dependency_checks`).
- [x] Detect:
  - [x] Hooks that reference identifiers not listed in dependency array.
  - [x] Dependency arrays containing values not referenced (potential stale closures or mistakes).
  - [x] Inline functions without dependency array (e.g., `useEffect(() => {...})` missing second argument).
- [x] Ensure helper emits warnings with sample locations (similar Python summaries used elsewhere).
- [x] Wire helper at end of async/React-related category.

## Fixtures & Tests
- [x] Add buggy React hooks fixture demonstrating missing deps etc. under `test-suite/js/buggy/react_hooks.js`.
- [x] Add clean fixture with correct deps.
- [x] Update `test-suite/manifest.json` with new cases (buggy + clean) referencing `--only=js`.
- [x] Run targeted manifest cases for new fixtures.

## Verification & Follow-up
- [ ] Integrate helper invocation into README/docs if needed (mention capability).
- [x] Update TODO as tasks complete and summarize in final report.
