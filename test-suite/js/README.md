# JavaScript/TypeScript UBS Mini Suite

- `buggy/security.js` contains eval, innerHTML, and missing error handling.
- `clean/security.js` shows the safe equivalents.
- `buggy/resource-lifecycle.js` and `clean/resource-lifecycle.js` cover browser resource cleanup, including Blob/Object URL revocation.
- `resource_lifecycle/object-url-*.ts` covers TypeScript Blob/Object URL cleanup regression samples.
- These smaller samples complement the full `test-suite/buggy` / `clean` collections and are used by the automated runner.
