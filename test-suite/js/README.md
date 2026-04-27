# JavaScript/TypeScript UBS Mini Suite

- `buggy/security.js` contains eval, innerHTML, and missing error handling.
- `clean/security.js` shows the safe equivalents.
- `buggy/resource-lifecycle.js` and `clean/resource-lifecycle.js` cover browser resource cleanup, including Blob/Object URL revocation.
- `async_errors/async-foreach-*.ts` covers TypeScript async loops that accidentally pass an `async` callback to `forEach`, which cannot be awaited by the caller.
- `async_errors/promise-all-map-*.ts` covers TypeScript `Promise.all(ids.map(...))` calls where a block-bodied `map` callback forgets to return the promise.
- `async_errors/use-effect-async-*.tsx` covers TypeScript/React effects that accidentally return a Promise by passing an async callback directly to `useEffect`.
- `security/dangerously-set-html-*.tsx` covers TypeScript/React XSS risk from unsanitized `dangerouslySetInnerHTML`.
- `security/message-event-origin-*.ts` covers TypeScript cross-origin message receivers that trust `event.data` without validating `event.origin`.
- `security/post-message-*.ts` covers TypeScript cross-origin messaging leaks from wildcard `postMessage` target origins.
- `security/target-blank-*.tsx` covers TypeScript/React reverse-tabnabbing protection for JSX `target="_blank"` links.
- `security/window-open-*.ts` covers TypeScript reverse-tabnabbing protection for `window.open(..., "_blank")`.
- `resource_lifecycle/object-url-*.ts` covers TypeScript Blob/Object URL cleanup regression samples.
- These smaller samples complement the full `test-suite/buggy` / `clean` collections and are used by the automated runner.
