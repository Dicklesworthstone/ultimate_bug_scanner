// GH #92 regression fixture: a multi-line .then() chain that DOES end in
// .catch() must stay clean under --fail-on-warning, and a bare `.then(`
// mention in a comment must never count as an unhandled promise.
export function loadConfig(onData) {
  fetch('/api/config', { signal: AbortSignal.timeout(5000) })
    .then((r) => r.json())
    .then((data) => onData(data))
    .catch((err) => console.error('load failed', err));
}
