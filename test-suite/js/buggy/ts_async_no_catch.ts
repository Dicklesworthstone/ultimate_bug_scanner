// GH #93 regression fixture: the js.async.* ast-grep rules must fire on .ts
// files (language variants), not only on .js.
export function loadConfig(onData: (d: unknown) => void): void {
  fetch('/api/config')
    .then((r) => r.json())
    .then((data) => onData(data));
}
