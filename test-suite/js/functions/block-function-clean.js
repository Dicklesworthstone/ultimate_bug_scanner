// Clean control for GH #72: module-scope function declarations whose names
// merely CONTAIN "for"/"if"/"while" substrings (formatCurrencyShort,
// classifyRecord, verifyRun) must not be reported as block declarations.
export function formatCurrencyShort(amount) {
  return `$${(amount / 100).toFixed(2)}`;
}

export function classifyRecord(record) {
  return record.total > 0 ? "credit" : "debit";
}

export function verifyRun(run) {
  return Boolean(run && run.completedAt);
}

export function formatValue(value) {
  return String(value);
}

export function classifyValue(value) {
  return typeof value;
}

export function whileLabel(count) {
  return `${count} remaining`;
}

export function ifCaption(enabled) {
  const render = function caption() {
    return enabled ? "on" : "off";
  };
  return render();
}
