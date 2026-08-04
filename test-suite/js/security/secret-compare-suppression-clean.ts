// GH #84: a trailing ubs:ignore marker must remove the suppressed finding
// from totals, per-severity counts, and the exit code -- not merely elide the
// locator line from the report. The detector used to test the marker against
// comment-stripped text, so a trailing "// ubs:ignore" was counted anyway.
export function verifyToken(token: string, expectedToken: string): boolean {
  if (token !== expectedToken) { // ubs:ignore -- deliberate: not a secret comparison
    return false;
  }
  return true;
}
