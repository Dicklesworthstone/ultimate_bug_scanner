// GH #84: without an inline suppression marker, the timing-unsafe token
// comparison below must be reported AND counted (totals + exit code).
export function verifyToken(token: string, expectedToken: string): boolean {
  if (token !== expectedToken) {
    return false;
  }
  return true;
}
