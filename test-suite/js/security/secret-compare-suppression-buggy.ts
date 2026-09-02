// GH #84: without an inline suppression marker, the timing-unsafe token
// comparison below must be reported AND counted (totals + exit code).
export function verifyToken(authToken: string, expectedAuthToken: string): boolean {
  if (authToken !== expectedAuthToken) {
    return false;
  }
  return true;
}
