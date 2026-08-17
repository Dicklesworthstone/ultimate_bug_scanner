// GH #91 regression fixture: every documented ubs:ignore placement must
// actually suppress the secret-comparison finding.

// Placement 1: marker on the line immediately above a multi-line statement.
export function checkTokenPrev(userToken: string, expectedToken: string): boolean {
  // ubs:ignore -- public correlation id, not a secret.
  const matches =
    userToken === expectedToken;
  return matches;
}

// Placement 2: formatter-relocated marker — trailing marker on a block-opening
// line moved to the first line inside the block (oxfmt/prettier style).
export function checkTokenBlock(userToken: string, expectedToken: string): void {
  if (userToken !== expectedToken) {
    // ubs:ignore -- public correlation id, not a secret.
    throw new Error('mismatch');
  }
}

// Placement 3: classic trailing marker on the flagged line itself.
export function checkTokenTrailing(userToken: string, expectedToken: string): boolean {
  return userToken === expectedToken; // ubs:ignore -- public correlation id, not a secret.
}
