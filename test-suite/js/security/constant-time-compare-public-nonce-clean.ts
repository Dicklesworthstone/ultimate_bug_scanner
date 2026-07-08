// Regression fixture for issue #61.
//
// The "Secret/token comparisons without timing-safe equality" check must NOT
// fire on:
//   (a) a comparison of two DIFFERENT sensitive concepts that is really a
//       public correlation nonce (doneToken !== sessionNonce), and
//   (b) an UNRELATED variable that is only "sensitive" because a sensitive
//       word appears inside a string literal elsewhere in the file
//       (file-wide name taint via literal contents).
//
// Both are false positives: no secret is being compared, and
// crypto.timingSafeEqual() has no role to play for values that are exchanged
// in the clear on both sides.

// A public, non-secret correlation nonce: printed into an agent's prompt and
// echoed back into an output file to detect stale-session crosstalk.
export function nonce(rand: () => number): string {
  let s = "";
  for (let i = 0; i < 12; i++) s += "0123456789abcdef"[Math.floor(rand() * 16)];
  return `onx-${s}`;
}

export function pointerPrompt(nonceValue: string): string {
  // Deliberately public: this text is sent verbatim into the agent's prompt.
  return `Completion token: ${nonceValue}`;
}

interface ScoreOpts {
  sessionNonce: string;
}

export function scoreDone(doneToken: string | null, opts: ScoreOpts): string {
  // (a) doneToken (a bearer-token concept) vs sessionNonce (a nonce concept):
  //     different concepts, so this is not a secret self-comparison.
  if (doneToken !== opts.sessionNonce) {
    return "stale-session mismatch";
  }
  return "ok";
}

export function validateBlocked(parsed: Record<string, unknown>): string[] {
  // The string literal "completion_token" must NOT taint the name `allowed`.
  const allowed = new Set(["reason", "needs", "completion_token", "partial"]);
  const errs: string[] = [];
  for (const k of Object.keys(parsed)) if (!allowed.has(k)) errs.push(`unexpected key '${k}'`);
  return errs;
}

export function checkType(t: string | string[], value: unknown): boolean {
  // (b) `allowed` here shares only a NAME with the Set above; comparing
  //     `a === actual` has nothing to do with any token.
  const allowed: string[] = Array.isArray(t) ? t : [t];
  const actual = typeof value;
  return allowed.some((a) => a === actual);
}
