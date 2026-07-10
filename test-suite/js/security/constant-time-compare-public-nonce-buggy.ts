// Buggy counterpart to the issue #61 regression fixture
// (constant-time-compare-public-nonce-clean.ts).
//
// The clean fixture proves the "Secret/token comparisons without timing-safe
// equality" check stays quiet on public correlation nonces (different-concept
// comparisons) and on names tainted only by string-literal contents. This
// fixture proves the narrowing did NOT swallow the true positives closest to
// those shapes: a nonce-vs-nonce (SAME concept) equality check and a
// taint-backed one-sided secret comparison must both still fire.

import crypto from "crypto";

// SAME-concept comparison: sessionNonce vs expectedNonce are both the "nonce"
// concept, so unlike doneToken !== sessionNonce (token vs nonce, clean), this
// must be flagged as a secret self-comparison done without timing-safe
// equality.
export function nonceReplayCheck(sessionNonce: string, expectedNonce: string): boolean {
  return sessionNonce === expectedNonce;
}

// SAME-concept comparison in the token family (mirrors the clean fixture's
// doneToken, but compared against another token rather than a nonce).
export function doneTokenCheck(doneToken: string, expectedToken: string): boolean {
  if (doneToken !== expectedToken) {
    return false;
  }
  return true;
}

// Data-flow taint: `derived` is assigned from an HMAC digest, so even a
// one-sided comparison against an innocently-named variable must fire. The
// #61 narrowing only applies to purely name-based (no-taint) two-sided
// comparisons.
export function webhookDigestCheck(payload: string, signingSecret: string, provided: string): boolean {
  const derived = crypto.createHmac("sha256", signingSecret).update(payload).digest("hex");
  return derived === provided;
}
