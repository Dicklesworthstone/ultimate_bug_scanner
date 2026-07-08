import crypto from "crypto";

type RequestLike = {
  headers: Record<string, string | undefined>;
  body: {
    csrfToken?: string;
  };
};

type User = {
  resetToken: string;
};

export function webhookSignatureCheck(req: RequestLike, body: string, signingSecret: string): boolean {
  const expectedSignature = crypto.createHmac("sha256", signingSecret).update(body).digest("hex");
  const providedSignature = req.headers["x-signature"] ?? "";
  return providedSignature === expectedSignature;
}

export function apiKeyCheck(requestApiKey: string, storedApiKey: string): boolean {
  if (requestApiKey !== storedApiKey) {
    return false;
  }
  return true;
}

export function csrfTokenCheck(req: RequestLike, sessionCsrfToken: string): boolean {
  return req.body.csrfToken == sessionCsrfToken;
}

export function passwordResetCheck(token: string, user: User): boolean {
  return token === user.resetToken;
}

export function bearerTokenCheck(req: RequestLike, expectedToken: string): boolean {
  return req.headers.authorization === expectedToken;
}

export function legacyInequalityCheck(token: string, user: User): boolean {
  return token != user.resetToken;
}

// Regression guard for issue #61: a real self-comparison of the SAME secret
// concept on both sides (token vs token) must still be flagged, even after the
// public-nonce (token vs nonce) false positive was narrowed away.
export function sessionTokenCheck(userToken: string, validToken: string): boolean {
  return userToken === validToken;
}
