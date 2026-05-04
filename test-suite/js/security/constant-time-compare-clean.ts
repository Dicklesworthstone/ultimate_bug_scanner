import crypto from "crypto";

type RequestLike = {
  headers: Record<string, string | undefined>;
};

type User = {
  resetToken: string;
};

function timingSafeStringEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function webhookSignatureCheck(req: RequestLike, body: string, signingSecret: string): boolean {
  const expectedSignature = crypto.createHmac("sha256", signingSecret).update(body).digest("hex");
  const providedSignature = req.headers["x-signature"] ?? "";
  return timingSafeStringEqual(providedSignature, expectedSignature);
}

export function apiKeyCheck(requestApiKey: string, storedApiKey: string): boolean {
  return timingSafeStringEqual(requestApiKey, storedApiKey);
}

export function passwordResetCheck(token: string, user: User): boolean {
  return timingSafeStringEqual(token, user.resetToken);
}

export function publicIdentifierCheck(userId: string, expectedUserId: string): boolean {
  return userId === expectedUserId;
}

export function tokenShapeCheck(token: string): boolean {
  return token.length === 32;
}

export function statusCheck(status: string, expectedStatus: string): boolean {
  return status === expectedStatus;
}
