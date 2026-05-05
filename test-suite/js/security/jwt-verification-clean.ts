import jwt from "jsonwebtoken";
import { verify as verifyToken } from "jsonwebtoken";
import { jwtVerify } from "jose";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "api";

export function verifyJsonwebtoken(token: string, publicKey: string): string | object {
  return jwt.verify(token, publicKey, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
  });
}

export function verifyAliased(token: string, publicKey: string): string | object {
  return verifyToken(token, publicKey, {
    algorithms: ["HS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
  });
}

export async function verifyJose(token: string, publicKey: CryptoKey): Promise<unknown> {
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: ISSUER,
    audience: AUDIENCE,
  });
  return payload;
}

export function documentationMentionsDoNotCount(): number {
  const decodeExample = "jwt.decode(token)";
  const unsafeVerifyExample = "jwt.verify(token, key, { ignoreExpiration: true })";
  /*
   * These strings document unsafe examples; they are not executable verifier calls.
   * jwt.verify(token, key, { algorithms: ["none"] })
   */
  return decodeExample.length + unsafeVerifyExample.length;
}
