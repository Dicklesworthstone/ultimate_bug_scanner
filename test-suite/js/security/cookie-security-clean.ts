import cookie from "cookie";
import { NextResponse } from "next/server";

type ResponseLike = {
  cookie(name: string, value: string, options?: Record<string, unknown>): void;
  setHeader(name: string, value: string): void;
};

export function expressSafeSession(res: ResponseLike, sessionId: string): void {
  res.cookie("session_id", sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
}

export function expressSafeCrossSite(res: ResponseLike, token: string): void {
  res.cookie("auth_token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
}

export function nextResponseSafe(token: string): NextResponse {
  const response = NextResponse.json({ ok: true });
  response.cookies.set("refresh_token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  return response;
}

export function nextResponseObjectFormSafe(token: string): NextResponse {
  const response = NextResponse.json({ ok: true });
  response.cookies.set({
    name: "login_token",
    value: token,
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  return response;
}

export function rawSetCookieHeader(res: ResponseLike, jwt: string): void {
  res.setHeader("Set-Cookie", `jwt=${jwt}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

export function serializedCookie(token: string): string {
  return cookie.serialize("access_token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
}
