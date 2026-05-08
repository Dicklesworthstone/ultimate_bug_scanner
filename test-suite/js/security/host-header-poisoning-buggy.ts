type HeaderRequest = {
  headers: Record<string, string | undefined>;
  get(name: string): string | undefined;
};

type WebRequest = {
  headers: {
    get(name: string): string | null;
  };
};

type Mailer = {
  send(message: { to: string; html: string }): Promise<void>;
};

declare function headers(): { get(name: string): string | null };

export function passwordResetUrl(req: HeaderRequest, token: string): string {
  const host = req.headers.host ?? "app.example.com";
  return `https://${host}/reset?token=${token}`;
}

export function forwardedVerificationUrl(request: WebRequest, token: string): string {
  const forwardedHost = request.headers.get("x-forwarded-host");
  const host = forwardedHost || request.headers.get("host") || "";
  const verifyUrl = new URL(`/verify?token=${token}`, `https://${host}`).toString();
  return verifyUrl;
}

export async function sendResetEmail(req: HeaderRequest, mailer: Mailer, token: string): Promise<void> {
  const host = req.get("host") ?? "app.example.com";
  const resetLink = `https://${host}/account/reset?token=${token}`;
  await mailer.send({
    to: "user@example.com",
    html: `<a href="${resetLink}">Reset password</a>`,
  });
}

export function nextHeadersCanonicalUrl(pathname: string): string {
  const origin = `https://${headers().get("host")}`;
  return new URL(pathname, origin).toString();
}
