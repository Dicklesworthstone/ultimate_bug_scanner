type HeaderRequest = {
  headers: Record<string, string | undefined>;
  get(name: string): string | undefined;
};

type WebRequest = {
  headers: {
    get(name: string): string | null;
  };
};

const PUBLIC_BASE_URL = "https://app.example.com";
const ALLOWED_HOSTS = new Set(["app.example.com", "accounts.example.com"]);

function trustedOriginFromHost(rawHost: string | null | undefined): string {
  const host = rawHost ?? "";
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error("untrusted host");
  }
  return `https://${host}`;
}

export function passwordResetUrl(_req: HeaderRequest, token: string): string {
  return new URL(`/reset?token=${token}`, PUBLIC_BASE_URL).toString();
}

export function forwardedVerificationUrl(request: WebRequest, token: string): string {
  const forwardedHost = request.headers.get("x-forwarded-host");
  const rawHost = forwardedHost || request.headers.get("host");
  const origin = trustedOriginFromHost(rawHost);
  return new URL(`/verify?token=${token}`, origin).toString();
}

export function canonicalUrlFromConfig(pathname: string): string {
  return new URL(pathname, PUBLIC_BASE_URL).toString();
}

export function auditRequestHost(req: HeaderRequest): boolean {
  const host = req.headers.host || "";
  return host.length > 0;
}

export function literalHostAfterAudit(pathname: string): string {
  const host = "app.example.com";
  return `https://${host}${pathname}`;
}
