import httpProxy from "http-proxy";
import { createProxyMiddleware } from "http-proxy-middleware";
import { NextResponse } from "next/server";

type ExpressRequest = {
  query: Record<string, string | undefined>;
  headers: Record<string, string | undefined>;
};

type ExpressResponse = {
  end(): void;
};

const allowedProxyHosts = new Set(["api.example.com", "static.example.com"]);
const proxy = httpProxy.createProxyServer({});

function validateProxyTarget(raw: string | null | undefined): string {
  const parsed = new URL(raw ?? "https://api.example.com/health");
  if (parsed.protocol !== "https:" || !allowedProxyHosts.has(parsed.hostname)) {
    throw new Error("blocked proxy target");
  }
  return parsed.toString();
}

function isAllowedProxyTarget(raw: string | undefined): boolean {
  if (!raw) {
    return false;
  }
  const parsed = new URL(raw);
  return parsed.protocol === "https:" && allowedProxyHosts.has(parsed.hostname);
}

export function proxyMiddlewareFromQuery(req: ExpressRequest) {
  const target = validateProxyTarget(req.query.upstream);
  return createProxyMiddleware({
    target,
    changeOrigin: true,
  });
}

export function proxyWebFromHeader(req: ExpressRequest, res: ExpressResponse) {
  const upstreamUrl = req.headers["x-upstream"];
  if (!isAllowedProxyTarget(upstreamUrl)) {
    throw new Error("blocked proxy target");
  }
  proxy.web(req, res, {
    target: upstreamUrl,
  });
}

export function proxyRouterFromHeader() {
  return createProxyMiddleware({
    router: (req: ExpressRequest) => validateProxyTarget(req.headers["x-proxy-target"]),
  });
}

export function nextRewriteProxy(request: Request) {
  const rewriteUrl = validateProxyTarget(new URL(request.url).searchParams.get("proxy"));
  return NextResponse.rewrite(rewriteUrl);
}
