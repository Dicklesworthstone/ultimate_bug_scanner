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

const proxy = httpProxy.createProxyServer({});

export function proxyMiddlewareFromQuery(req: ExpressRequest) {
  const target = req.query.upstream;
  return createProxyMiddleware({
    target,
    changeOrigin: true,
  });
}

export function proxyWebFromHeader(req: ExpressRequest, res: ExpressResponse) {
  const upstreamUrl = req.headers["x-upstream"];
  proxy.web(req, res, {
    target: upstreamUrl,
  });
}

export function proxyRouterFromHeader() {
  return createProxyMiddleware({
    router: (req: ExpressRequest) => req.headers["x-proxy-target"],
  });
}

export function nextRewriteProxy(request: Request) {
  const rewriteUrl = new URL(request.url).searchParams.get("proxy");
  return NextResponse.rewrite(rewriteUrl!);
}
