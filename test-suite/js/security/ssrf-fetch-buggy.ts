import axios from "axios";
import got from "got";
import http from "http";
import https from "https";

type ExpressRequest = {
  query: Record<string, string | undefined>;
  body: Record<string, string | undefined>;
  headers: Record<string, string | undefined>;
  hostname: string;
};

export async function proxyQueryUrl(req: ExpressRequest): Promise<Response> {
  const targetUrl = req.query.url;
  return fetch(targetUrl!, { signal: AbortSignal.timeout(5000) });
}

export function fetchPreview(request: Request): Promise<unknown> {
  const imageUrl = new URL(request.url).searchParams.get("image");
  return axios.get(imageUrl!);
}

export function postWebhook(req: ExpressRequest): Promise<unknown> {
  const callbackUrl = req.body.callbackUrl;
  return got(callbackUrl!);
}

export function streamHeaderTarget(req: ExpressRequest): http.ClientRequest {
  const remoteEndpoint = req.headers["x-forward-to"];
  return http.get(remoteEndpoint!);
}

export function nextRouteProxy(request: {
  nextUrl: { searchParams: URLSearchParams };
}): Promise<Response> {
  return fetch(request.nextUrl.searchParams.get("target")!, {
    signal: AbortSignal.timeout(5000),
  });
}

export function rawHttpsProxy(req: ExpressRequest): https.ClientRequest {
  return https.request(req.query.callback!);
}

export function proxyInboundHost(req: ExpressRequest): Promise<unknown> {
  const targetUrl = `https://${req.hostname}/internal/status`;
  return axios.get(targetUrl);
}

export function proxyHostHeader(req: ExpressRequest): Promise<Response> {
  const host = req.headers.host;
  return fetch(`https://${host}/internal/status`, {
    signal: AbortSignal.timeout(5000),
  });
}
