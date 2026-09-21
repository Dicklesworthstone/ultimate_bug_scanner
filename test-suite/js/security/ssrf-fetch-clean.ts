import axios from "axios";
import got from "got";
import http from "http";

type ExpressRequest = {
  query: Record<string, string | undefined>;
  body: Record<string, string | undefined>;
  headers: Record<string, string | undefined>;
  hostname: string;
};

const ALLOWED_HOSTS = new Set(["api.example.com", "images.example.com"]);

function validateOutboundUrl(raw: string | null | undefined): string {
  const parsed = new URL(raw ?? "https://api.example.com/status");
  if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error("blocked outbound URL");
  }
  return parsed.toString();
}

function isAllowedUrl(raw: string | undefined): boolean {
  if (!raw) {
    return false;
  }
  const parsed = new URL(raw);
  return parsed.protocol === "https:" && ALLOWED_HOSTS.has(parsed.hostname);
}

export async function proxyQueryUrl(req: ExpressRequest): Promise<Response> {
  const targetUrl = validateOutboundUrl(req.query.url);
  return fetch(targetUrl, { signal: AbortSignal.timeout(5000) });
}

export function fetchPreview(request: Request): Promise<unknown> {
  const imageUrl = validateOutboundUrl(new URL(request.url).searchParams.get("image"));
  return axios.get(imageUrl);
}

export function postWebhook(req: ExpressRequest): Promise<unknown> {
  const callbackUrl = validateOutboundUrl(req.body.callbackUrl);
  return got(callbackUrl);
}

export function streamHeaderTarget(req: ExpressRequest): http.ClientRequest {
  const remoteEndpoint = req.headers["x-forward-to"];
  if (!isAllowedUrl(remoteEndpoint)) {
    throw new Error("blocked outbound URL");
  }
  return http.get(remoteEndpoint);
}

export function constantServiceCall(): Promise<unknown> {
  return axios.get("https://api.example.com/status");
}

export function proxyAllowedInboundHost(req: ExpressRequest): Promise<unknown> {
  const targetUrl = validateOutboundUrl(`https://${req.hostname}/status`);
  return axios.get(targetUrl);
}

export function proxyAllowedHostHeader(req: ExpressRequest): Promise<Response> {
  const host = req.headers.host;
  const targetUrl = validateOutboundUrl(`https://${host}/status`);
  return fetch(targetUrl, { signal: AbortSignal.timeout(5000) });
}
