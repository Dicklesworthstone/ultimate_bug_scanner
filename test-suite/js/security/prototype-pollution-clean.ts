type RequestLike = {
  body: Record<string, unknown>;
  query: Record<string, string | undefined>;
  params: Record<string, string | undefined>;
  headers: { get(name: string): string | null };
  json(): Promise<Record<string, unknown>>;
};

declare function merge(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): Record<string, unknown>;

const bodySizeLimit = 1024 * 1024;

function stripPrototypeKeys(input: Record<string, unknown>): Record<string, unknown> {
  const clean = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(input)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    clean[key] = value;
  }
  return clean;
}

function safeMerge<T extends Record<string, unknown>>(target: T, source: Record<string, unknown>): T {
  const clean = stripPrototypeKeys(source);
  return Object.assign(target, clean);
}

function validatePrototypeKeys(rawKey: string | undefined): string {
  if (!rawKey || rawKey === "__proto__" || rawKey === "constructor" || rawKey === "prototype") {
    throw new Error("unsafe object key");
  }
  return rawKey;
}

export function assignSanitizedBody(req: RequestLike): Record<string, unknown> {
  const payload = stripPrototypeKeys(req.body);
  return Object.assign({}, payload);
}

export function safeMergeBody(req: RequestLike): Record<string, unknown> {
  return safeMerge({ theme: "light" }, req.body);
}

export async function mergeJsonRequest(request: RequestLike): Promise<Record<string, unknown>> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > bodySizeLimit) {
    throw new Error("payload too large");
  }

  const patch = stripPrototypeKeys(await request.json());
  return safeMerge({ enabled: true }, patch);
}

export function dynamicPropertyWrite(req: RequestLike): Record<string, unknown> {
  const key = validatePrototypeKeys(req.query.field);
  const value = req.params.value;
  const target: Record<string, unknown> = Object.create(null);
  target[key] = value;
  return target;
}

export function reviewedInlineMerge(req: RequestLike): Record<string, unknown> {
  return Object.assign({}, req.body); // ubs:ignore -- reviewed compatibility boundary
}

export function reviewedPreviousLineMerge(req: RequestLike): Record<string, unknown> {
  // ubs:ignore -- reviewed compatibility boundary
  return merge({}, req.query);
}
