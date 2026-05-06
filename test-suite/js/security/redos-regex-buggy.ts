type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, string | undefined>;
  nextUrl: { searchParams: URLSearchParams };
};

export function queryPattern(req: RequestLike): RegExp {
  const pattern = req.query.pattern ?? "";
  return new RegExp(pattern, "i");
}

export function nextSearchPattern(request: RequestLike): RegExp {
  const raw = request.nextUrl.searchParams.get("filter") ?? "";
  return RegExp(raw);
}

export function destructuredBodyPattern(req: RequestLike): RegExp {
  const { matcher } = req.body;
  return new RegExp(matcher ?? ".*");
}

export function templateInterpolatedPattern(req: RequestLike): RegExp {
  const pattern = req.query.prefix ?? "";
  return new RegExp(`^${pattern}:[a-z0-9_-]+$`);
}
