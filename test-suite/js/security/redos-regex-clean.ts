type RequestLike = {
  query: Record<string, string | undefined>;
  nextUrl: { searchParams: URLSearchParams };
};

const FIXED_STATUS_PATTERN = /^(active|archived)$/;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function allowedRegexPattern(value: string): string {
  switch (value) {
    case "email":
      return "^[^@]+@example\\.com$";
    case "status":
      return "^(active|archived)$";
    default:
      throw new Error("unsupported pattern");
  }
}

export function escapedQueryPattern(req: RequestLike): RegExp {
  const raw = req.query.pattern ?? "";
  return new RegExp(escapeRegExp(raw), "i");
}

export function allowlistedPattern(request: RequestLike): RegExp {
  const raw = request.nextUrl.searchParams.get("kind") ?? "status";
  const pattern = allowedRegexPattern(raw);
  return new RegExp(pattern);
}

export function fixedPattern(): RegExp {
  return FIXED_STATUS_PATTERN;
}
