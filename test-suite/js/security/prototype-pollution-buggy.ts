type RequestLike = {
  body: Record<string, unknown>;
  query: Record<string, string | undefined>;
  params: Record<string, string | undefined>;
  json(): Promise<Record<string, unknown>>;
};

declare function merge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown>;
declare const lodash: {
  merge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown>;
  defaultsDeep(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown>;
};

export function assignBodyIntoConfig(req: RequestLike): Record<string, unknown> {
  const payload = req.body;
  return Object.assign({}, payload);
}

export function lodashMergeBody(req: RequestLike): Record<string, unknown> {
  const preferences = req.body;
  return lodash.merge({ theme: "light" }, preferences);
}

export function defaultsFromQuery(req: RequestLike): Record<string, unknown> {
  const defaults = req.query;
  return lodash.defaultsDeep({}, defaults);
}

export async function mergeJsonRequest(request: RequestLike): Promise<Record<string, unknown>> {
  const patch = await request.json();
  return merge({ enabled: true }, patch);
}

export function dynamicPropertyWrite(req: RequestLike): Record<string, unknown> {
  const key = req.query.field;
  const value = req.params.value;
  const target: Record<string, unknown> = {};
  target[key ?? "name"] = value;
  return target;
}

export function unsuppressedInlineMergeControl(req: RequestLike): Record<string, unknown> {
  return Object.assign({}, req.body);
}

export function unsuppressedPreviousLineMergeControl(req: RequestLike): Record<string, unknown> {
  return merge({}, req.query);
}
