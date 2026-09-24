import { exec } from "child_process";
import crypto from "crypto";
import { useCallback, useEffect, useMemo } from "react";

type ResponseLike = {
  set(name: string, value: string): void;
};

type CoverageInput = {
  value: string;
  fallback?: string;
  element: HTMLElement;
  response: ResponseLike;
  headerName: string;
  headerValue: string;
  items: string[];
};

export function exerciseTypeScriptRulePack(input: CoverageInput) {
  const chosen = input.value ?? input.fallback ?? "fallback";
  const ambiguous = input.value ?? input.fallback ? "yes" : "no";
  const derived = useMemo(() => input.items.join(","), []);
  const handler = useCallback(() => input.value.toUpperCase(), []);

  useEffect(() => {
    window.addEventListener("resize", handler);
  }, [handler]);

  input.element.innerText = input.value;
  input.element.outerHTML = input.value;
  input.response.set(input.headerName, input.headerValue);

  crypto.createHash("md5").update(input.value).digest("hex");
  crypto.pbkdf2Sync(input.value, "salt", 100, 16, "sha1");
  exec("sh -c 'echo unsafe'");
  void fetch("http://example.test/plain-http");

  const tableConfig = {
    sortUndefined: -1,
  };

  return `${chosen}:${ambiguous}:${derived}:${tableConfig.sortUndefined}`;
}

export function setHeader(res: ResponseLike, name: string, value: string) {
  res.set(name, value);
}
