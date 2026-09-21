import { exec } from "child_process";
import crypto from "crypto";
import React, { useCallback, useEffect, useMemo } from "react";

type ResponseLike = {
  set(name: string, value: string): void;
};

type Props = {
  value: string;
  fallback?: string;
  headerName: string;
  headerValue: string;
  element: HTMLElement;
  items: Array<{ id: string; label: string }>;
};

export function AstGrepRulePackCoverage(props: Props) {
  const chosen = props.value ?? props.fallback ?? "fallback";
  const ambiguous = (props.value ?? props.fallback) ? "yes" : "no";
  const derived = useMemo(() => props.items.map((item) => item.label).join(","), []);
  const stableHandler = useCallback(() => props.value.toUpperCase(), []);

  useEffect(() => {
    window.addEventListener("resize", stableHandler);
  }, [stableHandler]);

  props.element.innerText = props.value;
  props.element.outerHTML = props.value;

  crypto.createHash("md5").update(props.value).digest("hex");
  crypto.pbkdf2Sync(props.value, "salt", 100, 16, "sha1");
  exec("sh -c 'echo unsafe'");
  void fetch("http://example.test/plain-http");

  const tableConfig = {
    sortUndefined: -1,
  };

  return (
    <section data-choice={ambiguous} data-table={tableConfig.sortUndefined}>
      <ul>
        {props.items.map((item) => (
          <MissingKeyRow label={item.label} />
        ))}
      </ul>
      <span>{chosen}</span>
      <span>{derived}</span>
    </section>
  );
}

function MissingKeyRow(props: { label: string }) {
  return <li>{props.label}</li>;
}

export function setHeader(res: ResponseLike, name: string, value: string) {
  res.set(name, value);
}

export class RenderLoop extends React.Component {
  render() {
    this.setState(null);
    return <div key="render-loop" />;
  }
}
