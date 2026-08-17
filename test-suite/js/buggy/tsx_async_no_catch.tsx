// GH #93 regression fixture: the js.async.* ast-grep rules must fire on .tsx
// files (language variants), not only on .js.
import { useEffect } from 'react';

export function Widget({ url }: { url: string }) {
  useEffect(() => {
    fetch(url)
      .then((r) => r.json())
      .then((d) => console.log(d));
  }, [url]);
  return <div />;
}
