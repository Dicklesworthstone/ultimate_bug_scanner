import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// Negative control for GH #77: a directory walk over fs.readdirSync Dirent
// entries is not archive extraction. Bindings merely NAMED entry/file must not
// be treated as archive sources without archive-library provenance.
export function walkTree(root: string): string[] {
  const collected: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const candidate = join(root, entry.name);
    if (entry.isDirectory()) {
      collected.push(...walkTree(candidate));
    } else {
      collected.push(candidate);
    }
  }
  return collected;
}

export function newestFile(root: string): string | null {
  let newest: string | null = null;
  let newestMtime = 0;
  for (const file of readdirSync(root)) {
    const candidate = join(root, file);
    const info = statSync(candidate);
    if (info.mtimeMs > newestMtime) {
      newestMtime = info.mtimeMs;
      newest = candidate;
    }
  }
  return newest;
}
