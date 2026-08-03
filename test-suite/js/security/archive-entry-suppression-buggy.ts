import fs from "node:fs";
import path from "node:path";

type TarHeader = {
  name: string;
};

// Control for GH #77: without an inline suppression the archive entry joined
// into the extraction destination must still be reported.
export function extractEntry(header: TarHeader, destination: string, contents: Buffer): void {
  const outputPath = path.join(destination, header.name);
  fs.writeFileSync(outputPath, contents);
}
