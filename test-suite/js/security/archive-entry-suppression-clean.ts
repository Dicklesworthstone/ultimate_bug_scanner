import fs from "node:fs";
import path from "node:path";

type TarHeader = {
  name: string;
};

// GH #77: the documented inline suppression has to silence the archive
// entry-path finding. The detector used to strip comments before testing for
// the marker, so a trailing "ubs:ignore" could never be seen.
export function extractEntry(header: TarHeader, destination: string, contents: Buffer): void {
  const outputPath = path.join(destination, header.name); // ubs:ignore -- entry names are validated upstream
  fs.writeFileSync(outputPath, contents);
}
