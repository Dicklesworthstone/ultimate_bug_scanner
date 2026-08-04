import fs from "node:fs";
import path from "node:path";

// Positive control for GH #77: entries with real archive-library provenance
// (adm-zip require + getEntries()) joined into destinations must be reported
// even without TypeScript archive types on the bindings.
const AdmZip = require("adm-zip");

export function extractAll(archivePath: string, destination: string): void {
  const zip = new AdmZip(archivePath);
  for (const entry of zip.getEntries()) {
    const entryPath = entry.entryName;
    const outputPath = path.join(destination, entryPath);
    fs.writeFileSync(outputPath, entry.getData());
  }
}
