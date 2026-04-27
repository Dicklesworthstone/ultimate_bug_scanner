type ExportPayload = {
  bytes: Uint8Array;
  filename: string;
};

export function downloadExport(payload: ExportPayload): string {
  const blob = new Blob([payload.bytes], { type: "application/octet-stream" });
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = href;
  link.download = payload.filename;
  link.click();
  return href;
}

downloadExport({ bytes: new Uint8Array([1, 2, 3]), filename: "export.bin" });
