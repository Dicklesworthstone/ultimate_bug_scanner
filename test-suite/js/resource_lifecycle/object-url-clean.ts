type PreviewHandle = {
  url: string;
  dispose: () => void;
};

export function buildPreviewHandle(bytes: Uint8Array): PreviewHandle {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  return {
    url,
    dispose() {
      URL.revokeObjectURL(url);
    },
  };
}

const preview = buildPreviewHandle(new Uint8Array([4, 5, 6]));
preview.dispose();
