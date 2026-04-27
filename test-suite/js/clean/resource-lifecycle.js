// Clean resource lifecycle sample
function buildPreviewUrl(bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'text/plain' }));
  return {
    url,
    dispose() {
      URL.revokeObjectURL(url);
    }
  };
}

const preview = buildPreviewUrl('hello');
preview.dispose();
