// Resource lifecycle regression sample
const notifier = {
  start() {
    document.addEventListener('visibilitychange', () => {
      console.log('changed');
    });
    const timerId = setInterval(() => console.log('tick'), 1000);
    this.timerId = timerId;
  }
};

notifier.start();

const observer = new MutationObserver(() => {});
observer.observe(document.body, { childList: true });

function exportReport(blob) {
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = 'report.csv';
  link.click();
}

exportReport(new Blob(['id,total\n1,42\n'], { type: 'text/csv' }));
// missing removeEventListener, clearInterval, disconnect, and revokeObjectURL
