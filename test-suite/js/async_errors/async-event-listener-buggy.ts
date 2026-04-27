async function sendAnalytics(eventName: string): Promise<void> {
  const response = await fetch("/api/analytics", {
    method: "POST",
    body: JSON.stringify({ eventName }),
  });
  if (!response.ok) {
    throw new Error("analytics failed");
  }
}

export function bindTracking(target: EventTarget): void {
  target.addEventListener("click", async () => {
    await sendAnalytics("checkout-clicked");
  });
}
