async function sendAnalytics(eventName: string): Promise<void> {
  const response = await fetch("/api/analytics", {
    method: "POST",
    body: JSON.stringify({ eventName }),
  });
  if (!response.ok) {
    throw new Error("analytics failed");
  }
}

function reportAnalyticsError(error: unknown): void {
  console.error("analytics failed", error);
}

export function bindTracking(target: EventTarget): () => void {
  const handleClick = (): void => {
    void sendAnalytics("checkout-clicked").catch(reportAnalyticsError);
  };

  target.addEventListener("click", handleClick);
  return () => target.removeEventListener("click", handleClick);
}
