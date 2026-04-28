type EventBus = {
  on(eventName: "message", listener: (payload: string) => void): void;
  off(eventName: "message", listener: (payload: string) => void): void;
};

async function persistMessage(payload: string): Promise<void> {
  if (!payload) {
    throw new Error("missing payload");
  }
  await Promise.resolve(payload);
}

function reportListenerError(error: unknown): void {
  console.error("message listener failed", error);
}

export function bindBus(bus: EventBus): () => void {
  const handleMessage = (payload: string): void => {
    void persistMessage(payload).catch(reportListenerError);
  };

  bus.on("message", handleMessage);
  return () => bus.off("message", handleMessage);
}
