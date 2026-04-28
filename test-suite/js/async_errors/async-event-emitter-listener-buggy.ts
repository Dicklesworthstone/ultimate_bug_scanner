type EventBus = {
  on(eventName: "message", listener: (payload: string) => void): void;
  addListener(eventName: "message", listener: (payload: string) => void): void;
};

async function persistMessage(payload: string): Promise<void> {
  if (!payload) {
    throw new Error("missing payload");
  }
  await Promise.resolve(payload);
}

export function bindBus(bus: EventBus): void {
  bus.on("message", async (payload) => {
    await persistMessage(payload);
  });
  bus.addListener("message", async (payload) => {
    await persistMessage(payload);
  });
}
