type AuthBridgeMessage = {
  kind: "auth-token";
  token: string;
};

const authStore = {
  save(token: string): void {
    sessionStorage.setItem("auth-token", token);
  },
};

window.addEventListener("message", (event: MessageEvent<AuthBridgeMessage>) => {
  if (event.data.kind !== "auth-token") {
    return;
  }

  authStore.save(event.data.token);
});
