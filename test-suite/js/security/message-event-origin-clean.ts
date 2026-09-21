type AuthBridgeMessage = {
  kind: "auth-token";
  token: string;
};

const TRUSTED_PARENT_ORIGIN = "https://app.example.test";

const authStore = {
  save(token: string): void {
    sessionStorage.setItem("auth-token", token);
  },
};

window.addEventListener("message", (event: MessageEvent<AuthBridgeMessage>) => {
  if (event.origin !== TRUSTED_PARENT_ORIGIN) {
    return;
  }
  if (event.data.kind !== "auth-token") {
    return;
  }

  authStore.save(event.data.token);
});
