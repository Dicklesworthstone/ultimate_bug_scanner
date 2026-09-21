type ApiUser = {
  id: string;
  email: string;
};

export async function loadUser(userId: string): Promise<ApiUser> {
  const response = await fetch(`/api/users/${encodeURIComponent(userId)}`);
  return response.json() as Promise<ApiUser>;
}

export function saveUser(user: ApiUser): Promise<Response> {
  return fetch("/api/users", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(user),
  });
}

export function loadAuditTrail(userId: string): Promise<string> {
  return window
    .fetch(`/api/users/${encodeURIComponent(userId)}/audit`)
    .then((response) => response.text());
}
