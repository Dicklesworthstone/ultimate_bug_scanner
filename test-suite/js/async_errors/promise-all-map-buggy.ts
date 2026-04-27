type User = {
  id: string;
  displayName: string;
};

async function fetchUser(id: string): Promise<User> {
  const response = await fetch(`/api/users/${encodeURIComponent(id)}`);
  return response.json() as Promise<User>;
}

export async function warmUserCache(ids: string[]): Promise<void> {
  await Promise.all(
    ids.map((id) => {
      fetchUser(id);
    })
  );
}
