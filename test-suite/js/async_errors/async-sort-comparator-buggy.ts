type User = { id: string; name: string };

async function scoreUser(user: User): Promise<number> {
  return Promise.resolve(user.name.length);
}

export function rankUsers(users: User[]): User[] {
  const ranked = [...users];
  ranked.sort(async (left, right) => {
    const leftScore = await scoreUser(left);
    const rightScore = await scoreUser(right);
    return rightScore - leftScore;
  });
  return ranked;
}

export function rankUsersImmutable(users: User[]): User[] {
  return users.toSorted(async function compareUsers(left, right) {
    const leftScore = await scoreUser(left);
    const rightScore = await scoreUser(right);
    return rightScore - leftScore;
  });
}
