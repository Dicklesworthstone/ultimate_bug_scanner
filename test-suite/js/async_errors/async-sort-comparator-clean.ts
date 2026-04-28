type User = { id: string; name: string };

async function scoreUser(user: User): Promise<number> {
  return Promise.resolve(user.name.length);
}

export async function rankUsers(users: User[]): Promise<User[]> {
  try {
    const scores = new Map<string, number>();
    for (const user of users) {
      scores.set(user.id, await scoreUser(user));
    }

    return [...users].sort((left, right) => {
      const leftScore = scores.get(left.id) ?? 0;
      const rightScore = scores.get(right.id) ?? 0;
      return rightScore - leftScore;
    });
  } catch (error) {
    throw new Error(`failed to rank users: ${String(error)}`);
  }
}
