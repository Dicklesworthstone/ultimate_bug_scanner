// GH #75: production source that stays in scope when tests/ is excluded.
interface Account {
  id: string;
}

export function accountId(account: Account): string {
  return account.id;
}
