type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, string | undefined>;
};

type Database = {
  query(sql: string, values: readonly unknown[]): Promise<unknown>;
};

type RouteContext = {
  params: Record<string, string | undefined>;
};

type PrismaLike = {
  $queryRaw(strings: TemplateStringsArray, ...values: readonly unknown[]): Promise<unknown>;
};

type SequelizeLike = {
  query(sql: string, options: { replacements: Record<string, unknown> }): Promise<unknown>;
};

type QueryBuilder = {
  where(values: Record<string, unknown>): Promise<unknown>;
};

declare function usersTable(name: "users"): QueryBuilder;

export async function parameterizedDbQuery(req: RequestLike, db: Database): Promise<unknown> {
  const email = req.query.email;
  return db.query("SELECT id, email FROM users WHERE email = $1", [email]);
}

export async function parameterizedRouteParams(_request: RequestLike, { params }: RouteContext, db: Database): Promise<unknown> {
  return db.query("SELECT id FROM tenants WHERE slug = $1", [params.tenant]);
}

export async function parameterizedDestructuredRouteParams(_request: RequestLike, { params }: RouteContext, db: Database): Promise<unknown> {
  const { account } = params;
  return db.query("SELECT id FROM accounts WHERE slug = $1", [account]);
}

export async function prismaSafeTaggedTemplate(req: RequestLike, prisma: PrismaLike): Promise<unknown> {
  const status = req.body.status;
  return prisma.$queryRaw`SELECT * FROM invoices WHERE status = ${status}`;
}

export async function sequelizeReplacements(req: RequestLike, sequelize: SequelizeLike): Promise<unknown> {
  const role = req.query.role;
  return sequelize.query("SELECT * FROM users WHERE role = :role", {
    replacements: { role },
  });
}

export async function queryBuilderWhereClause(req: RequestLike): Promise<unknown> {
  const email = req.query.email;
  return usersTable("users").where({ email });
}
