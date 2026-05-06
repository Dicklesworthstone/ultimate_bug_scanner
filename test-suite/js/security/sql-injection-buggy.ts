type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, string | undefined>;
};

type Database = {
  query(sql: string, values?: readonly unknown[]): Promise<unknown>;
};

type RouteContext = {
  params: Record<string, string | undefined>;
};

type PrismaLike = {
  $queryRaw(strings: TemplateStringsArray, ...values: readonly unknown[]): Promise<unknown>;
  $queryRawUnsafe(sql: string): Promise<unknown>;
  $executeRawUnsafe(sql: string): Promise<unknown>;
};

type SequelizeLike = {
  query(sql: string): Promise<unknown>;
};

export async function rawDbQueryFromQuery(req: RequestLike, db: Database): Promise<unknown> {
  const email = req.query.email;
  const sql = `SELECT id, email FROM users WHERE email = '${email}'`;
  return db.query(sql);
}

export async function rawDbQueryFromRouteParams(_request: RequestLike, { params }: RouteContext, db: Database): Promise<unknown> {
  const tenant = params.tenant;
  return db.query("SELECT id FROM tenants WHERE slug = '" + tenant + "'");
}

export async function rawDbQueryFromDestructuredRouteParams(_request: RequestLike, { params }: RouteContext, db: Database): Promise<unknown> {
  const { account } = params;
  return db.query("SELECT id FROM accounts WHERE slug = '" + account + "'");
}

export async function dynamicTableWithPlaceholder(req: RequestLike, db: Database): Promise<unknown> {
  const table = req.query.table;
  return db.query("SELECT id FROM " + table + " WHERE owner = $1", ["system"]);
}

export async function prismaUnsafeTemplate(req: RequestLike, prisma: PrismaLike): Promise<unknown> {
  const status = req.body.status;
  return prisma.$queryRawUnsafe(`SELECT * FROM invoices WHERE status = '${status}'`);
}

export async function prismaUnsafeConcat(req: RequestLike, prisma: PrismaLike): Promise<unknown> {
  const tenant = req.query.tenant;
  return prisma.$executeRawUnsafe("DELETE FROM tenant_jobs WHERE tenant = '" + tenant + "'");
}

export async function safeTagDoesNotHideUnsafeSameStatement(req: RequestLike, prisma: PrismaLike): Promise<unknown> {
  const tenant = req.query.tenant;
  return prisma.$queryRaw`SELECT 1`.then(() => prisma.$executeRawUnsafe("DELETE FROM tenant_jobs WHERE tenant = '" + tenant + "'"));
}

export async function sequelizeInterpolated(req: RequestLike, sequelize: SequelizeLike): Promise<unknown> {
  const role = req.query.role;
  return sequelize.query(`SELECT * FROM users WHERE role = '${role}'`);
}
