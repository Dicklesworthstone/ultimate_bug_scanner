# GH #94 regression fixture: an f-string whose every interpolated value is a
# module-level string constant is provably static — it must NOT be reported as
# interpolated SQL reaching an execution sink (Alembic seed-migration pattern).
_SETTING_KEY = "wflow.read.enabled"
_DESCRIPTION = "Enable the wflow read channel"


def upgrade(op):
    op.execute(
        f"INSERT INTO settings (key, description) VALUES ('{_SETTING_KEY}', '{_DESCRIPTION}')"
    )
