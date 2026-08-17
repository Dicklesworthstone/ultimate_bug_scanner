# GH #94 regression fixture: an interpolated name whose origin is not visible
# in this file (imported constant) cannot be proven external NOR static — it
# must surface as a Warning, not Critical and not silence.
from settings_registry import SETTING_KEY


def upgrade(op):
    op.execute(f"INSERT INTO settings (key) VALUES ('{SETTING_KEY}')")
