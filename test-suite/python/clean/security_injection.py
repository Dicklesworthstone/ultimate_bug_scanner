"""Safe equivalents for the python security fixture."""

import ast
import sqlite3
import subprocess
import yaml
import requests

USER_INPUT = "carol"

config = ast.literal_eval("{'debug': False}")
print(config)

data = yaml.safe_load("debug: false")
print(data)

subprocess.run(['ls', USER_INPUT], check=True)

conn = sqlite3.connect(':memory:')
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE name = ?", (USER_INPUT,))

resp = requests.get('https://example.com/api', timeout=5)
print(resp.status_code)
