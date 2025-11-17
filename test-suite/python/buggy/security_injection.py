"""Python security regression fixture: demonstrates eval, yaml.load, SQL injection, and shell=True."""

import os
import pickle
import sqlite3
import subprocess
import yaml
import requests

USER_INPUT = "admin' OR 1=1 --"

# Code injection
raw_json = "{'debug': True}"
eval(raw_json)  # UBS should flag eval

# Unsafe YAML load
data = yaml.load("debug: true", Loader=None)
print(data)

# Shell command injection
subprocess.run(f"ls {USER_INPUT}", shell=True)

# SQL injection
conn = sqlite3.connect(':memory:')
cur = conn.cursor()
cur.execute(
    f"SELECT * FROM users WHERE name = '{USER_INPUT}'"
)

# Insecure pickle
payload = requests.get('https://example.com/payload.bin', verify=False).content
pickle.loads(payload)

# Weak hash / hardcoded secret
API_KEY = "sk_live_123"
os.environ['HASH'] = 'md5'
