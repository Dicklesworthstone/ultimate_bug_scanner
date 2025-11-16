"""Buggy Python sample exercising UBS python module detections."""

import json
import os
import random
import subprocess
import requests

API_KEY = "sk_live_hardcoded"
DEFAULT_PASSWORD = "hunter2"


def eval_user_script(script: str):
    # CRITICAL: eval on untrusted input
    return eval(script)


def download_data(url):
    # WARNING: verify=False disables TLS security
    response = requests.get(url, verify=False)
    return response.text


def deserialize(payload: bytes):
    # CRITICAL: yaml.load without SafeLoader
    import yaml

    return yaml.load(payload)


def unsafe_open(path: str):
    # WARNING: open() without context manager or encoding
    f = open(path)
    data = f.read()
    return data


async def process_users(db, ids):
    results = []
    for user_id in ids:
        # WARNING: await inside loop + blocking call
        record = await db.fetch(user_id)
        results.append(json.loads(record))  # WARNING: no try/except
    return results


def run_shell(user_arg: str):
    # CRITICAL: shell=True injection
    subprocess.run(f"cat {user_arg}", shell=True)


class Dangerous:
    def __del__(self):
        # CRITICAL: bare except swallowing everything
        try:
            cleanup()
        except:
            pass


random.seed(42)  # INFO: math random for security
if random.random() > 0.5:
    print("Using insecure randomness")

