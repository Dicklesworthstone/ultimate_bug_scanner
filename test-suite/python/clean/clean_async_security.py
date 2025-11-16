"""Clean Python sample demonstrating defensive techniques."""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
from pathlib import Path

import httpx
import yaml


def safe_eval(expr: str) -> int:
    allowed = {"ONE": 1, "TWO": 2}
    if expr not in allowed:
        raise ValueError("unsupported literal")
    return allowed[expr]


def download_json(url: str) -> dict:
    with httpx.Client(timeout=5.0, verify=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.json()


def deserialize(payload: str) -> dict:
    return yaml.safe_load(payload)


def read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8") as handle:
        return handle.read()


async def process_users(db, ids):
    async def fetch_one(user_id: str):
        record = await db.fetch(user_id)
        return json.loads(record)

    coros = [fetch_one(user_id) for user_id in ids]
    return await asyncio.gather(*coros)


def run_checked_command(argv: list[str]) -> None:
    if not all(argv):
        raise ValueError("empty arguments not allowed")
    subprocess = __import__("subprocess")
    subprocess.run(argv, check=True)


@contextlib.contextmanager
def resource_guard(finalizer):
    try:
        yield
    finally:
        finalizer()


TOKEN = secrets.token_urlsafe(32)
