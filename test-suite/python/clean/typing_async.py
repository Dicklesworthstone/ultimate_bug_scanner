"""Clean async patterns with typing annotations."""

from __future__ import annotations

import asyncio
from typing import Any

async def process(queue: 'asyncio.Queue[Any]') -> None:
    async with asyncio.TaskGroup() as tg:
        while not queue.empty():
            item = await queue.get()
            tg.create_task(handle(item))

async def handle(item: dict[str, Any]) -> str:
    return item.get('value', 'missing')
