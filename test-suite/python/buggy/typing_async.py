"""BUGGY Python: typing/async pitfalls"""

from typing import Any
import asyncio

async def process(queue):
    # BUG: awaiting inside infinite loop sequentially with blocking call
    while True:
        await asyncio.sleep(1)
        data = queue.get_nowait()
        asyncio.create_task(handle(data))  # floating task

async def handle(item: Any):
    return item['value']  # potential KeyError

class Legacy:
    def method(self, flag):
        if flag is False:
            return 'no'
        if flag is True:
            return 'yes'
        return 'maybe'

