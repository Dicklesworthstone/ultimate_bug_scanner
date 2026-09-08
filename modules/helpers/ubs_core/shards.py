"""ubs_core.shards — work-stealing file shard queue (bead C5).

Inside a module, ubs_core processes file shards pulled from a shared queue
(work stealing across --jobs workers) so one slow file does not serialise
a category.
"""
from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Callable, Iterable, Sequence, TypeVar

T = TypeVar("T")


def make_shards(files: Sequence[Path | str], shard_size: int = 4) -> list[list[Path]]:
    """Partition a sequence of files into shards of at most shard_size paths."""
    if not files:
        return []
    path_list = [Path(f) for f in files]
    actual_size = max(1, int(shard_size))
    return [path_list[i : i + actual_size] for i in range(0, len(path_list), actual_size)]


class ShardQueue:
    """Thread-safe queue of file shards for work stealing across workers."""

    def __init__(self, shards: Sequence[Sequence[Path]]) -> None:
        self._queue: queue.Queue[list[Path]] = queue.Queue()
        for shard in shards:
            self._queue.put(list(shard))

    @property
    def remaining(self) -> int:
        return self._queue.qsize()

    def get_shard(self) -> list[Path] | None:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def task_done(self) -> None:
        self._queue.task_done()


def run_work_stealing(
    files: Sequence[Path | str],
    process_shard_fn: Callable[[list[Path]], Iterable[T]],
    num_workers: int = 1,
    shard_size: int | None = None,
) -> list[T]:
    """Process files in shards pulled from a shared queue across worker threads.

    If num_workers <= 1 or len(files) <= 1, processes files directly on the
    calling thread without concurrency overhead.
    """
    if not files:
        return []

    path_list = [Path(f) for f in files]
    if num_workers <= 1 or len(path_list) <= 1:
        return list(process_shard_fn(path_list))

    if shard_size is None or shard_size <= 0:
        # Dynamic shard size: balanced so workers steal multiple small shards
        shard_size = max(1, min(8, len(path_list) // (num_workers * 2)))

    shards = make_shards(path_list, shard_size=shard_size)
    if len(shards) <= 1:
        return list(process_shard_fn(path_list))

    q = ShardQueue(shards)
    workers_count = min(num_workers, len(shards))
    worker_results: list[list[T]] = [[] for _ in range(workers_count)]
    worker_errors: list[Exception] = []
    errors_lock = threading.Lock()

    def _worker(worker_id: int) -> None:
        results: list[T] = []
        try:
            while True:
                shard = q.get_shard()
                if shard is None:
                    break
                try:
                    res = process_shard_fn(shard)
                    results.extend(res)
                finally:
                    q.task_done()
        except Exception as exc:
            with errors_lock:
                worker_errors.append(exc)
        finally:
            worker_results[worker_id] = results

    threads: list[threading.Thread] = []
    for wid in range(workers_count):
        t = threading.Thread(target=_worker, args=(wid,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if worker_errors:
        raise worker_errors[0]

    combined: list[T] = []
    for res_list in worker_results:
        combined.extend(res_list)
    return combined


def parallel_file_map(
    files: Sequence[Path | str],
    fn: Callable[[Path], T],
    num_workers: int = 1,
    shard_size: int | None = None,
) -> dict[Path, T]:
    """Map fn over files across worker threads using work-stealing shards.

    Returns a dict mapping Path -> result.
    """
    path_list = [Path(f) for f in files]
    if not path_list:
        return {}

    if num_workers <= 1 or len(path_list) <= 1:
        return {p: fn(p) for p in path_list}

    def _process_shard(shard: list[Path]) -> list[tuple[Path, T]]:
        return [(p, fn(p)) for p in shard]

    items = run_work_stealing(path_list, _process_shard, num_workers=num_workers, shard_size=shard_size)
    return dict(items)
