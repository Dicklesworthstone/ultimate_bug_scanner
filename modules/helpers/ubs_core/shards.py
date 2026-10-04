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
        self._queue: queue.Queue[tuple[int, list[Path]]] = queue.Queue()
        for index, shard in enumerate(shards):
            self._queue.put((index, list(shard)))

    @property
    def remaining(self) -> int:
        return self._queue.qsize()

    def get_shard(self) -> list[Path] | None:
        task = self._get_task()
        return None if task is None else task[1]

    def _get_task(self) -> tuple[int, list[Path]] | None:
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
    calling thread without concurrency overhead. Results retain input-shard
    order, not worker completion order. Any failed worker invalidates the whole
    result; running callbacks are joined and unstarted work is abandoned.

    Callers must supply independent shards. This executor cannot infer import,
    package or other whole-selection dependencies on their behalf.
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
    shard_results: list[list[T] | None] = [None] * len(shards)
    worker_errors: list[BaseException] = []
    errors_lock = threading.Lock()
    stop = threading.Event()

    def _worker() -> None:
        while not stop.is_set():
            task = q._get_task()
            if task is None:
                return
            index, shard = task
            try:
                if not stop.is_set():
                    # Exhaust the iterator before publishing this shard. A
                    # yield followed by failure is not a completed analysis.
                    shard_results[index] = list(process_shard_fn(shard))
            except BaseException as exc:
                # SystemExit (even code 0) and worker-local interrupts otherwise
                # vanish at the thread boundary, producing incomplete success.
                with errors_lock:
                    worker_errors.append(exc)
                stop.set()
            finally:
                q.task_done()

    threads: list[threading.Thread] = []
    try:
        for _ in range(workers_count):
            t = threading.Thread(target=_worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    finally:
        # A launch failure or caller interruption must not leave callbacks
        # consuming inputs after the caller starts handling the failed run.
        stop.set()
        for t in threads:
            t.join()

    if worker_errors:
        error = worker_errors[0]
        if not isinstance(error, Exception):
            raise RuntimeError(f"Shard worker terminated before completion: {type(error).__name__}") from error
        raise error

    combined: list[T] = []
    for res_list in shard_results:
        if res_list is None:
            raise RuntimeError("Shard processing finished without a complete result")
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
