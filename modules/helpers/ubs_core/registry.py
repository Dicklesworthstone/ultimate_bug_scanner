"""ubs_core.registry — analyzer registry and run context (bead A2).

Analyzers register under a (layer, language) pair; several analyzers may share
one (layer, language). `layer` is one of the subcommand names of
`python3 -m ubs_core`; `scan` aggregates every layer.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
import queue
import threading
from typing import Callable, Iterable, Iterator

LAYERS: tuple[str, ...] = (
    "taint",
    "guards",
    "narrowing",
    "lifecycle",
    "ctcompare",
    "regex",
    "prefilter",
)

LANGS: tuple[str, ...] = (
    "python",
    "javascript",
    "cpp",
    "rust",
    "go",
    "java",
    "ruby",
    "swift",
    "csharp",
    "kotlin",
    "elixir",
)

Lang = str


@dataclass
class RunContext:
    """Inputs handed to every structured analyzer run."""

    lang: Lang
    files: list[Path] = field(default_factory=list)
    rules: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)

    def rule_enabled(self, rule_id: str) -> bool:
        """Respect an optional profile suppression list."""
        disabled = self.profile.get("disabled_rules") or ()
        return rule_id not in disabled


Finder = Callable[[RunContext], Iterable[dict]]
SelfTest = Callable[[], None]


@dataclass(frozen=True)
class Analyzer:
    layer: str
    lang: Lang
    name: str
    run: Finder
    selftests: tuple[tuple[str, SelfTest], ...] = ()
    # Splitting a selection can discard imports, package initializers and
    # function-summary edges. New analyzers preserve the whole selection unless
    # their author explicitly guarantees independent per-file semantics.
    file_independent: bool = False

    def __post_init__(self) -> None:
        if self.layer not in LAYERS:
            raise ValueError(f"unknown layer: {self.layer}")
        if self.lang not in LANGS:
            raise ValueError(f"unknown lang: {self.lang}")
        if type(self.file_independent) is not bool:
            raise ValueError("file_independent must be a boolean")


_REGISTRY: dict[tuple[str, Lang], list[Analyzer]] = {}

# An ordered consumer may be behind a fast later analyzer. Backpressure bounds
# its lead instead of retaining a whole finding list for every parallel unit.
MAX_BUFFERED_FINDINGS = 32


def register(analyzer: Analyzer) -> Analyzer:
    key = (analyzer.layer, analyzer.lang)
    bucket = _REGISTRY.setdefault(key, [])
    if any(existing.name == analyzer.name for existing in bucket):
        raise ValueError(f"duplicate analyzer name: {analyzer.name}")
    bucket.append(analyzer)
    return analyzer


def get(layer: str, lang: Lang) -> list[Analyzer]:
    try:
        return list(_REGISTRY[(layer, lang)])
    except KeyError:
        raise KeyError(f"no analyzer registered for layer={layer!r} lang={lang!r}") from None


def all_analyzers() -> Iterator[Analyzer]:
    for key in sorted(_REGISTRY):
        yield from _REGISTRY[key]


def analyzers_for_layer(layer: str) -> list[Analyzer]:
    return [a for a in all_analyzers() if a.layer == layer]


def analyzers_for_lang(lang: Lang) -> list[Analyzer]:
    return [a for a in all_analyzers() if a.lang == lang]


def _coerce_finding(raw: dict) -> dict:
    """Validate and normalize one finding record for NDJSON output."""
    for key in ("rule", "path", "line"):
        if key not in raw:
            raise ValueError(f"finding missing required key {key!r}: {raw!r}")
    finding = dict(raw)
    finding.setdefault("layer", "")
    finding.setdefault("lang", "")
    finding.setdefault("col", 1)
    finding.setdefault("severity", "warning")
    finding.setdefault("message", "")
    return finding


def _run_analyzers(analyzers: list[Analyzer], ctx: RunContext, jobs: int) -> Iterator[dict]:
    """Schedule analysis units, never arbitrary pieces of a project analysis.

    Whole-selection analyses may run beside other analyzers. File-independent
    analyzers can additionally share their file shards across workers. Preserve
    registration and input-file order regardless of worker completion order,
    and keep at most `jobs` submitted tasks outstanding. Each producer can be
    only MAX_BUFFERED_FINDINGS records ahead of its consumer; analyzer-internal
    state and one in-flight record per producer are outside that queue budget.
    """
    if type(jobs) is not int or not 1 <= jobs <= 64:
        raise ValueError("jobs must be an integer between 1 and 64")
    if jobs == 1:
        for analyzer in analyzers:
            for raw in analyzer.run(ctx):
                yield _coerce_finding(raw)
        return

    from ubs_core.shards import make_shards

    def tasks():
        for analyzer in analyzers:
            # Empty selections still reach the analyzer, just as in serial
            # mode; a project-level result need not have a source file.
            if analyzer.file_independent and len(ctx.files) > 1:
                size = max(1, min(8, len(ctx.files) // (jobs * 2)))
                groups = make_shards(ctx.files, shard_size=size)
            else:
                groups = [ctx.files]
            for files in groups:
                yield analyzer, files

    stop = threading.Event()
    errors: queue.SimpleQueue[BaseException] = queue.SimpleQueue()
    end = object()

    def check_failure():
        try:
            error = errors.get_nowait()
        except queue.Empty:
            return
        raise error

    def send(output, value):
        while not stop.is_set():
            try:
                output.put(value, timeout=0.05)
                return True
            except queue.Full:
                pass
        return False

    def run_task(analyzer, files, output):
        if stop.is_set():
            return
        try:
            # A task cannot mutate another task's selection or nested policy.
            local = replace(ctx, files=list(files), rules=deepcopy(ctx.rules), profile=deepcopy(ctx.profile))
            findings = iter(analyzer.run(local))
            try:
                while not stop.is_set():
                    try:
                        raw = next(findings)
                    except StopIteration:
                        break
                    if not send(output, _coerce_finding(raw)):
                        break
            finally:
                close = getattr(findings, "close", None)
                if close is not None:
                    close()
            send(output, end)
        except BaseException as exc:
            # A later task's failure must release earlier blocked producers,
            # not wait for the ordered consumer to reach its result queue.
            errors.put(exc)
            stop.set()
            raise

    iterator = iter(tasks())
    pending = deque()
    with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="ubs-analyzer") as executor:
        def submit_next():
            check_failure()
            task = next(iterator, None)
            if task is not None:
                output = queue.Queue(maxsize=MAX_BUFFERED_FINDINGS)
                pending.append((executor.submit(run_task, *task, output), output))

        try:
            for _ in range(jobs):
                submit_next()
            while pending:
                future, output = pending[0]
                while True:
                    check_failure()
                    try:
                        finding = output.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    check_failure()
                    if finding is end:
                        future.result()
                        break
                    yield finding
                pending.popleft()
                submit_next()
        finally:
            # Release bounded puts before joining the executor. Consumer
            # cancellation and submit failures must also close live generators.
            stop.set()
            for future, _ in pending:
                future.cancel()


def run_layer(layer: str, ctx: RunContext, *, jobs: int = 1) -> Iterator[dict]:
    """Yield normalized findings without splitting an analyzer's input scope."""
    yield from _run_analyzers(get(layer, ctx.lang), ctx, jobs)


def run_scan(ctx: RunContext, *, jobs: int = 1) -> Iterator[dict]:
    """Yield normalized findings across every layer registered for the language."""
    yield from _run_analyzers(analyzers_for_lang(ctx.lang), ctx, jobs)
