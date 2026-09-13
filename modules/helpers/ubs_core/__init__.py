"""ubs_core — Shared, stdlib-only utilities for Ultimate Bug Scanner helpers (bead A2).

Provides reconciled line/column resolution, delimiter and block tracking,
string/comment stripping with character and newline preservation, and span intervals.
"""
from __future__ import annotations

from ubs_core.io import (
    extract_statement_region,
    find_block_end,
    format_location,
    line_col,
    skip_ws,
)
from ubs_core.lexer import (
    Interval,
    Span,
    strip_comments_and_strings,
)

# A cached scan needs neither scheduling nor worker queues. Keep their public
# exports available without importing their dependencies on every helper start.
_DEFERRED_EXPORTS = {
    "CostModel": "scheduler",
    "ScheduleResult": "scheduler",
    "calculate_slot_utilization": "scheduler",
    "schedule_lpt": "scheduler",
    "ShardQueue": "shards",
    "make_shards": "shards",
    "parallel_file_map": "shards",
    "run_work_stealing": "shards",
}


def __getattr__(name: str):
    module_name = _DEFERRED_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_DEFERRED_EXPORTS))

__all__ = [
    "CostModel",
    "Interval",
    "ScheduleResult",
    "ShardQueue",
    "Span",
    "calculate_slot_utilization",
    "extract_statement_region",
    "find_block_end",
    "format_location",
    "line_col",
    "make_shards",
    "parallel_file_map",
    "run_work_stealing",
    "schedule_lpt",
    "skip_ws",
    "strip_comments_and_strings",
]
