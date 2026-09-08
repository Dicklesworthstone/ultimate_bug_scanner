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

from ubs_core.scheduler import (
    CostModel,
    ScheduleResult,
    calculate_slot_utilization,
    schedule_lpt,
)
from ubs_core.shards import (
    ShardQueue,
    make_shards,
    parallel_file_map,
    run_work_stealing,
)

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
