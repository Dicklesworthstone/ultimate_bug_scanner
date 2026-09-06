"""ubs_core.csharp_patterns.async_locks — cat 20 (async locks / semaphores).

Legacy: category_20_async_locks (3412-3448). The lock/await heuristic only
ran when the ast-grep pack did NOT cover await-in-lock exactly (legacy
AST_GREP_STATUS not used/clean) — needs_no_ast reproduces that gate — and
required a project-wide await census (>0) before counting lock sites
(gate_regex).
"""
from __future__ import annotations

import re

from ubs_core.csharp_patterns._table import P

PATTERNS = [
    P(
        category=20, rule_id="cs.pattern.lock-in-async", seq=540,
        label="lock in async code",
        text="lock(...) used in files that also use await ({n} lock sites) - ensure you never await while holding a lock",
        regex=re.compile(r'\block\s*\('),
        severity="warning",
        gate_regex=re.compile(r'\bawait\b'),
        needs_no_ast=True,
    ),
    P(
        category=20, rule_id="cs.pattern.semaphore-wait", seq=550,
        label="SemaphoreSlim.Wait",
        text="SemaphoreSlim.Wait() ({n}) - blocks; prefer WaitAsync with await",
        regex=re.compile(r'\bSemaphoreSlim\b.*\.Wait\s*\('),
        severity="warning",
    ),
]
