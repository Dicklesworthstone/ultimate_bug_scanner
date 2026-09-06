"""ubs_core.csharp_patterns.concurrency — cat 2 (resources) + cat 3 (async).

Legacy: category_2_resources_idisposable (1230-1255) and
category_3_concurrency_async (1257-1309). The cat-3 Task-handle half is the
async_handles_csharp analyzer (run after the Thread.Sleep check).
"""
from __future__ import annotations

import re

from ubs_core.csharp_patterns._table import P

PATTERNS = [
    # ── cat 2 ──
    P(
        category=2, rule_id="cs.pattern.new-httpclient", seq=110,
        label="new HttpClient()",
        text="new HttpClient(...) ({n}) - prefer IHttpClientFactory or shared instance",
        regex=re.compile(r'\bnew\s+HttpClient\s*\('),
        severity="warning",
    ),
    P(
        category=2, rule_id="cs.pattern.stream-no-using", seq=120,
        label="Stream without using",
        text="Stream created without 'using' on same line (approx) ({n})",
        regex=re.compile(r'\bnew\s+(FileStream|StreamReader|StreamWriter)\s*\('),
        severity="warning",
        # legacy post-pipe: grep -v ':[[:space:]]*using\b' (BRE) over the
        # rg output line `path:line:content`.
        exclude_regex=re.compile(r':[ \t]*using\b'),
    ),
    # ── cat 3 ──
    P(
        category=3, rule_id="cs.pattern.async-void", seq=130,
        label="async void",
        text="async void methods ({n}) - exceptions can crash process; prefer Task",
        regex=re.compile(r'\basync\s+void\b'),
        severity="warning",
    ),
    P(
        category=3, rule_id="cs.pattern.blocking-result", seq=140,
        label=".Result",
        text="Blocking on Task via .Result ({n}) - deadlock risk",
        regex=re.compile(r'\.Result\b'),
        severity="critical",
    ),
    P(
        category=3, rule_id="cs.pattern.blocking-wait", seq=150,
        label=".Wait()",
        text="Blocking on Task via Wait() ({n}) - deadlock risk",
        regex=re.compile(r'\.Wait\s*\('),
        severity="critical",
    ),
    P(
        category=3, rule_id="cs.pattern.getawaiter-getresult", seq=160,
        label="GetAwaiter().GetResult",
        text="GetAwaiter().GetResult() ({n}) - deadlock risk",
        regex=re.compile(r'GetAwaiter\s*\(\s*\)\s*\.GetResult\s*\('),
        severity="critical",
    ),
    P(
        category=3, rule_id="cs.pattern.thread-sleep", seq=170,
        label="Thread.Sleep",
        text="Thread.Sleep(...) ({n}) - blocks thread; in async code prefer Task.Delay",
        regex=re.compile(r'\bThread\.Sleep\s*\('),
        severity="warning",
    ),
]
