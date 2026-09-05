"""ubs_core.py_patterns.flow — categories 5, 6, 10, 21 (bead 0xjg.5).

Faithful ports of the legacy rg pipelines in modules/ubs-python.sh:
- CATEGORY 5 ASYNC/AWAIT PITFALLS (10882-10915): async/await census,
  await inside loops, blocking calls in async def. (run_async_error_checks
  is NOT ported here — the consolidated rule pack already covers
  py.async.task-no-await.)
- CATEGORY 6 ERROR HANDLING (10917-10948): bare except, except...: pass,
  raise e.
- CATEGORY 10 CONTROL FLOW GOTCHAS (11469-11495): control transfer in
  finally, nested ternary, unreachable code after return.
- CATEGORY 21 DEPRECATIONS (11858-11871): imp import / asyncio.get_event_loop.

Divergence notes
----------------
grep -A N pipelines: legacy piped the rg matches through `grep -A3/-A6/-A2/-A1`
context stages. rg streams matching lines only (RG_BASE carries no context
flags), so the literal pipeline degenerates to "header lines that self-match"
and the finally/raise-e/unreachable variants could then never fire. These
ports keep each pipeline's stated intent — "target line within N lines after
the header line" — as single cross-line regexes anchored at the header line.
Legacy counted/anchored the target lines instead; several targets after one
header collapse to one record per header (line-deduped project-wide, like
every pattern).

Possible un-awaited async paths: legacy warns when the project-wide
async_count > await_count and reports the difference — a two-count comparison
the Pattern protocol (severity resolved from ONE count) cannot express. It is
encoded conservatively via suppress_when_regex: warn only when async defs
exist and no `\bawait\b` word appears anywhere — a strict subset of the
legacy fire condition (awaits == 0 implies async_count > await_count).
"""
from __future__ import annotations

import re

from ubs_core.py_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 5: ASYNC/AWAIT PITFALLS ────────────────────────────────────
    Pattern(
        category=5,
        rule_id="py.async.census",
        title="Async functions found",
        # legacy 10890/10892: `rg -e 'async[[:space:]]+def[[:space:]]'`,
        # unconditional info census. v2 emits one record per async def line.
        regex=re.compile(r"async[ \t]+def[ \t]"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=5,
        rule_id="py.async.un-awaited-paths",
        title="Possible un-awaited async paths",
        # legacy 10893-10895: warning when async_count > await_count.
        # Conservative suppress_when encoding — see module docstring.
        regex=re.compile(r"async[ \t]+def[ \t]"),
        thresholds=((0, "warning"),),
        suppress_when_regex=re.compile(r"\bawait\b"),
    ),
    Pattern(
        category=5,
        rule_id="py.async.await-in-loop",
        title="await inside loops",
        # legacy 10899-10903: `for[[:space:]]+.*:|while[[:space:]]+.*:`
        # headers + `grep -A3 -w await` → `\bawait\b` on the header line
        # itself or within the 3 lines after it.
        regex=re.compile(
            r"[^\n]*(?:for|while)[ \t]+[^\n]*:[^\n]*"
            r"(?:\bawait\b|\n(?:[^\n]*\n){0,2}?[^\n]*\bawait\b)"
        ),
        thresholds=((3, "info"),),
    ),
    Pattern(
        category=5,
        rule_id="py.async.blocking-call",
        title="Blocking calls inside async functions",
        # legacy 10907-10912: `async[[:space:]]+def[[:space:]]` headers +
        # `grep -A6 -E 'time\.sleep\(|requests\.[a-z]+\(.*\)|subprocess\.run\(|open\('`
        # with final filter time\.sleep|requests\.|subprocess\.run|open\( —
        # a blocking-call line on the async def line or within the 6 after it.
        regex=re.compile(
            r"async[ \t]+def[ \t][^\n]*"
            r"(?:time\.sleep|requests\.|subprocess\.run|open\("
            r"|\n(?:[^\n]*\n){0,5}?[^\n]*(?:time\.sleep|requests\.|subprocess\.run|open\())"
        ),
        thresholds=((0, "warning"),),
    ),
    # ── Category 6: ERROR HANDLING ANTI-PATTERNS ────────────────────────────
    Pattern(
        category=6,
        rule_id="py.error-handling.bare-except",
        title="Bare except",
        # legacy 10926: `^[[:space:]]*except[[:space:]]*:[[:space:]]*$`.
        regex=re.compile(r"(?m)^[ \t]*except[ \t]*:[ \t]*$"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=6,
        rule_id="py.error-handling.except-pass",
        title="Exception swallowed with pass",
        # legacy 10935: `^[[:space:]]*except[[:space:]]+[^:]+:[[:space:]]*pass[[:space:]]*$`.
        # [^:\n] keeps legacy's per-line [^:] semantics in whole-file matching.
        regex=re.compile(r"(?m)^[ \t]*except[ \t]+[^:\n]+:[ \t]*pass[ \t]*$"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="py.error-handling.raise-name",
        title="Use 'raise' not 'raise e' to preserve traceback",
        # legacy 10942-10943: `except ... as name:` headers + `grep -A2 -E
        # 'raise[[:space:]]+name[[:space:]]*$'` → bare-name re-raise within
        # the 2 lines after the handler header.
        regex=re.compile(
            r"(?m)^[ \t]*except[ \t][^\n]*as[ \t]+[A-Za-z_][A-Za-z0-9_]*:[ \t]*\n"
            r"(?:[^\n]*\n){0,1}?[ \t]*raise[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*(?:\n|\Z)"
        ),
        thresholds=((0, "warning"),),
    ),
    # ── Category 10: CONTROL FLOW GOTCHAS ───────────────────────────────────
    Pattern(
        category=10,
        rule_id="py.control-flow.finally-transfer",
        title="Control transfer in finally",
        # legacy 11475-11476: `finally:[[:space:]]*$` headers + `grep -A3 -E
        # 'return|break|continue'` → transfer line within the 3 lines after
        # finally: (substring match — faithful to the unbounded grep -E).
        regex=re.compile(
            r"[^\n]*finally:[ \t]*\n(?:[^\n]*\n){0,2}?[^\n]*(?:return|break|continue)"
        ),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=10,
        rule_id="py.control-flow.nested-ternary",
        title="Nested ternary expressions",
        # legacy 11483: verbatim ` if .* else .* if .* else ` line regex.
        regex=re.compile(r" if .* else .* if .* else "),
        thresholds=((3, "info"),),
    ),
    Pattern(
        category=10,
        rule_id="py.control-flow.unreachable-code",
        title="Possible unreachable code after return",
        # legacy 11490-11491: word `return` lines + `grep -A1` follower +
        # `grep -v -E '^--$|return|^[[:space:]]*$'` → a non-blank follower
        # line without `return`, anchored here at the return line (the -A1
        # follower maps 1:1 onto the return line, so counts are preserved).
        regex=re.compile(
            r"\breturn\b[^\n]*\n(?![ \t]*\n)(?![^\n]*return)[^\n]+"
        ),
        thresholds=((5, "info"),),
    ),
    # ── Category 21: DEPRECATIONS & PY3.13 MIGRATIONS ───────────────────────
    Pattern(
        category=21,
        rule_id="py.deprecations.deprecated-api",
        title="Deprecated API usage",
        # legacy 11867: `^from[[:space:]]+imp[[:space:]]+import|^import[[:space:]]+imp|asyncio\.get_event_loop\(`.
        # `^import imp` substring-matches `import importlib` in legacy too — quirk kept.
        regex=re.compile(
            r"(?m)^from[ \t]+imp[ \t]+import|^import[ \t]+imp|asyncio\.get_event_loop\("
        ),
        thresholds=((0, "warning"),),
    ),
]
