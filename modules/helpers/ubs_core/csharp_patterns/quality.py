"""ubs_core.csharp_patterns.quality — cats 9/11/15/16/21/22/23/24.

Legacy: category_9_quality_markers (2944-2957), category_11_tests_debug
(2985-3015), category_15_exception_handling (3183-3216),
category_16_aspnet_web (3218-3242), category_21_exception_surfaces
(3450-3474), category_22_casts_truncation (3476-3500),
category_23_parsing_validation (3502-3517), category_24_perf_dos
(3519-3543).
"""
from __future__ import annotations

import re

from ubs_core.csharp_patterns._table import P

PATTERNS = [
    # ── cat 9 ──
    P(
        category=9, rule_id="cs.pattern.tech-debt-markers", seq=380,
        label="Markers",
        text="TODO/FIXME/HACK markers ({n})",
        regex=re.compile(r'\b(TODO|FIXME|HACK|XXX)\b'),
        severity="info",
    ),
    # ── cat 11 ──
    P(
        category=11, rule_id="cs.pattern.debugger-break", seq=390,
        label="Debugger.Break",
        text="Debugger.Break() ({n}) - remove before shipping",
        regex=re.compile(r'\bDebugger\.Break\s*\('),
        severity="warning",
    ),
    P(
        category=11, rule_id="cs.pattern.if-debug", seq=400,
        label="#if DEBUG",
        text="#if DEBUG blocks ({n}) - ensure no prod-only behavior hiding",
        regex=re.compile(r'^\s*#if\s+DEBUG\b'),
        severity="info",
    ),
    P(
        category=11, rule_id="cs.pattern.console-write", seq=410,
        label="Console.WriteLine",
        text="Console.Write/WriteLine ({n}) - check for noisy logs/leaked secrets",
        regex=re.compile(r'\bConsole\.Write(Line)?\s*\('),
        severity="info",
    ),
    # ── cat 15 ──
    P(
        category=15, rule_id="cs.pattern.throw-ex", seq=420,
        label="throw ex",
        text="'throw ex;' pattern ({n}) - resets stack trace, use 'throw;'",
        regex=re.compile(r'\bthrow\s+[A-Za-z_][A-Za-z0-9_]*\s*;'),
        severity="warning",
    ),
    P(
        category=15, rule_id="cs.pattern.empty-catch", seq=430,
        label="empty catch",
        text="Empty catch blocks ({n}) - exceptions swallowed",
        regex=re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}'),
        severity="warning",
    ),
    P(
        category=15, rule_id="cs.pattern.catch-exception", seq=440,
        label="catch(Exception)",
        text="catch(Exception ...) blocks ({n}) - ensure you handle/log appropriately",
        regex=re.compile(r'catch\s*\(\s*Exception\b[^)]*\)\s*\{'),
        severity="info",
    ),
    # ── cat 16 ──
    P(
        category=16, rule_id="cs.pattern.allow-any-origin", seq=450,
        label="AllowAnyOrigin",
        text="AllowAnyOrigin() ({n}) - verify this is intended; can expose APIs to browsers",
        regex=re.compile(r'AllowAnyOrigin\s*\('),
        severity="warning",
    ),
    P(
        category=16, rule_id="cs.pattern.developer-exception-page", seq=460,
        label="UseDeveloperExceptionPage",
        text="UseDeveloperExceptionPage() ({n}) - ensure only enabled in Development",
        regex=re.compile(r'UseDeveloperExceptionPage\s*\('),
        severity="warning",
    ),
    # ── cat 21 ──
    P(
        category=21, rule_id="cs.pattern.bare-catch", seq=470,
        label="catch { }",
        text="catch { } blocks ({n}) - catches all exceptions; ensure logging/rethrow",
        regex=re.compile(r'catch\s*\{\s*\}'),
        severity="warning",
    ),
    P(
        category=21, rule_id="cs.pattern.throw-new-in-catch", seq=480,
        label="throw new Exception in catch",
        text="catch ... throw new ...Exception(...) ({n}) - ensure you preserve original exception as InnerException",
        regex=re.compile(r'catch\s*\([^)]*\)\s*\{[^}]*throw\s+new\s+[A-Za-z_][A-Za-z0-9_]*Exception\s*\('),
        severity="info",
    ),
    # ── cat 22 ──
    P(
        category=22, rule_id="cs.pattern.unchecked-block", seq=490,
        label="unchecked",
        text="unchecked { ... } blocks ({n}) - overflow intentionally ignored; review",
        regex=re.compile(r'\bunchecked\s*\{'),
        severity="info",
    ),
    P(
        category=22, rule_id="cs.pattern.convert-toint32", seq=500,
        label="Convert.ToInt32",
        text="Convert.ToInt32(...) ({n}) - may throw/overflow; ensure bounds checks",
        regex=re.compile(r'\bConvert\.ToInt32\s*\('),
        severity="info",
    ),
    # ── cat 23 ──
    P(
        category=23, rule_id="cs.pattern.parse-no-tryparse", seq=510,
        label="Parse without TryParse",
        text=".Parse(...) calls ({n}) - can throw; prefer TryParse on untrusted input",
        regex=re.compile(r'\b(int|long|double|decimal|DateTime|Guid)\.Parse\s*\('),
        severity="warning",
    ),
    # ── cat 24 ──
    P(
        category=24, rule_id="cs.pattern.new-regex", seq=520,
        label="new Regex",
        text="new Regex(...) ({n}) - consider RegexOptions.Compiled/static caching; beware ReDoS with untrusted patterns",
        regex=re.compile(r'\bnew\s+Regex\s*\('),
        severity="info",
    ),
    P(
        category=24, rule_id="cs.pattern.linq-in-loops", seq=530,
        label="LINQ in loops",
        text="LINQ in loops ({n}) - potential perf hotspots; consider hoisting/optimizing",
        regex=re.compile(r'\b(for|foreach|while)\b.*\.(Select|Where|OrderBy|GroupBy)\s*\('),
        severity="info",
    ),
]
