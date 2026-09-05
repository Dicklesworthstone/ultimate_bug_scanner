"""ubs_core.py_detectors.division — category 2 division ladder (bead 0xjg.5).

Port of the "Division by variable (possible ÷0)" subheader
(modules/ubs-python.sh 10686-10761). Legacy ran `ast-grep run -p '$A / $B'`
and kept matches whose denominator text starts with `[A-Za-z_]` (the temp
script's `re.match(r"^[A-Za-z_]", denom)` variable-divisor filter), falling
back to rg `[A-Za-z0-9_)\\]][[:space:]]*/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*`
with a `grep -Ev "//|/\\*"` post-filter. This port walks ast.BinOp nodes
with ast.Div in-process — same detection, no subprocess.

ast-grep `$A / $B` does NOT match floor division (`a // b` is a different
operator node), so ast.FloorDiv is deliberately excluded, matching the
legacy fallback's `//` exclusion.

Legacy printed ONE tier, first match wins, on the project-wide count:
    warning > 25  "Division by variable - verify non-zero"
    info    > 0   "Division operations found - check divisors"
The multi-rule RULES protocol reproduces that: find() collects every
division line first, then emits records for exactly one tier — never both.
Legacy counted one hit per ast-grep match (nested `a / b / c` scored twice);
v2 counts DISTINCT lines, so one line yields at most one record.

`ubs:ignore` on the hit line or the line immediately before suppresses a
record (and its ladder count), mirroring the marker semantics of the other
detector ports (the legacy ast-grep path predated the marker).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_scan import MARKER

RULES = (
    ("py.numeric.division", 2,
     "Division operations found - check divisors", "info", ""),
    ("py.numeric.division-heavy", 2,
     "Division by variable - verify non-zero", "warning", "Guard before division"),
)

# Legacy ladder (ubs-python.sh 10745, 10759): warning above 25, else info.
WARNING_ABOVE = 25

# Legacy denominator filter: a variable-ish divisor, not a literal.
_DIVISOR_START = re.compile(r"[A-Za-z_]")


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    hits: list[tuple[Path, int, str]] = []
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        seen: set[int] = set()  # DISTINCT division lines per file
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue  # ast.FloorDiv (`//`) is a distinct op — excluded
            denominator = ast.get_source_segment(text, node.right)
            if denominator is None or not _DIVISOR_START.match(denominator):
                continue  # literal / parenthesized / operator denominators
            line_no = node.lineno
            if line_no in seen:
                continue
            idx = line_no - 1
            if any(0 <= i < len(lines) and MARKER in lines[i] for i in (idx, idx - 1)):
                continue  # literal / string / operator-prefix denominators
            seen.add(line_no)
            code = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ''
            hits.append((path, line_no, code))
    if not hits:
        return
    rule = "py.numeric.division-heavy" if len(hits) > WARNING_ABOVE else "py.numeric.division"
    for path, line_no, code in hits:
        yield rule, path, line_no, 1, code
