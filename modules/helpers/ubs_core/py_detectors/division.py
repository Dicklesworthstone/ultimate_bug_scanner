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

Two precision filters sit on top of the legacy denominator test, because a
`/` in modern Python is far more often a **path join** than a division:

- **Denominator shape is decided on the AST, not the source text.** The
  legacy `^[A-Za-z_]` prefix test accepted an f-string (`base / f"{x}.yml"`
  starts with `f`) and the constants `True`/`None`. A divisor that could be
  zero has to be a name, attribute, subscript or call result — nothing else
  qualifies.
- **pathlib joins are not divisions.** `PurePath.__truediv__` overloads `/`,
  so `rules_dir / name` is a path join. `ubs_core.py_detectors._pathlike`
  decides that statically; see its module docstring for the signals. Before
  this filter the ubs self-scan reported 78 of 85 "Division by variable"
  warnings on its own path joins.

Legacy printed ONE tier, first match wins, on the project-wide count:
    warning > 25  "Division by variable - verify non-zero"
    info    > 0   "Division operations found - check divisors"
The multi-rule RULES protocol reproduces that: find() collects every
division line first, then emits records for exactly one tier — never both.
Legacy counted one hit per ast-grep match (nested `a / b / c` scored twice);
v2 counts DISTINCT lines, so one line yields at most one record.

Comment directives use shared statement ownership and exact rule scopes.
Each ladder tier counts only sites eligible for that tier's public rule ID.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_detectors._pathlike import PathHints
from ubs_core.suppression import SourceSuppressions

RULES = (
    ("py.numeric.division", 2,
     "Division operations found - check divisors", "info", ""),
    ("py.numeric.division-heavy", 2,
     "Division by variable - verify non-zero", "warning", "Guard before division"),
)

# Legacy ladder (ubs-python.sh 10745, 10759): warning above 25, else info.
WARNING_ABOVE = 25

# A divisor that can be zero at runtime: a variable, an attribute, an element
# or a call result. Literals, f-strings, tuples and nested operators are not
# "division by a variable" — the legacy text prefix test only approximated
# this and let f-strings through.
_VARIABLE_DIVISOR_NODES = (ast.Name, ast.Attribute, ast.Subscript, ast.Call)


def _is_variable_divisor(node: ast.AST) -> bool:
    if not isinstance(node, _VARIABLE_DIVISOR_NODES):
        return False
    # `x / True`, `x / None` parse as Name in py2 but as Constant here; a
    # Name that is a known singleton keyword cannot reach this branch. Calls
    # that construct a literal number (`float(1)`) still count: the value is
    # not statically known.
    return True


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    suppressions = SourceSuppressions("python")
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
        suppressions.index(path, text)
        hints = PathHints(tree)
        seen: set[int] = set()  # DISTINCT division lines per file
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue  # ast.FloorDiv (`//`) is a distinct op — excluded
            if not _is_variable_divisor(node.right):
                continue  # literal / f-string / operator denominators
            if hints.is_path_join(node):
                continue  # pathlib join, not arithmetic
            line_no = node.lineno
            if line_no in seen:
                continue
            idx = line_no - 1
            seen.add(line_no)
            code = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ''
            hits.append((path, line_no, code))
    rule = "py.numeric.division-heavy"
    eligible = [hit for hit in hits if not suppressions.is_suppressed(hit[0], hit[1], rule)]
    if len(eligible) <= WARNING_ABOVE:
        rule = "py.numeric.division"
        eligible = [hit for hit in hits if not suppressions.is_suppressed(hit[0], hit[1], rule)]
    for path, line_no, code in eligible:
        yield rule, path, line_no, 1, code
