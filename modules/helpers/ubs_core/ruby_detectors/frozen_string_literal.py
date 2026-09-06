"""ubs_core.ruby_detectors.frozen_string_literal — category 17 (bead 0xjg.10).

Port of the legacy frozen_string_literal pragma walk (modules/ubs-ruby.sh
3432-3446): every .rb file whose first two lines lack
`frozen_string_literal:<whitespace>true` counts as one missing-pragma info
finding when the project total exceeds 25. The legacy walk pruned only
.git/vendor/node_modules; the v2 file list is the module's include list, a
strict subset on fixture trees.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "ruby.rails.frozen-string-literal"
CATEGORY = 17
TITLE = "Files missing frozen_string_literal pragma"
SEVERITY = "info"
DESCRIPTION = "Consider enabling globally if beneficial"

PRAGMA_RE = re.compile(r"frozen_string_literal:\s*true")


def find(files: Sequence[Path]) -> Iterable[tuple]:
    # Legacy threshold: the info finding fires only when the project-wide
    # missing-pragma count exceeds 25 (ubs-ruby.sh 3444).
    missing: list[tuple] = []
    for path in files:
        try:
            if not path.is_file() or path.suffix != ".rb":
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                head = [next(fh, "") for _ in range(2)]
        except OSError:
            missing.append((str(path), 1, 1, "unreadable file counts as missing pragma"))
            continue
        if not any(PRAGMA_RE.search(line) for line in head):
            missing.append((str(path), 1, 1, "missing frozen_string_literal: true pragma"))
    if len(missing) > 25:
        yield from missing
