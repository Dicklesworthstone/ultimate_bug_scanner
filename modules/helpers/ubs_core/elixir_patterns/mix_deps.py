"""ubs_core.elixir_patterns.mix_deps — category 14, mix.exs-scoped (bead 0xjg.13).

Legacy ubs-elixir.sh 2915-2942 points these pipelines at "$PROJECT_DIR/mix.exs"
specifically (not the project tree); the file_regex scope reproduces that.
The git-deps and unpinned-deps pipelines only run when mix.exs exists — the
file_regex scope already implies that (no mix.exs in the list, no hits). The
mix.lock filesystem check is a detector (mix_lockfile).
"""
from __future__ import annotations

import re

from ubs_core.elixir_scan import Pattern

_MIX_EXS_PATH = re.compile(r"(^|/)mix\.exs$")

PATTERNS: list[Pattern] = [
    Pattern(
        category=14,
        rule_id="ex.mix.git-deps",
        title="Git-sourced dependencies in mix.exs",
        # legacy 2923: `git:\s*"` over mix.exs, info >0.
        regex=re.compile(r'git:[ \t]*"'),
        file_regex=_MIX_EXS_PATH,
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=14,
        rule_id="ex.mix.unpinned-deps",
        title="Dependencies possibly without version constraints",
        # legacy 2930-2934: NET count of the `\{:\w+,` tuple pipeline minus
        # the pinned `\{:\w+,\s*"~>` pipeline over mix.exs, info when > 3.
        regex=re.compile(r"\{:\w+,"),
        diff_regexes=(re.compile(r'\{:\w+,[ \t]*"~>'),),
        file_regex=_MIX_EXS_PATH,
        thresholds=((3, "info"),),
    ),
]
