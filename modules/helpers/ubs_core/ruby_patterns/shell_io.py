"""ubs_core.ruby_patterns.shell_io — categories 7 and 8 rg subset (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 7 SHELL / SUBPROCESS SAFETY (2993-3011): Kernel#open pipe, system
  with interpolation, single-arg system form.
- CATEGORY 8 I/O & RESOURCE LIFECYCLE (3014-3037 rg part): File.open without
  block, Dir.chdir, Tempfile/mktmpdir without block. (The resource lifecycle
  correlation itself is the registered lifecycle_ruby analyzer.)
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

# legacy 3049/3072 block-form exclusions: `grep -E -v "do[[:space:]]*\||\{[[:space:]]*\|[^\|]*\|"`
_BLOCK_EXCLUDE = re.compile(r"do[ \t]*\||\{[ \t]*\|[^\|\n]*\|")

PATTERNS: list[Pattern] = [
    # ── Category 7: SHELL / SUBPROCESS SAFETY ───────────────────────────────
    Pattern(
        category=7,
        rule_id="ruby.shell.open-pipe",
        title="open('|cmd') spawns subshell",
        # legacy 3000: `open\([[:space:]]*['\"]\|`, warning >0.
        regex=re.compile(r"open\([ \t]*['\"]\|"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="ruby.shell.system-interpolation",
        title="Interpolated shell commands - sanitize inputs",
        # legacy 3004: `system\(("|')[^"']*#\{[^}]+\}[^"']("|')\)`, warning >0.
        regex=re.compile(r"system\((?:\"|')[^\"\n]*#\{[^}\n]+\}[^\"\n]*(?:\"|')\)"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="ruby.shell.system-single-arg",
        title="Use system('cmd', arg1, ...) to avoid shell",
        # legacy 3008: `system\(['\"][^'\",]+['\"]\)`, info >2.
        regex=re.compile(r"system\(['\"][^'\",\n]+['\"]\)"),
        thresholds=((2, "info"),),
    ),
    # ── Category 8: I/O & RESOURCE LIFECYCLE (rg part) ──────────────────────
    Pattern(
        category=8,
        rule_id="ruby.io.file-open-no-block",
        title="File.open used without block",
        # legacy 3023: `File\.open\([^\)]*\)` minus block forms; warning >5,
        # "Use File.open(...){|f| ... }".
        regex=re.compile(r"File\.open\([^)\n]*\)"),
        exclude_regex=_BLOCK_EXCLUDE,
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=8,
        rule_id="ruby.io.dir-chdir",
        title="Dir.chdir affects global state",
        # legacy 3029: `Dir\.chdir\(`, info >3, "Prefer chdir blocks or
        # absolute paths".
        regex=re.compile(r"Dir\.chdir\("),
        thresholds=((3, "info"),),
    ),
    Pattern(
        category=8,
        rule_id="ruby.io.tempfile-no-block",
        title="Tempfile/tmpdir without block may leak",
        # legacy 3035: `Tempfile\.new\(|Dir\.mktmpdir\(` minus block forms;
        # info >0.
        regex=re.compile(r"Tempfile\.new\(|Dir\.mktmpdir\("),
        exclude_regex=_BLOCK_EXCLUDE,
        thresholds=((0, "info"),),
    ),
]
