"""ubs_core.csharp_patterns — legacy rg-pipeline pattern table (bead 0xjg.12).

Each Pattern reproduces one legacy ubs-csharp.sh ``search`` + ``count_lines``
+ ``bump_counter`` pipeline: the regex is matched LINE-anchored (rg never
matches across lines), counts are distinct matching lines across the file
list with ``ubs:ignore`` marker lines dropped (count_lines parity), and the
legacy severity is fixed per check (every C# check is a single-tier
``>0`` ladder).

exclude_regex re-applies legacy ``grep -v`` post-filters against the rg
output form ``path:line:content``. gate_regex expresses legacy project-wide
preconditions (cat 20's await census). POSIX classes from the shell patterns
(``[[:space:]]``) are transliterated to ``[ \\t]`` — semantically identical
for single-line matching.
"""
