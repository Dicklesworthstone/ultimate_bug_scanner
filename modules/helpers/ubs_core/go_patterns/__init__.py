"""ubs_core.go_patterns — legacy rg-pipeline pattern tables (bead 0xjg.6).

Ports of the single-regex `grep_count_scoped` checks in modules/ubs-golang.sh
(multi-count ratios, AST-count-gated fallbacks and the project inventory live
in ubs_core.go_scan.computed_checks instead — they are not expressible as one
regex + threshold ladder).
"""
from ubs_core.go_scan import Pattern  # noqa: F401  (re-export for table authors)
