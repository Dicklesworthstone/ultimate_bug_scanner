"""ubs_core.elixir_detectors — ports of the legacy ubs-elixir.sh heredoc detectors.

Every module exposes:
    RULE_ID      stable `ex.<family>.<name>` id (contract rule grammar)
    CATEGORY     legacy category number
    TITLE        the legacy print_finding title (manifest-asserted)
    SEVERITY     fixed severity tier of the legacy print_finding call
    DESCRIPTION  legacy remediation text (informational)
    find(files)  iterable of (path, line, col, detail) per detection

Detection logic is ported verbatim from the module heredocs (same
SOURCE/SINK/sanitizer tables and context windows); only the self-walking
tree iteration is replaced by the caller's file list, and the __COUNT__/
__SAMPLE__ stdout dialect becomes yielded tuples. The heredocs' own
`ubs:ignore` checks (current + previous line) are preserved.

Unlike ruby_detectors, the elixir heredocs carry FOUR subtly different
logical_statement variants (do/end-aware, pipe-continuation-aware, and two
balance-only flavors with different lookahead windows), so each detector
keeps its own verbatim copy instead of sharing one — byte-parity of the
statement reconstruction matters more here than DRY.
"""
