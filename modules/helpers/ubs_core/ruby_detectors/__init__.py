"""ubs_core.ruby_detectors — ports of the legacy ubs-ruby.sh heredoc detectors.

Every module exposes:
    RULE_ID      stable `ruby.<family>.<name>` id (contract rule grammar)
    CATEGORY     legacy category number
    TITLE        the legacy print_finding title (manifest-asserted)
    SEVERITY     fixed severity tier of the legacy print_finding call
    DESCRIPTION  legacy remediation text (informational)
    find(files)  iterable of (path, line, col, detail) per detection

Detection logic is ported verbatim from the module heredocs (same SOURCE/
SINK/sanitizer tables and context windows); only the self-walking tree
iteration is replaced by the caller's file list, and the __COUNT__/
__SAMPLE__ stdout dialect becomes yielded tuples. The heredocs' own
`ubs:ignore` checks (current + previous line) are preserved.
"""
