"""ubs_core.go_detectors — ports of the legacy ubs-golang.sh heredoc detectors.

Every module exposes:
    RULE_ID      stable `go.<family>.<name>` id (contract rule grammar)
    CATEGORY     legacy category number
    TITLE        the legacy print_finding title (manifest-asserted)
    SEVERITY     fixed severity tier of the legacy print_finding call
    DESCRIPTION  remediation text (informational)
    MARKER       the legacy in-source suppression marker
    find(files)  iterable of (path, line, col, detail) per detection

Detection logic is ported verbatim from the heredocs (same SOURCE/SINK/
sanitizer tables, taint windows, and context windows); the heredocs' own
`ubs:ignore` checks are preserved.
"""
