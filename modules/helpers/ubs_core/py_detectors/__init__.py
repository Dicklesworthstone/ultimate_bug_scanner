"""ubs_core.py_detectors — ports of the legacy ubs-python.sh heredoc detectors.

Every module exposes:
    RULE_ID      stable `py.<family>.<name>` id (contract rule grammar)
    CATEGORY     legacy category number
    TITLE        the legacy print_finding title (manifest-asserted)
    SEVERITY     fixed severity tier of the legacy print_finding call
    DESCRIPTION  legacy remediation text (informational)
    find(files)  iterable of (path, line, col, detail) per detection

Detection logic is ported verbatim from the heredocs (same SOURCE/SINK/
sanitizer tables); the heredocs' own `ubs:ignore` checks are preserved.
"""
