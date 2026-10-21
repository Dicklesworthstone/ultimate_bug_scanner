"""ubs_core.py_detectors — ports of the legacy ubs-python.sh heredoc detectors.

Every module exposes:
    RULE_ID      stable `py.<family>.<name>` id (contract rule grammar)
    CATEGORY     legacy category number
    TITLE        the legacy print_finding title (manifest-asserted)
    SEVERITY     fixed severity tier of the legacy print_finding call
    DESCRIPTION  legacy remediation text (informational)
    find(files)  iterable of (path, line, col, detail) per detection

Detection logic retains the heredocs' SOURCE/SINK/sanitizer tables. Migrated
detectors use the shared statement-owned, rule-scoped comment policy; remaining
legacy marker checks are tracked by bead A7 rather than treated as equivalent.
"""
