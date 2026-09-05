"""ubs_core.java_detectors — legacy heredoc detector ports (bead 0xjg.8).

Protocol (mirrors ubs_core.py_detectors): single-rule modules expose RULE_ID,
CATEGORY, TITLE, SEVERITY, DESCRIPTION and ``find(files)`` yielding
(path, line, col, detail); multi-rule modules expose ``RULES`` and yield
(rule_id, path, line, col, detail).
"""
