"""Real identity-comparison bugs that the 'is' with literals rule must catch.

Companion to is_literal_clean.py (issue #66): narrowing the check to real AST
comparisons must not silence it. Every comparison below relies on CPython
interning and breaks for values computed at runtime.
"""


def classify(status, code, flag, values, name):
    if status is "ready":
        return "ready"
    if code is 200:
        return "ok"
    if flag is True:
        return "enabled"
    if values is []:
        return "empty"
    if name is not "admin":
        return "other"
    if code is -1:
        return "sentinel"
    return "unknown"
