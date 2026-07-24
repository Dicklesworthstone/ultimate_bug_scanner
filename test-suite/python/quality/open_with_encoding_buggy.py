"""Real open() defects that py.open-no-with / py.open-no-encoding must catch.

Companion to open_with_encoding_clean.py (issue #67): teaching the rules to
understand multi-line argument lists must not silence them. The first call
leaks a handle because it is not context-managed; the second is text-mode
without an explicit encoding, so it decodes with the ambient locale.
"""

import os


def read_leaky(path):
    handle = open(path, encoding="utf-8")
    return handle.read()


def read_locale_dependent(name):
    with open(os.path.join("cfg",
                           name)) as handle:
        return handle.read()
