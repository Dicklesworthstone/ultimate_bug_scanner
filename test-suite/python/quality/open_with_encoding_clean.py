"""Formatter-wrapped open() calls that are already correct (issue #67).

Every call below is context-managed and either declares an explicit
``encoding=`` or opens in binary mode, where ``encoding=`` is a TypeError.
The argument lists deliberately span multiple physical lines, because that is
what black/ruff produce for long paths and it is exactly the shape that made
``py.open-no-with`` and ``py.open-no-encoding`` misfire.
"""

import os
import pathlib


def load_config():
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "config.json"), encoding="utf-8") as handle:
        return handle.read()


def load_script(script_path):
    with open(script_path,
              encoding="utf-8") as handle:
        return handle.read()


def load_single_line(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def load_binary_positional(path):
    with open(path,
              "rb") as handle:
        return handle.read()


def load_binary_keyword(path):
    with open(path, mode="wb") as handle:
        handle.write(b"")


def load_via_pathlib(path):
    with pathlib.Path(path).open(encoding="utf-8") as handle:
        return handle.read()
