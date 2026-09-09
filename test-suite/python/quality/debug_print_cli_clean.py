#!/usr/bin/env python3
"""A command line entry point may write to stdout (self-scan gate, bead D8).

`py.debug.print` counted every `print(` in a project and turned warning above
50, so any CLI with a real report to render failed its own gate. A module that
declares a CLI role — shebang, argparse, sys.argv, or a __main__ guard — is
exempt; see python/quality/debug_print_library_buggy.py for the shape that is
still reported.
"""
import argparse
import sys


def report(rows):
    print("row 0")
    print("row 1")
    print("row 2")
    print("row 3")
    print("row 4")
    print("row 5")
    print("row 6")
    print("row 7")
    print("row 8")
    print("row 9")
    print("row 10")
    print("row 11")
    print("row 12")
    print("row 13")
    print("row 14")
    print("row 15")
    print("row 16")
    print("row 17")
    print("row 18")
    print("row 19")
    print("row 20")
    print("row 21")
    print("row 22")
    print("row 23")
    print("row 24")
    print("row 25")
    print("row 26")
    print("row 27")
    print("row 28")
    print("row 29")
    print("row 30")
    print("row 31")
    print("row 32")
    print("row 33")
    print("row 34")
    print("row 35")
    print("row 36")
    print("row 37")
    print("row 38")
    print("row 39")
    print("row 40")
    print("row 41")
    print("row 42")
    print("row 43")
    print("row 44")
    print("row 45")
    print("row 46")
    print("row 47")
    print("row 48")
    print("row 49")
    print("row 50")
    print("row 51")
    print("row 52")
    print("row 53")
    print("row 54")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="demo")
    parser.add_argument("--rows", type=int, default=1)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    report(range(args.rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
