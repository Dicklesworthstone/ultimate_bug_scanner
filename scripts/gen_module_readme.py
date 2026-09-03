#!/usr/bin/env python3
"""Render the Options block of modules/README.md from modules/contract.json.

    scripts/gen_module_readme.py           rewrite the block in place
    scripts/gen_module_readme.py --check   exit 1 when the README block is stale

The block sits between `<!-- contract:options -->` and
`<!-- /contract:options -->` inside the fenced code block, so the README stays
readable on GitHub while the flag list has exactly one source (bead A3b).
stdlib only; run by scripts/check_docs_claims.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "modules" / "contract.json"
README = ROOT / "modules" / "README.md"
BEGIN, END = "<!-- contract:options -->", "<!-- /contract:options -->"
COL = 19


def note(text: str, err: bool = False) -> None:
    (sys.stderr if err else sys.stdout).write(text + "\n")


def render_block(contract: dict) -> str:
    lines = []
    for entry in contract["flags"]:
        if not entry.get("documented", True):
            continue
        label = entry["flag"]
        if entry.get("value"):
            label += "=" + entry["value"]
        if entry.get("short"):
            label = f"{entry['short']}, {label}"
        doc_lines = entry["doc"].split("\n")
        lines.append(f"{label:<{COL}}{doc_lines[0]}".rstrip())
        for more in doc_lines[1:]:
            lines.append(" " * COL + more)
    return "\n".join(lines) + "\n"


def splice(text: str, block: str) -> str:
    start = text.index(BEGIN) + len(BEGIN)
    end = text.index(END)
    return text[:start] + "\n" + block + text[end:]


def main(argv: list[str]) -> int:
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        note(f"[gen-module-readme] cannot read {CONTRACT}: {exc}", err=True)
        return 2
    text = README.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        note(f"[gen-module-readme] markers {BEGIN} / {END} missing in {README}", err=True)
        return 2
    new = splice(text, render_block(contract))
    if "--check" in argv:
        if new != text:
            note("[gen-module-readme] modules/README.md Options block is stale; run scripts/gen_module_readme.py", err=True)
            return 1
        note("[gen-module-readme] modules/README.md Options block matches contract.json")
        return 0
    if new != text:
        README.write_text(new, encoding="utf-8")
        note("[gen-module-readme] rewrote the Options block")
    else:
        note("[gen-module-readme] already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
