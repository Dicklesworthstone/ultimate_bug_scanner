#!/usr/bin/env python3
"""SARIF parity audit (bead K5): every finding the json report carries should
appear in --format=sarif, for every module.

    uv run python shareable/test_sarif_parity.py                       # table only (audit)
    uv run python shareable/test_sarif_parity.py --assert              # every language must hold the floor
    uv run python shareable/test_sarif_parity.py --assert=python,rust  # assert these, report the rest

For each language the buggy fixture directory is scanned twice with the real
`ubs` (json and sarif). `json_occurrences` is the sum of findings[].count,
`json_samples` the number of sample locations, `sarif_results` the number of
SARIF results. A language is at parity when every json sample location is a
SARIF result (modules record a few samples per finding; a finding without a
recorded sample has no location and therefore no SARIF result — every result
must carry a physical location — its count rides along as
properties.occurrences on the located results). Modules whose json carries
no per-finding records yet (bead K2) only have to produce a non-empty SARIF on
the buggy fixtures.
Prints one `[sarif-parity:<lang>] PASS/FAIL/INFO` line per language.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"
LANGS = ["js", "python", "cpp", "rust", "golang", "java", "ruby", "swift", "csharp", "elixir"]
PARITY_FLOOR = float(os.environ.get("UBS_SARIF_PARITY_FLOOR", "1.0"))


def run(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "UBS_NO_AUTO_UPDATE": "1", "UBS_SKIP_SIZE_CHECK": "1"})
    return subprocess.run([str(UBS_BIN), *args], capture_output=True, text=True, env=env, cwd=REPO_ROOT, timeout=900)  # ubs:ignore


def audit(lang: str) -> dict:
    target = REPO_ROOT / "test-suite" / lang / "buggy"
    if not target.is_dir():
        return {"lang": lang, "skipped": f"no fixture dir {target}"}
    common = ["--ci", f"--only={lang}"]
    jp = run([*common, "--format=json", str(target)])
    sp = run([*common, "--format=sarif", str(target)])
    row = {"lang": lang, "json_exit": jp.returncode, "sarif_exit": sp.returncode}
    try:
        doc = json.loads(jp.stdout)
        scanner = next((s for s in doc.get("scanners", []) if s.get("language") == lang), {})
        findings = scanner.get("findings", []) or []
        row["json_occurrences"] = sum(int(f.get("count", 0) or 0) for f in findings)
        row["json_samples"] = sum(len(f.get("samples", []) or []) for f in findings)
        row["json_titles"] = len(findings)
    except Exception as exc:  # noqa: BLE001
        row["error"] = f"json: {exc}"
    try:
        sarif = json.loads(sp.stdout)
        results = [r for run_ in sarif.get("runs", []) for r in run_.get("results", []) or []]
        row["sarif_results"] = len(results)
        row["sarif_rules"] = len({r.get("ruleId") for r in results})
    except Exception as exc:  # noqa: BLE001
        row["error"] = (row.get("error", "") + f" sarif: {exc}").strip()
    return row


def main(argv: list[str]) -> int:
    strict_langs: set[str] | None = None
    for arg in argv:
        if arg == "--assert":
            strict_langs = set(LANGS)
        elif arg.startswith("--assert="):
            strict_langs = {x for x in arg.split("=", 1)[1].split(",") if x}
    langs = [a for a in argv if not a.startswith("--")] or LANGS
    failures = 0
    print(f"{'lang':8} {'json_occ':>8} {'json_smp':>8} {'sarif':>6}  verdict")
    for lang in langs:
        row = audit(lang)
        if "skipped" in row:
            print(f"[sarif-parity:{lang}] INFO skipped — {row['skipped']}")
            continue
        if "error" in row:
            print(f"[sarif-parity:{lang}] FAIL — {row['error']}")
            failures += 1
            continue
        occ, smp, res, titles = row["json_occurrences"], row["json_samples"], row["sarif_results"], row["json_titles"]
        strict = strict_langs is not None and lang in strict_langs
        if titles == 0:
            # The meta-runner's json carries no per-finding records for this
            # module yet (bead K2): nothing to compare against; SARIF must at
            # least not be empty on the buggy fixtures.
            ok = res > 0
            verdict = "PASS" if ok else ("FAIL" if strict else "GAP")
            print(f"{lang:8} {'n/a':>8} {'n/a':>8} {res:>6}  [sarif-parity:{lang}] {verdict} — json has no per-finding records (bead K2); sarif results {res}, rules {row.get('sarif_rules', 0)}")
        else:
            # Located parity: every json sample location must be a SARIF result
            # (the modules record at most a few samples per finding; occurrences
            # beyond them are summarised in one location-less result each).
            # Located parity: every json sample location is a SARIF result. Findings
            # without recorded samples have no location and therefore no result
            # (every SARIF result must carry one — harness contract); their counts
            # ride along as properties.occurrences on the located results.
            ratio = (res / smp) if smp else (1.0 if res > 0 else 0.0)
            ok = res >= smp * PARITY_FLOOR and (res > 0 or smp == 0)
            verdict = "PASS" if ok else ("FAIL" if strict else "GAP")
            print(f"{lang:8} {occ:>8} {smp:>8} {res:>6}  [sarif-parity:{lang}] {verdict} — sarif results vs json samples {res}/{smp} ({ratio:.0%}), titles {titles}, rules {row.get('sarif_rules', 0)}")
        if strict and not ok:
            failures += 1
    if strict_langs is not None:
        asserted = ", ".join(sorted(strict_langs & set(langs))) or "none"
        print(f"\n[sarif-parity] asserted: {asserted} — {'all at parity' if not failures else f'{failures} below the floor'}")
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
