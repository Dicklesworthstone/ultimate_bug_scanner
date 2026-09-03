#!/usr/bin/env python3
"""Documentation claim checker (bead J1, check mode).

The 2026-09-02 reality check found the docs promising flags the binaries did
not accept, language and helper counts that had drifted, and version strings
that disagreed. This script compares what the docs SAY against what the code
DOES and fails when they differ:

  flags        every --flag shown on a `ubs …` / `install.sh …` command line in
               the docs (or in README's option table) is accepted by ubs
               (robot-docs + --help), by a module --help, or by install.sh --help
  languages    every "N languages" claim equals len(ALL_LANGS) and the number of
               modules/ubs-*.sh
  helpers      modules/helpers/* and HELPER_CHECKSUMS in ubs list the same files,
               and AGENTS.md names each helper
  version      VERSION, UBS_VERSION in ubs and the README badge agree
  python-pin   pyproject requires-python, every workflow python-version /
               uv sync --python, the Nix dev shell and the docs name one CPython minor
  exit-codes   README's "Exit Codes:" block lists exactly the codes robot-docs advertises
  installer    every install.sh --help option has a parser arm

Prints one `[docs-claims:<check>] PASS|FAIL — detail` line per check and exits
1 when any check fails. stdlib only; runs the real binaries for their help.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "SKILL.md", ROOT / "modules" / "README.md"] + sorted((ROOT / "docs").glob("*.md"))
FAILURES: list[str] = []

FLAG_RE = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
# Flags of other tools that legitimately appear on the same command line as ubs
# in the docs (e.g. `ubs $(git diff --name-only --cached)`).
FOREIGN_FLAGS = {
    "--name-only", "--cached", "--diff-filter", "--no-verify",  # git
    "--global", "--save-dev",                                    # npm
    "--locked", "--python",                                      # uv
    "--robot", "--robot-triage", "--json",                       # bv / br in AGENTS.md examples
    "--rm", "--network",                                         # docker
    "--yes", "--dry-run", "--no-commit", "--allow-dirty",        # scripts/cut-release.sh
    "--version",                                                 # scripts/verify.sh --version
    "--install-args",                                            # scripts/verify.sh
    "--from-jsonl",                                              # bd import (Beads) piped from --beads-jsonl
}
OTHER_TOOL_MARKERS = (" br ", "bv ", " git ", "npm ", "cass ", "curl ", " uv ", "brew ", "scoop ", "cargo ", "docker ", "nix ", "shellcheck ", "minisign ", "cosign ")


def report(name: str, ok: bool, detail: str = "") -> None:
    print(f"[docs-claims:{name}] {'PASS' if ok else 'FAIL'}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        FAILURES.append(name)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "UBS_NO_AUTO_UPDATE": "1"})
    # ubs:ignore -- every cmd is a fixed repo-local path plus literal flags (see call sites); no user input
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, **kw)


def help_flags(text: str) -> set[str]:
    """--flags introduced in a help text: option lines and usage lines."""
    flags: set[str] = set()
    for line in text.splitlines():
        for match in re.finditer(r"(?<![\w-])(--[a-z][a-z0-9-]*)", line):
            flags.add(match.group(1))
    return flags


def accepted_flags() -> tuple[set[str], set[str], set[str], set[str]]:
    ubs_help = run([str(ROOT / "ubs"), "--help"])
    ubs_flags = help_flags(ubs_help.stdout + ubs_help.stderr)
    robot = run([str(ROOT / "ubs"), "robot-docs", "commands"])
    try:
        doc = json.loads(robot.stdout)
        robot_flags = {f["name"] for f in doc["commands"]["flags"]}
        robot_flags |= help_flags(" ".join(s["usage"] for s in doc["commands"]["subcommands"]))
    except Exception as exc:  # noqa: BLE001
        report("robot-docs", False, f"ubs robot-docs commands is not JSON: {exc}")
        robot_flags = set()
    module_flags: set[str] = set()
    for module in sorted((ROOT / "modules").glob("ubs-*.sh")):
        out = run([str(module), "--help"])
        module_flags |= help_flags(out.stdout + out.stderr)
    for sub in ("doctor", "sessions"):
        out = run([str(ROOT / "ubs"), sub, "--help"])
        ubs_flags |= help_flags(out.stdout + out.stderr)
    install = run(["bash", str(ROOT / "install.sh"), "--help"])
    install_flags = help_flags(install.stdout + install.stderr)
    return ubs_flags, robot_flags, module_flags, install_flags


def doc_command_flags() -> dict[str, list[tuple[Path, int, str]]]:
    """Flags on doc lines that show ubs/install.sh usage, or in README's option table."""
    found: dict[str, list[tuple[Path, int, str]]] = {}
    for doc in DOCS:
        in_ubs_help = False
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("Usage: ubs"):
                in_ubs_help = True
            elif in_ubs_help and line.startswith("```"):
                in_ubs_help = False
            mentions_ubs = bool(re.search(r"(^|[\s`$(/])ubs\s", line)) or "install.sh" in line
            if not (in_ubs_help or mentions_ubs):
                continue
            if any(marker in line for marker in OTHER_TOOL_MARKERS) and not in_ubs_help:
                # A line mixing tools: judge only when ubs is the command being shown.
                if not re.search(r"(^|[\s`$(/])ubs\s+[-a-z.]", line):
                    continue
            for match in FLAG_RE.finditer(line):
                flag = match.group(1)
                found.setdefault(flag, []).append((doc, lineno, line.strip()))
    return found


def check_flags() -> None:
    ubs_flags, robot_flags, module_flags, install_flags = accepted_flags()
    accepted = ubs_flags | robot_flags | module_flags | install_flags | FOREIGN_FLAGS
    unknown = []
    for flag, sites in sorted(doc_command_flags().items()):
        if flag in accepted or flag.startswith("--skip-") or flag == "--robot-" or flag.startswith("--robot"):
            continue
        doc, lineno, text = sites[0]
        unknown.append(f"{flag} ({doc.relative_to(ROOT)}:{lineno}: {text[:70]})")
    report("flags", not unknown, f"{len(unknown)} documented flag(s) no binary accepts: " + "; ".join(unknown) if unknown else f"{len(accepted)} accepted flags, docs consistent")
    # robot-docs must agree with --help.
    missing_in_help = sorted(f for f in robot_flags if f not in ubs_flags and not f.startswith("--skip-LANG"))
    report("robot-docs-vs-help", not missing_in_help, "robot-docs advertises flags --help lacks: " + ", ".join(missing_in_help) if missing_in_help else "every robot-docs flag is in --help")


def check_languages() -> None:
    ubs_text = (ROOT / "ubs").read_text(encoding="utf-8")
    match = re.search(r"^ALL_LANGS=\(([^)]*)\)", ubs_text, re.M)
    langs = match.group(1).split() if match else []
    modules = sorted(p.name for p in (ROOT / "modules").glob("ubs-*.sh"))
    problems = []
    if len(langs) != len(modules):
        problems.append(f"ALL_LANGS has {len(langs)} entries but there are {len(modules)} modules")
    for doc in DOCS:
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            if "narrowing" in lowered:
                continue  # type narrowing covers a documented subset of languages
            if not any(word in lowered for word in ("ubs", "scan", "detect", "cover", "module", "support", "unified", "fixture")):
                continue  # prose about someone else's project, not a claim about UBS
            for m in re.finditer(r"\b(\d+) (?:language modules|languages)\b", line):
                if int(m.group(1)) != len(langs):
                    problems.append(f"{doc.relative_to(ROOT)}:{lineno} claims {m.group(0)}; code has {len(langs)}")
    report("languages", not problems, "; ".join(problems) if problems else f"{len(langs)} languages, {len(modules)} modules, docs agree")


def check_helpers() -> None:
    ubs_text = (ROOT / "ubs").read_text(encoding="utf-8")
    block = re.search(r"declare -A HELPER_CHECKSUMS=\((.*?)\n\)", ubs_text, re.S)
    pinned = set(re.findall(r"\['((?:helpers|lib)/[^']+)'\]", block.group(1))) if block else set()
    on_disk = {f"helpers/{p.name}" for p in (ROOT / "modules" / "helpers").iterdir() if p.is_file() and not p.name.startswith(".")}
    # The shared module library ships through the same checksum channel.
    on_disk |= {f"lib/{p.name}" for p in (ROOT / "modules" / "lib").glob("*.sh")}
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    problems = []
    for name in sorted(on_disk - pinned):
        problems.append(f"{name} is not in HELPER_CHECKSUMS")
    for name in sorted(pinned - on_disk):
        problems.append(f"HELPER_CHECKSUMS lists missing file {name}")
    for name in sorted(on_disk):
        if name.split("/")[-1] not in agents:
            problems.append(f"AGENTS.md does not mention helper {name}")
    report("helpers", not problems, "; ".join(problems) if problems else f"{len(on_disk)} helpers pinned and documented")


def check_version() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    ubs_version = re.search(r'^UBS_VERSION="([^"]+)"', (ROOT / "ubs").read_text(encoding="utf-8"), re.M)
    badge = re.search(r"badge/version-(.+?)-blue\.svg", (ROOT / "README.md").read_text(encoding="utf-8"))
    values = {"VERSION": version, "ubs": ubs_version.group(1) if ubs_version else "?", "README badge": badge.group(1) if badge else "?"}
    ok = len(set(values.values())) == 1
    report("version", ok, ", ".join(f"{k}={v}" for k, v in values.items()))


def check_python_pin() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    req = re.search(r'requires-python\s*=\s*">=(\d+\.\d+)', pyproject)
    pin = req.group(1) if req else "?"
    sites: dict[str, set[str]] = {}
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        vals = set(re.findall(r'python-version:\s*"(\d+\.\d+)"', text)) | set(re.findall(r"--python (\d+\.\d+)", text))
        if vals:
            sites[wf.name] = vals
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sites["README.md"] = set(re.findall(r"CPython (\d+\.\d+)", readme)) | set(re.findall(r"uv sync --python (\d+\.\d+)", readme))
    sites["AGENTS.md"] = set(re.findall(r"Python (\d+\.\d+)", (ROOT / "AGENTS.md").read_text(encoding="utf-8")))
    flake = re.search(r"python3(\d\d)\b", (ROOT / "flake.nix").read_text(encoding="utf-8"))
    sites["flake.nix"] = {f"3.{flake.group(1)}"} if flake else set()
    lock = re.search(r'requires-python = "==(\d+\.\d+)\.\*"', (ROOT / "uv.lock").read_text(encoding="utf-8"))
    sites["uv.lock"] = {lock.group(1)} if lock else set()
    problems = [f"{name} says {sorted(vals)}" for name, vals in sites.items() if vals != {pin}]
    report("python-pin", not problems, f"pyproject pins {pin}; " + ("; ".join(problems) if problems else "every workflow, uv.lock, flake and doc agree"))


def check_exit_codes() -> None:
    robot = run([str(ROOT / "ubs"), "robot-docs", "exit-codes"])
    try:
        advertised = {int(e["code"]) for e in json.loads(robot.stdout)["exit_codes"]}
    except Exception as exc:  # noqa: BLE001
        report("exit-codes", False, f"robot-docs exit-codes unreadable: {exc}")
        return
    readme = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    documented: set[int] = set()
    in_block = False
    for line in readme:
        if line.startswith("Exit Codes:"):
            in_block = True
            continue
        if in_block:
            if line.startswith("```"):
                break
            m = re.match(r"^\s+(\d)\s{2,}", line)
            if m:
                documented.add(int(m.group(1)))
    report("exit-codes", documented == advertised, f"README documents {sorted(documented)}, robot-docs advertises {sorted(advertised)}")


def check_installer_flags() -> None:
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    helped = set(re.findall(r'print_help_option "(--[a-z-]+)', text))
    arms: set[str] = set()
    for m in re.finditer(r"^\s*((?:-[a-zA-Z]\|)?--[a-z-]+(?:\|-?-?[a-z-]+)*)\)", text, re.M):
        arms.update(part for part in m.group(1).split("|") if part.startswith("--"))
    missing = sorted(helped - arms)
    report("installer-flags", not missing, "help lists flags with no parser arm: " + ", ".join(missing) if missing else f"{len(helped)} installer flags all parsed")


MODULE_ARM_RE = re.compile(r"^\s*((?:-[a-zA-Z]\|)?--[a-z][a-z0-9-]*(?:=\*)?(?:\|[^)\n]+)?)\)", re.M)


def module_parser_flags() -> dict[str, set[str]]:
    """Flags each modules/ubs-<lang>.sh accepts, read from its case arms."""
    out: dict[str, set[str]] = {}
    for path in sorted((ROOT / "modules").glob("ubs-*.sh")):
        arms: set[str] = set()
        for m in MODULE_ARM_RE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            for part in m.group(1).split("|"):
                part = part.strip()
                if part.startswith("--"):
                    arms.add(part.split("=", 1)[0])
        out[path.stem.removeprefix("ubs-")] = arms
    return out


def check_module_readme() -> None:
    """modules/README.md names every module on disk, and every flag in its
    Options block exists in the parser of every module it is claimed for
    (all modules by default, the parenthesised subset, or all-except-X)."""
    text = (ROOT / "modules" / "README.md").read_text(encoding="utf-8")
    parsers = module_parser_flags()
    on_disk = set(parsers)
    problems: list[str] = []
    intro = re.search(r"current modules: ([^\n]*)", text)
    listed = set(re.findall(r"`([a-z]+)`", intro.group(1))) if intro else set()
    missing = sorted(on_disk - listed)
    if missing:
        problems.append("modules on disk not named in the intro: " + ", ".join(missing))
    block = re.search(r"Options:\n(.*?)```", text, re.S)
    lines = block.group(1).splitlines() if block else []
    checked = 0
    expected_by_flag: dict[str, set[str]] = {}
    for line in lines:
        m = re.match(r"^(?:-[a-zA-Z], )?(--[a-z][a-z0-9-]*)", line.strip())
        if not m:
            continue
        flag = m.group(1)
        if flag == "--help":
            continue
        rest = line[m.end():]
        expected = set(on_disk)
        except_m = re.search(r"all modules except ([a-z]+)", rest)
        subset_m = re.search(r"\(([a-z]+(?:, [a-z]+)+)\)", rest)
        same_m = re.search(r"same modules as (--[a-z-]+)", rest)
        if except_m:
            expected -= {except_m.group(1)}
        elif subset_m:
            expected = set(subset_m.group(1).split(", "))
        elif same_m:
            if same_m.group(1) not in expected_by_flag:
                problems.append(f"{flag}: refers to {same_m.group(1)}, which is documented later or not at all")
                continue
            expected = set(expected_by_flag[same_m.group(1)])
        expected_by_flag[flag] = expected
        for lang in sorted(expected):
            if lang not in parsers:
                problems.append(f"{flag}: README names unknown module {lang}")
            elif flag not in parsers[lang]:
                problems.append(f"{flag}: README claims {lang} accepts it, but modules/ubs-{lang}.sh has no parser arm")
        checked += 1
    if checked == 0:
        problems.append("no Options block found in modules/README.md")
    report("module-readme", not problems, "; ".join(problems) if problems else f"{checked} documented flags verified against {len(parsers)} module parsers")


def check_toon_digests_in_sync() -> None:
    """The toon_rust asset digests pinned in `ubs` (TOON_ASSET_SHA256, used by
    doctor --fix) and in install.sh (DEP_ASSET_SHA256) must be identical."""
    ubs_text = (ROOT / "ubs").read_text(encoding="utf-8")
    inst_text = (ROOT / "install.sh").read_text(encoding="utf-8")
    block = re.search(r"declare -A TOON_ASSET_SHA256=\((.*?)\)", ubs_text, re.S)
    in_ubs = dict(re.findall(r"\[(toon-[^\]]+)\]='([0-9a-f]{64})'", block.group(1))) if block else {}
    in_inst = dict(re.findall(r"\[(toon-[^\]]+)\]='([0-9a-f]{64})'", inst_text))
    problems: list[str] = []
    if not in_ubs:
        problems.append("no TOON_ASSET_SHA256 table in ubs")
    for name in sorted(set(in_ubs) | set(in_inst)):
        if in_ubs.get(name) != in_inst.get(name):
            problems.append(f"{name}: ubs={in_ubs.get(name, 'missing')[:12]} install.sh={in_inst.get(name, 'missing')[:12]}")
    report("toon-digests", not problems, "; ".join(problems) if problems else f"{len(in_ubs)} toon_rust asset digests identical in ubs and install.sh")


def check_help_heredoc_static() -> None:
    """The usage() help text in `ubs` is an unquoted heredoc: a backtick or $( )
    in it is executed at `ubs --help` time (twice in 2026 it ran `python`
    interactively and hung the installer's self-check). Nothing in that block
    may look like a command substitution."""
    text = (ROOT / "ubs").read_text(encoding="utf-8")
    start = text.find("usage() {")
    end = text.find("\nUSAGE\n", start)
    if start < 0 or end < 0:
        report("help-heredoc", False, "usage() heredoc not found in ubs")
        return
    offenders = [ln.strip()[:80] for ln in text[start:end].splitlines() if "`" in ln or "$(" in ln]
    report("help-heredoc", not offenders, "; ".join(offenders) if offenders else "no command substitution in the usage() heredoc")


def main() -> int:
    for check in (check_flags, check_languages, check_helpers, check_version, check_python_pin, check_exit_codes, check_installer_flags, check_module_readme, check_toon_digests_in_sync, check_help_heredoc_static):
        try:
            check()
        except Exception as exc:  # noqa: BLE001
            report(check.__name__.replace("check_", ""), False, f"raised {exc!r}")
    if FAILURES:
        print(f"\n[docs-claims] {len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("\n[docs-claims] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
