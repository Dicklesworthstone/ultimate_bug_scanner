"""swift_detectors.shell_execution — cat 6 "Process/posix shell usage".

Verbatim port of the shell-report heredoc in modules/ubs-swift.sh (ubs#101
semantics: bare and module-qualified C calls count, SwiftUI member
expressions and method declarations do not). The Process-info residual reuses
the actual source anchors so shell calls cannot consume another file's count.
"""
from __future__ import annotations

import re
from pathlib import Path

from ubs_core.swift_detectors._common import rel, should_skip

RULE_ID = "swift.security.shell-exec"
CATEGORY = 6
TITLE = "Shell-backed Process/system execution"
SEVERITY = "critical"

SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'DerivedData', 'build', 'dist', 'vendor'}
shell_path = re.compile(r"/(?:usr/)?bin/(?:sh|bash|zsh)$")
name = r"[A-Za-z_][A-Za-z0-9_]*"

# system(), popen() and posix_spawn() are C free functions, and a bare \b in
# front of them also matches at the boundary between "." and the name. Swift
# spells implicit- and qualified-member expressions with that dot, so
# ".font(.system(size: 13))" and "Font.system(size: 12)" -- SwiftUI font
# constructors -- were reported as shell execution (ubs#101). Requiring that no
# "." or identifier character precede the name drops them.
#
# The one legitimate dotted form is a C module qualifier: "Darwin.system(...)"
# and "Glibc.system(...)" really are the C call, so they get their own pattern
# rather than being lost with the member calls.
c_module = r"(?:Darwin|Glibc|SwiftGlibc|Musl|Foundation|WinSDK|ucrt|CRT|MSVCRT|Android|Bionic)"
shell_exec_calls = re.compile(
    r"(?<![.\w])(?:system|popen)\s*\("
    rf"|(?<![.\w]){c_module}\s*\.\s*(?:system|popen)\s*\("
)
posix_spawn_calls = re.compile(
    r"(?<![.\w])posix_spawnp?\s*\("
    rf"|(?<![.\w]){c_module}\s*\.\s*posix_spawnp?\s*\("
)
# Declaring a Swift method named system/popen is not calling the C one, and the
# declaration's name sits at a word boundary just like a call would.
shell_exec_declarations = re.compile(r"\bfunc\s+(?:system|popen|posix_spawnp?)\s*\(")


def executable_code(code: str) -> str:
    """Blank out declarations so only real call sites are matched."""
    return shell_exec_declarations.sub(lambda m: " " * len(m.group(0)), code)


def collect_findings(ctx):
    root = ctx.project_dir.resolve()
    base = root if root.is_dir() else root.parent
    findings = []
    for candidate in ctx.files:
        path = Path(candidate).resolve()
        if path.suffix != '.swift':
            continue
        if path != root and should_skip(path, base, SKIP_DIRS):
            continue
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        processes = {}
        for line_no, raw in enumerate(lines, start=1):
            code = raw.split('//', 1)[0].strip()
            if not code:
                continue
            callable_code = executable_code(code)
            if shell_exec_calls.search(callable_code):
                findings.append((rel(path, base), line_no, raw.strip(), "system/popen executes through a shell"))
            if posix_spawn_calls.search(callable_code) and re.search(r'"/(?:usr/)?bin/(?:sh|bash|zsh)"', code) and '"-c"' in code:
                findings.append((rel(path, base), line_no, raw.strip(), "posix_spawn shell -c"))

            created = re.search(rf"\b(?:let|var)\s+({name})\s*=\s*Process\s*\(", code)
            if created:
                processes.setdefault(created.group(1), {'line': line_no})

            executable = re.search(rf"\b({name})\.(?:executableURL|launchPath)\s*=\s*(?:URL\s*\(\s*fileURLWithPath:\s*)?[\"']([^\"']+)[\"']", code)
            if executable:
                proc = processes.setdefault(executable.group(1), {'line': line_no})
                proc['line'] = min(proc.get('line', line_no), line_no)
                proc['shell'] = shell_path.search(executable.group(2)) is not None
                proc['env'] = executable.group(2) == '/usr/bin/env'

            arguments = re.search(rf"\b({name})\.arguments\s*=\s*\[([^\]]*)", code)
            if arguments:
                proc = processes.setdefault(arguments.group(1), {'line': line_no})
                proc['line'] = min(proc.get('line', line_no), line_no)
                blob = arguments.group(2)
                proc['command_mode'] = '"-c"' in blob or "'-c'" in blob
                proc['env_shell'] = re.search(r"[\"'](?:sh|bash|zsh)[\"']", blob) is not None

        for proc_name, proc in processes.items():
            if proc.get('command_mode') and (proc.get('shell') or (proc.get('env') and proc.get('env_shell'))):
                line_no = proc.get('line', 1)
                findings.append((rel(path, base), line_no, lines[line_no - 1].strip(), f"Process {proc_name} uses shell -c"))
    return findings


def scan(ctx):
    desc = "Avoid /bin/sh -c, system(), and popen(); use a fixed executableURL plus an argument array."
    for path, line, code, reason in collect_findings(ctx):
        yield {
            "rule": RULE_ID,
            "category": CATEGORY,
            "path": path,
            "line": line,
            "severity": SEVERITY,
            "count": 1,
            "title": TITLE,
            "message": TITLE,
            "description": f"{desc} {reason}.",
            "samples": [{"path": path, "line": line, "code": code}],
        }
