"""Check optional-tool argv using actual Bash functions and inert tool doubles.

These are argument-boundary tests, not Xcode or Mix integration tests. No
developer tool, build, or Simulator is launched.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


def module_function(module: str, name: str) -> str:
    text = (REPO_ROOT / "modules" / module).read_text(encoding="utf-8")
    match = re.search(r"^" + re.escape(name) + r"\(\)\s*\{.*?^\}", text,
                      flags=re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"missing function {name} in {module}")
    return match.group(0)


class OptionalToolArgumentsTest(unittest.TestCase):
    def run_bash(self, script: str, root: Path) -> subprocess.CompletedProcess[str]:
        # Fixed checked-in functions plus shell-quoted test paths only.
        # ubs:ignore[py.security.command-injection]
        result = subprocess.run(
            ["bash", "-c", script], cwd=root,
            env=dict(os.environ, TMPDIR=str(root), PYTHONDONTWRITEBYTECODE="1"),
            text=True, capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def check_swift(self, kind: str, sdk: str | None, container: str) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-swift-argv-") as tmp:
            root = Path(tmp)
            project = root / "project with spaces"
            project.mkdir()
            bundle = project / ("App with spaces." + container)
            bundle.mkdir()
            capture = root / "argv.json"
            function = module_function("ubs-swift.sh", "run_xcodebuild_analyze")
            script = (
                "set -Eeuo pipefail\nIFS=$'\\n'\n" + function + "\n"
                f"PROJECT_DIR={shlex.quote(str(project))}\n"
                f"SDK_KIND={shlex.quote(kind)}\n"
                f"CAPTURE={shlex.quote(str(capture))}\n"
                "print_subheader(){ :; }; say(){ :; }; cleanup_add(){ :; }\n"
                "opt_push_counts(){ :; }\n"
                "GREEN=''; CHECK=''; RESET=''\n"
                # Bash function resolution ensures this never calls real Xcode.
                "xcodebuild(){\n"
                "  if [[ $1 == -list ]]; then printf '%s\\n' "
                "'{\"workspace\":{\"schemes\":[\"Scheme with spaces\"]},"
                "\"project\":{\"schemes\":[\"Scheme with spaces\"]}}'; fi\n"
                "}\n"
                "with_timeout(){ python3 -c "
                "'import json,sys; from pathlib import Path; "
                "Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))' "
                '"$CAPTURE" "$@"; }\n'
                "run_xcodebuild_analyze\n"
            )
            self.run_bash(script, root)
            selector = "-workspace" if container == "xcworkspace" else "-project"
            expected = ["xcodebuild", selector, str(bundle), "-scheme",
                        "Scheme with spaces", "analyze"]
            if sdk is not None:
                expected.extend(["-sdk", sdk])
            try:
                captured = json.loads(capture.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                self.fail(f"optional tool did not produce valid argv JSON: {exc}")
            self.assertEqual(captured, expected)

    def test_swift_sdk_arguments_for_workspaces_and_projects(self) -> None:
        sdks = {"ios": "iphonesimulator", "macos": "macosx",
                "tvos": "appletvsimulator", "watchos": "watchsimulator"}
        for container in ("xcworkspace", "xcodeproj"):
            for kind, sdk in sdks.items():
                with self.subTest(container=container, kind=kind):
                    self.check_swift(kind, sdk, container)

    def test_swift_empty_sdk_array_adds_no_empty_argument(self) -> None:
        # The CLI normalizes unknown SDKs; the private function also must remain
        # safe under nounset if invoked with no optional SDK arguments.
        for container in ("xcworkspace", "xcodeproj"):
            with self.subTest(container=container):
                self.check_swift("unknown", None, container)

    def test_mix_task_and_extra_arguments_keep_literal_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-mix-argv-") as tmp:
            root = Path(tmp)
            (root / "would-expand").touch()
            function = module_function("ubs-elixir.sh", "run_mix_tool")
            script = (
                "set -Eeuo pipefail\n" + function + "\n"
                f"PROJECT_DIR={shlex.quote(str(root))}\n"
                "ENABLE_MIX_TOOLS=1; HAS_MIX=1; EX_TIMEOUT=1200\n"
                "with_timeout(){ printf '%s\\0' \"$@\"; }\n"
                "run_mix_tool 'task with *' '--option=value with spaces' '*'\n"
            )
            result = self.run_bash(script, root)
            self.assertEqual(result.stdout.split("\0"),
                             ["1200", "mix", "task with *",
                              "--option=value with spaces", "*", ""])


if __name__ == "__main__":
    unittest.main()
