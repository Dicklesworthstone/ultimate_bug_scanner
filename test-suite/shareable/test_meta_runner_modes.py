#!/usr/bin/env python3
"""Regression tests for UBS meta-runner modes that do not scan a checkout."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"


def run_ubs(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    merged_env.update(env)
    return subprocess.run(
        [str(UBS_BIN), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=merged_env,
        check=False,
    )


def assert_not_size_guarded(result: subprocess.CompletedProcess[str]) -> None:
    output = result.stdout + result.stderr
    assert "Directory too large" not in output, output
    assert "Refusing to scan" not in output, output


def assert_no_function_not_found(result: subprocess.CompletedProcess[str]) -> None:
    """Issue #44 regression guard: bash exits 127 with 'command not found'
    when a function is referenced before its definition. The
    --suggest-ignore feature shipped broken because suggest_ignore_candidates
    was defined ~470 lines below its call site. Catch any future
    function-order regression before it ships again."""
    output = result.stdout + result.stderr
    assert "command not found" not in output, output
    assert "(exit 127)" not in output, output


def check_no_supported_languages(tmpdir: Path) -> None:
    """Issue #53 regression guard: a project containing only unsupported
    languages (e.g. Dart) must emit an explicit, machine-readable
    "no-supported-languages" result instead of silently exiting 0 with empty
    stdout. The empty-stdout behavior let review automation record false
    confidence ("UBS passed") for changes UBS never actually scanned.

    Issue #68 follow-up: the exit code must be non-zero too — a distinct 3, so
    consumers gating on $? cannot record "nothing was scanned" as a pass, and
    cannot confuse it with 1 (findings) or 2 (environment error). Legacy exit-0
    behaviour is opt-in via UBS_ALLOW_NO_SCAN=1."""
    env = {"NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"}
    dart_dir = tmpdir / "dart_only"
    (dart_dir / "lib").mkdir(parents=True)
    (dart_dir / "lib" / "main.dart").write_text("void main() {}\n")
    (dart_dir / "pubspec.yaml").write_text("name: demo\n")

    # JSON: structured result object, exit 3 (nothing was scanned ≠ pass).
    res = run_ubs([str(dart_dir), "--format=json"], env)
    assert res.returncode == 3, res.stdout + res.stderr
    assert res.stdout.strip(), "json no-langs result must not be empty stdout"
    payload = json.loads(res.stdout)
    assert payload["result"] == "no-supported-languages", payload
    assert payload["exit_code"] == 3, payload
    assert payload["detected_languages"] == [], payload
    assert "rust" in payload["supported_languages"], payload
    assert payload["totals"]["files"] == 0, payload

    # SARIF: valid log whose invocation carries the no-supported-languages marker.
    res = run_ubs([str(dart_dir), "--format=sarif"], env)
    assert res.returncode == 3, res.stdout + res.stderr
    sarif = json.loads(res.stdout)
    inv = sarif["runs"][0]["invocations"][0]
    assert inv["properties"]["result"] == "no-supported-languages", sarif
    assert inv["exitCode"] == 3, sarif

    # Text: explicit "this is NOT a pass" wording so humans aren't misled either.
    res = run_ubs([str(dart_dir), "--format=text"], env)
    assert res.returncode == 3, res.stdout + res.stderr
    assert "no supported languages" in res.stdout, res.stdout
    assert "NOT a pass" in res.stdout, res.stdout

    # Opt-out: UBS_ALLOW_NO_SCAN=1 restores the legacy exit-0 behaviour for
    # callers that intentionally point UBS at mixed/unsupported trees.
    legacy_env = dict(env, UBS_ALLOW_NO_SCAN="1")
    res = run_ubs([str(dart_dir), "--format=json"], legacy_env)
    assert res.returncode == 0, res.stdout + res.stderr
    payload = json.loads(res.stdout)
    assert payload["result"] == "no-supported-languages", payload
    assert payload["exit_code"] == 0, payload


def check_version_identity(tmpdir: Path) -> None:
    """Issue #79 regression guard: the optional git suffix on --version used to
    come from a bare `git rev-parse --short HEAD`, so it reported whatever
    repository the caller was standing in. UBS then attributed an unrelated
    project's commit to itself, and the identity changed with the working
    directory. The suffix must describe the UBS installation only."""
    env = {"NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"}

    foreign = tmpdir / "foreign_repo"
    foreign.mkdir(parents=True)
    git_base = [
        "git",
        "-c",
        "user.name=UBS Test",
        "-c",
        "user.email=ubs-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-C",
        str(foreign),
    ]
    subprocess.run([*git_base, "init", "--quiet"], check=True, capture_output=True)
    (foreign / "README.md").write_text("unrelated project\n")
    subprocess.run([*git_base, "add", "README.md"], check=True, capture_output=True)
    subprocess.run(
        [*git_base, "commit", "--quiet", "-m", "unrelated commit"],
        check=True,
        capture_output=True,
    )
    foreign_sha = subprocess.run(
        [*git_base, "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert foreign_sha, "could not create a foreign commit to test against"

    plain = tmpdir / "not_a_repo"
    plain.mkdir(parents=True)

    outputs = {}
    for label, cwd in (("ubs", REPO_ROOT), ("foreign", foreign), ("plain", plain)):
        result = subprocess.run(
            [str(UBS_BIN), "--version"],
            cwd=cwd,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs[label] = result.stdout.strip()

    assert outputs["ubs"].startswith("UBS Meta-Runner v"), outputs
    assert foreign_sha not in outputs["foreign"], outputs
    assert len(set(outputs.values())) == 1, (
        f"--version must not depend on the working directory: {outputs}"
    )


def main() -> None:
    tmpdir = Path(tempfile.mkdtemp(prefix="ubs-meta-runner-"))
    try:
        tight_limit_env = {
            "NO_COLOR": "1",
            "UBS_MAX_DIR_SIZE_MB": "1",
            "UBS_SKIP_SIZE_CHECK": "0",
            "UBS_ENABLE_AUTO_UPDATE": "0",
        }

        doctor = run_ubs(["doctor", f"--module-dir={tmpdir / 'modules'}"], tight_limit_env)
        assert doctor.returncode == 0, doctor.stdout + doctor.stderr
        assert "UBS Doctor" in doctor.stdout, doctor.stdout + doctor.stderr
        assert_not_size_guarded(doctor)

        update = run_ubs(["--update", "--quiet"], tight_limit_env)
        assert update.returncode == 0, update.stdout + update.stderr
        assert_not_size_guarded(update)

        # Issue #44: --suggest-ignore exited 127 because
        # suggest_ignore_candidates was called before its definition.
        # Build a tiny project tree with a recognizable language so
        # the meta-runner reaches the suggestion path (an "empty"
        # tree with no recognized files exits early before the
        # function would be called).
        scan_dir = tmpdir / "scan_target"
        (scan_dir / "src").mkdir(parents=True)
        (scan_dir / "src" / "main.rs").write_text("fn main() {}\n")
        (scan_dir / "Cargo.toml").write_text(
            '[package]\nname = "t"\nversion = "0.0.0"\nedition = "2021"\n'
        )
        suggest = subprocess.run(
            [str(UBS_BIN), "--suggest-ignore", str(scan_dir)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"},
            check=False,
        )
        # Function order is the failure mode being guarded against;
        # a non-zero exit from a downstream module is allowed (we don't
        # control what the rust scanner finds in `fn main() {}`), but
        # bash itself must never report "command not found".
        assert_no_function_not_found(suggest)

        # Issue #53: explicit unsupported-language result for Dart-only scans.
        check_no_supported_languages(tmpdir)

        # Issue #79: --version identity must belong to UBS, not the caller's cwd.
        check_version_identity(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
