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
        timeout=180,
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


def check_rust_cargo_phases(tmpdir: Path) -> None:
    """Issue #99 regression guard: the Rust module's cargo phases (categories
    12-14) were silent no-ops from v5.0.0 to v5.3.13 -- run_cargo_subcmd
    word-split its single "bash -lc '...'" argument, so bash executed `cd` and
    the empty log was reported as "cargo check clean". A sentinel `cargo` on
    PATH is the positive control that would have caught it: it must be hit
    when cargo phases are enabled and never in static-only mode.

    Also pins the surrounding contract: --no-cargo reaches the module through
    the meta-runner, UBS_SKIP_RUST_BUILD covers category 14 too, a targeted
    scan (shadow workspace without Cargo.toml) refuses to run cargo, every
    skip is reported as a typed "Not evaluated" finding rather than silence or
    "clean", and a cargo that exits non-zero without diagnostics is a failure."""
    proj = tmpdir / "cargo_proj"
    (proj / "src").mkdir(parents=True)
    (proj / "Cargo.toml").write_text(
        '[package]\nname = "sentinel_crate"\nversion = "0.0.0"\nedition = "2021"\n'
    )
    (proj / "src" / "lib.rs").write_text(
        "pub fn add(a: u32, b: u32) -> u32 {\n    a.wrapping_add(b)\n}\n"
    )

    fake_bin = tmpdir / "cargo_bin"
    fake_bin.mkdir()
    sentinel = fake_bin / "cargo"
    sentinel.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'cargo %s cwd=%s\\n' \"$*\" \"$PWD\" >> \"${SENTINEL_LOG:?}\"\n"
        "exit \"${SENTINEL_EXIT:-0}\"\n"
    )
    sentinel.chmod(0o755)
    # Make the module believe fmt/clippy are installed so those phases dispatch.
    for helper in ("cargo-fmt", "cargo-clippy"):
        stub = fake_bin / helper
        stub.write_text("#!/usr/bin/env bash\nexit 0\n")
        stub.chmod(0o755)

    counter = {"n": 0}

    def scan(args: list[str], extra_env: dict[str, str], cwd: Path = REPO_ROOT) -> tuple[subprocess.CompletedProcess[str], str]:
        counter["n"] += 1
        log = tmpdir / f"sentinel-{counter['n']}.log"
        env = {
            "NO_COLOR": "1",
            "UBS_ENABLE_AUTO_UPDATE": "0",
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "SENTINEL_LOG": str(log),
        }
        env.update(extra_env)
        merged = os.environ.copy()
        merged.update(env)
        result = subprocess.run(
            [str(UBS_BIN), "--only=rust", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            env=merged,
            check=False,
            timeout=180,
        )
        calls = log.read_text() if log.exists() else ""
        return result, calls

    # Positive control: cargo phases enabled -> the sentinel is really executed,
    # from the crate root, with the documented subcommands.
    result, calls = scan([str(proj)], {})
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    for expected in ("cargo fmt -- --check", "cargo clippy", "cargo check", "cargo test --no-run"):
        assert expected in calls, f"cargo phase '{expected}' never ran:\n{calls}\n{out}"
    assert "Cargo.toml" not in calls  # sanity: cwd lines, not manifest errors
    assert "cargo check clean" in out, out
    assert "Not evaluated" not in out, out

    # --no-cargo is forwarded by the meta-runner: nothing runs, every cargo
    # category says so, and the unqualified "EXCELLENT" banner is withheld.
    result, calls = scan(["--no-cargo", str(proj)], {})
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "scan target not found" not in out, out
    assert calls == "", f"--no-cargo still dispatched cargo:\n{calls}"
    assert out.count("Not evaluated:") >= 3, out
    assert "cargo phases skipped: --no-cargo" in out, out
    assert "EXCELLENT!" not in out, out
    assert "cargo check clean" not in out, out

    # UBS_SKIP_RUST_BUILD covers dependency hygiene (category 14) as well.
    result, calls = scan([str(proj)], {"UBS_SKIP_RUST_BUILD": "1"})
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert calls == "", f"UBS_SKIP_RUST_BUILD=1 still dispatched cargo:\n{calls}"
    assert "dependency hygiene" in out, out
    # The banner must name the lever that actually suppressed the phases, not a
    # hardcoded "--no-cargo".
    assert "cargo phases skipped: UBS_SKIP_RUST_BUILD=1" in out, out

    # Targeted scan: the shadow workspace has no Cargo.toml, so cargo must not
    # run (it would resolve a manifest above the temp dir) and the report must
    # name that reason.
    result, calls = scan(["src/lib.rs"], {}, cwd=proj)
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert calls == "", f"targeted scan dispatched cargo:\n{calls}"
    assert "cargo phases skipped: no Cargo.toml" in out, out
    assert out.count("Not evaluated:") >= 3, out

    # A cargo that fails without emitting diagnostics (wrapper refusing, broken
    # toolchain) is never "clean": since bead D10 it is an environment
    # condition — warnings plus "Not evaluated" per phase, the module reports
    # itself partial, and the run exits 2 (partial) rather than 1 (critical).
    result, calls = scan([str(proj)], {"SENTINEL_EXIT": "103"})
    out = result.stdout + result.stderr
    assert "cargo check" in calls, calls
    assert result.returncode == 2, out
    assert "cargo check clean" not in out, out
    assert "Tests build clean" not in out, out
    assert "exit 103" in out, out
    assert "cargo check could not run" in out, out
    assert "Partial: [CARGO_UNAVAILABLE]" in out, out
    assert "CRITICAL" not in out.split("cargo check could not run", 1)[1].split("\n", 3)[0], out


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
    try:
        payload = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Unsupported-language JSON response is invalid: {exc}\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        ) from exc
    assert payload["result"] == "no-supported-languages", payload
    assert payload["exit_code"] == 3, payload
    assert payload["detected_languages"] == [], payload
    assert "rust" in payload["supported_languages"], payload
    assert payload["totals"]["files"] == 0, payload

    # SARIF: valid log whose invocation carries the no-supported-languages marker.
    res = run_ubs([str(dart_dir), "--format=sarif"], env)
    assert res.returncode == 3, res.stdout + res.stderr
    try:
        sarif = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Unsupported-language SARIF response is invalid JSON: {exc}\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        ) from exc
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
    try:
        payload = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Legacy unsupported-language JSON response is invalid: {exc}\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        ) from exc
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
    subprocess.run([*git_base, "init", "--quiet"], check=True, capture_output=True, timeout=30)
    (foreign / "README.md").write_text("unrelated project\n")
    subprocess.run([*git_base, "add", "README.md"], check=True, capture_output=True, timeout=30)
    subprocess.run(
        [*git_base, "commit", "--quiet", "-m", "unrelated commit"],
        check=True,
        capture_output=True,
        timeout=30,
    )
    foreign_sha = subprocess.run(
        [*git_base, "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
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
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs[label] = result.stdout.strip()

    assert outputs["ubs"].startswith("UBS Meta-Runner v"), outputs
    assert foreign_sha not in outputs["foreign"], outputs
    assert len(set(outputs.values())) == 1, (
        f"--version must not depend on the working directory: {outputs}"
    )


def check_staged_rsync_diagnostics(tmpdir: Path) -> None:
    """Issue #98 regression guard: the staged/diff shadow-copy rsync used to
    run with `>/dev/null 2>&1`, so every failure collapsed into the generic
    "Failed to prepare shadow workspace" with no way to tell permission
    errors, missing paths, ENOSPC or bad file-list entries apart. Worse, the
    staged file list came from non-NUL `git diff --name-only`, which C-quotes
    paths containing backslashes (e.g. systemd mount-unit names like
    `var-tmp-ai\\x2dmachine.mount`), so such repos failed deterministically.

    Two guards: (a) a staged backslash-named file must no longer break
    workspace preparation at all; (b) a real rsync failure must exit non-zero
    AND surface rsync's own exit status and stderr."""
    env = {"NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"}
    repo = tmpdir / "staged_repo"
    repo.mkdir(parents=True)
    git_base = [
        "git",
        "-c",
        "user.name=UBS Test",
        "-c",
        "user.email=ubs-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-C",
        str(repo),
    ]
    subprocess.run([*git_base, "init", "--quiet"], check=True, capture_output=True, timeout=30)
    mount_unit = repo / "var-tmp-ai\\x2dmachine.mount"
    mount_unit.write_text("[Mount]\nWhere=/var/tmp/ai-machine\n")
    subprocess.run([*git_base, "add", "-A"], check=True, capture_output=True, timeout=30)

    def run_staged() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(UBS_BIN), "--staged"],
            cwd=repo,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
            check=False,
            timeout=180,
        )

    # (a) Backslash-named staged file: the C-quoted git record used to poison
    # the rsync --files-from list; with -z parsing the workspace must prepare.
    res = run_staged()
    output = res.stdout + res.stderr
    assert "Failed to prepare shadow workspace" not in output, output
    assert "Scanning shadow workspace" in output, output

    def require_copy_failure(result: subprocess.CompletedProcess[str]) -> None:
        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        assert "Failed to prepare shadow workspace" in output, output
        assert "rsync exited with status" in output, output
        assert "rsync:" in output, output

    # (b) A staged path missing from the worktree forces a real rsync failure
    # even when the suite runs as root (which can read chmod(0) files).
    # Preserve the fixture under another name and restore it after the run.
    parked_unit = repo / "parked-mount-unit"
    mount_unit.rename(parked_unit)
    try:
        require_copy_failure(run_staged())
    finally:
        parked_unit.rename(mount_unit)

    # Also retain the permission-error case wherever the OS enforces it for
    # this user. The missing-path negative above is required on every host.
    mount_unit.chmod(0)
    try:
        if not os.access(mount_unit, os.R_OK):
            require_copy_failure(run_staged())
    finally:
        mount_unit.chmod(0o644)


def check_self_update_dev_checkout_guard(tmpdir: Path) -> None:
    """Issue #107 regression guard: `--update` must recognize BOTH Git checkout
    layouts as development trees. An ordinary clone has a `.git` directory; a
    linked worktree (`git worktree add`) has a regular `.git` FILE holding a
    `gitdir:` pointer. The guard used to test `-d .git` only, so a worktree fell
    through to installed-binary handling — failing with "installed binary is not
    writable" on a read-only source and, on a writable one, heading toward
    replacing tracked source with a release artifact.

    Hermetic: no network is reachable because the fake curl/wget refuse and
    record any attempt; every scanner copy is chmod'ed read-only, and the test
    asserts the bytes are unchanged. The installed-layout control proves the
    guard was not widened into "never update anything"."""
    root = tmpdir / "update_guard"
    root.mkdir(parents=True)

    # A fake downloader that refuses and records: any acquisition attempt is a
    # failure of the guard, not something we want to actually perform.
    fake_bin = root / "bin"
    fake_bin.mkdir()
    attempts = root / "acquisition.log"
    for tool in ("curl", "wget"):
        stub = fake_bin / tool
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f'printf "{tool} %s\\n" "$*" >> "${{ACQUISITION_LOG:?}}"\n'
            "exit 7\n"
        )
        stub.chmod(0o755)

    git_base = [
        "git", "-c", "user.name=UBS Test", "-c", "user.email=ubs-test@example.invalid",
        "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always",
    ]
    repo = root / "repo"
    repo.mkdir()
    subprocess.run([*git_base, "-C", str(repo), "init", "--quiet", "-b", "main"],
                   check=True, capture_output=True, timeout=30)
    shutil.copy2(UBS_BIN, repo / "ubs")
    shutil.copy2(REPO_ROOT / "VERSION", repo / "VERSION")
    subprocess.run([*git_base, "-C", str(repo), "add", "ubs", "VERSION"],
                   check=True, capture_output=True, timeout=30)
    subprocess.run([*git_base, "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
                   check=True, capture_output=True, timeout=30)
    worktree = root / "worktree"
    subprocess.run([*git_base, "-C", str(repo), "worktree", "add", "--quiet",
                    "--detach", str(worktree)], check=True, capture_output=True, timeout=30)
    assert (worktree / ".git").is_file(), "fixture: linked worktree must have a .git FILE"
    assert not (worktree / ".git").is_dir(), "fixture: linked worktree .git must not be a dir"

    installed = root / "installed"
    installed.mkdir()
    shutil.copy2(UBS_BIN, installed / "ubs")
    shutil.copy2(REPO_ROOT / "VERSION", installed / "VERSION")
    assert not (installed / ".git").exists(), "fixture: installed layout must have no .git"

    binaries = {
        "checkout": repo / "ubs",
        "worktree": worktree / "ubs",
        "installed": installed / "ubs",
    }
    before = {name: path.read_bytes() for name, path in binaries.items()}
    for path in binaries.values():
        path.chmod(0o555)

    def update(path: Path, extra_args: list[str]) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "NO_COLOR": "1",
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "ACQUISITION_LOG": str(attempts),
            "UBS_NO_AUTO_UPDATE": "1",
            "UBS_ENABLE_AUTO_UPDATE": "0",
        }
        return subprocess.run(
            ["bash", str(path), "--update", *extra_args],
            cwd=root, capture_output=True, text=True, env=env, check=False,
            timeout=180,
        )

    try:
        for label in ("checkout", "worktree"):
            res = update(binaries[label], [])
            out = res.stdout + res.stderr
            assert res.returncode == 0, f"{label}: exit {res.returncode}\n{out}"
            assert "Development checkout detected" in out, f"{label}: {out}"
            assert "Self-update failed" not in out, f"{label}: {out}"

            quiet = update(binaries[label], ["--quiet"])
            qout = quiet.stdout + quiet.stderr
            assert quiet.returncode == 0, f"{label} --quiet: exit {quiet.returncode}\n{qout}"
            assert "Development checkout detected" not in qout, f"{label} --quiet: {qout}"

        # Neither Git layout may have reached the network at all.
        dev_attempts = attempts.read_text() if attempts.exists() else ""
        assert dev_attempts == "", (
            "development checkouts must not attempt release acquisition:\n" + dev_attempts
        )

        # Control: an installed-layout copy is NOT a development checkout, so it
        # still enters self-update and fails on the refusing downloader.
        res = update(binaries["installed"], [])
        out = res.stdout + res.stderr
        assert res.returncode != 0, out
        assert "Development checkout detected" not in out, out
    finally:
        for path in binaries.values():
            path.chmod(0o644)

    for name, path in binaries.items():
        assert path.read_bytes() == before[name], f"{name}: scanner bytes changed"


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
            timeout=180,
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

        # Issue #98: staged rsync failures must surface rsync's stderr, and
        # backslash-named staged files must not break workspace preparation.
        check_staged_rsync_diagnostics(tmpdir)

        # Issue #99: Rust cargo phases must really run (sentinel positive
        # control) and every static-only path must say so instead of "clean".
        check_rust_cargo_phases(tmpdir)

        # Issue #107: linked Git worktrees are development checkouts too.
        check_self_update_dev_checkout_guard(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
