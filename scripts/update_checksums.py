#!/usr/bin/env python3
"""Update checksums for UBS pinned modules + helper assets.

Updates:
- `ubs`: `MODULE_CHECKSUMS`, `HELPER_CHECKSUMS`, and the `HELPER_ASSETS` list.
- `SHA256SUMS`: release checksums for `install.sh` + `ubs`.
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

def compute_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git_ignored_untracked(root: Path, subdir: Path) -> set[Path]:
    """Untracked files git ignores under `subdir` (editor backups, caches).

    They are never in the repository, so pinning one puts a 404 into
    HELPER_ASSETS. Outside a git checkout (an exported tree) nothing is known
    to be ignored. Only this project's own repository counts: an exported tree
    placed inside some other repository (a vendor/ or build directory that
    repository ignores) would otherwise report every helper as ignored and the
    tables would lose all of their helper pins.
    """
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True, check=False, timeout=60,
        )
        if top.returncode != 0:
            return set()
        toplevel = top.stdout.decode("utf-8", "surrogateescape").rstrip("\n")
        if not toplevel or Path(toplevel).resolve() != root.resolve():
            return set()
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--others", "--ignored",
             "--exclude-standard", "--", str(subdir.relative_to(root))],
            capture_output=True, check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode != 0:
        return set()
    return {
        (root / rel).resolve()
        for rel in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if rel
    }

def main():
    root = Path(__file__).resolve().parent.parent
    ubs_script = root / "ubs"
    install_script = root / "install.sh"
    modules_dir = root / "modules"
    sha256sums = root / "SHA256SUMS"

    if not ubs_script.exists():
        print(f"Error: ubs script not found at {ubs_script}", file=sys.stderr)
        sys.exit(1)

    if not install_script.exists():
        print(f"Error: install.sh not found at {install_script}", file=sys.stderr)
        sys.exit(1)

    if not modules_dir.exists():
        print(f"Error: modules directory not found at {modules_dir}", file=sys.stderr)
        sys.exit(1)

    if not (modules_dir / "contract.json").is_file():
        print(f"Error: required module contract not found at {modules_dir / 'contract.json'}", file=sys.stderr)
        sys.exit(1)

    print("Updating pinned checksums in ubs...")
    
    # Map lang to filename
    # bash associative array keys in ubs: js, python, cpp, rust, golang, java, ruby, swift
    # filenames: ubs-js.sh, ubs-python.sh, etc.
    
    lang_map = {
        "js": "ubs-js.sh",
        "python": "ubs-python.sh",
        "cpp": "ubs-cpp.sh",
        "csharp": "ubs-csharp.sh",
        "rust": "ubs-rust.sh",
        "golang": "ubs-golang.sh",
        "java": "ubs-java.sh",
        "kotlin": "ubs-kotlin.sh",
        "ruby": "ubs-ruby.sh",
        "swift": "ubs-swift.sh",
        "elixir": "ubs-elixir.sh",
        "bash": "ubs-bash.sh",
        "php": "ubs-php.sh",
    }

    new_checksums = {}
    
    for lang, filename in lang_map.items():
        path = modules_dir / filename
        if not path.exists():
            print(f"Warning: Module {filename} not found for {lang}")
            continue
            
        checksum = compute_sha256(path)
        print(f"  {lang}: {checksum}")
        new_checksums[lang] = checksum

    # Step 1: Compute checksums for all helper assets
    helper_map = {
        "contract.json": "contract.json",
        "helpers/async_task_handles_csharp.py": "helpers/async_task_handles_csharp.py",
        "helpers/cfg_test_only_modules_rust.py": "helpers/cfg_test_only_modules_rust.py",
        "helpers/resource_lifecycle_cpp.py": "helpers/resource_lifecycle_cpp.py",
        "helpers/resource_lifecycle_csharp.py": "helpers/resource_lifecycle_csharp.py",
        "helpers/resource_lifecycle_py.py": "helpers/resource_lifecycle_py.py",
        "helpers/resource_lifecycle_go.go": "helpers/resource_lifecycle_go.go",
        "helpers/resource_lifecycle_java.py": "helpers/resource_lifecycle_java.py",
        "helpers/resource_lifecycle_ruby.py": "helpers/resource_lifecycle_ruby.py",
        "helpers/resource_lifecycle_swift.py": "helpers/resource_lifecycle_swift.py",
        "helpers/type_narrowing_csharp.py": "helpers/type_narrowing_csharp.py",
        "helpers/type_narrowing_ts.js": "helpers/type_narrowing_ts.js",
        "helpers/type_narrowing_rust.py": "helpers/type_narrowing_rust.py",
        "helpers/type_narrowing_kotlin.py": "helpers/type_narrowing_kotlin.py",
        "helpers/type_narrowing_swift.py": "helpers/type_narrowing_swift.py",
    }

    core_dir = modules_dir / "helpers" / "ubs_core"
    if core_dir.is_dir():
        ignored = git_ignored_untracked(root, core_dir)
        for path in sorted(core_dir.rglob("*")):
            # Local tool caches (.ruff_cache/, .pytest_cache/, __pycache__/)
            # are not shipped: a pinned path is also a download target in
            # HELPER_ASSETS, and one that is not in the repository 404s on
            # every installed scan.
            parts = path.relative_to(core_dir).parts
            if any(part == "__pycache__" or part.startswith(".") for part in parts):
                continue
            if path.is_file() and path.resolve() not in ignored:
                rel = "helpers/ubs_core/" + path.relative_to(core_dir).as_posix()
                helper_map[rel] = rel

    new_helper_checksums: dict[str, str] = {}
    for rel in sorted(helper_map):
        path = modules_dir / helper_map[rel]
        if not path.exists():
            print(f"Warning: Helper {rel} not found at {path}")
            continue
        checksum = compute_sha256(path)
        print(f"  {rel}: {checksum}")
        new_helper_checksums[rel] = checksum

    # Step 2: Update UBS_COMMON_HELPER_CHECKSUMS in modules/lib/ubs-common.sh
    lib_common = modules_dir / "lib" / "ubs-common.sh"
    if lib_common.exists():
        lib_content = lib_common.read_text(encoding="utf-8")
        lib_helper_pattern = re.compile(
            r"(declare\s+(?:-g\s+)?-A\s+UBS_COMMON_HELPER_CHECKSUMS=\s*\()([\s\S]*?)(\))",
            re.MULTILINE,
        )
        def replace_common_helpers(match):
            prefix = match.group(1)
            suffix = match.group(3)
            lines = []
            for rel in sorted(new_helper_checksums):
                # Include root-level data assets too. The shared library's own
                # digest is added only after rendering this table, below.
                lines.append(f"  ['{rel}']='{new_helper_checksums[rel]}'")
            return f"{prefix}\n" + "\n".join(lines) + f"\n{suffix}"

        new_lib_content = lib_helper_pattern.sub(replace_common_helpers, lib_content)
        if new_lib_content != lib_content:
            lib_common.write_text(new_lib_content, encoding="utf-8")
            print("✓ modules/lib/ubs-common.sh updated with helper checksums.")
        else:
            print("✓ modules/lib/ubs-common.sh helper checksums up to date.")

        # Step 3: Compute sha256 of modules/lib/ubs-common.sh and record it
        lib_checksum = compute_sha256(lib_common)
        new_helper_checksums["lib/ubs-common.sh"] = lib_checksum
        print(f"  lib/ubs-common.sh: {lib_checksum}")
    else:
        print(f"Warning: {lib_common} not found", file=sys.stderr)
        lib_checksum = ""

    # Step 4: Update UBS_LIB_CHECKSUM in each modules/ubs-*.sh and scripts/new-module.sh
    if lib_checksum:
        for mod_path in sorted(modules_dir.glob("ubs-*.sh")):
            mod_text = mod_path.read_text(encoding="utf-8")
            updated_mod_text = re.sub(
                r'UBS_LIB_CHECKSUM="[^"]*"',
                f'UBS_LIB_CHECKSUM="{lib_checksum}"',
                mod_text,
            )
            if updated_mod_text != mod_text:
                mod_path.write_text(updated_mod_text, encoding="utf-8")
                print(f"  ✓ {mod_path.name} updated with UBS_LIB_CHECKSUM={lib_checksum}")

        new_mod_path = root / "scripts" / "new-module.sh"
        if new_mod_path.exists():
            nm_text = new_mod_path.read_text(encoding="utf-8")
            updated_nm_text = re.sub(
                r'UBS_LIB_CHECKSUM="[^"]*"',
                f'UBS_LIB_CHECKSUM="{lib_checksum}"',
                nm_text,
            )
            if updated_nm_text != nm_text:
                new_mod_path.write_text(updated_nm_text, encoding="utf-8")
                print(f"  ✓ scripts/new-module.sh updated with UBS_LIB_CHECKSUM={lib_checksum}")

    # Step 5: Compute module checksums (after UBS_LIB_CHECKSUM is updated)
    new_checksums = {}
    for lang, filename in lang_map.items():
        path = modules_dir / filename
        if not path.exists():
            print(f"Warning: Module {filename} not found for {lang}")
            continue
        checksum = compute_sha256(path)
        print(f"  {lang}: {checksum}")
        new_checksums[lang] = checksum

    # Step 6: Read and update ubs script
    content = ubs_script.read_text(encoding="utf-8")
    daemon_script = root / "ubs-daemon"
    if not daemon_script.is_file() or daemon_script.is_symlink():
        raise SystemExit("Error: a regular ubs-daemon release executable is required")
    daemon_pattern = re.compile(r'^UBS_DAEMON_SHA256="[^"\n]*"$', re.MULTILINE)
    if len(daemon_pattern.findall(content)) != 1:
        raise SystemExit("Error: expected exactly one UBS_DAEMON_SHA256 pin")
    content_with_daemon = daemon_pattern.sub(
        f'UBS_DAEMON_SHA256="{compute_sha256(daemon_script)}"', content)
    
    # Regex to find the MODULE_CHECKSUMS array block
    pattern = re.compile(r"(declare -A MODULE_CHECKSUMS=\s*\()([\s\S]*?)(\))", re.MULTILINE)
    
    def replace_checksums(match):
        prefix = match.group(1)
        suffix = match.group(3)
        lines = []
        for lang in sorted(lang_map.keys()):
            if lang in new_checksums:
                lines.append(f"  [{lang}]='{new_checksums[lang]}'")
        return f"{prefix}\n" + "\n".join(lines) + f"\n{suffix}"

    new_content = pattern.sub(replace_checksums, content_with_daemon)

    helper_pattern = re.compile(r"(declare -A HELPER_CHECKSUMS=\s*\()([\s\S]*?)(\))", re.MULTILINE)

    def replace_helper_checksums(match):
        prefix = match.group(1)
        suffix = match.group(3)
        lines = []
        for rel in sorted(new_helper_checksums.keys()):
            checksum = new_helper_checksums.get(rel)
            if not checksum:
                continue
            lines.append(f"  ['{rel}']='{checksum}'")
        return f"{prefix}\n" + "\n".join(lines) + f"\n{suffix}"

    new_content = helper_pattern.sub(replace_helper_checksums, new_content)

    assets_pattern = re.compile(r"(HELPER_ASSETS=\s*\()([\s\S]*?)(\n\))")

    def replace_assets(match):
        prefix = match.group(1)
        suffix = match.group(3)
        lines = [f'  "{rel}"' for rel in sorted(new_helper_checksums.keys())]
        return prefix + "\n" + "\n".join(lines) + suffix

    new_content = assets_pattern.sub(replace_assets, new_content)
    
    if new_content != content:
        ubs_script.write_text(new_content, encoding="utf-8")
        print("✓ ubs script updated with new checksums.")
    else:
        print("✓ No changes needed in ubs.")

    # Step 7: Update SHA256SUMS
    release_entries = {
        "install.sh": compute_sha256(install_script),
        "ubs": compute_sha256(ubs_script),
        "ubs-daemon": compute_sha256(daemon_script),
    }
    if all(release_entries.values()):
        lines = [f"{release_entries[name]}  {name}" for name in sorted(release_entries)]
        sha256sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("✓ SHA256SUMS updated.")

if __name__ == "__main__":
    main()
