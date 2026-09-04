#!/usr/bin/env python3
"""Update checksums for UBS pinned modules + helper assets.

Updates:
- `ubs`: `MODULE_CHECKSUMS`, `HELPER_CHECKSUMS`, and the `HELPER_ASSETS` list.
- `SHA256SUMS`: release checksums for `install.sh` + `ubs`.
"""
import hashlib
import re
import sys
from pathlib import Path

def compute_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()

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
        "ruby": "ubs-ruby.sh",
        "swift": "ubs-swift.sh",
        "elixir": "ubs-elixir.sh"
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

    helper_map = {
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
        # Shared module library (bead A1): shipped and verified like a helper.
        "lib/ubs-common.sh": "lib/ubs-common.sh",
    }

    new_helper_checksums: dict[str, str] = {}
    # ubs_core package (beads A2/A6): every shipped file is pinned and verified
    # exactly like a flat helper, including nested analyzer modules.
    core_dir = modules_dir / "helpers" / "ubs_core"
    if core_dir.is_dir():
        for path in sorted(core_dir.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                rel = "helpers/ubs_core/" + path.relative_to(core_dir).as_posix()
                helper_map[rel] = rel

    for rel in sorted(helper_map):
        path = modules_dir / helper_map[rel]
        if not path.exists():
            print(f"Warning: Helper {rel} not found at {path}")
            continue
        checksum = compute_sha256(path)
        print(f"  {rel}: {checksum}")
        new_helper_checksums[rel] = checksum

    # Read ubs script
    content = ubs_script.read_text(encoding="utf-8")
    
    # Regex to find the MODULE_CHECKSUMS array block
    # It looks like:
    # declare -A MODULE_CHECKSUMS=(
    #   [js]='...'
    #   ...
    # )
    
    pattern = re.compile(r"(declare -A MODULE_CHECKSUMS=\s*\()([\s\S]*?)(\))", re.MULTILINE)
    
    def replace_checksums(match):
        prefix = match.group(1)
        suffix = match.group(3)
        
        lines = []
        for lang in sorted(lang_map.keys()): # Sort for stability
            if lang in new_checksums:
                # Preserve indentation
                lines.append(f"  [{lang}]='{new_checksums[lang]}'")
        
        return f"{prefix}\n" + "\n".join(lines) + f"\n{suffix}"

    new_content = pattern.sub(replace_checksums, content)

    helper_pattern = re.compile(r"(declare -A HELPER_CHECKSUMS=\s*\()([\s\S]*?)(\))", re.MULTILINE)

    def replace_helper_checksums(match):
        prefix = match.group(1)
        suffix = match.group(3)
        lines = []
        for rel in sorted(helper_map.keys()):
            checksum = new_helper_checksums.get(rel)
            if not checksum:
                continue
            lines.append(f"  ['{rel}']='{checksum}'")
        return f"{prefix}\n" + "\n".join(lines) + f"\n{suffix}"

    new_content = helper_pattern.sub(replace_helper_checksums, new_content)

    # Keep the shipped-asset list in sync with helper_map (single source of
    # truth), so ubs_core and lib ship through the same verified channel.
    assets_pattern = re.compile(r"(HELPER_ASSETS=\s*\()([\s\S]*?)(\n\))")

    def replace_assets(match):
        prefix = match.group(1)
        suffix = match.group(3)
        lines = [f'  "{rel}"' for rel in sorted(helper_map) if rel in new_helper_checksums]
        return prefix + "\n" + "\n".join(lines) + suffix

    new_content = assets_pattern.sub(replace_assets, new_content)
    
    if new_content != content:
        ubs_script.write_text(new_content, encoding="utf-8")
        print("✓ ubs script updated with new checksums.")
    else:
        print("✓ No changes needed.")

    # Keep repo SHA256SUMS up-to-date so `scripts/verify.sh` and release tooling
    # always have the correct install + runner hashes.
    release_entries = {
        "install.sh": compute_sha256(install_script),
        "ubs": compute_sha256(ubs_script),
    }
    if all(release_entries.values()):
        lines = [f"{release_entries[name]}  {name}" for name in sorted(release_entries)]
        sha256sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("✓ SHA256SUMS updated.")

if __name__ == "__main__":
    main()
