#!/usr/bin/env python3
"""Generate docs/coverage-matrix.md and README coverage section from detectors.yml (bead D1).

Usage:
    scripts/generate_coverage_matrix.py          # Generate docs/coverage-matrix.md and update README.md
    scripts/generate_coverage_matrix.py --check  # Verify docs/coverage-matrix.md and README.md are up to date
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "detectors.yml"
COVERAGE_MD_PATH = REPO_ROOT / "docs" / "coverage-matrix.md"
README_PATH = REPO_ROOT / "README.md"

README_BEGIN = "<!-- coverage:matrix -->"
README_END = "<!-- /coverage:matrix -->"

LANG_SHORT_DISPLAYS = {
    "js": "JS / TS",
    "python": "Python",
    "golang": "Go",
    "rust": "Rust",
    "java": "Java",
    "cpp": "C / C++",
    "ruby": "Ruby",
    "swift": "Swift",
    "csharp": "C#",
    "elixir": "Elixir",
}


def load_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        raise FileNotFoundError(f"Missing {REGISTRY_PATH}")
    text = REGISTRY_PATH.read_text(encoding="utf-8").strip()
    if text.startswith("{") and text.endswith("}"):
        import json
        return json.loads(text)
    try:
        import yaml
        with REGISTRY_PATH.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        import json
        return json.loads(text)


def render_markdown_matrix(registry: dict[str, Any]) -> str:
    langs = [lang["id"] for lang in registry["languages"]]
    families = registry["families"]

    lines = [
        "# 🧭 UBS Detector Coverage Matrix",
        "",
        "> Generated automatically from [`detectors.yml`](../detectors.yml) by `scripts/generate_coverage_matrix.py`.",
        "> Hand-maintained registry; validated by `test-suite/quality/rule_quality_harness.py`.",
        "",
        "## Summary",
        "",
    ]

    total_cells = len(families) * len(langs)
    implemented_count = 0
    planned_count = 0
    na_count = 0

    for fam_info in families.values():
        dets = fam_info.get("detectors", {})
        for lang in langs:
            st = dets.get(lang, {}).get("status", "planned")
            if st == "implemented":
                implemented_count += 1
            elif st == "n-a":
                na_count += 1
            else:
                planned_count += 1

    lines.extend([
        f"- **Detector Families**: {len(families)}",
        f"- **Languages Supported**: {len(langs)}",
        f"- **Implemented Cells**: {implemented_count} ({implemented_count * 100 / total_cells:.1f}%)",
        f"- **Planned Cells**: {planned_count} ({planned_count * 100 / total_cells:.1f}%)",
        f"- **N/A Cells**: {na_count} ({na_count * 100 / total_cells:.1f}%)",
        "",
        "## Matrix",
        "",
        "Legend:",
        "- **✓** Implemented (with verified buggy and clean regression fixture pairs)",
        "- **○** Planned / In Progress",
        "- **—** Not Applicable for language runtime/ecosystem",
        "",
    ])

    header_cols = ["Family"] + [LANG_SHORT_DISPLAYS.get(lang_id, lang_id) for lang_id in langs]
    lines.append("| " + " | ".join(header_cols) + " |")
    lines.append("| " + " | ".join(["---"] * len(header_cols)) + " |")

    for fam_id, fam_info in sorted(families.items(), key=lambda x: x[1].get("display", x[0])):
        row = [fam_info.get("display", fam_id)]
        dets = fam_info.get("detectors", {})
        for lang_id in langs:
            st = dets.get(lang_id, {}).get("status", "planned")
            if st == "implemented":
                row.append("✓")
            elif st == "n-a":
                row.append("—")
            else:
                row.append("○")
        lines.append("| " + " | ".join(row) + " |")

    lines.extend([
        "",
        "## Family Details",
        "",
    ])

    for fam_id, fam_info in sorted(families.items(), key=lambda x: x[1].get("display", x[0])):
        disp = fam_info.get("display", fam_id)
        desc = fam_info.get("description", "")
        lines.append(f"### {disp} (`{fam_id}`)")
        if desc:
            lines.append(f"{desc}\n")

        dets = fam_info.get("detectors", {})
        impl_langs = [lang_id for lang_id in langs if dets.get(lang_id, {}).get("status") == "implemented"]
        plan_langs = [lang_id for lang_id in langs if dets.get(lang_id, {}).get("status") == "planned"]
        na_langs = [lang_id for lang_id in langs if dets.get(lang_id, {}).get("status") == "n-a"]

        if impl_langs:
            lines.append("**Implemented:**")
            for lang_id in impl_langs:
                d = dets[lang_id]
                rules = ", ".join(f"`{r}`" for r in d.get("rule_ids", []))
                cases = ", ".join(f"`{c}`" for c in d.get("manifest_cases", []))
                lines.append(f"- **{LANG_SHORT_DISPLAYS.get(lang_id, lang_id)}**: {rules} (cases: {cases})")
            lines.append("")

        if plan_langs:
            lines.append(f"**Planned:** {', '.join(LANG_SHORT_DISPLAYS.get(lang_id, lang_id) for lang_id in plan_langs)}\n")

        if na_langs:
            lines.append(f"**N/A:** {', '.join(LANG_SHORT_DISPLAYS.get(lang_id, lang_id) for lang_id in na_langs)}\n")

    return "\n".join(lines) + "\n"


def render_readme_matrix(registry: dict[str, Any]) -> str:
    langs = [lang["id"] for lang in registry["languages"]]
    families = registry["families"]

    lines = [
        "| Detector Family | " + " | ".join(LANG_SHORT_DISPLAYS.get(lang_id, lang_id) for lang_id in langs) + " |",
        "| " + " | ".join(["---"] * (len(langs) + 1)) + " |",
    ]

    for fam_id, fam_info in sorted(families.items(), key=lambda x: x[1].get("display", x[0])):
        row = [fam_info.get("display", fam_id)]
        dets = fam_info.get("detectors", {})
        for lang_id in langs:
            st = dets.get(lang_id, {}).get("status", "planned")
            if st == "implemented":
                row.append("✓")
            elif st == "n-a":
                row.append("—")
            else:
                row.append("○")
        lines.append("| " + " | ".join(row) + " |")

    lines.extend([
        "",
        "*(Legend: **✓** Implemented with dual-sided regression test pairs; **○** Planned; **—** N/A. Full details in [`docs/coverage-matrix.md`](docs/coverage-matrix.md).)*",
    ])
    return "\n".join(lines)


def update_readme(new_content: str, check_only: bool = False) -> bool:
    if not README_PATH.exists():
        return True
    readme_text = README_PATH.read_text(encoding="utf-8")
    if README_BEGIN not in readme_text or README_END not in readme_text:
        return True

    start_pos = readme_text.index(README_BEGIN) + len(README_BEGIN)
    end_pos = readme_text.index(README_END)
    existing_block = readme_text[start_pos:end_pos].strip()
    clean_new_content = new_content.strip()

    if existing_block == clean_new_content:
        return True

    if check_only:
        return False

    updated_text = readme_text[:start_pos] + "\n\n" + clean_new_content + "\n\n" + readme_text[end_pos:]
    README_PATH.write_text(updated_text, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    check_only = "--check" in argv

    try:
        registry = load_registry()
    except Exception as exc:
        print(f"[generate-coverage-matrix] error loading {REGISTRY_PATH}: {exc}", file=sys.stderr)
        return 2

    md_content = render_markdown_matrix(registry)
    readme_block = render_readme_matrix(registry)

    if check_only:
        if not COVERAGE_MD_PATH.exists():
            print(f"[generate-coverage-matrix] {COVERAGE_MD_PATH} is missing", file=sys.stderr)
            return 1
        if COVERAGE_MD_PATH.read_text(encoding="utf-8") != md_content:
            print(f"[generate-coverage-matrix] {COVERAGE_MD_PATH} is out of sync with {REGISTRY_PATH}", file=sys.stderr)
            return 1
        if not update_readme(readme_block, check_only=True):
            print(f"[generate-coverage-matrix] README.md coverage section is out of sync with {REGISTRY_PATH}", file=sys.stderr)
            return 1
        print("[generate-coverage-matrix] docs/coverage-matrix.md and README.md are up to date.")
        return 0

    COVERAGE_MD_PATH.parent.mkdir(parents=True, exist_ok=True)
    COVERAGE_MD_PATH.write_text(md_content, encoding="utf-8")
    update_readme(readme_block, check_only=False)
    print(f"[generate-coverage-matrix] updated {COVERAGE_MD_PATH} and {README_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
