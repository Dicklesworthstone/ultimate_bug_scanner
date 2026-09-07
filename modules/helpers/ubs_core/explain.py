"""ubs_core.explain — rule explainer for UBS static analysis rules (bead K3).

Usage:
    python3 -m ubs_core.explain <rule-id> [--format=text|json] [--repo-root=DIR] [--no-color]
    python3 -m ubs_core explain <rule-id> ...

Inspects a rule: prints its message, remediation, category ID, calibrated
confidence, severity, and buggy / clean fixture code excerpts from the test-suite.
Unknown rule IDs exit 2 with nearest fuzzy/substring matches.
"""
from __future__ import annotations

import argparse
import difflib
import importlib
import inspect
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# Default remediation guidance per detectors.yml family when a specific
# rule doesn't declare a dedicated override.
FAMILY_REMEDIATIONS: dict[str, str] = {
    "archive_extraction": (
        "Validate target paths before extraction. Ensure the canonical destination "
        "path starts with the intended target extraction directory to prevent Zip Slip."
    ),
    "open_redirect": (
        "Validate redirect targets against an allowlist of trusted URLs or enforce "
        "relative path redirects (e.g. starting with '/' and not '//')."
    ),
    "ssrf": (
        "Validate outbound URLs against an IP allowlist and block private, loopback, "
        "and cloud metadata ranges (RFC 1918, 169.254.169.254, 127.0.0.1, ::1)."
    ),
    "header_injection": (
        "Sanitize HTTP header values to disallow carriage return and newline "
        "characters (\\r, \\n) to prevent HTTP response splitting."
    ),
    "path_traversal": (
        "Canonicalize file paths using realpath/resolve and verify the path remains "
        "strictly inside the intended base directory before accessing the filesystem."
    ),
    "security_randomness": (
        "Use a cryptographically secure pseudo-random number generator (CSPRNG, e.g. "
        "crypto.randomBytes, secrets, java.security.SecureRandom) for security tokens, keys, and salts."
    ),
    "ct_compare": (
        "Use constant-time comparison functions (e.g. hmac.compare_digest, crypto.timingSafeEqual, "
        "subtle.ConstantTimeCompare) when comparing passwords, MACs, or cryptographic secrets."
    ),
    "jwt": (
        "Verify JWT signatures with appropriate algorithms (RS256, ES256, HS256) and "
        "explicitly reject the insecure 'none' algorithm."
    ),
    "cors": (
        "Do not combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
        "Validate the incoming Origin against an explicit allowlist."
    ),
    "cookies": (
        "Set the Secure, HttpOnly, and SameSite (Lax or Strict) protection flags on sensitive session cookies."
    ),
    "secrets": (
        "Store sensitive credentials in environment variables or a dedicated secret store; "
        "never hardcode keys, passwords, or tokens in source files."
    ),
    "async_errors": (
        "Ensure all promises and async tasks are awaited or chained with error handlers "
        "to prevent unhandled rejections and resource leaks."
    ),
    "sql_injection": (
        "Use parameterized queries or prepared statements instead of dynamic string concatenation/interpolation."
    ),
    "command_injection": (
        "Pass arguments as parameter arrays rather than executing shell command strings (avoid shell=True / raw shells)."
    ),
    "deserialization": (
        "Avoid deserializing untrusted data with unsafe serialization formats (pickle, yaml.load without SafeLoader, etc.)."
    ),
    "tls_verification": (
        "Enable TLS certificate verification (e.g. verify=True, rejectUnauthorized: true) in production environments."
    ),
    "type_narrowing": (
        "Check for null/undefined before accessing properties or use optional chaining / safe navigation operators."
    ),
    "deep_guard": (
        "Ensure nested object properties are guarded against null or undefined at every step of access."
    ),
    "resource_lifecycle": (
        "Ensure open handles, connections, streams, and files are deterministically released "
        "using context managers (try-with-resources, with, defer, RAII)."
    ),
    "taint": (
        "Sanitize and validate untrusted input before propagating it to sensitive sinks."
    ),
}

LANG_NAMES: dict[str, str] = {
    "js": "JavaScript / TypeScript",
    "javascript": "JavaScript / TypeScript",
    "python": "Python",
    "golang": "Go",
    "go": "Go",
    "rust": "Rust",
    "java": "Java / Kotlin",
    "kotlin": "Kotlin",
    "cpp": "C / C++",
    "c": "C / C++",
    "ruby": "Ruby",
    "swift": "Swift",
    "csharp": "C# / .NET",
    "cs": "C# / .NET",
    "elixir": "Elixir",
}

SRC_EXTS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".kts", ".cpp", ".cc", ".cxx",
    ".c", ".h", ".hh", ".hpp", ".hxx", ".rb", ".swift", ".cs", ".ex", ".exs",
}

IGNORE_FILE_NAMES = {
    "CMakeLists.txt", "Cargo.lock", "Cargo.toml", "go.mod", "go.sum",
    "package.json", "package-lock.json", "tsconfig.json",
}


def find_repo_root(hint: Path | str | None = None) -> Path:
    """Locate the root of the ultimate_bug_scanner repository."""
    if hint:
        p = Path(hint).resolve()
        if (p / "detectors.yml").exists() or (p / "ubs").exists():
            return p
    # Try traversing upwards from __file__
    cur = Path(__file__).resolve()
    for parent in [cur, *cur.parents]:
        if (parent / "detectors.yml").exists() and (parent / "ubs").exists():
            return parent
    # Try CWD
    cwd = Path.cwd().resolve()
    for parent in [cwd, *cwd.parents]:
        if (parent / "detectors.yml").exists() and (parent / "ubs").exists():
            return parent
    return cwd


def _is_case_buggy(case: dict[str, Any]) -> bool:
    path_str = case.get("path", "").lower()
    cid = case.get("id", "").lower()
    tags = [str(t).lower() for t in case.get("tags", [])]
    return "buggy" in path_str or "buggy" in cid or "buggy" in tags


def _is_case_clean(case: dict[str, Any]) -> bool:
    path_str = case.get("path", "").lower()
    cid = case.get("id", "").lower()
    tags = [str(t).lower() for t in case.get("tags", [])]
    return "clean" in path_str or "clean" in cid or "clean" in tags


def _find_primary_source_file(target_path: Path, lang: str | None = None) -> Path | None:
    """Given a file or directory path, resolve the primary code fixture file."""
    if target_path.is_file():
        return target_path
    if not target_path.is_dir():
        return None

    candidates: list[Path] = []
    for f in target_path.iterdir():
        if f.is_file() and f.name not in IGNORE_FILE_NAMES and f.suffix in SRC_EXTS:
            candidates.append(f)

    if not candidates:
        return None

    # Prefer candidate whose extension matches language
    if lang:
        lang_lower = lang.lower()
        for c in candidates:
            ext = c.suffix.lower()
            if "py" in lang_lower and ext in (".py", ".pyi"):
                return c
            if ("js" in lang_lower or "ts" in lang_lower) and ext in (".ts", ".js", ".tsx", ".jsx"):
                return c
            if "go" in lang_lower and ext == ".go":
                return c
            if "rust" in lang_lower and ext == ".rs":
                return c
            if "java" in lang_lower and ext in (".java", ".kt"):
                return c
            if "cpp" in lang_lower and ext in (".cpp", ".cc", ".cxx", ".c"):
                return c
            if "ruby" in lang_lower and ext == ".rb":
                return c
            if "swift" in lang_lower and ext == ".swift":
                return c
            if "cs" in lang_lower and ext == ".cs":
                return c
            if "elixir" in lang_lower and ext in (".ex", ".exs"):
                return c

    return candidates[0]


def _extract_file_excerpt(file_path: Path, max_lines: int = 40) -> str:
    """Read a fixture file and produce a concise, illustrative excerpt."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    lines = content.splitlines()
    if len(lines) <= max_lines:
        return content.rstrip()

    head = lines[:35]
    remaining = len(lines) - 35
    head.append(f"... ({remaining} more lines)")
    return "\n".join(head)


def build_catalog(repo_root: Path) -> dict[str, dict[str, Any]]:
    """Aggregate rule metadata across detectors.yml, ubs_core, and test-suite/manifest.json."""
    catalog: dict[str, dict[str, Any]] = {}

    # 1. detectors.yml registry (authoritative for family, display, manifest cases)
    detectors_path = repo_root / "detectors.yml"
    det_data: dict[str, Any] = {}
    if detectors_path.exists():
        try:
            det_data = json.loads(detectors_path.read_text(encoding="utf-8"))
        except Exception:
            try:
                import yaml
                with detectors_path.open("r", encoding="utf-8") as f:
                    det_data = yaml.safe_load(f) or {}
            except Exception:
                det_data = {}

    for fam_id, fval in det_data.get("families", {}).items():
        fam_display = fval.get("display", fam_id.replace("_", " ").title())
        fam_desc = fval.get("description", "")
        fam_rem = FAMILY_REMEDIATIONS.get(fam_id, fam_desc)
        for lang, dval in fval.get("detectors", {}).items():
            rids = dval.get("rule_ids", [])
            m_cases = dval.get("manifest_cases", [])
            for rid in rids:
                rec = catalog.setdefault(rid, {})
                rec["rule_id"] = rid
                rec["name"] = fam_display
                rec["family"] = fam_id
                rec["family_display"] = fam_display
                rec["family_description"] = fam_desc
                rec["language"] = lang
                rec["severity"] = "critical"
                rec["confidence"] = "high"
                rec["category_id"] = f"{lang}.security"
                rec["message"] = fam_desc
                rec["remediation"] = fam_rem
                rec["manifest_cases"] = list(m_cases)

    # 2. *_detectors modules in modules/helpers/ubs_core
    helpers_core = repo_root / "modules" / "helpers" / "ubs_core"
    if helpers_core.is_dir():
        for dpath in helpers_core.glob("*_detectors"):
            for pyfile in dpath.glob("*.py"):
                if pyfile.name.startswith("__"):
                    continue
                modname = f"ubs_core.{dpath.name}.{pyfile.stem}"
                try:
                    mod = importlib.import_module(modname)
                    rid = getattr(mod, "RULE_ID", None)
                    if rid:
                        rec = catalog.setdefault(rid, {})
                        rec["rule_id"] = rid
                        if not rec.get("language"):
                            rec["language"] = dpath.name.replace("_detectors", "")
                        cat = getattr(mod, "CATEGORY", None)
                        if cat is not None and not rec.get("category_id"):
                            rec["category_id"] = f"{rec.get('language', 'core')}.{cat}"
                        title = getattr(mod, "TITLE", None)
                        if title and (not rec.get("message") or rec.get("message") == rec.get("family_description")):
                            rec["message"] = title
                        sev = getattr(mod, "SEVERITY", None)
                        if sev and not rec.get("severity"):
                            rec["severity"] = sev
                        desc = getattr(mod, "DESCRIPTION", None)
                        if desc and not rec.get("remediation"):
                            rec["remediation"] = desc
                        if not rec.get("confidence"):
                            rec["confidence"] = "high"
                except Exception:
                    pass

        # 3. *_rules.py modules in modules/helpers/ubs_core
        for rfile in helpers_core.glob("*_rules.py"):
            modname = f"ubs_core.{rfile.stem}"
            try:
                mod = importlib.import_module(modname)
                cat_map = getattr(mod, "CATEGORY_MAP", {})
                sev_map = getattr(mod, "SEVERITY_MAP", {})
                sum_map = getattr(mod, "SUMMARY_MAP", {})
                rem_map = getattr(mod, "REMEDIATION_MAP", {})
                rules_list = getattr(mod, "_RULES", [])
                lang_str = rfile.stem.replace("_rules", "")

                for stem, yml in rules_list:
                    m_id = re.search(r"^id:\s*([^\s]+)", yml, re.MULTILINE)
                    m_msg = re.search(r"^message:\s*(.*)$", yml, re.MULTILINE)
                    m_sev = re.search(r"^severity:\s*([^\s]+)", yml, re.MULTILINE)
                    if m_id:
                        rid = m_id.group(1)
                        rec = catalog.setdefault(rid, {})
                        rec["rule_id"] = rid
                        rec.setdefault("language", lang_str)
                        if not rec.get("message") and m_msg:
                            rec["message"] = m_msg.group(1).strip("\"'")
                        if not rec.get("severity") and m_sev:
                            rec["severity"] = m_sev.group(1).strip()
                        rec.setdefault("confidence", "high")
                        rec.setdefault("category_id", f"{lang_str}.general")
                        if not rec.get("remediation"):
                            rec["remediation"] = f"Review and address potential issues flagged by {rid}."

                for rid, cat in cat_map.items():
                    rec = catalog.setdefault(rid, {})
                    rec["rule_id"] = rid
                    rec.setdefault("category_id", f"{lang_str}.{cat}")
                for rid, sev in sev_map.items():
                    rec = catalog.setdefault(rid, {})
                    rec["rule_id"] = rid
                    rec["severity"] = sev
                for rid, summ in sum_map.items():
                    rec = catalog.setdefault(rid, {})
                    rec["rule_id"] = rid
                    rec["message"] = summ
                for rid, rem in rem_map.items():
                    rec = catalog.setdefault(rid, {})
                    rec["rule_id"] = rid
                    rec["remediation"] = rem
            except Exception:
                pass

        # 4. *_patterns modules in modules/helpers/ubs_core
        for dpath in helpers_core.glob("*_patterns"):
            lang_str = dpath.name.replace("_patterns", "")
            for pyfile in dpath.glob("*.py"):
                if pyfile.name.startswith("__"):
                    continue
                modname = f"ubs_core.{dpath.name}.{pyfile.stem}"
                try:
                    mod = importlib.import_module(modname)
                    for p in getattr(mod, "PATTERNS", []):
                        rid = getattr(p, "rule_id", None)
                        if rid:
                            rec = catalog.setdefault(rid, {})
                            rec["rule_id"] = rid
                            rec.setdefault("language", lang_str)
                            cat = getattr(p, "category", None)
                            if cat is not None:
                                rec.setdefault("category_id", f"{lang_str}.{cat}")
                            title = getattr(p, "title", None) or getattr(p, "desc", None) or getattr(p, "name", None)
                            if title and not rec.get("message"):
                                rec["message"] = title
                            rec.setdefault("severity", "warning")
                            rec.setdefault("confidence", "high")
                            if not rec.get("remediation"):
                                rec["remediation"] = f"Refactor code to avoid the pattern identified by {rid}."
                except Exception:
                    pass

        # 5. analyzers in modules/helpers/ubs_core/analyzers
        try:
            from ubs_core.registry import all_analyzers
            import ubs_core.analyzers  # noqa: F401
            for a in all_analyzers():
                mod = inspect.getmodule(a.run)
                if mod:
                    rid = getattr(mod, "RULE_ID", None)
                    if rid:
                        rec = catalog.setdefault(rid, {})
                        rec["rule_id"] = rid
                        rec.setdefault("language", a.lang)
                        rec.setdefault("category_id", getattr(mod, "CATEGORY_ID", f"{a.lang}.{a.layer}"))
                        msg = getattr(mod, "TITLE", None) or getattr(mod, "MESSAGE", None)
                        if msg and not rec.get("message"):
                            rec["message"] = msg
                        rem = getattr(mod, "REMEDIATION", None)
                        if rem and not rec.get("remediation"):
                            rec["remediation"] = rem
                        rec.setdefault("severity", "warning")
                        rec.setdefault("confidence", "high")
        except Exception:
            pass

    return catalog


def resolve_fixtures_for_rule(
    rule_data: dict[str, Any],
    manifest_cases_by_id: dict[str, Any],
    repo_root: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve buggy and clean fixture records with code excerpts for a rule."""
    manifest_cases = rule_data.get("manifest_cases", [])
    lang = rule_data.get("language")

    buggy_case: dict[str, Any] | None = None
    clean_case: dict[str, Any] | None = None

    for cid in manifest_cases:
        case = manifest_cases_by_id.get(cid)
        if not case:
            continue
        if not buggy_case and _is_case_buggy(case):
            buggy_case = case
        elif not clean_case and _is_case_clean(case):
            clean_case = case

    buggy_fixture: dict[str, Any] | None = None
    if buggy_case:
        target_path = repo_root / buggy_case.get("path", "")
        source_file = _find_primary_source_file(target_path, lang)
        if source_file and source_file.exists():
            rel_path = str(source_file.relative_to(repo_root))
            excerpt = _extract_file_excerpt(source_file)
            buggy_fixture = {
                "case_id": buggy_case.get("id", ""),
                "path": rel_path,
                "excerpt": excerpt,
            }

    clean_fixture: dict[str, Any] | None = None
    if clean_case:
        target_path = repo_root / clean_case.get("path", "")
        source_file = _find_primary_source_file(target_path, lang)
        if source_file and source_file.exists():
            rel_path = str(source_file.relative_to(repo_root))
            excerpt = _extract_file_excerpt(source_file)
            clean_fixture = {
                "case_id": clean_case.get("id", ""),
                "path": rel_path,
                "excerpt": excerpt,
            }

    return buggy_fixture, clean_fixture


def find_nearest_matches(query: str, all_ids: list[str], n: int = 5) -> list[str]:
    """Find the closest matching rule IDs using fuzzy and token matching."""
    # 1. Fuzzy match with cutoff
    matches = difflib.get_close_matches(query, all_ids, n=n, cutoff=0.4)
    if matches:
        return matches

    # 2. Lower cutoff fuzzy match
    matches = difflib.get_close_matches(query, all_ids, n=n, cutoff=0.25)
    if matches:
        return matches

    # 3. Substring / token matching
    q_norm = query.lower().replace("-", " ").replace("_", " ").replace(".", " ")
    q_tokens = [t for t in q_norm.split() if len(t) >= 3]
    scored: list[tuple[int, str]] = []
    for rid in all_ids:
        rid_norm = rid.lower()
        score = 0
        if query.lower() in rid_norm:
            score += 10
        for token in q_tokens:
            if token in rid_norm:
                score += 2
        if score > 0:
            scored.append((score, rid))

    scored.sort(key=lambda x: (-x[0], len(x[1])))
    return [item[1] for item in scored[:n]]


def explain_rule(
    rule_id: str | None,
    repo_root: Path | None = None,
    output_format: str = "text",
    no_color: bool = False,
) -> tuple[int, str, str]:
    """Explain a static analysis rule.

    Returns:
        (exit_code, stdout_text, stderr_text)
    """
    root = repo_root or find_repo_root()
    catalog = build_catalog(root)

    # Validate rule_id argument
    if not rule_id or not rule_id.strip():
        err_msg = "rule-id argument is required"
        if output_format == "json":
            out_obj = {
                "error": err_msg,
                "exit_code": 2,
            }
            return 2, json.dumps(out_obj, indent=2) + "\n", f"Error: {err_msg}\n"
        usage_text = (
            "Usage: ubs explain <rule-id> [--format=text|json] [--no-color]\n\n"
            f"Error: {err_msg}.\n"
        )
        return 2, "", usage_text

    target_id = rule_id.strip()
    rule_data: dict[str, Any] | None = catalog.get(target_id)

    # Case-insensitive fallback
    if not rule_data:
        target_lower = target_id.lower()
        for rid, val in catalog.items():
            if rid.lower() == target_lower:
                rule_data = val
                target_id = rid
                break

    # If still not found, suggest nearest matches and exit 2
    if not rule_data:
        suggestions = find_nearest_matches(target_id, list(catalog.keys()), n=5)
        if output_format == "json":
            out_obj = {
                "error": f"Unknown rule '{target_id}'",
                "rule_id": target_id,
                "suggestions": suggestions,
                "exit_code": 2,
            }
            stderr_text = f"Error: Unknown rule '{target_id}'.\n"
            if suggestions:
                stderr_text += "Did you mean one of these?\n" + "".join(f"  - {s}\n" for s in suggestions)
            return 2, json.dumps(out_obj, indent=2) + "\n", stderr_text

        lines = [f"Error: Unknown rule '{target_id}'."]
        if suggestions:
            lines.append("\nDid you mean one of these?")
            for s in suggestions:
                lines.append(f"  - {s}")
        else:
            lines.append("No close matching rules found.")
        return 2, "", "\n".join(lines) + "\n"

    # Load test-suite manifest to resolve fixtures
    manifest_path = root / "test-suite" / "manifest.json"
    manifest_cases_by_id: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            m_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_cases_by_id = {c["id"]: c for c in m_doc.get("cases", [])}
        except Exception:
            pass

    buggy_fixture, clean_fixture = resolve_fixtures_for_rule(rule_data, manifest_cases_by_id, root)

    # Prepare response payload
    rule_rec: dict[str, Any] = {
        "rule_id": target_id,
        "name": rule_data.get("name") or rule_data.get("family_display") or target_id,
        "category_id": rule_data.get("category_id") or "general",
        "family": rule_data.get("family"),
        "language": rule_data.get("language") or "general",
        "severity": rule_data.get("severity") or "warning",
        "confidence": rule_data.get("confidence") or "high",
        "message": rule_data.get("message") or f"Issue detected by {target_id}",
        "remediation": rule_data.get("remediation") or f"Review and resolve findings for {target_id}.",
        "buggy_fixture": buggy_fixture,
        "clean_fixture": clean_fixture,
        "fixtures": {
            "buggy": buggy_fixture,
            "clean": clean_fixture,
        },
    }

    if output_format == "json":
        return 0, json.dumps(rule_rec, indent=2) + "\n", ""

    # Text formatting
    lang_display = LANG_NAMES.get(rule_rec["language"], rule_rec["language"].title())
    color_enabled = not no_color and os.environ.get("NO_COLOR", "") == ""

    # ANSI styles
    BOLD = "\033[1m" if color_enabled else ""
    RESET = "\033[0m" if color_enabled else ""
    CYAN = "\033[36m" if color_enabled else ""
    YELLOW = "\033[33m" if color_enabled else ""
    RED = "\033[31m" if color_enabled else ""
    GREEN = "\033[32m" if color_enabled else ""
    DIM = "\033[2m" if color_enabled else ""

    sev_color = RED if rule_rec["severity"] == "critical" else (YELLOW if rule_rec["severity"] == "warning" else CYAN)

    out_lines: list[str] = [
        f"{CYAN}================================================================================{RESET}",
        f"{BOLD}Rule:{RESET}        {target_id}",
        f"{BOLD}Category:{RESET}    {rule_rec['category_id']}",
        f"{BOLD}Language:{RESET}    {lang_display}",
        f"{BOLD}Severity:{RESET}    {sev_color}{rule_rec['severity']}{RESET}",
        f"{BOLD}Confidence:{RESET}  {GREEN}{rule_rec['confidence']}{RESET} (calibrated)",
        f"{CYAN}================================================================================{RESET}",
        "",
        f"{BOLD}Message:{RESET}",
        f"  {rule_rec['message']}",
        "",
        f"{BOLD}Remediation:{RESET}",
        f"  {rule_rec['remediation']}",
        "",
    ]

    if buggy_fixture:
        b_path = buggy_fixture.get("path", "buggy fixture")
        out_lines.append(f"{RED}{BOLD}Buggy Fixture Example{RESET} ({b_path}):")
        out_lines.append(f"{DIM}--------------------------------------------------------------------------------{RESET}")
        for line in buggy_fixture.get("excerpt", "").splitlines():
            out_lines.append(f"  {line}")
        out_lines.append(f"{DIM}--------------------------------------------------------------------------------{RESET}")
        out_lines.append("")

    if clean_fixture:
        c_path = clean_fixture.get("path", "clean fixture")
        out_lines.append(f"{GREEN}{BOLD}Clean Fixture Example{RESET} ({c_path}):")
        out_lines.append(f"{DIM}--------------------------------------------------------------------------------{RESET}")
        for line in clean_fixture.get("excerpt", "").splitlines():
            out_lines.append(f"  {line}")
        out_lines.append(f"{DIM}--------------------------------------------------------------------------------{RESET}")
        out_lines.append("")

    if not buggy_fixture and not clean_fixture:
        out_lines.append(f"{DIM}No fixture examples registered for this rule.{RESET}")
        out_lines.append("")

    return 0, "\n".join(out_lines) + "\n", ""


def run_explain_cli(args: argparse.Namespace) -> int:
    """CLI dispatcher called by ubs_core.cli or explain main."""
    repo_root = Path(args.repo_root) if getattr(args, "repo_root", None) else None
    fmt = getattr(args, "format", "text")
    no_col = getattr(args, "no_color", False)
    code, out, err = explain_rule(args.rule_id, repo_root=repo_root, output_format=fmt, no_color=no_col)
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if err:
        sys.stderr.write(err)
        sys.stderr.flush()
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ubs explain",
        description="Explain a static analysis rule: message, remediation, fixture examples, confidence, and category.",
    )
    parser.add_argument("rule_id", nargs="?", default=None, help="rule identifier to explain (e.g. py.security.open-redirect)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="output format: text (default) or json")
    parser.add_argument("--repo-root", default=None, help="repository root path")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color escapes")

    args = parser.parse_args(argv)
    return run_explain_cli(args)


if __name__ == "__main__":
    sys.exit(main())
