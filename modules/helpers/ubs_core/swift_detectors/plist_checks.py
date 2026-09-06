"""swift_detectors.plist_checks — cats 17/19 Info.plist ATS + entitlements parse.

Verbatim ports of the run_plist_checks and run_entitlements_checks heredocs
in modules/ubs-swift.sh (plistlib precise parsing). Each finding is one
legacy print_finding (count 1) titled "<title> [<file>]".
"""
from __future__ import annotations

import plistlib
from pathlib import Path

ATS_RULE = "swift.infoplist.ats-parse"
ENTS_RULE = "swift.build.entitlements"

SUSPICIOUS_ENTITLEMENTS = [
    ("get-task-allow", True, "warning", "get-task-allow enabled", "Debugging entitlement present; ensure Release builds disable this."),
    ("com.apple.security.cs.disable-library-validation", True, "warning", "Disable library validation", "Weakens Hardened Runtime; review justification."),
    ("com.apple.security.cs.allow-jit", True, "info", "JIT allowed", "JIT increases attack surface; ensure it is required by ObjC APIs."),
    ("com.apple.security.cs.allow-unsigned-executable-memory", True, "warning", "Unsigned executable memory", "High risk; avoid unless absolutely required."),
    ("com.apple.security.cs.allow-dyld-environment-variables", True, "warning", "DYLD env vars allowed", "High risk; avoid unless required for dev tooling."),
]


def _load(path: Path):
    try:
        with path.open("rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return None


def _ats_findings(path: Path):
    pl = _load(path)
    if not isinstance(pl, dict):
        return
    ats = pl.get("NSAppTransportSecurity") or {}
    if not isinstance(ats, dict):
        return

    if ats.get("NSAllowsArbitraryLoads") is True:
        yield ("warning", str(path), "ATS arbitrary loads enabled", "NSAllowsArbitraryLoads=true")
    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        yield ("info", str(path), "Arbitrary loads in web content", "NSAllowsArbitraryLoadsInWebContent=true")
    if ats.get("NSAllowsLocalNetworking") is True:
        yield ("info", str(path), "Local networking allowed", "NSAllowsLocalNetworking=true")

    ex = ats.get("NSExceptionDomains") or {}
    if isinstance(ex, dict):
        for domain, cfg in ex.items():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                yield ("warning", str(path), f"HTTP allowed for {domain}", "NSExceptionAllowsInsecureHTTPLoads=true")
            if cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads") is True:
                yield ("info", str(path), f"Temporary HTTP for {domain}", "NSTemporaryExceptionAllowsInsecureHTTPLoads=true")
            if cfg.get("NSIncludesSubdomains") is True and ("*" in str(domain)):
                yield ("warning", str(path), f"Broad subdomain exception {domain}", "NSIncludesSubdomains with wildcard-like domain")


def _entitlement_findings(path: Path):
    pl = _load(path)
    if not isinstance(pl, dict):
        return
    for key, val, sev, title, detail in SUSPICIOUS_ENTITLEMENTS:
        if pl.get(key) == val:
            yield (sev, str(path), title, f"{key}={val}; {detail}")


def _walk_candidates(root: Path, matcher):
    """The heredocs os.walk the scan root unpruned."""
    import os

    if root.is_file():
        if matcher(root.name):
            yield root
        return
    if not root.is_dir():
        return
    for dp, _dn, files in os.walk(root):
        for n in files:
            if matcher(n):
                yield Path(dp) / n


def scan(ctx):
    """Emit ATS findings (cat 17) and entitlement findings (cat 19)."""
    root = ctx.project_dir.resolve()
    for path in _walk_candidates(root, lambda n: n == "Info.plist"):
        for sev, fp, title, detail in _ats_findings(path):
            yield {
                "rule": ATS_RULE,
                "category": 17,
                "path": fp,
                "line": 0,
                "severity": sev,
                "count": 1,
                "title": f"{title} [{fp}]",
                "message": f"{title} [{fp}]",
                "description": detail,
            }
    for path in _walk_candidates(root, lambda n: n.endswith(".entitlements")):
        for sev, fp, title, detail in _entitlement_findings(path):
            yield {
                "rule": ENTS_RULE,
                "category": 19,
                "path": fp,
                "line": 0,
                "severity": sev,
                "count": 1,
                "title": f"{title} [{fp}]",
                "message": f"{title} [{fp}]",
                "description": detail,
            }
