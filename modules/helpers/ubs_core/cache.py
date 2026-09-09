"""ubs_core.cache — Merkle-keyed incremental scan cache (bead C4).

Provides:
- Cache root: $XDG_CACHE_HOME/ubs/<H(engine‖module checksum‖rulepack hash)>/
- Per-file entries keyed by BLAKE2b(file bytes) storing NDJSON findings.
- Per-directory Merkle nodes keyed by hash of child names+hashes
  (from `git ls-files -s` blob ids in clean git tree, else stat+content hash).
- Whole-subtree skip when directory Merkle nodes match.
- Cross-file dependency tracking (inputs set).
- Lock-free reads, atomic writes (temp + os.replace).
- User controls: UBS_CACHE_DIR, UBS_NO_CACHE, --no-cache, --prune-cache.
- Doctor diagnostics and prune support.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

# Environment variables
ENV_CACHE_DIR = "UBS_CACHE_DIR"
ENV_NO_CACHE = "UBS_NO_CACHE"
ENV_CACHE_FILE = "UBS_CACHE_FILE"


def get_cache_base_dir() -> Path:
    """Return the base directory for UBS caches."""
    override = os.environ.get(ENV_CACHE_DIR)
    if override:
        return Path(override).expanduser().resolve()
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg).expanduser().resolve() / "ubs"
    return Path.home() / ".cache" / "ubs"


def is_cache_disabled() -> bool:
    """Check if cache reading/writing is disabled."""
    val = os.environ.get(ENV_NO_CACHE, "").strip().lower()
    return val in ("1", "true", "yes", "on")


CACHE_SCHEMA_VERSION = "2"


def compute_cache_key(
    lang: str,
    engine_version: str = "",
    module_checksum: str = "",
    rulepack_hash: str = "",
    extra: str = "",
) -> str:
    """Compute the cache directory key H(engine‖module checksum‖rulepack hash)."""
    if not engine_version:
        engine_version = "5.3.13"
    h = hashlib.blake2b(digest_size=16)
    payload = f"v{CACHE_SCHEMA_VERSION}‖{lang}‖{engine_version}‖{module_checksum}‖{rulepack_hash}‖{extra}".encode("utf-8")
    h.update(payload)
    return h.hexdigest()


def atomic_write_json(target_path: Path, data: Any) -> None:
    """Write data as JSON to target_path atomically using tempfile + os.replace."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.parent / f".tmp.{os.getpid()}.{uuid.uuid4().hex}"
    try:
        temp_path.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temp_path, target_path)
    except OSError:
        pass
    finally:
        if temp_path.is_file():
            try:
                temp_path.unlink()
            except OSError:
                pass


def lock_free_read_json(target_path: Path) -> Any | None:
    """Read data as JSON lock-free, handling missing or partial files gracefully."""
    try:
        with open(target_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def get_clean_git_blobs(project_dir: Path) -> dict[str, str] | None:
    """If project_dir is inside a clean git worktree, return {rel_posix_path: blob_sha}."""
    try:
        cur = project_dir.resolve()
        is_git = False
        for _ in range(10):
            if (cur / ".git").exists():
                is_git = True
                break
            if cur.parent == cur:
                break
            cur = cur.parent
        if not is_git:
            return None

        # Check if git is available and tree is clean
        status_res = subprocess.run(
            ["git", "-C", str(project_dir), "status", "--porcelain"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
        )
        if status_res.returncode != 0:
            return None
        # Must have zero modified/untracked files for a clean git tree
        if status_res.stdout.strip():
            return None
        ls_res = subprocess.run(
            ["git", "-C", str(project_dir), "ls-files", "-s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if ls_res.returncode != 0:
            return None
        blobs: dict[str, str] = {}
        for line in ls_res.stdout.splitlines():
            # Format: <mode> <blob_sha> <stage>\t<relpath>
            parts = line.split(None, 3)
            if len(parts) >= 4:
                blob_sha = parts[1]
                path_str = parts[3].strip()
                blobs[path_str] = blob_sha
        return blobs
    except (OSError, subprocess.SubprocessError):
        return None


LANG_PREFIX_MAP = {
    "python": "py", "py": "py",
    "golang": "go", "go": "go",
    "javascript": "js", "typescript": "js", "js": "js", "ts": "js",
    "csharp": "csharp", "cs": "csharp",
    "cpp": "cpp", "c": "cpp",
    "rust": "rust", "rs": "rust",
    "java": "java",
    "kotlin": "kotlin", "kt": "kotlin",
    "ruby": "ruby", "rb": "ruby",
    "swift": "swift",
    "elixir": "elixir", "ex": "elixir",
    "bash": "bash", "sh": "bash",
}


def hash_rules_dir(rules_dir: Path | str) -> str:
    """Hash the contents of an ast-grep rules directory."""
    p = Path(rules_dir)
    if not p.is_dir():
        return ""
    h = hashlib.blake2b(digest_size=16)
    for rf in sorted(p.rglob("*.yml")):
        try:
            h.update(rf.name.encode("utf-8"))
            h.update(rf.read_bytes())
        except OSError:
            pass
    for mf in sorted(p.rglob("*.json")):
        try:
            h.update(mf.name.encode("utf-8"))
            h.update(mf.read_bytes())
        except OSError:
            pass
    return h.hexdigest()


class CapturingSink:
    """Wraps an underlying file sink to capture findings emitted per file."""

    def __init__(self, target_sink: Any = None, project_dir: Path | str | None = None) -> None:
        self._sink = target_sink
        self.project_dir = Path(project_dir).resolve() if project_dir else None
        self.by_file: dict[str, list[dict]] = {}

    def write(self, s: str) -> int:
        n = self._sink.write(s) if self._sink is not None else len(s)
        line = s.strip()
        if line:
            try:
                rec = json.loads(line)
                if isinstance(rec, dict) and "path" in rec and "rule" in rec:
                    p = str(rec.get("path", ""))
                    self.by_file.setdefault(p, []).append(rec)
            except ValueError:
                pass
        return n

    def get_for_file(self, f: Path | str, project_dir: Path | str | None = None) -> list[dict]:
        """Look up captured findings for a file under relative or absolute path variants."""
        path_obj = Path(f)
        str_f = str(f)
        try:
            target_res = str(path_obj.resolve())
        except Exception:
            target_res = str_f

        p_dir = Path(project_dir).resolve() if project_dir else self.project_dir
        collected: list[dict] = []
        seen_ids: set[int] = set()

        for k, v in self.by_file.items():
            if not k:
                continue
            matches = False
            if k == str_f or k == path_obj.name:
                matches = True
            else:
                try:
                    k_path = Path(k)
                    if str(k_path.resolve()) == target_res:
                        matches = True
                    elif p_dir and str((p_dir / k_path).resolve()) == target_res:
                        matches = True
                except Exception:
                    pass
            if matches:
                for r in v:
                    r_id = id(r)
                    if r_id not in seen_ids:
                        seen_ids.add(r_id)
                        collected.append(r)
        return collected

    def flush(self) -> None:
        if self._sink is not None and hasattr(self._sink, "flush"):
            self._sink.flush()


class ScanCache:
    """Merkle-keyed incremental scan cache for language scanner runs."""

    def __init__(
        self,
        lang: str,
        project_dir: str | Path = ".",
        skip: str = "",
        custom_rules: str = "",
        rulepack_hash: str = "",
        engine_version: str = "",
        module_checksum: str = "",
        extra: str = "",
    ) -> None:
        self.lang = lang
        self.project_dir = Path(project_dir).resolve()
        self.skip = skip
        self.custom_rules = custom_rules
        self.enabled = not is_cache_disabled()

        # Derive hashes if not provided
        if not rulepack_hash:
            rulepack_hash = self._derive_rulepack_hash()
        if not module_checksum:
            module_checksum = self._derive_module_checksum()

        rules_hash = hash_rules_dir(custom_rules) if custom_rules else ""
        extra_parts = [f"skip={skip}", f"rules_hash={rules_hash}"]
        if extra:
            extra_parts.append(extra)
        self.cache_key = compute_cache_key(
            lang=self.lang,
            engine_version=engine_version,
            module_checksum=module_checksum,
            rulepack_hash=rulepack_hash,
            extra=";".join(extra_parts),
        )
        self.cache_root = get_cache_base_dir() / self.cache_key
        self.files_dir = self.cache_root / "files"
        self.dirs_dir = self.cache_root / "dirs"
        self.stat_cache: dict[str, tuple[int, int, str]] = {}  # path -> (mtime_ns, size, hash)

        self.stats = {
            "hits": 0,
            "misses": 0,
            "total": 0,
            "hit_rate": 0.0,
            "merkle_dir_hits": 0,
            "file_hits": 0,
        }

    def _derive_rulepack_hash(self) -> str:
        """Derive rulepack hash from language rules, patterns, and detectors."""
        prefix = LANG_PREFIX_MAP.get(self.lang, self.lang)
        core_dir = Path(__file__).resolve().parent
        h = hashlib.blake2b(digest_size=16)

        rules_file = core_dir / f"{prefix}_rules.py"
        if rules_file.is_file():
            try:
                h.update(rules_file.read_bytes())
            except OSError:
                pass

        patterns_dir = core_dir / f"{prefix}_patterns"
        if patterns_dir.is_dir():
            for f in sorted(patterns_dir.glob("*.py")):
                try:
                    h.update(f.name.encode("utf-8"))
                    h.update(f.read_bytes())
                except OSError:
                    pass

        detectors_dir = core_dir / f"{prefix}_detectors"
        if detectors_dir.is_dir():
            for f in sorted(detectors_dir.glob("*.py")):
                try:
                    h.update(f.name.encode("utf-8"))
                    h.update(f.read_bytes())
                except OSError:
                    pass

        ast_file = core_dir / f"{prefix}_ast.py"
        if ast_file.is_file():
            try:
                h.update(ast_file.read_bytes())
            except OSError:
                pass

        analyzers_dir = core_dir / "analyzers"
        if analyzers_dir.is_dir():
            for f in sorted(analyzers_dir.glob("*.py")):
                try:
                    h.update(f.name.encode("utf-8"))
                    h.update(f.read_bytes())
                except OSError:
                    pass

        return h.hexdigest()

    def _derive_module_checksum(self) -> str:
        """Derive module checksum from the language scan module."""
        prefix = LANG_PREFIX_MAP.get(self.lang, self.lang)
        core_dir = Path(__file__).resolve().parent
        scan_file = core_dir / f"{prefix}_scan.py"
        if scan_file.is_file():
            try:
                return hashlib.blake2b(scan_file.read_bytes(), digest_size=16).hexdigest()
            except OSError:
                pass
        return "default"

    def _get_file_hash(self, path: Path, git_blobs: dict[str, str] | None) -> str | None:
        """Compute content hash for path, using git blobs if clean git, else stat+blake2b."""
        if git_blobs is not None:
            try:
                rel = path.resolve().relative_to(self.project_dir).as_posix()
                if rel in git_blobs:
                    return git_blobs[rel]
            except Exception:
                pass

        try:
            st = path.stat()
            key = str(path)
            cached = self.stat_cache.get(key)
            if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                return cached[2]
            data = path.read_bytes()
            h = hashlib.blake2b(data, digest_size=16).hexdigest()
            self.stat_cache[key] = (st.st_mtime_ns, st.st_size, h)
            return h
        except OSError:
            return None

    def partition_files(
        self, files: Sequence[Path]
    ) -> tuple[dict[Path, list[dict]], list[Path]]:
        """Partition target files into cached hits and misses needing scanning.

        Returns (cached_findings_map, files_to_scan).
        """
        total = len(files)
        self.stats["total"] = total
        if not self.enabled or total == 0:
            self.stats["misses"] = total
            return {}, list(files)

        git_blobs = get_clean_git_blobs(self.project_dir)

        # 1. Compute file hashes for all target files
        file_hashes: dict[Path, str] = {}
        for f in files:
            fh = self._get_file_hash(f, git_blobs)
            if fh:
                file_hashes[f] = fh

        # 2. Group files by parent directory to evaluate directory Merkle nodes
        by_dir: dict[Path, list[Path]] = {}
        for f in files:
            by_dir.setdefault(f.parent, []).append(f)

        cached_findings: dict[Path, list[dict]] = {}
        files_to_scan: list[Path] = []

        # 3. For each directory, compute Merkle node
        for d, dir_files in by_dir.items():
            # Children hashes: (file_name, file_hash)
            children: list[tuple[str, str, str]] = []
            dir_file_hashes: dict[str, str] = {}
            for f in dir_files:
                fh = file_hashes.get(f)
                if fh:
                    children.append(("file", f.name, fh))
                    dir_file_hashes[f.name] = fh

            # Calculate directory Merkle hash
            merkle_content = "".join(
                f"{t}:{n}:{h}\n" for t, n, h in sorted(children)
            ).encode("utf-8")
            dir_merkle = hashlib.blake2b(merkle_content, digest_size=16).hexdigest()
            dir_cache_file = self.dirs_dir / dir_merkle[:2] / f"{dir_merkle}.json"

            dir_hit = False
            dir_data = lock_free_read_json(dir_cache_file)
            if isinstance(dir_data, dict) and dir_data.get("merkle") == dir_merkle:  # ubs:ignore
                # Whole directory subtree hit!
                saved_findings = dir_data.get("findings", {})
                if isinstance(saved_findings, dict):
                    dir_hit = True
                    self.stats["merkle_dir_hits"] += 1
                    for f in dir_files:
                        recs = saved_findings.get(f.name, [])
                        # Ensure finding path reflects current file path
                        adapted = []
                        for r in recs:
                            c = dict(r)
                            c["path"] = str(f)
                            adapted.append(c)
                        cached_findings[f] = adapted

            if not dir_hit:
                # Fall back to per-file cache
                for f in dir_files:
                    fh = file_hashes.get(f)
                    if not fh:
                        files_to_scan.append(f)
                        continue
                    file_cache_file = self.files_dir / fh[:2] / f"{fh}.json"
                    file_data = lock_free_read_json(file_cache_file)
                    if isinstance(file_data, dict) and file_data.get("hash") == fh:
                        # Validate cross-file input set if recorded
                        inputs_valid = True
                        for in_path_str, in_hash in file_data.get("inputs", {}).items():
                            cur_in_hash = self._get_file_hash(Path(in_path_str), git_blobs)
                            if cur_in_hash != in_hash:
                                inputs_valid = False
                                break
                        if inputs_valid:
                            recs = file_data.get("findings", [])
                            adapted = []
                            for r in recs:
                                c = dict(r)
                                c["path"] = str(f)
                                adapted.append(c)
                            cached_findings[f] = adapted
                            self.stats["file_hits"] += 1
                            continue
                    files_to_scan.append(f)

        hits = len(cached_findings)
        misses = len(files_to_scan)
        self.stats["hits"] = hits
        self.stats["misses"] = misses
        self.stats["hit_rate"] = round(hits / total, 4) if total > 0 else 0.0

        return cached_findings, files_to_scan

    def _lookup_findings(self, f: Path, findings_by_file: dict[str, list[dict]]) -> list[dict]:
        """Lookup findings for a file across path representations."""
        str_f = str(f)
        try:
            target_res = str(f.resolve())
        except Exception:
            target_res = str_f

        collected: list[dict] = []
        seen_ids: set[int] = set()

        for k, v in findings_by_file.items():
            if not k:
                continue
            matches = False
            if k == str_f or k == f.name:
                matches = True
            else:
                try:
                    k_path = Path(k)
                    if str(k_path.resolve()) == target_res:
                        matches = True
                    elif self.project_dir and str((self.project_dir / k_path).resolve()) == target_res:
                        matches = True
                except Exception:
                    pass
            if matches:
                for r in v:
                    r_id = id(r)
                    if r_id not in seen_ids:
                        seen_ids.add(r_id)
                        collected.append(r)
        return collected

    def store_scanned_files(
        self,
        files: Sequence[Path],
        findings_by_file: dict[str, list[dict]],
        inputs_by_file: dict[str, dict[str, str]] | None = None,
    ) -> None:
        """Store newly scanned files into per-file cache and update directory Merkle nodes."""
        if not self.enabled or not files:
            return

        git_blobs = get_clean_git_blobs(self.project_dir)
        file_hashes: dict[Path, str] = {}
        for f in files:
            fh = self._get_file_hash(f, git_blobs)
            if fh:
                file_hashes[f] = fh

        # 1. Write per-file entries
        for f in files:
            fh = file_hashes.get(f)
            if not fh:
                continue
            recs = self._lookup_findings(f, findings_by_file)
            if len(files) > 1:
                recs = [
                    r for r in recs
                    if r.get("rule") not in (
                        "py.functions.missing-returns",
                        "rust.code-quality.tech-debt",
                        "rust.async.spawn-handle-heuristic",
                        "rust.tests.test-todo",
                    )
                ]
            inputs = inputs_by_file.get(str(f), {}) if inputs_by_file else {}
            target_path = self.files_dir / fh[:2] / f"{fh}.json"
            atomic_write_json(target_path, {
                "hash": fh,
                "findings": recs,
                "inputs": inputs,
                "stored_at": time.time(),
            })

        # 2. Update directory Merkle nodes
        by_dir: dict[Path, list[Path]] = {}
        for f in files:
            by_dir.setdefault(f.parent, []).append(f)

        for d, dir_files in by_dir.items():
            children: list[tuple[str, str, str]] = []
            dir_findings: dict[str, list[dict]] = {}
            for f in dir_files:
                fh = file_hashes.get(f)
                if fh:
                    children.append(("file", f.name, fh))
                    recs = self._lookup_findings(f, findings_by_file)
                    dir_findings[f.name] = recs

            merkle_content = "".join(
                f"{t}:{n}:{h}\n" for t, n, h in sorted(children)
            ).encode("utf-8")
            dir_merkle = hashlib.blake2b(merkle_content, digest_size=16).hexdigest()
            dir_cache_file = self.dirs_dir / dir_merkle[:2] / f"{dir_merkle}.json"
            atomic_write_json(dir_cache_file, {
                "merkle": dir_merkle,
                "findings": dir_findings,
                "stored_at": time.time(),
            })

    def write_stats(self, target_file: str | Path | None = None) -> None:
        """Write scan cache statistics to target_file or ENV_CACHE_FILE."""
        dest = target_file or os.environ.get(ENV_CACHE_FILE)
        if not dest:
            return
        p = Path(dest)
        atomic_write_json(p, self.stats)


def doctor_stats(base_dir: Path | None = None) -> dict[str, Any]:
    """Gather diagnostic stats about the scan cache on disk."""
    root = base_dir or get_cache_base_dir()
    if not root.is_dir():
        return {
            "status": "empty",
            "cache_dir": str(root),
            "size_bytes": 0,
            "entries_count": 0,
            "keys_count": 0,
            "oldest_age_days": 0.0,
        }

    total_size = 0
    total_entries = 0
    keys = set()
    oldest_time = time.time()

    for p in root.rglob("*.json"):
        if p.name.startswith(".tmp"):
            continue
        try:
            st = p.stat()
            total_size += st.st_size
            total_entries += 1
            if st.st_mtime < oldest_time:
                oldest_time = st.st_mtime
            # Key is the immediate child of root
            try:
                rel = p.relative_to(root)
                keys.add(rel.parts[0])
            except Exception:
                pass
        except OSError:
            pass

    age_days = max(0.0, round((time.time() - oldest_time) / 86400.0, 1)) if total_entries > 0 else 0.0
    return {
        "status": "ok" if total_entries > 0 else "empty",
        "cache_dir": str(root),
        "size_bytes": total_size,
        "entries_count": total_entries,
        "keys_count": len(keys),
        "oldest_age_days": age_days,
    }


def prune_cache(
    base_dir: Path | None = None,
    max_age_days: float = 7.0,
    prune_all: bool = False,
) -> tuple[int, int]:
    """Prune entries older than max_age_days (or all entries if prune_all).

    Returns (freed_bytes, removed_count).
    """
    root = base_dir or get_cache_base_dir()
    if not root.is_dir():
        return 0, 0

    freed_bytes = 0
    removed_count = 0
    now = time.time()
    cutoff = now - (max_age_days * 86400.0)

    for p in list(root.rglob("*.json")):
        try:
            st = p.stat()
            if prune_all or st.st_mtime < cutoff:
                freed_bytes += st.st_size
                removed_count += 1
                p.unlink()
        except OSError:
            pass

    # Clean up empty directories
    for d in sorted(root.rglob("*"), reverse=True):
        if d.is_dir():
            try:
                d.rmdir()
            except OSError:
                pass

    return freed_bytes, removed_count


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for doctor and cache management."""
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.cache")
    sub = parser.add_subparsers(dest="command")

    doc_p = sub.add_parser("doctor", help="Inspect or prune the scan cache")
    doc_p.add_argument("--prune-cache", action="store_true", help="Prune the cache")
    doc_p.add_argument("--all", action="store_true", help="Prune all entries")
    doc_p.add_argument("--max-age-days", type=float, default=7.0, help="Max age in days for pruning")
    doc_p.add_argument("--cache-dir", default="", help="Override cache root")
    doc_p.add_argument("--format", choices=["text", "json"], default="json")

    args = parser.parse_args(argv)
    cache_dir = Path(args.cache_dir).expanduser().resolve() if getattr(args, "cache_dir", "") else None

    if args.command == "doctor":
        if args.prune_cache:
            freed, count = prune_cache(
                base_dir=cache_dir,
                max_age_days=args.max_age_days,
                prune_all=args.all,
            )
            res = {
                "action": "prune",
                "pruned_bytes": freed,
                "pruned_entries": count,
                "cache_dir": str(cache_dir or get_cache_base_dir()),
            }
        else:
            res = doctor_stats(base_dir=cache_dir)
            res["action"] = "stats"

        if args.format == "json":
            sys.stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
        else:
            if res.get("action") == "prune":
                mb = round(res["pruned_bytes"] / (1024 * 1024), 2)
                sys.stdout.write(f"Pruned scan cache: removed {mb} MB ({res['pruned_entries']} entries)\n")
            else:
                mb = round(res["size_bytes"] / (1024 * 1024), 2)
                sys.stdout.write(
                    f"Scan cache: {mb} MB ({res['entries_count']} entries across {res['keys_count']} keys, "
                    f"oldest {res['oldest_age_days']} days) [dir: {res['cache_dir']}]\n"
                )
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
