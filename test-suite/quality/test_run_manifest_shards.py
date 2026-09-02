"""--shard I/N must partition the enabled manifest cases: every case in exactly
one shard, sizes differ by at most one, and the split is stable across runs."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

TEST_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEST_ROOT))
import run_manifest  # noqa: E402


class ShardTests(unittest.TestCase):
    def test_partition_is_disjoint_complete_and_balanced(self) -> None:
        manifest = json.loads((TEST_ROOT / "manifest.json").read_text())
        ids = [c["id"] for c in manifest["cases"] if c.get("enabled", True)]
        total = 4
        shards = [run_manifest.shard_case_ids(ids, i, total) for i in range(1, total + 1)]
        self.assertEqual(sum(len(s) for s in shards), len(ids))
        self.assertEqual(set().union(*shards), set(ids))
        for a in range(total):
            for b in range(a + 1, total):
                self.assertFalse(shards[a] & shards[b], f"shards {a + 1} and {b + 1} overlap")
        sizes = sorted(len(s) for s in shards)
        self.assertLessEqual(sizes[-1] - sizes[0], 1)

    def test_split_is_stable(self) -> None:
        ids = [f"case-{i}" for i in range(10)]
        self.assertEqual(run_manifest.shard_case_ids(ids, 2, 3), run_manifest.shard_case_ids(ids, 2, 3))
        self.assertEqual(run_manifest.shard_case_ids(ids, 1, 3), {"case-0", "case-3", "case-6", "case-9"})

    def test_parse_shard_rejects_bad_specs(self) -> None:
        self.assertIsNone(run_manifest.parse_shard(None))
        self.assertEqual(run_manifest.parse_shard("2/4"), (2, 4))
        for bad in ("0/4", "5/4", "a/b", "3"):
            with self.assertRaises(SystemExit):
                run_manifest.parse_shard(bad)

    def test_cli_prints_shard_summary(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TEST_ROOT / "run_manifest.py"), "--shard", "1/50", "--list"],
            capture_output=True, text=True, cwd=TEST_ROOT, timeout=60,
        )
        # --list exits before running; the option must still parse.
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
