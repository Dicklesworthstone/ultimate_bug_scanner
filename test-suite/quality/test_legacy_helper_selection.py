"""A selected project remains scannable beneath an ignored-name ancestor."""
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "modules" / "helpers"))

from ubs_core.analyzers import (  # noqa: E402
    async_handles_csharp, lifecycle_csharp, lifecycle_java, lifecycle_swift,
    narrowing_csharp,
)


class LegacyHelperSelectionTests(unittest.TestCase):
    def test_selected_roots_and_files_preserve_descendant_exclusions(self):
        collectors = (
            ("java-lifecycle", lifecycle_java.iter_java_files, ".java"),
            ("swift-lifecycle", lifecycle_swift.iter_swiftish_files, ".swift"),
            ("csharp-lifecycle", lifecycle_csharp.iter_csharp_files, ".cs"),
            ("csharp-narrowing", narrowing_csharp.iter_csharp_files, ".cs"),
            ("csharp-async", async_handles_csharp.iter_csharp_files, ".cs"),
        )
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="legacy-selection-", dir=artifacts))
        for name, collect, suffix in collectors:
            with self.subTest(helper=name):
                started = time.monotonic()
                print(f"[legacy-selection:{name}] RUN", flush=True)
                project = work / name / "build" / "project"
                nested = project / "build"
                nested.mkdir(parents=True)
                source = project / ("source" + suffix)
                excluded = nested / ("generated" + suffix)
                unrelated = project / "notes.txt"
                for path in (source, excluded, unrelated):
                    path.write_text("// selection fixture\n", encoding="utf-8")
                self.assertEqual({source}, set(collect(project)))
                self.assertEqual({excluded}, set(collect(nested)))
                self.assertEqual({excluded}, set(collect(excluded)))
                self.assertEqual(set(), set(collect(unrelated)))
                print(f"[legacy-selection:{name}] PASS ({time.monotonic() - started:.3f}s)", flush=True)


if __name__ == "__main__":
    unittest.main()
