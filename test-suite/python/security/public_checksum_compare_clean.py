"""GH #102 regression fixture (Python): public SHA-256 integrity checks.

`verify_public_fixture` compares public article bytes with a public staging
manifest. Nothing here is a bearer secret or a keyed authentication tag, so the
constant-time comparison detector must stay silent; `sha256`, `digest`,
`hexdigest` and `checksum` vocabulary alone is never the trigger (the
authentication counterexamples live in public_checksum_compare_buggy.py).

The runtime contract — an intact payload verifies, a modified payload is
rejected — is exercised by test-suite/quality/test_security_precision.py, so
the integrity check cannot be weakened to satisfy the scanner.
"""
import hashlib
import json
from pathlib import Path


def prepare_public_fixture(root: Path):
    article = b"public article bytes"
    (root / "article.html").write_bytes(article)
    metadata = {"bytes": len(article), "sha256": hashlib.sha256(article).hexdigest()}
    (root / "manifest.json").write_text(json.dumps(metadata), encoding="utf-8")


def verify_public_fixture(root: Path):
    entry = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    payload = (root / "article.html").read_bytes()
    if entry["bytes"] != len(payload) or entry["sha256"] != hashlib.sha256(payload).hexdigest():
        raise RuntimeError("staging integrity mismatch")


def verify_streamed(root: Path, expected_sha256: str) -> bool:
    digest = hashlib.sha256()
    with (root / "article.html").open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest() == expected_sha256


def verify_named_algorithm(payload: bytes, algorithm: str, expected: str) -> bool:
    checksum = hashlib.new(algorithm, payload).hexdigest()
    return checksum == expected
