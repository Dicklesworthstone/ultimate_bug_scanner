"""GH #102 positive controls (Python): equality on secret material stays reported.

`sha256`, `digest`, `hexdigest` or the name `checksum` is not an exemption when
the digest is keyed, hashes a secret, is fed a secret, or has unknown
provenance. The trailing ``expect`` comments mark every line the detector must
report (asserted by test-suite/quality/test_security_precision.py).
"""
import hashlib
import hmac


def verify_webhook_tag(signing_secret: bytes, payload: bytes, provided_tag: str) -> bool:
    expected_tag = hmac.new(signing_secret, payload, "sha256").hexdigest()
    return expected_tag == provided_tag  # expect: secret_eq


def verify_bearer(headers, expected_bearer_token: str) -> bool:
    return headers["Authorization"] == f"Bearer {expected_bearer_token}"  # expect: secret_eq


def verify_keyed_checksum(mac_key: bytes, payload: bytes, checksum: str) -> bool:
    return hashlib.blake2b(payload, key=mac_key).hexdigest() == checksum  # expect: secret_eq


def verify_password_digest(password: str, stored_digest: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == stored_digest  # expect: secret_eq


def verify_streamed_secret(api_key: bytes, expected_checksum: str) -> bool:
    checksum = hashlib.sha256()
    checksum.update(api_key)
    return checksum.hexdigest() == expected_checksum  # expect: secret_eq


def verify_unknown_digest(computed, manifest_entry) -> bool:
    return computed.hexdigest() != manifest_entry["sha256"]  # expect: secret_eq
