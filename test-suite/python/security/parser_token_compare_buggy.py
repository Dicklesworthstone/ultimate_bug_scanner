"""GH #85 positive control (Python): qualified security vocabulary must still
trigger the constant-time comparison detector after the parser-vocabulary
tightening. Every ==/!= below compares secret material and must be reported.
"""

import os

EXPECTED_AUTH_TOKEN = os.environ.get("EXPECTED_AUTH_TOKEN", "")


def compute_hmac(payload):
    import hashlib
    import hmac

    return hmac.new(b"k", payload, hashlib.sha256).hexdigest()


def check_api_key(request):
    api_key = request.headers.get("X-API-Key")
    return api_key == os.environ["API_KEY"]  # secret compared with ==


def check_session_token(session_token, stored):
    return session_token == stored  # secret compared with ==


def verify_webhook(payload, provided_signature):
    expected = compute_hmac(payload)
    return provided_signature == expected  # signature compared with ==


def check_auth_token(headers):
    auth_token = headers.get("Authorization")
    if auth_token != EXPECTED_AUTH_TOKEN:  # secret compared with !=
        return False
    return True


def check_password(password, stored_hash):
    return password == stored_hash  # password compared with ==
