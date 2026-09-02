"""GH #85 regression fixture (Python): ordinary parser/domain vocabulary must not
be treated as secret material by the constant-time comparison detector.

Shaped after two real false positives UBS raised against its own sources:
`TARGET_SIGS.get(sig) == "asyncio_task"` (modules/helpers/resource_lifecycle_py.py)
and `if token == "rm":` (.claude/hooks/git_safety_guard.py). Every comparison in
this file is a parser/layout/schema check, never secret material.
"""

TARGET_SIGS = {"asyncio.create_task": "asyncio_task", "loop.create_task": "asyncio_task"}


def find_layout_marker(line):
    token = line.split()
    candidate = token[0] if token else ""
    return candidate == "BR2"


def is_page_break(token):
    return token == "PAGE_BREAK" or token == "FF"


def guard_allows(token):
    # A shell-command tokenizer: `rm` is a command word, not a credential.
    if token == "rm":
        return False
    return True


def is_async_task(sig):
    # `sig` is a call signature string ("module.function"), not a crypto signature.
    return bool(sig) and TARGET_SIGS.get(sig) == "asyncio_task"


def session_matches(session_id, expected):
    return session_id == expected


def signature_format_is_detached(signature_format):
    return signature_format == "detached"


def credential_kind_is_certificate(credential_type):
    return credential_type == "certificate"


def jwt_header_is_jose(jwt_header):
    return jwt_header == "JOSE"


def map_key_present(key, keys):
    return any(entry == key for entry in keys)
