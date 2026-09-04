"""Suppression fixture: every ubs:ignore marker arrangement (bead A7, GH #91).

The nomarkers twin of this file strips every marker comment; the runner must
report findings again there. Categories were chosen so each finding surfaces
as a native path:line code sample (ast-grep rule pack or AST helpers), never
as a bandit ``Location:`` passthrough.
"""

import hashlib
import pickle
import subprocess
import tempfile


def remember(bucket=[]):
    bucket.append("entry")
    return bucket


def fingerprint_size(raw_blob):
    """Middle-of-multiline marker arrangement."""
    hex_size = len(
        hashlib.
        md5(raw_blob).hexdigest()
    )
    return hex_size


def load_knob(raw_line):
    """Trailing bare marker arrangement."""
    knob = eval (raw_line)
    return knob


def restore_state(archived_blob):
    """Previous-line rule-scoped marker arrangement."""
    blob_state = (
        pickle.
        loads(archived_blob)
    )
    return blob_state


def claim_scratch_path():
    """Trailing rule-scoped marker arrangement."""
    scratch_name = (
        tempfile.
        mktemp()
    )
    return scratch_name


def probe(host_arg):
    """Previous-line bare marker arrangement."""
    completed = subprocess.run(
        ["bash", "-c", host_arg],
        shell=True,
    )
    return completed.returncode
