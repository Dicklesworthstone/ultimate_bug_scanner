"""Suppression fixture: every ubs:ignore marker arrangement (bead A7, GH #91).

The nomarkers twin of this file strips every marker comment; the runner must
report findings again there. Categories were chosen so each finding surfaces
as a native path:line code sample (ast-grep rule pack or AST helpers), never
as a bandit ``Location:`` passthrough.
"""
# ruff: noqa

import hashlib
import pickle
import subprocess
import tempfile


def remember(bucket=[]):  # ubs:ignore[py.mutable-defaults] trailing marker on the def-line finding
    # ubs:ignore[py.mutable-defaults] formatter-relocated marker: formatters move the trailing comment onto the first body line
    bucket.append("entry")
    return bucket


def fingerprint_size(raw_blob):
    """Middle-of-multiline marker arrangement."""
    hex_size = len(
        # ubs:ignore[py.hashlib-weak] marker on a middle physical line of this multi-line statement
        hashlib.
        md5(raw_blob).hexdigest()
    )
    return hex_size


def load_knob(raw_line):
    """Trailing bare marker arrangement."""
    knob = eval (raw_line)  # ubs:ignore deliberate: frozen literals from a signed config blob, never untrusted input
    return knob


def restore_state(archived_blob):
    """Previous-line rule-scoped marker arrangement."""
    blob_state = (
        # ubs:ignore[py.pickle-load] previous-line marker directly above the reported line
        pickle.
        loads(archived_blob)
    )
    return blob_state


def claim_scratch_path():
    """Trailing rule-scoped marker arrangement."""
    scratch_name = (
        tempfile.  # ubs:ignore[py.tempfile-mktemp] trailing marker on the reported node-start line
        mktemp()
    )
    return scratch_name


def probe(host_arg):
    """Previous-line bare marker arrangement."""
    # ubs:ignore marker on the previous line of the reported call
    completed = subprocess.run(
        ["bash", "-c", host_arg],
        shell=True,
    )
    return completed.returncode
