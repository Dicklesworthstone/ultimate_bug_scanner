"""Clean sample: ``None`` guards that exit or re-narrow before any use (bead D4).

The narrowing layer must report zero findings here: every guard below either
returns/raises, rebinds the guarded name inside the branch, or is followed by
a second exiting guard before the first dereference.
"""
from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


def pick_primary(config):
    if config is None:
        LOG.warning("config missing; using defaults")
        return {}
    return config["primary"]


def describe(user):
    if user == None:
        raise ValueError("user is required")
    return user.name


def send_payload(payload):
    if payload is None:
        payload = b""
    return payload.encode("utf-8")


def nested_lookup(table, key):
    if table is None:
        table = {}
    row = table.get(key)
    if row is None:
        LOG.warning("key %r missing; using empty row", key)
        row = {}
    return row["value"]


def render(widget):
    if widget is None:
        LOG.warning("widget missing; nothing to render")
    if widget is None:
        return ""
    return widget.render()


def label(node):
    if node is None:
        return "<none>"
    return node.label
