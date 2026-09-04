"""Buggy sample: partial ``None`` guards that log but never exit (bead D4).

Every function below warns when a value is missing and then keeps going,
dereferencing the very value the guard just tested. The narrowing layer must
flag one ``python.narrowing.partial_none_guard`` warning per partial guard.
"""
from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


def pick_primary(config):
    if config is None:
        LOG.warning("config missing; continuing anyway")
    return config["primary"]


def describe(user):
    if user == None:
        LOG.warning("describe() called without a user")
    return user.name


def send_payload(payload):
    if payload is None:
        LOG.warning("payload missing; sending default body instead")
    return payload.encode("utf-8")


def nested_lookup(table, key):
    if table is None:
        LOG.warning("table not loaded yet")
    row = table.get(key)
    if row is None:
        LOG.warning("key %r missing", key)
    return row["value"]
