"""GH #102 regression fixture (Python): SafeLoader subclasses are safe loaders.

A trivial subclass inherits SafeLoader's constructors, and a strict mapping
subclass that rejects duplicate/non-string keys and delegates value
construction to SafeLoader does not enable Python-object constructors. None of
the loads below may be reported by ``py.yaml-unsafe``, ``py.security.yaml-load``
or the Loader classification in the unsafe-deserialization detector.
"""
import yaml
from yaml import SafeLoader
from yaml.resolver import BaseResolver


class StrictSafeLoader(yaml.SafeLoader):
    pass


class UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate and non-string mapping keys."""


def construct_unique_mapping(loader, node):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str):
            raise yaml.constructor.ConstructorError(
                None, None, f"non-string mapping key {key!r}", key_node.start_mark
            )
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate mapping key {key!r}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


UniqueKeySafeLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping)


def load_trivial_subclass(text: str) -> dict:
    return yaml.load(text, Loader=StrictSafeLoader)


def load_strict_mapping(text: str) -> dict:
    return yaml.load(text, Loader=UniqueKeySafeLoader)


def load_strict_stream(text: str) -> list:
    return list(yaml.load_all(text, Loader=UniqueKeySafeLoader))


def load_positional_loader(text: str) -> dict:
    return yaml.load(text, yaml.CSafeLoader)


def load_bare_import(text: str) -> dict:
    return yaml.load(text, Loader=SafeLoader)


def load_scalars_only(text: str) -> dict:
    return yaml.load(text, Loader=yaml.BaseLoader)


def load_fixture() -> dict:
    return yaml.load("title: fixture", Loader=StrictSafeLoader)
