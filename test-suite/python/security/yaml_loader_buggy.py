"""GH #102 positive controls (Python): loaders that construct arbitrary Python
objects stay critical, and a Loader whose safety cannot be established in this
file is reported for manual review. A reassuring class name is not evidence.

The trailing ``expect`` comments name the rule that must report each load
(unsafe -> py.security.yaml-unsafe-loader, unresolved ->
py.security.yaml-loader-unresolved); test-suite/quality/test_security_precision.py
asserts the exact sets.
"""
import yaml
from yaml import FullLoader
from app.loaders import AuditLoader


class TotallySafeLoader(yaml.Loader):
    """The name says safe; the base class constructs arbitrary Python objects."""


class ApplyLoader(yaml.SafeLoader):
    pass


def construct_apply(loader, node):
    return eval(loader.construct_scalar(node))


ApplyLoader.add_constructor("!apply", construct_apply)


class PythonObjectLoader(yaml.SafeLoader):
    pass


PythonObjectLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/object", yaml.constructor.FullConstructor.construct_python_object
)


class ImportedBaseLoader(AuditLoader):
    pass


def load_legacy(text):
    return yaml.load(text, Loader=yaml.Loader)  # expect: unsafe


def load_unsafe(text):
    return yaml.load(text, Loader=yaml.UnsafeLoader)  # expect: unsafe


def load_full(text):
    return yaml.load(text, Loader=FullLoader)  # expect: unsafe


def load_default_loader(text):
    return yaml.load(text, Loader=None)  # expect: unsafe


def load_reassuring_name(text):
    return yaml.load(text, Loader=TotallySafeLoader)  # expect: unsafe


def load_apply(text):
    return yaml.load(text, Loader=ApplyLoader)  # expect: unsafe


def load_python_objects(text):
    return list(yaml.load_all(text, Loader=PythonObjectLoader))  # expect: unsafe


def load_imported_base(text):
    return yaml.load(text, Loader=ImportedBaseLoader)  # expect: unresolved


def load_imported_loader(text):
    return yaml.load(text, Loader=AuditLoader)  # expect: unresolved


def load_dynamic(text, make_loader):
    return yaml.load(text, Loader=make_loader())  # expect: unresolved


def load_without_loader(text):
    return yaml.load(text)  # expect: no-loader
