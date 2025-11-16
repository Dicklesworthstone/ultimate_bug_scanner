"""BUGGY PYTHON: resource management and subprocess issues."""

import pathlib
import subprocess

def read_config(path):
    # BUG: file handle never closed and encoding unspecified
    cfg = open(path, "r")
    return cfg.read()


def temporary_files(paths):
    data = []
    for p in paths:
        fh = open(p, "w")  # BUG: overwritten handle, no close
        fh.write("temp")
        data.append(fh)
    return data


def delete_path(user_supplied):
    # BUG: shell=True injection risk
    subprocess.run(f"rm -rf {user_supplied}", shell=True)


def insecure_permissions():
    tmp = pathlib.Path("/tmp/insecure.txt")
    tmp.write_text("secret")
    tmp.chmod(0o777)  # BUG: world writeable
