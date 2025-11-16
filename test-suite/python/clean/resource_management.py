"""Clean Python example: context managers and safe subprocess APIs."""

import pathlib
import subprocess


def read_config(path: pathlib.Path) -> str:
    with path.open("r", encoding="utf-8") as handle:
        return handle.read()


def write_temp(paths: list[pathlib.Path]) -> None:
    for p in paths:
        with p.open("w", encoding="utf-8") as fh:
            fh.write("ok")


def delete_path(path: pathlib.Path) -> None:
    subprocess.run(["rm", "-rf", path], check=True)
