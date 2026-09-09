"""Path joins are not divisions (self-scan gate, bead D8).

`pathlib.PurePath` overloads `/`, so every line below is a path join. The
category-2 division ladder reported 78 of these on the ubs tree itself before
`ubs_core.py_detectors._pathlike` taught it the difference. Nothing here may
raise "Division by variable".
"""
from pathlib import Path

BASE_DIR = Path("/srv/app")


def cache_dir() -> Path:
    return BASE_DIR / "cache"


def layout(rules_dir: Path, name: str, files_dir: str) -> list[Path]:
    fdir = Path(files_dir)
    rules_sub = rules_dir / "rules"
    parent = fdir.parent
    return [
        rules_sub / f"{name}.yml",
        rules_sub / name,
        BASE_DIR / name,
        Path.cwd() / name,
        Path.home() / name,
        parent / name,
        fdir.resolve() / name,
        fdir.parents[1] / name,
        cache_dir() / name,
        (BASE_DIR / "a") / name,
    ]


def walk(root: Path) -> list[Path]:
    found = []
    for entry in root.iterdir():
        found.append(entry / "manifest.json")
    return found


def annotated(target: Path, leaf: str) -> Path:
    out: Path = target / leaf
    return out
