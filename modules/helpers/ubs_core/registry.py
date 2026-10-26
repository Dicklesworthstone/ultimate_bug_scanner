"""ubs_core.registry — analyzer registry and run context (bead A2).

Analyzers register under a (layer, language) pair; several analyzers may share
one (layer, language). `layer` is one of the subcommand names of
`python3 -m ubs_core`; `scan` aggregates every layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

LAYERS: tuple[str, ...] = (
    "taint",
    "guards",
    "narrowing",
    "lifecycle",
    "ctcompare",
    "regex",
    "prefilter",
)

LANGS: tuple[str, ...] = (
    "python",
    "javascript",
    "cpp",
    "rust",
    "go",
    "java",
    "ruby",
    "swift",
    "csharp",
    "kotlin",
    "elixir",
    "php",
)

Lang = str


@dataclass
class RunContext:
    """Inputs handed to every structured analyzer run."""

    lang: Lang
    files: list[Path] = field(default_factory=list)
    rules: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)

    def rule_enabled(self, rule_id: str) -> bool:
        """Respect an optional profile suppression list."""
        disabled = self.profile.get("disabled_rules") or ()
        return rule_id not in disabled


Finder = Callable[[RunContext], Iterable[dict]]
SelfTest = Callable[[], None]


@dataclass(frozen=True)
class Analyzer:
    layer: str
    lang: Lang
    name: str
    run: Finder
    selftests: tuple[tuple[str, SelfTest], ...] = ()

    def __post_init__(self) -> None:
        if self.layer not in LAYERS:
            raise ValueError(f"unknown layer: {self.layer}")
        if self.lang not in LANGS:
            raise ValueError(f"unknown lang: {self.lang}")


_REGISTRY: dict[tuple[str, Lang], list[Analyzer]] = {}


def register(analyzer: Analyzer) -> Analyzer:
    key = (analyzer.layer, analyzer.lang)
    bucket = _REGISTRY.setdefault(key, [])
    if any(existing.name == analyzer.name for existing in bucket):
        raise ValueError(f"duplicate analyzer name: {analyzer.name}")
    bucket.append(analyzer)
    return analyzer


def get(layer: str, lang: Lang) -> list[Analyzer]:
    from .analyzers import load

    load(lang)
    try:
        return list(_REGISTRY[(layer, lang)])
    except KeyError:
        raise KeyError(f"no analyzer registered for layer={layer!r} lang={lang!r}") from None


def all_analyzers() -> Iterator[Analyzer]:
    from .analyzers import load

    load()
    for key in sorted(_REGISTRY):
        yield from _REGISTRY[key]


def analyzers_for_layer(layer: str) -> list[Analyzer]:
    return [a for a in all_analyzers() if a.layer == layer]


def analyzers_for_lang(lang: Lang) -> list[Analyzer]:
    from .analyzers import load

    load(lang)
    return [a for key in sorted(_REGISTRY) for a in _REGISTRY[key] if a.lang == lang]


def _coerce_finding(raw: dict) -> dict:
    """Validate and normalize one finding record for NDJSON output."""
    for key in ("rule", "path", "line"):
        if key not in raw:
            raise ValueError(f"finding missing required key {key!r}: {raw!r}")
    finding = dict(raw)
    finding.setdefault("layer", "")
    finding.setdefault("lang", "")
    finding.setdefault("col", 1)
    finding.setdefault("severity", "warning")
    finding.setdefault("message", "")
    return finding


def _run_analyzer(
    analyzer: Analyzer, ctx: RunContext, errors: list[str] | None,
) -> Iterator[dict]:
    """Keep completed records and sibling analyzers when a caller collects errors."""
    try:
        for raw in analyzer.run(ctx):
            yield _coerce_finding(raw)
    except (Exception, SystemExit) as exc:
        if errors is None:
            raise
        scope = str(ctx.files[0]) if len(ctx.files) == 1 else f"{len(ctx.files)} selected files"
        errors.append(f"{analyzer.name} ({scope}): {type(exc).__name__}: {exc}")


def run_layer(layer: str, ctx: RunContext, *, errors: list[str] | None = None) -> Iterator[dict]:
    """Yield normalized findings for one layer; propagate failures by default."""
    for analyzer in get(layer, ctx.lang):
        yield from _run_analyzer(analyzer, ctx, errors)


def run_scan(ctx: RunContext, *, errors: list[str] | None = None) -> Iterator[dict]:
    """Yield every registered layer, optionally retaining failures separately."""
    for analyzer in analyzers_for_lang(ctx.lang):
        for finding in _run_analyzer(analyzer, ctx, errors):
            finding.setdefault("layer", analyzer.layer)
            yield finding
