# Repo Hygiene Audit

Date: 2026-04-27

This audit separates preserved project context from ephemeral files that should
not live in the repository root or source history.

## Preserved And Moved

These files have durable project value but were distracting in the root:

| Old path | New path | Rationale |
| --- | --- | --- |
| `AGENT_FRIENDLINESS_REPORT.md` | `docs/reports/AGENT_FRIENDLINESS_REPORT.md` | Agent-readiness assessment belongs with reports. |
| `RESEARCH_FINDINGS.md` | `docs/reports/RESEARCH_FINDINGS.md` | TOON integration research belongs with reports. |
| `PLAN_TO_REFLECT_AGENT_FEEDBACK.md` | `docs/planning/PLAN_TO_REFLECT_AGENT_FEEDBACK.md` | Product evolution plan belongs with planning docs. |
| `TODO.md` | `docs/planning/TODO.md` | Historical work log belongs with planning docs. |
| `gh_og_share_image.png` | `docs/assets/gh_og_share_image.png` | Binary social image asset should not sit in root. |
| `ubs_illustration.webp` | `docs/assets/ubs_illustration.webp` | README artwork belongs with assets. |

## Ignored Going Forward

The root `.gitignore` now covers these recurring artifact families:

- Beads runtime SQLite databases, WAL/SHM sidecars, daemon locks, and daemon logs.
- Migrated Beads scratch copies such as `*.migrated`.
- Agent-generated modes-of-reasoning/planning scratch artifacts.
- JSON artifact dumps named like `artifact-*.json` or under an `artifacts/` directory.
- Tool caches such as `.ruff_cache/`.

## Tracked Removal Candidates

These files are tracked today but look like runtime detritus rather than source
or useful project documentation:

| Path | Size | Reason |
| --- | ---: | --- |
| `.beads/daemon-2026-01-05T17-28-29.046.log.gz` | 2.2M | Compressed daemon runtime log. |
| `.beads/daemon-2026-01-06T09-02-19.431.log.gz` | 2.5M | Compressed daemon runtime log. |
| `.beads/daemon-2026-01-07T00-07-35.450.log.gz` | 2.5M | Compressed daemon runtime log. |
| `.beads/daemon-2026-01-07T15-08-43.877.log.gz` | 2.5M | Compressed daemon runtime log. |
| `.beads/daemon-2026-01-08T06-10-58.078.log.gz` | 2.5M | Compressed daemon runtime log. |
| `.beads/daemon-2026-01-08T21-13-01.994.log.gz` | 2.5M | Compressed daemon runtime log. |
| `.beads/daemon-2026-01-09T12-50-54.494.log.gz` | 2.5M | Compressed daemon runtime log. |
| `.beads/deletions.jsonl.migrated` | 4K | One-time migration scratch output. |

Recommended removal from Git tracking, after explicit deletion approval:

```bash
git rm --cached .beads/daemon-2026-01-05T17-28-29.046.log.gz .beads/daemon-2026-01-06T09-02-19.431.log.gz .beads/daemon-2026-01-07T00-07-35.450.log.gz .beads/daemon-2026-01-07T15-08-43.877.log.gz .beads/daemon-2026-01-08T06-10-58.078.log.gz .beads/daemon-2026-01-08T21-13-01.994.log.gz .beads/daemon-2026-01-09T12-50-54.494.log.gz .beads/deletions.jsonl.migrated
```

`git rm --cached` would remove these files from future GitHub checkouts while
leaving the local working copies in place.

## Root After This Pass

The tracked root is now limited to normal project entrypoints and metadata:

- `AGENTS.md`, `README.md`, `CHANGELOG.md`, `LICENSE`
- `Dockerfile`, `flake.nix`, `pyproject.toml`, `uv.lock`
- `install.sh`, `ubs`, `VERSION`, `SHA256SUMS`
- `.gitattributes`, `.gitignore`, `.ubsignore`, `SKILL.md`
