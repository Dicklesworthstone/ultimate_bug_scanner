# Bash fixtures

- `buggy/sample.sh` — must yield at least one critical (an eval-style call) and one info (a TODO marker); manifest case `bash-buggy`.
- `clean/sample.sh` — must yield no critical; manifest case `bash-clean`.

Replace both when the example checks in `modules/ubs-bash.sh` become real detectors; every real rule needs a line in each fixture and a manifest expectation.
