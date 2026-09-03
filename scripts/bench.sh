#!/usr/bin/env bash
# Benchmark the meta-runner on a fixed corpus and record the numbers (bead C1).
#
#   scripts/bench.sh [--runs N] [--out DIR] [--large] [--oss]
#
# Corpus (deterministic, no network unless --oss):
#   fixtures      the test-suite tree as checked in
#   synthetic-50k a generated tree of ~50K source lines built by repeating the
#                 fixture files under seeded names (same content every run)
#   synthetic-400k (only with --large) the same recipe at ~400K lines
#   --oss         one pinned OSS repository per language (see OSS_REPOS), cloned
#                 into $XDG_CACHE_HOME/ubs-bench once and reused
#
# Each corpus item is scanned N times with `ubs --ci --format=json` and
# UBS_PROFILE=1; the median wall time, CPU time, peak RSS, timeouts and totals
# are written to DIR/latest.json and appended to DIR/history.ndjson. Compare
# runs with scripts/bench_cusum.py (CUSUM on log wall time against a baseline).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RUNS=3
OUT_DIR="$ROOT_DIR/benchmarks"
LARGE=0
OSS=0
for arg in "$@"; do
  case "$arg" in
    --runs=*) RUNS="${arg#*=}" ;;
    --out=*) OUT_DIR="${arg#*=}" ;;
    --large) LARGE=1 ;;
    --oss) OSS=1 ;;
    -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
[[ "$RUNS" =~ ^[0-9]+$ && "$RUNS" -ge 1 ]] || { echo "--runs must be a positive integer" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

# Pinned OSS corpus (repo@commit): fetched only with --oss.
OSS_REPOS=(
  "js=https://github.com/expressjs/express@v4.21.2"
  "python=https://github.com/pallets/flask@3.1.0"
  "golang=https://github.com/gin-gonic/gin@v1.10.0"
  "rust=https://github.com/BurntSushi/ripgrep@15.2.0"
)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ubs-bench.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT_DIR"

# Deterministic synthetic tree: repeat the fixture files under seeded names
# until the requested line budget is reached. Same input every run.
build_synthetic(){
  local dest="$1" target_lines="$2"
  python3 - "$ROOT_DIR/test-suite" "$dest" "$target_lines" <<'PY'
import pathlib, random, shutil, sys
src, dest, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3])
exts = {".js", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".rb", ".swift", ".cs", ".ex", ".exs", ".c", ".cc", ".cpp", ".h"}
files = sorted(p for p in src.rglob("*") if p.is_file() and p.suffix in exts and "artifacts" not in p.parts)
rng = random.Random(20260902)
lines = 0
n = 0
dest.mkdir(parents=True, exist_ok=True)
while lines < target:
    p = rng.choice(files)
    text = p.read_text(encoding="utf-8", errors="ignore")
    sub = dest / f"pkg{n % 40:02d}"
    sub.mkdir(exist_ok=True)
    (sub / f"{p.stem}_{n:05d}{p.suffix}").write_text(text, encoding="utf-8")
    lines += text.count("\n") + 1
    n += 1
print(f"{n} files, {lines} lines")
PY
}

count_tree(){
  local dir="$1"
  python3 - "$dir" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
exts = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".py", ".pyi", ".go", ".rs", ".java", ".kt", ".rb", ".swift", ".cs", ".ex", ".exs", ".c", ".cc", ".cpp", ".h", ".hpp"}
files = [p for p in root.rglob("*") if p.is_file() and p.suffix in exts and ".git" not in p.parts and "node_modules" not in p.parts]
lines = 0
for p in files:
    try:
        lines += p.read_text(encoding="utf-8", errors="ignore").count("\n")
    except OSError:
        pass
print(f"{len(files)} {lines}")
PY
}

# One timed scan: prints "wall_s cpu_s rss_mb exit timeouts total_ms critical warning info files"
timed_scan(){
  local target="$1" out="$WORK/scan.json" timing="$WORK/time.txt"
  local t0 t1 wall
  t0="$(date +%s.%N)"
  /usr/bin/time -f '%U %S %M' -o "$timing" env NO_COLOR=1 UBS_NO_AUTO_UPDATE=1 UBS_PROFILE=1 UBS_SKIP_SIZE_CHECK=1 \
    "$ROOT_DIR/ubs" --ci --format=json "$target" >"$out" 2>"$WORK/scan.err" && rc=0 || rc=$?
  t1="$(date +%s.%N)"
  wall="$(python3 -c "print(round($t1 - $t0, 3))")"
  # GNU time prepends "Command exited with non-zero status N" when the scan
  # found something (exit 1); the measurements are always the last line.
  local user sys rss
  read -r user sys rss < <(tail -n 1 "$timing")
  local cpu; cpu="$(python3 -c "print(round($user + $sys, 3))")"
  local rss_mb=$(( rss / 1024 ))
  local timeouts total_ms critical warning info files
  read -r timeouts total_ms critical warning info files < <(jq -r '
    [ ((.failed_modules // []) | map(select(.status == "timeout")) | length),
      (.profile.total_ms // 0), (.totals.critical // 0), (.totals.warning // 0), (.totals.info // 0), (.totals.files // 0) ]
    | map(tostring) | join(" ")' "$out" 2>/dev/null || echo "0 0 0 0 0 0")
  printf '%s %s %s %s %s %s %s %s %s %s\n' "$wall" "$cpu" "$rss_mb" "$rc" "$timeouts" "$total_ms" "$critical" "$warning" "$info" "$files"
}

bench_item(){
  local name="$1" target="$2"
  local counts files lines
  counts="$(count_tree "$target")"
  read -r files lines <<<"$counts"
  echo "▶ $name: $files files, $lines lines, $RUNS run(s)" >&2
  local samples="$WORK/$name.samples"
  : >"$samples"
  local i
  for ((i = 1; i <= RUNS; i++)); do
    timed_scan "$target" >>"$samples"
    echo "  run $i: $(tail -n 1 "$samples" | awk '{print "wall " $1 "s cpu " $2 "s rss " $3 "MB exit " $4 " timeouts " $5}')" >&2
  done
  python3 - "$name" "$files" "$lines" "$samples" <<'PY'
import json, statistics, sys
name, files, lines, path = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
rows = [line.split() for line in open(path) if line.strip()]
walls = [float(r[0]) for r in rows]
cpus = [float(r[1]) for r in rows]
rss = [int(r[2]) for r in rows]
item = {
    "name": name, "files": files, "lines": lines, "runs": len(rows),
    "wall_s": round(statistics.median(walls), 3),
    "wall_s_min": round(min(walls), 3), "wall_s_max": round(max(walls), 3),
    "cpu_s": round(statistics.median(cpus), 3),
    "rss_mb": max(rss),
    "exit_codes": sorted({int(r[3]) for r in rows}),
    "timeouts": max(int(r[4]) for r in rows),
    "profile_total_ms": int(statistics.median(int(r[5]) for r in rows)),
    "totals": {"critical": int(rows[-1][6]), "warning": int(rows[-1][7]), "info": int(rows[-1][8]), "files": int(rows[-1][9])},
}
print(json.dumps(item))
PY
}

items="$WORK/items.ndjson"
: >"$items"
bench_item fixtures "$ROOT_DIR/test-suite" >>"$items"

SYN50="$WORK/synthetic-50k"
build_synthetic "$SYN50" 50000 >&2
bench_item synthetic-50k "$SYN50" >>"$items"

if [[ "$LARGE" -eq 1 ]]; then
  SYN400="$WORK/synthetic-400k"
  build_synthetic "$SYN400" 400000 >&2
  bench_item synthetic-400k "$SYN400" >>"$items"
fi

if [[ "$OSS" -eq 1 ]]; then
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/ubs-bench"
  mkdir -p "$cache"
  for spec in "${OSS_REPOS[@]}"; do
    lang="${spec%%=*}"; url_ref="${spec#*=}"; url="${url_ref%@*}"; ref="${url_ref##*@}"
    dir="$cache/$lang-${ref}"
    if [[ ! -d "$dir/.git" ]]; then
      echo "▶ fetching $url@$ref → $dir" >&2
      git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$ref" "$url" "$dir"
    fi
    bench_item "oss-$lang" "$dir" >>"$items"
  done
fi

# Single-file overhead (beads C3/C3d): the agent-hook case `ubs FILE --ci`
# against the module alone on the same file, alternating, first pair discarded
# as warm-up. overhead = meta - module per pair; p50 and p95 by nearest rank.
# Text mode, because that is what the hooks run (json mode adds the module's
# own report-json pass). Timed with $EPOCHREALTIME (bash 5): no extra process.
SINGLE_FILE_TARGET_REL="test-suite/python/clean/clean_async_security.py"
now_ms(){ local t="${EPOCHREALTIME/./}"; echo $(( t / 1000 )); }
bench_single_file(){
  local target="$ROOT_DIR/$SINGLE_FILE_TARGET_REL" samples="$WORK/single-file.samples"
  local i t0 t1 t2 meta module
  : >"$samples"
  echo "▶ single-file: $SINGLE_FILE_TARGET_REL, $RUNS pair(s) + 1 warm-up" >&2
  for ((i = 0; i <= RUNS; i++)); do
    t0="$(now_ms)"
    env NO_COLOR=1 UBS_NO_AUTO_UPDATE=1 "$ROOT_DIR/ubs" "$target" --ci >/dev/null 2>&1 || true
    t1="$(now_ms)"
    env NO_COLOR=1 "$ROOT_DIR/modules/ubs-python.sh" --ci "$target" >/dev/null 2>&1 || true
    t2="$(now_ms)"
    meta=$(( t1 - t0 )); module=$(( t2 - t1 ))
    if [[ "$i" -eq 0 ]]; then echo "  warm-up: meta ${meta}ms module ${module}ms" >&2; continue; fi
    printf '%s %s\n' "$meta" "$module" >>"$samples"
    echo "  pair $i: meta ${meta}ms module ${module}ms overhead $((meta - module))ms" >&2
  done
  python3 - "$SINGLE_FILE_TARGET_REL" "$samples" <<'PY'
import json
import statistics
import sys

rel, path = sys.argv[1], sys.argv[2]
rows = [tuple(int(x) for x in line.split()) for line in open(path) if line.strip()]
meta = [m for m, _ in rows]
module = [mod for _, mod in rows]
over = [m - mod for m, mod in rows]


def nearest_rank(values, q):
    if not values:
        return 0
    ordered = sorted(values)
    k = max(1, int(round(q * len(ordered))))
    return ordered[k - 1]


print(json.dumps({
    "name": "single-file", "file": rel, "runs": len(rows), "mode": "text",
    "meta_ms": meta, "module_ms": module,
    "meta_ms_p50": int(statistics.median(meta)) if meta else 0,
    "module_ms_p50": int(statistics.median(module)) if module else 0,
    "overhead_ms_p50": int(statistics.median(over)) if over else 0,
    "overhead_ms_p95": nearest_rank(over, 0.95),
    "target_overhead_ms_p95": 150,
}))
PY
}
single_file_json="$WORK/single-file.json"
bench_single_file >"$single_file_json"

ubs_sha="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
ubs_version="$(grep -m1 '^UBS_VERSION=' "$ROOT_DIR/ubs" | cut -d'"' -f2)"
ast_grep_version="$( (command -v ast-grep >/dev/null 2>&1 && ast-grep --version 2>/dev/null | head -n 1) || echo unknown)"
cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 0)"
jq -s --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg sha "$ubs_sha" --arg ver "$ubs_version" \
   --arg ag "$ast_grep_version" --argjson cores "$cores" --arg os "$(uname -s)" --argjson runs "$RUNS" \
   --slurpfile sf "$single_file_json" '
  {generated_at: $ts, runs_per_item: $runs,
   engine: {ubs_sha: $sha, ubs_version: $ver, ast_grep: $ag},
   host: {cores: $cores, os: $os},
   corpus: ., single_file: $sf[0]}' "$items" >"$OUT_DIR/latest.json"
jq -c '.' "$OUT_DIR/latest.json" >>"$OUT_DIR/history.ndjson"
echo "wrote $OUT_DIR/latest.json (+ history.ndjson)" >&2
jq -r '.corpus[] | "  \(.name): \(.files) files, \(.lines) lines → wall \(.wall_s)s (min \(.wall_s_min), max \(.wall_s_max)), cpu \(.cpu_s)s, rss \(.rss_mb)MB, timeouts \(.timeouts)"' "$OUT_DIR/latest.json" >&2
jq -r '.single_file | "  single-file (\(.file)): meta p50 \(.meta_ms_p50)ms, module p50 \(.module_ms_p50)ms → overhead p50 \(.overhead_ms_p50)ms, p95 \(.overhead_ms_p95)ms (target \(.target_overhead_ms_p95)ms; the hard gate lands with bead C3b)"' "$OUT_DIR/latest.json" >&2
