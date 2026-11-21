#!/usr/bin/env bash
# Sweep `m3tal-review audit --jobs N` and report wall time and peak CPU per setting.
#
# Usage: scripts/bench-jobs.sh [repo] [reps]
#   repo   directory to audit               (default: .)
#   reps   measured runs per --jobs setting (default: 3)
#
# Settings: default (auto), 1, 2, 4, and half the online CPU count. Configurations
# are run interleaved (one of each per round) so a warming page cache or drifting
# CPU frequency does not favour whichever setting happens to run first.
#
# Peak CPU is sampled every ~100 ms from /proc/<pid>/stat (Linux) or a `ps`
# process-tree walk (macOS), so it reports the busiest sample window rather than
# the lifetime average that /usr/bin/time prints. CPU-seconds and both CPU
# columns include child processes (the git calls audit makes, plus go vet/test
# and the scanner binaries when those are enabled), which is what makes the
# average-CPU column agree with wall time. The audit cache is disabled so every
# run re-does the analysis; runs otherwise use default settings.
#
# Requires Go on PATH unless M3TAL_BIN points at a prebuilt binary.
set -u

REPO="${1:-.}"
REPS="${2:-3}"

case "$REPS" in
  ''|*[!0-9]*) echo "bench-jobs: reps must be a positive integer" >&2; exit 2 ;;
esac
if [ "$REPS" -lt 1 ]; then
  echo "bench-jobs: reps must be a positive integer" >&2
  exit 2
fi
if [ ! -d "$REPO" ]; then
  echo "bench-jobs: no such directory: $REPO" >&2
  exit 2
fi
if command -v git >/dev/null 2>&1 && ! git -C "$REPO" rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "bench-jobs: $REPO is not a Git repository; audit needs one" >&2
  exit 2
fi

export M3TAL_NO_AUDIT_CACHE=1

CORES=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)
case "$CORES" in ''|*[!0-9]*) CORES=1 ;; esac
HALF=$(( CORES / 2 ))
[ "$HALF" -lt 1 ] && HALF=1
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
case "$HZ" in ''|*[!0-9]*|0) HZ=100 ;; esac

BIN="${M3TAL_BIN:-}"
CLEANUP=""
if [ -z "$BIN" ]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "bench-jobs: go not found on PATH; set M3TAL_BIN to a prebuilt binary" >&2
    exit 2
  fi
  BUILD_DIR=$(mktemp -d)
  CLEANUP="$BUILD_DIR"
  BIN="$BUILD_DIR/m3tal-review"
  trap '[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"' EXIT
  echo "Building $BIN ..."
  if ! CGO_ENABLED=0 go build -trimpath -o "$BIN" ./cmd/m3tal-review; then
    echo "bench-jobs: build failed" >&2
    exit 1
  fi
fi

WORK=$(mktemp -d)
trap '[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"; rm -rf "$WORK"' EXIT

# now_us: current time in microseconds. EPOCHREALTIME (bash 5) is free; otherwise
# fall back to perl/python3 (macOS ships neither bash 5 nor GNU date by default).
now_us() {
  if [ -n "${EPOCHREALTIME:-}" ]; then
    local t s f
    t=${EPOCHREALTIME/[.,]/.}
    s=${t%%.*}
    f="${t#*.}000000"
    echo "$(( s * 1000000 + 10#${f:0:6} ))"
  elif command -v perl >/dev/null 2>&1; then
    perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000000'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time()*1000000))'
  else
    printf '%s000000\n' "$(date +%s)"
  fi
}

# tree_cpu_cs: cumulative CPU of pid plus its descendants, in centiseconds;
# fails once pid is gone. Linux reads utime+stime+cutime+cstime, where the
# cutime/cstime pair already covers children the audit has reaped (its git,
# go and scanner subprocesses). macOS ps has no child-time columns, so there
# the whole process tree is summed instead.
tree_cpu_cs() {
  local pid="$1" rest state
  if [ -d /proc ]; then
    rest=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null) || return 1
    [ -n "$rest" ] || return 1
    state=${rest%% *}
    [ "$state" = "Z" ] && return 1
    echo "$rest" | awk -v hz="$HZ" '{printf "%d\n", ($12 + $13 + $14 + $15) * 100 / hz}'
    return 0
  fi
  ps -A -o pid=,ppid=,time= 2>/dev/null | awk -v root="$pid" '
    function to_cs(t,   d, hms, n, b, i, tot, f, parts) {
      d = 0
      if (index(t, "-") > 0) { split(t, parts, "-"); d = parts[1] + 0; t = parts[2] }
      split(t, hms, ".")
      f = (hms[2] == "") ? 0 : substr(hms[2] "00", 1, 2) + 0
      n = split(hms[1], b, ":")
      tot = 0
      for (i = 1; i <= n; i++) tot = tot * 60 + b[i]
      return d * 8640000 + tot * 100 + f
    }
    { n++; p[n] = $1; pp[n] = $2; c[n] = to_cs($3); seen[$1] = 1 }
    END {
      if (!(root in seen)) exit 1
      in_tree[root] = 1
      do {
        changed = 0
        for (i = 1; i <= n; i++)
          if (!(p[i] in in_tree) && (pp[i] in in_tree)) { in_tree[p[i]] = 1; changed = 1 }
      } while (changed)
      total = 0
      for (i = 1; i <= n; i++) if (p[i] in in_tree) total += c[i]
      printf "%d\n", total
    }'
}

# rss_kb: peak resident set size in kB (Linux) or the largest sample (macOS).
rss_kb() {
  local pid="$1"
  if [ -r "/proc/$pid/status" ]; then
    awk '/^VmHWM:/{print $2}' "/proc/$pid/status" 2>/dev/null
  else
    ps -o rss= -p "$pid" 2>/dev/null | tr -d ' '
  fi
}

# run_one LABEL [--jobs N]: one audit, echoing "wall_us cpu_cs peak_pct rss_kb".
run_one() {
  local label="$1"
  shift
  local start prev_ts prev_cs ts cs dt dc pct peak=0 rss=0 tmp i=0
  local -a args
  args=("$@")

  start=$(now_us)
  "$BIN" audit ${args[@]+"${args[@]}"} >/dev/null 2>&1 &
  local pid=$!

  prev_cs=$(tree_cpu_cs "$pid") || prev_cs=0
  prev_ts=$start
  while :; do
    sleep 0.1
    cs=$(tree_cpu_cs "$pid") || break
    ts=$(now_us)
    tmp=$(rss_kb "$pid" 2>/dev/null)
    case "$tmp" in ''|*[!0-9]*) ;; *) if [ "$tmp" -gt "$rss" ]; then rss=$tmp; fi ;; esac
    dt=$(( ts - prev_ts ))
    dc=$(( cs - prev_cs ))
    if [ "$dt" -gt 0 ] && [ "$dc" -gt 0 ]; then
      # dc is centiseconds of CPU, dt microseconds of wall: dc*1e6/dt is percent.
      pct=$(awk -v dc="$dc" -v dt="$dt" 'BEGIN{printf "%d", dc * 1e6 / dt}')
      [ "$pct" -gt "$peak" ] && peak=$pct
    fi
    prev_cs=$cs
    prev_ts=$ts
    i=$(( i + 1 ))
    [ "$i" -gt 36000 ] && break
  done

  wait "$pid" 2>/dev/null
  local end
  end=$(now_us)
  echo "$label $(( end - start )) $prev_cs $peak $rss"
}

label_for() {
  case "$1" in
    auto) echo "default" ;;
    *) echo "jobs=$1" ;;
  esac
}

REPORT="$WORK/report.txt"
: >"$REPORT"

JOBS_LIST="auto 1 2 4 $HALF"
DEDUP=" "
for j in $JOBS_LIST; do
  case "$DEDUP" in
    *" $j "*) continue ;;
  esac
  DEDUP="$DEDUP$j "
done

echo "m3tal-review audit --jobs sweep"
echo "  repo:  $(cd "$REPO" && pwd)"
echo "  cores: $CORES"
echo "  reps:  $REPS"
echo "  warm-up run (discarded) ..."
(cd "$REPO" && "$BIN" audit >/dev/null 2>&1)

for r in $(seq 1 "$REPS"); do
  for j in $DEDUP; do
    disp=$(label_for "$j")
    if [ "$j" = "auto" ]; then
      line=$(cd "$REPO" && run_one "$disp")
    else
      line=$(cd "$REPO" && run_one "$disp" --jobs "$j")
    fi
    echo "$r $line" >>"$REPORT"
  done
done

echo
awk '
{
  round = $1; label = $2; wall = $3 / 1e6; cpu = $4 / 100; peak = $5; rss = $6
  key = label
  if (!(key in seen)) { order[++n] = key; seen[key] = 1 }
  wsum[label] += wall; csum[label] += cpu; r[label]++
  if (!(label in wmin) || wall < wmin[label]) wmin[label] = wall
  if (!(label in wmax) || wall > wmax[label]) wmax[label] = wall
  if (peak > pmax[label]) pmax[label] = peak
  if (rss > rmax[label]) rmax[label] = rss
}
END {
  printf "%-10s %4s %9s %16s %7s %8s %9s\n", "setting", "runs", "wall", "range", "cpu-s", "avg CPU", "peak CPU"
  for (i = 1; i <= n; i++) {
    k = order[i]
    wall = wsum[k] / r[k]
    cpu = csum[k] / r[k]
    if (r[k] > 1)
      range = sprintf("%.2f-%.2fs", wmin[k], wmax[k])
    else
      range = sprintf("%.2fs", wall)
    printf "%-10s %4d %8.2fs %16s %7.1f %7.0f%% %8.0f%%\n",
      k, r[k], wall, range, cpu, (wall > 0 ? cpu / wall * 100 : 0), pmax[k]
  }
  printf "\nmax RSS: "
  for (i = 1; i <= n; i++) { k = order[i]; printf "%s=%dMB ", k, rmax[k] / 1024 }
  printf "\n"
}' "$REPORT"

echo "note: CPU columns include child processes; 100% means one core busy."
echo "note: audit-cache disabled; --jobs >= cores is equivalent to the default."
