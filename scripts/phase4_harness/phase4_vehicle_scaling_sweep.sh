#!/bin/bash
# Vehicle-count scaling sweep driver: numVehicles = 4, 6, 9 legit + 1 attacker, the A/B/C/D x
# filter-off/on matrix, sustained-duration method of Update 21 (attackerMatchLegitDuration:true,
# attackerFloodRateCapPerSec:1010 for cheap_invalid_signature only).
#
# Per level: pilot (8 cells x PILOT_N) -> gate -> full (8 cells x FULL_N) with a gate after every
# cell -> reconcile -> gzip the raw logs -> next level. Any gate STOP, or an isolated hard failure
# at level end, halts the sweep with STOP_REPORT.txt and a restored config.json.
# Exit codes: 0 complete | 2 gate STOP | 3 isolated failure, stopped before the next level |
#             4 pre-flight failure.
# SEPARATE from phase4_run_trials.sh / phase4_sweep_params.sh / phase4_pilot_cheap_invalid.sh /
# phase4_run_trials_match_duration.sh, none of which are touched.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
HARNESS="$REPO/scripts/phase4_harness"
ROOT="${SWEEP_ROOT:-$REPO/phase4_raw_logs/phase4_vehicle_scaling_sweep}"   # SWEEP_ROOT only for smoke tests
BIN="$REPO/build/pq-v2verifier"
AGG="$HARNESS/phase4_vehicle_scaling_aggregate.py"
LEVELS=(${SWEEP_LEVELS:-4 6 9})
PILOT_N=${SWEEP_PILOT_N:-5}
FULL_N=${SWEEP_FULL_N:-30}
CELLS=(A_off A_on B_off B_on C_off C_on D_off D_on)
ALLCELLS=$(IFS=,; echo "${CELLS[*]}")
RMEM_MIN=33554432
MIN_FREE_GB=40

mkdir -p "$ROOT"
BASELINE_CFG="$ROOT/config.json.baseline"
EVENTS="$ROOT/events.log"
TIMES="$ROOT/trial_times.tsv"
SAMPLER_PID=""
PHASE=""
LEVEL_REVIEW=0
RMEM_SEEN=0

ts()  { date +%s.%N; }
log() { echo "$(ts) $*" | tee -a "$EVENTS"; }

cleanup() {
    local rc=$?
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null
    if [ -f "$BASELINE_CFG" ]; then
        cp "$BASELINE_CFG" "$REPO/config.json"
        if cmp -s "$BASELINE_CFG" "$REPO/config.json"; then log "config.json restored to baseline"
        else log "WARNING: config.json does NOT match baseline after restore"; fi
    fi
    if pgrep -x pq-v2verifier >/dev/null; then log "WARNING: stray pq-v2verifier process, killing"; pkill -x pq-v2verifier; fi
    log "driver exit rc=$rc"
    exit $rc
}
trap cleanup EXIT

stop_run() {   # $1 reason, $2 optional file to append to the report
    { echo "=== STOP $(date) ==="; echo "$1"; [ -n "${2:-}" ] && [ -f "$2" ] && { echo "--- $2 ---"; cat "$2"; }; } >> "$ROOT/STOP_REPORT.txt"
    log "STOP: $1"
    exit 2
}

review_stop() {
    { echo "=== REVIEW STOP $(date) ==="; echo "$1"; [ -n "${2:-}" ] && [ -f "$2" ] && { echo "--- $2 ---"; cat "$2"; }; } >> "$ROOT/STOP_REPORT.txt"
    log "REVIEW STOP: $1"
    exit 3
}

preflight_fail() { echo "PREFLIGHT FAIL: $1" | tee -a "$EVENTS"; exit 4; }

check_rmem() {   # read the live value before EVERY trial, never trust an earlier check
    local v; v=$(cat /proc/sys/net/core/rmem_max)
    if (( v < RMEM_MIN )); then stop_run "net.core.rmem_max=$v < $RMEM_MIN before trial $1 (reverted since the last trial?)"; fi
    RMEM_SEEN=$v
}

preflight() {
    pgrep -x pq-v2verifier >/dev/null && preflight_fail "a pq-v2verifier process is already running"
    # systemd-timesyncd steps the wall clock forward ~0.4-0.75 s every 32 s while the guest clock lags (intermittent, multi-hour
    # blocks); the receiver's latency and the filter's STALE test are system_clock differences, so every message in flight at a
    # step looks that much older (CORRECTIONS.md #21). NTP must be off for a long run; the journal-based detection below is only
    # the safety net. SWEEP_ALLOW_NTP=1 is for smoke tests only.
    local ntp; ntp=$(timedatectl show -p NTP --value 2>/dev/null || echo unknown)
    if [ "$ntp" != "no" ] && [ "${SWEEP_ALLOW_NTP:-0}" != "1" ]; then
        preflight_fail "NTP is enabled (NTP=$ntp): run  sudo timedatectl set-ntp false  first (persistent; re-enable later with 'sudo timedatectl set-ntp true'), or set SWEEP_ALLOW_NTP=1 for a smoke test"
    fi
    local v; v=$(cat /proc/sys/net/core/rmem_max)
    (( v >= RMEM_MIN )) || preflight_fail "net.core.rmem_max=$v (need >= $RMEM_MIN): run  sudo sysctl -w net.core.rmem_max=$RMEM_MIN"
    python3 - "$BIN" "$REPO" <<'PY' || preflight_fail "binary is stale or missing the Update 21 code"
import os, sys
b, repo = sys.argv[1], sys.argv[2]
mt = os.path.getmtime(b)
srcs = [f"{repo}/{s}" for s in ("src/main.cpp","src/Vehicle.cpp","src/AttackerVehicle.cpp","src/bsm.cpp","src/v2vcrypto.cpp",
        "include/Vehicle.h","include/AttackerVehicle.h","include/arguments.h","include/bsm.h","include/v2vcrypto.h")]
if any(os.path.getmtime(s) > mt for s in srcs): sys.exit("source newer than binary")
d = open(b, "rb").read()
for s in (b"AttackerFloodRateCap", b"AttackerRunSummary", b"LegitDone", b"TraceWrap", b"SocketConfig"):
    if s not in d: sys.exit(f"missing string {s}")
PY
    for i in 0 1 2 3 4 5 6 7 8 9; do
        for f in "falcon_keys/$i/falcon.key" "falcon_keys/$i/falcon.pub" "keys/$i/p256.key" "cert_keys/$i/p256.key" "trace_files/$i.csv"; do
            [ -s "$REPO/$f" ] || preflight_fail "missing $f"
        done
    done
    [ -f "$REPO/exports/update21_per_trial.csv" ] || preflight_fail "exports/update21_per_trial.csv missing (reference for the gates)"
    grep -q measured_rate_per_sec "$REPO/exports/update21_per_trial.csv" || preflight_fail "update21 CSV lacks measured_rate_per_sec (Part 0.3 not done)"
    if [ ! -f "$BASELINE_CFG" ]; then
        grep -q '"numMessages":25' "$REPO/config.json" || preflight_fail "config.json is not at its baseline state; refusing to save it as the baseline"
        cp "$REPO/config.json" "$BASELINE_CFG"
    fi
    {   echo "started=$(date) host=$(hostname)"; echo "nproc=$(nproc)"; uname -a; echo "boot=$(uptime -s)"
        echo "rmem_max=$v"; echo "NTP=$ntp timesyncd=$(systemctl is-active systemd-timesyncd 2>&1) allow_ntp_override=${SWEEP_ALLOW_NTP:-0}"; free -m; df -h "$REPO" | tail -1; } > "$ROOT/environment.txt"
    [ -f "$TIMES" ] || : > "$TIMES"
}

start_sampler() {
    local drv=$$
    setsid nohup bash -c "while kill -0 $drv 2>/dev/null; do { date +%s; cat /proc/loadavg; free -m; echo ---; } >> '$ROOT/resource_usage.log'; sleep 15; done" >/dev/null 2>&1 &
    SAMPLER_PID=$!
    log "resource sampler started (driver pid $drv)"
}

write_config() {   # $1=L $2=cell
    local L=$1 cell=$2 na mode filt cap
    case $cell in
        A_off) na=0; mode=expensive_valid;          filt=false; cap=0;;
        A_on)  na=0; mode=expensive_valid;          filt=true;  cap=0;;
        B_off) na=1; mode=expensive_valid;          filt=false; cap=0;;
        B_on)  na=1; mode=expensive_valid;          filt=true;  cap=0;;
        C_off) na=1; mode=invalid_signature;        filt=false; cap=0;;
        C_on)  na=1; mode=invalid_signature;        filt=true;  cap=0;;
        D_off) na=1; mode=cheap_invalid_signature;  filt=false; cap=1010;;
        D_on)  na=1; mode=cheap_invalid_signature;  filt=true;  cap=1010;;
    esac
    cat > "$REPO/config.json" <<EOF
{
  "scenario": {
    "numVehicles":$L,
    "numMessages":300,
    "signatureScheme":"falcon",
    "numAttackers":$na,
    "attackerMode":"$mode",
    "numAttackerMessages":2000,
    "certCycleHashOnlyCount":4,
    "spamFilterEnabled":$filt,
    "spamFilterMinGapMs":50,
    "spamFilterAdmitMs":100,
    "bufferTtlMs":500,
    "spamFilterGlobalStateCap":512,
    "attackerMatchLegitDuration":true,
    "attackerDurationMargin":2.0,
    "attackerFloodRateCapPerSec":$cap
  }
}
EOF
}

run_trial() {   # $1=dir $2=cell $3=trial $4=L
    local dir=$1 cell=$2 t=$3 L=$4 base="$1/$2_trial$3"
    [ -f "$base.done" ] && return 0
    check_rmem "$cell#$t (L=$L $PHASE)"
    local t0; t0=$(ts)
    (timeout 120 "$BIN" dsrc receiver nogui --test > "${base}_recv.log" 2>&1) &
    local recv_pid=$!
    sleep 1
    timeout 120 "$BIN" dsrc transmitter nogui --test > "${base}_xmit.log" 2>&1
    local xrc=$?
    wait "$recv_pid"
    local rrc=$?
    echo "recv=$rrc xmit=$xrc" > "$base.rc"
    local t1; t1=$(ts)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$L" "$PHASE" "$cell" "$t" "$t0" "$t1" >> "$TIMES"
    echo "rmem_max=$RMEM_SEEN start=$t0 end=$t1" > "$base.done"
    echo "  [L=$L $PHASE $cell trial $t] recv rc=$rrc xmit rc=$xrc"
}

run_cell() {   # $1=dir $2=L $3=N $4=cell
    local dir=$1 L=$2 N=$3 cell=$4
    log "cell $cell (L=$L $PHASE N=$N) start"
    write_config "$L" "$cell"
    local t
    for t in $(seq 1 "$N"); do run_trial "$dir" "$cell" "$t" "$L"; done
    log "cell $cell (L=$L $PHASE) done"
}

gate() {   # $1=dir $2=L $3=N $4=phase $5=cells $6=tag [extra aggregator args...]
    local dir=$1 L=$2 N=$3 phase=$4 cells=$5 tag=$6; shift 6
    local out="$dir/gate_$tag.txt"
    # SWEEP_AGG_EXTRA is a test hook only (e.g. --ref-atk to force a STOP); empty in the real sweep
    python3 "$AGG" --outdir "$dir" --num-vehicles "$L" --n-trials "$N" --phase "$phase" --cells "$cells" \
        --trial-times "$TIMES" --verdict-json "$dir/gate_$tag.json" "$@" ${SWEEP_AGG_EXTRA:-} > "$out" 2>&1
    local rc=$?
    log "gate $tag (L=$L $phase cells=$cells): rc=$rc  $(grep '^VERDICT' "$out" | tail -1)"
    case $rc in
        0) ;;
        3) LEVEL_REVIEW=1; log "isolated hard failure(s) noted; level continues, next level will not start" ;;
        2) stop_run "gate $tag returned STOP (L=$L $phase)" "$out" ;;
        *) stop_run "aggregator error rc=$rc at gate $tag" "$out" ;;
    esac
}

resume_purge() {   # drop .done markers of existing trials that no longer verify, so they are re-run
    local dir=$1 L=$2 N=$3 phase=$4
    ls "$dir"/*.done >/dev/null 2>&1 || return 0
    python3 "$AGG" --outdir "$dir" --num-vehicles "$L" --n-trials "$N" --phase "$phase" --allow-missing \
        --bad-trials "$dir/bad_on_resume.txt" > "$dir/resume_verify.txt" 2>&1
    if [ -s "$dir/bad_on_resume.txt" ]; then
        while read -r cell trial; do rm -f "$dir/${cell}_trial${trial}.done"; log "resume: trial $cell#$trial failed re-verification, will re-run"; done < "$dir/bad_on_resume.txt"
    fi
    # a trial without a .done marker cannot be trusted either way; markers come from this driver only
}

compress_dir() {
    local dir=$1
    find "$dir" -type f -name '*.log' -print0 | xargs -0 -r -n 4 -P 8 gzip -f
    local f bad=0
    while IFS= read -r -d '' f; do gzip -t "$f" || { log "gzip -t FAILED: $f"; bad=1; }; done < <(find "$dir" -type f -name '*.log.gz' -print0)
    (( bad )) && stop_run "gzip integrity check failed in $dir"
    log "compressed + verified raw logs in $dir ($(du -sh "$dir" | cut -f1))"
}

run_level() {
    local L=$1 ldir="$ROOT/n$1"
    local pdir="$ldir/pilot" fdir="$ldir/full"
    mkdir -p "$pdir" "$fdir"
    if [ -f "$ldir/level.complete" ]; then
        log "level L=$L already complete; re-verifying its compressed logs"
        gate "$fdir" "$L" "$FULL_N" full "$ALLCELLS" "verify_complete"
        return 0
    fi
    LEVEL_REVIEW=0
    local free_gb; free_gb=$(df -BG --output=avail "$REPO" | tail -1 | tr -dc '0-9')
    (( free_gb >= MIN_FREE_GB )) || stop_run "only ${free_gb}G free (< ${MIN_FREE_GB}G) before level L=$L"
    log "=================== LEVEL L=$L (legit=$L + 1 attacker) start ==================="

    PHASE=pilot
    resume_purge "$pdir" "$L" "$PILOT_N" pilot
    local c
    for c in A_off A_on; do run_cell "$pdir" "$L" "$PILOT_N" "$c"; done
    gate "$pdir" "$L" "$PILOT_N" pilot "A_off,A_on" "pilotA"           # the key check, BEFORE B/C/D run
    for c in B_off B_on C_off C_on D_off D_on; do run_cell "$pdir" "$L" "$PILOT_N" "$c"; done
    gate "$pdir" "$L" "$PILOT_N" pilot "$ALLCELLS" "pilotAll"
    log "L=$L pilot PASSED every gate; proceeding to the full run (advance approval, conditional on this pass)"

    PHASE=full
    resume_purge "$fdir" "$L" "$FULL_N" full
    local done_cells=""
    for c in "${CELLS[@]}"; do
        run_cell "$fdir" "$L" "$FULL_N" "$c"
        done_cells="${done_cells:+$done_cells,}$c"
        gate "$fdir" "$L" "$FULL_N" full "$done_cells" "full_$c"
    done
    gate "$fdir" "$L" "$FULL_N" full "$ALLCELLS" "full_final" --csv-per-trial "$fdir/per_trial.csv" --csv-summary "$fdir/summary.csv"
    python3 "$AGG" --outdir "$pdir" --num-vehicles "$L" --n-trials "$PILOT_N" --phase pilot --trial-times "$TIMES" --csv-per-trial "$pdir/per_trial.csv" --csv-summary "$pdir/summary.csv" > "$pdir/final_report.txt" 2>&1
    cp "$fdir/gate_full_final.txt" "$fdir/aggregate_report.txt"

    compress_dir "$pdir"; compress_dir "$fdir"
    touch "$ldir/level.complete"
    log "=================== LEVEL L=$L complete ==================="
    if (( LEVEL_REVIEW )); then
        review_stop "level L=$L had isolated hard failure(s); logs compressed, next level NOT started" "$fdir/gate_full_final.txt"
    fi
}

main() {
    preflight
    start_sampler
    log "sweep start: levels=${LEVELS[*]} pilot_n=$PILOT_N full_n=$FULL_N baseline_cfg=$BASELINE_CFG"
    local L
    for L in "${LEVELS[@]}"; do run_level "$L"; done
    python3 "$HARNESS/phase4_vehicle_scaling_resources.py" "$ROOT" > "$ROOT/resource_report.txt" 2>&1
    log "SWEEP COMPLETE (resource report: $ROOT/resource_report.txt)"
}

main
