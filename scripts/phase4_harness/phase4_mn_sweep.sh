#!/bin/bash
# Cert-cycle m x n sweep driver at L=6 legit + 1 attacker: m (certCycleSegmentCount) in {2,3,4,5} x
# n (certCycleHashOnlyCount) in {1,2,4,8}, the full A/B/C/D x filter-off/on matrix per combo, N=5/cell,
# bufferTtlMs=500, sustained-duration method of Update 21/22 (attackerMatchLegitDuration:true,
# attackerFloodRateCapPerSec:1010 for cheap_invalid_signature only).
#
# Order: m2_n4 first as the regression combo (must reproduce the L=6 vehicle-scaling result: modal
# 1794/0/0 in every cell, filter-on cert verifications = 6 - STOP otherwise), then the four m=5 combos
# (tightest TTL headroom, 100 ms, so a TTL-driven surprise shows up early), then the rest m-ascending.
#
# Per combo: A_off/A_on -> gate A -> B/C/D -> gate all (phase4_vehicle_scaling_aggregate.py, --phase full)
# -> prediction check (phase4_mn_sweep_aggregate.py --combo; a deviation marks the combo REVIEW, never
# stops) -> gzip -> combo.complete. Each combo has its own trial_times.tsv: clock-step lookup is keyed by
# (L, phase, cell, trial), which would collide across combos in one file.
# Exit codes: 0 complete (possibly with REVIEW combos) | 2 gate STOP | 4 pre-flight failure.
#
# Update 23 (segmentation study): every trial also writes per-message timing CSVs (PQV2V_TIMING_PREFIX) and runs
# in SWEEP_CERT_VERIFY_MODE (every|once, exported as PQV2V_CERT_VERIFY_MODE). SWEEP_L / SWEEP_NUM_MSGS /
# SWEEP_CELLS default to the original L=6 / 300 / all 8 cells; any other setting gets its own ROOT
# (phase4_raw_logs/phase4_seg_sweep/L<L>_msgs<N>[_verifyonce]), one gate over SWEEP_CELLS, and no m2_n4 regression gate.
# Resume: a combo is skipped only if its summary.csv exists AND every trial has its timing files in this run's
# mode; trials without them (e.g. from before Update 23) are re-run. Order is coarse-first: n in SWEEP_COARSE_N
# (default "0 2 4 6") before the rest, m2_n4 first when present.
# SEPARATE from every other phase4 driver, none of which are touched.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
HARNESS="$REPO/scripts/phase4_harness"
L=${SWEEP_L:-6}
NUM_MSGS=${SWEEP_NUM_MSGS:-300}
CERT_MODE=${SWEEP_CERT_VERIFY_MODE:-every}
case $CERT_MODE in every|once) ;; *) echo "SWEEP_CERT_VERIFY_MODE=$CERT_MODE (expected every|once)"; exit 4;; esac
DEFAULT_CELLS="A_off,A_on,B_off,B_on,C_off,C_on,D_off,D_on"
IFS=',' read -r -a CELLS <<< "${SWEEP_CELLS:-$DEFAULT_CELLS}"
ALLCELLS=$(IFS=,; echo "${CELLS[*]}")
DEFAULT_PARAMS=0
[ "$L" = 6 ] && [ "$NUM_MSGS" = 300 ] && [ "$ALLCELLS" = "$DEFAULT_CELLS" ] && DEFAULT_PARAMS=1
MODE_SUFFIX=""; [ "$CERT_MODE" = once ] && MODE_SUFFIX="_verifyonce"
if (( DEFAULT_PARAMS )); then
    DEFAULT_ROOT="$REPO/phase4_raw_logs/phase4_mn_sweep$MODE_SUFFIX"
    RUN_NAME="mn_sweep_L6${MODE_SUFFIX}"
else
    DEFAULT_ROOT="$REPO/phase4_raw_logs/phase4_seg_sweep/L${L}_msgs${NUM_MSGS}${MODE_SUFFIX}"
    RUN_NAME="seg_sweep_L${L}_msgs${NUM_MSGS}${MODE_SUFFIX}"
fi
ROOT="${SWEEP_ROOT:-$DEFAULT_ROOT}"   # SWEEP_ROOT only for smoke tests
BIN="$REPO/build/pq-v2verifier"
AGG="$HARNESS/phase4_vehicle_scaling_aggregate.py"
MNAGG="$HARNESS/phase4_mn_sweep_aggregate.py"
# committed copy of phase4_raw_logs/phase4_vehicle_scaling_sweep/n6/full/summary.csv (L=6 vehicle-scaling result)
REF_SUMMARY="$REPO/exports/seg_grid/reference/vehicle_scaling_n6_summary.csv"
# final CSVs go to exports/ only for the real run; a SWEEP_ROOT smoke test keeps them under its own root
CSV_DIR="${SWEEP_ROOT:+$ROOT}"
CSV_DIR="${CSV_DIR:-$REPO/exports}"
N=${SWEEP_N:-5}
TTL=500
COMBOS=(${SWEEP_COMBOS:-2:4 5:1 5:2 5:4 5:8 2:1 2:2 2:8 3:1 3:2 3:4 3:8 4:1 4:2 4:4 4:8})
COARSE_N=" ${SWEEP_COARSE_N:-0 2 4 6} "
RMEM_MIN=33554432
MIN_FREE_GB=40

mkdir -p "$ROOT"
BASELINE_CFG="$ROOT/config.json.baseline"
EVENTS="$ROOT/events.log"
REVIEW_LIST="$ROOT/review_combos.txt"
SAMPLER_PID=""
TIMES=""
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

preflight_fail() { echo "PREFLIGHT FAIL: $1" | tee -a "$EVENTS"; exit 4; }

check_rmem() {   # read the live value before EVERY trial, never trust an earlier check
    local v; v=$(cat /proc/sys/net/core/rmem_max)
    if (( v < RMEM_MIN )); then stop_run "net.core.rmem_max=$v < $RMEM_MIN before trial $1 (reverted since the last trial?)"; fi
    RMEM_SEEN=$v
}

preflight() {
    pgrep -x pq-v2verifier >/dev/null && preflight_fail "a pq-v2verifier process is already running"
    # NTP clock steps make in-flight messages look late/stale (CORRECTIONS.md #21); off for a real run.
    local ntp; ntp=$(timedatectl show -p NTP --value 2>/dev/null || echo unknown)
    if [ "$ntp" != "no" ] && [ "${SWEEP_ALLOW_NTP:-0}" != "1" ]; then
        preflight_fail "NTP is enabled (NTP=$ntp): run  sudo timedatectl set-ntp false  first (re-enable later with 'sudo timedatectl set-ntp true'), or set SWEEP_ALLOW_NTP=1 for a smoke test"
    fi
    local v; v=$(cat /proc/sys/net/core/rmem_max)
    (( v >= RMEM_MIN )) || preflight_fail "net.core.rmem_max=$v (need >= $RMEM_MIN): run  sudo sysctl -w net.core.rmem_max=$RMEM_MIN"
    python3 - "$BIN" "$REPO" <<'PY' || preflight_fail "binary is stale or missing the variable-m code"
import os, sys
b, repo = sys.argv[1], sys.argv[2]
mt = os.path.getmtime(b)
srcs = [f"{repo}/{s}" for s in ("src/main.cpp","src/Vehicle.cpp","src/AttackerVehicle.cpp","src/bsm.cpp","src/v2vcrypto.cpp",
        "include/Vehicle.h","include/AttackerVehicle.h","include/arguments.h","include/bsm.h","include/v2vcrypto.h",
        "include/ieee16092.h")]
if any(os.path.getmtime(s) > mt for s in srcs): sys.exit("source newer than binary")
d = open(b, "rb").read()
for s in (b"AttackerFloodRateCap", b"AttackerRunSummary", b"LegitDone", b"TraceWrap", b"SocketConfig", b"certCycleSegmentCount",
          b"PQV2V_TIMING_PREFIX", b"PQV2V_CERT_VERIFY_MODE"):
    if s not in d: sys.exit(f"missing string {s}")
PY
    for i in 0 1 2 3 4 5 6 7 8 9; do
        for f in "falcon_keys/$i/falcon.key" "falcon_keys/$i/falcon.pub" "keys/$i/p256.key" "cert_keys/$i/p256.key" "trace_files/$i.csv"; do
            [ -s "$REPO/$f" ] || preflight_fail "missing $f"
        done
    done
    [ -f "$REPO/exports/update21_per_trial.csv" ] || preflight_fail "exports/update21_per_trial.csv missing (reference for the gates)"
    [ -f "$REF_SUMMARY" ] || preflight_fail "$REF_SUMMARY missing (reference for the m2_n4 regression gate)"
    if [ ! -f "$BASELINE_CFG" ]; then
        grep -q '"numMessages":25' "$REPO/config.json" || preflight_fail "config.json is not at its baseline state; refusing to save it as the baseline"
        cp "$REPO/config.json" "$BASELINE_CFG"
    fi
    {   echo "started=$(date) host=$(hostname)"; echo "nproc=$(nproc)"; uname -a; echo "boot=$(uptime -s)"
        echo "rmem_max=$v"; echo "NTP=$ntp timesyncd=$(systemctl is-active systemd-timesyncd 2>&1) allow_ntp_override=${SWEEP_ALLOW_NTP:-0}"
        echo "combos=${COMBOS[*]} N=$N L=$L numMessages=$NUM_MSGS cells=$ALLCELLS cert_verify_mode=$CERT_MODE bufferTtlMs=$TTL"; free -m; df -h "$REPO" | tail -1; } > "$ROOT/environment.txt"
}

start_sampler() {
    local drv=$$
    setsid nohup bash -c "while kill -0 $drv 2>/dev/null; do { date +%s; cat /proc/loadavg; free -m; echo ---; } >> '$ROOT/resource_usage.log'; sleep 15; done" >/dev/null 2>&1 &
    SAMPLER_PID=$!
    log "resource sampler started (driver pid $drv)"
}

write_config() {   # $1=cell $2=m $3=n
    local cell=$1 m=$2 n=$3 na mode filt cap
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
    "numMessages":$NUM_MSGS,
    "signatureScheme":"falcon",
    "numAttackers":$na,
    "attackerMode":"$mode",
    "numAttackerMessages":2000,
    "certCycleHashOnlyCount":$n,
    "certCycleSegmentCount":$m,
    "spamFilterEnabled":$filt,
    "spamFilterMinGapMs":50,
    "spamFilterAdmitMs":100,
    "bufferTtlMs":$TTL,
    "spamFilterGlobalStateCap":512,
    "attackerMatchLegitDuration":true,
    "attackerDurationMargin":2.0,
    "attackerFloodRateCapPerSec":$cap
  }
}
EOF
}

run_trial() {   # $1=dir $2=cell $3=trial
    local dir=$1 cell=$2 t=$3 base="$1/$2_trial$3"
    [ -f "$base.done" ] && return 0
    check_rmem "$cell#$t ($(basename "$dir"))"
    local t0; t0=$(ts)
    rm -f "${base}"_{msgtiming,ttfv,sendtimes}.csv{,.gz}   # a re-run never mixes with stale timing files
    (PQV2V_TIMING_PREFIX="$base" PQV2V_CERT_VERIFY_MODE="$CERT_MODE" \
        timeout 120 "$BIN" dsrc receiver nogui --test > "${base}_recv.log" 2>&1) &
    local recv_pid=$!
    sleep 1
    PQV2V_TIMING_PREFIX="$base" PQV2V_CERT_VERIFY_MODE="$CERT_MODE" \
        timeout 120 "$BIN" dsrc transmitter nogui --test > "${base}_xmit.log" 2>&1
    local xrc=$?
    wait "$recv_pid"
    local rrc=$?
    echo "recv=$rrc xmit=$xrc" > "$base.rc"
    local t1; t1=$(ts)
    # phase column is always "full": the gate is called with --phase full and looks trials up by it
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$L" "full" "$cell" "$t" "$t0" "$t1" >> "$TIMES"
    echo "rmem_max=$RMEM_SEEN start=$t0 end=$t1" > "$base.done"
    echo "  [$(basename "$dir") $cell trial $t] recv rc=$rrc xmit rc=$xrc"
}

run_cell() {   # $1=dir $2=cell $3=m $4=n
    local dir=$1 cell=$2 m=$3 n=$4
    log "$(basename "$dir") cell $cell (N=$N) start"
    write_config "$cell" "$m" "$n"
    local t
    for t in $(seq 1 "$N"); do run_trial "$dir" "$cell" "$t"; done
    log "$(basename "$dir") cell $cell done"
}

gate() {   # $1=dir $2=cells $3=tag [extra aggregator args...]
    local dir=$1 cells=$2 tag=$3; shift 3
    local out="$dir/gate_$tag.txt"
    python3 "$AGG" --outdir "$dir" --num-vehicles "$L" --n-trials "$N" --phase full --cells "$cells" \
        --msgs-per-vehicle "$NUM_MSGS" --trial-times "$TIMES" --verdict-json "$dir/gate_$tag.json" "$@" > "$out" 2>&1
    local rc=$?
    log "gate $tag ($(basename "$dir") cells=$cells): rc=$rc  $(grep '^VERDICT' "$out" | tail -1)"
    case $rc in
        0) ;;
        3) echo "$(basename "$dir") gate_$tag REVIEW" >> "$REVIEW_LIST"; log "isolated hard failure(s) noted; sweep continues" ;;
        2)  # The UNPARSED-stop_reason rate test was sized for a 180-trial level; one 30-trial combo moves it
            # 3.3 points per garbled line. If it is the ONLY stop condition, downgrade to REVIEW; the rate is
            # re-checked pooled over the whole sweep at the end (pooled_unparsed_check). Every other STOP stands.
            if unparsed_only_stop "$dir/gate_$tag.json"; then
                echo "$(basename "$dir") gate_$tag UNPARSED_RATE_REVIEW" >> "$REVIEW_LIST"
                log "UNPARSED_RATE_REVIEW $(basename "$dir") gate_$tag: STOP was only the per-combo unparsed stop_reason rate; continuing (pooled check at sweep end)"
            else
                stop_run "gate $tag returned STOP ($(basename "$dir"))" "$out"
            fi ;;
        *) stop_run "aggregator error rc=$rc at gate $tag ($(basename "$dir"))" "$out" ;;
    esac
}

unparsed_only_stop() {   # $1=verdict json; true iff every immediate condition is the unparsed-rate one and the
                         # hard-failure counts are below the full-phase STOP thresholds (2/cell, 3 total)
    python3 - "$1" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
imm = v.get("immediate", [])
ok = (bool(imm) and all(str(i[2]).startswith("unparsed_stop_reason_rate=") for i in imm)
      and max(v.get("fails_by_cell", {}).values(), default=0) < 2 and v.get("hard_failures", 0) < 3)
sys.exit(0 if ok else 1)
PY
}

pooled_unparsed_check() {   # the unparsed stop_reason rate over every combo's full gate, same 15% / >=20 rule
    local res
    res=$(python3 - "$ROOT" <<'PY'
import glob, json, sys
u = t = 0
for f in glob.glob(f"{sys.argv[1]}/m*_n*/gate_all.json"):
    v = json.load(open(f)); u += v.get("unparsed_stop_reason", 0); t += v.get("attacker_trials", 0)
rate = u / t if t else 0.0
print(f"{u}/{t} {rate:.1%} {'FAIL' if t >= 20 and rate > 0.15 else 'OK'}")
PY
)
    log "pooled unparsed stop_reason rate over the sweep: $res (limit 15%, Update 21 baseline 3.3%)"
    [[ "$res" == *OK ]] || stop_run "pooled unparsed stop_reason rate over the whole sweep exceeds 15%: $res"
}

resume_purge() {   # drop .done markers of existing trials that no longer verify, so they are re-run
    local dir=$1
    ls "$dir"/*.done >/dev/null 2>&1 || return 0
    python3 "$AGG" --outdir "$dir" --num-vehicles "$L" --n-trials "$N" --phase full --allow-missing --no-csv \
        --cells "$ALLCELLS" --msgs-per-vehicle "$NUM_MSGS" \
        --bad-trials "$dir/bad_on_resume.txt" > "$dir/resume_verify.txt" 2>&1
    if [ -s "$dir/bad_on_resume.txt" ]; then
        while read -r cell trial; do rm -f "$dir/${cell}_trial${trial}.done"; log "resume: trial $cell#$trial failed re-verification, will re-run"; done < "$dir/bad_on_resume.txt"
    fi
}

compress_dir() {
    local dir=$1
    find "$dir" -type f \( -name '*.log' -o -name '*_msgtiming.csv' -o -name '*_ttfv.csv' -o -name '*_sendtimes.csv' \) \
        -print0 | xargs -0 -r -n 4 -P 8 gzip -f
    local f bad=0
    while IFS= read -r -d '' f; do gzip -t "$f" || { log "gzip -t FAILED: $f"; bad=1; }; done < <(find "$dir" -type f \
        \( -name '*.log.gz' -o -name '*_msgtiming.csv.gz' -o -name '*_ttfv.csv.gz' -o -name '*_sendtimes.csv.gz' \) -print0)
    (( bad )) && stop_run "gzip integrity check failed in $dir"
    log "compressed + verified raw logs in $dir ($(du -sh "$dir" | cut -f1))"
}

regression_gate() {   # $1=dir of m2_n4: must reproduce the L=6 vehicle-scaling result
    local dir=$1 out="$1/regression_gate.txt"
    python3 - "$dir/summary.csv" "$REF_SUMMARY" > "$out" 2>&1 <<'PY'
import csv, sys
new = {r["cell"]: r for r in csv.DictReader(open(sys.argv[1]))}
ref = {r["cell"]: r for r in csv.DictReader(open(sys.argv[2]))}
bad = []
for cell, r in sorted(new.items()):
    rr = ref.get(cell, {})
    ok_modal = r["modal_valid_drop_deadline"] == "1794/0/0"
    ok_cert = cell.endswith("_off") or float(r["cert_verify_n_mean"]) == 6.0
    print(f"{cell}: modal {r['modal_valid_drop_deadline']} (ref {rr.get('modal_valid_drop_deadline')}) "
          f"cert_verify_n_mean {r['cert_verify_n_mean']} (ref {rr.get('cert_verify_n_mean')}) -> {'OK' if ok_modal and ok_cert else 'MISMATCH'}")
    if not (ok_modal and ok_cert):
        bad.append(cell)
missing = sorted(set(ref) - set(new))
if missing:
    print(f"cells missing from the new summary: {missing}"); bad += missing
print("REGRESSION:", "FAIL " + ",".join(bad) if bad else "PASS")
sys.exit(1 if bad else 0)
PY
    local rc=$?
    log "regression gate m2_n4 vs L=6 vehicle-scaling: $(tail -1 "$out")"
    (( rc == 0 )) || stop_run "m2_n4 regression gate failed" "$out"
}

have_file() { [ -f "$1" ] || [ -f "$1.gz" ]; }

recv_mode() {   # cert_verify_mode printed in a trial's receiver summary (absent = pre-Update-23 binary)
    local f=$1
    # -a: receiver logs can contain stray binary bytes, and grep then suppresses the matched line
    if [ -f "$f" ]; then grep -a -m1 -o '^cert_verify_mode=[a-z]*' "$f"
    elif [ -f "$f.gz" ]; then zcat "$f.gz" | grep -a -m1 -o '^cert_verify_mode=[a-z]*'; fi
}

trial_timing_ok() {   # $1=dir $2=cell $3=trial: this trial has its timing files, recorded in this run's mode
    local base="$1/$2_trial$3"
    have_file "${base}_msgtiming.csv" && have_file "${base}_ttfv.csv" || return 1
    case $2 in A_*) have_file "${base}_sendtimes.csv" || return 1;; esac
    [ "$(recv_mode "${base}_recv.log")" = "cert_verify_mode=$CERT_MODE" ]
}

timing_purge() {   # drop .done markers of trials lacking timing files / in the other mode, so they re-run
    local dir=$1 c t n=0
    for c in "${CELLS[@]}"; do
        for t in $(seq 1 "$N"); do
            if [ -f "$dir/${c}_trial${t}.done" ] && ! trial_timing_ok "$dir" "$c" "$t"; then
                rm -f "$dir/${c}_trial${t}.done"; n=$((n + 1))
            fi
        done
    done
    (( n )) && log "resume: $n trial(s) in $(basename "$dir") lack timing files for mode=$CERT_MODE; will re-run"
    return 0
}

combo_timing_complete() {   # every trial of every cell present with timing files in this mode
    local dir=$1 c t
    for c in "${CELLS[@]}"; do
        for t in $(seq 1 "$N"); do trial_timing_ok "$dir" "$c" "$t" || return 1; done
    done
}

prediction_check() {   # $1=dir $2=tag
    local dir=$1 tag=$2
    python3 "$MNAGG" --root "$ROOT" --combo "$tag" --n-trials "$N" --num-vehicles "$L" --msgs-per-vehicle "$NUM_MSGS" \
        --cells "$ALLCELLS" > "$dir/prediction_check.txt" 2>&1
    local prc=$?
    # soft clock-step warnings (never a stop or REVIEW): surface them in events.log too
    grep '^  WARNING' "$dir/prediction_check.txt" | while read -r line; do log "SOFT_WARNING $tag: $line"; done
    if (( prc == 3 )); then
        echo "$tag PREDICTION_DEVIATION" >> "$REVIEW_LIST"
        grep '^  DEVIATION' "$dir/prediction_check.txt" | while read -r line; do log "PREDICTION_DEVIATION $tag: $line"; done
    elif (( prc != 0 )); then
        stop_run "prediction check error rc=$prc for $tag" "$dir/prediction_check.txt"
    else
        log "prediction check $tag: all cells match $NUM_MSGS*L-L(m-1) / NO_CERT_YET=L(m-1) and the cert-verify count (mode=$CERT_MODE)"
    fi
}

run_combo() {   # $1=m $2=n
    local m=$1 n=$2 tag="m$1_n$2" dir="$ROOT/m$1_n$2"
    mkdir -p "$dir"
    TIMES="$dir/trial_times.tsv"
    [ -f "$TIMES" ] || : > "$TIMES"
    # Resume rule (Update 23): skip only when summary.csv exists AND every trial has timing files in this mode.
    if [ -f "$dir/summary.csv" ] && combo_timing_complete "$dir"; then
        if [ ! -f "$dir/combo.complete" ]; then   # interrupted after its gate: finish the bookkeeping only
            log "combo $tag has summary + timing but no combo.complete; finishing prediction check + compression"
            prediction_check "$dir" "$tag"
            compress_dir "$dir"
            touch "$dir/combo.complete"
        fi
        log "combo $tag already complete (summary.csv + timing files, mode=$CERT_MODE); skipping"
        return 0
    fi
    rm -f "$dir/combo.complete"
    timing_purge "$dir"
    local free_gb; free_gb=$(df -BG --output=avail "$REPO" | tail -1 | tr -dc '0-9')
    (( free_gb >= MIN_FREE_GB )) || stop_run "only ${free_gb}G free (< ${MIN_FREE_GB}G) before combo $tag"
    log "=================== COMBO $tag (L=$L msgs=$NUM_MSGS mode=$CERT_MODE m=$m n=$n tau=$((m + n)) ttl_headroom=$((TTL - (m - 1) * 100))ms) start ==================="
    resume_purge "$dir"
    local c
    if (( DEFAULT_PARAMS )); then
        for c in A_off A_on; do run_cell "$dir" "$c" "$m" "$n"; done
        gate "$dir" "A_off,A_on" "A" --no-csv
        for c in B_off B_on C_off C_on D_off D_on; do run_cell "$dir" "$c" "$m" "$n"; done
    else
        for c in "${CELLS[@]}"; do run_cell "$dir" "$c" "$m" "$n"; done
    fi
    gate "$dir" "$ALLCELLS" "all" --csv-per-trial "$dir/per_trial.csv" --csv-summary "$dir/summary.csv"
    (( DEFAULT_PARAMS )) && [ "$CERT_MODE" = every ] && [ "$tag" = "m2_n4" ] && regression_gate "$dir"
    prediction_check "$dir" "$tag"
    compress_dir "$dir"
    touch "$dir/combo.complete"
    log "=================== COMBO $tag complete ==================="
}

order_combos() {   # coarse-first: m2_n4 (regression combo) if present, then n in COARSE_N, then the rest
    local c first=() coarse=() rest=()
    for c in "${COMBOS[@]}"; do
        if [ "$c" = "2:4" ]; then first+=("$c")
        elif [[ "$COARSE_N" == *" ${c##*:} "* ]]; then coarse+=("$c")
        else rest+=("$c"); fi
    done
    COMBOS=("${first[@]}" "${coarse[@]}" "${rest[@]}")
}

main() {
    preflight
    start_sampler
    order_combos
    log "sweep start: combos=${COMBOS[*]} N=$N L=$L msgs=$NUM_MSGS cells=$ALLCELLS mode=$CERT_MODE ttl=$TTL baseline_cfg=$BASELINE_CFG"
    local c
    for c in "${COMBOS[@]}"; do run_combo "${c%%:*}" "${c##*:}"; done
    pooled_unparsed_check
    python3 "$MNAGG" --root "$ROOT" --n-trials "$N" --num-vehicles "$L" --msgs-per-vehicle "$NUM_MSGS" --cells "$ALLCELLS" \
        --csv-per-trial "$CSV_DIR/${RUN_NAME}_per_trial.csv" \
        --csv-summary "$CSV_DIR/${RUN_NAME}_summary.csv" > "$ROOT/report_build.txt" 2>&1 || log "WARNING: final report build failed (see report_build.txt)"
    if [ -s "$REVIEW_LIST" ]; then
        log "SWEEP COMPLETE with REVIEW combos: $(tr '\n' ' ' < "$REVIEW_LIST")"
    else
        log "SWEEP COMPLETE (all combos PASS)"
    fi
}

main
