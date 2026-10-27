#!/bin/bash
# Design-space sweep of the spam filter's own config knobs (bufferTtlMs,
# spamFilterGlobalStateCap), backing off the locked C_on condition (Update 15). Deliberately
# a SEPARATE script from phase4_run_trials.sh and phase4_pilot_cheap_invalid.sh - never edits
# either - so there is zero risk of re-triggering the locked N=75 A/B/C matrix or the locked
# N=75 D_off/D_on matrix. write_config()/run_trial() bodies are copied verbatim in shape from
# phase4_pilot_cheap_invalid.sh, extended with buffer_ttl_ms/global_cap/num_vehicles params.
#
# Exploratory data only: N=15/cell, not N=75. Lower confidence than the locked series by
# design - see context/UPDATES.md Update 21.
#
# Usage:
#   phase4_sweep_params.sh ttl        # sub-sweep 1: bufferTtlMs, numVehicles=2 (no gate)
#   phase4_sweep_params.sh cap_pilot  # Step 2.5 pre-flight: 5 trials @ numVehicles=9, cap=512
#   phase4_sweep_params.sh cap        # sub-sweep 2: spamFilterGlobalStateCap, numVehicles=9
#                                      # (only after cap_pilot is reviewed and approved)
set -euo pipefail
source "$(dirname "$0")/require_rcvbuf.sh"

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRATCH="${SCRATCH:-$REPO/phase4_raw_logs}"
OUTDIR="$SCRATCH/phase4_sweep_trials"
ORIG_CONFIG="$SCRATCH/config_backup/config.json.orig"
mkdir -p "$OUTDIR"

N_TRIALS=15
N_PILOT_TRIALS=5

write_config() {
    local num_vehicles=$1
    local buffer_ttl_ms=$2
    local global_cap=$3
    cat > "$REPO/config.json" << EOF
{
  "scenario": {
    "numVehicles":$num_vehicles,
    "numMessages":300,
    "signatureScheme":"falcon",
    "numAttackers":1,
    "attackerMode":"invalid_signature",
    "numAttackerMessages":2000,
    "certCycleHashOnlyCount":4,
    "spamFilterEnabled":true,
    "spamFilterMinGapMs":50,
    "spamFilterAdmitMs":100,
    "bufferTtlMs":$buffer_ttl_ms,
    "spamFilterGlobalStateCap":$global_cap
  }
}
EOF
}

restore_production_config() {
    cp "$ORIG_CONFIG" "$REPO/config.json"
}

run_trial() {
    local cell=$1
    local trial=$2
    local recv_log="$OUTDIR/${cell}_trial${trial}_recv.log"
    local xmit_log="$OUTDIR/${cell}_trial${trial}_xmit.log"
    local t0 t1
    t0=$(date +%s.%N)
    (timeout 120 "$REPO/build/pq-v2verifier" dsrc receiver nogui --test > "$recv_log" 2>&1) &
    local recv_pid=$!
    sleep 1
    timeout 120 "$REPO/build/pq-v2verifier" dsrc transmitter nogui --test > "$xmit_log" 2>&1
    wait "$recv_pid"
    local rc=$?
    t1=$(date +%s.%N)
    local elapsed
    elapsed=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
    echo "  [$cell trial $trial] recv exit=$rc elapsed=${elapsed}s"
}

run_cell() {
    local cell=$1 num_vehicles=$2 buffer_ttl_ms=$3 global_cap=$4 n_trials=$5
    echo "=== Cell: $cell (numVehicles=$num_vehicles bufferTtlMs=$buffer_ttl_ms spamFilterGlobalStateCap=$global_cap) ==="
    write_config "$num_vehicles" "$buffer_ttl_ms" "$global_cap"
    for t in $(seq 1 "$n_trials"); do
        run_trial "$cell" "$t"
    done
    restore_production_config
    echo "  [config.json restored to production defaults after $cell]"
}

case "${1:-}" in
    ttl)
        # Sub-sweep 1: bufferTtlMs, numVehicles=2 (production population, no trace-file
        # dependency, no gate). cap fixed at production default 512.
        run_cell "TTL50"   2 50   512 "$N_TRIALS"
        run_cell "TTL100"  2 100  512 "$N_TRIALS"
        run_cell "TTL250"  2 250  512 "$N_TRIALS"
        run_cell "TTL500"  2 500  512 "$N_TRIALS"
        run_cell "TTL1000" 2 1000 512 "$N_TRIALS"
        run_cell "TTL2000" 2 2000 512 "$N_TRIALS"
        echo "TTL SUB-SWEEP COMPLETE"
        ;;
    cap_pilot)
        # Step 2.5 hard gate: 5 trials at numVehicles=9, cap=512 (production default cap) to
        # validate the untested 9-vehicle population before committing to the full 105-trial
        # cap sub-sweep. bufferTtlMs fixed at production default 500.
        run_cell "CAP_PILOT512" 9 500 512 "$N_PILOT_TRIALS"
        echo "CAP PILOT COMPLETE"
        ;;
    cap)
        # Sub-sweep 2: spamFilterGlobalStateCap, numVehicles=9 (only after cap_pilot approved).
        # bufferTtlMs fixed at production default 500.
        run_cell "CAP2"   9 500 2   "$N_TRIALS"
        run_cell "CAP4"   9 500 4   "$N_TRIALS"
        run_cell "CAP6"   9 500 6   "$N_TRIALS"
        run_cell "CAP8"   9 500 8   "$N_TRIALS"
        run_cell "CAP10"  9 500 10  "$N_TRIALS"
        run_cell "CAP15"  9 500 15  "$N_TRIALS"
        run_cell "CAP512" 9 500 512 "$N_TRIALS"
        echo "CAP SUB-SWEEP COMPLETE"
        ;;
    *)
        echo "Usage: $0 {ttl|cap_pilot|cap}" >&2
        exit 1
        ;;
esac
