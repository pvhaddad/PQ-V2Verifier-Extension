#!/bin/bash
# Segmentation-study grid (Update 23): A_off only, numMessages=200, N=5 trials per combo, verify-once mode
# (Fig. 3 version B), run pass-major so an interrupted run still leaves a complete coarse grid for every L:
#   Pass 1: n in {0,2,4,6} x m in {2,3,4,5}, for L = 6, 4, 3, 5
#   Pass 2: n in {1,3,5}   x m in {2,3,4,5}, for L = 6, 4, 3, 5
#   Pass 3 (OPTIONAL, last; set SEG_GRID_PASS3=1): every-mode reference slice at L=6, m in {2,5} x n in {0,4},
#          same N - the A-vs-B comparison for phase4_mn_sweep_aggregate.py --ab-reference.
# Each (pass, L) is one phase4_mn_sweep.sh call with explicit SWEEP_COMBOS; each L/mode gets its own ROOT
# (phase4_raw_logs/phase4_seg_sweep/L<L>_msgs200[_verifyonce]). Safe to re-run: the driver skips a combo only
# when its summary.csv and every trial's timing files (in this mode) exist, so completed combos are not repeated.
# Stops at the first driver failure (exit code passed through). Does not raise rmem_max or touch NTP itself.
set -uo pipefail

HARNESS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="$HARNESS/phase4_mn_sweep.sh"
LOG="$(dirname "$(dirname "$HARNESS")")/phase4_raw_logs/phase4_seg_sweep/grid_events.log"
mkdir -p "$(dirname "$LOG")"
log() { echo "$(date +%s.%N) $*" | tee -a "$LOG"; }

ntp=$(timedatectl show -p NTP --value 2>/dev/null || echo unknown)
if [ "$ntp" != "no" ]; then
    log "PREFLIGHT FAIL: NTP is enabled (NTP=$ntp); run  sudo timedatectl set-ntp false  first"
    exit 4
fi

combos() {   # $1 = n values; prints m:n for m in 2..5
    local n m out=()
    for n in $1; do for m in 2 3 4 5; do out+=("$m:$n"); done; done
    echo "${out[*]}"
}

run_pass() {   # $1=pass label $2=mode $3=combos $4.. = L values
    local label=$1 mode=$2 cs=$3 L rc; shift 3
    for L in "$@"; do
        log "=== $label: L=$L mode=$mode combos=$cs ==="
        SWEEP_CELLS=A_off SWEEP_NUM_MSGS=200 SWEEP_N=5 SWEEP_L="$L" SWEEP_CERT_VERIFY_MODE="$mode" \
            SWEEP_COMBOS="$cs" bash "$DRIVER"
        rc=$?
        log "$label L=$L driver rc=$rc"
        (( rc == 0 )) || { log "stopping: driver failed in $label L=$L"; exit "$rc"; }
    done
}

run_pass "pass 1 (coarse n)" once "$(combos "0 2 4 6")" 6 4 3 5
run_pass "pass 2 (odd n)"    once "$(combos "1 3 5")"   6 4 3 5
if [ "${SEG_GRID_PASS3:-0}" = 1 ]; then   # OPTIONAL: every-mode A-vs-B reference slice
    run_pass "pass 3 (every-mode reference)" every "2:0 5:0 2:4 5:4" 6
fi
log "grid complete"
