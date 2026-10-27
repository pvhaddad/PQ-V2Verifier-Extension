#!/bin/bash
# Sanity pilot for the sustained-duration A/B/C/D re-run (attackerMatchLegitDuration:true,
# context/UPDATES.md Update 21), with Attack D rate-capped at ~1010 msg/sec
# (attackerFloodRateCapPerSec - see main.cpp's [AttackerFloodRateCap] wiring) to model the
# physical DSRC channel ceiling instead of this laptop's raw CPU speed. Deliberately a SEPARATE
# script from phase4_run_trials.sh / phase4_sweep_params.sh / phase4_pilot_cheap_invalid.sh -
# zero risk of touching the locked Update 15/20 matrix or any other in-progress work.
# write_config()/run_trial() bodies follow the same shape as those scripts, with corrected
# REPO/SCRATCH default to this checkout and its phase4_raw_logs/; override via env.
set -euo pipefail
source "$(dirname "$0")/require_rcvbuf.sh"

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRATCH="${SCRATCH:-$REPO/phase4_raw_logs}"
OUTDIR="$SCRATCH/phase4_pilot_match_duration_trials"
mkdir -p "$OUTDIR"

N_TRIALS=3

{
  echo "nproc=$(nproc)"
  free -m
} > "$OUTDIR/environment.txt"

# Resource sampler: backgrounded for the lifetime of this script only, killed by the EXIT trap
# below. Motivation: prior WSL2 kernel logs showed vmstat_shepherd CPU-contention warnings, and
# duration-mode trials hold ~30s of sustained load each - more contention exposure than any
# prior fixed-count run.
RESOURCE_LOG="$OUTDIR/resource_usage.log"
: > "$RESOURCE_LOG"
(
  while true; do
    { date; cat /proc/loadavg; free -m; echo "---"; } >> "$RESOURCE_LOG"
    sleep 12
  done
) &
SAMPLER_PID=$!

cleanup() {
    kill "$SAMPLER_PID" 2>/dev/null || true
}
trap cleanup EXIT

write_config() {
    local num_attackers=$1
    local attacker_mode=$2
    local filter_enabled=$3
    local flood_rate_cap=$4
    cat > "$REPO/config.json" << EOF
{
  "scenario": {
    "numVehicles":2,
    "numMessages":300,
    "signatureScheme":"falcon",
    "numAttackers":$num_attackers,
    "attackerMode":"$attacker_mode",
    "numAttackerMessages":2000,
    "certCycleHashOnlyCount":4,
    "spamFilterEnabled":$filter_enabled,
    "spamFilterMinGapMs":50,
    "spamFilterAdmitMs":100,
    "bufferTtlMs":500,
    "spamFilterGlobalStateCap":512,
    "attackerMatchLegitDuration":true,
    "attackerDurationMargin":2.0,
    "attackerFloodRateCapPerSec":$flood_rate_cap
  }
}
EOF
}

run_trial() {
    local cell=$1
    local trial=$2
    local recv_log="$OUTDIR/${cell}_trial${trial}_recv.log"
    local xmit_log="$OUTDIR/${cell}_trial${trial}_xmit.log"
    (timeout 120 "$REPO/build/pq-v2verifier" dsrc receiver nogui --test > "$recv_log" 2>&1) &
    local recv_pid=$!
    sleep 1
    timeout 120 "$REPO/build/pq-v2verifier" dsrc transmitter nogui --test > "$xmit_log" 2>&1
    wait "$recv_pid"
    local rc=$?
    echo "  [$cell trial $trial] recv exit=$rc"
}

run_cell() {
    local cell=$1 num_attackers=$2 attacker_mode=$3 filter_enabled=$4 flood_rate_cap=$5
    echo "=== Cell: $cell (attackers=$num_attackers mode=$attacker_mode filter=$filter_enabled flood_cap=$flood_rate_cap) ==="
    write_config "$num_attackers" "$attacker_mode" "$filter_enabled" "$flood_rate_cap"
    for t in $(seq 1 $N_TRIALS); do
        run_trial "$cell" "$t"
    done
}

# Condition A: no attack
run_cell "A_off" 0 "expensive_valid" false 0
run_cell "A_on"  0 "expensive_valid" true  0

# Condition B: expensive_valid flood - real signing cost paces it, no rate cap needed/applied
run_cell "B_off" 1 "expensive_valid" false 0
run_cell "B_on"  1 "expensive_valid" true  0

# Condition C: invalid_signature flood - real signing cost paces it, no rate cap needed/applied
run_cell "C_off" 1 "invalid_signature" false 0
run_cell "C_on"  1 "invalid_signature" true  0

# Condition D: cheap_invalid_signature - rate-capped at ~1010 msg/sec (context/UPDATES.md Update 21;
# see [AttackerFloodRateCap] in the transmitter log for the achieved rate each trial)
run_cell "D_off" 1 "cheap_invalid_signature" false 1010
run_cell "D_on"  1 "cheap_invalid_signature" true  1010

echo "ALL PILOT TRIALS COMPLETE"
