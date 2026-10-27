#!/bin/bash
# Pilot for the two new CHEAP_INVALID_SIGNATURE cells (context/UPDATES.md Update 17). Small N, new
# cells only - deliberately a SEPARATE script from phase4_run_trials.sh (not an extension of
# it in place) so there is zero risk of accidentally re-triggering the locked N=75 A/B/C
# matrix (Update 15) mid-pilot. write_config()/run_trial() bodies are copied verbatim from
# phase4_run_trials.sh, same shape, same reconciliation convention.
set -euo pipefail
source "$(dirname "$0")/require_rcvbuf.sh"

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRATCH="${SCRATCH:-$REPO/phase4_raw_logs}"
OUTDIR="$SCRATCH/phase4_pilot_trials"
mkdir -p "$OUTDIR"

N_TRIALS=75

write_config() {
    local num_attackers=$1
    local attacker_mode=$2
    local num_attacker_msgs=$3
    local filter_enabled=$4
    cat > "$REPO/config.json" << EOF
{
  "scenario": {
    "numVehicles":2,
    "numMessages":300,
    "signatureScheme":"falcon",
    "numAttackers":$num_attackers,
    "attackerMode":"$attacker_mode",
    "numAttackerMessages":$num_attacker_msgs,
    "certCycleHashOnlyCount":4,
    "spamFilterEnabled":$filter_enabled,
    "spamFilterMinGapMs":50,
    "spamFilterAdmitMs":100,
    "bufferTtlMs":500,
    "spamFilterGlobalStateCap":512
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
    local cell=$1 num_attackers=$2 attacker_mode=$3 num_attacker_msgs=$4 filter_enabled=$5
    echo "=== Cell: $cell (attackers=$num_attackers mode=$attacker_mode msgs=$num_attacker_msgs filter=$filter_enabled) ==="
    write_config "$num_attackers" "$attacker_mode" "$num_attacker_msgs" "$filter_enabled"
    for t in $(seq 1 $N_TRIALS); do
        run_trial "$cell" "$t"
    done
}

# New cells only - mirrors B_off/B_on's shape (numAttackers:1, numAttackerMessages:2000)
run_cell "D_off" 1 "cheap_invalid_signature" 2000 false
run_cell "D_on"  1 "cheap_invalid_signature" 2000 true

echo "ALL PILOT TRIALS COMPLETE"
