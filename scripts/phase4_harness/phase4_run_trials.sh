#!/bin/bash
# Phase 4 trial runner. Runs N trials for each (condition x filter_state) cell,
# same attacker/harness/metrics as Phase 2/Checkpoint 5, --test mode only (the only
# correctly-wired multi-vehicle invocation path, per context/UPDATES.md Update 2).
set -euo pipefail
source "$(dirname "$0")/require_rcvbuf.sh"

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRATCH="${SCRATCH:-$REPO/phase4_raw_logs}"
OUTDIR="$SCRATCH/phase4_trials"
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

# Condition A: no attack
run_cell "A_off" 0 "expensive_valid" 0 false
run_cell "A_on"  0 "expensive_valid" 0 true

# Condition B: expensive_valid flood
run_cell "B_off" 1 "expensive_valid" 2000 false
run_cell "B_on"  1 "expensive_valid" 2000 true

# Condition C: invalid_signature flood
run_cell "C_off" 1 "invalid_signature" 2000 false
run_cell "C_on"  1 "invalid_signature" 2000 true

echo "ALL TRIALS COMPLETE"
