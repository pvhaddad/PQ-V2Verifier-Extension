#!/usr/bin/env python3
"""Pilot aggregator for the two new CHEAP_INVALID_SIGNATURE cells (D_off/D_on). Same
reconciliation discipline as phase4_aggregate.py: verify metrics-size invariant exactly for
every trial before including it, plus the new attacker outcome breakdown (Update 16) since
that's the whole point of this pilot.

N=75 scale-up (Update 20): also verifies, as a hard per-trial check (not just an averaged
stat), that D_on's RATE/NO_CACHE/BUFFER_CAP/BUFFER_TTL_EVICT_INCOMPLETE/pending split
matches the N=10 pilot's zero-variance finding (667/1332/0/0/1) on every single trial.
Any deviating trial is flagged individually and EXCLUDED from the average, not silently
folded in - it needs to be traced (raw log, [SpamFilterDiag]/[SpamFilter] sequence)
before being written up, same standard as Update 15's B_on/C_on anomaly tracing."""
import re
import statistics
import sys
from pathlib import Path

OUTDIR = Path(__file__).resolve().parents[2] / "phase4_raw_logs" / "phase4_pilot_trials"
N_TRIALS = 75

CELLS = {
    "D_off": (300, 2, 2000, 1),
    "D_on":  (300, 2, 2000, 1),
}

REASONS = ["RATE", "LENGTH", "NO_CACHE", "STALE", "FRAG_INDEX", "SEG_HASH",
           "BUFFER_CAP", "BUFFER_TTL_EVICT_INCOMPLETE"]
EXPECTED_D_ON = {"RATE": 667, "NO_CACHE": 1332, "BUFFER_CAP": 0, "BUFFER_TTL_EVICT_INCOMPLETE": 0,
                 "LENGTH": 0, "STALE": 0, "FRAG_INDEX": 0, "SEG_HASH": 0}
EXPECTED_D_ON_PENDING = 1

def read(fn):
    return open(fn, "r", encoding="utf-8", errors="replace").read()

def parse_summary(text):
    d = {}
    m = re.search(r"Legitimate messages processed: (\d+)", text)
    d["legit_total"] = int(m.group(1)) if m else None
    m = re.search(r"Attacker messages processed:\s+(\d+)", text)
    d["attacker_total"] = int(m.group(1)) if m else None
    m = re.search(r"Legitimate VALID: (\d+)/(\d+)", text)
    d["legit_valid"], d["legit_valid_denom"] = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    m = re.search(r"Legitimate drop rate, excluding startup: (\d+)/(\d+)", text)
    d["drop_num"], d["drop_denom"] = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    m = re.search(r"Legitimate deadline-miss ratio.*?: (\d+)/(\d+)", text)
    d["deadline_miss_num"], d["deadline_miss_denom"] = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    m = re.search(r"Attacker reached full crypto \(>=1 falcon_verify paid\): (\d+)/(\d+)", text)
    d["atk_full_crypto"] = int(m.group(1)) if m else None
    m = re.search(r"Attacker rejected cheaply \(SPAM_FILTERED, zero crypto\): (\d+)/(\d+)", text)
    d["atk_cheap_reject"] = int(m.group(1)) if m else None
    m = re.search(r"Attacker still pending \(NO_CERT_YET at run end\): (\d+)/(\d+)", text)
    d["atk_pending"] = int(m.group(1)) if m else None
    m = re.search(r"message avg=([\d.]+) p95=([\d.]+) \(n=(\d+)\) \| cert avg=([\d.]+) p95=([\d.]+) \(n=(\d+)\)", text)
    if m:
        d["cert_verify_n"] = int(m.group(6))
    d["incomplete_run"] = "INCOMPLETE RUN" in text
    m = re.search(r"Spam-filter drop reasons \(attacker senders\):\n((?:\s+\S+: \d+\n?)+)", text)
    d["atk_reasons"] = {}
    if m:
        block = m.group(1)
        for r in REASONS:
            rm = re.search(rf"{r}: (\d+)", block)
            d["atk_reasons"][r] = int(rm.group(1)) if rm else None
    return d

def main():
    all_ok = True
    results = {}
    for cell, (num_msgs, num_vehicles, num_attacker_msgs, num_attackers) in CELLS.items():
        expected_total = num_msgs * num_vehicles + num_attacker_msgs * num_attackers
        trials = []
        for t in range(1, N_TRIALS + 1):
            fn = OUTDIR / f"{cell}_trial{t}_recv.log"
            if not fn.exists():
                print(f"MISSING: {fn}"); all_ok = False; continue
            text = read(fn)
            d = parse_summary(text)
            d["trial"] = t
            actual_total = (d["legit_total"] or 0) + (d["attacker_total"] or 0)
            if d["incomplete_run"]:
                print(f"FAIL [{cell} trial {t}]: INCOMPLETE RUN"); all_ok = False; continue
            if actual_total != expected_total:
                print(f"FAIL [{cell} trial {t}]: mismatch actual={actual_total} expected={expected_total}")
                all_ok = False; continue
            # also verify the new 3-way attacker reconciliation
            atk_sum = (d["atk_full_crypto"] or 0) + (d["atk_cheap_reject"] or 0) + (d["atk_pending"] or 0)
            if atk_sum != d["attacker_total"]:
                print(f"FAIL [{cell} trial {t}]: attacker 3-way reconciliation mismatch "
                      f"({d['atk_full_crypto']}+{d['atk_cheap_reject']}+{d['atk_pending']}={atk_sum} != {d['attacker_total']})")
                all_ok = False; continue
            trials.append(d)
        results[cell] = trials
        print(f"[{cell}] {len(trials)}/{N_TRIALS} trials reconciled exactly (expected_total={expected_total}, "
              f"attacker 3-way check included)")

    # Hard zero-variance check for D_on's RATE/NO_CACHE/BUFFER_CAP/BUFFER_TTL_EVICT_INCOMPLETE
    # split, per trial - deviating trials are flagged and excluded from the average, not
    # silently folded in.
    if "D_on" in results:
        deviations = []
        clean_count = 0
        for t in results["D_on"]:
            mismatches = []
            for r, expected in EXPECTED_D_ON.items():
                actual = t["atk_reasons"].get(r)
                if actual != expected:
                    mismatches.append(f"{r}: expected {expected}, got {actual}")
            if t["atk_pending"] != EXPECTED_D_ON_PENDING:
                mismatches.append(f"pending: expected {EXPECTED_D_ON_PENDING}, got {t['atk_pending']}")
            if mismatches:
                deviations.append((t["trial"], mismatches))
            else:
                clean_count += 1
        print(f"\n[D_on zero-variance check] {clean_count}/{len(results['D_on'])} trials match "
              f"RATE=667/NO_CACHE=1332/BUFFER_CAP=0/BUFFER_TTL_EVICT_INCOMPLETE=0/pending=1 EXACTLY")
        if deviations:
            print(f"*** {len(deviations)} DEVIATING TRIAL(S) - DO NOT AVERAGE, TRACE INDIVIDUALLY ***")
            for trial_num, mismatches in deviations:
                print(f"  D_on trial {trial_num}: " + "; ".join(mismatches))
            all_ok = False

    print("\n" + "=" * 100)
    for cell, trials in results.items():
        if not trials:
            print(f"{cell}: NO VALID TRIALS"); continue
        valid_fracs = [t["legit_valid"] / t["legit_valid_denom"] for t in trials]
        drop_fracs = [t["drop_num"] / t["drop_denom"] if t["drop_denom"] else 0 for t in trials]
        dm_fracs = [t["deadline_miss_num"] / t["deadline_miss_denom"] for t in trials]
        atk_full = [t["atk_full_crypto"] for t in trials]
        atk_cheap = [t["atk_cheap_reject"] for t in trials]
        atk_pend = [t["atk_pending"] for t in trials]
        cert_ns = [t.get("cert_verify_n", 0) for t in trials]

        def stat(xs):
            xs = [x for x in xs if x == x]
            if len(xs) <= 1: return f"{xs[0] if xs else 'n/a'}"
            return f"avg={statistics.mean(xs):.4g} min={min(xs)} max={max(xs)}"

        print(f"\n--- {cell} (n_trials={len(trials)}) ---")
        print(f"  legit VALID frac:      {stat(valid_fracs)}")
        print(f"  legit drop frac:       {stat(drop_fracs)}")
        print(f"  deadline-miss frac:    {stat(dm_fracs)}")
        print(f"  attacker full_crypto:  {stat(atk_full)} / 2000")
        print(f"  attacker cheap_reject: {stat(atk_cheap)} / 2000")
        print(f"  attacker pending:      {stat(atk_pend)} / 2000")
        print(f"  cert-sig verify n:     {stat(cert_ns)}")

    print("\n" + "=" * 100)
    print("ALL RECONCILED EXACTLY" if all_ok else "*** SOME TRIALS FAILED RECONCILIATION ***")
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
