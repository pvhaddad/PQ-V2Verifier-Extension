#!/usr/bin/env python3
"""
Phase 4 trial aggregator (scratchpad-only, not part of the shipped codebase - same
category as compare_falcon_logs.py). Parses each trial's receive-log summary block,
verifies the metrics-size invariant EXACTLY for every single trial (not spot-checked -
per the standard set in context/UPDATES.md Update 12/13, a passing aggregate must not paper over
one bad trial), then reports min/avg/max/stddev per cell. Raises loudly on any trial
that doesn't reconcile rather than silently including it in the aggregate.
"""
import re
import statistics
import sys
from pathlib import Path

OUTDIR = Path(__file__).resolve().parents[2] / "phase4_raw_logs" / "phase4_trials"
N_TRIALS = 75

# cell -> (num_messages, num_vehicles, num_attacker_msgs, num_attackers)
CELLS = {
    "A_off": (300, 2, 0, 0),
    "A_on":  (300, 2, 0, 0),
    "B_off": (300, 2, 2000, 1),
    "B_on":  (300, 2, 2000, 1),
    "C_off": (300, 2, 2000, 1),
    "C_on":  (300, 2, 2000, 1),
}

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
    m = re.search(r"Legitimate NO_CERT_YET.*?: (\d+)", text)
    d["no_cert_yet"] = int(m.group(1)) if m else None
    m = re.search(r"Legitimate drop rate, excluding startup: (\d+)/(\d+)", text)
    d["drop_num"], d["drop_denom"] = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    m = re.search(r"Legitimate deadline-miss ratio.*?: (\d+)/(\d+)", text)
    d["deadline_miss_num"], d["deadline_miss_denom"] = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    m = re.search(r"Legitimate VALID-message latency \(ms\): p50=([\d.]+) p95=([\d.]+) p99=([\d.]+) max=([\d.]+)", text)
    if m:
        d["lat_p50"], d["lat_p95"], d["lat_p99"], d["lat_max"] = map(float, m.groups())
    m = re.search(r"message avg=([\d.]+) p95=([\d.]+) \(n=(\d+)\) \| cert avg=([\d.]+) p95=([\d.]+) \(n=(\d+)\)", text)
    if m:
        d["msg_verify_avg"], d["msg_verify_p95"], d["msg_verify_n"] = float(m.group(1)), float(m.group(2)), int(m.group(3))
        d["cert_verify_avg"], d["cert_verify_p95"], d["cert_verify_n"] = float(m.group(4)), float(m.group(5)), int(m.group(6))
    m = re.search(r"Legitimate SPAM_FILTERED.*?: (\d+)", text)
    d["spam_filtered"] = int(m.group(1)) if m else None
    d["incomplete_run"] = "INCOMPLETE RUN" in text
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
                print(f"MISSING: {fn}")
                all_ok = False
                continue
            text = read(fn)
            d = parse_summary(text)
            actual_total = (d["legit_total"] or 0) + (d["attacker_total"] or 0)
            if d["incomplete_run"]:
                print(f"FAIL [{cell} trial {t}]: INCOMPLETE RUN printed")
                all_ok = False
                continue
            if actual_total != expected_total:
                print(f"FAIL [{cell} trial {t}]: metrics-size mismatch - "
                      f"actual(legit={d['legit_total']}+attacker={d['attacker_total']}={actual_total}) "
                      f"!= expected({expected_total})")
                all_ok = False
                continue
            d["trial"] = t
            d["expected_total"] = expected_total
            trials.append(d)
        results[cell] = trials
        print(f"[{cell}] {len(trials)}/{N_TRIALS} trials reconciled exactly (expected_total={expected_total})")

    print()
    print("=" * 100)
    for cell, trials in results.items():
        if not trials:
            print(f"{cell}: NO VALID TRIALS")
            continue
        valid_fracs = [t["legit_valid"] / t["legit_valid_denom"] for t in trials]
        drop_fracs = [t["drop_num"] / t["drop_denom"] if t["drop_denom"] else 0 for t in trials]
        dm_fracs = [t["deadline_miss_num"] / t["deadline_miss_denom"] for t in trials]
        p95_lats = [t.get("lat_p95", float("nan")) for t in trials]
        msg_ns = [t.get("msg_verify_n", 0) for t in trials]
        cert_ns = [t.get("cert_verify_n", 0) for t in trials]

        def stat(xs):
            xs = [x for x in xs if x == x]  # drop NaN
            if not xs:
                return "n/a"
            if len(xs) == 1:
                return f"{xs[0]:.4g} (n=1)"
            return f"avg={statistics.mean(xs):.4g} min={min(xs):.4g} max={max(xs):.4g} stddev={statistics.stdev(xs):.4g}"

        print(f"\n--- {cell} (n_trials={len(trials)}) ---")
        print(f"  legit VALID frac:      {stat(valid_fracs)}")
        print(f"  legit drop frac:       {stat(drop_fracs)}")
        print(f"  deadline-miss frac:    {stat(dm_fracs)}")
        print(f"  VALID latency p95(ms): {stat(p95_lats)}")
        print(f"  message-sig verify n:  {stat(msg_ns)}")
        print(f"  cert-sig verify n:     {stat(cert_ns)}")

    print("\n" + "=" * 100)
    print("ALL RECONCILED EXACTLY" if all_ok else "*** SOME TRIALS FAILED RECONCILIATION - SEE ABOVE ***")
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
