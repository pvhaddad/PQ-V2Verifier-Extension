#!/usr/bin/env python3
"""Resource-contention analysis for the vehicle-count scaling sweep.

Joins resource_usage.log (epoch + /proc/loadavg + free -m every ~15s) with trial_times.tsv
(level, phase, cell, trial, start_epoch, end_epoch) and reports, per vehicle-count level:
load average and memory while trials were running, whether load climbs with vehicle count, and
whether trials that deviated (drops, deadline misses, hard failures, UNPARSED) coincided with
higher load than clean trials. Read-only."""
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "phase4_raw_logs/phase4_vehicle_scaling_sweep")


def parse_samples(path):
    samples, block = [], []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.strip() == "---":
            if len(block) >= 3:
                try:
                    epoch = int(block[0].strip())
                    load1 = float(block[1].split()[0])
                    mem_used = next(int(l.split()[2]) for l in block if l.startswith("Mem:"))
                    swap_used = next(int(l.split()[2]) for l in block if l.startswith("Swap:"))
                    samples.append((epoch, load1, mem_used, swap_used))
                except (ValueError, StopIteration, IndexError):
                    pass
            block = []
        else:
            block.append(line)
    return samples


def main():
    samples = parse_samples(ROOT / "resource_usage.log")
    trials = []
    with open(ROOT / "trial_times.tsv") as fh:
        for row in csv.reader(fh, delimiter="\t"):
            L, phase, cell, t, t0, t1 = row
            trials.append((int(L), phase, cell, int(t), float(t0), float(t1)))
    print(f"resource samples: {len(samples)}   trials timed: {len(trials)}")
    if not samples or not trials:
        print("nothing to analyze")
        return
    env = ROOT / "environment.txt"
    if env.exists():
        print(env.read_text().strip(), "\n")

    def within(t0, t1):
        return [s for s in samples if t0 - 1 <= s[0] <= t1 + 1]

    in_trial = set()
    per_level = defaultdict(list)
    trial_max_load = {}
    for L, phase, cell, t, t0, t1 in trials:
        ws = within(t0, t1)
        for s in ws:
            in_trial.add(s[0])
            per_level[L].append(s)
        if ws:
            trial_max_load[(L, phase, cell, t)] = max(s[1] for s in ws)
    idle = [s for s in samples if s[0] not in in_trial]
    if idle:
        print(f"between-trial/idle samples: n={len(idle)} mean load1={statistics.mean(s[1] for s in idle):.2f}")
    print(f"\n{'L':>3s} {'samples':>8s} {'load1 mean':>11s} {'load1 p95':>10s} {'load1 max':>10s} {'mem used MB max':>16s} {'swap used MB max':>17s}")
    means = {}
    for L in sorted(per_level):
        ss = per_level[L]
        loads = sorted(s[1] for s in ss)
        p95 = loads[min(len(loads) - 1, int(0.95 * len(loads)))]
        means[L] = statistics.mean(loads)
        print(f"{L:>3d} {len(ss):>8d} {means[L]:>11.2f} {p95:>10.2f} {loads[-1]:>10.2f} {max(s[2] for s in ss):>16d} {max(s[3] for s in ss):>17d}")
    lv = sorted(means)
    if len(lv) >= 2:
        delta = means[lv[-1]] - means[lv[0]]
        mono = all(means[a] <= means[b] for a, b in zip(lv, lv[1:]))
        print(f"\nmean load1 {lv[0]} -> {lv[-1]} legit vehicles: {means[lv[0]]:.2f} -> {means[lv[-1]]:.2f} (delta {delta:+.2f}); "
              f"monotonic increase across levels: {mono}")
        print("interpretation guide: this box has 28 cores, so load1 near 1-2 is idle-ish; a rise that stays far below 28 "
              "is not contention, a rise toward 28 would be.")

    # deviating vs clean trials (needs the per-level per_trial.csv the driver writes at level end)
    dev, clean = [], []
    for L in lv:
        f = ROOT / "reanalysis" / f"n{L}_full_per_trial.csv"      # corrected-parser reanalysis, if present
        if not f.exists():
            f = ROOT / f"n{L}" / "full" / "per_trial.csv"          # otherwise the driver's as-run file
        if not f.exists():
            continue
        for r in csv.DictReader(open(f, newline="")):
            key = (L, "full", r["cell"], int(r["trial"]))
            if key not in trial_max_load:
                continue
            deviating = (r["trial_status"] != "OK" or r["legit_drop_count"] not in ("0", "NA")
                         or r["deadline_miss_count"] not in ("0", "NA") or r["stop_reason"] == "UNPARSED")
            (dev if deviating else clean).append((key, trial_max_load[key]))
    if dev or clean:
        print(f"\nfull-run trials: clean={len(clean)} deviating/flagged={len(dev)}")
        if clean:
            print(f"  max load1 during clean trials:     mean {statistics.mean(v for _, v in clean):.2f}")
        if dev:
            print(f"  max load1 during deviating trials: mean {statistics.mean(v for _, v in dev):.2f}")
            for (L, phase, cell, t), v in sorted(dev, key=lambda kv: -kv[1])[:15]:
                print(f"    L={L} {cell} trial {t}: max load1 {v:.2f}")
        if dev and clean:
            gap = statistics.mean(v for _, v in dev) - statistics.mean(v for _, v in clean)
            print(f"  difference (deviating - clean): {gap:+.2f}  (a gap near 0 = no sign that deviations coincide with load spikes)")


if __name__ == "__main__":
    main()
