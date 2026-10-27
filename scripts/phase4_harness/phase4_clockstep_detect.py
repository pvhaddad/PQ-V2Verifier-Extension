#!/usr/bin/env python3
"""Journal-based detection of wall-clock steps (CORRECTIONS.md #21 / BUGS.md).

The receiver measures latency, and the spam filter its STALE test, as `system_clock now - embedded
system_clock send time`. A forward step of CLOCK_REALTIME while a message is in flight therefore makes it
look 0.4-0.75 s old (spurious [DeadlineMiss] lines and spurious STALE drops). systemd-resolved logs
"Clock change detected" on every step, and every journal entry carries both a realtime and a monotonic
timestamp, so the size of each step is the jump in (realtime - monotonic) between consecutive entries.
No sudo needed (the user is in `adm`).

As a library: fetch_steps(), steps_in_window(), cluster_latencies(), explain_event().
As a CLI: per-trial step exposure for a sweep (`--trial-times`) or for an older log directory
(`--logdir`, windows from the transmitter logs' mtimes). Read-only."""
import argparse
import csv
import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# messaging window inside one trial, relative to the receiver start t0 that the driver logs: the transmitter
# starts ~1 s later and the legit vehicles send for ~30.2 s
WIN_START_OFFSET, WIN_END_OFFSET = 1.3, 31.6
STEP_MATCH_TOL_MS = 25.0   # observed |jump - latency| was 0-2 ms in all 17 events; generous margin


def _entries_from_lines(lines):
    out = []
    for line in lines:
        try:
            j = json.loads(line)
        except Exception:
            continue
        m = j.get("MESSAGE")
        if not isinstance(m, str) or "Clock change detected" not in m:
            continue
        out.append({"rt": int(j["__REALTIME_TIMESTAMP"]) / 1e6, "mono": int(j["__MONOTONIC_TIMESTAMP"]) / 1e6,
                    "boot": j.get("_BOOT_ID", "")})
    return out


def fetch_steps(since, until, journal_json=None):
    """Return (steps, error). Each step: rt (post-step clock), mono, jump_ms (realtime-monotonic offset change vs
    the previous entry of the same boot), interval_s. Looks 5 min before `since` so the first step has a predecessor."""
    if journal_json:
        entries = _entries_from_lines(open(journal_json, errors="replace"))
    else:
        cmd = ["journalctl", "--no-pager", "-o", "json", "--since", f"@{int(since - 300)}", "--until", f"@{int(until + 15)}"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except Exception as e:  # journalctl missing / timed out
            return [], f"journalctl failed: {e!r}"
        if p.returncode != 0 and not p.stdout:
            return [], f"journalctl rc={p.returncode}: {p.stderr.strip()[:120]}"
        entries = _entries_from_lines(p.stdout.splitlines())
    entries.sort(key=lambda e: (e["boot"], e["mono"]))
    steps = []
    for i in range(1, len(entries)):
        a, b = entries[i - 1], entries[i]
        if a["boot"] != b["boot"]:
            continue
        steps.append({"rt": b["rt"], "mono": b["mono"], "boot": b["boot"],
                      "jump_ms": ((b["rt"] - b["mono"]) - (a["rt"] - a["mono"])) * 1000.0, "interval_s": b["mono"] - a["mono"]})
    steps.sort(key=lambda s: s["rt"])
    return steps, None


def steps_in_window(steps, a, b):
    return [s for s in steps if a <= s["rt"] <= b]


def cluster_latencies(recv_text, legit_max=None):
    """Mean latency (ms) of each cluster of [DeadlineMiss] lines, clusters split at >20 ms gaps. `legit_max` = numVehicles:
    only LEGIT senders (vehicle id < legit_max) count, because late *attacker* messages are common and unrelated to
    clock steps (the event under test is a late/dropped legit message)."""
    lat = sorted(float(m.group(2)) for m in re.finditer(r"\[DeadlineMiss\] vehicle=(\d+) outcome=\d+ latency_ms=([\d.]+)", recv_text)
                 if legit_max is None or int(m.group(1)) < legit_max)
    clusters, cur = [], []
    for x in lat:
        if cur and x - cur[-1] > 20.0:
            clusters.append(cur); cur = []
        cur.append(x)
    if cur:
        clusters.append(cur)
    return [sum(c) / len(c) for c in clusters]


def explain_event(cluster_lats, window_steps):
    """Classify a trial that had late/dropped legit messages.
    YES: every latency cluster matches a step in the window within STEP_MATCH_TOL_MS;
    STEP_SIZE_MISMATCH: steps in the window but some cluster matches none; NO_STEP_IN_WINDOW: no step at all."""
    if not window_steps:
        return "NO_STEP_IN_WINDOW"
    if not cluster_lats:
        return "STEP_SIZE_MISMATCH"   # events recorded (drops) but no [DeadlineMiss] latency to compare
    ok = all(any(abs(s["jump_ms"] - lat) <= STEP_MATCH_TOL_MS for s in window_steps) for lat in cluster_lats)
    return "YES" if ok else "STEP_SIZE_MISMATCH"


def load_trial_times(tsv):
    """{(level, phase, cell, trial): (t0, t1)}; a re-run of a trial (resume) replaces the earlier row."""
    d = {}
    for r in csv.reader(open(tsv), delimiter="\t"):
        if len(r) == 6:
            d[(int(r[0]), r[1], r[2], int(r[3]))] = (float(r[4]), float(r[5]))
    return d


def window_for(t0):
    return t0 + WIN_START_OFFSET, t0 + WIN_END_OFFSET


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trial-times", help="the sweep's trial_times.tsv (level phase cell trial t0 t1)")
    ap.add_argument("--phase", default="full")
    ap.add_argument("--logdir", help="older dataset: windows from the *_xmit.log mtimes (end - 31.0 s .. end - 0.4 s)")
    ap.add_argument("--journal-json", help="use a saved `journalctl -o json` dump instead of calling journalctl (tests/reanalysis)")
    ap.add_argument("--csv", help="write one row per trial")
    args = ap.parse_args()

    wins = []   # (label, level, a, b)
    if args.trial_times:
        for (L, phase, cell, t), (t0, t1) in sorted(load_trial_times(args.trial_times).items()):
            if phase == args.phase:
                a, b = window_for(t0); wins.append((f"{cell}#{t}", L, a, b))
    if args.logdir:
        for f in sorted(glob.glob(os.path.join(args.logdir, "*_xmit.log"))):
            e = os.path.getmtime(f); wins.append((os.path.basename(f).replace("_xmit.log", ""), 0, e - 31.0, e - 0.4))
    if not wins:
        sys.exit("no trial windows (give --trial-times and/or --logdir)")
    steps, err = fetch_steps(min(w[2] for w in wins), max(w[3] for w in wins), args.journal_json)
    if err:
        sys.exit(f"clock-step detection unavailable: {err}")
    print(f"{len(steps)} 'Clock change detected' steps in the range; {len(wins)} trial windows")
    by = {}
    rows = []
    for label, L, a, b in wins:
        ws = steps_in_window(steps, a, b)
        by.setdefault(L, []).append(len(ws))
        rows.append({"trial": label, "level": L, "steps_in_window": len(ws), "max_jump_ms": f"{max((s['jump_ms'] for s in ws), default=0):.0f}"})
    for L, ks in sorted(by.items()):
        print(f"  level {L or '(logdir)'}: trials={len(ks)} exposed(>=1 step)={sum(1 for k in ks if k)} ({100*sum(1 for k in ks if k)/len(ks):.0f}%) steps in windows={sum(ks)}")
    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n"); w.writeheader(); w.writerows(rows)


if __name__ == "__main__":
    main()
