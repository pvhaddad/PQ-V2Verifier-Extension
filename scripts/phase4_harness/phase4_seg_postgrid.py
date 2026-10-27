#!/usr/bin/env python3
"""Post-grid merge for the segmentation study (Update 23): one set of analysis files across every L and mode.

Scans --grid-root for run directories named L<L>_msgs<N>[_verifyonce] (as written by phase4_mn_sweep.sh /
phase4_seg_grid.sh) and writes to --out-dir:
  seg_grid_summary.csv          one row per (L, mode, m, n, cell): every phase4_mn_sweep_aggregate.py summary column
                                plus L, run_dir, msgs_per_vehicle (cert_verify_mode is already a column)
  seg_grid_messages.csv.gz      one row per received message, all runs/trials, with derived timing columns
  seg_grid_pooled_cert_verify.csv  cert_verify_ns and t2-t0 pooled per mode, over all L and per L
  seg_grid_ab_check.csv         every-vs-once check for every (L, m, n, cell) present in both modes
  data_dictionary.md            every column of the four files above, with units
Summary statistics reuse phase4_mn_sweep_aggregate.py (same exclusions: legit senders only, wall_clock_step=1
trials excluded from timing stats, send->t3 skipped when a sender's row counts don't match). The per-message file
keeps every row, including clock-step trials (wall_clock_step column) so they can be filtered either way.
Read-only on the raw logs."""
import argparse
import csv
import gzip
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phase4_mn_sweep_aggregate as agg  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
RUN_RE = re.compile(r"^L(\d+)_msgs(\d+)(_verifyonce)?$")
TRIAL_RE = re.compile(r"^(\w+?)_trial(\d+)_msgtiming\.csv(?:\.gz)?$")
RECV_RE = re.compile(r"^(\w+?)_trial(\d+)_recv\.log(?:\.gz)?$")

MESSAGE_FIELDS = [
    "L", "cert_verify_mode", "m", "n", "tau", "cell", "trial", "wall_clock_step", "sender_id", "seq", "phase",
    "kind", "outcome", "cert_path", "t0_ns", "t1_ns", "t2_ns", "t3_ns", "cert_verify_ns", "msg_verify_ns",
    "t1_t0_ns", "t2_t0_ns", "t3_t0_ns", "overhead_ns", "send_ns", "send_t3_ns", "sendjoin_ok",
]


def find_runs(grid_root):
    runs = []
    for p in sorted(Path(grid_root).iterdir()):
        mo = RUN_RE.match(p.name)
        if p.is_dir() and mo:
            runs.append({"dir": p, "L": int(mo.group(1)), "msgs": int(mo.group(2)),
                         "mode": "once" if mo.group(3) else "every"})
    return sorted(runs, key=lambda r: (r["mode"], r["L"], r["msgs"]))


def summarize_run(run, cells, n_trials, pooled):
    agg.MSGS_PER_VEHICLE = run["msgs"]
    agg.ALL_CELLS = cells
    rows, _, _ = agg.load_run(run["dir"], run["L"], 500, n_trials, pooled)
    for r in rows:
        r["L"], r["run_dir"], r["msgs_per_vehicle"] = run["L"], run["dir"].name, run["msgs"]
    return rows


def write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("NA" if r.get(k) is None else agg.fmt(r[k], 6) if isinstance(r[k], float) else r[k])
                        for k in fields})


def write_messages(runs, cells, path):
    """Stream every per-message row of every trial into one gzipped CSV. Returns (rows, trials, trials_without_timing)."""
    n_rows = n_trials = n_missing = 0
    na = lambda v: None if v in ("NA", "", None) else int(v)
    with gzip.open(path, "wt", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MESSAGE_FIELDS, lineterminator="\n")
        w.writeheader()
        for run in runs:
            for combo in sorted(p for p in run["dir"].iterdir() if p.is_dir() and agg.COMBO_RE.match(p.name)):
                m, n = map(int, agg.COMBO_RE.match(combo.name).groups())
                trials = sorted({(mo.group(1), int(mo.group(2))) for f in combo.iterdir()
                                 if (mo := TRIAL_RE.match(f.name)) and mo.group(1) in cells})
                with_recv = {(mo.group(1), int(mo.group(2))) for f in combo.iterdir()
                             if (mo := RECV_RE.match(f.name)) and mo.group(1) in cells}
                n_missing += len(with_recv - set(trials))
                for cell, t in trials:
                    base = combo / f"{cell}_trial{t}"
                    rows = agg.read_csv_maybe_gz(f"{base}_msgtiming.csv")
                    sends = agg.read_csv_maybe_gz(f"{base}_sendtimes.csv")
                    recv = agg.read_log(Path(f"{base}_recv.log")) or ""
                    step = re.search(r"^wall_clock_step=(\d)$", recv, re.M)
                    ref = re.search(r"^receiver_steady_ref_ns=(\d+)$", recv, re.M)
                    mode = agg.recv_cert_verify_mode(recv)
                    join = None
                    if sends is not None and ref is not None:
                        rx = Counter(r["sender_id"] for r in rows)
                        tx = Counter(r["sender_id"] for r in sends)
                        if all(rx[s] == tx.get(s, -1) for s in rx if int(s) < run["L"]):
                            join = {(r["sender_id"], r["seq"]): int(r["send_ns"]) for r in sends}
                    n_trials += 1
                    for r in rows:
                        t0, t1, t2, t3 = (na(r[k]) for k in ("t0_ns", "t1_ns", "t2_ns", "t3_ns"))
                        cv, mv = na(r["cert_verify_ns"]), na(r["msg_verify_ns"])
                        send = join.get((r["sender_id"], r["seq"])) if join is not None else None
                        out = {
                            "L": run["L"], "cert_verify_mode": mode, "m": m, "n": n, "tau": m + n, "cell": cell,
                            "trial": t, "wall_clock_step": step.group(1) if step else None,
                            "sender_id": r["sender_id"], "seq": r["seq"],
                            "phase": "first" if int(r["seq"]) < m + n else "steady",
                            "kind": r["kind"], "outcome": r["outcome"], "cert_path": r.get("cert_path", "NA"),
                            "t0_ns": t0, "t1_ns": t1, "t2_ns": t2, "t3_ns": t3, "cert_verify_ns": cv, "msg_verify_ns": mv,
                            "t1_t0_ns": t1 - t0 if t1 is not None else None,
                            "t2_t0_ns": t2 - t0 if t2 is not None else None,
                            "t3_t0_ns": t3 - t0 if t3 is not None else None,
                            "overhead_ns": (t3 - t0) - (cv or 0) - mv if t3 is not None and mv is not None else None,
                            "send_ns": send,
                            "send_t3_ns": int(ref.group(1)) + t3 - send if send is not None and t3 is not None else None,
                            "sendjoin_ok": 1 if join is not None else 0,
                        }
                        w.writerow({k: ("NA" if v is None else v) for k, v in out.items()})
                        n_rows += 1
    return n_rows, n_trials, n_missing


def pooled_rows(pooled_all, pooled_by_L):
    rows = []
    for scope, L, pooled in [("all_L", "all", pooled_all)] + [("per_L", L, p) for L, p in sorted(pooled_by_L.items())]:
        for mode in sorted(pooled):
            for metric in agg.POOLED_ONLY_IN_ONCE:
                xs = pooled[mode][metric]
                rows.append({"scope": scope, "L": L, "cert_verify_mode": mode, "metric": metric, "n": len(xs),
                             **agg.stats(xs)})
    return rows


# ---- data dictionary ----
STAT_WORDS = {"mean": "mean", "median": "median", "p95": "95th percentile (nearest rank)",
              "p99": "99th percentile (nearest rank)", "max": "maximum"}
SPLIT_WORDS = {"all": "all rows", "SEGMENT": "segment-carrying messages only", "HASH_ONLY": "hash-only messages only",
               "first": "first cycle (seq < m+n) only", "steady": "steady state (seq >= m+n) only",
               "VERIFIED_NOW": "rows whose cert was falcon_verify'd on this message",
               "CACHED": "rows whose cert verify was skipped (verify-once mode)"}
METRIC_WORDS = {
    "cert_verify_ns": "cert falcon_verify call duration (PRIMARY; VERIFIED_NOW rows only)",
    "msg_verify_ns": "message falcon_verify call duration (PRIMARY)",
    "t1_t0_ns": "t1 - t0: frame received -> cert reassembled + digest matched (completing segment only)",
    "t2_t0_ns": "t2 - t0: frame received -> cert verify done (VERIFIED_NOW rows only)",
    "t3_t0_ns": "t3 - t0: frame received -> message verify + outcome done (end-to-end incl. testbed overhead)",
    "overhead_ns": "(t3 - t0) - cert_verify_ns - msg_verify_ns (NA cert counted as 0): non-crypto receive-path time",
    "send_t3_ns": "send_ns -> t3: sender's sendto() -> message verify done (incl. socket queueing)",
}
SUMMARY_FIXED = {
    "L": ("count", "legitimate vehicles (numVehicles)"),
    "run_dir": ("-", "raw-log run directory under the grid root"),
    "msgs_per_vehicle": ("messages", "numMessages per legitimate vehicle"),
    "combo": ("-", "mM_nN tag"), "m": ("count", "segments per cert (certCycleSegmentCount)"),
    "n": ("count", "hash-only messages per cycle (certCycleHashOnlyCount)"), "cell": ("-", "benchmark cell (A_off here)"),
    "tau": ("messages", "cycle length m + n"), "refresh_ms": ("ms", "cycle period tau x 100 ms"),
    "buffer_ttl_ms": ("ms", "bufferTtlMs (filter-on only; unused under A_off)"),
    "ttl_headroom_ms": ("ms", "bufferTtlMs - (m-1) x 100 (filter-on only)"),
    "n_trials": ("count", "trials found for this combo x cell"),
    "gate_hard_failures": ("count", "hard failures in the combo's gate (summary.csv)"),
    "predicted_legit_valid": ("messages", "predicted VALID per trial = L(numMessages+1-m)"),
    "modal_legit_valid": ("messages", "most common VALID count across trials"),
    "valid_minus_pred": ("messages", "modal VALID - predicted"),
    "trials_valid_ne_pred": ("count", "trials whose VALID != predicted"),
    "predicted_no_cert_yet": ("messages", "predicted NO_CERT_YET per trial = L(m-1)"),
    "modal_no_cert_yet": ("messages", "most common NO_CERT_YET count"),
    "no_cert_yet_minus_pred": ("messages", "modal NO_CERT_YET - predicted"),
    "trials_no_cert_yet_ne_pred": ("count", "trials whose NO_CERT_YET != predicted"),
    "deviation_label": ("-", "empty, or why the counts deviated (ANOMALY / REDUCED_TTL_MARGIN / TTL_EXCEEDED)"),
    "legit_valid_frac_mean": ("fraction", "mean over trials of VALID / legit messages"),
    "legit_drop_frac_mean": ("fraction", "mean legit drop rate excluding startup NO_CERT_YET"),
    "deadline_miss_frac_mean": ("fraction", "mean fraction of legit messages with system-clock latency > 100 ms"),
    "legit_latency_p99_ms_mean": ("ms", "mean over trials of the receiver's p99 VALID latency (system clock, send -> verify)"),
    "cert_verify_n_mean": ("count", "mean cert falcon_verify calls per trial (receiver summary)"),
    "attacker_total_mean": ("messages", "mean attacker messages per trial (0 under A_off)"),
    "attacker_full_crypto_frac_mean": ("fraction", "attacker messages that reached falcon_verify (NA under A_off)"),
    "attacker_cheap_reject_frac_mean": ("fraction", "attacker messages rejected by a cheap check (NA under A_off)"),
    "legit_total_values": ("messages", "distinct legit totals seen (';'-joined)"),
    "seg_bytes_mean": ("bytes", "mean on-wire size of a segment-carrying frame"),
    "hash_only_bytes": ("bytes", "on-wire size of a hash-only frame (NA when n=0)"),
    "hash_only_nonmodal_lines": ("count", "hash-only TX lines with a non-modal size (stdout garbling)"),
    "seg_garbled_lines": ("count", "segment TX lines excluded as garbled"),
    "mean_wire_bytes_per_msg": ("bytes", "mean on-wire bytes per message for the exact message mix"),
    "predicted_steady_wire_bytes_per_msg": ("bytes", "(m x seg_bytes + n x hash_only_bytes) / tau"),
    "cert_verify_mode": ("-", "every | once (receiver summary line; 'every' for pre-Update-23 logs)"),
    "clock_step_trials": ("count", "trials whose receiver flagged wall_clock_step=1 (soft warning; all trials, timed or not)"),
    "clock_step_trials_valid_ne_pred": ("count", "of those, trials whose VALID count is off the prediction (soft warning, never a failure)"),
    "timing_trials": ("count", "trials that have per-message timing files"),
    "wall_clock_step_trials": ("count", "timing trials flagged wall_clock_step=1 (excluded from timing stats)"),
    "sendjoin_skipped_trials": ("count", "used trials where send->t3 was skipped (row-count mismatch or no sendtimes)"),
    "verified_now_rows": ("rows", "rows whose cert was verified on that message (once mode: L per trial)"),
    "cert_verify_count_expected": ("count", "expected cert verifications per trial (once: L; every: predicted VALID; A_off only)"),
    "cert_verify_count_check": ("-", "PASS / FAIL / NA: every trial's cert verify count == expected"),
    "frac_t3_t0_gt_100ms": ("fraction", "rows with t3 - t0 > 100 ms"),
    "frac_send_t3_gt_100ms": ("fraction", "joined rows with send -> t3 > 100 ms"),
    "ttfv_ms_mean": ("ms", "mean time-to-first-verified per sender (first t0 -> first VALID t3)"),
    "ttfv_ms_min": ("ms", "minimum ttfv across senders and trials"),
    "ttfv_ms_max": ("ms", "maximum ttfv across senders and trials"),
    "ttfv_unverifiable_check": ("-", "PASS if every sender had exactly m-1 unverifiable messages before its first VALID"),
    "msg_verify_ns_median": ("ns", "median msg_verify_ns over all used rows - drift check, should not depend on m or n"),
}
DROP_WORDS = ("count", "total over trials of spam-filter drops for this reason (filter-on only; 0 under A_off)")


def describe_summary(col):
    if col in SUMMARY_FIXED:
        return SUMMARY_FIXED[col]
    mo = re.match(r"^(legit|attacker)_drop_(\w+)$", col)
    if mo:
        return DROP_WORDS[0], f"{mo.group(1)} {mo.group(2)} drops: " + DROP_WORDS[1]
    for metric, words in METRIC_WORDS.items():
        if col.startswith(metric + "_"):
            split, stat = col[len(metric) + 1:].rsplit("_", 1)
            once_note = " (NA in once mode for this metric: see the pooled file)" if metric in agg.POOLED_ONLY_IN_ONCE else ""
            return "ns", f"{STAT_WORDS[stat]} of {words}; {SPLIT_WORDS[split]}{once_note}"
    return "?", "UNDOCUMENTED - add to phase4_seg_postgrid.py"


MESSAGE_WORDS = {
    "L": ("count", "legitimate vehicles"), "cert_verify_mode": ("-", "every | once"),
    "m": ("count", "segments per cert"), "n": ("count", "hash-only per cycle"), "tau": ("messages", "m + n"),
    "cell": ("-", "benchmark cell"), "trial": ("-", "trial number within the combo"),
    "wall_clock_step": ("0/1", "1 = the system clock stepped >100 ms during this trial's receive run (summary stats exclude these)"),
    "sender_id": ("-", "plaintext vehicle_id from the frame (0..L-1 legit)"),
    "seq": ("-", "per-sender arrival index at the receiver (0-based)"),
    "phase": ("-", "first (seq < m+n) or steady"),
    "kind": ("-", "SEGMENT or HASH_ONLY"),
    "outcome": ("-", "VALID / NO_CERT_YET / INVALID_SIGNATURE / EXPIRED / INVALID_CERT_SIGNATURE / SPAM_FILTERED"),
    "cert_path": ("-", "VERIFIED_NOW (cert verified on this message) / CACHED (skipped, once mode) / NA (no cert held, or filter-on)"),
    "t0_ns": ("ns", "steady_clock, relative to receiver start: frame off the socket (after recvfrom)"),
    "t1_ns": ("ns", "cert reassembled + digest matched (completing segment of a cycle only; filter-off rebuilds every cycle)"),
    "t2_ns": ("ns", "cert falcon_verify done (VERIFIED_NOW only)"),
    "t3_ns": ("ns", "message falcon_verify done and outcome classified"),
    "cert_verify_ns": ("ns", "duration of the cert falcon_verify call alone (PRIMARY)"),
    "msg_verify_ns": ("ns", "duration of the message falcon_verify call alone (PRIMARY; also runs for NO_CERT_YET rows)"),
    "t1_t0_ns": ("ns", "t1 - t0"), "t2_t0_ns": ("ns", "t2 - t0"),
    "t3_t0_ns": ("ns", "t3 - t0 (end-to-end receive path incl. load_falcon_key + bookkeeping; excludes socket queueing)"),
    "overhead_ns": ("ns", "(t3 - t0) - cert_verify_ns - msg_verify_ns (NA cert counted as 0)"),
    "send_ns": ("ns", "absolute steady_clock at the sender's sendto() (CLOCK_MONOTONIC, shared across processes)"),
    "send_t3_ns": ("ns", "t3 (absolute) - send_ns: send -> verified, incl. socket queueing"),
    "sendjoin_ok": ("0/1", "1 = every sender's receiver row count matched its sendtimes count, so send_ns is joined by seq"),
}
POOLED_WORDS = {
    "scope": ("-", "all_L (pooled over every L) or per_L"), "L": ("count", "L, or 'all'"),
    "cert_verify_mode": ("-", "every | once"), "metric": ("-", "cert_verify_ns or t2_t0_ns"),
    "n": ("rows", "rows pooled (legit, clock-step trials excluded; VERIFIED_NOW only)"),
    **{k: ("ns", v) for k, v in STAT_WORDS.items()},
}
AB_WORDS = {
    "L": ("count", "legitimate vehicles"), "m": ("count", "segments per cert"), "n": ("count", "hash-only per cycle"),
    "cell": ("-", "benchmark cell"),
    "median_t3_t0_every_ns": ("ns", "median t3 - t0 in the every-mode run"),
    "median_t3_t0_once_ns": ("ns", "median t3 - t0 in the once-mode run"),
    "diff_every_minus_once_ns": ("ns", "every - once: the per-message cost verify-once removes"),
    "median_cert_verify_every_ns": ("ns", "every-mode median cert_verify_ns (what the difference should approximate)"),
    "ratio": ("ratio", "diff / median cert_verify (expected ~1)"),
    "flag": ("-", "OK if 0.5 <= ratio <= 1.5, WARN otherwise (never fails), NA if a side has no data"),
}


def write_dictionary(path, summary_cols):
    def table(cols, lookup):
        lines = ["| Column | Unit | Meaning |", "|---|---|---|"]
        for c in cols:
            unit, words = lookup(c)
            esc = lambda x: str(x).replace("|", "\\|")   # a literal '|' would split the markdown cell
            lines.append(f"| `{c}` | {esc(unit)} | {esc(words)} |")
        return lines

    undocumented = [c for c in summary_cols if describe_summary(c)[0] == "?"]
    out = [
        "# Segmentation grid: data dictionary",
        "",
        "Generated by `scripts/phase4_harness/phase4_seg_postgrid.py` (Update 23). All `*_ns` values are nanoseconds",
        "from `std::chrono::steady_clock`; `t0`-`t3` are relative to the receiver's start, `send_ns` is absolute",
        "(joined via each trial's `receiver_steady_ref_ns`). **Primary metrics are `cert_verify_ns` and `msg_verify_ns`**",
        "(the `falcon_verify` calls alone). `t3_t0_ns` is end-to-end receive-path time including testbed overhead",
        "(`load_falcon_key` reads the key file every message) and excludes socket queueing; `send_t3_ns` includes it.",
        "A_off verify costs are cold-core costs (the receiver idles ~17 ms between legit messages at L=6).",
        "`NA` = not defined for that row (see each column). Summary/pooled/ab statistics use legit senders only and",
        "exclude trials flagged `wall_clock_step=1`; the per-message file keeps them, flagged.",
        "",
        "## seg_grid_summary.csv (one row per L x mode x m x n x cell)",
        "",
        "Timing columns follow `<metric>_<split>_<stat>`; each is listed below.",
        "",
        *table(summary_cols, describe_summary),
        "",
        "## seg_grid_messages.csv.gz (one row per received message)",
        "",
        *table(MESSAGE_FIELDS, lambda c: MESSAGE_WORDS[c]),
        "",
        "## seg_grid_pooled_cert_verify.csv",
        "",
        "In once mode each trial has only L cert verifications, so cert-verify statistics are pooled across combos.",
        "",
        *table(["scope", "L", "cert_verify_mode", "metric", "n"] + list(agg.TIMING_STATS), lambda c: POOLED_WORDS[c]),
        "",
        "## seg_grid_ab_check.csv (every-mode vs once-mode, same L, m, n, cell)",
        "",
        *table(agg.AB_FIELDS, lambda c: AB_WORDS[c]),
        "",
    ]
    Path(path).write_text("\n".join(out))
    return undocumented


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--grid-root", default=str(REPO / "phase4_raw_logs/phase4_seg_sweep"))
    ap.add_argument("--out-dir", default=str(REPO / "exports/seg_grid"))
    ap.add_argument("--cells", default="A_off")
    ap.add_argument("--n-trials", type=int, default=5, help="trial numbers 1..N are looked up per combo x cell")
    args = ap.parse_args()
    cells = [c for c in args.cells.split(",") if c]
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    runs = find_runs(args.grid_root)
    if not runs:
        print(f"no L<L>_msgs<N>[_verifyonce] run directories under {args.grid_root}")
        return 1
    print("runs: " + ", ".join(f"{r['dir'].name} (L={r['L']}, mode={r['mode']})" for r in runs))

    pooled_all = defaultdict(lambda: defaultdict(list))
    pooled_by_L = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    summary, by_run = [], {}
    for run in runs:
        pooled_run = defaultdict(lambda: defaultdict(list))
        rows = summarize_run(run, cells, args.n_trials, pooled_run)
        for mode, metrics in pooled_run.items():
            for metric, xs in metrics.items():
                pooled_all[mode][metric].extend(xs)
                pooled_by_L[run["L"]][mode][metric].extend(xs)
        by_run[(run["L"], run["msgs"], run["mode"])] = rows
        summary += rows
    if not summary:
        print("no combo data found"); return 1

    base_cols = [c for c in summary[0] if c not in ("L", "run_dir", "msgs_per_vehicle", "cert_verify_mode")]
    summary_cols = ["L", "cert_verify_mode", "msgs_per_vehicle", "run_dir"] + base_cols
    write_csv(out / "seg_grid_summary.csv", summary_cols, summary)

    ab = []
    for (L, msgs, mode), rows in sorted(by_run.items()):
        if mode == "once" and (L, msgs, "every") in by_run:
            ab += agg.ab_rows(rows, by_run[(L, msgs, "every")], L)
    write_csv(out / "seg_grid_ab_check.csv", agg.AB_FIELDS, ab)

    pooled = pooled_rows(pooled_all, pooled_by_L)
    write_csv(out / "seg_grid_pooled_cert_verify.csv", ["scope", "L", "cert_verify_mode", "metric", "n"] + list(agg.TIMING_STATS), pooled)

    n_rows, n_trials, n_missing = write_messages(runs, cells, out / "seg_grid_messages.csv.gz")
    undocumented = write_dictionary(out / "data_dictionary.md", summary_cols)

    print(f"summary: {len(summary)} rows x {len(summary_cols)} columns")
    print(f"messages: {n_rows} rows from {n_trials} trials ({n_missing} trials had no timing files)")
    print("pooled cert verify (us):")
    for r in pooled:
        if r["scope"] == "all_L":
            print(f"  {r['cert_verify_mode']:<6} {r['metric']:<15} n={r['n']:<6} "
                  + " ".join(f"{k}={agg.fmt(agg.us(r[k]), 1)}" for k in agg.TIMING_STATS))
    print("every-vs-once check:")
    print("\n".join(agg.ab_lines(ab)) if ab else "  (no L with both modes)")
    checks = Counter(r["cert_verify_count_check"] for r in summary)
    ttfv = Counter(r["ttfv_unverifiable_check"] for r in summary)
    print(f"cert_verify_count_check: {dict(checks)}   ttfv_unverifiable_check: {dict(ttfv)}")
    if undocumented:
        print(f"WARNING: undocumented summary columns: {undocumented}")
    print(f"wrote {out}/: seg_grid_summary.csv, seg_grid_messages.csv.gz, seg_grid_pooled_cert_verify.csv, "
          f"seg_grid_ab_check.csv, data_dictionary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
