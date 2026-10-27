#!/usr/bin/env python3
"""Cross-combo aggregator + per-combo prediction check for the m x n cert-cycle sweep (phase4_mn_sweep.sh).

Two modes:
  --combo mM_nN   prediction check for ONE combo (the driver calls this after each combo's gate). Prints
                  one '  DEVIATION ...' line per cell whose modal legit VALID != 300L - L(m-1) or whose modal
                  legit NO_CERT_YET != L(m-1). Exit 0 = all cells match, 3 = deviation(s) (driver marks the
                  combo REVIEW and continues - never a stop), 1 = error.
  (no --combo)    full report over every mM_nN dir under --root: per-trial + summary CSVs and report.txt.

Why the prediction check compares VALID and NO_CERT_YET directly instead of the receiver's "drop rate,
excluding startup": that metric excludes EVERY legit NO_CERT_YET, so a partial TTL failure is only partly
visible in it (an evicted sender's segment messages become NO_CERT_YET and are excluded; only its hash-only
messages show up, as NO_CACHE drops). Cold-start loss scales as L(m-1) (each vehicle's first m-1 segment
messages arrive before its cert can be reconstructed); nothing here assumes m=2.

Deviation labels: TTL only exists on the filter-ON path. A filter-on cell with ttl_headroom_ms =
bufferTtlMs - (m-1)*100 <= 200 (m=4,5 at 500 ms) is a reduced-TTL-margin cell, and a deviation there is
labelled REDUCED_TTL_MARGIN; every other deviation is labelled ANOMALY. Both list per-reason drop counts.

Wire bytes come from the transmitter's '[FalconCertCycle] TX ... wire_bytes=' lines (legit vehicles only),
whole-line anchored: the transmitter's stdout is unsynchronized across threads and garbles a share of lines
(CORRECTIONS.md #19), so per-kind means are taken from clean lines and weighted by the exact per-kind message
counts implied by the cycle (every vehicle starts at cycle position 0).
Timing (Update 23): when a trial has the receiver's per-message timing files (<cell>_trial<t>_msgtiming.csv[.gz],
_ttfv.csv[.gz]) and the transmitter's _sendtimes.csv[.gz], per-combo timing columns are appended to the summary
(existing columns unchanged; missing files -> NA). PRIMARY metrics are cert_verify_ns and msg_verify_ns (the
falcon_verify calls alone, pure crypto cost). t3-t0 is end-to-end receive-path time INCLUDING testbed overhead
(load_falcon_key reads + hex-decodes the key file every message, plus bookkeeping), and
overhead_ns = (t3-t0) - cert_verify_ns - msg_verify_ns isolates that overhead. Legit senders only; trials whose
receiver summary says wall_clock_step=1 are excluded from timing stats (still counted). In cert_verify_mode=once
there are only L VERIFIED_NOW rows per trial, so cert_verify_ns / t2-t0 are reported pooled across the run
(<summary>_pooled_cert_verify.csv), not per combo. send->t3 joins sendtimes by (sender, seq) and is skipped for a
trial whenever any sender's receiver row count differs from its sendtimes row count (seq is the arrival index, so
a lost packet would shift every later row).
Read-only on the logs."""
import argparse
import csv
import gzip
import re
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from phase4_vehicle_scaling_aggregate import read_log, parse_recv  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
ALL_CELLS = ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"]
DROP_REASONS = ["RATE", "LENGTH", "NO_CACHE", "STALE", "FRAG_INDEX", "SEG_HASH", "BUFFER_CAP",
                "BUFFER_TTL_EVICT_INCOMPLETE"]
MSGS_PER_VEHICLE = 300   # --msgs-per-vehicle overrides (config numMessages)
INTERVAL_MS = 100
REDUCED_MARGIN_MS = 200
DSRC_CAP = 2304
COMBO_RE = re.compile(r"^m(\d+)_n(\d+)$")
TX_RE = re.compile(r"^\[FalconCertCycle\] TX vehicle=(\d+) cycle_pos=\d+ fragment_set_id=\d+ kind=(\S+) wire_bytes=(\d+)$", re.M)


def parse_drop_reasons(text, who):
    m = re.search(rf"Spam-filter drop reasons \({who} senders\):\n((?:  \w+: \d+\n)+)", text)
    if not m:
        return None
    d = dict((k, int(v)) for k, v in re.findall(r"  (\w+): (\d+)", m.group(1)))
    return {k: d.get(k, 0) for k in DROP_REASONS}


def parse_wire(text, L):
    seg, ho = [], []
    for v, kind, b in TX_RE.findall(text or ""):
        if int(v) >= L:
            continue
        (seg if kind.startswith("SEGMENT_CARRYING") else ho if kind == "HASH_ONLY" else []).append(int(b))
    h = Counter(ho).most_common(1)[0][0] if ho else None
    # n=0 (Update 23) has no hash-only frames to anchor the lower bound; the DSRC cap alone applies then.
    clean_seg = [b for b in seg if (h is None or h < b) and b <= DSRC_CAP]
    return {"hash_only_bytes": h, "hash_only_nonmodal_lines": sum(1 for b in ho if b != h),
            "seg_values": clean_seg, "seg_garbled_lines": len(seg) - len(clean_seg)}


def seg_msgs_per_vehicle(m, n):
    tau = m + n
    return (MSGS_PER_VEHICLE // tau) * m + min(MSGS_PER_VEHICLE % tau, m)


def fmt(x, nd=2):
    if x is None or x == "NA":
        return "NA"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def mean_or_none(xs):
    xs = [x for x in xs if x is not None]
    return statistics.mean(xs) if xs else None


def modal(xs):
    xs = [x for x in xs if x is not None]
    return Counter(xs).most_common(1)[0][0] if xs else None


def label_for(cell, headroom):
    if cell.endswith("_on") and headroom <= 0:
        return f"TTL_EXCEEDED (headroom {headroom} ms) - reassembly outlasts the TTL, collapse expected"
    if cell.endswith("_on") and headroom <= REDUCED_MARGIN_MS:
        return f"REDUCED_TTL_MARGIN (headroom {headroom} ms) - expected-margin deviation, see drop reasons"
    return "ANOMALY"


# ---- Update 23: per-message timing ----
TIMING_STATS = ("mean", "median", "p95", "p99", "max")
BASE_SPLITS = ("all", "SEGMENT", "HASH_ONLY", "first", "steady")
PATH_SPLITS = ("VERIFIED_NOW", "CACHED")
# metric -> splits. t2_t0/cert_verify_ns exist only on VERIFIED_NOW rows; t1_t0 only on the completing segment.
TIMING_SPEC = [
    ("cert_verify_ns", BASE_SPLITS), ("msg_verify_ns", BASE_SPLITS + PATH_SPLITS),
    ("t1_t0_ns", BASE_SPLITS), ("t2_t0_ns", BASE_SPLITS), ("t3_t0_ns", BASE_SPLITS + PATH_SPLITS),
    ("overhead_ns", BASE_SPLITS + PATH_SPLITS), ("send_t3_ns", BASE_SPLITS),
]
POOLED_ONLY_IN_ONCE = ("cert_verify_ns", "t2_t0_ns")   # ~L rows per trial in once mode


def pct(sorted_xs, p):
    """Nearest-rank percentile, same convention as the receiver's percentile_ms."""
    k = max(0, min(len(sorted_xs) - 1, math.ceil(p / 100 * len(sorted_xs)) - 1))
    return sorted_xs[k]


def stats(xs):
    if not xs:
        return {k: None for k in TIMING_STATS}
    xs = sorted(xs)
    return {"mean": statistics.fmean(xs), "median": statistics.median(xs), "p95": pct(xs, 95),
            "p99": pct(xs, 99), "max": xs[-1]}


def read_csv_maybe_gz(path):
    p = Path(path)
    if p.exists():
        with open(p, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    gz = Path(str(p) + ".gz")
    if gz.exists():
        with gzip.open(gz, "rt", newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    return None


def recv_cert_verify_mode(recv_text):
    """Older receivers print no cert_verify_mode line; they always verified every message."""
    m = re.search(r"^cert_verify_mode=(\w+)$", recv_text or "", re.M)
    return m.group(1) if m else "every"


def load_timing(base, recv_text, L, m, n):
    """One trial's timing samples (legit senders only), or None when its timing files are missing."""
    rows = read_csv_maybe_gz(f"{base}_msgtiming.csv")
    ttfv = read_csv_maybe_gz(f"{base}_ttfv.csv")
    if rows is None or ttfv is None:
        return None
    sends = read_csv_maybe_gz(f"{base}_sendtimes.csv")
    step = re.search(r"^wall_clock_step=(\d)$", recv_text or "", re.M)
    ref = re.search(r"^receiver_steady_ref_ns=(\d+)$", recv_text or "", re.M)
    na = lambda v: None if v in ("NA", "", None) else int(v)
    rows = [r for r in rows if int(r["sender_id"]) < L]
    tau = m + n

    # send->t3 join guard: seq is the receiver's per-sender arrival index, so it only lines up with the
    # sender's own index if nothing was lost - require equal row counts for every sender.
    join = None
    if sends is not None and ref is not None:
        rx_counts = Counter(r["sender_id"] for r in rows)
        tx_counts = Counter(r["sender_id"] for r in sends if int(r["sender_id"]) < L)
        if rx_counts == tx_counts:
            join = {(r["sender_id"], r["seq"]): int(r["send_ns"]) for r in sends}
    ref_ns = int(ref.group(1)) if ref else None

    samples = defaultdict(list)
    gt100 = send_gt100 = n_t3 = n_send = verified_now = 0
    for r in rows:
        t0, t1, t2, t3 = (na(r[k]) for k in ("t0_ns", "t1_ns", "t2_ns", "t3_ns"))
        cv, mv = na(r["cert_verify_ns"]), na(r["msg_verify_ns"])
        path = r.get("cert_path", "NA")
        base_splits = ("all", r["kind"], "first" if int(r["seq"]) < tau else "steady")
        path_splits = base_splits + ((path,) if path in PATH_SPLITS else ())

        def add(metric, value, splits):
            for sp in splits:
                samples[(metric, sp)].append(value)
        if path == "VERIFIED_NOW":
            verified_now += 1
            if cv is not None:
                add("cert_verify_ns", cv, base_splits)
            if t2 is not None:
                add("t2_t0_ns", t2 - t0, base_splits)
        if t1 is not None:
            add("t1_t0_ns", t1 - t0, base_splits)
        if t3 is not None:
            n_t3 += 1
            gt100 += (t3 - t0) > 100_000_000
            add("t3_t0_ns", t3 - t0, path_splits)
            if mv is not None:
                add("msg_verify_ns", mv, path_splits)
                add("overhead_ns", (t3 - t0) - (cv or 0) - mv, path_splits)
            if join is not None:
                d = ref_ns + t3 - join[(r["sender_id"], r["seq"])]
                n_send += 1
                send_gt100 += d > 100_000_000
                add("send_t3_ns", d, base_splits)
    ttfv = [t for t in ttfv if int(t["sender_id"]) < L]
    return {"wall_clock_step": bool(step and step.group(1) == "1"), "samples": samples,
            "verified_now": verified_now, "gt100": gt100, "n_t3": n_t3,
            "send_gt100": send_gt100, "n_send": n_send, "sendjoin_skipped": join is None,
            "ttfv_ms": [float(t["ttfv_ms"]) for t in ttfv if t["ttfv_ms"] != "NA"],
            "ttfv_ok": all(int(t["n_unverifiable_before_first_valid"]) == m - 1 for t in ttfv) and len(ttfv) == L}


def timing_columns(cell, ts, L, pred_valid, pooled):
    """Per-combo x cell timing columns (fixed key set, so every summary row has the same columns)."""
    col = {}
    modes = {t["cert_verify_mode"] for t in ts}
    mode = modes.pop() if len(modes) == 1 else "mixed"
    timed = [t for t in ts if t["timing"] is not None]
    used = [t for t in timed if not t["timing"]["wall_clock_step"]]
    col["cert_verify_mode"] = mode
    # Soft warning (Update 23): trials the receiver flagged wall_clock_step=1 (from every trial's summary, timed or
    # not), and how many of them miss the predicted VALID count. Never a failure: the count prediction is
    # system-clock-sensitive only through STALE/EXPIRED/deadline effects, which a clock step produces spuriously.
    stepped = [t for t in ts if t.get("wall_clock_step") == 1]
    col["clock_step_trials"] = len(stepped)
    col["clock_step_trials_valid_ne_pred"] = sum(1 for t in stepped if t["legit_valid"] != pred_valid)
    col["timing_trials"] = len(timed)
    col["wall_clock_step_trials"] = sum(1 for t in timed if t["timing"]["wall_clock_step"])
    col["sendjoin_skipped_trials"] = sum(1 for t in used if t["timing"]["sendjoin_skipped"])
    col["verified_now_rows"] = sum(t["timing"]["verified_now"] for t in used) if used else None
    # cert-verify count per trial (receiver summary's cert n=): L in once mode, every verifiable message in
    # every mode. Only defined for A_off (no attacker, filter off); other cells verify a different population.
    want = (L if mode == "once" else pred_valid) if cell == "A_off" and mode in ("once", "every") else None
    got = [t["cert_verify_n"] for t in ts]
    col["cert_verify_count_expected"] = want
    col["cert_verify_count_check"] = ("NA" if want is None or not got
                                      else "PASS" if all(g == want for g in got) else "FAIL")
    n_t3 = sum(t["timing"]["n_t3"] for t in used)
    n_send = sum(t["timing"]["n_send"] for t in used)
    col["frac_t3_t0_gt_100ms"] = sum(t["timing"]["gt100"] for t in used) / n_t3 if n_t3 else None
    col["frac_send_t3_gt_100ms"] = sum(t["timing"]["send_gt100"] for t in used) / n_send if n_send else None
    tt = [x for t in used for x in t["timing"]["ttfv_ms"]]
    col["ttfv_ms_mean"] = statistics.fmean(tt) if tt else None
    col["ttfv_ms_min"] = min(tt) if tt else None
    col["ttfv_ms_max"] = max(tt) if tt else None
    col["ttfv_unverifiable_check"] = "NA" if not used else ("PASS" if all(t["timing"]["ttfv_ok"] for t in used) else "FAIL")
    merged = defaultdict(list)
    for t in used:
        for k, v in t["timing"]["samples"].items():
            merged[k].extend(v)
    msg_all = merged.get(("msg_verify_ns", "all"), [])
    col["msg_verify_ns_median"] = statistics.median(msg_all) if msg_all else None   # drift check across the sweep
    for metric, splits in TIMING_SPEC:
        pooled_only = mode == "once" and metric in POOLED_ONLY_IN_ONCE
        if metric in POOLED_ONLY_IN_ONCE and mode in ("once", "every"):
            pooled[mode][metric].extend(merged.get((metric, "all"), []))
        for sp in splits:
            st = stats([] if pooled_only else merged.get((metric, sp), []))
            for k in TIMING_STATS:
                col[f"{metric}_{sp}_{k}"] = st[k]
    return col


def load_combo(root, tag, L, ttl, n_trials):
    m, n = map(int, COMBO_RE.match(tag).groups())
    d = Path(root) / tag
    trials = []
    for cell in ALL_CELLS:
        for t in range(1, n_trials + 1):
            recv = read_log(d / f"{cell}_trial{t}_recv.log")
            if recv is None:
                continue
            r = parse_recv(recv)
            r.update({"combo": tag, "m": m, "n": n, "cell": cell, "trial": t})
            r["legit_drop_reasons"] = parse_drop_reasons(recv, "legit")
            r["attacker_drop_reasons"] = parse_drop_reasons(recv, "attacker")
            r["wire"] = parse_wire(read_log(d / f"{cell}_trial{t}_xmit.log"), L)
            r["cert_verify_mode"] = recv_cert_verify_mode(recv)
            r["timing"] = load_timing(d / f"{cell}_trial{t}", recv, L, m, n)
            trials.append(r)
    gate = {}
    sfile = d / "summary.csv"
    if sfile.exists():
        gate = {r["cell"]: r for r in csv.DictReader(open(sfile, newline="", encoding="utf-8"))}
    return m, n, trials, gate


def summarize(tag, m, n, trials, gate, L, ttl, pooled=None):
    pooled = pooled if pooled is not None else defaultdict(lambda: defaultdict(list))
    tau = m + n
    headroom = ttl - (m - 1) * INTERVAL_MS
    pred_valid = MSGS_PER_VEHICLE * L - L * (m - 1)
    pred_ncy = L * (m - 1)
    rows = []
    for cell in ALL_CELLS:
        ts = [r for r in trials if r["cell"] == cell]
        if not ts:
            continue
        valid = [r["legit_valid"] for r in ts]
        ncy = [r["legit_no_cert_yet"] for r in ts]
        mv, mn = modal(valid), modal(ncy)
        drops = {k: sum((r["legit_drop_reasons"] or {}).get(k, 0) for r in ts) for k in DROP_REASONS}
        atk_drops = {k: sum((r["attacker_drop_reasons"] or {}).get(k, 0) for r in ts) for k in DROP_REASONS}
        seg_vals = [b for r in ts for b in r["wire"]["seg_values"]]
        h = modal([r["wire"]["hash_only_bytes"] for r in ts])
        S = statistics.mean(seg_vals) if seg_vals else None
        segc = seg_msgs_per_vehicle(m, n)
        mean_wire = (segc * S + (MSGS_PER_VEHICLE - segc) * (h or 0)) / MSGS_PER_VEHICLE if S and (h or n == 0) else None
        steady = (m * S + n * (h or 0)) / tau if S and (h or n == 0) else None
        lt = [r["legit_total"] for r in ts]
        g = gate.get(cell, {})
        # The deviation test uses trials NOT flagged wall_clock_step=1 (Update 23): a flagged trial's count is a soft
        # warning (clock_step_* columns), never a deviation/REVIEW. Pre-Update-23 logs have no flag, so nothing changes.
        clean = [r for r in ts if r.get("wall_clock_step") != 1]
        cmv, cmn = modal([r["legit_valid"] for r in clean]), modal([r["legit_no_cert_yet"] for r in clean])
        dev = bool(clean) and ((cmv != pred_valid) or (cmn != pred_ncy))
        row = {
            "combo": tag, "m": m, "n": n, "cell": cell, "tau": tau, "refresh_ms": tau * INTERVAL_MS,
            "buffer_ttl_ms": ttl, "ttl_headroom_ms": headroom, "n_trials": len(ts),
            "gate_hard_failures": g.get("hard_failures", "NA"),
            "predicted_legit_valid": pred_valid, "modal_legit_valid": mv,
            "valid_minus_pred": (mv - pred_valid) if mv is not None else "NA",
            "trials_valid_ne_pred": sum(1 for v in valid if v != pred_valid),
            "predicted_no_cert_yet": pred_ncy, "modal_no_cert_yet": mn,
            "no_cert_yet_minus_pred": (mn - pred_ncy) if mn is not None else "NA",
            "trials_no_cert_yet_ne_pred": sum(1 for v in ncy if v != pred_ncy),
            "deviation_label": label_for(cell, headroom) if dev else "",
            "legit_valid_frac_mean": mean_or_none([r["legit_valid"] / r["legit_total"] for r in ts if r["legit_total"]]),
            "legit_drop_frac_mean": mean_or_none([r["drop_num"] / r["drop_denom"] for r in ts if r["drop_denom"]]),
            "deadline_miss_frac_mean": mean_or_none([r["dm_num"] / r["legit_total"] for r in ts if r["legit_total"] and r["dm_num"] is not None]),
            "legit_latency_p99_ms_mean": mean_or_none([r["lat_p99"] for r in ts]),
            "cert_verify_n_mean": mean_or_none([r["cert_verify_n"] for r in ts]),
            "attacker_total_mean": mean_or_none([r["attacker_total"] for r in ts]),
            "attacker_full_crypto_frac_mean": mean_or_none([r["atk_full"] / r["attacker_total"] for r in ts if r["attacker_total"]]),
            "attacker_cheap_reject_frac_mean": mean_or_none([r["atk_cheap"] / r["attacker_total"] for r in ts if r["attacker_total"]]),
            "legit_total_values": ";".join(sorted({str(v) for v in lt})),
            "seg_bytes_mean": S, "hash_only_bytes": h,
            "hash_only_nonmodal_lines": sum(r["wire"]["hash_only_nonmodal_lines"] for r in ts),
            "seg_garbled_lines": sum(r["wire"]["seg_garbled_lines"] for r in ts),
            "mean_wire_bytes_per_msg": mean_wire, "predicted_steady_wire_bytes_per_msg": steady,
        }
        for k in DROP_REASONS:
            row[f"legit_drop_{k}"] = drops[k]
        for k in DROP_REASONS:
            row[f"attacker_drop_{k}"] = atk_drops[k]
        row.update(timing_columns(cell, ts, L, pred_valid, pooled))   # Update 23; appended after the existing columns
        rows.append(row)
    return rows


def deviation_lines(rows, trials):
    out = []
    for r in rows:
        if not r["deviation_label"]:
            continue
        reasons = ", ".join(f"{k}={r['legit_drop_' + k]}" for k in DROP_REASONS if r["legit_drop_" + k]) or "none (filter-off or no drops)"
        out.append(f"  DEVIATION {r['combo']} {r['cell']}: modal VALID {r['modal_legit_valid']} vs predicted {r['predicted_legit_valid']} "
                   f"({r['valid_minus_pred']:+}), modal NO_CERT_YET {r['modal_no_cert_yet']} vs predicted {r['predicted_no_cert_yet']} "
                   f"({r['no_cert_yet_minus_pred']:+}); headroom {r['ttl_headroom_ms']} ms; [{r['deviation_label']}]; "
                   f"legit drop reasons (all trials): {reasons}")
        for t in trials:
            if t.get("wall_clock_step") == 1:
                continue   # listed as a soft warning instead
            if t["cell"] == r["cell"] and (t["legit_valid"] != r["predicted_legit_valid"] or t["legit_no_cert_yet"] != r["predicted_no_cert_yet"]):
                out.append(f"      trial {t['trial']}: VALID {t['legit_valid']} NO_CERT_YET {t['legit_no_cert_yet']} "
                           f"drop {t['drop_num']}/{t['drop_denom']} deadline-miss {t['dm_num']}")
    return out


def load_run(root, L, ttl, n_trials, pooled):
    combos = sorted((p.name for p in root.iterdir() if p.is_dir() and COMBO_RE.match(p.name)),
                    key=lambda s: tuple(map(int, COMBO_RE.match(s).groups())))
    all_rows, all_trials = [], []
    for tag in combos:
        m, n, trials, gate = load_combo(root, tag, L, ttl, n_trials)
        if not trials:
            continue
        all_rows += summarize(tag, m, n, trials, gate, L, ttl, pooled)
        all_trials += trials
    return all_rows, all_trials, combos


def us(v):
    return None if v is None else v / 1000.0


def timing_report(pivot):
    """Timing pivots (Update 23), appended to the report by main()'s pivot(). Values in microseconds."""
    pivot("cert_verify_mode", lambda r: r["cert_verify_mode"])
    pivot("median msg_verify_ns in us (PRIMARY; should not depend on m or n - drift check)",
          lambda r: us(r["msg_verify_ns_median"]), nd=1)
    pivot("median cert_verify_ns in us (PRIMARY; every mode only - once mode is pooled below)",
          lambda r: us(r["cert_verify_ns_all_median"]), nd=1)
    pivot("median t3-t0 in us (end-to-end incl. testbed overhead)", lambda r: us(r["t3_t0_ns_all_median"]), nd=1)
    pivot("median overhead_ns in us ((t3-t0) - cert_verify - msg_verify)", lambda r: us(r["overhead_ns_all_median"]), nd=1)
    pivot("median t1-t0 in us (completing segment: reassembly + digest)", lambda r: us(r["t1_t0_ns_all_median"]), nd=1)
    pivot("median send->t3 in ms", lambda r: None if r["send_t3_ns_all_median"] is None else r["send_t3_ns_all_median"] / 1e6, nd=3)
    pivot("ttfv_ms mean [unverifiable-before-first-valid == m-1 check]",
          lambda r: f"{fmt(r['ttfv_ms_mean'], 1)}[{r['ttfv_unverifiable_check']}]")
    pivot("cert-verify count check (once: == L; every: == predicted VALID; A_off only)",
          lambda r: r["cert_verify_count_check"])
    pivot("timing trials / wall_clock_step trials (excluded) / sendjoin skipped",
          lambda r: f"{r['timing_trials']}/{r['wall_clock_step_trials']}/{r['sendjoin_skipped_trials']}")
    pivot("verified_now_rows (sum over timed trials)", lambda r: r["verified_now_rows"])


def write_pooled(pooled, path):
    out = ["== pooled cert_verify_ns / t2-t0 across all combos, by cert_verify_mode (us) =="]
    rows = []
    for mode in sorted(pooled):
        for metric in POOLED_ONLY_IN_ONCE:
            xs = pooled[mode][metric]
            st = stats(xs)
            rows.append({"cert_verify_mode": mode, "metric": metric, "n": len(xs), **st})
            out.append(f"  {mode:<6} {metric:<15} n={len(xs):<7} " + " ".join(
                f"{k}={fmt(us(st[k]), 1)}" for k in TIMING_STATS))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["cert_verify_mode", "metric", "n"] + list(TIMING_STATS), lineterminator="\n")
        w.writeheader()
        w.writerows({k: ("NA" if v is None else fmt(v, 1) if isinstance(v, float) else v) for k, v in r.items()} for r in rows)
    if not rows:
        out.append("  (no timing data)")
    out += [f"  wrote {path}", ""]
    return out


AB_FIELDS = ["L", "m", "n", "cell", "median_t3_t0_every_ns", "median_t3_t0_once_ns", "diff_every_minus_once_ns",
             "median_cert_verify_every_ns", "ratio", "flag"]


def ab_rows(once_rows, every_rows, L):
    """A-vs-B rows: median(t3-t0) every minus once should be ~ the every-mode median cert_verify_ns."""
    ref = {(r["m"], r["n"], r["cell"]): r for r in every_rows}
    rows = []
    for r in once_rows:
        e = ref.get((r["m"], r["n"], r["cell"]))
        if e is None:
            continue
        a, b, c = e["t3_t0_ns_all_median"], r["t3_t0_ns_all_median"], e["cert_verify_ns_all_median"]
        diff = (a - b) if a is not None and b is not None else None
        ratio = diff / c if diff is not None and c else None
        flag = "NA" if ratio is None else ("OK" if 0.5 <= ratio <= 1.5 else "WARN")
        if e["cert_verify_mode"] != "every" or r["cert_verify_mode"] != "once":
            flag += f" (modes: reference={e['cert_verify_mode']} this={r['cert_verify_mode']})"
        rows.append({"L": L, "m": r["m"], "n": r["n"], "cell": r["cell"], "median_t3_t0_every_ns": a,
                     "median_t3_t0_once_ns": b, "diff_every_minus_once_ns": diff,
                     "median_cert_verify_every_ns": c, "ratio": ratio, "flag": flag})
    return rows


def ab_lines(rows):
    return [f"  L={r['L']} m={r['m']} n={r['n']} {r['cell']}: every {fmt(us(r['median_t3_t0_every_ns']), 1)} "
            f"once {fmt(us(r['median_t3_t0_once_ns']), 1)} diff {fmt(us(r['diff_every_minus_once_ns']), 1)} "
            f"cert_verify(every) {fmt(us(r['median_cert_verify_every_ns']), 1)} ratio {fmt(r['ratio'], 2)} {r['flag']}"
            for r in rows]


def write_ab_check(once_rows, every_rows, L, path):
    out = ["== A-vs-B check: every-mode reference vs this run (us) =="]
    rows = ab_rows(once_rows, every_rows, L)
    out += ab_lines(rows)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=AB_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows({k: ("NA" if v is None else fmt(v, 3) if isinstance(v, float) else v) for k, v in r.items()} for r in rows)
    if not rows:
        out.append("  (no (m, n, cell) present in both runs)")
    out += [f"  wrote {path}", ""]
    return out


def main():
    global MSGS_PER_VEHICLE, ALL_CELLS
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(REPO / "phase4_raw_logs/phase4_mn_sweep"))
    ap.add_argument("--combo", help="mM_nN: prediction check for one combo only")
    ap.add_argument("--num-vehicles", type=int, default=6)
    ap.add_argument("--n-trials", type=int, default=5)
    ap.add_argument("--buffer-ttl-ms", type=int, default=500)
    ap.add_argument("--csv-per-trial", default=str(REPO / "exports/mn_sweep_L6_per_trial.csv"))
    ap.add_argument("--csv-summary", default=str(REPO / "exports/mn_sweep_L6_summary.csv"))
    ap.add_argument("--report", default=None, help="default: <root>/report.txt")
    ap.add_argument("--msgs-per-vehicle", type=int, default=MSGS_PER_VEHICLE, help="config numMessages")
    ap.add_argument("--cells", default=",".join(ALL_CELLS), help="comma list of cells to read (e.g. A_off)")
    ap.add_argument("--ab-reference", default=None,
                    help="root of a cert_verify_mode=every run (same L) to compare against this run (A-vs-B check)")
    args = ap.parse_args()
    MSGS_PER_VEHICLE = args.msgs_per_vehicle
    ALL_CELLS = [c for c in args.cells.split(",") if c]
    L, ttl = args.num_vehicles, args.buffer_ttl_ms

    if args.combo:
        if not COMBO_RE.match(args.combo):
            print(f"bad combo tag {args.combo}"); return 1
        m, n, trials, gate = load_combo(args.root, args.combo, L, ttl, args.n_trials)
        if not trials:
            print(f"no trials found for {args.combo}"); return 1
        rows = summarize(args.combo, m, n, trials, gate, L, ttl)
        print(f"[prediction] {args.combo}: m={m} n={n} tau={m + n} headroom={ttl - (m - 1) * INTERVAL_MS} ms "
              f"predicted VALID={MSGS_PER_VEHICLE * L - L * (m - 1)} NO_CERT_YET={L * (m - 1)}")
        for r in rows:
            print(f"  {r['cell']}: modal VALID {r['modal_legit_valid']} NO_CERT_YET {r['modal_no_cert_yet']} "
                  f"cert_verify_n_mean {fmt(r['cert_verify_n_mean'])} S={fmt(r['seg_bytes_mean'], 1)} B"
                  f" cert_verify_mode={r['cert_verify_mode']} cert-verify count check={r['cert_verify_count_check']}"
                  f" (expected {r['cert_verify_count_expected']}) msg_verify_ns median={fmt(r['msg_verify_ns_median'], 0)}"
                  + ("" if not r["deviation_label"] else "  <-- deviation"))
        for r in rows:
            if r["clock_step_trials"]:
                print(f"  WARNING (soft, not a deviation) {r['combo']} {r['cell']}: {r['clock_step_trials']} trial(s) flagged "
                      f"wall_clock_step=1, {r['clock_step_trials_valid_ne_pred']} of them off the predicted VALID; "
                      f"excluded from timing stats")
        devs = deviation_lines(rows, trials)
        devs += [f"  DEVIATION {r['combo']} {r['cell']}: cert-verify count check FAIL (expected "
                 f"{r['cert_verify_count_expected']} per trial, mode {r['cert_verify_mode']}, "
                 f"mean {fmt(r['cert_verify_n_mean'])})" for r in rows if r["cert_verify_count_check"] == "FAIL"]
        print("\n".join(devs) if devs else "  (no deviations)")
        return 3 if devs else 0

    root = Path(args.root)
    pooled = defaultdict(lambda: defaultdict(list))
    all_rows, all_trials, combos = load_run(root, L, ttl, args.n_trials, pooled)
    if not all_rows:
        print(f"no combo data under {root}"); return 1

    Path(args.csv_summary).parent.mkdir(parents=True, exist_ok=True)
    with open(args.csv_summary, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(all_rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows({k: fmt(v, 6) if isinstance(v, float) else ("NA" if v is None else v) for k, v in r.items()} for r in all_rows)
    pt_cols = ["combo", "m", "n", "cell", "trial", "legit_total", "legit_valid", "legit_no_cert_yet", "drop_num", "drop_denom",
               "dm_num", "lat_p99", "cert_verify_n", "attacker_total", "atk_full", "atk_cheap", "atk_pending",
               "sock_actual", "incomplete_run", "hash_only_bytes", "seg_bytes_mean", "seg_clean_lines"] + \
              [f"legit_drop_{k}" for k in DROP_REASONS] + [f"attacker_drop_{k}" for k in DROP_REASONS]
    with open(args.csv_per_trial, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=pt_cols, lineterminator="\n", extrasaction="ignore")
        w.writeheader()
        for t in all_trials:
            row = dict(t)
            row["hash_only_bytes"] = t["wire"]["hash_only_bytes"]
            row["seg_bytes_mean"] = mean_or_none(t["wire"]["seg_values"])
            row["seg_clean_lines"] = len(t["wire"]["seg_values"])
            for who in ("legit", "attacker"):
                for k in DROP_REASONS:
                    row[f"{who}_drop_{k}"] = (t[f"{who}_drop_reasons"] or {}).get(k, "NA")
            w.writerow({k: ("NA" if row.get(k) is None else fmt(row[k], 3) if isinstance(row.get(k), float) else row[k]) for k in pt_cols})

    ms = sorted({r["m"] for r in all_rows}); ns = sorted({r["n"] for r in all_rows})
    by = {(r["m"], r["n"], r["cell"]): r for r in all_rows}
    lines = [f"m x n cert-cycle sweep report  (L={L}, bufferTtlMs={ttl}, N={args.n_trials}/cell, combos={len(combos)})",
             f"Predicted legit VALID = {MSGS_PER_VEHICLE}L - L(m-1) = {MSGS_PER_VEHICLE * L} - {L}(m-1), and NO_CERT_YET = {L}(m-1),",
             "assuming no TTL eviction or attack-induced loss; filter-on cells with TTL headroom <= "
             f"{REDUCED_MARGIN_MS} ms are reduced-margin cells.",
             "TTL headroom (bufferTtlMs - (m-1)*100): " + ", ".join(f"m={m}: {ttl - (m - 1) * INTERVAL_MS} ms" for m in ms),
             "Refresh interval tau*100 ms: " + ", ".join(f"(m={m},n={n}): {(m + n) * INTERVAL_MS}" for m in ms for n in ns), ""]

    def pivot(title, key, cells=ALL_CELLS, nd=2):
        lines.append(f"== {title} ==")
        for cell in cells:
            if not any((m, n, cell) in by for m in ms for n in ns):
                continue
            lines.append(f"  {f'[{cell}]':<20}" + "".join(f"{'n=' + str(n):>14}" for n in ns))
            for m in ms:
                vals = []
                for n in ns:
                    r = by.get((m, n, cell))
                    v = key(r) if r else "-"
                    vals.append(f"{fmt(v, nd):>14} ")
                lines.append(f"    {f'm={m} (hr {ttl - (m - 1) * INTERVAL_MS}ms)':<18}" + "".join(vals))
        lines.append("")

    pivot("legit VALID modal (predicted in parentheses)", lambda r: f"{r['modal_legit_valid']}({r['predicted_legit_valid']})")
    pivot("legit NO_CERT_YET modal (predicted in parentheses)", lambda r: f"{r['modal_no_cert_yet']}({r['predicted_no_cert_yet']})")
    pivot("legit drop frac (excl. startup), mean", lambda r: r["legit_drop_frac_mean"], nd=5)
    pivot("legit deadline-miss frac, mean", lambda r: r["deadline_miss_frac_mean"], nd=5)
    pivot("legit VALID latency p99 ms, mean", lambda r: r["legit_latency_p99_ms_mean"])
    pivot("cert-sig verifications per trial, mean", lambda r: r["cert_verify_n_mean"], nd=1)
    pivot("attacker full-crypto frac, mean", lambda r: r["attacker_full_crypto_frac_mean"], cells=[c for c in ALL_CELLS if c[0] != "A"], nd=5)
    pivot("attacker cheap-reject frac, mean", lambda r: r["attacker_cheap_reject_frac_mean"], cells=[c for c in ALL_CELLS if c[0] != "A"], nd=5)
    pivot("legit BUFFER_TTL_EVICT_INCOMPLETE, total over trials", lambda r: r["legit_drop_BUFFER_TTL_EVICT_INCOMPLETE"],
          cells=[c for c in ALL_CELLS if c.endswith("_on")])
    pivot("segment-carrying wire bytes S (clean legit TX lines), mean", lambda r: r["seg_bytes_mean"], cells=["A_on"], nd=1)
    pivot("mean wire bytes/msg: exact 300-msg mix (steady-state prediction)",
          lambda r: f"{fmt(r['mean_wire_bytes_per_msg'], 1)}({fmt(r['predicted_steady_wire_bytes_per_msg'], 1)})", cells=["A_on"])
    hb = sorted({r["hash_only_bytes"] for r in all_rows if r["hash_only_bytes"] is not None})
    lines.append(f"hash-only wire bytes (modal per cell): {hb}; non-modal hash-only lines total: "
                 f"{sum(r['hash_only_nonmodal_lines'] for r in all_rows)}; garbled segment lines excluded: "
                 f"{sum(r['seg_garbled_lines'] for r in all_rows)}")
    lines.append("")
    lines.append("== deviations from predicted VALID / NO_CERT_YET (labelled) ==")
    devs = []
    for tag in combos:
        devs += deviation_lines([r for r in all_rows if r["combo"] == tag], [t for t in all_trials if t["combo"] == tag])
    lines += devs if devs else ["  (none)"]
    lines.append("")
    lines.append("== gate hard failures per combo x cell (from each combo's summary.csv) ==")
    hf = [f"  {r['combo']} {r['cell']}: {r['gate_hard_failures']}" for r in all_rows if r["gate_hard_failures"] not in ("0", "NA")]
    lines += hf if hf else ["  (none)"]
    timing_report(pivot)
    stem = str(Path(args.csv_summary).with_suffix(""))
    lines += write_pooled(pooled, f"{stem}_pooled_cert_verify.csv")
    if args.ab_reference:
        ref_rows, _, _ = load_run(Path(args.ab_reference), L, ttl, args.n_trials, defaultdict(lambda: defaultdict(list)))
        lines += write_ab_check(all_rows, ref_rows, L, f"{stem}_ab_check.csv")
    report = Path(args.report) if args.report else root / "report.txt"
    report.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {args.csv_summary}, {args.csv_per_trial}, {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
