#!/usr/bin/env python3
"""Parser + gate evaluator for the vehicle-count scaling sweep (numVehicles = 4/6/9 legit + 1
attacker, sustained-duration methodology of Update 21).

Differs from phase4_match_duration_aggregate.py (which is left untouched, and hardcodes L=2):
  * numVehicles is a parameter; the expected legit total is 300*L, never a constant 600.
  * reads .log or .log.gz, so a compressed level can be re-verified later.
  * evaluates the sweep's GATES and returns an exit code the driver acts on:
        0 = PASS (flags may be printed)   2 = STOP   3 = REVIEW (isolated hard failure(s) below the
        stop thresholds: finish the level, but do not start the next one)
  * every trial's receiver log must carry `[SocketConfig] ... actual=67108864`: a clamped
    SO_RCVBUF is silent (no crash, no warning) and can still reconcile, so it is a hard failure.
  * an UNPARSED stop_reason/rate is never a failure by itself (the transmitter's unsynchronized
    std::cout loses whole lines, CORRECTIONS.md #19); it is cross-checked against the backstop
    marker and the receiver-side attacker_total, and counted per level.
  * the D-cell rate gate uses the MEASURED rate (receiver attacker_total / attacker send time),
    never the startup-constant `achieved_rate_per_sec` line (CORRECTIONS.md #20).
Read-only on the logs."""
import argparse
import csv
import gzip
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phase4_clockstep_detect as cs

REPO = Path(__file__).resolve().parents[2]
ALL_CELLS = ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"]

# ---- gate constants (documented in the approved plan) ----
LEGIT_MSGS_PER_VEHICLE = 300
SOCKET_ACTUAL_MIN = 67108864          # 2 x the 32 MiB the receiver requests (kernel doubles it)
ATK_HIGH_MULT, ATK_LOW_MULT = 1.5, 0.5
PROXY_WINDOW_S = 30.2                 # legit window, used only when the attacker's own elapsed is lost
RATE_STOP_LO, RATE_STOP_HI, RATE_BAND = 500.0, 1010.0, 0.15
A_TRIAL_STOP, A_MEAN_STOP = 0.01, 0.002
PILOT_DROP_STOP, FULL_DROP_FLAG = 0.005, 0.02
UNPARSED_STOP_RATE, UNPARSED_MIN_TRIALS = 0.15, 20
FULL_CELL_FAIL_STOP, FULL_LEVEL_FAIL_STOP = 2, 3


# wall-clock-step detection state (set in main() when --trial-times is given)
TRIAL_TIMES, STEPS, STEP_ERR = None, [], None


def read_log(base):
    base = Path(base)
    if base.exists():
        return open(base, "r", encoding="utf-8", errors="replace").read()
    gz = Path(str(base) + ".gz")
    if gz.exists():
        with gzip.open(gz, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return None


def _num(pattern, text, cast, group=1):
    """Regex-extract + cast; None on no match or a malformed (race-spliced) number."""
    m = re.search(pattern, text)
    if not m:
        return None
    try:
        return cast(m.group(group))
    except ValueError:
        return None


def parse_recv(text):
    d = {}
    g = lambda pat, cast=int, grp=1: _num(pat, text, cast, grp)
    d["summary_present"] = "Falcon Verify Metrics Summary" in text
    d["legit_total"] = g(r"Legitimate messages processed: (\d+)")
    d["attacker_total"] = g(r"Attacker messages processed:\s+(\d+)")
    d["legit_valid"] = g(r"Legitimate VALID: (\d+)/\d+")
    d["drop_num"] = g(r"Legitimate drop rate, excluding startup: (\d+)/\d+")
    d["drop_denom"] = g(r"Legitimate drop rate, excluding startup: \d+/(\d+)")
    d["dm_num"] = g(r"Legitimate deadline-miss ratio.*?: (\d+)/\d+")
    d["atk_full"] = g(r"Attacker reached full crypto \(>=1 falcon_verify paid\): (\d+)/\d+")
    d["atk_cheap"] = g(r"Attacker rejected cheaply \(SPAM_FILTERED, zero crypto\): (\d+)/\d+")
    d["atk_pending"] = g(r"Attacker still pending \(NO_CERT_YET at run end\): (\d+)/\d+")
    d["legit_no_cert_yet"] = g(r"Legitimate NO_CERT_YET \(startup artifact, excluded from drop rate below\): (\d+)")
    d["cert_verify_n"] = g(r"\| cert avg=[\d.eE+-]+ p95=[\d.eE+-]+ \(n=(\d+)\)")
    d["lat_p50"] = g(r"Legitimate VALID-message latency \(ms\): p50=([\d.eE+-]+)", float)
    d["lat_p99"] = g(r"Legitimate VALID-message latency \(ms\): p50=[\d.eE+-]+ p95=[\d.eE+-]+ p99=([\d.eE+-]+)", float)
    d["lat_max"] = g(r"Legitimate VALID-message latency \(ms\):.*? max=([\d.eE+-]+)", float)
    d["loop_cost_avg_ms"] = g(r"FULL loop iteration cost \(ms, recv\+prints\+verify combined\): avg=([\d.eE+-]+)", float)
    d["sock_actual"] = g(r"\[SocketConfig\] requested SO_RCVBUF=\d+ actual \(post-clamp[^)]*\)=(\d+)")
    d["incomplete_run"] = "INCOMPLETE RUN" in text
    # Update 23 receivers print wall_clock_step=0|1 (steady vs. system elapsed differ by >100 ms); None = older log
    d["wall_clock_step"] = g(r"(?m)^wall_clock_step=(\d)$")
    return d


def parse_xmit(text, attacker_id):
    d = {}
    # Only the two values the transmitter can print are accepted. The unsynchronized stdout race can
    # cut the word mid-token (observed: "stop_reason=compl mess..." from an interleaved legit-vehicle
    # line, L=9 C_on trial 13); a partial word is UNPARSED, not a "different stop reason", and goes
    # through the same cross-checks (no backstop marker, attacker_total in range).
    m = re.search(r"stop_reason=(completion|backstop_timeout)(?![a-z_])", text)
    d["stop_reason"] = m.group(1) if m else None
    d["backstop_fired"] = "[AttackerBackstopFired]" in text
    d["nominal_rate"] = _num(r"achieved_rate_per_sec=([\d.]+)", text, float)   # startup CONSTANT, informational only
    elapsed = _num(rf"\[FloodRateCheck\] vehicle={attacker_id} num_msgs=\d+ nominal_inter_message_delay_ms=\d+ "
                   r"total_send_time_ms=(\d+(?:\.\d+)?) avg_actual_gap_ms=", text, float)
    src = "FloodRateCheck"
    if elapsed is None:
        elapsed = _num(r"actual_elapsed_ms=(\d+(?:\.\d+)?) messages_sent=", text, float)
        src = "AttackerRunSummary"
    d["elapsed_ms"], d["elapsed_src"] = elapsed, (src if elapsed is not None else None)
    return d


def load_update21_refs(csv_path):
    """Per-mode reference attacker_total (median) and D measured-rate baseline (median) from the
    corrected Update 21 export - the same box/binary/method, so a fair yardstick."""
    refs, rates = {"B": [], "C": [], "D": []}, []
    for r in csv.DictReader(open(csv_path, newline="", encoding="utf-8")):
        if r["cell"][0] in refs and r["reconciliation_status"] == "OK":
            refs[r["cell"][0]].append(int(r["attacker_total"]))
        if r["cell"].startswith("D_") and r["measured_rate_per_sec"] not in ("NA", "UNPARSED"):
            rates.append(float(r["measured_rate_per_sec"]))
    return {k: statistics.median(v) for k, v in refs.items()}, statistics.median(rates)


def cell_mode(cell):
    return cell[0]  # A / B / C / D


def annotate_clock(row, cell, t, args, recv):
    """Attach wall-clock-step evidence (journal 'Clock change detected') to a trial. A trial with late or dropped
    legit messages is EXPLAINED if a step inside its messaging window has the size of the late-message latency
    (the receiver's latency and the filter's STALE test are system_clock differences, so a forward step makes every
    message in flight look that much older; nothing was actually delayed - CORRECTIONS.md #21). NO_STEP_IN_WINDOW
    is the interesting case: a late/dropped message with no clock step is a candidate real delay."""
    row["clock_steps_in_window"] = None; row["clock_step_max_jump_ms"] = None; row["event_explained"] = "NA"
    has_event = (row.get("dm_num") or 0) > 0 or (row.get("drop_num") or 0) > 0
    if TRIAL_TIMES is None:
        return
    key = (args.num_vehicles, args.phase, cell, t)
    if STEP_ERR is not None or key not in TRIAL_TIMES:
        row["event_explained"] = "UNKNOWN" if has_event else "NA"
        return
    a, b = cs.window_for(TRIAL_TIMES[key][0])
    ws = cs.steps_in_window(STEPS, a, b)
    row["clock_steps_in_window"] = len(ws)
    row["clock_step_max_jump_ms"] = max((s["jump_ms"] for s in ws), default=0.0)
    if has_event:
        lats = cs.cluster_latencies(recv, legit_max=args.num_vehicles)
        row["event_explained"] = cs.explain_event(lats, ws)
        row["event_latencies"] = lats
        if row["event_explained"] == "NO_STEP_IN_WINDOW":
            row["flags"].append("UNEXPLAINED late/dropped legit msg: NO clock step in the trial's window - candidate REAL delay")
        elif row["event_explained"] == "STEP_SIZE_MISMATCH":
            row["flags"].append(f"late/dropped legit msg with a clock step in window but sizes do not match "
                                f"(latencies {[round(x) for x in lats]} ms vs jumps {[round(s['jump_ms']) for s in ws]} ms)")


def evaluate_trial(cell, t, args, refs, rate_baseline):
    """Classify one trial. Returns a row dict incl. fails (hard), flags, immediate (instant STOP)."""
    L = args.num_vehicles
    base = Path(args.outdir)
    row = {"cell": cell, "trial": t, "fails": [], "flags": [], "immediate": []}
    recv = read_log(base / f"{cell}_trial{t}_recv.log")
    xmit = read_log(base / f"{cell}_trial{t}_xmit.log")
    if recv is None:
        row["fails"].append("missing_recv_log")
        row["missing"] = True
        return row
    d = parse_recv(recv)
    row.update(d)
    expected = LEGIT_MSGS_PER_VEHICLE * L
    row["expected_legit"] = expected
    if not d["summary_present"]:
        row["fails"].append("recv_no_summary")
    if d["incomplete_run"]:
        row["fails"].append("incomplete_run")
    if d["legit_total"] != expected:
        row["fails"].append(f"legit_total={d['legit_total']}!={expected}")
    atk = d["attacker_total"] or 0
    if atk > 0 and (d["atk_full"] or 0) + (d["atk_cheap"] or 0) + (d["atk_pending"] or 0) != atk:
        row["fails"].append("attacker_3way_mismatch")
    if d["sock_actual"] is None:
        row["fails"].append("socket_config_missing")
    elif d["sock_actual"] < SOCKET_ACTUAL_MIN:
        row["fails"].append(f"socket_rcvbuf_clamped={d['sock_actual']}")
    rc_file = base / f"{cell}_trial{t}.rc"
    if rc_file.exists():
        rcs = dict(kv.split("=") for kv in rc_file.read_text().split())
        if any(v != "0" for v in rcs.values()):
            row["fails"].append(f"process_rc({rc_file.read_text().strip()})")

    mode = cell_mode(cell)
    if mode == "A":
        dm = (d["dm_num"] or 0) / expected if expected else 0.0
        drop = (d["drop_num"] or 0) / d["drop_denom"] if d["drop_denom"] else 0.0
        row["dm_frac"], row["drop_frac"] = dm, drop
        # Update 23: deadline misses and STALE drops are system_clock differences, so a trial the receiver itself
        # flagged wall_clock_step=1 is a soft warning - recorded, never a STOP (it would otherwise abort the driver).
        if max(dm, drop) > A_TRIAL_STOP and d.get("wall_clock_step") == 1:
            row["flags"].append(f"SOFT_WALL_CLOCK_STEP: a_cell_trial_over_{A_TRIAL_STOP:.0%}(dm={dm:.4%},drop={drop:.4%}) "
                                f"during wall_clock_step=1 - not a stop")
        elif max(dm, drop) > A_TRIAL_STOP:
            row["immediate"].append(f"a_cell_trial_over_{A_TRIAL_STOP:.0%}(dm={dm:.4%},drop={drop:.4%})")
        elif max(dm, drop) > 0:
            row["flags"].append(f"a_cell_nonzero(dm={d['dm_num']},drop={d['drop_num']})"
                                + (" during wall_clock_step=1" if d.get("wall_clock_step") == 1 else ""))
        if row["fails"]:
            row["immediate"].append("a_cell_hard_failure:" + ",".join(row["fails"]))
        annotate_clock(row, cell, t, args, recv)
        return row

    drop = (d["drop_num"] or 0) / d["drop_denom"] if d["drop_denom"] else 0.0
    row["drop_frac"] = drop
    row["dm_frac"] = (d["dm_num"] or 0) / expected if expected else 0.0
    x = parse_xmit(xmit, L) if xmit is not None else {"stop_reason": None, "backstop_fired": False,
                                                       "nominal_rate": None, "elapsed_ms": None, "elapsed_src": None}
    row.update({"stop_reason": x["stop_reason"], "nominal_rate": x["nominal_rate"],
                "elapsed_ms": x["elapsed_ms"], "elapsed_src": x["elapsed_src"]})
    if x["backstop_fired"]:
        row["fails"].append("backstop_fired")
    if x["stop_reason"] not in (None, "completion"):
        row["fails"].append(f"stop_reason={x['stop_reason']}")
    ref = refs[mode]
    if atk > ATK_HIGH_MULT * ref:
        row["fails"].append(f"attacker_total_high({atk}>{ATK_HIGH_MULT}x{ref:.0f}: backstop-consistent)")
    elif atk < ATK_LOW_MULT * ref:
        row["flags"].append(f"attacker_total_low({atk}<{ATK_LOW_MULT}x{ref:.0f})")
    if x["stop_reason"] is None and not any(f.startswith(("backstop", "attacker_total_high")) for f in row["fails"]):
        row["flags"].append("stop_reason_UNPARSED:probable-completion(no backstop marker, attacker_total in range)")
    # measured rate = receiver-side attacker_total / attacker's own send time (never the nominal constant)
    if x["elapsed_ms"] and d["attacker_total"] is not None:
        row["measured_rate"] = atk / (x["elapsed_ms"] / 1000.0)
    else:
        row["measured_rate"] = None
    if mode == "D":
        rate = row["measured_rate"]
        if rate is None:
            rate = atk / PROXY_WINDOW_S
            row["flags"].append("d_rate_from_proxy(attacker elapsed lost)")
        row["rate_used"] = rate
        if rate > RATE_STOP_HI or rate < RATE_STOP_LO:
            row["immediate"].append(f"d_rate_out_of_bounds({rate:.0f}/s not in {RATE_STOP_LO:.0f}-{RATE_STOP_HI:.0f})")
        elif abs(rate / rate_baseline - 1) > RATE_BAND:
            row["flags"].append(f"d_rate_off_baseline({rate:.0f}/s vs {rate_baseline:.0f}/s +/-{RATE_BAND:.0%})")
    annotate_clock(row, cell, t, args, recv)
    return row


def mmm(xs):
    return [f"{statistics.mean(xs):.10g}", f"{min(xs):.10g}", f"{max(xs):.10g}"] if xs else ["NA"] * 3


def summarize_cell(cell, rows, args):
    good = [r for r in rows if not r["fails"]]
    expected = LEGIT_MSGS_PER_VEHICLE * args.num_vehicles
    out = {"cell": cell, "n_trials": len(rows), "n_ok": len(good), "hard_failures": sum(1 for r in rows if r["fails"]),
           "flag_count": sum(len(r["flags"]) for r in rows)}
    val = [r["legit_valid"] / r["legit_total"] for r in good if r["legit_total"]]
    drop = [r["drop_frac"] for r in good]
    dm = [r["dm_frac"] for r in good]
    for k, xs in (("legit_valid_frac", val), ("legit_drop_frac", drop), ("deadline_miss_frac", dm)):
        out[k + "_mean"], out[k + "_min"], out[k + "_max"] = mmm(xs)
    atk = [r["attacker_total"] for r in good]
    out["attacker_total_mean"], out["attacker_total_min"], out["attacker_total_max"] = mmm(atk)
    has_atk = cell[0] != "A"
    full = [r["atk_full"] / r["attacker_total"] for r in good if has_atk and r["attacker_total"]]
    cheap = [r["atk_cheap"] / r["attacker_total"] for r in good if has_atk and r["attacker_total"]]
    out["attacker_full_crypto_frac_mean"], out["attacker_full_crypto_frac_min"], out["attacker_full_crypto_frac_max"] = mmm(full)
    out["attacker_cheap_reject_frac_mean"], out["attacker_cheap_reject_frac_min"], out["attacker_cheap_reject_frac_max"] = mmm(cheap)
    pend = [r["atk_pending"] for r in good if has_atk]
    out["attacker_pending_min"], out["attacker_pending_max"] = (min(pend), max(pend)) if pend else ("NA", "NA")
    cv = [r["cert_verify_n"] for r in good if r.get("cert_verify_n") is not None]
    out["cert_verify_n_mean"], out["cert_verify_n_min"], out["cert_verify_n_max"] = mmm(cv)
    if has_atk:
        dist = Counter((r["stop_reason"] or "UNPARSED") for r in good)
        out["stop_reason_distribution"] = ";".join(f"{k}={v}" for k, v in sorted(dist.items()))
        out["stop_reason_unparsed"] = dist.get("UNPARSED", 0)
    else:
        out["stop_reason_distribution"], out["stop_reason_unparsed"] = "NA", "NA"
    mr = [r["measured_rate"] for r in good if r.get("measured_rate")]
    out["measured_rate_per_sec_mean"], out["measured_rate_per_sec_min"], out["measured_rate_per_sec_max"] = mmm(mr)
    out["measured_rate_n"] = len(mr) if has_atk else "NA"
    p99 = [r["lat_p99"] for r in good if r.get("lat_p99") is not None]
    out["legit_latency_p99_ms_mean"], _, out["legit_latency_p99_ms_max"] = mmm(p99)
    lc = [r["loop_cost_avg_ms"] for r in good if r.get("loop_cost_avg_ms") is not None]
    out["receiver_loop_cost_avg_ms_mean"], _, out["receiver_loop_cost_avg_ms_max"] = mmm(lc)
    triples = [(r["legit_valid"], r["drop_num"], r["dm_num"]) for r in good]
    modal = Counter(triples).most_common(1)[0][0] if triples else None
    out["modal_valid_drop_deadline"] = "/".join(str(v) for v in modal) if modal else "NA"
    out["deviating_trials"] = sum(1 for t in triples if t != modal)
    out["trials_valid_ne_modal"] = sum(1 for t in triples if modal and t[0] != modal[0])
    out["trials_drop_gt0"] = sum(1 for t in triples if (t[1] or 0) > 0)
    out["trials_deadline_miss_gt0"] = sum(1 for t in triples if (t[2] or 0) > 0)
    out["clock_step_exposed_trials"] = sum(1 for r in rows if (r.get("clock_steps_in_window") or 0) > 0) if TRIAL_TIMES is not None else "NA"
    out["events_explained_by_clock_step"] = sum(1 for r in rows if r.get("event_explained") == "YES") if TRIAL_TIMES is not None else "NA"
    out["events_unexplained"] = sum(1 for r in rows if r.get("event_explained") in ("NO_STEP_IN_WINDOW", "STEP_SIZE_MISMATCH")) if TRIAL_TIMES is not None else "NA"
    out["wall_clock_step_trials"] = sum(1 for r in rows if r.get("wall_clock_step") == 1)
    out["_drop_mean"] = statistics.mean(drop) if drop else 0.0
    out["_dm_mean"] = statistics.mean(dm) if dm else 0.0
    # STOP-test means exclude receiver-flagged clock-step trials (Update 23); the reported means above keep them.
    nostep = [r for r in good if r.get("wall_clock_step") != 1]
    out["_drop_mean_nostep"] = statistics.mean([r["drop_frac"] for r in nostep]) if nostep else 0.0
    out["_dm_mean_nostep"] = statistics.mean([r["dm_frac"] for r in nostep]) if nostep else 0.0
    return out


PER_TRIAL_COLS = ["cell", "trial", "legit_valid_count", "legit_drop_count", "deadline_miss_count", "attacker_total",
                  "attacker_full_crypto", "attacker_cheap_reject", "attacker_pending", "stop_reason",
                  "nominal_rate_per_sec", "measured_rate_per_sec", "measured_elapsed_ms", "measured_elapsed_source",
                  "trial_status", "fails", "flags", "legit_total", "legit_drop_denominator", "legit_no_cert_yet",
                  "socket_rcvbuf_actual", "legit_latency_p50_ms", "legit_latency_p99_ms", "legit_latency_max_ms",
                  "receiver_loop_cost_avg_ms", "cert_verify_n",
                  "clock_steps_in_window", "clock_step_max_jump_ms", "event_explained_by_clock_step"]
SUMMARY_COLS = None  # taken from the first summary row


def per_trial_csv_row(r):
    na = lambda v: "NA" if v is None else v
    is_a = r["cell"][0] == "A"
    return {"cell": r["cell"], "trial": r["trial"], "legit_valid_count": na(r.get("legit_valid")),
            "legit_drop_count": na(r.get("drop_num")), "deadline_miss_count": na(r.get("dm_num")),
            "attacker_total": na(r.get("attacker_total")), "attacker_full_crypto": na(r.get("atk_full")),
            "attacker_cheap_reject": na(r.get("atk_cheap")), "attacker_pending": na(r.get("atk_pending")),
            "stop_reason": "NA" if is_a else (r.get("stop_reason") or "UNPARSED"),
            "nominal_rate_per_sec": na(r.get("nominal_rate")) if r["cell"][0] == "D" else "NA",
            "measured_rate_per_sec": "NA" if is_a else ("UNPARSED" if not r.get("measured_rate") else r["measured_rate"]),
            "measured_elapsed_ms": "NA" if is_a else ("UNPARSED" if not r.get("elapsed_ms") else r["elapsed_ms"]),
            "measured_elapsed_source": "NA" if is_a else (r.get("elapsed_src") or "UNPARSED"),
            "trial_status": "FAIL" if r["fails"] else ("OK+flags" if r["flags"] else "OK"),
            "fails": ";".join(r["fails"]), "flags": ";".join(r["flags"]),
            "legit_total": na(r.get("legit_total")), "legit_drop_denominator": na(r.get("drop_denom")),
            "legit_no_cert_yet": na(r.get("legit_no_cert_yet")), "socket_rcvbuf_actual": na(r.get("sock_actual")),
            "legit_latency_p50_ms": na(r.get("lat_p50")), "legit_latency_p99_ms": na(r.get("lat_p99")),
            "legit_latency_max_ms": na(r.get("lat_max")), "receiver_loop_cost_avg_ms": na(r.get("loop_cost_avg_ms")),
            "cert_verify_n": na(r.get("cert_verify_n")),
            "clock_steps_in_window": na(r.get("clock_steps_in_window")),
            "clock_step_max_jump_ms": "NA" if r.get("clock_step_max_jump_ms") is None else f"{r['clock_step_max_jump_ms']:.0f}",
            "event_explained_by_clock_step": r.get("event_explained", "NA")}


def main():
    global LEGIT_MSGS_PER_VEHICLE
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--num-vehicles", type=int, required=True)
    ap.add_argument("--n-trials", type=int, required=True)
    ap.add_argument("--phase", choices=["pilot", "full"], required=True)
    ap.add_argument("--cells", default=",".join(ALL_CELLS))
    ap.add_argument("--update21-csv", default=str(REPO / "exports/update21_per_trial.csv"))
    ap.add_argument("--ref-atk", default=None, help="override per-mode reference attacker_total, e.g. B=125000,C=126000,D=24000")
    ap.add_argument("--rate-baseline", type=float, default=None)
    ap.add_argument("--allow-missing", action="store_true", help="skip trials whose logs do not exist yet (resume verification)")
    ap.add_argument("--csv-per-trial", help="default: <outdir>/per_trial.csv (see --no-csv)")
    ap.add_argument("--csv-summary", help="default: <outdir>/summary.csv (see --no-csv)")
    ap.add_argument("--no-csv", action="store_true", help="skip writing the default per-trial/summary CSVs")
    ap.add_argument("--verdict-json")
    ap.add_argument("--trial-times", help="the sweep's trial_times.tsv; enables journal-based wall-clock-step detection")
    ap.add_argument("--journal-json", help="saved `journalctl -o json` dump instead of calling journalctl (tests/offline reanalysis)")
    ap.add_argument("--bad-trials", help="write 'cell trial' lines for trials with hard failures (driver re-runs them)")
    ap.add_argument("--msgs-per-vehicle", type=int, default=LEGIT_MSGS_PER_VEHICLE,
                    help="config numMessages (Update 23: the segmentation grid runs 200)")
    args = ap.parse_args()
    LEGIT_MSGS_PER_VEHICLE = args.msgs_per_vehicle

    if not args.no_csv:
        if args.csv_per_trial is None:
            args.csv_per_trial = str(Path(args.outdir) / "per_trial.csv")
        if args.csv_summary is None:
            args.csv_summary = str(Path(args.outdir) / "summary.csv")

    global TRIAL_TIMES, STEPS, STEP_ERR
    if args.trial_times:
        TRIAL_TIMES = cs.load_trial_times(args.trial_times)
        mine = [v for k, v in TRIAL_TIMES.items() if k[0] == args.num_vehicles and k[1] == args.phase]
        if mine:
            STEPS, STEP_ERR = cs.fetch_steps(min(v[0] for v in mine), max(v[1] for v in mine), args.journal_json)
        else:
            STEPS, STEP_ERR = [], "no trial_times rows for this level/phase"
    refs, base_rate = load_update21_refs(args.update21_csv)
    if args.ref_atk:
        refs.update({kv.split("=")[0]: float(kv.split("=")[1]) for kv in args.ref_atk.split(",")})
    rate_baseline = args.rate_baseline or base_rate
    cells = [c for c in args.cells.split(",") if c]
    L = args.num_vehicles
    print(f"[gate] level L={L} phase={args.phase} cells={cells} n_trials={args.n_trials} dir={args.outdir}")
    print(f"[gate] refs attacker_total(B/C/D)={refs['B']:.0f}/{refs['C']:.0f}/{refs['D']:.0f} "
          f"D measured-rate baseline={rate_baseline:.1f}/s expected_legit={LEGIT_MSGS_PER_VEHICLE * L}")

    all_rows, cell_rows = [], {}
    for cell in cells:
        rows = []
        for t in range(1, args.n_trials + 1):
            r = evaluate_trial(cell, t, args, refs, rate_baseline)
            if r.get("missing") and args.allow_missing:
                continue
            rows.append(r)
        cell_rows[cell] = rows
        all_rows += rows

    immediate, flags = [], []
    fails_by_cell = {}
    summaries = []
    for cell, rows in cell_rows.items():
        s = summarize_cell(cell, rows, args)
        summaries.append(s)
        fails_by_cell[cell] = s["hard_failures"]
        for r in rows:
            for reason in r["immediate"]:
                immediate.append((cell, r["trial"], reason))
            for f in r["flags"]:
                flags.append((cell, r["trial"], f))
        if rows and cell[0] == "A":
            for k, name in (("_dm_mean", "deadline-miss"), ("_drop_mean", "drop")):
                if s[k + "_nostep"] > A_MEAN_STOP:
                    immediate.append((cell, None, f"a_cell_mean_{name}={s[k + '_nostep']:.4%}>{A_MEAN_STOP:.1%} "
                                                  f"(wall_clock_step=1 trials excluded)"))
                elif s[k] > A_MEAN_STOP:
                    flags.append((cell, None, f"SOFT_WALL_CLOCK_STEP: a_cell_mean_{name}={s[k]:.4%}>{A_MEAN_STOP:.1%} only "
                                              f"with the {s['wall_clock_step_trials']} wall_clock_step=1 trial(s) included - not a stop"))
        if rows and args.phase == "pilot" and s["_drop_mean"] > PILOT_DROP_STOP:
            immediate.append((cell, None, f"pilot_cell_mean_drop={s['_drop_mean']:.4%}>{PILOT_DROP_STOP:.1%}"))
        elif rows and args.phase == "pilot" and s["_drop_mean"] > 0:
            flags.append((cell, None, f"pilot_cell_mean_drop={s['_drop_mean']:.4%} (<= {PILOT_DROP_STOP:.1%})"))
        if rows and args.phase == "full" and s["_drop_mean"] > FULL_DROP_FLAG:
            flags.append((cell, None, f"FULL_RUN_cell_mean_drop={s['_drop_mean']:.4%}>{FULL_DROP_FLAG:.0%} (finding, not a stop)"))

    atk_rows = [r for r in all_rows if r["cell"][0] != "A" and not r.get("missing")]
    n_unparsed = sum(1 for r in atk_rows if r.get("stop_reason") is None)
    unparsed_rate = n_unparsed / len(atk_rows) if atk_rows else 0.0
    if len(atk_rows) >= UNPARSED_MIN_TRIALS and unparsed_rate > UNPARSED_STOP_RATE:
        immediate.append(("*", None, f"unparsed_stop_reason_rate={unparsed_rate:.1%}>{UNPARSED_STOP_RATE:.0%} "
                                     f"({n_unparsed}/{len(atk_rows)}; Update 21 baseline 3.3%)"))
    total_fail = sum(fails_by_cell.values())

    if args.phase == "pilot":
        verdict = "STOP" if (immediate or total_fail) else "PASS"
    else:
        if immediate or any(v >= FULL_CELL_FAIL_STOP for v in fails_by_cell.values()) or total_fail >= FULL_LEVEL_FAIL_STOP:
            verdict = "STOP"
        elif total_fail >= 1:
            verdict = "REVIEW"
        else:
            verdict = "PASS"

    # ---- report ----
    for s in summaries:
        print(f"\n--- {s['cell']} (trials={s['n_trials']} ok={s['n_ok']} hard_failures={s['hard_failures']}) ---")
        print(f"  legit VALID frac     mean/min/max: {s['legit_valid_frac_mean']} / {s['legit_valid_frac_min']} / {s['legit_valid_frac_max']}   modal valid/drop/dm: {s['modal_valid_drop_deadline']}")
        print(f"  legit drop frac      mean/min/max: {s['legit_drop_frac_mean']} / {s['legit_drop_frac_min']} / {s['legit_drop_frac_max']}   deviating trials: {s['deviating_trials']} (valid!=modal {s['trials_valid_ne_modal']}, drop>0 {s['trials_drop_gt0']}, dm>0 {s['trials_deadline_miss_gt0']})")
        print(f"  deadline-miss frac   mean/min/max: {s['deadline_miss_frac_mean']} / {s['deadline_miss_frac_min']} / {s['deadline_miss_frac_max']}")
        print(f"  legit latency p99 ms mean/max: {s['legit_latency_p99_ms_mean']} / {s['legit_latency_p99_ms_max']}   receiver loop cost avg ms mean/max: {s['receiver_loop_cost_avg_ms_mean']} / {s['receiver_loop_cost_avg_ms_max']}")
        if s["cell"][0] != "A":
            print(f"  attacker_total       mean/min/max: {s['attacker_total_mean']} / {s['attacker_total_min']} / {s['attacker_total_max']}")
            print(f"  attacker full-crypto frac mean {s['attacker_full_crypto_frac_mean']} | cheap-reject frac mean/min/max {s['attacker_cheap_reject_frac_mean']} / {s['attacker_cheap_reject_frac_min']} / {s['attacker_cheap_reject_frac_max']} | pending {s['attacker_pending_min']}-{s['attacker_pending_max']} | cert-sig verify n mean {s['cert_verify_n_mean']}")
            print(f"  stop_reason: {s['stop_reason_distribution']}   measured send rate mean/min/max: {s['measured_rate_per_sec_mean']} / {s['measured_rate_per_sec_min']} / {s['measured_rate_per_sec_max']} (n={s['measured_rate_n']})")
    print("\n=== hard failures (individually listed) ===")
    bad = [r for r in all_rows if r["fails"]]
    for r in bad:
        print(f"  FAIL {r['cell']} trial {r['trial']}: {'; '.join(r['fails'])}")
    print("  (none)" if not bad else "")
    print("=== deviating-but-reconciled trials (individually listed) ===")
    dev_lines = 0
    for cell, rows in cell_rows.items():
        good = [r for r in rows if not r["fails"]]
        triples = [(r["legit_valid"], r["drop_num"], r["dm_num"]) for r in good]
        modal = Counter(triples).most_common(1)[0][0] if triples else None
        for r in good:
            tr = (r["legit_valid"], r["drop_num"], r["dm_num"])
            if modal and tr != modal:
                dev_lines += 1
                print(f"  {cell} trial {r['trial']}: valid/drop/deadline-miss = {tr[0]}/{tr[1]}/{tr[2]} (modal {modal[0]}/{modal[1]}/{modal[2]})")
    print("  (none)" if not dev_lines else "")
    if TRIAL_TIMES is not None:
        print("=== late/dropped legit messages vs wall-clock steps (journal 'Clock change detected') ===")
        if STEP_ERR:
            print(f"  DETECTION UNAVAILABLE: {STEP_ERR}")
        else:
            allr = [r for r in all_rows if not r.get("missing")]
            exposed = sum(1 for r in allr if (r.get("clock_steps_in_window") or 0) > 0)
            print(f"  {len(STEPS)} steps in the range; trials exposed to >=1 step inside their messaging window: {exposed}/{len(allr)}")
            evs = [r for r in allr if r.get("event_explained") not in (None, "NA")]
            cnt = Counter(r["event_explained"] for r in evs)
            print(f"  trials with a late/dropped legit message: {len(evs)}  -> explained by a step: {cnt.get('YES', 0)}, "
                  f"step-size mismatch: {cnt.get('STEP_SIZE_MISMATCH', 0)}, NO step in window (candidate real delay): {cnt.get('NO_STEP_IN_WINDOW', 0)}")
            for r in evs:
                print(f"    {r['cell']} trial {r['trial']}: {r['event_explained']}  (late-message latency clusters {[round(x) for x in r.get('event_latencies', [])]} ms; "
                      f"steps in window {r.get('clock_steps_in_window')}, largest jump {r.get('clock_step_max_jump_ms') or 0:.0f} ms)")
    print("=== flags (logged, not stops) ===")
    for cell, t, f in flags:
        print(f"  FLAG {cell} trial {t if t else '*'}: {f}")
    print("  (none)" if not flags else "")
    print("=== IMMEDIATE-STOP conditions ===")
    for cell, t, reason in immediate:
        print(f"  STOP {cell} trial {t if t else '*'}: {reason}")
    print("  (none)" if not immediate else "")
    print(f"\nUNPARSED stop_reason: {n_unparsed}/{len(atk_rows)} attacker trials ({unparsed_rate:.1%}; Update 21 baseline 15/450 = 3.3%)")
    print(f"VERDICT: {verdict} hard_failures={total_fail} by_cell={fails_by_cell} immediate={len(immediate)} flags={len(flags)}")

    if args.csv_per_trial:
        Path(args.csv_per_trial).parent.mkdir(parents=True, exist_ok=True)
        with open(args.csv_per_trial, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=PER_TRIAL_COLS, lineterminator="\n")
            w.writeheader()
            w.writerows(per_trial_csv_row(r) for r in all_rows)
    if args.csv_summary and summaries:
        cols = [k for k in summaries[0] if not k.startswith("_")]
        with open(args.csv_summary, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, lineterminator="\n", extrasaction="ignore")
            w.writeheader()
            w.writerows(summaries)
    if args.bad_trials:
        Path(args.bad_trials).write_text("".join(f"{r['cell']} {r['trial']}\n" for r in bad))
    if args.verdict_json:
        Path(args.verdict_json).write_text(json.dumps({
            "verdict": verdict, "hard_failures": total_fail, "fails_by_cell": fails_by_cell,
            "immediate": [list(i) for i in immediate], "flags": len(flags),
            "unparsed_stop_reason": n_unparsed, "attacker_trials": len(atk_rows)}, indent=1))
    return {"PASS": 0, "STOP": 2, "REVIEW": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
