#!/usr/bin/env python3
"""Duration-mode-aware aggregator for the sustained-duration A/B/C/D re-run
(attackerMatchLegitDuration:true, context/UPDATES.md Update 21). Unlike phase4_aggregate.py /
phase4_pilot_aggregate.py (both correctly left untouched - they aggregate the OLD
fixed-numAttackerMessages matrix, where BUGS.md already documents them as not
duration-mode-aware), this script's reconciliation checks the LEGIT-ONLY invariant
(legit_total == numMessages*numVehicles), since in duration mode the attacker's own
message count is an OUTPUT, not an input - there is no fixed total to check it against.
A_off/A_on have numAttackers=0, so attackerMatchLegitDuration never actually engages for
them (main.cpp only opens duration mode when num_attackers > 0) - they still use the
original count-mode receive path, but the same legit-only check applies unchanged.

Attacker outcome counts (full_crypto/cheap_reject/pending) are still cross-checked against
each other (3-way sum == attacker_total) as an internal consistency invariant - that holds
regardless of duration mode, since it's just accounting for whatever attacker messages
actually arrived.

Also opportunistically parses the transmitter log's [AttackerRunSummary]/[FloodRateCheck]
lines for stop_reason/actual_elapsed_ms/messages_sent - these come from a
multi-threaded, unsynchronized std::cout (see context/UPDATES.md Update 21 finding), so a field
coming back empty for a given trial is reported as such, not treated as a parse bug.
"""
import argparse
import csv
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

_ap = argparse.ArgumentParser()
_ap.add_argument("--outdir", default=str(Path(__file__).resolve().parents[2] / "phase4_raw_logs" / "phase4_pilot_match_duration_trials"))
_ap.add_argument("--n-trials", type=int, default=3)
# Optional structured export (Update 21 CSV export). With neither flag given, stdout is
# byte-identical to before these flags existed; "wrote ..." confirmations go to stderr.
_ap.add_argument("--csv-per-trial", default=None, help="write one row per trial (every trial, any status)")
_ap.add_argument("--csv-summary", default=None, help="write one row per cell, computed from the reconciled trials")
_args = _ap.parse_args()

OUTDIR = Path(_args.outdir)
N_TRIALS = _args.n_trials
NUM_MSGS = 300
NUM_VEHICLES = 2
EXPECTED_LEGIT_TOTAL = NUM_MSGS * NUM_VEHICLES  # 600, same for every cell

CELLS = ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"]


def read(fn):
    return open(fn, "r", encoding="utf-8", errors="replace").read()


def _num(pattern, text, cast, group=1):
    """Regex-extract + cast, returning None on any failure instead of raising - the
    transmitter log's multi-threaded stdout race (context/UPDATES.md Update 21) can splice two
    threads' digits together (e.g. "101.93630218.4"), which looks like a match but isn't
    a valid number. A field lost this way is reported as unavailable, not a crash."""
    m = re.search(pattern, text)
    if not m:
        return None
    try:
        return cast(m.group(group))
    except ValueError:
        return None


def parse_recv_summary(text):
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
    m = re.search(r"message avg=([\d.eE+-]+) p95=([\d.eE+-]+) \(n=(\d+)\) \| cert avg=([\d.eE+-]+) p95=([\d.eE+-]+) \(n=(\d+)\)", text)
    d["cert_verify_n"] = int(m.group(6)) if m else None
    d["incomplete_run"] = "INCOMPLETE RUN" in text
    d["receive_end_of_run"] = "[ReceiveEndOfRun]" in text
    return d


def parse_xmit_diagnostics(text):
    """Best-effort only - transmitter stdout is multi-threaded and unsynchronized
    (context/UPDATES.md Update 21), so any field can come back None for a given trial."""
    d = {}
    m = re.search(r"stop_reason=([a-z_]+)", text)
    d["stop_reason"] = m.group(1) if m else None
    d["actual_elapsed_ms"] = _num(r"actual_elapsed_ms=([\d.]+)", text, float)
    d["messages_sent"] = _num(r"messages_sent=(\d+)", text, int)
    d["completion_lag_ms"] = _num(r"completion_lag_ms=([\d.eE+-]+)", text, float)
    d["backstop_fired"] = "[AttackerBackstopFired]" in text
    # NOTE: this key keeps its historical name so the stdout report is unchanged, but the value
    # is the NOMINAL rate main.cpp computes at startup (1000/flood_delay_ms), not a measurement
    # (CORRECTIONS.md #20). The CSVs call it nominal_rate_per_sec and add a measured rate.
    d["achieved_rate_per_sec"] = _num(r"achieved_rate_per_sec=([\d.]+)", text, float)
    # Measured attacker send time, from the attacker's OWN transmitter lines (attacker id ==
    # NUM_VEHICLES). Each pattern requires the number to be followed by the next field's name,
    # so a number spliced together by the stdout race ("101.93630218.4") does not match.
    # Never imputed: if neither line survived, the elapsed time is simply unavailable.
    elapsed = _num(rf"\[FloodRateCheck\] vehicle={NUM_VEHICLES} num_msgs=\d+ nominal_inter_message_delay_ms=\d+ "
                   r"total_send_time_ms=(\d+(?:\.\d+)?) avg_actual_gap_ms=", text, float)
    source = "FloodRateCheck"
    if elapsed is None:
        elapsed = _num(r"actual_elapsed_ms=(\d+(?:\.\d+)?) messages_sent=", text, float)
        source = "AttackerRunSummary"
    d["measured_elapsed_ms"] = elapsed
    d["measured_elapsed_source"] = source if elapsed is not None else None
    return d


PER_TRIAL_COLUMNS = [
    "cell", "trial", "legit_valid_count", "legit_drop_count", "deadline_miss_count",
    "attacker_total", "attacker_full_crypto", "attacker_cheap_reject", "attacker_pending",
    "stop_reason", "nominal_rate_per_sec", "reconciliation_status",
    # trailing extras: denominators the fractions need, and the measured send rate
    "legit_total", "legit_drop_denominator",
    "measured_rate_per_sec", "measured_elapsed_ms", "measured_elapsed_source",
]


def _na(v):
    return "NA" if v is None else v


def _csv_row(cell, t, d, status):
    """One per-trial CSV row. stop_reason/achieved_rate come from the transmitter log, whose
    multi-threaded stdout can lose a whole line: 'NA' = not applicable to this cell (no
    attacker / not a rate-capped cell), 'UNPARSED' = applicable but not recoverable."""
    if cell.startswith("A_"):
        stop_reason = "NA"
    else:
        stop_reason = d.get("stop_reason") or "UNPARSED"
    if cell.startswith("D_"):
        rate = d.get("achieved_rate_per_sec")
        rate = "UNPARSED" if rate is None else rate
    else:
        rate = "NA"
    # measured send rate = receiver-side attacker_total / attacker's own send elapsed time
    elapsed_ms = d.get("measured_elapsed_ms")
    atk = d.get("attacker_total")
    if cell.startswith("A_"):
        measured, measured_ms, measured_src = "NA", "NA", "NA"
    elif elapsed_ms and atk is not None:
        measured, measured_ms, measured_src = atk / (elapsed_ms / 1000.0), elapsed_ms, d["measured_elapsed_source"]
    else:
        measured, measured_ms, measured_src = "UNPARSED", "UNPARSED", "UNPARSED"
    return {
        "cell": cell, "trial": t,
        "legit_valid_count": _na(d.get("legit_valid")),
        "legit_drop_count": _na(d.get("drop_num")),
        "deadline_miss_count": _na(d.get("deadline_miss_num")),
        "attacker_total": _na(d.get("attacker_total")),
        "attacker_full_crypto": _na(d.get("atk_full_crypto")),
        "attacker_cheap_reject": _na(d.get("atk_cheap_reject")),
        "attacker_pending": _na(d.get("atk_pending")),
        "stop_reason": stop_reason, "nominal_rate_per_sec": rate,
        "reconciliation_status": status,
        "legit_total": _na(d.get("legit_total")),
        "legit_drop_denominator": _na(d.get("drop_denom")),
        "measured_rate_per_sec": measured, "measured_elapsed_ms": measured_ms,
        "measured_elapsed_source": measured_src,
    }


def _fmt(x):
    return f"{x:.10g}"


def _mmm(xs):
    """mean/min/max as formatted strings, or NA x3 when there is nothing to aggregate."""
    if not xs:
        return ["NA", "NA", "NA"]
    return [_fmt(statistics.mean(xs)), _fmt(min(xs)), _fmt(max(xs))]


SUMMARY_COLUMNS = [
    "cell", "n_trials", "n_reconciled",
    "legit_valid_frac_mean", "legit_valid_frac_min", "legit_valid_frac_max",
    "legit_drop_frac_mean", "legit_drop_frac_min", "legit_drop_frac_max",
    "deadline_miss_frac_mean", "deadline_miss_frac_min", "deadline_miss_frac_max",
    "attacker_total_mean", "attacker_total_min", "attacker_total_max",
    "attacker_full_crypto_frac_mean", "attacker_full_crypto_frac_min", "attacker_full_crypto_frac_max",
    "attacker_cheap_reject_frac_mean", "attacker_cheap_reject_frac_min", "attacker_cheap_reject_frac_max",
    "attacker_pending_min", "attacker_pending_max",
    "stop_reason_distribution",
    "nominal_rate_per_sec_mean", "nominal_rate_per_sec_min", "nominal_rate_per_sec_max",
    "nominal_rate_n_parsed",
    "measured_rate_per_sec_mean", "measured_rate_per_sec_min", "measured_rate_per_sec_max",
    "measured_rate_n",
    "modal_valid_drop_deadline", "deviating_trials",
    "trials_valid_ne_modal", "trials_drop_gt0", "trials_deadline_miss_gt0",
]


def _summary_row(cell, rows):
    """Per-cell summary from that cell's per-trial rows. Stats use reconciled (OK) trials only,
    same population the stdout report uses; n_trials/n_reconciled expose any exclusions."""
    ok = [r for r in rows if r["reconciliation_status"] == "OK"]
    out = {"cell": cell, "n_trials": len(rows), "n_reconciled": len(ok)}
    valid = [r["legit_valid_count"] / r["legit_total"] for r in ok]
    drop = [r["legit_drop_count"] / r["legit_drop_denominator"] if r["legit_drop_denominator"] else 0.0 for r in ok]
    dm = [r["deadline_miss_count"] / r["legit_total"] for r in ok]
    for name, xs in (("legit_valid_frac", valid), ("legit_drop_frac", drop), ("deadline_miss_frac", dm)):
        out[name + "_mean"], out[name + "_min"], out[name + "_max"] = _mmm(xs)
    atk = [r["attacker_total"] for r in ok]
    out["attacker_total_mean"], out["attacker_total_min"], out["attacker_total_max"] = _mmm(atk)
    has_atk = not cell.startswith("A_")
    full = [r["attacker_full_crypto"] / r["attacker_total"] for r in ok if has_atk and r["attacker_total"] > 0]
    cheap = [r["attacker_cheap_reject"] / r["attacker_total"] for r in ok if has_atk and r["attacker_total"] > 0]
    out["attacker_full_crypto_frac_mean"], out["attacker_full_crypto_frac_min"], out["attacker_full_crypto_frac_max"] = _mmm(full)
    out["attacker_cheap_reject_frac_mean"], out["attacker_cheap_reject_frac_min"], out["attacker_cheap_reject_frac_max"] = _mmm(cheap)
    pend = [r["attacker_pending"] for r in ok if has_atk]
    out["attacker_pending_min"] = min(pend) if pend else "NA"
    out["attacker_pending_max"] = max(pend) if pend else "NA"
    if has_atk:
        dist = Counter(r["stop_reason"] for r in ok)
        out["stop_reason_distribution"] = ";".join(f"{k}={v}" for k, v in sorted(dist.items()))
    else:
        out["stop_reason_distribution"] = "NA"
    rates = [r["nominal_rate_per_sec"] for r in ok if isinstance(r["nominal_rate_per_sec"], float)]
    out["nominal_rate_per_sec_mean"], out["nominal_rate_per_sec_min"], out["nominal_rate_per_sec_max"] = _mmm(rates)
    out["nominal_rate_n_parsed"] = len(rates) if cell.startswith("D_") else "NA"
    measured = [r["measured_rate_per_sec"] for r in ok if isinstance(r["measured_rate_per_sec"], float)]
    out["measured_rate_per_sec_mean"], out["measured_rate_per_sec_min"], out["measured_rate_per_sec_max"] = _mmm(measured)
    out["measured_rate_n"] = len(measured) if has_atk else "NA"
    triples = [(r["legit_valid_count"], r["legit_drop_count"], r["deadline_miss_count"]) for r in ok]
    modal = Counter(triples).most_common(1)[0][0] if triples else None
    out["modal_valid_drop_deadline"] = "/".join(str(v) for v in modal) if modal else "NA"
    out["deviating_trials"] = sum(1 for t in triples if t != modal)
    out["trials_valid_ne_modal"] = sum(1 for t in triples if modal and t[0] != modal[0])
    out["trials_drop_gt0"] = sum(1 for t in triples if t[1] > 0)
    out["trials_deadline_miss_gt0"] = sum(1 for t in triples if t[2] > 0)
    return out


def _write_csv(path, columns, dict_rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, lineterminator="\n")
        w.writeheader()
        w.writerows(dict_rows)
    print(f"wrote {len(dict_rows)} rows -> {p}", file=sys.stderr)


def main():
    all_ok = True
    results = {}
    csv_rows = []
    for cell in CELLS:
        trials = []
        for t in range(1, N_TRIALS + 1):
            recv_fn = OUTDIR / f"{cell}_trial{t}_recv.log"
            xmit_fn = OUTDIR / f"{cell}_trial{t}_xmit.log"
            if not recv_fn.exists():
                print(f"MISSING: {recv_fn}"); all_ok = False
                csv_rows.append(_csv_row(cell, t, {}, "FAIL:missing_recv_log"))
                continue
            d = parse_recv_summary(read(recv_fn))
            d["trial"] = t
            if xmit_fn.exists():
                d.update(parse_xmit_diagnostics(read(xmit_fn)))

            if d["incomplete_run"]:
                print(f"FAIL [{cell} trial {t}]: INCOMPLETE RUN "
                      f"(legit_total={d['legit_total']}, expected={EXPECTED_LEGIT_TOTAL})")
                all_ok = False
                csv_rows.append(_csv_row(cell, t, d, "FAIL:incomplete_run"))
                continue
            if d["legit_total"] != EXPECTED_LEGIT_TOTAL:
                print(f"FAIL [{cell} trial {t}]: legit-only mismatch actual={d['legit_total']} "
                      f"expected={EXPECTED_LEGIT_TOTAL}")
                all_ok = False
                csv_rows.append(_csv_row(cell, t, d, f"FAIL:legit_total={d['legit_total']}"))
                continue
            atk_total = d["attacker_total"] or 0
            atk_sum = (d["atk_full_crypto"] or 0) + (d["atk_cheap_reject"] or 0) + (d["atk_pending"] or 0)
            if atk_total > 0 and atk_sum != atk_total:
                print(f"FAIL [{cell} trial {t}]: attacker 3-way reconciliation mismatch "
                      f"({d['atk_full_crypto']}+{d['atk_cheap_reject']}+{d['atk_pending']}={atk_sum} != {atk_total})")
                all_ok = False
                csv_rows.append(_csv_row(cell, t, d, "FAIL:attacker_3way"))
                continue
            csv_rows.append(_csv_row(cell, t, d, "OK"))
            if d.get("backstop_fired"):
                print(f"FLAG [{cell} trial {t}]: [AttackerBackstopFired] - legit thread may not "
                      f"have reported completion, treat as suspect")
            if d.get("stop_reason") not in (None, "completion") and atk_total > 0:
                print(f"FLAG [{cell} trial {t}]: stop_reason={d.get('stop_reason')} (expected 'completion')")
            trials.append(d)
        results[cell] = trials
        print(f"[{cell}] {len(trials)}/{N_TRIALS} trials reconciled exactly "
              f"(legit-only expected_total={EXPECTED_LEGIT_TOTAL}, attacker 3-way check included)")

    print("\n" + "=" * 100)
    for cell, trials in results.items():
        if not trials:
            print(f"{cell}: NO VALID TRIALS")
            continue
        valid_fracs = [t["legit_valid"] / t["legit_valid_denom"] for t in trials if t["legit_valid_denom"]]
        drop_fracs = [t["drop_num"] / t["drop_denom"] if t["drop_denom"] else 0 for t in trials]
        dm_fracs = [t["deadline_miss_num"] / t["deadline_miss_denom"] for t in trials if t["deadline_miss_denom"]]
        atk_totals = [t["attacker_total"] for t in trials if t["attacker_total"] is not None]
        cert_ns = [t.get("cert_verify_n") or 0 for t in trials]
        elapsed = [t["actual_elapsed_ms"] for t in trials if t.get("actual_elapsed_ms") is not None]
        stop_reasons = [t.get("stop_reason") for t in trials if t.get("stop_reason")]
        achieved_rates = [t["achieved_rate_per_sec"] for t in trials if t.get("achieved_rate_per_sec") is not None]

        def stat(xs):
            xs = [x for x in xs if x == x]
            if not xs: return "n/a"
            if len(xs) == 1: return f"{xs[0]}"
            return f"avg={statistics.mean(xs):.4g} min={min(xs)} max={max(xs)}"

        print(f"\n--- {cell} (n_trials={len(trials)}) ---")
        print(f"  legit VALID frac:      {stat(valid_fracs)}")
        print(f"  legit drop frac:       {stat(drop_fracs)}")
        print(f"  deadline-miss frac:    {stat(dm_fracs)}")
        print(f"  attacker_total (output, no fixed target): {stat(atk_totals)}")
        print(f"  cert-sig verify n:     {stat(cert_ns)}")
        print(f"  stop_reason values seen: {stop_reasons if stop_reasons else 'n/a (parse gap or no attacker)'}")
        print(f"  actual_elapsed_ms:     {stat(elapsed)}")
        if achieved_rates:
            print(f"  achieved_rate_per_sec (rate-cap cells only): {stat(achieved_rates)}")

    print("\n" + "=" * 100)
    print("ALL RECONCILED EXACTLY" if all_ok else "*** SOME TRIALS FAILED RECONCILIATION ***")

    if _args.csv_per_trial:
        _write_csv(_args.csv_per_trial, PER_TRIAL_COLUMNS, csv_rows)
    if _args.csv_summary:
        summary = [_summary_row(c, [r for r in csv_rows if r["cell"] == c]) for c in CELLS]
        _write_csv(_args.csv_summary, SUMMARY_COLUMNS, summary)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
