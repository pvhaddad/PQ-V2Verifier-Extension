#!/usr/bin/env python3
"""Sanity check: the Update 21 CSV exports vs the table written into context/UPDATES.md.

The write-up table is parsed programmatically out of UPDATES.md (nothing retyped here), and
each (metric, cell) claim is compared to exports/update21_summary.csv. The summary CSV is
itself cross-checked against a from-scratch recompute over exports/update21_per_trial.csv (a
separate code path from the aggregator's), so a bug in either export file can't hide.

Neither source is trusted over the other: every disagreement is printed as MISMATCH with the
claimed value and the CSV value, and the exit code is non-zero if there is any. Read-only.
"""
import csv
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UPDATES = REPO / "context/UPDATES.md"
SUMMARY = REPO / "exports/update21_summary.csv"
PER_TRIAL = REPO / "exports/update21_per_trial.csv"
CELLS = ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"]
N = 75
LEGIT_TOTAL = 600

results = []  # (ok, metric, cell, claimed, csv_detail)


def record(ok, metric, cell, claimed, detail):
    results.append((ok, metric, cell, claimed, detail))


def f4(x):
    return f"{float(x):.4f}"


def load_claims():
    lines = UPDATES.read_text(encoding="utf-8").split("\n")
    start = next(i for i, l in enumerate(lines) if l.strip() == "## Update 21")
    hdr = next(i for i in range(start, len(lines)) if lines[i].startswith("| Metric |"))
    cols = [c.strip() for c in lines[hdr].strip().strip("|").split("|")]
    claims = {}
    i = hdr + 2
    while i < len(lines) and lines[i].startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        metric = cells[0].strip("`")
        claims[metric] = dict(zip(cols[1:], (c.replace("¹", "").replace("²", "").strip() for c in cells[1:])))
        i += 1
    return claims


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def check_claims(claims, summ, per_trial):
    for cell in CELLS:
        s = summ[cell]
        pt = per_trial[cell]
        modal_valid, modal_drop, _modal_dm = (int(v) for v in s["modal_valid_drop_deadline"].split("/"))
        n_trials = int(s["n_trials"])

        # --- Legit VALID frac: "0.9967 (74/75)" = modal value, count of trials AT the modal value
        c = claims["Legit VALID frac"][cell]
        m = re.fullmatch(r"([\d.]+) \((\d+)/(\d+)\)", c)
        want_val, want_n, want_of = m.group(1), int(m.group(2)), int(m.group(3))
        got_val, got_n = f4(modal_valid / LEGIT_TOTAL), n_trials - int(s["trials_valid_ne_modal"])
        record(want_val == got_val and want_n == got_n and want_of == n_trials, "Legit VALID frac", cell, c,
               f"modal {modal_valid}/{LEGIT_TOTAL}={got_val}, {got_n}/{n_trials} trials at modal")

        # --- Legit drop frac: "0 (74/75)" = modal drop value, count of trials at zero drops
        c = claims["Legit drop frac"][cell]
        m = re.fullmatch(r"([\d.]+) \((\d+)/(\d+)\)", c)
        want_val, want_n, want_of = float(m.group(1)), int(m.group(2)), int(m.group(3))
        got_n = n_trials - int(s["trials_drop_gt0"])
        record(want_val == float(modal_drop) and want_n == got_n and want_of == n_trials,
               "Legit drop frac", cell, c, f"modal drop count {modal_drop}, {got_n}/{n_trials} trials with 0 drops")

        # --- Deadline-miss: "0 (75/75)" or "~0 (Z/75; K/600 in M trial[s])" - checked against raw per-trial rows
        c = claims["Deadline-miss frac"][cell]
        dm_counts = Counter(int(r["deadline_miss_count"]) for r in pt)
        zero_trials = dm_counts.get(0, 0)
        nonzero = {k: v for k, v in dm_counts.items() if k > 0}
        m0 = re.fullmatch(r"0 \((\d+)/(\d+)\)", c)
        m1 = re.fullmatch(r"~0 \((\d+)/(\d+); (\d+)/600 in (\d+) trials?\)", c)
        if m0:
            ok = int(m0.group(1)) == zero_trials and not nonzero
        elif m1:
            ok = int(m1.group(1)) == zero_trials and nonzero == {int(m1.group(3)): int(m1.group(4))}
        else:
            ok = False
        record(ok, "Deadline-miss frac", cell, c, f"{zero_trials} trials at 0; nonzero (count -> #trials): {nonzero or 'none'}")

        # --- Attacker total: "0" or "avg X (lo-hi)"; avg compared to half a unit of its last displayed digit
        c = claims["Attacker total (output)"][cell]
        if c == "0":
            ok = s["attacker_total_min"] == "0" and s["attacker_total_max"] == "0" and float(s["attacker_total_mean"]) == 0
        else:
            m = re.fullmatch(r"avg ([\d,]+) \(([\d,]+)-([\d,]+)\)", c)
            avg, lo, hi = (int(g.replace(",", "")) for g in m.groups())
            trailing = len(str(avg)) - len(str(avg).rstrip("0"))
            tol = 10 ** trailing / 2
            ok = (abs(float(s["attacker_total_mean"]) - avg) <= tol
                  and int(s["attacker_total_min"]) == lo and int(s["attacker_total_max"]) == hi)
        record(ok, "Attacker total (output)", cell, c,
               f"mean {float(s['attacker_total_mean']):.1f} min {s['attacker_total_min']} max {s['attacker_total_max']}")

        # --- full-crypto / cheap-reject frac: "n/a", "V (all 75)", or "a-b" (compared at 4 dp)
        for metric, key in (("Attacker full-crypto frac", "attacker_full_crypto_frac"),
                            ("Attacker cheap-reject frac", "attacker_cheap_reject_frac")):
            c = claims[metric][cell]
            if c == "n/a":
                ok, detail = all(s[f"{key}_{k}"] == "NA" for k in ("mean", "min", "max")), "NA expected"
            else:
                lo, hi = f4(s[f"{key}_min"]), f4(s[f"{key}_max"])
                m = re.fullmatch(r"([\d.]+) \(all (\d+)\)", c)
                if m:
                    ok = lo == m.group(1) and hi == m.group(1) and int(m.group(2)) == n_trials
                else:
                    a, b = c.split("-")
                    ok = lo == a and hi == b
                detail = f"min {lo} max {hi} (4dp)"
            record(ok, metric, cell, c, detail)

        # --- pending count: "n/a", "K (all 75)", or "a-b"
        c = claims["Attacker pending (count)"][cell]
        if c == "n/a":
            ok, detail = s["attacker_pending_min"] == "NA" and s["attacker_pending_max"] == "NA", "NA expected"
        else:
            lo, hi = s["attacker_pending_min"], s["attacker_pending_max"]
            m = re.fullmatch(r"(\d+) \(all (\d+)\)", c)
            ok = (lo == m.group(1) and hi == m.group(1)) if m else (f"{lo}-{hi}" == c)
            detail = f"min {lo} max {hi}"
        record(ok, "Attacker pending (count)", cell, c, detail)

        # --- stop_reason: "n/a", or "completion=70/UNPARSED=5" -> compared as {reason: count} dicts
        # (order/separator-insensitive), and the counts must add up to every trial in the cell
        c = claims["stop_reason"][cell]
        if c == "n/a":
            ok = s["stop_reason_distribution"] == "NA"
        else:
            want = {k: int(v) for k, v in (p.split("=") for p in c.split("/"))}
            got = {k: int(v) for k, v in (p.split("=") for p in s["stop_reason_distribution"].split(";"))}
            ok = want == got and sum(want.values()) == n_trials
        record(ok, "stop_reason", cell, c, f"csv distribution: {s['stop_reason_distribution']}")

        # --- send rate (D only): "—" or "nominal 1000 (75/75) / measured 805 (774-842; 75/75)".
        # nominal = the startup constant (must be exactly 1000 on n trials); measured = mean and
        # min-max compared as integers (rounded from the CSV), and n = trials with a measurement.
        c = claims["Send rate (D only): nominal / measured"][cell]
        if c == "—":
            # the write-up makes no rate claim for A/B/C; the CSV must not carry a nominal rate for them
            ok = s["nominal_rate_per_sec_mean"] == "NA" and s["nominal_rate_n_parsed"] == "NA"
            detail = f"nominal rate NA expected; csv nominal mean {s['nominal_rate_per_sec_mean']}"
        else:
            m = re.fullmatch(r"nominal (\d+) \((\d+)/(\d+)\) / measured (\d+) \((\d+)-(\d+); (\d+)/(\d+)\)", c)
            nom, nom_n, nom_of, meas_mean, meas_lo, meas_hi, meas_n, meas_of = (int(g) for g in m.groups())
            ok = (all(float(s[f"nominal_rate_per_sec_{k}"]) == nom for k in ("mean", "min", "max"))
                  and int(s["nominal_rate_n_parsed"]) == nom_n == nom_of == n_trials
                  and round(float(s["measured_rate_per_sec_mean"])) == meas_mean
                  and round(float(s["measured_rate_per_sec_min"])) == meas_lo
                  and round(float(s["measured_rate_per_sec_max"])) == meas_hi
                  and int(s["measured_rate_n"]) == meas_n == meas_of == n_trials)
            detail = (f"nominal {s['nominal_rate_per_sec_mean']} (n={s['nominal_rate_n_parsed']}); measured mean "
                      f"{float(s['measured_rate_per_sec_mean']):.1f} min {float(s['measured_rate_per_sec_min']):.1f} "
                      f"max {float(s['measured_rate_per_sec_max']):.1f} (n={s['measured_rate_n']})")
        record(ok, "Send rate (D only)", cell, c, detail)


def recompute_vs_summary(summ, per_trial):
    """Independent recompute from the per-trial CSV; must agree with the summary CSV."""
    problems = []
    for cell in CELLS:
        rows = per_trial[cell]
        s = summ[cell]
        if len(rows) != N:
            problems.append(f"{cell}: {len(rows)} per-trial rows, expected {N}")
        ok = [r for r in rows if r["reconciliation_status"] == "OK"]
        if int(s["n_trials"]) != len(rows) or int(s["n_reconciled"]) != len(ok):
            problems.append(f"{cell}: n_trials/n_reconciled {s['n_trials']}/{s['n_reconciled']} vs {len(rows)}/{len(ok)}")
        valid = [int(r["legit_valid_count"]) / int(r["legit_total"]) for r in ok]
        drop = [int(r["legit_drop_count"]) / int(r["legit_drop_denominator"]) for r in ok]
        dm = [int(r["deadline_miss_count"]) / int(r["legit_total"]) for r in ok]
        for key, xs in (("legit_valid_frac", valid), ("legit_drop_frac", drop), ("deadline_miss_frac", dm)):
            for stat, val in (("mean", statistics.mean(xs)), ("min", min(xs)), ("max", max(xs))):
                if abs(float(s[f"{key}_{stat}"]) - val) > 1e-9:
                    problems.append(f"{cell}: {key}_{stat} summary {s[f'{key}_{stat}']} vs recompute {val}")
        atk = [int(r["attacker_total"]) for r in ok]
        # mean is stored to 10 significant digits, so compare relatively (1e-9), like the other stats
        if (int(s["attacker_total_min"]), int(s["attacker_total_max"])) != (min(atk), max(atk)) \
                or abs(float(s["attacker_total_mean"]) - statistics.mean(atk)) > 1e-9 * max(1.0, statistics.mean(atk)):
            problems.append(f"{cell}: attacker_total stats disagree with per-trial recompute")
        triples = [(int(r["legit_valid_count"]), int(r["legit_drop_count"]), int(r["deadline_miss_count"])) for r in ok]
        modal = Counter(triples).most_common(1)[0][0]
        if s["modal_valid_drop_deadline"] != "/".join(map(str, modal)) \
                or int(s["deviating_trials"]) != sum(t != modal for t in triples) \
                or int(s["trials_drop_gt0"]) != sum(t[1] > 0 for t in triples) \
                or int(s["trials_deadline_miss_gt0"]) != sum(t[2] > 0 for t in triples) \
                or int(s["trials_valid_ne_modal"]) != sum(t[0] != modal[0] for t in triples):
            problems.append(f"{cell}: modal/deviation counts disagree with per-trial recompute")
        if not cell.startswith("A_"):
            dist = ";".join(f"{k}={v}" for k, v in sorted(Counter(r["stop_reason"] for r in ok).items()))
            if s["stop_reason_distribution"] != dist:
                problems.append(f"{cell}: stop_reason_distribution {s['stop_reason_distribution']} vs {dist}")
    return problems


def main():
    claims = load_claims()
    summ = {r["cell"]: r for r in load_csv(SUMMARY)}
    pt_all = load_csv(PER_TRIAL)
    per_trial = {c: [r for r in pt_all if r["cell"] == c] for c in CELLS}
    assert len(pt_all) == N * len(CELLS), f"per-trial rows: {len(pt_all)}"
    assert set(summ) == set(CELLS), f"summary cells: {sorted(summ)}"

    print(f"Parsed {len(claims)} metric rows from Update 21 table: {list(claims)}\n")
    check_claims(claims, summ, per_trial)
    for ok, metric, cell, claimed, detail in results:
        print(f"{'PASS    ' if ok else 'MISMATCH'} | {metric:26s} | {cell:5s} | writeup: {claimed:38s} | csv: {detail}")

    n_bad = sum(1 for r in results if not r[0])
    print(f"\nWrite-up vs CSV: {len(results) - n_bad} PASS, {n_bad} MISMATCH (of {len(results)} metric-cell checks)")
    bad_metrics = sorted({r[1] for r in results if not r[0]})
    if bad_metrics:
        print("Metrics with mismatches:", bad_metrics)

    problems = recompute_vs_summary(summ, per_trial)
    print(f"Summary CSV vs independent recompute from per-trial CSV: "
          f"{'CONSISTENT' if not problems else str(len(problems)) + ' PROBLEM(S)'}")
    for p in problems:
        print("  ", p)
    return 1 if (n_bad or problems) else 0


if __name__ == "__main__":
    sys.exit(main())
