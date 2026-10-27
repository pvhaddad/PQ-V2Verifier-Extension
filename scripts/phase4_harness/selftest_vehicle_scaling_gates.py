#!/usr/bin/env python3
"""Self-test for phase4_vehicle_scaling_aggregate.py's gates, using real Update 21 logs (L=2) and
small doctored copies. Nothing is run against the simulator; only the aggregator is exercised.
Exit code 0 only if every case behaves as specified."""
import os
import re
import shutil
import tempfile
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "phase4_raw_logs/phase4_match_duration_trials"
AGG = REPO / "scripts/phase4_harness/phase4_vehicle_scaling_aggregate.py"
WORK = Path(os.environ.get("SELFTEST_DIR") or tempfile.mkdtemp(prefix="pqv2v_selftest_"))
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)

# rc: 0 PASS, 2 STOP, 3 REVIEW
results = []


def link_real(case_dir, cell, trial, src_trial=1):
    for kind in ("recv", "xmit"):
        dst = case_dir / f"{cell}_trial{trial}_{kind}.log"
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        os.symlink(SRC / f"{cell}_trial{src_trial}_{kind}.log", dst)


def doctor(case_dir, cell, trial, kind, fn):
    """Replace the symlink for one log with a doctored real copy."""
    dst = case_dir / f"{cell}_trial{trial}_{kind}.log"
    text = Path(os.path.realpath(dst)).read_text(encoding="utf-8", errors="replace")
    new = fn(text)
    assert new != text, f"doctoring had no effect on {dst.name}"
    dst.unlink()
    dst.write_text(new, encoding="utf-8")


def run(case_dir, cells, n, phase, extra=()):
    p = subprocess.run([sys.executable, str(AGG), "--outdir", str(case_dir), "--num-vehicles", "2",
                        "--n-trials", str(n), "--phase", phase, "--cells", ",".join(cells), *extra],
                       capture_output=True, text=True)
    return p.returncode, p.stdout


def check(name, got_rc, want_rc, out, must_contain=()):
    ok = got_rc == want_rc and all(s in out for s in must_contain)
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: rc={got_rc} (want {want_rc})"
          + ("" if all(s in out for s in must_contain) else f"  MISSING TEXT {[s for s in must_contain if s not in out]}"))
    if not ok:
        print("\n".join("      | " + l for l in out.splitlines()[-25:]))


def mk(name, cells, n=3):
    d = WORK / name
    d.mkdir()
    for c in cells:
        for t in range(1, n + 1):
            link_real(d, c, t, src_trial=t)
    return d


# 0. untouched real Update 21 trials must pass both phases (all 8 cells, 3 trials)
d = mk("clean", ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"])
rc, out = run(d, ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"], 3, "pilot")
check("0a real Update 21 trials, pilot rules", rc, 0, out, ["VERDICT: PASS"])
rc, out = run(d, ["A_off", "A_on", "B_off", "B_on", "C_off", "C_on", "D_off", "D_on"], 3, "full")
check("0b real Update 21 trials, full rules", rc, 0, out, ["VERDICT: PASS"])

# 1. clamped SO_RCVBUF (425984 = 2 x 212992): hard failure
def clamp(t):
    return re.sub(r"(\[SocketConfig\][^\n]*=)67108864", r"\g<1>425984", t)
d = mk("clamp1", ["B_off"]); doctor(d, "B_off", 2, "recv", clamp)
rc, out = run(d, ["B_off"], 3, "pilot");  check("1a clamped buffer, 1 trial, PILOT -> STOP", rc, 2, out, ["socket_rcvbuf_clamped=425984"])
rc, out = run(d, ["B_off"], 3, "full");   check("1b clamped buffer, 1 trial, FULL -> REVIEW", rc, 3, out, ["VERDICT: REVIEW"])
d = mk("clamp2", ["B_off"]); doctor(d, "B_off", 2, "recv", clamp); doctor(d, "B_off", 3, "recv", clamp)
rc, out = run(d, ["B_off"], 3, "full");   check("1c clamped buffer, 2 trials in a cell, FULL -> STOP", rc, 2, out, ["VERDICT: STOP"])

# 2. [SocketConfig] line missing entirely
d = mk("nosock", ["B_off"]); doctor(d, "B_off", 1, "recv", lambda t: re.sub(r"\[SocketConfig\][^\n]*\n", "", t))
rc, out = run(d, ["B_off"], 3, "pilot");  check("2  [SocketConfig] missing -> STOP", rc, 2, out, ["socket_config_missing"])

# 3. backstop marker in the transmitter log
d = mk("backstop", ["C_on"]); doctor(d, "C_on", 1, "xmit", lambda t: t + "\n[AttackerBackstopFired] vehicle=2 legit_vehicles_done=1/2\n")
rc, out = run(d, ["C_on"], 3, "pilot");   check("3  [AttackerBackstopFired] -> STOP", rc, 2, out, ["backstop_fired"])

# 4. attacker_total backstop-consistent (>1.5x reference) - simulated with a low reference
d = mk("atkhigh", ["B_off"])
rc, out = run(d, ["B_off"], 3, "pilot", ["--ref-atk", "B=50000"]); check("4  attacker_total > 1.5x reference -> STOP", rc, 2, out, ["attacker_total_high"])

# 5. A cell: 5% deadline-miss in one trial (receiver falling behind on legit volume alone)
d = mk("adm", ["A_off"])
doctor(d, "A_off", 2, "recv", lambda t: re.sub(r"(deadline-miss ratio[^\n]*?: )0/600", r"\g<1>30/600", t))
rc, out = run(d, ["A_off"], 3, "pilot");  check("5a A-cell trial 5% deadline-miss, PILOT -> STOP", rc, 2, out, ["a_cell_trial_over_1%"])
rc, out = run(d, ["A_off"], 3, "full");   check("5b A-cell trial 5% deadline-miss, FULL -> STOP", rc, 2, out, ["a_cell_trial_over_1%"])
# 5c: 1 late message in 600 (0.17%): flag only
d = mk("adm1", ["A_off"])
doctor(d, "A_off", 2, "recv", lambda t: re.sub(r"(deadline-miss ratio[^\n]*?: )0/600", r"\g<1>1/600", t))
rc, out = run(d, ["A_off"], 3, "pilot");  check("5c A-cell 1/600 late message -> PASS with FLAG", rc, 0, out, ["a_cell_nonzero", "FLAG"])

# 6. pilot-only drop threshold: one trial with 10/598 drops (mean 0.84% over 2 trials)
d = mk("drop", ["B_off"], n=2)
doctor(d, "B_off", 1, "recv", lambda t: re.sub(r"(Legitimate drop rate, excluding startup: )0/598", r"\g<1>10/598", t))
rc, out = run(d, ["B_off"], 2, "pilot");  check("6a pilot cell-mean drop 0.84% (>0.5%) -> STOP", rc, 2, out, ["pilot_cell_mean_drop"])
rc, out = run(d, ["B_off"], 2, "full");   check("6b same data in FULL run -> no drop-based stop", rc, 0, out, ["VERDICT: PASS"])
d = mk("drop2", ["B_off"], n=5)
doctor(d, "B_off", 1, "recv", lambda t: re.sub(r"(Legitimate drop rate, excluding startup: )0/598", r"\g<1>1/598", t))
rc, out = run(d, ["B_off"], 5, "pilot");  check("6c pilot cell-mean drop 0.03% (<=0.5%) -> PASS with FLAG", rc, 0, out, ["pilot_cell_mean_drop", "FLAG"])

# 7. D rate: attacker send time inflated 30s -> 300s (rate ~80/s < 500/s)
d = mk("drate", ["D_off"])
doctor(d, "D_off", 1, "xmit", lambda t: re.sub(r"(\[FloodRateCheck\] vehicle=2 num_msgs=\d+ nominal_inter_message_delay_ms=\d+ total_send_time_ms=)[\d.]+", r"\g<1>300000", t))
rc, out = run(d, ["D_off"], 3, "pilot");  check("7  measured D rate < 500/s -> STOP", rc, 2, out, ["d_rate_out_of_bounds"])

# 8. a single UNPARSED stop_reason: probable-completion FLAG, never a failure by itself
d = mk("unparsed1", ["B_off"])
doctor(d, "B_off", 1, "xmit", lambda t: t.replace("stop_reason=", "stop_rea_son="))
rc, out = run(d, ["B_off"], 3, "pilot");  check("8  single UNPARSED stop_reason -> PASS + probable-completion flag", rc, 0, out, ["probable-completion"])

# 8b. a stop_reason cut mid-word by the stdout race ("stop_reason=compl mess ...", seen at L=9 C_on
#     trial 13) must be UNPARSED + probable-completion, NOT a hard failure; a real backstop_timeout still fails
d = mk("truncated", ["C_on"])
doctor(d, "C_on", 1, "xmit", lambda t: t.replace("stop_reason=completion", "stop_reason=compl mess", 1))
rc, out = run(d, ["C_on"], 3, "pilot");   check("8b truncated 'stop_reason=compl' -> PASS + probable-completion (not a failure)", rc, 0, out, ["probable-completion"])
d = mk("realbackstop", ["C_on"])
doctor(d, "C_on", 1, "xmit", lambda t: t.replace("stop_reason=completion", "stop_reason=backstop_timeout", 1))
rc, out = run(d, ["C_on"], 3, "pilot");   check("8c a real stop_reason=backstop_timeout still -> STOP", rc, 2, out, ["stop_reason=backstop_timeout"])

# 9. UNPARSED rate far above the 3.3% baseline (24 attacker trials, all UNPARSED) -> STOP
d = WORK / "unparsedmany"; d.mkdir()
for c in ("B_off", "B_on", "C_off", "C_on"):
    for t in range(1, 7):
        link_real(d, c, t, src_trial=1)
for c in ("B_off", "B_on", "C_off", "C_on"):
    src = SRC / f"{c}_trial1_xmit.log"
    stripped = d / f"_{c}_stripped.log"
    stripped.write_text(src.read_text(encoding="utf-8", errors="replace").replace("stop_reason=", "stop_rea_son="), encoding="utf-8")
    for t in range(1, 7):
        x = d / f"{c}_trial{t}_xmit.log"
        x.unlink()
        os.symlink(stripped, x)
rc, out = run(d, ["B_off", "B_on", "C_off", "C_on"], 6, "pilot"); check("9  UNPARSED 100% of 24 attacker trials -> STOP", rc, 2, out, ["unparsed_stop_reason_rate"])

# 10. a real hard failure the old harness would also catch: INCOMPLETE RUN
d = mk("incomplete", ["C_off"]); doctor(d, "C_off", 1, "recv", lambda t: t.replace("Legitimate messages processed: 600", "*** INCOMPLETE RUN: only 46 of 600 ***\nLegitimate messages processed: 46"))
rc, out = run(d, ["C_off"], 3, "pilot");  check("10 INCOMPLETE RUN -> STOP", rc, 2, out, ["incomplete_run"])

# 11. driver rc file (timeout 124) is a hard failure
d = mk("rcfile", ["B_on"]); (d / "B_on_trial1.rc").write_text("recv=124 xmit=0\n")
rc, out = run(d, ["B_on"], 3, "pilot");   check("11 receiver timeout rc=124 -> STOP", rc, 2, out, ["process_rc"])

# 12. journal-based wall-clock-step detection (synthetic journal + synthetic trial_times; no live data)
import json as _json
T0 = 1_800_000_000.0


def clk_case(name, step_jump_ms, event_latency_ms, step_in_window=True):
    """One doctored real trial (B_off #1, L=2 'pilot') with a legit late message of `event_latency_ms` (or none),
    plus a fake journal holding one 'Clock change detected' step of `step_jump_ms` inside or outside its window."""
    d = mk(name, ["B_off"], n=1)
    if event_latency_ms:
        doctor(d, "B_off", 1, "recv", lambda t_: re.sub(r"(deadline-miss ratio[^\n]*?: )0/600", r"\g<1>1/600", t_)
               + f"\n[DeadlineMiss] vehicle=0 outcome=0 latency_ms={event_latency_ms}\n")
    (d / "trial_times.tsv").write_text(f"2\tpilot\tB_off\t1\t{T0}\t{T0 + 36}\n")
    mono_prev, rt_prev = 1000.0, T0 - 20.0
    mono_step = mono_prev + 32.25
    rt_step = (rt_prev - mono_prev) + step_jump_ms / 1000.0 + mono_step
    if not step_in_window:
        rt_step += 200.0; mono_step += 200.0       # same offset jump, but well after the trial ended
    lines = [{"__REALTIME_TIMESTAMP": str(int(x[0] * 1e6)), "__MONOTONIC_TIMESTAMP": str(int(x[1] * 1e6)),
              "MESSAGE": "Clock change detected. Flushing caches.", "_BOOT_ID": "b"} for x in ((rt_prev, mono_prev), (rt_step, mono_step))]
    (d / "journal.json").write_text("\n".join(_json.dumps(x) for x in lines) + "\n")
    return d


def run_clk(d):
    return run(d, ["B_off"], 1, "pilot", ["--trial-times", str(d / "trial_times.tsv"), "--journal-json", str(d / "journal.json")])


d = clk_case("clk_yes", 500.0, 501.2)
rc, out = run_clk(d);  check("12a late msg (501 ms) + step of +500 ms in window -> EXPLAINED, no UNEXPLAINED flag", rc, 0, out, ["explained by a step: 1"])
results.append("UNEXPLAINED" not in out); print(f"{'PASS' if results[-1] else 'FAIL'}  12a' no UNEXPLAINED flag when explained")
d = clk_case("clk_none", 500.0, 501.2, step_in_window=False)
rc, out = run_clk(d);  check("12b late msg but NO step in the window -> flagged UNEXPLAINED (candidate real delay), not a stop", rc, 0, out, ["UNEXPLAINED", "NO step in window (candidate real delay): 1"])
d = clk_case("clk_mismatch", 100.0, 501.2)
rc, out = run_clk(d);  check("12c step of +100 ms vs a 501 ms late msg -> STEP_SIZE_MISMATCH flag", rc, 0, out, ["step-size mismatch: 1"])
d = clk_case("clk_clean", 500.0, 0)
rc, out = run_clk(d);  check("12d clean trial that merely had a step -> counted as exposed, no event, no flag", rc, 0, out, ["exposed to >=1 step inside their messaging window: 1/1"])
results.append("UNEXPLAINED" not in out and "mismatch" not in out.lower().replace("step-size mismatch: 0", "")); print(f"{'PASS' if results[-1] else 'FAIL'}  12d' no flag on a clean exposed trial")
d = mk("clk_absent", ["B_off"], n=1)
rc, out = run(d, ["B_off"], 1, "pilot"); check("12e without --trial-times the report has no clock section and behaves as before", rc, 0, out, ["VERDICT: PASS"])
results.append("wall-clock steps" not in out); print(f"{'PASS' if results[-1] else 'FAIL'}  12e' no clock section without --trial-times")

n_ok = sum(results)
print(f"\nSELFTEST: {n_ok}/{len(results)} cases behaved as specified")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(0 if n_ok == len(results) else 1)
