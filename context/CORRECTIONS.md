# Corrections Log

Every "CORRECTED" or explicit walk-back found across the 22 updates in
`context/UPDATES.md`, synthesized in one place so a stale belief from an earlier update
doesn't get relayed as current. Read this before citing any specific finding from
`context/UPDATES.md` if the update it comes from is more than a few numbers back — check
whether it was later corrected here first. Format: **Previously believed** → **Actually**
→ **Corrected in**.

1. **Previously believed:** attack variant #2 (expensive-valid flooding) was "currently
   being implemented" and variant #1 (invalid-signature) was "deferred."
   **Actually:** both #1 and #2 were implemented and verified end-to-end.
   **Corrected in:** Update 1 (self-correction, same update the stale text originally
   appeared in).

2. **Previously believed:** an earlier implementation-plan draft assumed
   `AttackerVehicle` would need `private`→`protected` promotions on `Vehicle`'s internals
   to implement its attack variants.
   **Actually:** not needed — the type-erased virtual hooks (`post_process_spdu`,
   `inter_message_delay_ms`) sidestepped it entirely; `AttackerVehicle` never touches
   `Vehicle`'s generate/sign functions or spdu struct types directly.
   **Corrected in:** Update 3.

3. **Previously believed:** "Falcon Certificate Fragmentation + Spam Filter — PLANNED,
   NOT YET IMPLEMENTED" (Update 4's heading, including step 1, segmentation + cycle).
   **Actually:** Phase 1 (segmentation + cycle) was implemented.
   **Corrected in:** Update 5 (Update 4's heading and step-1 status line were left as-is
   rather than edited, per this doc's own convention of not silently rewriting history —
   Update 5 is authoritative for Phase 1's status).

4. **Previously believed:** the Falcon certificate is fragmented once at first contact
   with a sender and then cached forever.
   **Actually:** it's re-broadcast on a repeating cycle (`m=2` segment-carrying messages
   + `n` hash-only messages, cycle repeats indefinitely) — not a one-shot fragmentation.
   **Corrected in:** Update 4 (self-correction, same update).

5. **Previously believed:** the per-sender fragment reconstruction buffer opens once, at
   a sender's "first contact."
   **Actually:** it opens at the start of every cycle's `m`-segment window (recurring
   every τ messages) and should close well before the next cycle begins.
   **Corrected in:** Update 4 (self-correction, same update, tied to correction #4 above).

6. **Previously believed:** Phase 2's flood test showed "0% degradation, every run" —
   clean, deterministic, no legitimate-traffic impact at any scale tested.
   **Actually:** rare, environment-driven backlog spikes cause occasional legitimate
   deadline misses (0-2/600) and much more frequent attacker deadline misses — a real, if
   rare, degradation effect the "0% every run" framing didn't capture. Root-caused to
   2-core-VM scheduling/wake-latency, not a code defect.
   **Corrected in:** Update 8 (reopens the "Phase 2 closed" call from Update 7).

7. **Previously believed:** a single attacker could rotate through multiple *valid*
   pseudonym certificates via certificate-churn flooding, making churned messages "look
   first-seen" like legitimate traffic — implying churn could bypass trust checks.
   **Actually:** the attacker's real CA-signed pseudonym cert supply is exactly 1; churn
   traffic uses fabricated self-signed certs, which never chain to the trusted root and
   are *always* correctly rejected as invalid-cert-signature, never `VALID`. Churn is a
   variant of invalid-signature flooding with cache-defeating identity rotation layered
   on, not a stealthy trust-bypass.
   **Corrected in:** Update 9.

8. **Previously believed:** the Phase 3 spam-filter plan expected a churn/flood attacker
   to contribute "throttled" (small but nonzero) cert-sig-verify completions.
   **Actually:** for a flood-paced attacker, the cert-sig-verify count is exactly zero —
   the rate-limiter blocks the attacker's cert reconstruction before it ever completes,
   so cert-sig verify never even runs. A stronger result than planned (zero crypto cost,
   not merely reduced crypto cost).
   **Corrected in:** Update 11.

9. **Previously believed:** Update 9's "always correctly rejected via cert-sig failure"
   described the *only* rejection mechanism for churned/fabricated certs.
   **Actually:** there are two mechanisms depending on attacker speed — a fast attacker
   (segment gap under `spamFilterMinGapMs`) is rate-blocked before reconstruction ever
   completes (cert-sig verify never runs); a slow/patient attacker reconstructs normally
   and then correctly fails cert-sig verify (Update 9's original mechanism). The security
   *outcome* (never admitted, never cached) is unchanged; only the *mechanism* claim is
   corrected.
   **Corrected in:** Update 11.

10. **Previously believed:** B_on's (spam-filter-on, `expensive_valid` attack)
    trial-to-trial legitimate-VALID variance was caused by the `RATE` check
    (segment-0-to-segment-1 gap falling *under* `spamFilterMinGapMs`, 50ms) hitting
    legitimate vehicles.
    **Actually:** zero `RATE` drops were ever attributed to a legitimate vehicle in the
    traced data — the real mechanism is buffer-TTL-eviction under receiver backlog (the
    gap between processing segment 0 and segment 1 exceeding `bufferTtlMs`, 500ms — a gap
    *too large*, the opposite direction from `RATE`).
    **Corrected in:** Update 14.

11. **Previously believed:** "C (`invalid_signature`) under filter-ON is clean across the
    board — 0% legitimate drop, 0% deadline-miss in all 5 trials" (an N=5 result).
    **Actually:** at N=75, legitimate drops occur in 24/75 C_on trials (32%), up to 3.367%
    in the worst trial — a roughly-1-in-3 event the 5-trial sample simply didn't catch.
    **Corrected in:** Update 15 (Correction 1).

12. **Previously believed:** the legitimate-drop backlog artifact (Update 11/12/14)
    "always" self-heals after exactly one cert cycle, every time observed.
    **Actually:** across all 150 B_on+C_on N=75 trials, this holds in 148/150 (98.7%) —
    but two trials show the identical failure pattern recurring across two cycles before
    healing. Eventual self-healing still holds in every trial checked; "always exactly
    one cycle" does not.
    **Corrected in:** Update 15 (Correction 2).

13. **Previously believed:** condition A (no attack) showed nonzero deadline-miss in all
    5 N=5 trials, averaging 0.83% (range 0.17%-2.17%) — worse than the attack conditions.
    **Actually:** at N=75, deadline-miss is exactly 0/75 for both A_off and A_on. The
    underlying scheduling-spike mechanism (Update 8) is real and not in question, but the
    N=5 sample's specific nonzero magnitude does not reproduce at 15x the sample size.
    Root cause of the discrepancy (unlucky small sample vs. environment-history-dependent
    spike frequency) is flagged, not resolved.
    **Corrected in:** Update 15 (Correction 3).

14. **Previously believed (pre-implementation draft):** the "attacker reached full
    crypto" metric should be `VALID + INVALID_SIGNATURE + INVALID_CERT_SIGNATURE`, and
    "cheap reject" should be computed as `sum(attacker_spam_drop_reason_counts)`.
    **Actually:** "full crypto" must also include `EXPIRED` (assigned only when
    `falcon_verify()` actually ran and succeeded, against a stale timestamp — crypto was
    still paid). "Cheap reject" must use `attacker_outcome_counts[SPAM_FILTERED]`
    directly — the drop-reason sum double-counts whenever `BUFFER_TTL_EVICT_INCOMPLETE`
    fires (confirmed as a real hazard: a checkpoint trial's sum was 1999 against a true
    `SPAM_FILTERED` of 1983).
    **Corrected in:** Update 16 (caught during planning, before it produced a
    reconciliation failure in a real trial).

15. **Previously believed (draft analysis):** entering the Falcon cert cycle at position
    1 (worst-case cold start) produces the outcome breakdown "1 `BUFFER_CAP` + 5
    `NO_CERT_YET`" under the spam-filter (filter-ON) path.
    **Actually:** "1 `BUFFER_CAP` + 4 `NO_CACHE` + 1 `NO_CERT_YET`" — the filter-ON
    path's HASH_ONLY branch drops a cache-miss as `NO_CACHE`/`SPAM_FILTERED`, a distinct
    outcome bucket from `NO_CERT_YET`. The total counts (5 at position 2, 6 at position
    1) were already correct; only the sub-breakdown was wrong.
    **Corrected in:** Update 18.

16. **Previously believed (draft of Update 19):** D_on's near-total rejection of
    `CHEAP_INVALID_SIGNATURE` attacker traffic was caused by "the same `RATE`-limiter
    mechanism" as Update 11/16, citing Update 16's `invalid_signature` checkpoint example
    as the analogy.
    **Actually:** that citation was from a different cell entirely. D_on's own
    drop-reason data shows a distinct, fully deterministic mechanism: 33.4% RATE + 66.6%
    NO_CACHE with zero variance across every trial, and zero `BUFFER_CAP` — roughly 10x
    higher RATE share than the `invalid_signature` cell it was compared to, because the
    much faster (unpaced) attack produces gaps that fail `RATE` cleanly and
    deterministically rather than the scheduling-sensitive mix seen elsewhere.
    **Corrected in:** Update 19 (corrected within the same update, before publication of
    the pilot results).

17. **Previously believed (draft of Update 19):** D_off's (filter-off,
    `CHEAP_INVALID_SIGNATURE`) crypto cost was "the highest of any cell measured so far."
    **Actually:** D_off's cert-sig-verify volume (2597) is identical to B_off/C_off — the
    total crypto workload is unchanged, not higher. What actually differs is
    legitimate-traffic deadline-miss rate (roughly 3.4x B_off/C_off's), because the same
    crypto volume gets compressed into a much shorter burst window once signing delay no
    longer paces the attacker.
    **Corrected in:** Update 19 (corrected within the same update).

18. **Previously believed:** Update 2's description of `transmit()`'s destination
    address — "`transmit()`'s destination uses `INADDR_ANY` (0.0.0.0)... works on
    Linux... fragile if ever ported off Linux" — was the current state of the code.
    **Actually:** the source had since been changed to `INADDR_LOOPBACK` (no matching
    `UPDATES.md` entry recorded the change), and that change was itself broken: the
    missing `htonl()` wrapper made every transmitted packet's destination
    byte-swap to `1.0.0.127` on little-endian hardware, silently discarding all
    traffic (confirmed via `strace`, and via a raw UDP packet proving the
    receiver-side bind/recvfrom path was never the problem) — a portability bug of a
    different kind than Update 2 described, not the one it described.
    **Corrected in:** this session (moved to `context/BUGS.md`'s "Resolved" section
    with the full fix and verification).

19. **Previously believed (Update 21 as first written, 2026-09-18):** every attacker-bearing
    trial of the N=75 × 8-cell sustained-duration run was confirmed to have ended by
    `stop_reason=completion` — the table read `completion (75/75)` in all six attacker
    cells, and the diagnostic caveat said "`stop_reason` values themselves parsed cleanly on
    every trial regardless."
    **Actually:** `stop_reason` is parseable in only 435 of the 450 attacker-bearing trials
    (B_off 70/75, B_on 73/75, C_off 71/75, C_on 74/75, D_off 74/75, D_on 73/75). In the
    other 15 the `[AttackerRunSummary]` line is absent from the transmitter log entirely —
    lost outright, not merely number-corrupted — to the same unsynchronized multi-thread
    `std::cout` race the caveat already described for other fields, so completion is
    *unrecorded* for those trials, not confirmed. Nothing contradicts it: no log in the run
    shows `stop_reason=backstop_timeout`. (The absence of `[AttackerBackstopFired]` alone is
    weak evidence, since that line sits in the same racy stream.) The stronger, independent
    evidence is receiver-side, from the single-threaded receiver logs: every one of the 15
    has an `attacker_total` inside the range of its own cell's parsed-`completion` trials,
    and a 60s backstop-terminated run would roughly double it (~250k for B/C, ~48k for D at
    the measured ~800/sec — see #20; first written as ~60k at the nominal 1000/sec), so these
    almost certainly completed normally at ~30s. This is
    inference from receiver data, not a recovered log line:
    - B_off (119,034-127,948): trial 8 (125,000), 21 (123,593), 35 (123,100), 54 (126,895), 62 (127,201)
    - B_on (122,784-126,919): trial 5 (125,943), 41 (125,948)
    - C_off (125,588-127,948): trial 19 (126,377), 22 (127,312), 43 (126,503), 74 (126,539)
    - C_on (124,707-133,484): trial 4 (126,235)
    - D_off (23,363-25,403): trial 70 (24,361)
    - D_on (22,572-25,119): trial 52 (23,418), 58 (22,735)

    Found during the Update 21 CSV export, by re-parsing all 1,200 raw logs in Python
    (an earlier `grep`-based count here was unreliable — `grep` on this machine is `ugrep`
    — and was superseded by the Python count). **Not affected:** reconciliation (600/600),
    every receiver-derived number in the table, and the D cells' nominal rate line (`achieved_rate_per_sec`, a startup constant — see #20)
    (75/75 each — printed at startup, before any worker thread exists).
    **Corrected in:** Update 21 (table `stop_reason` row now
    `completion=<n>/UNPARSED=<n>` per cell with footnote ², and the "parsed cleanly on every
    trial" sentence removed), 2026-09-18. The `exports/update21_*.csv` files encode these
    trials as `UNPARSED` from the start and needed no change.

20. **Previously believed (Update 21 as first written, and as left by #19; 2026-09-19):** the
    rate cap was confirmed *empirically* — the D cells "achieved" 1000 msg/sec ("an actual
    achieved rate of 1000/sec ... empirically via `achieved_rate_per_sec=1000.0` on all 150
    D-cell trials", "about 1% under the requested cap"; table row "Achieved rate (D only):
    1000/sec (75/75)"; sanity paragraph "D cells' achieved rate exactly 1000/sec on all 3
    trials"). The exported CSVs carried the same value as `achieved_rate_per_sec`.
    **Actually:** `achieved_rate_per_sec` is `1000.0 / attacker_flood_delay_ms`, computed once
    at startup and printed by `src/main.cpp:122-125` — a nominal constant that prints 1000
    whenever the delay is 1ms, whatever the attacker really does. It measures nothing.
    Measured over all 150 D-cell trials (receiver-side `attacker_total` ÷ the attacker's own
    send time from its `[FloodRateCheck]` line, or `[AttackerRunSummary]` where that line was
    lost; 150/150 recoverable): mean **791 msg/sec**, median 793, range 743-842 (D_off mean 805,
    D_on mean 778) — about 21% under the nominal 1000 and 22% under the 1010 target, because
    `sleep_for(1ms)` overshoots and each message also costs generation/send time (the
    attacker's own `avg_actual_gap_ms` is 1.2-1.3ms). The cap does work as a ceiling (the
    uncapped attacker sent ~200,000 msg/sec), and the D results stand as an ~800 msg/sec flood
    below the 1010 channel ceiling; what was wrong was the claim of reaching ~1000. #19's
    back-of-envelope for a backstopped D run is adjusted accordingly (~48k, not ~60k).
    **Not affected:** every receiver-derived number in Update 21's table, reconciliation, and
    B/C. **Left unchanged on purpose:** `src/main.cpp`'s log label and the comment above it
    ("~1% under") are misleading, but editing the source would make the binary older than its
    source and force a rebuild in the middle of a dataset; every parser treats the field as
    nominal instead.
    Found while planning the vehicle-count scaling sweep, whose D-cell pilot gate was about to
    rely on this field.
    **Corrected in:** Update 21 (prose, sanity paragraph and table row now give nominal vs
    measured), `README.md` item 10, and the exports (`achieved_rate_*` columns renamed
    `nominal_rate_*`; `measured_rate_per_sec` / `measured_elapsed_*` added), 2026-09-19.

21. **Previously believed (Update 22 as written 2026-09-19, and Update 21's footnote ¹):** the 14 trials
    (of 1,320) in Update 21/22 with any late or dropped legitimate message were isolated ~0.4-0.75 s
    "stall"/pause events (Update 22: "one shared ~0.4-0.75 s pause ... a host/VM-level scheduling
    stall"); the 10 filter-on legit drops (all `STALE`) were "the filter's staleness check on messages
    that sat 0.4-0.6 s"; Update 21's 6 deviating trials were "the same class of run-to-run
    self-heal/backlog-timing variance" as Update 15; the cluster sizes (2.0/3.7/6.0 per event) were
    late/dropped *legit* messages; and stalls per 100 trials (1.00/1.25/0.00/2.08) were a comparable
    rate across levels.
    **Actually:** all 14 events, and the 3 pilot events, are **forward steps of the machine's wall clock,
    not delays.** (1) Each coincides (±0.5 s, the resolution of the 1-s send timestamp) with a
    `systemd-resolved: Clock change detected` journal entry: 17/17, chance ~10⁻²⁹. (2) Every journal entry
    carries realtime and monotonic timestamps, and the realtime-minus-monotonic jump at the matched entry
    equals the event's late-message latency to within 0-2 ms (mean −1.0 ms, SD 0.6; e.g. 527.3 ms vs
    +527, 737.9 vs +737, 586.6 vs +586). (3) The steps recur every 32.25 s (SD 0.02 s), always
    forward, typically +0.4-0.75 s, matching `systemd-timesyncd` (enabled, NTP=yes) with its 32 s minimum
    poll and stepping above ~0.4 s; the journal names only `systemd-resolved` as the detector, so naming
    timesyncd as the actor is an inference. (4) The receiver's latency and the filter's `STALE` test
    (`src/Vehicle.cpp`: `received_time - send_ts >= spam_filter_admit_ms`) are both `system_clock` differences
    between two processes, so a forward step makes every message in flight at that instant look 0.4-0.75 s
    old: nothing was delayed, and the filter dropped fresh messages as "stale". (5) Sampler load/memory at
    the events was unremarkable (load1 percentile mean 45, 1 of 17 above the 90th) and the kernel journal
    has no scheduling warnings in either boot (nearest WSL `drop_caches` 92 s away).
    Also wrong in Update 22: (a) cluster sizes included attacker messages in the B/C/D cells; legit-only late
    messages per event are 1.2 (L=2), 2.0 (L=4), 4.4 (L=9); (b) "per 100 trials" was confounded by
    exposure: the stepping regime ran for all of Update 21 and in blocks during the sweep (on 23:17-01:37,
    01:40-04:09, 06:49-08:22; off 04:09-06:49), so L=6 had only 10 steps inside its trials and its zero is
    uninformative; per exposed step the rate is 1.09% (L=2, 6/552), 1.40% (L=4, 3/215), 0/10 (L=6), 3.47%
    (L=9, 5/144), rising with vehicle count as the mechanism predicts but with overlapping 95% intervals.
    **Not established:** why the guest clock falls behind ~0.4-0.75 s per 32 s in multi-hour blocks. It did
    not reproduce afterwards (idle, a 3-process CPU load and one real simulator trial, all run while the
    regime was off, showed no drift against the Windows host clock), and the Windows System event log has
    no power/sleep events at any transition.
    **Effect on conclusions:** no real delay to legitimate traffic was observed at any level; the 10 filter-on
    drops and every deadline-miss count in Updates 21/22 are artifacts of clock stepping, not filter or
    receiver cost. The same artifact can inflate deadline-miss, latency-tail and `STALE` numbers in *any*
    run on this machine while the regime is on (Updates 15/20, on the older VM, were not checked). Not
    affected: attacker-side numbers, cheap-reject fractions, reconciliation, send rates.
    **Corrected in:** Update 22 (answer, trend table, "What deviated" with an evidence table, pilots and
    resource sections) and Update 21 (footnote ¹ reworded, footnote ³ added), 2026-09-19;
    `context/BUGS.md` and `README.md` (recurrence guidance). No Update 21 or 22 number changed.

22. **Previously believed (Update 5, `UPDATES.md` ~line 405; code comments in `include/Vehicle.h` and
    `src/Vehicle.cpp`):** Falcon-512 hash-only frames are 761 B, segment-carrying frames (m=2) are 1583-1587 B,
    and the per-message signature array on the wire is 666 B.
    **Actually:** `~/liboqs-x86` was reinstalled as **liboqs 0.16.0** on 2026-09-17 ~15:06, which defines
    `OQS_SIG_falcon_512_length_signature` as **752** (was 666). `falcon_spdu::signature` is sized by that
    constant and always sent in full, so every build since then sends 845 B hash-only frames and
    858 + segment-length B segment-carrying frames (1671-1674 B at m=2); `sizeof(falcon_spdu)` went from
    1592 to 1720. Hash-only grew by 84 B (+86 B of signature array, -2 B of alignment padding before
    `cert_cycle`). Segment-carrying frames grew by 86 B: the same 84 B, plus 2 B from the later
    `fragment_count` field (1 B + 1 B padding). The actual Falcon signature length (~655-659 B) and the cert
    bundle (968 + 4 + cert-sig length = ~1627-1631 B) did not change. The last 761 B log is from
    2026-09-17 14:57 (`phase4_raw_logs/phase4_pilot_trials_n10_backup/`) and the first 845 B log is from
    2026-09-18 01:31. Re-verified 2026-10-11 with an m=2, n=4 `--test` run (RX: 48 x 845 B, 24 x 1671-1674 B)
    and a layout probe compiled against the headers.
    **Effect on conclusions:** every byte column in `exports/` (the seg_grid, the seg_sweep summaries and
    `mn_sweep_L6`) comes from the logged `wire_bytes` of post-upgrade runs and is correct. Any figure or text
    that uses 761 B / ~1,586 B, a ~666 B signature or a ~87 B payload (the current non-signature,
    non-hash overhead is 85 B) describes the pre-2026-09-17 build. Mean bytes per message from those values
    are low by 84 + 2m/τ B (86 B at n=0, 84.5 B at m=2, n=6), so the offset is not constant.
    Timing, count and verification results are unaffected.
    **Corrected in:** this entry (2026-10-11), and the "666 bytes" comments in `include/Vehicle.h` and
    `src/Vehicle.cpp`. `UPDATES.md` is left as written, per this log's convention.

## Also verified this session (not a doc-internal correction, but resolves an
"as of this Update, not yet implemented" note that would otherwise read as still current)

Update 9 flagged a cache-poisoning gap: the Phase-1 baseline path (`ccons_falcon`) caches
a reconstructed cert on full-hash integrity alone, with no cert-signature check — a fix
was "planned for Phase 3, not yet implemented" as of that update. Direct source read this
session (`grep` on `src/Vehicle.cpp`) confirms the fix **did land** in the Phase 3
spam-filter path: `spam_filter_verify_falcon` reconstructs, then requires
`cert_sig_ok` (a real `falcon_verify` call) to be true before writing to
`spam_filter_cert_cache` — a failed cert-sig verify is a terminal rejection that never
reaches message-sig verify, exactly as Update 9 specified. The *original* baseline path
(`ccons_falcon` → `falcon_reconstructed_certs`, used only when `spamFilterEnabled:false`)
still caches on hash alone — but that's correctly that path's documented
undefended-baseline behavior, not a residual defect. See `context/BUGS.md` for the full
citation.
