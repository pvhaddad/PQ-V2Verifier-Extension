# Open Questions

Undecided design choices found across `context/UPDATES.md` — things that need a person's
input or a decision, not code defects (those are in `context/BUGS.md`). Don't
unilaterally resolve any of these; surface them when they're relevant to a task.

- **Does the Safety Contract need its own on/off toggle in the defense-ablation matrix?**
  (To show it does something measurable on its own, vs. being treated as always-bundled
  whenever the Agile Protocol is present.) Explicitly flagged as "not yet resolved with
  grad student" — don't unilaterally decide this. (Evaluation methodology section /
  `context/METHODOLOGY.md`)
- **Should `common_cert_fields::hostname` (a dead field, ~32 bytes/cert) be removed?**
  Flagged as a possible future cross-cutting cleanup, explicitly not resolved — "raise
  with Geoff/Hassan before touching it," since removing it would touch ECDSA's cert
  struct layout and signature, not just Falcon's. See `context/BUGS.md` for the technical
  detail. (Update 5)
- **What does `main.cpp`'s receiver-reconstruction pattern actually do across outer-loop
  iterations?** `v1` (the receiver `Vehicle`) is reconstructed fresh on every outer-loop
  iteration instead of once outside the loop, and each iteration requests the full
  `num_msgs * num_vehicles` again rather than a partitioned slice. Unclear whether
  `receive()` internally drains a shared queue (making later iterations no-ops) or
  genuinely reprocesses. Explicitly flagged "needs its own investigation pass," never
  followed up. Check before relying on iteration count for anything in experimental
  design. (Update 2)
- **What does the `sockfd2`/GUI socket path in `receive()` actually do, and does it
  matter?** A second, separate socket exists in `receive()`, not yet investigated, not
  currently blocking anything. Noted for completeness only. (Update 2)
- **What is the exact OS/virtualization mechanism behind the scheduling/wake-latency
  spikes** (hypervisor steal time vs. Linux CFS scheduler latency vs. something else)
  that cause rare backlog growth and deadline misses? Strong circumstantial evidence
  narrowed it to "environment-level, not a code defect," but the precise mechanism was
  never pinned down — a few `vmstat` samples showed 0 steal time, but that's not a
  thorough check. Would need further investigation if challenged in the report. (Update
  8; see `context/BUGS.md` for the practical implication.)
- **Does the ~5-10% margin between a single attacker's achievable signing rate and the
  receiver's achieved processing rate stay transient at a higher aggregate flood rate**
  (multiple concurrent attackers, or a single attacker on faster hardware)? Not
  established either way at the scales tested. "Re-check if the ratio sweep pushes past
  what's been tested here." Note: multi-attacker/distributed flooding as a *threat model*
  is explicitly excluded (see below) — this question is narrower, about whether the
  existing single-attacker margin analysis generalizes, not about testing a new threat
  model. (Update 6)
- **Wilson score 95% confidence intervals are still not computed.** Flagged in the
  original methodology, deferred at N=5, deferred again at the N=5→75 scale-up ("worth
  doing before report if time permits, not done in this pass"), and still not done as of
  the latest N=75 runs (Updates 13-20). The aggregator already has per-trial fractions in
  hand, so this should be cheap to add. (`context/METHODOLOGY.md`; Update 13-20)
- **Why did condition A's (no-attack) deadline-miss rate drop from a nonzero N=5 average
  (0.83%) to exactly 0% at N=75?** Two non-exclusive candidate explanations were offered
  (an unlucky small N=5 sample vs. environment-history-dependent spike frequency
  following a fresh VM reboot) but neither was confirmed. Flagged as an open
  environmental question, not resolved. (Update 15, Correction 3)
- **Does `D_off`/`D_on`'s (the `CHEAP_INVALID_SIGNATURE` cell pair) clean 0/150-trial
  legitimate-drop record — versus B_on/C_on's 16/75 and 24/75 — reflect a real
  mechanistic difference, or sample luck?** Noted as an open observation, explicitly not
  traced. Worth revisiting if D_off/D_on are ever pushed to report-quality analysis
  alongside B/C. (Update 20)
- **Should the Layer 2.5 "RSU as just another vehicle node" cheap approximation actually
  be pursued**, now that Update 2 confirmed real multi-vehicle interaction exists in the
  testbed (the condition the Feasibility section's fallback plan was waiting on)? The
  triggering condition was met, but whether to actually build it — instead of, or
  alongside, treating RSU-Edge coordination as a design-only contribution — has never
  been revisited. (`context/ARCHITECTURE.md` Feasibility section / Update 2)

## Explicitly excluded — not open questions, don't re-raise

- **Multi-attacker/distributed flooding as a threat model.** Considered and deliberately
  excluded, not deferred: this project's threat model is a single malicious/compromised
  vehicle, not a coordinated multi-sender DDoS. "Don't revisit this as an open question in
  later phases; it was a deliberate scope decision, not an oversight." (Update 7)
