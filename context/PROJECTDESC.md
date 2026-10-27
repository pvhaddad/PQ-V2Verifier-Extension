# Project Description

Full project summary, plus related-paper
findings and the historical "current status" snapshots. Read this when you need the full
project framing, citations for related work, or a sense of how the project's status has
evolved over time (the root file only keeps the *current* status line, overwritten each
time — this file keeps the history).

## Project in one paragraph

Research project investigating a DoS vector introduced by post-quantum cryptography
in V2X/VANET communications: PQC signatures are larger and slower to verify than ECDSA,
so an attacker can flood a vehicle with expensive-to-verify (or invalid) PQC-signed
messages, exhausting its verification budget and crowding out genuine safety-critical
Basic Safety Messages (BSMs). BSMs broadcast at ~10Hz and must be verified within a
~100ms deadline — miss it and it's a "denial-of-safety" attack, not just a dropped packet.

**Deliverables:** (1) reproducible PQC verify-cost benchmark table, (2) instrumented
BSM-verification simulation, (3) working verify-flooding attack + budget/admission
defense, (4) short report + poster + code repo.

## Related-paper findings worth knowing (don't re-derive)

- Real hardware measurement (ARM Cortex-A53): **FN-DSA-512 verification (0.5ms) was
  faster than ECC verification (27.26ms)** in that setup — counterpoint to a blanket
  "PQC is always slower" framing. Verification cost is algorithm/implementation-specific.
- A related paper's "packet loss is acceptable" conclusion relied on CPM message
  redundancy (multiple senders reporting overlapping data). **This does not generalize to
  BSMs**, which are non-redundant (a single vehicle's own position/speed). Flag this if
  ever reusing that result.
- A related UAV-swarm safety-contract framework reported 81.7% overall attack-success
  reduction across six attack types, but **Timing Disruption was its weakest-defended
  category (48.8% residual success)** — structurally the closest analogue to our
  verify-exhaustion attack. Don't assume that framework solves verify-exhaustion by
  default; the authors themselves flag it as their weak point.

## Status history

The current status lives in `README.md`'s "Project Status" section.
This section preserves the earlier snapshots for historical reference.

**As of the initial project notes (pre-Update-1, Week 8–10 of implementation):**
Week 8–10 of implementation. Advised by a professor, working day-to-day with a grad
student. Treat requests to "just implement Layer 2 fully" or similar with the feasibility
notes above in mind — surface the scoping tradeoff rather than silently overriding it.

**As of Update 20 (latest, see `context/UPDATES.md` for full detail):** Falcon-512
message path, certificate fragmentation, the Phase 3 spam filter (all 5 checkpoints
passed), and the Phase 4 defended-vs-undefended benchmark matrix (N=75/cell across three
attack conditions × filter on/off, plus a fourth attack-mode pilot scaled to N=75) are all
implemented and verified end-to-end. Headline result: the spam filter collapses cert-sig
verification from ~2597/2600 messages under flood to exactly 2 (the two legitimate
vehicles' one-time reconstructions) — a ~99.9% reduction in attacker-driven crypto cost —
at a small, fully-understood, self-healing cost to legitimate traffic. Wilson score CIs
and the Safety Contract ablation-matrix-toggle question remain open (see
`context/OPEN_QUESTIONS.md`).
