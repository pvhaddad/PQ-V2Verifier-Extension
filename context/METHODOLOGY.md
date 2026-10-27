# Evaluation Methodology

Read this when designing or running a benchmark: the defense-ablation matrix, the
dependent variables to report, and the statistics standard to hit before this reaches the
report. See `context/UPDATES.md` (Updates 13–20) for how this methodology was actually
applied — this file is the standing methodology, not the results.

**Defense ablation matrix (currently 3-tier, possibly needs a 4th):**
1. Spam filter only
2. Spam filter + Agile
3. Spam filter + Agile + Hashed Cert

Open question, **not yet resolved with grad student**: whether Safety Contract needs its
own on/off toggle in this matrix (to show it does something measurable) or should be
treated as always-bundled whenever Agile is present. Don't unilaterally decide this —
flag it. (Note: Phase 4, per `context/UPDATES.md` Update 13, ended up running a
**single-tier** ablation only — no-defense vs. spam-filter-only — since Layers 2/3 aren't
implemented in the testbed. The 3-tier matrix above remains the target if/when Layer 2 is
built; it has not been run.)

**Dependent variables:**
- Verification latency — **tail (95th/99th percentile), not just average**, given the
  ~100ms deadline.
- Legitimate-vehicle message drop rate specifically — must exclude attacker messages you
  *want* dropped, don't report overall drop rate.
- Deadline-miss ratio (>100ms).
- Agile switch frequency.

**Statistics — not yet added, should borrow from related papers:** Wilson score 95% CIs,
fixed trial count per condition (related work used 40–75 trials/cell). Trial count was
scaled up to N=75/cell in practice (Update 14/15/20); Wilson CIs themselves are still not
computed as of Update 20 (see `context/OPEN_QUESTIONS.md`).
