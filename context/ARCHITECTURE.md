# Architecture

The layer stack, locked-in design decisions (with rationale), terminology pitfalls, and
feasibility/scoping assessment. Read this when working on the RSU-Edge/Vehicle-Edge
design itself, the defense-layer stack, or anything touching Layer 2/2.5/3 scoping.

## Architecture: the (Three/Four-)Layer Stack

Naming note, state this explicitly whenever presenting to avoid confusion: **"Vehicle
Edge"** is Paper 3's original edge-local concept; **"RSU Edge"** is our extension — VANETs
have roadside infrastructure that UAV swarms (Paper 3's domain) don't, so centralizing
some decisions there is viable in a way it wasn't for them. Both are "edge" as opposed to
cloud/centralized — the distinction is *which* edge node, not edge-vs-non-edge.

| Layer | Mechanism | Tier | Depends on | Notes |
|---|---|---|---|---|
| 1 | **Spam Filter** | Vehicle Edge | Nothing — standalone | Per-message admission check. Primary, load-bearing DoS defense. Works with a static algorithm. This is the safe, comfortably-implementable deliverable. |
| — | **Hashed Certificate** | Vehicle Edge (+ optionally RSU Edge) | Shared CA | Cache full cert after first verification, match by hash on repeat senders — cheap, skips full re-verify. **Cache-defeated by certificate-churn flooding** (attacker rotates hash IDs so nothing matches the cache) — needs a separate rate-limit on first-time-seen certs specifically. **NOTE: the parenthetical "everything looks first-seen" framing here is corrected in Update 9** — churned certs are fabricated/self-signed and are *always correctly rejected* as invalid-cert-signature, they do not look like valid first-seen senders. |
| 2 | **Agile Cryptography Protocol** | RSU Edge | RSU infrastructure | Aggregates BSM-rate signal across vehicles in range, issues protocol-switch advisories. **Not implementable as-is in PQ-V2Verifier** — it's pure V2V, no RSU/infra-node concept exists in the testbed. |
| 3 | **Safety Contract** | Vehicle Edge | Only meaningful if Layer 2 exists | Gates any proposed algorithm/protocol switch (from RSU advisory OR local trigger) against hard floors before enactment. Closes the downgrade-attack surface Layer 2 introduces. |

**Locked-in design decisions:**
- RSU issues **advisories, not commands** — a vehicle combines the RSU signal with its
  own local corroborating evidence before acting. Prevents a spoofed/compromised RSU from
  forcing downgrades directly.

  **Why RSUs advise instead of command.** In the SCMS (Security Credential Management
  System) trust model underlying IEEE 1609.2 — which IEEE 1609.2.1 extends with
  certificate-management detail applicable to infrastructure devices — an RSU is an End
  Entity (EE), not a Certificate Authority (CA). Holding a valid EE certificate only
  proves the RSU is a legitimate, CA-enrolled participant; it does not make the RSU a
  root of trust, and its authority is exactly as delegated and revocable as any vehicle's.
  A signed message from an RSU is therefore the same *kind* of claim as a signed message
  from a vehicle — one participant's attestation — not a CA-level directive. Treating an
  RSU's protocol-switch signal as a binding command would silently promote an EE
  credential to CA-level authority it was never issued, and would hand a single spoofed
  or compromised RSU (no harder to compromise than any other EE) the ability to force a
  downgrade across every vehicle in range. Requiring a vehicle to corroborate the RSU's
  advisory with its own local evidence before acting keeps the actual trust boundary
  where SCMS puts it — at the CA — rather than relocating it to whichever EE happens to
  be fixed infrastructure.
- Layer 1 sheds load *before* Layer 2 ever proposes a switch — attacker must defeat local
  filtering first.
- Top-down (RSU-aggregated) signal is primary/authoritative; bottom-up (vehicle
  self-reports) require a quorum of independent vehicles before being trusted — a single
  self-report is a trivial one-message downgrade attack.

## Terminology pitfalls — keep these strictly separate

- **Safety Contract** = validates a *proposed protocol/algorithm change* against 5 formal
  invariants before enacting it (QuantumResistance, EnergyBounded, CycleLimited,
  RefreshValid, DeadlineMet — fail-closed, revert to last verified config on any
  violation). It is NOT a per-message check.
- **Spam Filter** = validates individual incoming BSMs.
- These two have been conflated in past slides/drafts — if editing report/poster content,
  check for recurrence.
- "RSU-Edge vs. Vehicle-Edge" is NOT an edge-vs-cloud distinction — both are edge.

## Feasibility / scoping (already assessed, don't relitigate without new info)

- **Layer 1 + verify-exhaustion attack:** solid fit, comfortably implementable in
  PQ-V2Verifier as-is. This is the primary deliverable — prioritize it.
- **Layer 2 (Agile Protocol):** algorithm-switching itself is code-feasible via liboqs.
  The testbed has no environmental-context detection — don't try to build urban/rural/
  highway classification from scratch. Simplify the trigger to a real-time load signal
  (queue depth / arrival rate) derivable from Layer 1's own instrumentation.
- **Layer 2.5 (RSU coordination):** cannot be implemented in PQ-V2Verifier as-is. Plan:
  fully implement/evaluate Layers 1–3, treat RSU-Edge coordination as a **design
  contribution** (architecture diagram + written justification + threat-model reasoning),
  not working code — unless multi-vehicle interaction turns out to exist, in which case
  the cheap approximation is hacking the RSU in as just another "vehicle" node
  broadcasting advisories via existing primitives. **Note: multi-vehicle interaction was
  confirmed to exist in Update 2** — the fallback condition has been met, but whether to
  actually pursue the cheap RSU-as-vehicle approximation instead of (or alongside) the
  design-only treatment has not been revisited since (see `context/OPEN_QUESTIONS.md`).
- **Layer 3 (Safety Contract):** feasible as a largely self-contained threshold-check
  module, low implementation risk, fed by benchmark timing data (PQ-Benchmarks or raw
  liboqs timing).
