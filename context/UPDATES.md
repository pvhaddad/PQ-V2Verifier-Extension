# Updates Log

Chronological, verbatim engineering history (Update 1 through Update 20), moved unchanged
from the original project notes. This is the full audit trail — every status change,
finding, correction, and checkpoint result, in the order it happened. For a synthesized
view of just the corrections (stale beliefs that were later walked back), see
`context/CORRECTIONS.md` instead of re-deriving them by reading all 20 updates in order.
For just the outstanding defects/limitations or open design questions, see
`context/BUGS.md` / `context/OPEN_QUESTIONS.md`.

-----------------------------------------------------------------------------------------
## Update 1

## Falcon-512 Message Path — STATUS: IMPLEMENTED

The Falcon message path does NOT need to be rediscovered as missing — this was true of
the original public release but is no longer true of this repo. Confirmed absent from
both public artifacts before building it here: neither `pq-v2verifier` nor `pq-veins`
GitHub repos have real Falcon sign/verify wired into an actual message path.
`pq-veins`'s "Falcon" mode (`PQV2VApp.cc`) only inflates simulated message SIZE
(`FALCON_FULL_SPDU_SIZE_BITS`/`FALCON_DIGEST_SPDU_SIZE_BITS` constants) — zero hits for
"sign"/"verify" in that file, no real cryptographic operation. `pq-v2verifier`'s own
GitHub README confirms this is intentional: the testbed ships crypto *primitives* as
starter code, not a finished protocol.

**What exists now in this repo:**
- `falcon_spdu` struct (`Vehicle.h`, alongside `ecdsa_spdu`)
- `generate_falcon_spdu()`, `sign_message_falcon()`, `verify_message_falcon()`,
  `load_falcon_key()` (`Vehicle.cpp`) — structural mirrors of the ECDSA equivalents,
  adapted for two real differences: Falcon signatures are variable-length (max 666
  bytes, tracked via explicit length fields — do NOT assume fixed-size like ECDSA's
  72-byte buffer), and `falcon_sign`/`falcon_verify` operate on raw bytes directly (no
  SHA-256 pre-hash, unlike the ECDSA path's `sha256sum()`-then-sign pattern)
- `hex_to_bytes()` helper (`v2vcrypto.cpp`) — Falcon keys on disk
  (`falcon_keys/<n>/falcon.{key,pub}`) are hex-ASCII text, not PEM, so the existing
  `load_key()` (PEM/EC_KEY-specific) could not be reused
- `signatureScheme` field in `config.json` (`"ecdsa"` default / `"falcon"`), threaded
  through `arguments.h`/`main.cpp` into `transmit()`/`receive()`

**Known, deliberate limitations — do not "fix" without asking first:**
- Falcon uses a SINGLE keypair for both cert-signing and message-signing. No
  `cert_falcon_keys/` directory exists and none was generated. Documented scoping
  simplification (ECDSA's independent-key separation is a real security property from
  the Partially Hybrid paper's threat model — this is a known, stated gap, not an
  oversight) — must appear in report limitations section.
- Non-`--test` SDR/DSRC hardware framing path only supports ECDSA — no frame layout
  defined for the larger, variable-length Falcon struct. Falcon in that mode exits with
  an explicit error. Out of scope for this project.
- **ECDSA path is untouched** — `generate_ecdsa_spdu()`, `sign_message_ecdsa()`,
  `verify_message_ecdsa()`, `ecdsa_spdu` are byte-for-byte unchanged. Verified via
  `--test` regression run before/after (`Valid: TRUE` both times, matching).

**Files touched:** `include/ieee16092.h`, `include/Vehicle.h`, `src/Vehicle.cpp`,
`include/v2vcrypto.h`, `src/v2vcrypto.cpp`, `include/arguments.h`, `src/main.cpp`,
`config.json`.

## Attack implementation — status and order

Hassan's scoped order: (1) invalid-signature flooding, (2) valid-but-expensive message
flooding, (3) certificate-churn flooding, (4) algorithm-choice-as-cost-multiplier.
Touch points: `v2vcrypto.cpp`, `bsm.cpp`.

**STATUS: both variants #1 and #2 are now implemented and verified end-to-end — see
Update 3.** (This paragraph previously said #2 was "currently being implemented" and #1
"deferred" — that was accurate at the time it was written but is stale now; corrected
here rather than left to mislead. Variants #3/#4 remain out of scope, not started.)


-----------------------------------------------------------------------------------------
## Update 2

## Multi-Vehicle Interaction via `numVehicles > 2` — STATUS: CONFIRMED

This was the prerequisite blocker for any multi-vehicle attacker-ratio experiment. Traced
end-to-end via direct source reads (`main.cpp`, `Vehicle.cpp`) rather than assumed from
docs — do not re-derive.

**Finding: genuine many-to-one interaction is real, but only works in `--test` mode.**

- `main.cpp` (~lines 74–101): `num_vehicles` read from `config.json`
  (`scenario.numVehicles`). Creates `num_vehicles` distinct `Vehicle(i)` objects, spawns
  one `transmit_static` thread per vehicle via `std::thread` (real concurrency, not
  sequential trace replay), then constructs a single `Vehicle v1(0)` as the receiver,
  called with `num_msgs * num_vehicles`.
- `Vehicle::transmit()`: opens an ephemeral socket per call, sends via UDP to a **shared
  destination port** — every transmitting vehicle targets the same `servaddr`.
- `Vehicle::receive()`: binds **one** listening socket; `recvfrom()` captures `cliaddr`
  per packet, and `incoming_spdu.vehicle_id` is read and passed into
  `verify_message_ecdsa/falcon(..., vehicle_id_number)` — confirms the receiver correctly
  attributes each packet to its actual sender. This is real cross-vehicle traffic, not
  independent parallel replay.

**Port mismatch bug — use `--test` for all multi-vehicle runs, this is not optional:**

| Mode | `transmit()` dest port | `receive()` bind port | Works? |
|---|---|---|---|
| `test = true`  | 6666  | 6666 | Yes |
| `test = false` | 52001 | 4444 | No — mismatched, no packets ever arrive |

Non-`--test` mode is currently non-functional for multi-vehicle communication. This is
the only correctly-wired invocation path, not a workaround — state this explicitly (with
the port table) in the methodology section rather than leaving `--test` as an unexplained
flag.

**Minor, non-blocking:** `transmit()`'s destination uses `INADDR_ANY` (0.0.0.0) rather
than an explicit loopback address. Works on Linux (kernel treats 0.0.0.0 destination as
loopback in most configs); fragile if ever ported off Linux.

**Open follow-up — do NOT treat as resolved, needs its own investigation pass:**
1. `v1` is reconstructed fresh on every outer-loop iteration in `main.cpp` instead of
   once outside the loop, and each iteration requests the full `num_msgs * num_vehicles`
   again rather than a partitioned slice. Unclear whether `receive()` internally drains a
   shared queue (making later iterations no-ops) or genuinely reprocesses — check before
   relying on iteration count for anything in the experimental design.
2. `sockfd2` / gui socket path exists as a second, separate socket in `receive()` — not
   yet investigated, not currently blocking, noted for completeness only.

**Practical implication for experimental design:** the attacker:legitimate ratio sweep
(1:2, 1:5, etc.) is unblocked and can proceed using `numVehicles` + `--test`. Any
multi-vehicle Spam Filter evaluation must launch with `--test` or it will silently produce
zero received messages rather than an error — worth a defensive check/log line if this
becomes a recurring gotcha during benchmarking.


-----------------------------------------------------------------------------------------
## Update 3

## Scheme-Dispatch Refactor + Attacker Implementation (variants #1, #2) — STATUS: IMPLEMENTED

Both land together since the attacker work was deliberately sequenced *after* the refactor
(the attacker hook needed the post-refactor call sites, not the pre-refactor ones — see
below). Don't re-derive either; both were verified end-to-end via `--test` runs, not just
read through.

### Scheme-dispatch refactor

`Vehicle::transmit()`/`receive()` no longer branch on `signature_scheme` per-message.
Each now branches **once per call**, selecting a template instantiation that runs the
shared loop body for whichever scheme is active:
- `transmit_loop<SpduT>` (`Vehicle.h`/`.cpp`): takes a `generate_spdu` member-function
  pointer, owns the send loop + `post_process_spdu`/`inter_message_delay_ms` hook calls
  (see below).
- `receive_loop<SpduT>`: takes a `verify` member-function pointer and a `read_frame`
  lambda (captures the scheme-specific framing — ECDSA's non-test DSRC reassembly,
  Falcon's "not implemented" exit) built once by `receive()` before the loop starts.
- `print_bsm`/`print_spdu`/`forward_bsm_to_gui` collapsed from byte-for-byte-duplicated
  overload pairs into single templates.
- `scheme_frame_size(signature_scheme)` added to `arguments.h` (ECDSA 350B / Falcon
  2435B, NDSS Table III) — not consumed by anything yet, reserved for the still-unbuilt
  Spam Filter fragmentation stage.

**Adding a third scheme (Dilithium, Sphincs+) now means:** a new spdu struct + four
scheme-specific functions (generate/sign/verify/load_key) + one new `if`/`else if` branch
in `transmit()`/`receive()` picking the right template instantiation. No changes needed
to the loop bodies themselves.

**Constraint honored:** `generate_ecdsa_spdu`, `sign_message_ecdsa`, `verify_message_ecdsa`,
`ecdsa_spdu` are byte-for-byte unchanged — only *where they're called from* moved.

**Files touched:** `include/Vehicle.h`, `src/Vehicle.cpp`, `include/arguments.h`.

### Attacker implementation

`AttackerVehicle : public Vehicle` (`include/AttackerVehicle.h`, `src/AttackerVehicle.cpp`
— new files, added to `CMakeLists.txt`). Supports both in-scope variants via one
constructor param, no plugin/variant-registry system built for #3/#4 (out of scope,
not started):

- **Variant #2 (`EXPENSIVE_VALID`)**: overrides `inter_message_delay_ms()` to return a
  configurable flood delay instead of `Vehicle`'s hardcoded 100ms. Reuses the entire
  valid sign/verify path unchanged — messages are real, just fast.
- **Variant #1 (`INVALID_SIGNATURE`)**: overrides `post_process_spdu()` to flip the
  **last** byte of the already-signed signature buffer. This matters more than it sounds:
  flipping the *first* byte corrupts the DER SEQUENCE tag on ECDSA signatures, which
  makes `ECDSA_verify()` return `-1` (malformed input, not "invalid signature") —
  `v2vcrypto.cpp`'s `ecdsa_verify()` treats `-1` as fatal and calls `exit()`. Hit this for
  real (`Fatal error: ECDSA_verify returned -1: Bad address`) before switching to the last
  byte, which is always deep inside DER value content for ECDSA and just an opaque
  content byte for Falcon — safe for both. If this class is ever extended, do not flip
  byte 0 of an ECDSA-shaped signature buffer.

**Mechanism enabling both without touching `Vehicle`'s internals:** `post_process_spdu`/
`inter_message_delay_ms` are non-template virtuals on `Vehicle` (default no-op / 100ms),
type-erased to `(unsigned char* signature, unsigned int length)` rather than the full
`SpduT` — C++ doesn't allow virtual member function templates, and type-erasing down to
just what the attacker needs to mutate sidesteps that while still working uniformly
across `ecdsa_spdu`/`falcon_spdu`. Turned out **no `private`→`protected` promotions were
needed** (an earlier plan draft assumed they would be) — `AttackerVehicle` never touches
`generate_*_spdu`/`sign_message_*`/the spdu struct types directly.

**Config wiring** (`config.json`, additive to `numVehicles`, not carved out of it —
carving out would shrink the legitimate pool as the ratio sweeps, confounding the
experiment):
```json
"numAttackers": 1,
"attackerMode": "expensive_valid",   // or "invalid_signature"
"numAttackerMessages": 100
```
Attacker IDs occupy `[numVehicles, numVehicles + numAttackers)` — a new range above the
legitimate `[0, numVehicles)` range, so role is derivable from `vehicle_id` alone with no
wire-format change (`vehicle_id < numVehicles` => legitimate). `main.cpp`'s vehicle
container changed from `std::vector<Vehicle>` (value semantics, would slice the subclass)
to `std::vector<std::unique_ptr<Vehicle>>`. All three new config fields default to
values that make an old `config.json` without them behave identically to before
(`numAttackers` defaults to 0).

**Prerequisites this exposed, now resolved for the `numVehicles=2, numAttackers=1` case:**
`trace_files/` only had `0.csv` — `Vehicle::load_trace()` fatally exits for any other ID.
Duplicated to `1.csv`/`2.csv` (documented as a known simplification near `load_trace()`:
legitimate vehicles share identical trace data in these runs, meaning non-diverse BSM
content — fine for latency/drop-rate measurement, flag as a limitation if these results
reach the report). Keys (`keys/`, `cert_keys/`, `falcon_keys/`) already covered IDs 0-9,
so no key generation was needed for this ID range. **`scripts/generate_keys.py` is still
hardcoded to exactly 10 identities** (loop bound and directory bootstrap both hardcode
`10`) — will need parameterizing the first time a sweep needs `numVehicles + numAttackers
> 10`, not before.

**Verified end-to-end** (`--test`, both signature schemes where applicable):
- `numAttackers=0` regression: byte-identical behavior to pre-attacker code, including
  the first real (not just source-traced) run of `numVehicles=2`.
- Mixed run (`numVehicles=2, numAttackers=1, numAttackerMessages=100,
  attackerMode=expensive_valid`): 150/150 messages valid — 25+25 from legitimate
  vehicles 0/1, 100 from attacker vehicle 2.
- Same config with `attackerMode=invalid_signature`: 50/50 legitimate messages valid,
  100/100 attacker messages correctly rejected, no crash — confirms the last-byte-flip
  fix holds through the full config-driven path, not just an isolated unit check, and
  confirms legitimate traffic is unaffected by the attacker's presence.

**Not yet configurable, hardcoded for now:** attacker flood delay is hardcoded to 0ms in
`main.cpp` (send as fast as the vehicle can produce messages) — wasn't one of the three
config fields requested; add a fourth field if per-run delay tuning turns out to matter
for the ratio sweep.

**Still out of scope, not started:** variant #3 (certificate-churn flooding) and variant
#4 (algorithm-choice-as-cost-multiplier) — per Hassan's order, deferred, not abandoned.
`AttackerVehicle`'s two-mode design doesn't actively block adding them later but wasn't
built to anticipate them either.


-----------------------------------------------------------------------------------------
## Update 4

## Falcon Certificate Fragmentation + Spam Filter — STATUS: PLANNED, NOT YET IMPLEMENTED

**Correction: Phase 1 (segmentation + cycle, step 1 below) is now STATUS: IMPLEMENTED — see
Update 5.** Steps 2-4 (baseline benchmark, spam filter, defended benchmark) remain not started.
This heading and the STATUS line on step 1 below are stale as of Update 5; left as-is rather than
silently edited, per this doc's own convention — treat Update 5 as authoritative for Phase 1.

This is the stage `scheme_frame_size()` (Update 3, `arguments.h`, ECDSA 350B / Falcon
2435B) was reserved for but never consumed. Two prerequisites are already satisfied from
earlier updates — do not re-derive or re-build either:
- **Attacker already exists** (Update 3): `AttackerVehicle` variants #1
  (invalid-signature) and #2 (expensive-valid), verified end-to-end. Baseline
  benchmarking below reuses this as-is.
- **Multi-vehicle interaction already confirmed** (Update 2), `--test` mode only. All
  work and benchmarking in this section must run `--test` for the same port-mismatch
  reason documented there.

### Why fragmentation, not hash-referencing
Falcon-512 cert exceeds the 2,304-byte DSRC MAC-layer cap (IEEE 802.11-2020) by ~131
bytes. For a fair comparison against current IEEE 1609.2 hardware constraints, this must
be split across real frames — hash-referencing the cert away would dodge the comparison,
not make it. Falcon needs only **m=2** frames (contrast Dilithium/Sphincs+, which need
many more — future work, out of scope here).

### Certificate transmission cycle (τ = m + n messages) — periodic, not first-contact-only
Correction to an earlier draft of this section: the cert is **not** fragmented once at
first contact and then cached forever. It's re-broadcast on a **repeating cycle**: `m=2`
segment-carrying messages, followed by `n` hash-only messages, then the cycle repeats.
`m=2` is fixed (Falcon-specific, per above). **`n` is a tunable parameter** — no config
field name finalized yet, treat as a named placeholder (e.g. `certCycleHashOnlyCount`)
pending resolution, same pattern as the Agile Protocol placeholders. Confirmed default
for design purposes: `n=4`, giving `τ=6` messages per full cycle.

Per-message fields, confirmed from design diagram, sizes/naming grounded in Ben Jemaa,
Hebbal & Lonc ("Implementation and Impact Assessment of Quantum Safe Hybrid Signature in
V2X") — the paper already mapped in the project brief as the Hashed Certificate source:
- **Full Hash** — present on every message in the cycle (both segment-carrying and
  hash-only). This is `hashedId8` in the source paper: **SHA-256 of the full certificate,
  truncated to 8 bytes**, sent at variable rate `n` instead of re-sending the whole cert.
  It's the cache-lookup key for the hash-only fast path — a receiver that already holds
  the reconstructed cert for this sender matches Full Hash and skips straight to the
  cheap-checks path, no re-verification. Source paper: unknown hash (cert never seen in
  full) → message dropped as "cryptographic packet loss" — same behavior our shared drop
  node should produce on Full Hash miss.
- **Seg Hash** — present only on the `m` segment-carrying messages, one per segment. Hash
  of that individual segment, not the whole cert. **RESOLVED: SHA-256 truncated to 8
  bytes**, same convention as Full Hash/`hashedId8` — not specified in source material,
  this is our own design decision, not a paper citation. Rationale: (1) frame budget is
  tight (Falcon already overshoots the 2304B cap by ~131 bytes even at m=2; a full 32-byte
  SHA-256 per segment would add 64B across the two segment messages vs. 16B truncated —
  potentially the difference between m=2 staying feasible or not), and (2) the security
  property actually needed here is second-preimage resistance (can an attacker forge a
  fake segment matching an already-broadcast hash?), not collision resistance — those have
  very different bounds (~2^n vs. ~2^(n/2) for an n-bit hash), and 2^64 is computationally
  infeasible against a 100ms-cadence BSM stream. This is an early cheap-reject check, not
  the system's security boundary (full cert PQ+ECDSA verification is that) — truncation
  doesn't weaken what it's actually relying on. Lets a receiver validate segment 0's
  integrity as soon as it arrives, without waiting on segment 1 — catches a
  corrupted/tampered segment immediately instead of only discovering it after full
  reconstruction fails.
- **Signature** — every message, all cycle positions (unrelated to cert fragmentation;
  this is the ordinary per-BSM signature, already implemented per Update 1/3).

### Implementation order — do not reorder
Each phase's benchmark harness depends on the previous phase being real, not stubbed.
1. **Certificate segmentation + cycle.** `CFrag`/`CCons` for Falcon only, m=2. Split into
   roughly-equal segments within the 2304B cap; reconstruct before verification. Implement
   the full τ=m+n periodic cycle (not a one-shot fragmentation), with `n` as a named,
   tunable config parameter, not a hardcoded 4. Wire into the actual transmit/receive
   path — traffic on the wire must be genuinely frame-constrained, not conceptually
   split. Include Full Hash (every message) and Seg Hash (segment messages only).
2. **Baseline benchmark, no defenses.** Run the existing attacker (variants #1/#2)
   against fragmented, cyclic Falcon traffic with no spam filter present. Build metrics
   instrumentation now — tail latency (95th/99th pct), legitimate-vehicle drop rate
   (excludes attacker messages), deadline-miss ratio (>100ms) — as a harness reused
   **unmodified** in step 4. Do not build two separate harnesses; any difference between
   them undermines the before/after comparison.
3. **Spam filter.** Cheap checks → fragment index validation → **Seg Hash check (segment
   messages only, reject early on mismatch)** → buffer completeness + slot-cap mitigation
   (below) → full Falcon-512 verify → cache Full Hash. Full-Hash-match fast path for
   repeat senders. Shared drop node for any failed check.
4. **Benchmark with defenses.** Same attacker, same harness, same metrics as step 2 —
   only the spam filter is switched on. This is the "spam filter only" ablation cell.

### Fragment buffer slot-cap mitigation (incomplete-fragment-flooding defense)
Fragmentation introduces a new attack surface: an attacker opens many partial
reconstruction buffers without completing them. Mitigation: **cap = 1 open fragment
buffer per sender identity.** Still holds under the periodic cycle (corrected above): a
sender only has **one segment-transmission in progress at a time** even though it recurs
every τ messages — cap=1 costs legitimate traffic nothing, at any point in the cycle,
while bounding memory a single identity can consume. (Earlier draft of this section
implied the buffer opens once at "first contact" — wrong; it opens at the start of every
cycle's `m`-segment window and should close well before the next one begins.)

```cpp
struct FragmentBuffer {
    SenderId sender_id;
    uint32_t fragment_set_id;   // identifies THIS cycle's segment-transmission instance —
                                 // must change cycle-to-cycle so a stale/evicted buffer
                                 // can't be confused with the next cycle's segment 0
    std::array<std::optional<std::vector<uint8_t>>, 2> fragments; // m=2 for Falcon
    std::array<uint8_t, 8> full_hash;  // hashedId8 (Ben Jemaa et al.) — SHA-256 of the
                                        // full cert, truncated to 8 bytes; cache key
    // Note: Seg Hash (SHA-256/8B, matches full_hash convention) is checked against each
    // incoming segment BEFORE it's stored here — see handling logic below. No need to
    // retain it in this struct once a segment has passed the check.
    uint64_t first_seen_ts_ms;
    bool is_complete() const {
        return fragments[0].has_value() && fragments[1].has_value();
    }
};

std::unordered_map<SenderId, FragmentBuffer> active_buffers; // cap = 1 per sender_id
constexpr uint32_t BUFFER_TTL_MS = 500; // cert-transmission-cycle timescale, NOT the
                                          // 100ms BSM admission deadline — do not conflate
```

Handling logic: incoming segment message first checked against its **Seg Hash** —
mismatch → drop immediately, never touches the buffer (catches corruption before
reconstruction is even attempted). Passes Seg Hash, no open buffer for sender → opens one
(`fragment_index` must be 0). Passes Seg Hash, matches the open buffer's
`fragment_set_id` → attaches; complete → reconstruct + verify against Full Hash + cache +
free slot. Passes Seg Hash but sender has an open buffer for a *different*
`fragment_set_id` → **DROP** (cap enforcement). Buffer older than `BUFFER_TTL_MS` → evict
regardless of state, freeing the slot ahead of the next cycle.

**Explicitly does NOT cover certificate-churning** (attacker rotates sender ID per
message — each new ID gets its own slot). That's variant #3, already deferred per
Hassan's order (Update 1) — this mitigation is scoped to single-identity buffer flooding
only. State this boundary explicitly if it reaches the report; don't imply the slot cap
solves churning too. **Superseded in part by Update 9** (Phase 3): a *global* cap on top
of this per-sender cap was added specifically to bound churn's memory blast radius — see
Update 9 for the corrected threat model and why the global cap does not need to be large.

**Secondary, out-of-scope observation (Phase 2 flood-scale testing):** at high enough
flood volume, the receiver's UDP socket can drop datagrams at the OS kernel layer
(confirmed via `/proc/net/snmp` `Udp: RcvbufErrors`, default `rmem_max` ≈208KB) before
they ever reach application code — a network-layer DoS mechanism, distinct from this
project's verify-exhaustion (compute-layer) thesis. Observed as a transient early-burst
effect at ~20k messages/flood in this environment (2 CPU cores), not a sustained
throughput ceiling — see Update 6. Don't conflate the two mechanisms if this resurfaces
at larger scale.


-----------------------------------------------------------------------------------------
## Update 5

## Falcon Cert Fragmentation Phase 1 (segmentation + cycle) — STATUS: IMPLEMENTED

Corrects Update 4's step-1 STATUS line — see the correction note at the top of that section.
Numbers below are from actual compiled/verified `--test` runs (single-vehicle cycle demo,
multi-vehicle isolation check, full production config with the attacker present), not the
plan-time hand-computed projections Update 4 carried. Steps 2-4 (baseline benchmark, spam
filter, defended benchmark) are still not started.

**Confirmed byte-budget numbers** (supersede Update 4's hand-computed estimates for anything
concerning the *new*, post-fragmentation wire format — Update 4's ≈2392B figure was for the
old, pre-fragmentation struct that embedded the whole cert every message, and isn't directly
comparable to the numbers below):
- `sizeof(falcon_spdu)` (new struct, cert moved out to `cert_cycle` envelope) = **1592 bytes**,
  printed at runtime via a standing debug line, not just asserted at plan time.
- Wire length actually sent/received, confirmed via both TX-side `wire_length()` and RX-side
  `recvfrom()` return value logging (the two matched exactly in every run): **HASH_ONLY = 761
  bytes**, consistent across every hash-only message observed. **SEGMENT_CARRYING ranged
  1583-1587 bytes** across observed cycles — not a fixed constant, because Falcon signature
  lengths are variable (actual length ≤666B max) and CFrag splits the actual-length cert
  bundle, not a padded-to-max one, so the exact split varies slightly cycle to cycle. Both
  comfortably under the 2304B DSRC cap, confirming m=2 with real runtime numbers.
- `static_assert(FALCON_CERT_SEGMENT_MAX_BYTES * FALCON_CERT_CYCLE_M >= FALCON_CERT_BUNDLE_MAX_BYTES)`
  (`ieee16092.h`) is a standing compile-time guard against a future silent regression in this
  math (e.g. a struct reorder or alignment change) — not just a one-time confirmation.

**Sign-once-per-cycle requirement — confirmed necessary, not just designed-for.** The Falcon
cert is (re-)signed exactly once per cycle, at `cycle_position == 0`, not once per message.
Falcon signing is randomized (nondeterministic): segments sliced from two separate signing
operations (i.e. re-signing between segment 0 and segment 1) would never concatenate back into
something that verifies. This was identified as a requirement during planning and is now
empirically validated — every cycle across every tested run (single-vehicle, multi-vehicle,
attacker-present) produced a successful `Reconstructed cert OK` and a subsequent `Valid: TRUE`,
which would not happen if this weren't respected. The per-message BSM signature is unaffected
and still freshly signed every message, unchanged.

**Dormant UB, found via a real crash, worth knowing if it ever resurfaces elsewhere.** Both
`ecdsa_explicit_certificate`/`ecdsa_implicit_certificate` and `falcon_explicit_certificate`
embed `common_cert_fields`, which contains a `std::string hostname`. Both schemes'
pre-fragmentation code paths already send these structs whole, raw, across a UDP socket
between two separate OS processes (`sendto`/`recvfrom` on `sizeof(spdu)`) — technically
undefined behavior, since a `std::string`'s internal (SSO) self-pointer becomes invalid once
its raw bytes are copied into a different object's memory. This has been silently harmless in
both the ECDSA path and the pre-Phase-1 Falcon path specifically because (a) the received
struct is only ever passed to `falcon_verify`/`sha256sum`/`ecdsa_verify` as an opaque byte
range — no `std::string` member function is ever invoked on it — and (b) `Vehicle::receive()`
terminates via `exit(0)`, which skips stack unwinding and local destructors entirely, so the
corrupted string object is never destructed either. Phase 1's own new code hit this for real
once: `ccons_falcon` originally reconstructed a `falcon_explicit_certificate` via raw `memcpy`
into a live object, which was then copy-constructed via `unordered_map` insertion
(`falcon_reconstructed_certs[sender_id] = entry`) — that copy-construction is what actually
dereferences the corrupted pointer, and it segfaulted. Fixed by storing/passing the
reconstructed cert as opaque bytes (`unsigned char[sizeof(falcon_explicit_certificate)]`)
end-to-end instead of a typed struct (`Vehicle.h`/`Vehicle.cpp`, `falcon_reconstructed_cert_entry`,
`ccons_falcon`). **Not an action item for the untouched ECDSA/pre-fragmentation-Falcon paths** —
flagging so a future crash from this same pattern (e.g. if something ever copy-constructs a
received cert struct, or `receive()` stops calling `exit()`) isn't mistaken for a new
regression.

**`common_cert_fields::hostname` is a dead field, confirmed via full-codebase grep — not
something Phase 1's blob-building swept in by accident.** Set exactly once, via its default
member initializer (`certificates.h:14`, `std::string hostname = "hostname"`); never assigned
or read anywhere else in the codebase. Distinct from, and unrelated to, `Vehicle::hostname`
(a separate field, defaults to `"null_hostname"`, exposed via `get_hostname()` — never copied
into any cert). Despite being inert placeholder data, it's already baked into **both** schemes'
cryptographic cert signatures pre-Phase-1 (whole-struct raw signing: ECDSA's
`sha256sum(&cert, sizeof(cert), ...)`, Falcon's `falcon_sign(..., &vehicle_certificate_falcon,
sizeof(vehicle_certificate_falcon), ...)`), so it can't be dropped from just the wire bundle
(`build_falcon_cert_bundle_blob`) without also changing what gets signed — the reconstructed
blob has to match the signed bytes exactly or verification fails. Because `common_cert_fields`
is shared across `ecdsa_implicit_certificate`/`ecdsa_explicit_certificate`/
`falcon_explicit_certificate`, actually removing it would touch ECDSA's cert struct layout and
signature too — out of scope for the "ECDSA byte-for-byte unchanged" constraint (Update 1).
Costs ~32 bytes (libstdc++ `std::string` layout) of every cert transmission/segment — real but
modest against the 897-byte Falcon public key dominating the ~968-byte cert struct. Flagged as
a possible future cross-cutting cleanup, not resolved here — raise with Geoff/Hassan before
touching it, since it's an ECDSA-affecting change, not a Falcon-only one.


-----------------------------------------------------------------------------------------
## Update 6

## Phase 2 flood-rate verification + transient-vs-sustained loss investigation — STATUS: RESOLVED

### Attacker flood is confirmed genuinely unpaced
`[FloodRateCheck]` instrumentation added to `Vehicle::transmit()`'s Falcon-only branch
(measures actual wall-clock inter-send gap, independent of the nominal
`inter_message_delay_ms()` setting). Directly confirms two separate "100ms" concepts in
this codebase don't get conflated: `inter_message_delay_ms()` (real send pacing, `0` for
attackers) vs. the unrelated hardcoded `100` inside `calculate_speed_kph()` (only affects
a BSM's reported `speed` content, zero effect on send timing). Measured: legit vehicles
~106-107ms actual gap (matches nominal 100ms + real signing/socket overhead); attacker
~4.5-4.6ms actual gap regardless of scale (300 to 20,000 messages) — ~23x faster,
confirming the flood is real, not accidentally rate-limited to look like normal traffic.

### `sync_with_stdio(false)` fixed a false "hang"
A 4900-message flood test previously hit a 2-minute tool timeout without crashing. Root
cause: heavy per-message console I/O (both Phase 1's `[FalconCertCycle]` lines and
pre-existing `SPDU received!`/`Calculated heading` prints) synchronized against C stdio by
default, adding large constant overhead unrelated to actual Falcon verify cost.
`std::ios_base::sync_with_stdio(false);` added once at the top of `main()` — pure
performance, produces byte-identical output, so it cannot affect ECDSA's Phase 1
"byte-for-byte unchanged" regression evidence. Same 4900-message run: 120s+ timeout → 23s.

### Loss at high flood volume is a transient burst, not a sustained rate mismatch
At 20,000 attacker messages (τ picked to stress-test), the receiver occasionally failed to
receive every message before `receive_loop`'s exact-count blocking wait hung forever (this
harness has no receive timeout - a real limitation, addressed below). Investigated whether
this reflects the receiver's steady-state Falcon-verify throughput being inadequate for the
attacker's send rate (a real, structural finding) versus a one-off kernel-buffer burst (a
testbed artifact). Added periodic (every 1000 msgs, not per-message) `[ReceiverProgress]`
throughput logging inside `verify_message_falcon`. Three independent pieces of evidence, all
pointing the same direction:
1. **Achieved rate is flat, not degrading**: ~222-243 msg/sec sustained across all 20,000
   messages, no downward trend — and this is at/slightly above the attacker's own measured
   average send rate (~220 msg/sec). A sustained mismatch would show the achieved rate
   trending down as backlog grows; it doesn't.
2. **`Udp: RcvbufErrors`** (`/proc/net/snmp`, polled every 3s during a run) incremented
   exactly once, by exactly the count of messages later found missing, at ~18s into a
   ~91s send window - then flat for the remaining 380s of observation. Loss concentrated
   early, not spread throughout - the transient-burst signature, not sustained.
3. **`ss -u -a -n` showed `Recv-Q = 0`** at a stall point - nothing backlogged waiting to
   be drained; the receiver is blocked on specific already-lost packets, not falling behind
   a growing queue.
Environment note: only 2 CPU cores available: 3 concurrent sender threads (2 legit + 1
attacker) plus the receiver process/thread all contend for them, and the early-burst timing
(~18s in) is consistent with startup contention as all sender threads spin up together,
not a fundamental algorithmic throughput ceiling.

**Caveat, not yet resolved:** the margin between achieved rate (~230/msg/sec) and the
single attacker's rate (~220/sec) is real but not large (~5-10%). This is transient at
*this* attack configuration (one attacker thread, `flood_delay_ms=0`); it is NOT
established to stay transient at a higher aggregate flood rate (multiple concurrent
attackers, or a single attacker on faster hardware). Re-check if the ratio sweep pushes
past what's been tested here.

**Fix confirmed working.** `net.core.rmem_max` raised out-of-band (`sudo sysctl -w
net.core.rmem_max=33554432`, 32MiB - sized to comfortably cover a full ~20k-message flood
at worst-case ~1585B/msg, doubled to 64MiB internally by the kernel).

**Session-scoped, not persistent — re-apply after every VM reboot.** Deliberately not
written to `/etc/sysctl.conf` (shared VM; a permanent system-wide change shouldn't
outlive this specific experiment). Resets to the ~208KB default on reboot. Re-run
`sudo sysctl -w net.core.rmem_max=33554432` before any flood-scale (thousands of
messages) benchmark run, or the exact transient-loss artifact diagnosed in this update
will silently reappear and could be mistaken for a new regression rather than this
already-solved, already-understood issue. App-side changes:
`SO_RCVBUF` set to 32MiB and `SO_RCVTIMEO` set to 5s on the receiver's socket (shared
between ECDSA/Falcon - safe for ECDSA under any realistic load: a bigger buffer is never
harmful, and 5s is enormously larger than any real inter-message gap, so it only trips on
genuine loss); `receive_loop`'s `read_frame` contract changed from `void` to `bool`
(false = timed out) so a future loss reports "received X of Y before timing out" instead
of hanging forever. Re-ran the same 20,000-attacker-message flood after raising the
ceiling: `[SocketConfig]` confirmed `actual=67108864` (64MiB, no longer clamped to
~208KB), zero `[ReceiveTimeout]` lines, full 20,400-message run completed cleanly in 90s
(previously hung indefinitely), 0% drop rate / 0% deadline-miss ratio for legitimate
traffic - confirms the transient-burst diagnosis was correct, not just plausible.

**Audit, prompted by finding the same `(socklen_t*)` bad-pointer-cast bug independently
twice** (once in the Falcon-only receive lambda while building Phase 1, once in the
ECDSA `read_frame` lambda while adding the timeout-detection logic above - both were
silently harmless because nothing checked `recvfrom()`'s return value until the timeout
logic needed to). Searched every `recvfrom()`/`recv()`/`accept()`/`getsockopt()`/
`getsockname()`/`getpeername()` call site in the codebase: exactly 3 `recvfrom()` calls
exist total (ECDSA test-mode, ECDSA non-test-mode, Falcon test-mode), no other socklen_t-
taking syscalls anywhere. All 3 now use correctly-typed local `socklen_t` variables; a
final grep for the `(socklen_t *)` cast pattern across the whole codebase returns nothing.
Confirmed clean, not just assumed clean from the two sites already found.

**Scope clarification, stated explicitly since downstream phases depend on it holding:**
the "ECDSA byte-for-byte unchanged" constraint (Update 1) constrains `ecdsa_spdu`'s struct
layout and wire protocol - what gets sent/received and how it's interpreted on the wire -
not "zero lines of code touched anywhere in ECDSA's call path." Fixing the `read_frame`
addrlen bug above, `receive_loop`'s `read_frame` signature change, the shared
`SO_RCVBUF`/`SO_RCVTIMEO` socket setup, and `sync_with_stdio(false)` all touch code that
runs during ECDSA's execution but none of them touch `ecdsa_spdu`'s layout or the wire
protocol - consistent with this reading. Verification method used throughout is stricter
than the boundary itself: exact `--test` output matching (identical `Valid:` counts,
byte-identical console output) as the empirical check, which is why new diagnostic prints
were deliberately kept inside Falcon-only branches even though they wouldn't violate the
struct/protocol boundary either - a self-imposed convenience for clean regression
comparison, not a separate scope rule.

See the project notes' earlier note (added alongside this update, in the Falcon Certificate
Fragmentation section) for the one-line pointer: this OS-level socket-buffer-overflow
mechanism is a network-layer DoS distinct from this project's verify-exhaustion
(compute-layer) thesis - real, but a secondary/out-of-scope observation, not what's being
studied here.


-----------------------------------------------------------------------------------------
## Update 7

## Phase 2 null-degradation result, explained: Falcon sign/verify cost asymmetry — STATUS: RESOLVED, PHASE 2 CLOSED

Closes the question Update 6 left open: is "no measurable degradation" under the
`expensive_valid`/`invalid_signature` flood (confirmed genuinely unpaced, confirmed not
an artifact of the OS socket-buffer issue) a real receiver-capacity finding, or could it
still be an artifact of how fast one attacker thread can produce valid Falcon-512
signatures? Instrumented `falcon_sign()`/`falcon_verify()` call cost directly (isolated
from surrounding socket/cycle/print overhead already covered by `[FloodRateCheck]`/
`[ReceiverProgress]`), from the same 20,000-message `expensive_valid` flood run:

- **Attacker-side Falcon signing** (vehicle=2, n=20,000 messages): avg **3.58ms**, p95
  **5.63ms** per message. Implies a theoretical single-thread ceiling of ~1000/3.58 ≈
  **279 msg/sec** - matches the independently-measured `[FloodRateCheck]` achieved rate
  (~220-230 msg/sec) once cert-cycle bookkeeping/socket overhead on top of raw signing is
  accounted for.
- **Receiver-side Falcon verification** (n=20,600 messages, message signature only): avg
  **0.033ms**, p95 **0.058ms** per message. Implies a theoretical receiver capacity of
  ~1000/0.033 ≈ **30,000 msg/sec** from crypto cost alone.
- **~109x asymmetry.** Falcon-512 signing (Gaussian/FFO sampling, floating-point heavy)
  is far more expensive than verification (NTT-based polynomial ops + norm check) - this
  is the expected, documented shape of Falcon's cost profile, now measured directly in
  this testbed rather than assumed from the literature.

**What this means for Phase 2's result:** the null-degradation finding is a real,
receiver-capacity finding, not a broken test - but the reason is specifically that **a
single attacker's own signing cost is self-limiting** for this attack shape. One
malicious/compromised vehicle cannot forge Falcon-512 messages fast enough (~279 msg/sec
theoretical max) to meaningfully stress the receiver's verify capacity (~30,000 msg/sec
theoretical max). This is Falcon-512's sign/verify cost asymmetry running in the
defender's favor for the single-attacker threat model this project studies - a genuine,
citable result, not an absence of one.

**Multi-attacker/distributed flooding was considered and explicitly excluded, not
deferred as an open question.** Standing up several parallel attacker threads/processes
to push combined signing throughput past the single-thread ceiling would test a
distributed-flooding threat model - out of scope. This project's threat model (stated at
the top of this doc) is a single malicious/compromised vehicle exploiting the PQC
verify-cost/deadline mismatch, not a coordinated multi-sender DDoS. Don't revisit this as
an open question in later phases; it was a deliberate scope decision, not an oversight.

**Flagged for future work, not resolved here:** this sign/verify ratio is Falcon-512-specific
and should not be assumed to transfer to Dilithium or Sphincs+ if either gets implemented
later - their sign/verify cost profiles differ structurally (e.g., Dilithium's rejection
sampling has a different cost shape than Falcon's Gaussian sampling). Re-measure with the
same `[FalconSignCost]`/verify-cost-isolation approach if that work happens; don't assume
this ~109x figure carries over.

**Phase 2 is closed with this explanation attached.** Phase 3 (spam filter) proceeds per
Update 4's plan.


-----------------------------------------------------------------------------------------
## Update 8

## Backlog mechanism investigation (rare legit deadline-misses at 20k-message scale) — STATUS: ROOT CAUSE IDENTIFIED, ENVIRONMENT-LEVEL, NOT A CODE DEFECT

Reopens the "Phase 2 closed" call from Update 7. Rederiving Update 7's benchmark numbers live
(not from memory) surfaced something the earlier summary missed: two back-to-back runs of the
*identical* `invalid_signature`/20k-message config gave different legitimate deadline-miss
counts (2/600 vs 0/600). Investigating that inconsistency led to a permanent per-message
`[DeadlineMiss]` diagnostic (`verify_message_falcon`), which revealed the attacker's own
messages regularly miss the 100ms deadline (hundreds out of 20,000, latency climbing as high
as ~980ms over the course of a run) and occasionally so does a legitimate message (0-2 out of
600, latency up to 161ms while still verifying `VALID`) — a real, if rare, degradation effect
Update 7's "0% every run" framing did not capture.

### What was ruled out (measured, not assumed)
1. **Crypto verify cost** — already measured in Update 7 (~0.035ms/msg avg). Confirmed still
   negligible here too.
2. **`std::endl` forced-flush I/O overhead** — strong initial hypothesis (12+ unconditional
   flushing prints per message across `receive_loop`/`print_spdu`/`print_bsm`/Falcon-only
   lines). Replaced with `'\n'` throughout the hot receive path (safe under the "byte-for-byte
   unchanged" constraint: `exit()` still flushes/destructs static-duration streams, so final
   log content is unaffected, only when it's physically written) - re-ran the identical flood:
   loop-iteration cost was unchanged (4.29ms -> 4.63ms, noise-level, if anything slightly
   worse) and attacker deadline-misses got worse, not better (686 -> 1547). **Hypothesis
   rejected by direct measurement** - kept the fix anyway since it's a harmless, real
   improvement (fewer syscalls per message), just not the cause.
3. **Receiver CPU starvation from contention with the attacker's signing thread** — checked via
   `ps`/`/proc/<pid>/status` sampled every 4s through a live flood run. Receiver: ~4% CPU,
   `voluntary_ctxt_switches` climbing steadily (~170/sec) with almost no
   `nonvoluntary_ctxt_switches` (~2/sec) - it's mostly blocked in `recvfrom()` waiting
   (voluntary), not being preempted. Transmitter (3 worker threads + main): ~103-107% CPU on
   the 2-core environment - using barely more than one core. **Rejected**: the receiver has
   ample spare CPU capacity: it isn't starved, it's genuinely idle most of the time.
4. **Sender-side throughput degrading over a long run** — measured the attacker's own
   per-message send gap (`generate_falcon_spdu` call-to-call), split first-half vs second-half
   of a 20k-message run: 4.77ms vs 4.76ms avg - flat, no trend, max only 37.3ms. **Rejected**:
   the attacker's own production rate is stable throughout; it does not get slower over time.

### What the evidence points to instead
Isolated `recvfrom()`'s own call duration directly (wrapped just the syscall, Falcon-only,
separate from the "full loop iteration" measurement that includes prints/verify/bookkeeping):
avg **4.55ms**, accounting for nearly the entire 4.68ms full-loop-iteration average, with a
max of **1093.73ms for a single syscall** - on loopback UDP, with no real network latency, a
blocking call taking over a second cannot reflect genuine I/O wait once data exists; it
reflects the calling process not being scheduled back to running promptly.

The symmetric clue: the two **legitimate** vehicles' send-side threads (`sleep_for(100ms)`
between messages, the simplest possible blocking-wait pattern in this codebase) show the
*same* signature independently - measured average gap 105-125ms (already somewhat over the
nominal 100ms) with **max gaps of 1084ms and 1101ms** in the same run. A `sleep_for` call
"waking up" 10x late is the same category of event as a blocked `recvfrom()` "waking up" late
- both are examples of a thread that was sleeping/blocked not getting scheduled back onto a
CPU promptly when its wait condition was satisfied, not a data-availability or crypto-cost
problem. That this shows up independently on the send side (a totally different code path,
totally different wait mechanism) and the receive side is what makes an environment-level
scheduling/wake-latency explanation more convincing than a codebase-specific one.

**Conclusion: this is an environment characteristic of the specific 2-core (`nproc`=2) test VM
this project has been running on, not a software inefficiency in PQ-V2Verifier's Falcon
implementation.** The steady-state numbers are not close to any edge: attacker production
(~4.7-4.8ms/msg, ~210/sec) and receiver crypto capacity (~0.035ms/msg, ~28,000/sec theoretical)
have a huge margin between them, matching Update 7's asymmetry finding. What actually causes
the rare backlog growth and occasional legitimate-message deadline miss is **rare,
unpredictable scheduling/wake-latency spikes** (visible as long max values, not a shifted
average) affecting *any* blocked or sleeping thread in this environment under sustained load -
each spike adds a delay that every message queued behind it inherits until the backlog drains,
which is why latency climbs within a run rather than staying flat, and why it's probabilistic
whether a given legitimate message (out of only 600, against 20,000 attacker messages) happens
to land in one of these windows.

**Not fully closed - what's still unproven:** this investigation shows strong circumstantial
evidence (the receive-side/send-side symmetry, ruling out four more specific causes by direct
measurement) but has not pinned down the *exact* OS/virtualization mechanism (e.g., hypervisor
steal time vs. Linux CFS scheduler latency under this specific load pattern vs. something else
entirely). A few `vmstat` samples during one run showed 0 steal time, but that's not a
thorough check across many runs/conditions. If this ever needs to be defended in the report
beyond "measured, ruled out four specific causes, environment-level scheduling latency is the
remaining explanation," that would need further investigation - flagged here rather than
overclaimed.

**Practical implication for the benchmark methodology:** Phase 2's headline "0% degradation"
result (Update 6/7) is still directionally correct at the scales tested - this is a rare,
environment-driven effect, not a systematic one - but should not be reported as a flat "0%
across the board" without this caveat attached. The new `[DeadlineMiss]`,
`[FalconSendGapTrend]`, and the "FULL loop iteration cost" / "recvfrom() syscall duration"
lines in the metrics summary are now permanent instrumentation, not one-off diagnostics - any
future benchmark run at this scale should check them before reporting a clean result.


-----------------------------------------------------------------------------------------
## Update 9

## Certificate-churn threat-model correction — STATUS: CORRECTED, Phase 3 design updated accordingly

Corrects the churn framing used everywhere above (the Hashed Certificate table row, Update
1's variant list, Update 4's slot-cap section) before Phase 3 (Spam Filter) implementation
began. Not a new constraint - this is the D1P1.a paper's own formal threat model, which
earlier passes through this doc failed to fold into the churn description.

### The correction
**The attacker's *CA-signed* pseudonym cert supply is exactly 1** ("unable to acquire more
than one pseudonym certificate per pseudonym from CA"). Consequence: a single attacker
**cannot** rotate through multiple *valid* identities. Every earlier description of
certificate-churn flooding in this doc that implied the attacker looks like a stream of
legitimate first-seen senders ("exploiting legitimate pseudonym rotation... without
violating CA policy", "attacker never reuses a cert, so everything looks first-seen") is
**overstated**.

What the attacker actually can do: **fabricate self-signed certs with rotating hash IDs**
to force a cache miss on every message (defeats the Hashed Certificate mitigation's
caching, which is real and unchanged). But a fabricated cert does not chain to the trusted
root, so full verification of a churned message **always resolves to
invalid-cert-signature, never VALID.** Churn is therefore best understood as a variant of
**attack #2 (invalid-signature flooding)** with cache-defeating identity rotation layered
on top - **not** a stealthy trust-bypass. Report/limitations-slide framing should soften
from "hardest attack case to close" to **"forces repeated compute-cost verification of
traffic that is always correctly rejected."**

### Correctness implication this exposed (designed into Phase 3's spam filter; NOT YET IMPLEMENTED as of this Update)
The Phase-1 placeholder reconstruction logic - live today at `ccons_falcon`
(`Vehicle.cpp:622`, called `Vehicle.cpp:726`) - caches a reconstructed cert into
`falcon_reconstructed_certs[sender_id]` (`Vehicle.cpp:727`) on **full-hash integrity
alone**: it never checks cert-*signature* validity before caching (confirmed by reading
the call site - `ccons_falcon`'s own success is the only gate on the `if` at
`Vehicle.cpp:726` that leads to the cache write). Under the corrected model, a fabricated
cert reconstructs just fine (the attacker computes its own `full_hash` correctly over its
own fabricated bytes) and **would be cached today if this code path is exercised by a
churn attacker**, silently poisoning the hashedId8 fast path for that fabricated identity.
**Required fix, load-bearing for "always correctly rejected" to hold at the code level and
not just in the write-up (planned for Phase 3, not yet implemented):** gate caching on
cert-sig `falcon_verify` success - reconstruct -> full-hash check -> **cert-sig verify ->
cache ONLY if valid**. A failed cert-sig verify must become a **terminal** outcome
(`INVALID_CERT_SIGNATURE`) that never falls through to message-sig verify (there is no
trusted key to check a message signature against once cert-sig verification has failed -
the only key material available would be whatever was extracted from the attacker's own
fabricated cert, which the attacker controls on both sides, so checking against it would
prove nothing). Until this fix lands, the *current* code's cache is exposed to exactly the
poisoning scenario described above if churn traffic is directed at it.

### What does NOT change
The buffer/cache memory-exhaustion concern the per-sender slot-cap (Update 4) defends
against is unaffected by this correction - the attacker can still fabricate unlimited fake
hash IDs locally regardless of real CA-cert count, so a per-sender cap alone still doesn't
bound total state across many *distinct fabricated sender identities*. Confirmed by direct
code citation, not assumed: the claimed sender identity (`spdu.vehicle_id`, wire field) is
never cryptographically checked against the cert content before being used as the lookup
key for both the verification public key (`load_falcon_key(vehicle_id, ...)`,
`Vehicle.cpp:686`) and the two per-sender reconstruction structures
(`falcon_cert_buffers[sender_id]` / `falcon_reconstructed_certs[sender_id]`,
`Vehicle.cpp:709,727`, both `unordered_map<uint8_t, ...>` keyed on that same unauthenticated
field, `Vehicle.h:83-84`) - so churn can still rotate `vehicle_id` per message even with
only 1 real CA cert. **Status: a global cap is PLANNED for Phase 3 (not yet implemented as
of this Update)** - a global LRU/TTL cap on top of the existing per-sender cap, specifically
to bound this residual memory surface; see the Phase 3 plan doc for the exact sizing
rationale (small, because with cert-sig-gated caching the *legitimate* cache will no longer
turn over at all once implemented: one entry per real vehicle, stable for its lifetime,
contingent on the companion sign-once-per-vehicle fix - also planned for Phase 3, also not
yet implemented). No change to the already-implemented fragmentation/buffer-cap mechanism
from this correction, only to the threat-model framing and the (not-yet-implemented)
cache-gating correctness fix described above.


-----------------------------------------------------------------------------------------
## Update 10

## Phase 3 spam filter implementation — STATUS: CODE COMPLETE, Checkpoint 1 PASSED

Dual-path admission control (Path A/HASH_ONLY, Path B/SEGMENT_CARRYING), shared drop
node, and the guarded summary additions are all implemented and compiling clean (zero new
warnings beyond pre-existing OpenSSL 3.0 deprecation notices). Design is per
the Phase 3 design plan (5 rounds of correction, all resolved
before implementation started) — not re-derived here.

### Checkpoint 1 (filter-OFF regression) — PASSED, with scoping decision recorded

**Decision: "byte-identical" for this and all subsequent Phase 3 checkpoints is scoped to
RX (receiver) output specifically, not raw TX (transmitter) console output.** This is a
decision made at Checkpoint 1, not a pre-existing invariant — the original checkpoint
language didn't distinguish RX from TX. Narrowing was justified because: (1) Phase 3's
diff touches only `verify_message_falcon` and its receive-side helpers — never
`transmit_loop`/`generate_falcon_spdu`'s console prints; (2) TX-side mismatches have a
confirmed root cause (below), not just a suspicion; (3) TX console prints have zero effect
on receiver behavior, verification outcomes, or any reported metric. **This scoping
carries forward to Checkpoints 2-5 — but any RX-side mismatch still gets full root-cause
scrutiny, never waved through as "probably just interleaving."**

**TX-side root cause (confirmed, not assumed):** the two legitimate vehicles' transmit
threads (`std::thread` per vehicle, `main.cpp`) write to a shared `stdout` via
unsynchronized `std::cout` calls — `Vehicle.cpp:89` (`sizeof(falcon_spdu)`), `:486` (`TX
vehicle=...`), `:517` (`Calculated heading`). None of these lines are in Phase 3's diff;
this is a harness characteristic dating to Update 2/3's multi-vehicle `--test` design.
Confirmed via `file`/byte-count: captured TX logs contain literal NUL bytes and garbled
mid-line text (e.g. `'[[alconCertCycle] sizeof(falcon_spdu)=\x00Fal...'`) from two
threads' writes interleaving mid-flush — reproducible on any 2-vehicle concurrent `--test`
run regardless of Phase 3 code. **Side finding: this NUL-byte content silently defeats
plain `grep` under a non-C locale** (multi-byte-sequence handling causes 0 matches with no
error, even `grep -c`/`-n` on a pattern that's actually present) — use `grep -a` (force
text) or read raw bytes in Python for any future log inspection on this project's `--test`
captures, not bare `grep`.

**RX-side: byte-exact PASS** between a fresh `--test` capture (current, Task 7-complete
binary, `spamFilterEnabled:false`) and the post-sign-fix Falcon baseline
(`phase3_baseline_filteroff_recv.log`, captured immediately after Checkpoint 0). Verified:
- Full per-sender message-block sequence (3651 lines/sender, both senders) — exact match.
- Dedicated summary comparison (message/outcome counts, percentages, drop-reason
  breakdown, `cert avg=...(n=598)`/`message avg=...(n=600)` sign-once-fix signature
  counts) — exact match, `[DeadlineMiss]`-ratio-count named exception excluded per the
  established rule.
- Update-8 diagnostics still present (`[SocketConfig]`=1, `[FloodRateCheck]`=2,
  `[FalconSignCost]`=2, `[FalconSendGapTrend]`=2; `[ReceiverProgress]`=0 expected — gated
  on `falcon_receive_progress_count % 1000 == 0` (`Vehicle.cpp:700-701`), a counter
  incremented unconditionally once per `verify_message_falcon` call, before the
  `spam_filter_enabled` branch (`:715`) — so it fires identically regardless of filter
  on/off. This run processed only 600 legit messages (`numAttackers:0`), never reaching
  the threshold, hence 0 is the correctly-expected value, confirmed against source, not
  just observed; `[DeadlineMiss]`=0 and `[ReceiveTimeout]`=0 expected — clean no-attacker
  run).
- `falcon_metrics.size() == expected_total` — no false "INCOMPLETE RUN".
- ECDSA: confirmed byte-for-byte untouched two ways — source-level (exhaustive
  case-insensitive grep for "ecdsa" in `Vehicle.cpp`; every hit falls in the
  already-Update-3-verified dispatch/glue code or the untouched
  `generate_ecdsa_spdu`/`sign_message_ecdsa`/`verify_message_ecdsa` bodies themselves —
  zero hits anywhere in Phase 3's added code block), and functionally (50/50 valid,
  `--test`, `numVehicles=2, numAttackers=0`).

**Two real bugs found and fixed in the scratchpad verification tool
(`compare_falcon_logs.py`) during this checkpoint — not code bugs, tool bugs, but worth
recording since they'd otherwise produce false-FAIL noise on every future checkpoint:**
1. `wire_bytes_selfcheck` conflated a sender's `fragment_index=0` and `=1` segments into
   one "must be identical" bucket. **Wrong invariant** — CFrag splits into
   `FALCON_CERT_CYCLE_M` *roughly-equal* segments, so an odd-length cert bundle legitimately
   gives one segment 1 more byte than the other (confirmed deterministic:
   vehicle 0's baseline run showed `idx=0`→1588B, `idx=1`→1587B, unchanging across all 50
   cycles — not randomness). Fixed to key on `(sender, fragment_index)`, generalized to be
   `M`-agnostic (pulls `FALCON_CERT_CYCLE_M`, checks exactly `M` distinct indices appear
   per sender, checks `max-min <= 1` byte across the `M` per-index sizes) rather than
   hardcoded to 2 — **this invariant assumes CFrag's specific "divide into ~M-equal-parts"
   strategy; a future scheme whose fragmentation instead packs toward the frame-size max
   (plausible for something like Sphincs+, given its size relative to the DSRC cap) would
   need a differently-shaped check, not just a different `M`.**
2. The RX per-sender block comparison attached the run's one trailing summary block to
   whichever sender happened to send the last message — a coin flip that differs run to
   run and has nothing to do with either sender's actual content. Fixed by stripping the
   summary (and its preceding blank line) before per-sender attribution; the *correct*
   summary comparison already existed as a separate, dedicated pass
   (`compare_summary()`) and had been passing the whole time.

### Files touched this update
`src/Vehicle.cpp` (guarded summary additions to `print_falcon_verify_metrics_summary`,
completing Task 7). No other relevant source changes beyond that — everything else
this update covers is verification (Checkpoint 1) and a scratchpad-tool-only fix.

### Next
Checkpoint 2 (filter-ON functional), Checkpoint 3 (buffer-cap behavior under
incomplete-fragment flooding), Checkpoint 4 (metrics-size invariant both modes),
Checkpoint 5 (report before/after-shaped numbers) — not started. Then Phase 4.


-----------------------------------------------------------------------------------------
## Update 11

## Checkpoint 2 (filter-ON functional) — PASSED, with a real emergent mechanism found and corrected

Ran `spamFilterEnabled:true`, `numVehicles=2/numMessages=300` (600 legit) against a
`numAttackers=1/numAttackerMessages=2000/attackerMode=expensive_valid` flood, `--test`.
No crash, clean completion both times. Two runs were captured; the second added a
temporary diagnostic print (`Vehicle.cpp:951-957`, `[SpamFilterDiag] RX vehicle=...
fragment_set_id=... kind=... idx=...`, mirroring the filter-OFF path's existing
per-message print at `Vehicle.cpp:728` that the filter-ON path never reaches) —
**kept as permanent instrumentation**, not reverted, since Checkpoint 3's buffer-cap
investigation will need this same visibility and it exactly mirrors an existing,
already-accepted print pattern.

### Headline numbers
`Legitimate VALID: 586/600 (97.7%)`, `Legitimate SPAM_FILTERED: 10-12`
(scheduling-spike-driven, see below), `cert-sig verifies performed: n=2` (both legit
vehicles; **zero** from the 2000-message attacker flood), `message-sig verifies
performed: n=586` (all legit). `X ≪ Y` holds emphatically: 586-588 crypto verifies
against 2600 messages processed.

### The mechanism is NOT what the approved plan assumed — corrected here, not silently
The plan's Path B summary section expected the attacker to contribute "throttled
attacker-churn completions" to the cert-sig-verify count — i.e., some nonzero number of
reconstructions that then correctly fail cert-sig verify (Update 9's mechanism). **That
is not what happens for a flood-paced attacker.** Traced via the new diagnostic
end-to-end:

1. Segment 0 of the attacker's first cycle opens a fragment buffer. Critically,
   `falcon_last_seen_sendts[sender_id]` gets updated at this point (`Vehicle.cpp:1079`),
   **unconditionally**, even though the outcome is only `NO_CERT_YET` (pending) — not a
   real admission.
2. Segment 1 arrives ~4.5ms later (the attacker's real send pacing, per Update 7). The
   rate check (`Vehicle.cpp:1012-1018`) compares this gap against `spamFilterMinGapMs`
   (50ms, default) and **rejects it as `RATE`**, before it ever reaches the
   fragment-attach code. The buffer from segment 0 never completes.
3. That incomplete buffer then blocks every later cycle's segment messages as
   `BUFFER_CAP` (fragment_set_id mismatch) until `bufferTtlMs` (500ms) evicts it —
   confirmed via periodic `[SpamFilter] BUFFER_TTL_EVICT sender=2 (incomplete)` events,
   14 times across a ~2000-message run. After each eviction the cycle repeats: a fresh
   segment 0 opens a new buffer, its own segment 1 fails the same rate check, repeat.
   Early in the run this shows up as `RATE`/`STALE` (draining a real ~400ms receiver
   backlog from concurrent startup contention — same Update-8-diagnosed mechanism, larger
   magnitude here because 3 sender threads + a flood are all starting at once); once the
   backlog clears, the steady-state reason is `BUFFER_CAP`.

**Root cause, precisely:** any sender whose own segment-0-to-segment-1 send gap is
smaller than `spamFilterMinGapMs` can **structurally never complete a cert
reconstruction** — regardless of whether its signature or cert would have been valid.
Segment 0's `NO_CERT_YET` outcome still consumes the rate-limiter's "last accepted"
slot, which segment 1 (the very next message, by design ~arriving milliseconds later for
any fast sender) can then never clear.

### Reconciliation with Update 9's churn-rejection claim — qualifier added, not contradicted
Update 9 states fabricated/churned certs are "always correctly rejected" via cert-sig
`falcon_verify` failing. That mechanism is real but **only covers one of two cases** —
Update 9's text should be read with this split, not as unconditional:

- **Fast attacker/churner (segment-0-to-segment-1 gap < `spamFilterMinGapMs`):**
  rate-blocked before reconstruction ever completes. Cert-sig verify **never runs**.
  Dropped as `RATE` (directly) or `BUFFER_CAP`/`STALE` (downstream consequence of the
  stuck buffer). This is this Update's finding.
- **Slow/patient attacker/churner (segment gap ≥ `spamFilterMinGapMs`):** reconstructs
  normally, reaches cert-sig verify, and **correctly fails it** — Update 9's original
  mechanism, unchanged, still the operative path for a churner that paces itself to stay
  under the rate floor specifically to get a real verify attempt.

**Both outcomes converge on the same security guarantee: never admitted, never cached,
never charged a message-sig verify.** Update 9's "always correctly rejected" framing is
still accurate as a security *outcome* claim; what's corrected here is the *mechanism*
claim — it is not always via cert-sig failure specifically. A sufficiently fast attacker
gets an even cheaper rejection (no crypto at all) than Update 9's original text implies.

### Crypto-verify accounting expectation — corrected (plan doc's language was stale)
The plan's Phase 3 design section ("Summary additions") described attacker cert-sig-verify contribution as "throttled
attacker-churn completions" — implying a throttled-but-nonzero count. Per this Update,
for a flood-paced attacker that count is **exactly zero**, not throttled-nonzero. This is
a **stronger** headline result than planned (zero crypto cost on the attacker, not
reduced crypto cost), not a weaker one — corrected in the design plan directly alongside
this entry.

### New named config invariant: `spamFilterMinGapMs` must stay below the BSM send interval
Legit vehicles are unaffected under normal conditions only because their ~100ms BSM
cadence keeps segment-0-to-segment-1 gaps safely above the current 50ms floor — the same
mechanism that permanently blocks the attacker would equally break **legitimate** cert
reconstruction if `spamFilterMinGapMs` were ever tuned up past the configured send
interval (currently hardcoded 100ms per `Vehicle::generate_bsm`/`inter_message_delay_ms`
default). **This holds today only because the chosen defaults (50 < 100) happen to
satisfy it — nothing in the code enforces or checks this relationship.** Anyone tuning
`spamFilterMinGapMs` upward (e.g., to throttle a slower attacker harder) without knowing
this constraint could silently break legitimate cert caching. Flagged as a follow-up
worth a startup assertion or loud config-validation warning (e.g., in `main.cpp` after
reading both fields) — **not implemented**, out of Checkpoint 2's scope; raise before
anyone else tunes `spamFilterMinGapMs`.

### Legit drops this run — exactly reconciled against the Checkpoint 1 baseline, zero residual
**The 598/600 (Checkpoint 1, filter-OFF, no attacker) → 586/600 (this run) legit-VALID
gap is fully accounted for: 598 − 586 = 12, and the per-vehicle `SPAM_FILTERED` breakdown
sums to exactly 12 with no unexplained residual.** Both runs share the same startup
`NO_CERT_YET` count (2), so the comparison is apples-to-apples on the 598-message
non-startup base.

Traced precisely via the `[SpamFilterDiag]` print (not just categorized as plausible):
**both legit vehicles fail only their very first cycle (`fragment_set_id=1`), then never
drop again for the remaining ~99 cycles of the run.** Exact per-vehicle sequence,
confirmed from the raw log:
1. Segment 0 (`idx=0`) arrives already `>spamFilterAdmitMs` (100ms) stale — the receiver's
   startup backlog (three sender threads + receiver all starting concurrently, same
   Update-8-diagnosed contention) means `received_time − send_ts` was already ~470-478ms
   by the time this very first message was processed. Dropped `STALE` — this check runs
   before the buffer code even touches state, so no buffer opens.
2. Segment 1 (`idx=1`) arrives moments later. No buffer exists for this sender (segment 0
   never opened one), and since `fragment_index != 0` it can't open one starting
   mid-sequence (`Vehicle.cpp:1069-1071`). Dropped `BUFFER_CAP`.
3. All 4 of that cycle's hash-only messages reference a hash nothing has cached yet.
   Dropped `NO_CACHE` ×4.

`1(STALE) + 1(BUFFER_CAP) + 4(NO_CACHE) = 6` per vehicle × 2 vehicles = **12, matching the
gap exactly.** Cycle 2 (`fragment_set_id=2`) onward, both vehicles reconstruct and cache
normally with zero further drops for the rest of the 600-message run — confirmed by
`cert avg=...(n=2)` (both vehicles did succeed, just one cycle later than their first
attempt) and by the drop log showing no further `vehicle=0`/`vehicle=1` entries after
this one failed cycle each. This is a pure startup artifact, not a sustained-load effect —
it is exactly the `BUFFER_TTL_EVICT_INCOMPLETE`-family legit-drop mode the Phase 3 plan
named in advance (Update 4), now empirically confirmed and fully traced, not just
categorized as plausible.

**Restated Checkpoint 2 verdict:** the 12-message gap vs. Checkpoint 1 is fully accounted
for by named, understood, filter-induced drop categories — zero unexplained residual.

### Files touched this update
`src/Vehicle.cpp` (`[SpamFilterDiag]` print at `spam_filter_verify_falcon`'s entry,
`Vehicle.cpp:951-957` — kept as permanent instrumentation, see above).
The Phase 3 design plan (Path B summary language corrected per above).

### Next
Checkpoint 3 (buffer-cap behavior under incomplete-fragment flooding — the mechanism
found in this Update is directly relevant groundwork), Checkpoint 4 (metrics-size
invariant both modes), Checkpoint 5 (report before/after-shaped numbers). Then Phase 4.


-----------------------------------------------------------------------------------------
## Update 12

## Checkpoint 3 (buffer-cap behavior under incomplete-fragment flooding) — PASSED

Two of Checkpoint 3's three required properties (per-sender cap=1, mismatched sets
dropped not reset) turn out to be **structural guarantees provable from source directly**,
not just emergent behavior to be inferred from aggregate counts — verified as such rather
than only empirically observed:

- **Bounded to 1 open buffer per sender**: `spam_filter_buffers` is
  `std::unordered_map<uint8_t, spam_filter_fragment_buffer>` (`Vehicle.h:179`), keyed on
  `sender_id`. A map can hold at most one entry per key by construction — this is not an
  enforced limit that could have an off-by-one or race bug, it is structurally impossible
  to exceed.
- **Mismatched `fragment_set_id` dropped, not reset**: `Vehicle.cpp:1083-1087` — the
  mismatch branch (`if(buf.fragment_set_id != env.fragment_set_id)`) calls `return
  spam_filter_drop(...)` immediately. `spam_filter_drop` (`Vehicle.cpp:883-901`) never
  touches `spam_filter_buffers`. `buf` (a reference into the map) is never written to on
  this path — confirmed by reading the full function body, not inferred.

Also confirmed empirically, reusing Checkpoint 2/Update 11's `expensive_valid`-attacker
run as real single-identity incomplete-fragment-flooding evidence (its own buffer never
completes across ~333 cycle attempts, ~547-584 `BUFFER_CAP` drops recorded, final state
never exceeded 1 open buffer for that sender) — this scenario already exercised exactly
what Checkpoint 3 asks for, discovered as an emergent property of Checkpoint 2 rather
than requiring a separately engineered attack variant (no dedicated "incomplete-fragment
flooding" `AttackerVehicle` mode exists — variant #3 churn remains deferred per Update 1).

### Global cap: never previously exercised at runtime — deliberately forced and confirmed
Every run through Checkpoint 2 had ≤3 possible sender identities, far under the default
`spamFilterGlobalStateCap=512` — `enforce_spam_filter_global_cap` had never actually fired.
Forced it with a dedicated test: `numVehicles=2, numAttackers=0, spamFilterGlobalStateCap=1`
(`--test`, 30 messages/vehicle). Result: `[SpamFilter] GLOBAL_CAP_EVICT` fired 9 times
(alternating `buffer sender=0`/`cache hash=...` — LRU eviction across both structures
correctly, not just one), final state never exceeded the configured cap (`0 open buffers,
1 cached certs (cap=1)` at run end), no crash, no false `INCOMPLETE RUN`. As expected for
a deliberately pathological cap=1 with 2 live legit senders (each evicts the other's cache
entry before it can be reused, forcing repeated re-reconstruction): `Legitimate VALID:
25/60 (41.7%)`, `cert avg=...(n=5)` (vs. the `n=2` seen under a normal cap — directly
demonstrates the real cost of an undersized global cap, not a bug). This confirms the
mechanism works correctly under contention; it is not evidence that `cap=1` is a
reasonable production value — the default 512 remains sized per Update 9's rationale
(≈`numVehicles` stable entries + headroom, no routine legit turnover once cached).

### Config used, then restored
Test used `spamFilterEnabled:true` variants of `config.json` (kept in scratchpad, not
committed); production `config.json` restored to
`numVehicles:2, numMessages:25, numAttackers:1, numAttackerMessages:100,
spamFilterEnabled:false` after each test.

### Checkpoint 4 (metrics-size invariant, both modes) — PASSED, arithmetic shown for the two highest-risk runs
`print_falcon_verify_metrics_summary`'s `INCOMPLETE RUN` check (`Vehicle.cpp:1190-1191`,
`actual_total < expected_total`) only catches **under**-count — it says nothing about an
**over**-count (a double-push). The real invariant needs the arithmetic shown, not just
the absence of that message. Also worth noting: `legit_total`/`attacker_total`
(`Vehicle.cpp:1172-1182`) are computed by iterating `falcon_metrics` directly, classifying
every record into exactly one bucket — so the printed "Legitimate/Attacker messages
processed" figures ARE `falcon_metrics.size()`, not an independent counter that could
diverge from it.

Checked the two runs from this Update specifically — the eviction-heavy global-cap run is
the highest-risk case (repeated create/evict churn on both `spam_filter_buffers` and
`spam_filter_cert_cache`, exactly where an off-by-one in drop/eviction bookkeeping would
most likely surface as a double-push or skipped push):

- **Incomplete-fragment run (`checkpoint2b`)**: config `numMessages=300, numVehicles=2,
  numAttackerMessages=2000, numAttackers=1` → `expected_total = 300×2 + 2000×1 = 2600`.
  Printed `Legitimate messages processed: 600` + `Attacker messages processed: 2000` =
  **2600 = 2600, exact.**
- **Global-cap eviction run (`checkpoint3_globalcap`)**: config `numMessages=30,
  numVehicles=2, numAttackers=0` → `expected_total = 30×2 + 0×0 = 60`. Printed
  `Legitimate messages processed: 60` + `Attacker messages processed: 0` = **60 = 60,
  exact**, despite 9 `GLOBAL_CAP_EVICT` events alternating buffer/cache eviction.

Both exact, no residual either direction. Checkpoints 1-2's normal (non-eviction-stressed)
runs were already confirmed via the `INCOMPLETE RUN` check plus this same tautological
`legit_total+attacker_total` relationship holding in their printed summaries.

### Checkpoint 5 (before/after-shaped numbers) — PASSED, Phase 3 code-complete and verified end-to-end
Apples-to-apples: identical config both runs (`numVehicles=2, numMessages=300,
numAttackers=1, numAttackerMessages=2000, attackerMode=expensive_valid, --test`), only
`spamFilterEnabled` toggled. Both confirmed no-crash, no `INCOMPLETE RUN`, metrics-size
invariant exact (filter-OFF: `legit_total(600)+attacker_total(2000)=2600=expected_total`,
same arithmetic as Update 12's filter-ON check).

| Metric | Filter OFF (baseline) | Filter ON | Change |
|---|---|---|---|
| Legit VALID | 598/600 (99.67%) | 586/600 (97.67%) | −12, fully reconciled (Update 11 — one startup cycle per vehicle, self-healing) |
| Legit drop rate (excl. startup) | 0/598 (0%) | 12/598 (2.0%) | all named/understood, zero residual |
| Legit deadline-miss ratio | 0/600 (0%) | 2/600 (0.33%) | small, startup-artifact-attributable |
| Legit VALID latency (ms) | p50=3.47 p95=6.78 p99=11.46 max=43.32 | p50=3.58 p95=6.96 p99=9.48 max=14.68 | comparable; filter-ON max notably lower |
| **Message-sig verifies performed** | **n=2600** | **n=586** | **77.5% reduction** |
| **Cert-sig verifies performed** | **n=2597** | **n=2** | **99.92% reduction** — headline result |
| Full loop iteration cost (ms) | avg=12.33 p95=90.41 max=739.13 (n=2599) | avg=12.19 p95=94.00 max=470.65 (n=2599) | comparable avg; filter-ON max substantially lower |

**Filter-OFF message-sig (n=2600) vs. cert-sig (n=2597) reconciled exactly — not table
rounding, a real and precisely explained pre-existing behavior.** Traced to source, not
assumed equal: `Vehicle.cpp:775-798` (the untouched Phase 1/2 body) gates cert-sig verify
on `cert_it != falcon_reconstructed_certs.end()` — skipped when no cert is cached yet —
but runs message-sig verify **unconditionally on every message** (`:794-798`), checking
against the vehicle's independently disk-loaded key (`load_falcon_key`, `:720`), which
has nothing to do with cert-cache state. `2600 − 2597 = 3` exactly matches the 3
`no reconstructed certificate yet` log lines in this run — confirmed via direct grep —
one per sender identity (`vehicle=2`, `vehicle=0`, `vehicle=1`), each that identity's
very first message before its own first reconstruction completes. These 3 still get a
timed message-sig verify attempt (against the correct on-disk key, so `sig_result` would
be `true`) but are forced to `NO_CERT_YET` outcome regardless of `sig_result`, since
`no_cert_yet` short-circuits the outcome classification (`:817`) ahead of `sig_result`.
This is pre-existing Phase 1/2 behavior, outside Phase 3's diff — not a new discrepancy
introduced by this Update, now precisely explained rather than left as an unremarked gap.

**Filter-ON "2/600 legit deadline-miss" — confirmed exact, not pattern-matched to Update
8's general finding.** Grepped the full `checkpoint2b` receive log for every
`[DeadlineMiss] vehicle=0` / `vehicle=1` line: **exactly two, and no others** in the
600-message legit stream. Both are the identical two events already fully traced in this
Update's 12-message reconciliation — vehicle=1's and vehicle=0's `fragment_set_id=1`
segment-0 `STALE` drops (`latency_ms=473.749`/`478.307`), i.e. the direct consequence of
each vehicle's one failed startup cycle, not a separate or additional effect. Notably, the
`BUFFER_CAP`/`NO_CACHE` siblings from that same failed cycle did **not** individually
exceed the 100ms threshold when processed — consistent with the backlog draining rapidly
within the same cycle (matches the fsid=17→19 latency-decreasing trend already
established in Update 11), not a sustained condition. So "2/600, startup-artifact" is now
an exact, log-verified identity with the already-traced mechanism, not an inference by
resemblance to a different (Update 8) finding.

**Headline result for the report:** the spam filter eliminates essentially all
attacker-driven crypto cost (cert-sig verify collapses from every-message re-verification
to exactly the 2 legit vehicles' one-time reconstructions — the 2000-message
`expensive_valid` flood contributes zero cert-sig and zero message-sig verifies, per
Update 11's rate-limiter mechanism, not the "verify-once-then-cache" mechanism originally
assumed) at a small, fully-understood, self-healing cost to legit traffic (12 messages
out of 600, one cycle per vehicle, concentrated at startup under concurrent thread
contention — not a sustained-load effect). This is the input Phase 4 will formalize
across the full defense-ablation matrix (`context/METHODOLOGY.md`) —
this Update's numbers are a single defended-vs-undefended cell, not the full sweep.

### Phase 3 status: CODE COMPLETE, all 5 checkpoints PASSED
Sign-once fix (Task 1-2), config/struct/enum additions (Task 3-4), guarded dispatch
(Task 5), dual-path admission control (Task 6), shared drop node + summary (Task 7),
Checkpoints 1-5 (Updates 10-12, this entry) all verified end-to-end with cited evidence,
not just asserted. `config.json` restored to production defaults
(`spamFilterEnabled:false, numMessages:25, numAttackerMessages:100`) after every test.

-----------------------------------------------------------------------------------------
## Update 13

## Phase 4 — Benchmark with defenses — STATUS: IN PROGRESS

### Scope decisions (flagged to and confirmed by Geoff before implementation)
- **Single-tier ablation only**: no-defense vs. spam-filter-only. The 3-tier matrix in
  "Evaluation methodology" needs Layers 2/3 (Agile Protocol, Safety Contract), neither
  implemented in this testbed (Feasibility section, unchanged) — those remain a design
  contribution, not a benchmarked cell.
- **Trial count**: N=5 per cell (of the offered 5-10 range), no Wilson CIs yet — proving
  the harness/reconciliation discipline scales before committing to the full 40-75/cell
  related-work standard. Revisit before this reaches the report.
- **Attack coverage**: all three Phase 2 conditions (A: no attack, B: `expensive_valid`
  flood, C: `invalid_signature` flood) × filter OFF/ON = 6 cells, 30 runs total.
  `numVehicles=2, numMessages=300` (600 legit) throughout; B/C use
  `numAttackers=1, numAttackerMessages=2000`.

### Harness
`phase4_run_trials.sh` (scratchpad) drives all 30 `--test` runs; `phase4_aggregate.py`
(scratchpad, same category as `compare_falcon_logs.py`) parses each trial's summary and
**verifies the metrics-size invariant exactly for every single trial before including it
in any aggregate** — a trial that doesn't reconcile is reported as a failure, not
silently averaged in. All 30/30 trials reconciled exactly on the first run.

### Real finding: condition A's deadline-miss/latency numbers are NOT what they appear, explained not just flagged
Raw aggregate initially showed `A_off` (no attack, lowest load) with WORSE deadline-miss
(nonzero in all 5 trials, up to 2.17%) and higher/more variable p95 latency than `B_off`/
`C_off` (under flood) — backwards from naive expectation. Investigated rather than
reported as-is (confirmed reproducible via 3 isolated re-runs, ruling out a first-in-batch
artifact) and traced to source:

1. **`recvfrom()` spikes of ~1000-1450ms occur in both `A_off` and `A_on`** — same
   magnitude, same mechanism as Update 8's already-diagnosed OS/scheduling wake-latency,
   confirmed present regardless of filter state (it's a receive-side, pre-verify
   phenomenon, independent of what the filter does after a message is dequeued).
2. **Condition A's low aggregate rate (~20 msg/sec, 2 legit vehicles at 100ms cadence, no
   attacker) makes a single such spike dominate its deadline-miss statistic** — the same
   spike affecting 600 messages moves the percentage far more than it would against B/C's
   2600-message, ~230+/sec flood, where it's diluted and the receiver thread stays
   continuously "hot" rather than idling between sparse arrivals. This is a **sample-rate
   dilution effect**, not evidence that flooding conditions are safer.
3. **Filter-ON recovers from the same spike faster than filter-OFF**: `A_on` showed
   **zero** deadline-misses across all 5 trials despite comparable-magnitude `recvfrom()`
   spikes (~1011-1031ms, confirmed directly) — because the cache-fast-path's far lower
   per-message cost (no reconstruction/cert-verify after the first cycle, minimal prints)
   drains the resulting backlog before trailing messages accumulate past 100ms. **This is
   a previously uncharacterized secondary benefit of the spam filter** — faster recovery
   from environment-induced backlog, not just reduced steady-state crypto cost.

**Practical implication for reporting:** condition-A deadline-miss/latency-tail numbers
must carry this caveat wherever they appear — a bare percentage comparison across
conditions A vs. B/C, without this explanation, invites exactly the wrong conclusion.

### Aggregated results (N=5/cell, all reconciled exactly)

| Cell | Legit VALID frac | Legit drop frac | Deadline-miss frac | VALID p95 latency (ms) | msg-sig verify n | cert-sig verify n |
|---|---|---|---|---|---|---|
| A_off | 0.9967 (all 5) | 0 | avg 0.83% (0.17-2.17%, see above) | avg 31.8 (14.6-44.7) | 600 (all 5) | 598 (all 5) |
| A_on | 0.9967 (all 5) | 0 | 0% (all 5) | avg 7.49 (7.15-7.88) | 598 (all 5) | 2 (all 5) |
| B_off | 0.9967 (all 5) | 0 | avg 0.13% (0-0.33%) | avg 7.18 (6.18-7.77) | 2600 (all 5) | 2597 (all 5) |
| B_on | avg 0.9927 (0.977-0.997) | avg 0.34% (0-1.68%) | 0% (all 5) | avg 7.00 (6.02-7.37) | avg 595.6 (586-598) | 2 (all 5) |
| C_off | 0.9967 (all 5) | 0 | avg 0.067% (0-0.33%) | avg 7.34 (7.07-7.74) | 2600 (all 5) | 2597 (all 5) |
| C_on | 0.9967 (all 5) | 0 | 0% (all 5) | avg 7.27 (6.27-8.41) | 598 (all 5) | 2 (all 5) |

**B_on's legit-VALID variance (0.977-0.997) directly confirms Update 11/12's diagnosis as
genuinely probabilistic, not deterministic**: some trials show the full startup-cycle
drop (matching Checkpoint 5/2's original single-run 586/600), others show none at all
(598/600, matching the undefended baseline) — consistent with a real, if rare,
scheduling-contention-dependent artifact rather than a fixed feature of the code.

**C (invalid_signature) under filter-ON is clean across the board** — 0% legit drop, 0%
deadline-miss in all 5 trials, cert-sig verify collapsed to n=2 (matching B_on's
best-case trials) — this attacker variant doesn't trigger B's rate-limiter/reconstruction
interaction (Update 11) since `invalid_signature` still completes real cert reconstruction
before its message-sig fails; the churn-rejection mechanism (Update 9) applies once
reconstruction resolves, and cheap checks reject the flood before any of that matters.

### Config
`config.json` restored to production defaults after every trial cell
(`spamFilterEnabled:false, numMessages:25, numAttackerMessages:100`, matching all prior
Updates' convention).

### Next
Present this table's headline numbers formally (crypto-cost reduction, condition-A
caveat, B_on's probabilistic-drop confirmation) as the Phase 4 report input. Revisit
trial count (Wilson CIs, 40-75/cell) before this reaches the actual report — flagged,
not resolved here.


-----------------------------------------------------------------------------------------
## Update 14

## Trial-count scale-up, B_on mechanism correction, spamFilterMinGapMs limitation note — Monday-noon-deadline pass

### 1. Trial count: N=5 → N=75/cell, harness unchanged

**Actual wall-clock time of the existing N=5 matrix** (pulled from `phase4_trials/*_recv.log`
mtimes, not re-run to find out): all 30 trials (6 cells × 5) completed in **~981.6s
first-trial-completion to last** (`A_off_trial1_recv.log` 00:14:21 → `C_on_trial5_recv.log`
00:30:43), averaging **33.85s/trial** with no meaningful variance across cells (32.3-36.4s
regardless of attack condition or filter state — dominated by the fixed ~30s of two legit
vehicles' 300-message, 100ms-cadence transmit loop, not by attacker volume or filter cost).
Total N=5 run ≈ **16.9 minutes**.

**Proposal: N=75/cell (450 trials total), the top of the 40-75/cell related-work range**,
not something short of it. At the measured 33.85s/trial: 450 × 33.85s ≈ **4.23 hours**,
comfortably inside the 36-hour budget (≈12% of it) with wide margin for occasional slow
trials (Update 8's scheduling-latency spikes), the B_on retrace below, the limitations
note, and human review before Monday noon. Going past 75/cell was considered and rejected —
the budget has slack to spare, but 75 is the ceiling of the cited related-work standard;
exceeding it buys no methodological credibility the report can point to, so 75 is both the
"fits" answer and the "matches the standard" answer at once, resolving Update 13's
"revisit trial count" flag definitively rather than picking an arbitrary larger number just
because the clock allowed it.

`phase4_run_trials.sh`/`phase4_aggregate.py`: only the `N_TRIALS` constant changed (5→75)
in each; harness logic, cell definitions, and the metrics-size reconciliation gate are
byte-for-byte unchanged. **Before launching, the N=5 logs were copied to
`phase4_trials_n5_backup/`** so the B_on retrace below (which cites that exact run) isn't
destroyed by the larger run overwriting `phase4_trials/*`.

**Run launched in background** (`phase4_run_trials_n75.log`); every trial still gated on
exact metrics-size reconciliation via `phase4_aggregate.py` before inclusion, same as
Update 13 — a trial that doesn't reconcile is reported as a failure, not dropped silently.
Final N=75 aggregate numbers to be appended once the run completes — **not yet available
as of this Update's initial text**, tracked as an in-progress addendum below.

### 2. B_on legit-drop mechanism — Update 13's language corrected, NOT via RATE

Update 13 claimed the B_on trial-to-trial legit-VALID variance (598/600 in 4 trials,
586/600 in 1) "directly confirms Update 11/12's diagnosis" without citing per-message
log lines for the actual drop — pattern-matching on aggregate magnitude (586 vs. 598),
exactly the gap flagged as needing real proof. Retraced it from the preserved N=5 backup
(`phase4_trials_n5_backup/B_on_trial5_recv.log`, the one trial with drops).

**Finding: the mechanism is NOT `RATE` (segment-0-to-segment-1 gap under
`spamFilterMinGapMs`).** Zero `reason=RATE` drops attributed to vehicle=0 or vehicle=1
anywhere in this file — the 64 `RATE` drops present are all `sender=2` (the attacker),
consistent with Update 11's original attacker-specific finding, not evidence of the same
mechanism hitting legit traffic. The `RATE` hypothesis in this task's own framing turns
out to be wrong for the legit-vehicle case; the real mechanism, cited exactly:

```
[SpamFilterDiag] RX vehicle=0 fragment_set_id=1 kind=SEGMENT_CARRYING idx=0     (line 41)
  ... (2157 lines of interleaved multi-sender traffic later) ...
[SpamFilterDiag] RX vehicle=0 fragment_set_id=1 kind=SEGMENT_CARRYING idx=1     (line 2198)
[SpamFilter] BUFFER_TTL_EVICT sender=0 (incomplete)                              (line 2199)
[SpamFilter] DROP reason=BUFFER_CAP vehicle=0                                   (line 2200)
```

Segment 0 (`idx=0`) is accepted cleanly and opens a buffer — no `STALE`, unlike Update
11/12's original trace. By the time segment 1 (`idx=1`) is processed, `bufferTtlMs`
(500ms) has elapsed since segment 0 opened the buffer, so it's evicted
(`BUFFER_TTL_EVICT ... incomplete`) *at the moment segment 1 arrives* — confirming the TTL
check is evaluated lazily on next-message-for-that-sender, not via a background sweep.
With no buffer left and `fragment_index=1 != 0`, segment 1 can't open a new one mid-sequence
(Update 11's second `BUFFER_CAP` code path — "no buffer + can't start mid-sequence" — not
the "mismatched `fragment_set_id`" path either). Vehicle=1 shows the identical pattern
(`BUFFER_TTL_EVICT sender=1 (incomplete)` immediately before its own `BUFFER_CAP`). Both
vehicles: 1×`BUFFER_CAP` + 4×`NO_CACHE` (cascading, same cycle's hash-only messages) = 5
each, **10 total, matching `Legitimate SPAM_FILTERED: 10` exactly**, all confined to
`fragment_set_id=1` (the first cycle) with zero drops in any later cycle for either
vehicle — confirmed via `grep` (0 hits) — matching `cert avg=...(n=2)` (both vehicles
reconstructed successfully by cycle 2, self-healing, same shape as Update 11/12).

**Root cause is the *receiver taking longer than 500ms between processing segment 0 and
segment 1 for that sender* — a large inter-processing gap (backlog/scheduling-induced,
Update 8's mechanism), not a small one.** This is the opposite direction from `RATE`
(which fires on a gap *too small*, under 50ms, and only ever hit the attacker in this
data). It's also not quite Update 11/12's original trace either (that one had segment 0
itself arrive `STALE`; here segment 0 is accepted fine and it's the *buffer*, not the
message, that goes stale before segment 1 shows up) — a related but mechanistically
distinct startup/backlog artifact, not a repeat of the same log signature.

**All 5 trials checked, not just trial 5**: trials 1-4 show **zero** legit `DROP` lines of
any reason — clean 598/600 with no filter-induced drop at all that run. Only trial 5 hit
the backlog window. This is consistent with Update 13's "scheduling-contention-dependent,
probabilistic, not deterministic" framing — that part holds up — but the specific
mechanism cited ("RATE... segment-0-to-segment-1 gap under spamFilterMinGapMs") did not,
and is corrected here rather than left standing. **Corrected language for the report:**
describe B_on's rare legit-VALID variance as **buffer-TTL-eviction under receiver backlog
during the vehicle's first cert cycle** (Update 8-class scheduling artifact), not as a
rate-limiter interaction — the rate-limiter (`RATE`) mechanism is real and load-bearing,
but for the *attacker's* zero-cost rejection (Update 11's actual finding), not for
explaining legit drops.

### 3. Known Limitation: `spamFilterMinGapMs` vs. BSM send interval — documentation only, no code change

**Not implemented as a startup assertion, by explicit instruction — recorded here as a
limitation instead.**

> `spamFilterMinGapMs` (currently 50ms) must stay below the configured BSM send interval
> (currently hardcoded 100ms, `Vehicle::generate_bsm`/`inter_message_delay_ms` default) or
> legitimate cert reconstruction breaks by the **same mechanism** that (partially) blocks
> a fast attacker: a sender whose own segment-0-to-segment-1 gap falls under
> `spamFilterMinGapMs` can structurally never complete a cert reconstruction, because
> segment 0's `NO_CERT_YET` outcome still consumes the rate-limiter's "last accepted" slot
> unconditionally (Update 11), which segment 1 then fails against. **This holds today only
> because the chosen defaults (50 < 100) happen to satisfy the relationship — nothing in
> the code enforces or checks it.** Anyone tuning `spamFilterMinGapMs` upward (e.g., to
> throttle a slower/patient attacker harder) without knowing this constraint could silently
> break legitimate cert caching for every legit vehicle, not just degrade it at the margin.

Flagged for the report's limitations section verbatim. No `main.cpp` config-validation
assertion added — this update is documentation-only per explicit instruction, matching the
"flag, don't unilaterally decide/implement" posture this doc already uses for open
questions (e.g., the Safety Contract ablation-matrix toggle question).


-----------------------------------------------------------------------------------------
## Update 15

## N=75/cell Phase 4 rerun — STATUS: COMPLETE, corrects three N=5-based claims from Update 13

The VM rebooted mid-run during the first N=75 attempt (`/tmp` wiped, killing that run and
the N=5 backup logs used for Update 14's B_on trace citations — the trace conclusions
survived since they were already written into the project notes, only the raw evidence file
was lost). `net.core.rmem_max` re-applied (Update 6's reboot-resets-it issue, confirmed
recurring exactly as documented), harness scripts recreated verbatim, config restored,
rerun launched clean. **All 450/450 trials (75/cell × 6 cells) reconciled exactly against
the metrics-size invariant — zero failures.**

### Headline aggregate table (N=75/cell)

| Cell | Legit VALID frac | Legit drop frac | Deadline-miss frac | VALID p95 latency (ms) | msg-sig verify n | cert-sig verify n |
|---|---|---|---|---|---|---|
| A_off | 0.9967 (all 75) | 0 | 0% (all 75) | avg=11.8 (7.51-14.96) | 600 (all 75) | 598 (all 75) |
| A_on  | 0.9967 (all 75) | 0 | 0% (all 75) | avg=12.9 (10.47-14.8) | 598 (all 75) | 2 (all 75) |
| B_off | 0.9967 (all 75) | 0 | avg 0.073% (0-0.667%) | avg=12.01 (9.04-14.71) | 2600 (all 75) | 2597 (all 75) |
| B_on  | avg 0.9925 (0.9567-0.9967) | avg 0.371% (0-3.367%) | avg 0.027% (0-0.333%) | avg=10.53 (7.65-12.29) | avg 595.5 (574-598) | 2 (all 75) |
| C_off | 0.9967 (all 75) | 0 | avg 0.073% (0-1.167%) | avg=10.78 (6.64-13.4) | 2600 (all 75) | 2597 (all 75) |
| C_on  | avg 0.9906 (0.9567-0.9967) | avg 0.521% (0-3.367%) | avg 0.029% (0-0.333%) | avg=11.2 (9.19-14.26) | avg 594.4 (574-598) | 2 (all 75) |

The N=5 headline result stands: crypto-cost collapse (cert-sig verify 2597→2 whenever the
filter is on) is unchanged and confirmed at 15x the sample size. Three of Update 13's more
specific claims do **not** survive the larger sample and are corrected below rather than
left standing — this is exactly the scale-dependent blind spot N=5 was always at risk of,
now caught instead of carried into the report.

### Correction 1: C_on is NOT "clean across the board" — real, moderately frequent legit drops

Update 13 stated: "C (invalid_signature) under filter-ON is clean across the board — 0%
legit drop, 0% deadline-miss in all 5 trials." **False at N=75**: legit drops occur in
**24/75 C_on trials (32%)**, up to 3.367% in the worst trial — not a rare edge case, a
roughly-1-in-3 event that a 5-trial sample simply didn't catch. `B_on` shows the same
previously-known effect at similar frequency (16/75, 21%), consistent with Update 13's
own framing for B_on ("probabilistic... not deterministic") — the news here is that C_on
turns out to share it, contrary to the "clean across the board" claim specifically made
for C_on.

**Mechanism check, not just magnitude**: traced `C_on_trial16` (20 legit drops, the
largest single-trial count observed) the same way Update 14 traced B_on — confirmed
**zero** `reason=RATE` drops for vehicle=0/1 (both trials' legit drops are 100%
`BUFFER_CAP`+`NO_CACHE`, preceded by `BUFFER_TTL_EVICT sender=N (incomplete)` immediately
before each `BUFFER_CAP`, identical signature to Update 14's B_on trace). **Confirms the
mechanism is attack-mode-independent** — it's the receiver-backlog/scheduling artifact
(Update 8-class), not something specific to `expensive_valid` vs. `invalid_signature`
flood shape. Update 14's correction (mechanism is buffer-TTL-eviction-under-backlog, not
`RATE`) holds for C_on too, now confirmed rather than assumed to generalize.

### Correction 2: legit-drop cycle confinement — "always self-heals after exactly one cycle" softened

Update 11/12/14 characterized the legit-drop artifact as confined to `fragment_set_id=1`
(the first cert cycle) with clean recovery from cycle 2 onward, every time observed.
**Across all 150 B_on+C_on trials, this holds in 148/150 (98.7%)** — but **`B_on_trial18`
(20 drops) and `C_on_trial16` (20 drops) show the identical failure pattern recurring in
`fragment_set_id=2` as well as `1`** (confirmed via the same `BUFFER_TTL_EVICT`→
`BUFFER_CAP` signature at both cycle boundaries, both vehicles, both trials). Both cases
still show `cert avg=...(n=2)` per vehicle by the run's end (i.e., cycle 3 onward is
clean in every case checked) — so "self-healing" as an eventual outcome still holds, but
**"always exactly one cycle" was an artifact of the small N=5/single-run samples checked
so far, not a structural guarantee.** Corrected framing for the report: the backlog
artifact usually resolves after one bad cycle, occasionally needs two, never persists
indefinitely in any of the 450 trials.

### Correction 3: A_off/A_on deadline-miss dropped to 0% at N=75 — N=5 result likely unrepresentative

Update 13 reported A_off deadline-miss as "avg 0.83% (0.17-2.17%)" (implicitly nonzero in
all 5 trials — the range floor is 0.17%, not 0) and explained it via a sample-rate-dilution
argument (a rare `recvfrom()` scheduling spike, Update 8's mechanism, hits harder against
A's low ~20msg/sec aggregate rate than B/C's flood rate). **At N=75, deadline-miss is
exactly 0/75 for both A_off and A_on** — confirmed via direct per-trial check, not just
the aggregate average rounding to a small number. The underlying scheduling-spike
mechanism (Update 8) is not in question — it's real, independently confirmed elsewhere —
but the N=5 sample's specific magnitude (nonzero in what looks like all 5 trials) does not
reproduce at 15x the sample size in this environment. Two non-exclusive candidate
explanations, **neither confirmed, flagged rather than asserted**: (1) N=5 was a small,
unlucky sample that happened to land on a cluster of spikes; (2) this run followed a fresh
reboot (see below) with a cleaner scheduler/memory state than whatever the original N=5
run's environment history looked like, and the spike frequency is itself
environment-history-dependent in a way not yet characterized. **Do not report the original
"avg 0.83%" A-condition figure without this correction attached** — use the N=75 figure
(0%) as the operative number, with this discrepancy noted as an open environmental
question, not resolved here.

### Infrastructure note: mid-run VM reboot

First N=75 launch (started ~00:14 on the original session's clock) was lost to an
unplanned VM reboot partway through. Confirmed via `uptime` (came back up at 15:29 the
same calendar day) — this is the same session-scoped `net.core.rmem_max` reset Update 6
already documented as reboot-sensitive, now confirmed to recur for real, not just a
theoretical risk noted in passing. Everything under `/tmp` (harness scripts, all N=5 and
in-progress N=75 logs) was wiped; everything under `/home/user/pq-v2verifier` (the
project notes, the build binary, `config.json`) survived. Recovery: re-ran `sudo sysctl -w
net.core.rmem_max=33554432`, recreated `phase4_run_trials.sh`/`phase4_aggregate.py`
verbatim (N_TRIALS=75), restored `config.json` to production defaults, sanity-checked the
binary (48/50 VALID on a quick `--test` run, matching the known baseline pattern) before
relaunching. Relaunched run completed cleanly ~4h15m later, on the same pace as the
pre-reboot attempt (33.1-34.0s/trial throughout, no degradation). **Practical implication
for future runs on this VM**: treat any multi-hour background job on this environment as
reboot-vulnerable — the harness itself has no checkpoint/resume capability, so a
recurrence means restarting the affected cells from trial 1, not resuming mid-matrix. Not
addressed here (out of scope for a documentation/rerun pass); worth a checkpointing
mechanism if a longer run (e.g., a future Wilson-CI-driven N>75 pass) is ever needed.

### Next
N=75 numbers above supersede Update 13's N=5 table as the Phase 4 report input, with the
three corrections above carried along. Wilson score 95% CIs (flagged in Update 13,
deferred again in Update 14) still not computed — N=75 makes them cheap to add now that
the aggregator already has per-trial fractions in hand; worth doing before the report if
time permits, not done in this pass.

### Addendum: A_off/A_on's 598/600 split — explained, verified at source level

Both A-condition cells show `legit VALID frac = 0.9967 = 598/600` despite `0%` legit drop
and `0%` deadline-miss. Not a defect — this is `legit_no_cert_yet` (Update 12's field,
tracked but not previously called out for the A condition specifically): each trial's very
first BSM from each of the 2 legit vehicles arrives before that vehicle's own Falcon cert
finishes its `m=2`-fragment reconstruction, so cert-sig can't be attempted yet — the same
cold-start mechanism Update 12 originally traced for `B_off` (2600 vs. 2597, "one per
sender identity"), here isolated to the 2-legit-sender case with no attacker diluting it.

**Confirmed at both the log and source level, not just inferred from aggregate counts:**
- `NO_CERT_YET` count is exactly **2** in every A_off/A_on trial spot-checked (1, 25, 50,
  75 — no exceptions).
- `A_off`: `[FalconCertCycle] DROP vehicle=1: no reconstructed certificate yet` and the
  `vehicle=0` equivalent, one line each, confirmed in trial 1's log. msg-sig verify
  `n=600`, cert-sig verify `n=598` — the baseline path (`Vehicle.cpp:775-798`) runs
  message-sig verify **unconditionally** (`no_cert_yet` only gates `cert_result`, set
  `false` at :779; message-sig call at :795-798 is outside that `if`), so these 2
  startup messages still get a timed (wasted) message-sig attempt.
- `A_on`: msg-sig verify `n=598` (not 600) — the spam-filter path
  (`Vehicle.cpp:1076-1090`) returns `NO_CERT_YET` **immediately** on first-buffer-open
  (line 1089, inside the `if(buf_it == spam_filter_buffers.end())` branch) with no
  `falcon_verify` call at all for message-sig. Matches the design rationale already on
  record at `Vehicle.cpp:1136-1138` ("no trusted key to check a message signature against"
  once/until cert-sig has succeeded) and the comment at :1106-1108 ("only a successful
  cert-sig verify or a cache hit ever reaches message-sig verify") — confirms the filter
  avoids the wasted crypto work the baseline path still pays for.

**Report guidance (per this addendum's prompt):** distinguish **raw VALID frac**
(598/600 = 99.67%, includes the unavoidable 2-message cold-start transient) from
**steady-state VALID frac** (`legit_valid / (total - legit_no_cert_yet)` =
598/598 = **100%** for both A_off and A_on, since neither has any other drop category).
The gap between raw and steady-state is entirely and only the cold-start transient — not
residual defense-induced loss — for both cells; report both numbers if the distinction is
useful, since 99.67% alone reads as "some loss" when the true steady-state figure is
clean.


-----------------------------------------------------------------------------------------
## Update 16

## Attacker-side outcome + drop-reason tracking — STATUS: IMPLEMENTED, metrics only

Three additive changes were scoped for this session: attacker-side metrics (this Update),
a new cheap-signing attack mode (Update 17), and a cert-cycle phase-offset parameter —
the last was scoped down mid-planning to a documentation-only note (Update 18), not
implemented. **Nothing in this Update touches admission/drop decision logic** — every
edit either computes a new local `bool` from data already in scope, selects which of two
counters to increment, or adds a print line. **Update 15's N=75 A/B/C × off/on table is
completely unaffected** — this only changes what gets counted/printed for attacker
traffic in *future* runs; it does not re-run or reinterpret any existing trial.

### What changed
`falcon_metrics` already recorded an outcome for every message regardless of sender type —
attacker traffic was just never broken out of the raw `attacker_total` counter, and
`spam_drop_reason_counts` was a single global array that couldn't distinguish which sender
type triggered which cheap-reject reason (mislabeled "ALL senders, legit + attacker" in
the print block). Fixed by:
- `spam_drop_reason_counts` split into `legit_spam_drop_reason_counts` /
  `attacker_spam_drop_reason_counts` (`Vehicle.h`).
- New `spam_filter_num_vehicles` member, set from `receive()`'s existing `num_vehicles`
  parameter — makes the legit/attacker boundary usable *live* during the receive loop
  (previously that boundary only existed post-hoc, forwarded straight into
  `print_falcon_verify_metrics_summary` after the loop already finished).
- `spam_filter_drop()` gained an `is_attacker` parameter, threaded through all **13** call
  sites inside `spam_filter_verify_falcon` (not ~12 as first estimated during exploration —
  one call site, the post-reconstruction Full-Hash-mismatch branch, was initially missed)
  plus the standalone `BUFFER_TTL_EVICT_INCOMPLETE` increment that bypasses
  `spam_filter_drop` entirely.
- `print_falcon_verify_metrics_summary` gained `attacker_outcome_counts`, a new "Attacker
  outcome breakdown" print block, and a corrected 3-way reconciliation.

### Correctness fix caught during planning, not part of the original request
The "attacker reached full crypto" formula must include `EXPIRED`, not just
`VALID + INVALID_SIGNATURE + INVALID_CERT_SIGNATURE` — `EXPIRED` is only assigned when
`falcon_verify()` *did* run and *did* succeed (just against a stale timestamp), so it
unambiguously means crypto was paid. And "cheap reject" must use
`attacker_outcome_counts[SPAM_FILTERED]` directly, **not**
`sum(attacker_spam_drop_reason_counts)` — the sum double-counts whenever
`BUFFER_TTL_EVICT_INCOMPLETE` fires, since that increments as a side-effect of evicting a
*stale, unrelated prior* buffer, without an accompanying `SPAM_FILTERED` push for the
*current* message. **Confirmed as a real, not just theoretical, hazard** at the Change-1
checkpoint trial (`invalid_signature`/filter-on/2000 attacker messages):
`sum(attacker_spam_drop_reason_counts) = 66(RATE) + 1332(NO_CACHE) + 585(BUFFER_CAP) +
16(BUFFER_TTL_EVICT_INCOMPLETE) = 1999`, but the real `SPAM_FILTERED` count was `1983` —
using the sum would have broken the reconciliation invariant
(`1999 + 0 + 17 = 2016 ≠ 2000`). Using `attacker_outcome_counts[SPAM_FILTERED]` directly,
reconciliation held exactly: `0 (full_crypto) + 1983 (cheap_reject) + 17 (pending) = 2000`.

### Checkpoint — PASSED
Clean rebuild, one `--test` trial (`attackerMode:"invalid_signature", spamFilterEnabled:true,
numAttackerMessages:2000`, matching the `C_on` cell shape): new attacker breakdown printed
correctly, 3-way reconciliation held exactly, both new per-sender-type drop-reason blocks
printed, legit-side lines matched the established `598/600` baseline pattern exactly. The
attacker's `full_crypto=0` result is directly consistent with Update 15's already-known
`C_on` cert-sig-verify `n=2` (zero attacker contribution) — this breakdown just makes that
fact explicit instead of implicit.

### Files touched
`include/Vehicle.h`, `src/Vehicle.cpp`. No changes to `arguments.h`, `main.cpp`, or any
receiver-side admission logic.


-----------------------------------------------------------------------------------------
## Update 17

## New attack mode: `CHEAP_INVALID_SIGNATURE` — STATUS: IMPLEMENTED

`INVALID_SIGNATURE` signs for real before corrupting the last byte (`AttackerVehicle::
post_process_spdu`), so it's rate-capped at the same ~279 msg/sec signing ceiling as
`EXPENSIVE_VALID` (Update 7) — it doesn't represent an attacker who skips signing entirely,
since there's no reason to pay sign cost for a signature that's going to be invalid anyway.
`CHEAP_INVALID_SIGNATURE` bypasses `falcon_sign()` entirely for the **message** signature
and writes random bytes directly into the signature buffer at a plausible length, isolating
achievable flood rate from attacker-side signing cost.

### Why `post_process_spdu` alone couldn't do this
Confirmed via the call graph (`transmit_loop`, `Vehicle.cpp:26-40`): `post_process_spdu`
runs strictly *after* `generate_falcon_spdu` → `sign_message_falcon` has already completed
and paid the real signing cost. It also receives `signature_length` **by value**, so it
can't rewrite `spdu.signature_buffer_length` even if it wanted to. The bypass has to happen
at the `sign_message_falcon(spdu);` call site itself, inside `generate_falcon_spdu`.

### Mechanism
- New `attack_mode::CHEAP_INVALID_SIGNATURE` enumerator (`arguments.h`), mapped from
  `attackerMode:"cheap_invalid_signature"` in `main.cpp`, preserving the existing
  "unrecognized string silently falls through to `EXPENSIVE_VALID`" convention.
- New virtual hook `Vehicle::bypass_falcon_signing()` (default `false`, no-op — identical
  to today for `Vehicle` and any non-overriding subclass), following the exact same
  type-erased-default-virtual pattern as `post_process_spdu`/`inter_message_delay_ms`.
  `AttackerVehicle` overrides it to return `mode == attack_mode::CHEAP_INVALID_SIGNATURE`.
- `generate_falcon_spdu`'s `sign_message_falcon(spdu);` call replaced with a branch: if
  `bypass_falcon_signing()`, fill `spdu.signature` (the full 666-byte
  `OQS_SIG_falcon_512_length_signature` buffer) with `RAND_bytes()` and set
  `signature_buffer_length` to that same max length; else sign for real, unchanged.
- **`post_process_spdu` was NOT touched** — its existing condition
  (`mode == attack_mode::INVALID_SIGNATURE`) already naturally excludes the new
  enumerator, so it's a no-op for the new mode with zero code change. This is what
  guarantees `INVALID_SIGNATURE`'s behavior (and the frozen `C`-cell N=75 results) stays
  byte-for-byte identical.
- **Cert-signing deliberately left real** (a different call site, gated by
  `falcon_cert_prepared` to run once per vehicle lifetime) — its one-time ~3.58ms cost is
  statistically invisible against 2000 attacker messages, and leaving it real means the
  bypass attacker still presents a genuinely valid cert, isolating exactly the intended
  variable (per-message signing cost) rather than conflating it with cert-cache behavior.

### Why max-length random bytes is the right "plausible length" choice
Confirmed via `wire_length(const falcon_spdu&)` (`Vehicle.cpp:46-58`): `signature` is a
fixed-size array positioned *before* `cert_cycle` in the struct layout (`cert_cycle` "MUST
stay last" per its own comment), and `wire_length()`'s truncation only ever happens inside
`cert_cycle` — so the **entire 666-byte `signature` array is always sent on the wire today,
for every real message too**, regardless of the real (shorter, variable) signature length.
Filling the whole array and declaring the max length is memory-safe and wire-format-
consistent with existing behavior, not a new phenomenon.

### Timing instrumentation
Nothing pushed to `falcon_message_sign_times_ms` when bypassed — that vector's own meaning
is real Falcon signing cost specifically, and Update 7's asymmetry analysis depends on that
staying pure. No new counter needed: the existing unconditional `[FalconSignCost]` print
already self-evidently shows `message_sign_avg_ms=0 ... (n=0)` when fully bypassed, and
`[FloodRateCheck]`'s wall-clock `avg_actual_gap_ms` already captures the achieved rate.

### Checkpoint — PASSED
- Clean rebuild, no new warnings.
- Smoke test (`attackerMode:"cheap_invalid_signature"`, 200 attacker messages): confirmed
  `[FalconSignCost] vehicle=2 message_sign_avg_ms=0 ... (n=0)` (zero real message signs) with
  `cert_sign ... (n=1)` (cert-signing still real, as designed). `[FloodRateCheck]`
  `avg_actual_gap_ms=0.023` vs. ~4.5-4.6ms for real Falcon signing (Update 7) — roughly
  **200x faster** achievable send rate, unconstrained by signing cost. Receiver-side:
  attacker messages landed in cheap-reject/pending, not `VALID`, no crash.
- Regression check: re-ran the exact `invalid_signature`/2000-message/filter-on config from
  the Update 16 checkpoint. Legit-side lines were byte-for-byte identical
  (`598/600` VALID, `2` `NO_CERT_YET`, `0%` drop, `0%` deadline-miss in both runs).
  Attacker-side counts showed only ~1-message run-to-run variance (`1982-1983`
  `SPAM_FILTERED`, `17-18` pending) — the same class of scheduling-timing noise already
  documented throughout this doc (Update 8/12/14), not a functional regression. **Existing
  `C_off`/`C_on` N=75 results (Update 15) remain valid** — `INVALID_SIGNATURE`'s code path
  is provably untouched by this addition.

### Files touched
`include/arguments.h`, `include/Vehicle.h`, `src/Vehicle.cpp` (plus `#include
<openssl/rand.h>`), `include/AttackerVehicle.h`, `src/AttackerVehicle.cpp`, `src/main.cpp`.
No receiver-side changes — a bypassed message just fails `falcon_verify()` on random bytes
and lands in existing outcome/drop categories, made visible for free by Update 16.


-----------------------------------------------------------------------------------------
## Update 18

## Cert-cycle phase offset — STATUS: DEFERRED, documentation only, not implemented

Scoped out of tonight's implementation mid-planning (explicit instruction) — this is a
known-gap note plus a ready-to-implement design, not working code.

### The gap
`falcon_cycle_position = 0` (`Vehicle.h:49`) is a fixed in-class default initializer, never
touched by the constructor or anywhere else except inside `generate_falcon_spdu`. Every
N=75 result (Update 15) therefore reflects **synchronized cert-cycle start across every
vehicle** — every trial's first BSM from each vehicle is guaranteed cycle position 0.
Realistic mid-cycle receiver entry (a sender whose cycle the receiver only starts observing
partway through) is untested.

### Worst-case cold-start delay — traced directly from source, composition corrected during planning
Derived from `generate_falcon_spdu`'s position sequence (`position = (offset + i) % tau`,
`tau=6` with current defaults) and cross-checked against both the filter-ON
(`spam_filter_verify_falcon`) and filter-OFF (`Vehicle.cpp:722-782`) receive paths directly:

- **Entry at cycle position 2**: **5 messages** before the first successful reconstruction
  attempt. Filter-ON: 4×`NO_CACHE` (HASH_ONLY messages against a cache that doesn't exist
  yet, since the real cert isn't (re)signed until position wraps to 0) + 1×`NO_CERT_YET`
  (the SEGMENT_CARRYING idx=0 message that finally opens a buffer). Filter-OFF: all 5 are
  `NO_CERT_YET` — the baseline path doesn't distinguish message kind for its "no
  reconstructed cert" gate, so every message before completion gets the same outcome
  regardless of HASH_ONLY vs. SEGMENT_CARRYING.
- **Entry at cycle position 1 (worst case)**: **6 messages**. Filter-ON: 1×`BUFFER_CAP` (a
  SEGMENT_CARRYING idx=1 message arrives with no buffer open and can't start mid-sequence)
  + 4×`NO_CACHE` + 1×`NO_CERT_YET`. Filter-OFF: all 6 `NO_CERT_YET`.
- **Entry at position 0 (current, default)**: 1 message (`NO_CERT_YET`) per vehicle —
  matches the already-verified N=75 baseline (`legit_no_cert_yet = 2` for 2 vehicles,
  Update 15's addendum).
- **Correction made during planning**: an earlier draft of this analysis stated the
  entry-at-position-1 filter-ON composition as "1 `BUFFER_CAP` + 5 `NO_CERT_YET`" — wrong.
  Verified directly against `spam_filter_verify_falcon`'s HASH_ONLY branch
  (`Vehicle.cpp:964-974`), which drops a cache-miss as `NO_CACHE`/`SPAM_FILTERED`, a
  distinct outcome bucket from `NO_CERT_YET`. Corrected to 1 `BUFFER_CAP` + 4 `NO_CACHE` +
  1 `NO_CERT_YET`. The total counts (5 and 6) were already correct in the earlier draft —
  only the sub-breakdown was wrong.

### Design already worked out for whenever this is picked up (future-work candidate)
- One new scalar config field (e.g. `certCyclePhaseOffset`, `uint32_t`, default 0).
- Threaded through a new optional constructor parameter:
  `Vehicle(int number, uint32_t cert_cycle_phase_offset = 0)`, storing the raw value into
  `falcon_cycle_position`; `AttackerVehicle`'s constructor forwards the same param
  (default 0) to `Vehicle(...)`.
- Normalized safely via `falcon_cycle_position %= (FALCON_CERT_CYCLE_M +
  falcon_cycle_hash_only_count_n);` added once in `Vehicle::transmit()` right after
  `falcon_cycle_hash_only_count_n` is set — provably a no-op at the default offset=0
  (`0 % anything = 0`), so `offset=0` is mathematically identical to current behavior,
  sanity-checkable via a diff-free regression run before trusting non-zero offsets.
- **Flat global offset chosen over per-vehicle desync** (explicitly discussed and settled
  during planning): one scalar applied identically to every constructed vehicle (legit and
  attacker alike), matching the existing single-scalar `write_config` sweep pattern and
  already sufficient to test "receiver encounters a sender mid-cycle" — the offset is
  relative to receiver startup, not to other senders. A per-vehicle-varying alternative
  (`(offset + vehicle_index) % tau`, adding inter-vehicle desync as a free byproduct) was
  considered and explicitly deferred as a further follow-up, not silently rejected.
- No receiver-side code changes needed — every "premature" HASH_ONLY/SEGMENT_CARRYING path
  traced above lands in already-implemented, already-exercised cheap-check/cold-start
  branches (`NO_CACHE`, `BUFFER_CAP`, `NO_CERT_YET`), no new crash/UB surface.

### Status
Not implemented. No code changes in this Update. Flagged as a future-work candidate with the
above design ready to execute against.


-----------------------------------------------------------------------------------------
## Update 19

## Pilot: new `CHEAP_INVALID_SIGNATURE` cells (D_off/D_on) — STATUS: COMPLETE, N=10/cell

Small pilot only, per explicit instruction — **not** a full N=75 run, and **not** an
extension of `phase4_run_trials.sh` in place (a deliberately separate script,
`phase4_pilot_cheap_invalid.sh`, reusing the identical `write_config`/`run_trial` bodies,
so there was zero risk of accidentally re-triggering the locked N=75 A/B/C matrix
mid-pilot). Two new cells, mirroring `B_off`/`B_on`'s shape (`numAttackers:1,
numAttackerMessages:2000, numVehicles:2, numMessages:300`), only `attackerMode` changed to
`"cheap_invalid_signature"`. **All 20/20 trials reconciled exactly** — both the existing
metrics-size invariant and the new attacker 3-way reconciliation
(`full_crypto + cheap_reject + pending == attacker_total`, Update 16) held on every trial.

### Results (N=10/cell)

| Metric | D_off (filter OFF) | D_on (filter ON) |
|---|---|---|
| Legit VALID frac | 0.9967 (all 10) | 0.9967 (all 10) |
| Legit drop frac | 0 (all 10) | 0 (all 10) |
| Deadline-miss frac | avg 0.25% (0-0.5%) | 0% (all 10) |
| Attacker reached full crypto | **1999/2000** (all 10) | **0/2000** (all 10) |
| Attacker rejected cheaply | 0/2000 (all 10) | 1999/2000 (all 10) |
| Attacker pending | 1/2000 (all 10) | 1/2000 (all 10) |
| Cert-sig verify n | 2597 (all 10) | 2 (all 10) |

### D_on's rejection mechanism — cited from D_on's own drop-reason data, not by analogy

An earlier draft of this Update attributed D_on's near-total attacker rejection to "the same
`RATE`-limiter mechanism" as Update 11/16, citing Update 16's `invalid_signature` checkpoint
example — but that example is from a **different cell**. Corrected here using D_on's own
`attacker_spam_drop_reason_counts` (Update 16's new per-sender-type breakdown), pulled
directly from all 10 `D_on` pilot logs, aggregated:

| Reason | D_on total (10 trials) | Per-trial | Share of attacker rejections |
|---|---|---|---|
| RATE | 6670 | **667, every single trial, no variance** | 33.4% |
| NO_CACHE | 13320 | **1332, every single trial, no variance** | 66.6% |
| BUFFER_CAP | 0 | 0, every trial | 0% |
| BUFFER_TTL_EVICT_INCOMPLETE | 0 | 0, every trial | 0% |
| LENGTH / STALE / FRAG_INDEX / SEG_HASH | 0 | 0, every trial | 0% |

`667 + 1332 = 1999`, matching `attacker_cheap_reject` exactly on every trial — and unlike
Update 16's checkpoint (where `sum(attacker_spam_drop_reason_counts) = 1999 ≠
SPAM_FILTERED = 1983` because of `BUFFER_TTL_EVICT_INCOMPLETE`'s double-count hazard), D_on's
sum matches `SPAM_FILTERED` exactly on every trial, because `BUFFER_TTL_EVICT_INCOMPLETE` is
zero throughout — no stale buffer ever survives long enough to be evicted at this flood rate.

**This is a cleaner and more specific mechanism than Update 16's `invalid_signature`
checkpoint, not the same one — the RATE share is much higher, as anticipated.** Update 16's
single-trial breakdown for `invalid_signature`/filter-on was `66 RATE + 1332 NO_CACHE + 585
BUFFER_CAP + 16 BUFFER_TTL_EVICT_INCOMPLETE` (out of 1983) — RATE was only **3.3%** of
rejections there, with `BUFFER_CAP`/TTL-eviction (a receiver-backlog-interaction artifact,
Update 8-class) doing most of the work instead. D_on's RATE share is **33.4%**, roughly
**10x higher**, and `BUFFER_CAP` is entirely absent. Reading: at real-signing pace
(~4.5ms/msg), a segment-carrying message's gap against the frozen `last_seen_sendts` is
*close* to the 50ms floor, so which specific mechanism catches it (a clean `RATE` reject vs.
a buffer going stale and evicting before the next segment arrives) is somewhat
scheduling-dependent, exactly the mixed/noisy picture Update 8 already documents elsewhere.
At the ~200x tighter gaps `CHEAP_INVALID_SIGNATURE` produces, **every** segment-carrying
message fails the `RATE` check directly and deterministically, with such a wide margin that
no buffer ever survives long enough to reach `BUFFER_TTL_EVICT_INCOMPLETE` either — the
mechanism collapses to a single, exact, repeatable outcome instead of a scheduling-sensitive
mix. Legit traffic is unaffected in both cells across all 20 trials (`598/600` VALID, `0%`
drop rate).

### D_off: identical crypto volume, compressed into a shorter burst — not "higher cost"

An earlier draft claimed `D_off`'s crypto cost was "the highest of any cell measured so
far" — this overstates what the numbers show. `D_off`'s cert-sig verify count is **`2597`,
identical** to `B_off` and `C_off` (Update 15's N=75 table: both `2597 (all 75)`) — the
*total volume* of crypto operations performed is unchanged, not higher. `D_off` doesn't
force more work through the receiver; it forces the *same* work through in far less
wall-clock time, since signing delay no longer paces the attacker's send rate.

**What's actually different is legit-traffic pressure, visible in the deadline-miss rate:**
`D_off`'s deadline-miss frac is **avg 0.25% (0-0.5%)**, roughly **3.4x** `B_off`/`C_off`'s
N=75 average of **0.073%** each (Update 15's table). Same crypto volume, same receiver, but
compressed into a much shorter burst window — the attacker's ~2000 messages arrive and get
processed in a fraction of the time real signing would have taken, so the receiver's
existing per-message cost (verify + prints + bookkeeping) has to absorb a much higher
instantaneous arrival rate, producing more queueing-induced deadline misses for legit
traffic even though the crypto workload itself is unchanged. This is also the more direct
justification for why `D_on`'s rate-based early rejection specifically matters here — the
filter isn't defending against a larger raw message count (`D_off` and `B_off`/`C_off` all
processed 2000 attacker messages), it's defending against **burst timing**: an attacker that
can no longer be throttled by its own signing cost still gets throttled by
`spamFilterMinGapMs`, at zero crypto cost, before its compressed burst ever reaches the
receiver's per-message processing pipeline.

### Explicit confirmation
**These are new, additional cells. Update 15's existing A/B/C × off/on N=75 table is not
re-run, not superseded, and not otherwise touched by this work.** `D_off`/`D_on` are a
single small-N pilot cell pair, not yet run at report-quality trial count — a full N=75
pass on these two cells (following the exact precedent of Update 14/15's scale-up) is a
natural next step if these results hold up to scrutiny, but is explicitly not queued by
this Update.

### Config
`config.json` restored to production defaults
(`numVehicles:2, numMessages:25, numAttackers:1, attackerMode:"expensive_valid",
numAttackerMessages:100, spamFilterEnabled:false`) after the pilot, matching every prior
Update's convention.


-----------------------------------------------------------------------------------------
## Update 20

## N=75/cell scale-up: `CHEAP_INVALID_SIGNATURE` cells (D_off/D_on) — STATUS: COMPLETE

Update 19's N=10 pilot flagged "a full N=75 pass... is a natural next step if these
results hold up to scrutiny" — this is that pass, following the exact N=5→75 precedent
Update 14/15 already established for the main A/B/C matrix. **No code changes** — Changes
1/2 (Updates 16/17) were already implemented and validated; this is a config-scale-up,
run, and aggregate task only.

**Isolation, same rationale as Update 19**: run via a separate script
(`phase4_pilot_cheap_invalid.sh`, `N_TRIALS` bumped `10→75` in place, same single-line-
constant-change precedent as Update 14), never touching `phase4_run_trials.sh` — zero risk
to the locked A/B/C N=75 matrix. The N=10 pilot's raw logs were backed up to
`phase4_pilot_trials_n10_backup/` before this run overwrote `phase4_pilot_trials/`, so
Update 19's specific citations (e.g., the single-trial `invalid_signature`-checkpoint
comparison numbers) remain independently verifiable.

**All 150/150 trials (75/cell × 2 cells) reconciled exactly** — both the metrics-size
invariant and the attacker 3-way reconciliation (`full_crypto + cheap_reject + pending ==
attacker_total`, Update 16's checkpoint standard) held on every single trial, zero
failures.

### Verified: the N=10 pilot's zero-variance finding holds exactly at N=75, no exceptions

Update 19 found `D_on`'s attacker rejection was a deterministic split (`667 RATE + 1332
NO_CACHE`, zero `BUFFER_CAP`/`BUFFER_TTL_EVICT_INCOMPLETE`) with zero variance across all
10 trials, reasoned to be pure integer arithmetic on cycle length (`τ=6`) and message count
(`2000`) rather than a scheduling-dependent artifact. **Checked as a hard per-trial
assertion, not an average, across all 75 `D_on` trials: 75/75 match `RATE=667,
NO_CACHE=1332, BUFFER_CAP=0, BUFFER_TTL_EVICT_INCOMPLETE=0, pending=1` exactly.** Zero
deviations — no trial needed tracing. This confirms the N=10 finding was not a small-sample
artifact: the mechanism really is deterministic (a function of `τ` and total message count
only, independent of wall-clock scheduling noise), unlike the legit-side backlog artifacts
found throughout this doc (Update 8/11/12/14/15), which are all scheduling-dependent and
do show real trial-to-trial variance at this sample size.

### Results (N=75/cell)

| Metric | D_off (filter OFF) | D_on (filter ON) |
|---|---|---|
| Legit VALID frac | 0.9967 (all 75) | 0.9967 (all 75) |
| Legit drop frac | 0 (all 75) | 0 (all 75) |
| Deadline-miss frac | avg 0.29% (0-0.83%) | 0% (all 75) |
| Attacker reached full crypto | **1999/2000** (all 75) | **0/2000** (all 75) |
| Attacker rejected cheaply | 0/2000 (all 75) | 1999/2000 (all 75) |
| Attacker pending | 1/2000 (all 75) | 1/2000 (all 75) |
| Cert-sig verify n | 2597 (all 75) | 2 (all 75) |

### Attacker drop-reason breakdown (D_on, N=75, exact on every trial)

| Reason | Per-trial (all 75) | Share of attacker rejections |
|---|---|---|
| RATE | 667 | 33.4% |
| NO_CACHE | 1332 | 66.6% |
| BUFFER_CAP | 0 | 0% |
| BUFFER_TTL_EVICT_INCOMPLETE | 0 | 0% |
| LENGTH / STALE / FRAG_INDEX / SEG_HASH | 0 | 0% |

This drop-reason breakdown (per-trial counts and percentages) is identical to Update 19's
N=10 pilot table — the larger sample changes nothing about the mechanism, only confirms
it. (The headline table's deadline-miss figure shifted slightly, 0.25%→0.29% for `D_off`,
ordinary N=10-to-N=75 sampling variation on a timing statistic, not a mechanism change —
see Update 15 for the same class of shift on other cells.) `D_off` shows no analogous drop-reason
block (the spam filter's print block is guarded on `spamFilterEnabled`, absent entirely
for a filter-off run), consistent with `attacker_cheap_reject=0/2000` there — with no
filter, there is nothing to cheaply reject.

### Legit-side note: zero backlog-artifact drops across all 150 trials, unlike the main matrix

`D_off`/`D_on`'s legit drop frac is **exactly 0 in all 75 trials, both cells** — no
occurrence of the buffer-TTL-eviction-under-startup-backlog artifact that hit `B_on`/`C_on`
in 16/75 and 24/75 trials respectively (Update 15). Not investigated further here since it
isn't a deviation requiring tracing (both cells' legit traffic is clean, not anomalous),
but noted as an open observation, not asserted as an explained finding: worth revisiting if
`D_off`/`D_on` are ever pushed to report-quality analysis alongside B/C, since the
mechanism that makes this pair different (if any beyond sample luck) hasn't been traced.

### Explicit confirmations
- **Update 15's existing A/B/C × off/on N=75 table remains completely untouched and
  unaffected by this work.** Nothing in this Update re-runs, edits, or reinterprets any of
  those 450 trials.
- **This run supersedes Update 19's N=10 pilot as the reportable D_off/D_on figures for the
  report/poster.** Update 19 itself is not edited or removed — it stays in this doc as the
  pilot record (including its corrected mechanism analysis from the precision-fix pass),
  but Update 20's N=75 numbers above are what should be cited going forward.

### Config
`config.json` restored to production defaults
(`numVehicles:2, numMessages:25, numAttackers:1, attackerMode:"expensive_valid",
numAttackerMessages:100, spamFilterEnabled:false`) after the run, matching every prior
Update's convention.

## Update 21

## Sustained-duration A/B/C/D re-run (WSL2, rate-capped Attack D) — STATUS: COMPLETE, N=75/cell × 8 cells = 600 trials

**Separate dataset, not a correction to Update 15/20.** This redoes the A/B/C/D matrix with
`attackerMatchLegitDuration:true` (each attacker floods until every legit vehicle finishes,
instead of stopping after a fixed `numAttackerMessages` count) and, for Attack D only, a new
send-rate cap. Two things differ from Update 15/20 simultaneously — the attacker-sustain
methodology *and* the execution environment (this machine's WSL2, `nproc=28`, vs. the original
2-core VM) — so no numeric difference from Update 15/20 below should be attributed to either
change alone. Update 15/20 remain the citable, unedited record for the old fixed-count
methodology; this Update is cross-referenced against them, never framed as superseding them.

**This Update does supersede an aborted attempt from the immediately preceding session on
this same machine** (undocumented in this file until now, since it never reached a clean
result): a first pass enabled `attackerMatchLegitDuration:true` with no rate cap on Attack D
and collapsed the receiver two different ways —
- **D_off (filter disabled)**: the attacker sent 6,091,247 messages in ~30s (~200k msg/sec,
  bounded only by this laptop's CPU, since `cheap_invalid_signature` skips real signing
  entirely — see `bypass_falcon_signing()`, `src/AttackerVehicle.cpp:32-34`, and the
  `RAND_bytes`-filled signature at `src/Vehicle.cpp:594-599`). Only 298,944 of those messages
  ever reached the receiver before the OS UDP receive buffer overflowed; the run ended early
  on `[ReceiveEndOfRun]`'s 5s idle timeout having processed only 46/600 legit messages
  (`INCOMPLETE RUN`).
- **D_on (filter enabled)**: the spam filter correctly flagged 4,754,018/4,754,022 attacker
  messages as `SPAM_FILTERED`, but doing 4.75M "cheap" per-message checks in ~30s (avg
  0.0064ms each ≈ 30.4s of receiver time) consumed essentially the receiver's entire
  single-threaded time budget for the whole trial, starving legit traffic to 6.02%
  VALID / 93.57% deadline-miss — directly contradicting Update 20's "small, self-healing
  cost" framing, which was measured against a 46ms burst, not a sustained flood.

B_off/B_on and C_off/C_on were unaffected in that same aborted pass (600/600 legit received,
0% deadline-miss, clean reconciliation) — only Attack D broke, because it's the only mode
whose send rate isn't naturally throttled by real signing cost.

### Root cause and fix: Attack D's send rate wasn't bounded by anything realistic

A real attacker doing a pure volumetric flood is bounded by the physical DSRC channel, not by
how fast a laptop can call `RAND_bytes`/`sendto`. B/C are unaffected by this because their real
per-message Falcon signing cost is itself a legitimate, intentional part of what those two
conditions measure — this fix is scoped **specifically to Attack D**.

Added `attackerFloodRateCapPerSec` (`config.json`, default `0` = disabled/unthrottled, no
behavior change for any mode when unset; `src/main.cpp`, ~20 new lines plus one changed call
site; see `README.md` item 10 for the full field description). When set and `attackerMode` is
`"cheap_invalid_signature"`, it's converted to a per-message delay in whole milliseconds and
passed as `AttackerVehicle`'s existing `flood_delay_ms` constructor argument — reusing the
`inter_message_delay_ms()`/`sleep_for` pacing mechanism that was already wired into
`transmit_loop` (`src/Vehicle.cpp:62`) and already duration-mode-compatible, just never
exposed via config. `expensive_valid`/`invalid_signature` ignore the field entirely.

**Rate derivation**: ~1010 msg/sec, from Twardokus & Rahbari (the paper this testbed extends),
Table IV — Falcon Partially-Hybrid's frame-duration-constrained channel capacity is
`vmax=101` vehicles under worst-case 6 Mbps DSRC data rate, each sending 1 BSM per 100ms
cadence → `101 × 10 = ~1010` BSM/sec realistic ceiling. Millisecond-granularity `sleep_for`
can't hit 1010/sec exactly: `round(1000/1010) = 1ms` per message → a **nominal** rate of
**1000/sec**. That figure (`1000/flood_delay_ms`, printed on the `[AttackerFloodRateCap]`
startup line as `achieved_rate_per_sec`) is a constant computed once at startup, not a
measurement. The **measured** rate is lower: `sleep_for(1ms)` overshoots and each message also
costs generation/send time (the attacker's own `avg_actual_gap_ms` is ~1.2-1.3ms), so D
actually sends a mean of **791 msg/sec** (median 793, range 743-842 across all 150 D-cell
trials; measured as receiver-side `attacker_total` ÷ the attacker's own send time), about 21%
under the nominal 1000 and 22% under the 1010 target. The cap still works as a ceiling (the
uncapped attacker sent ~200,000 msg/sec), but the rate is not "about 1% under" as first
written — see `context/CORRECTIONS.md` #20.

**Out-of-scope observation, not addressed here**: the aborted pass's B_off/C_off also ran at
~4,200 msg/sec on this WSL2 hardware — also above the 1010 msg/sec channel ceiling, just not
catastrophically so (real signing cost still kept the receiver from being overrun). Left
untouched per explicit scoping (B/C's real signing cost is what's being measured for those
conditions), but flagged here as a candidate for future work rather than re-discovered as a
surprise later.

### Verification before the batch: one manual trial, then N=3/cell × 8 cells

Single manual trial (D, filter off, `attackerFloodRateCapPerSec:1010`): no `INCOMPLETE RUN`,
`Legitimate messages processed: 600`, 0% deadline-miss, attacker messages processed = 24,591
(order-of-magnitude match to the ~30,000 expected at ~1000/sec × ~30s, not millions).

Sanity pilot (`phase4_pilot_match_duration.sh` + `phase4_match_duration_aggregate.py`, both new
and separate from `phase4_run_trials.sh`/`phase4_sweep_params.sh`/`phase4_pilot_cheap_invalid.sh`
— zero risk to the locked Update 15/20 matrix or any other in-progress work), N=3/cell, all 8
cells (A/B/C/D × off/on): **24/24 trials reconciled exactly**, every cell 598/600 legit VALID,
0% deadline-miss, every attacker-bearing trial `stop_reason=completion` (never
`backstop_timeout`), D cells' nominal rate line 1000/sec on all 3 trials (a startup constant;
the measured rate was not checked at this stage — see CORRECTIONS.md #20). Resource sampler
(`/proc/loadavg` + `free -m` every ~12s) showed a loadavg peak of 1.44 on this 28-core box and
zero swap use — no contention. Clean pass on both gates → proceeded automatically into the full
N=75 matrix per advance approval for this run.

### Full run: N=75/cell × 8 cells, 600/600 trials reconciled exactly, zero failures

Same script pattern scaled to `N_TRIALS=75`
(`phase4_run_trials_match_duration.sh`/`phase4_match_duration_aggregate.py`). Reconciliation
here checks the **legit-only** invariant (`legit_total == numMessages*numVehicles == 600`),
not the old fixed-total check `phase4_aggregate.py`/`phase4_pilot_aggregate.py` use — those two
scripts are correctly left untouched, since `context/BUGS.md` already documented them as not
duration-mode-aware, and they're only ever used for the old fixed-count matrix. The attacker's
own message count is an *output* here, not an input, so there's no fixed total to check it
against; the 3-way outcome sum (`full_crypto + cheap_reject + pending == attacker_total`) is
still checked as an internal consistency invariant, since that holds regardless of duration
mode.

**All 600/600 trials reconciled exactly, zero failures, zero trials excluded.**

| Metric | A_off | A_on | B_off | B_on | C_off | C_on | D_off | D_on |
|---|---|---|---|---|---|---|---|---|
| Legit VALID frac | 0.9967 (75/75) | 0.9967 (75/75) | 0.9967 (75/75) | 0.9967 (74/75)¹ | 0.9967 (75/75) | 0.9967 (75/75) | 0.9967 (75/75) | 0.9967 (74/75)¹ |
| Legit drop frac | 0 (75/75) | 0 (75/75) | 0 (75/75) | 0 (74/75)¹ | 0 (75/75) | 0 (75/75) | 0 (75/75) | 0 (74/75)¹ |
| Deadline-miss frac | 0 (75/75) | 0 (75/75) | ~0 (74/75; 1/600 in 1 trial) | ~0 (74/75; 1/600 in 1 trial)¹ | ~0 (74/75; 1/600 in 1 trial) | 0 (75/75) | ~0 (74/75; 2/600 in 1 trial) | ~0 (73/75; 1/600 in 2 trials) |
| Attacker total (output) | 0 | 0 | avg 125,400 (119,034-127,948) | avg 125,600 (122,784-126,919) | avg 126,800 (125,588-127,948) | avg 126,500 (124,707-133,484) | avg 24,320 (23,363-25,403) | avg 23,550 (22,572-25,119) |
| Attacker full-crypto frac | n/a | n/a | 1.0000 (all 75) | 0.0000 (all 75) | 1.0000 (all 75) | 0.0000 (all 75) | 1.0000 (all 75) | 0.0000 (all 75) |
| Attacker cheap-reject frac | n/a | n/a | 0.0000 (all 75) | 0.9995 (all 75) | 0.0000 (all 75) | 0.9995 (all 75) | 0.0000 (all 75) | 0.9973-0.9976 |
| Attacker pending (count) | n/a | n/a | 1 (all 75) | 61 (all 75) | 1 (all 75) | 61 (all 75) | 1 (all 75) | 60-61 |
| `stop_reason` | n/a | n/a | completion=70/UNPARSED=5² | completion=73/UNPARSED=2² | completion=71/UNPARSED=4² | completion=74/UNPARSED=1² | completion=74/UNPARSED=1² | completion=73/UNPARSED=2² |
| Send rate (D only): nominal / measured | — | — | — | — | — | — | nominal 1000 (75/75) / measured 805 (774-842; 75/75) | nominal 1000 (75/75) / measured 778 (743-833; 75/75) |

¹ B_on/D_on each had exactly 1/75 trials with `legit_valid=597/600` instead of 598/600 (one
extra drop) — **originally described here as the same class of run-to-run self-heal/backlog-timing
variance as Update 15; that was wrong: these trials are wall-clock-step artifacts, see ³.** No deviating trial's numbers were folded into an average silently —
counted and called out here instead, same standard as Update 15.

² Parseable `stop_reason` per cell, from re-parsing every transmitter log: `completion` in
435 of the 450 attacker-bearing trials, `UNPARSED` in the other 15. In those 15 the
`[AttackerRunSummary]` line is missing from the transmitter log entirely (lost to the
unsynchronized multi-thread `std::cout` race described below), so their stop reason is
unrecorded, not confirmed. No log shows `backstop_timeout`, and all 15 have a receiver-side
`attacker_total` inside their cell's normal range — a 60s backstop run would roughly double
it — so they very likely completed normally. See `context/CORRECTIONS.md` #19 (this row
originally read `completion (75/75)` in all six cells).

³ **Correction (2026-09-19, CORRECTIONS.md #21): all 6 deviating trials in this table are wall-clock-step artifacts, not delays or backlog.**
They are B_off 53, B_on 15, C_off 24, D_off 46, D_on 13 and D_on 47: the 1-2/600 late-message counts in the deadline-miss row, and the two
597/600 trials (B_on 15 and D_on 47) with one `STALE` drop each. Each coincides (±0.5 s) with a `systemd-resolved: Clock change detected` journal entry, and
the realtime-minus-monotonic offset jump at that entry equals the trial's late-message latency to within 1-2 ms (527→+527, 496→+496, 597→+597,
738→+737, 603→+601, 468→+467 ms). The receiver measures latency, and the filter its `STALE` test, as `system_clock` now minus the embedded `system_clock` send time, so a forward
clock step (+0.4-0.75 s, every 32.25 s while this machine's clock was lagging) inflates every message in flight at that instant; nothing was actually delayed. The
stepping was already running for the whole of this run (journal: steps every 32.25 s from 00:31 to 07:33 on 2026-09-18; 552 of the 600 trials had at least one step inside their messaging window).
The counts in the table are as measured and are unchanged; what changes is their meaning.

**Headline finding: the spam filter's near-total cheap-rejection result holds under a truly
sustained flood, unlike the aborted uncapped attempt.** With Attack D rate-capped to a
realistic channel ceiling, `D_on`'s legit VALID frac is 0.9967 — identical to every other
cell, not the 6.02% collapse seen in the uncapped pass. `D_off`/`D_on`'s attacker full-crypto
vs. cheap-reject split (100%/0% off, 0%/~99.7% on) mirrors Update 20's old fixed-count finding
(`1999/2000` full-crypto off, `1999/2000` cheap-reject on) at a completely different, sustained
message volume (~24,000 vs. 2,000) — the mechanism generalizes, it wasn't an artifact of the
old 46ms-burst scale. Both of the aborted pass's failure modes (socket-buffer overflow *and*
filter-check-budget starvation) were downstream of the attacker's unrealistic, CPU-bound send
rate — capping that rate to the paper's own channel-capacity ceiling resolved both at once,
without touching the filter logic itself.

### Resource monitoring: no contention found

`/proc/loadavg` + `free -m` sampled every ~15s for the full ~6-hour run (`environment.txt`:
`nproc=28`, 15,841MB total RAM). Loadavg ranged 0.00-1.86 (median 0.83) across 1,407 samples —
trivial on a 28-core box. Used memory held steady at 887-963MB throughout, no growth trend.
Swap stayed at 0MB used for all but one sample (1MB, negligible). No correlation was found
between the handful of deviating trials (footnote ¹ above) and any load/memory spike in the
sampled log — they occurred during otherwise-idle periods, consistent with ordinary
scheduling-timing jitter rather than resource contention.

### Diagnostic-field caveat: transmitter-side stdout is multi-threaded and unsynchronized

`std::cout` is shared, unguarded, across three threads (2 legit + 1 attacker) in the
transmitter process. This doesn't affect any number in the table above (all sourced from the
receiver process, which is single-threaded), but it does corrupt the transmitter's own
diagnostic prints (`[AttackerRunSummary]`'s `actual_elapsed_ms`, `[FloodRateCheck]`) under
high message volume — observed directly: one B/C/D trial's `actual_elapsed_ms` field parsed
as a two-numbers-spliced-together string (`"101.93630218.4"`), which isn't a valid float. The
new aggregator (`phase4_match_duration_aggregate.py`) was fixed to catch this
(`_num()` helper, returns `None` instead of crashing) rather than assume the field is reliable.
Not fixed at the source (would mean adding a mutex around every transmit-side `std::cout` use,
out of scope for this Update) — noted here as a known limitation of the duration-mode diagnostic fields, not of
the reconciliation data.

### Explicit confirmations
- **Updates 15/20's tables remain completely untouched.** Nothing in this Update re-runs,
  edits, or reinterprets those 450+150 trials; they stay the citable record for the old
  fixed-count methodology on the original 2-core VM.
- `phase4_run_trials.sh`, `phase4_sweep_params.sh`, and `phase4_pilot_cheap_invalid.sh` were
  never touched or executed during this work.
- New files: `src/main.cpp` (diff above), `README.md` (field 10),
  `scripts/phase4_harness/phase4_pilot_match_duration.sh`,
  `scripts/phase4_harness/phase4_run_trials_match_duration.sh`,
  `scripts/phase4_harness/phase4_match_duration_aggregate.py`. The `scripts/phase4_harness/`
  and `phase4_raw_logs/` directories are both git-ignored (`.gitignore:4-5`), so none of this —
  including the ~18GB of raw per-message logs this run produced (vs. Update 15's 376MB, from
  sustaining real per-message traffic for the full trial instead of a fixed 2000-message
  burst) — touches the tracked repo.

### Config
`config.json` restored to production defaults
(`numVehicles:2, numMessages:25, numAttackers:1, attackerMode:"expensive_valid",
numAttackerMessages:100, spamFilterEnabled:false`) after the run, matching every prior
Update's convention.

## Update 22

## Vehicle-count scaling sweep: 4 / 6 / 9 legitimate vehicles + 1 attacker, A/B/C/D × filter off/on (WSL2, sustained-duration, rate-capped D) — STATUS: COMPLETE (the driver exited in REVIEW state on one false positive in its own gate; corrected below; the meaning of the late/dropped-message events was corrected on 2026-09-19, see CORRECTIONS.md #21)

Hassan asked whether the spam filter's effectiveness holds as network density rises. This
re-runs Update 21's A/B/C/D × filter-off/on matrix at `numVehicles` = 4, 6 and 9 (plus the one
attacker; the simulator caps at 10 senders), **N=30 per cell = 240 trials per level, 720 trials
total**, each level preceded by an N=5/cell pilot gated before the full run. `numVehicles=2` is
**not re-run**: its column below is Update 21's own N=75 data, read from
`exports/update21_per_trial.csv`. Same machine, same binary (unchanged since Update 21; the
harness re-checked it was newer than every source file), same method (`attackerMatchLegitDuration:true`;
`attackerFloodRateCapPerSec:1010` for D only), so unlike Updates 15/20 the L=2 point **is**
directly comparable to the others. One caveat: the L=2 data was collected in an earlier WSL boot (WSL
was restarted at ~23:13 on 2026-09-18, between the two runs), so a small environment difference
between L=2 and the other levels cannot be excluded.

**N=30 is a deliberate tradeoff, not a headline-grade sample.** Update 21 used N=75 per cell;
this is a secondary scaling panel, so each level gets 30. That is small for the events that
matter here (see "What deviated": about 1 trial in 100 shows any legit drop or late message), so
this panel can rule out large effects but cannot resolve small changes in a rare-event rate. Same
standard of disclosure as the `bufferTtlMs`/`spamFilterGlobalStateCap` sweep.

### Answer: the filter holds from 2 to 9 legitimate vehicles. Nothing breaks, and the only late or dropped legit messages are wall-clock-step artifacts, not filter or receiver cost

- **Effect on the attacker is unchanged.** Cheap-reject fraction with the filter on is flat across
  levels: B_on / C_on ≈ 0.9995 and D_on ≈ 0.9974-0.9977 at every level (table below), and **zero**
  attacker messages reached full crypto in any filter-on trial at any level (495 trials), against ~100% reaching full crypto with the filter off.
- **No cost to legitimate traffic was observed.** Legit drops (excluding the one cold-start
  `NO_CERT_YET` per vehicle) with the filter on: 2/134,550 (L=2), 1/107,640 (L=4), 0/161,460 (L=6), 7/242,190 (L=9), never above 0.0029%; with the filter off there were zero
  drops at every level. All 10 filter-on drops were `STALE` cheap-drops, and **every one coincides with a forward step of the machine's wall clock** (see "What deviated"): the messages were not delayed, the clock jumped, so the filter's `received_time − send_ts >= 100 ms` test saw a fresh message as stale. They are artifacts of this machine's clock, not a cost of the filter; with synchronized clocks none would be expected.
- **The receiver did not fall behind on legitimate volume.** This was the main new risk (one
  single-threaded receive loop absorbing up to 9 × 10 = 90 legit msg/s, before any attacker
  traffic). The no-attacker A cells stayed clean: A_off legit VALID-latency p99 rose only mildly, 2.1 ms (L=2) to 3.5 ms (L=9), against the 100 ms
  deadline, and the pooled A-cell late-message rate was 0.0000% / 0.0000% / 0.0000% / 0.0050% at L=2/4/6/9 (the L=9 figure is 8 late messages in 2 of 60 trials, largest 6/2,700 = 0.22% of that trial). Those late messages are clock-step artifacts, not delays (see "What deviated").
- **Where density does show up.** Only in how likely a clock step is to catch legit messages in
  flight. Per clock step that occurred inside a trial's messaging window, the chance of at least one legit
  late/dropped message was 1.09% at L=2 (6/552), 1.40% at L=4 (3/215) and 3.47% at L=9 (5/144), and legit late messages per event were
  1.2 / 2.0 / 4.4 at L=2 / 4 / 9: more vehicles send in the same instant, so more are in flight when a step lands.
  With the filter ON those messages become `STALE` drops; with it OFF they are just late.
- **What this panel cannot say.** L=6 saw only 10 clock steps inside its trials (the stepping regime was off for most of it), so its zero
  events carry no information. The per-step rates' 95% intervals overlap (L=2 0.50-2.35%, L=4 0.48-4.02%, L=9 1.49-7.87%), so the rise with
  vehicle count is what the mechanism predicts but is not established by this N. Earlier drafts reported "stalls per 100 trials"
  (1.00 / 1.25 / 0.00 / 2.08), which was confounded by how many trials happened to run while stepping was on; that figure is withdrawn.

### Full results, L=4 (4 legitimate + 1 attacker; N=30/cell, 240 trials; expected legit msgs/trial = 1200; non-startup = 1196)

| Metric | A_off | A_on | B_off | B_on | C_off | C_on | D_off | D_on |
|---|---|---|---|---|---|---|---|---|
| Legit VALID frac (modal value; trials at it) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (29/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) |
| Legit drops, non-startup (trials with a drop) | 0 | 0 | 0 | 1 (1 trial) | 0 | 0 | 0 | 0 |
| Late legit msgs >100 ms (trials with one) | 0 | 0 | 2 (1 trial) | 2 (1 trial) | 0 | 0 | 2 (1 trial) | 0 |
| Attacker total (output) | 0 | 0 | avg 125,463 (124,314-126,473) | avg 123,460 (118,560-125,161) | avg 121,622 (119,556-123,926) | avg 120,650 (118,913-124,000) | avg 26,528 (26,340-26,723) | avg 26,382 (26,232-26,551) |
| Attacker full-crypto frac | n/a | n/a | 1.0000 (all 30) | 0.0000 (all 30) | 1.0000 (all 30) | 0.0000 (all 30) | 1.0000 (all 30) | 0.0000 (all 30) |
| Attacker cheap-reject frac | n/a | n/a | 0.0000 (all 30) | 0.9995 (all 30) | 0.0000 (all 30) | 0.9995 (all 30) | 0.0000 (all 30) | 0.9977 (all 30) |
| Attacker pending (count) | n/a | n/a | 1 (all 30) | 61 (all 30) | 1 (all 30) | 61 (all 30) | 1 (all 30) | 60-61 |
| `stop_reason` | n/a | n/a | completion=30/UNPARSED=0 | completion=29/UNPARSED=1 | completion=27/UNPARSED=3 | completion=30/UNPARSED=0 | completion=29/UNPARSED=1 | completion=30/UNPARSED=0 |
| Measured attacker send rate, msg/s (mean; min-max; n measured) | — | — | 4165 (4127-4197; n=30) | 4102 (3938-4155; n=28) | 4038 (3972-4116; n=27) | 4008 (3951-4110; n=26) | 881 (874-887; n=28) | 875 (870-880; n=30) |
| Legit VALID-latency p99, ms (mean; worst trial) | 3.14 (3.48) | 2.57 (3.23) | 1.58 (3.54) | 1.06 (1.69) | 1.27 (1.65) | 0.94 (1.23) | 1.71 (2.42) | 1.63 (2.20) |

Cold-start `NO_CERT_YET` = 4 per trial (one per vehicle), so the modal VALID fraction is 1196/1200 = 0.9967 at every level, as at L=2. Reconciled trials that differed from the modal (valid/drop/late) triple, listed individually:

  - B_off trial 1: valid/drop/late = 1196/0/2 (modal 1196/0/0)
  - B_on trial 9: valid/drop/late = 1195/1/2 (modal 1196/0/0)
  - D_off trial 12: valid/drop/late = 1196/0/2 (modal 1196/0/0)

### Full results, L=6 (6 legitimate + 1 attacker; N=30/cell, 240 trials; expected legit msgs/trial = 1800; non-startup = 1794)

| Metric | A_off | A_on | B_off | B_on | C_off | C_on | D_off | D_on |
|---|---|---|---|---|---|---|---|---|
| Legit VALID frac (modal value; trials at it) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) |
| Legit drops, non-startup (trials with a drop) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Late legit msgs >100 ms (trials with one) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Attacker total (output) | 0 | 0 | avg 123,820 (123,144-124,503) | avg 122,296 (120,895-123,339) | avg 123,520 (122,597-125,525) | avg 122,714 (121,719-123,535) | avg 24,500 (23,207-26,283) | avg 26,082 (25,889-26,259) |
| Attacker full-crypto frac | n/a | n/a | 1.0000 (all 30) | 0.0000 (all 30) | 1.0000 (all 30) | 0.0000 (all 30) | 1.0000 (all 30) | 0.0000 (all 30) |
| Attacker cheap-reject frac | n/a | n/a | 0.0000 (all 30) | 0.9995 (all 30) | 0.0000 (all 30) | 0.9995 (all 30) | 0.0000 (all 30) | 0.9976-0.9977 |
| Attacker pending (count) | n/a | n/a | 1 (all 30) | 61 (all 30) | 1 (all 30) | 61 (all 30) | 1 (all 30) | 61 (all 30) |
| `stop_reason` | n/a | n/a | completion=29/UNPARSED=1 | completion=30/UNPARSED=0 | completion=29/UNPARSED=1 | completion=29/UNPARSED=1 | completion=27/UNPARSED=3 | completion=29/UNPARSED=1 |
| Measured attacker send rate, msg/s (mean; min-max; n measured) | — | — | 4095 (4054-4117; n=28) | 4045 (3999-4079; n=29) | 4086 (4053-4150; n=29) | 4057 (4026-4089; n=28) | 809 (765-868; n=29) | 861 (855-867; n=29) |
| Legit VALID-latency p99, ms (mean; worst trial) | 3.30 (3.79) | 2.75 (3.23) | 1.61 (2.28) | 1.36 (2.14) | 1.43 (1.92) | 1.17 (1.56) | 2.47 (3.39) | 1.54 (1.79) |

Cold-start `NO_CERT_YET` = 6 per trial (one per vehicle), so the modal VALID fraction is 1794/1800 = 0.9967 at every level, as at L=2. Reconciled trials that differed from the modal (valid/drop/late) triple, listed individually:

  - (none)

### Full results, L=9 (9 legitimate + 1 attacker; N=30/cell, 240 trials; expected legit msgs/trial = 2700; non-startup = 2691)

| Metric | A_off | A_on | B_off | B_on | C_off | C_on | D_off | D_on |
|---|---|---|---|---|---|---|---|---|
| Legit VALID frac (modal value; trials at it) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (30/30) | 0.9967 (29/30) | 0.9967 (30/30) | 0.9967 (29/30) | 0.9967 (30/30) | 0.9967 (30/30) |
| Legit drops, non-startup (trials with a drop) | 0 | 0 | 0 | 4 (1 trial) | 0 | 3 (1 trial) | 0 | 0 |
| Late legit msgs >100 ms (trials with one) | 8 (2 trials) | 0 | 5 (1 trial) | 5 (1 trial) | 0 | 4 (1 trial) | 0 | 0 |
| Attacker total (output) | 0 | 0 | avg 122,606 (121,444-123,971) | avg 121,514 (119,644-122,983) | avg 124,011 (120,668-125,854) | avg 121,296 (119,553-124,824) | avg 26,618 (26,562-26,677) | avg 26,120 (25,860-26,707) |
| Attacker full-crypto frac | n/a | n/a | 1.0000 (all 30) | 0.0000 (all 30) | 1.0000 (all 30) | 0.0000 (all 30) | 1.0000 (all 30) | 0.0000 (all 30) |
| Attacker cheap-reject frac | n/a | n/a | 0.0000 (all 30) | 0.9995 (all 30) | 0.0000 (all 30) | 0.9995 (all 30) | 0.0000 (all 30) | 0.9976-0.9978 |
| Attacker pending (count) | n/a | n/a | 1 (all 30) | 61 (all 30) | 1 (all 30) | 61 (all 30) | 1 (all 30) | 60-61 |
| `stop_reason` | n/a | n/a | completion=29/UNPARSED=1 | completion=25/UNPARSED=5 | completion=30/UNPARSED=0 | completion=28/UNPARSED=2 | completion=30/UNPARSED=0 | completion=29/UNPARSED=1 |
| Measured attacker send rate, msg/s (mean; min-max; n measured) | — | — | 4072 (4034-4118; n=27) | 4034 (3970-4083; n=26) | 4117 (4006-4180; n=30) | 4012 (3956-4143; n=28) | 881 (879-884; n=30) | 864 (856-884; n=30) |
| Legit VALID-latency p99, ms (mean; worst trial) | 3.45 (4.10) | 2.45 (3.15) | 2.49 (3.13) | 1.56 (2.17) | 2.06 (3.21) | 1.26 (1.78) | 1.33 (1.65) | 1.73 (2.37) |

Cold-start `NO_CERT_YET` = 9 per trial (one per vehicle), so the modal VALID fraction is 2691/2700 = 0.9967 at every level, as at L=2. Reconciled trials that differed from the modal (valid/drop/late) triple, listed individually:

  - A_off trial 10: valid/drop/late = 2691/0/2 (modal 2691/0/0)
  - A_off trial 20: valid/drop/late = 2691/0/6 (modal 2691/0/0)
  - B_off trial 2: valid/drop/late = 2691/0/5 (modal 2691/0/0)
  - B_on trial 18: valid/drop/late = 2687/4/5 (modal 2691/0/0)
  - C_on trial 7: valid/drop/late = 2688/3/4 (modal 2691/0/0)

### Four-point trend (L=2 from Update 21, N=75/cell; L=4/6/9 from this run, N=30/cell)

**Effect on the attacker**

| Metric | L=2 | L=4 | L=6 | L=9 |
|---|---|---|---|---|
| B_on attacker cheap-reject frac (mean) | 0.99951 | 0.99951 | 0.99950 | 0.99950 |
| C_on attacker cheap-reject frac (mean) | 0.99952 | 0.99949 | 0.99950 | 0.99950 |
| D_on attacker cheap-reject frac (mean) | 0.99742 | 0.99772 | 0.99766 | 0.99768 |
| filter-ON attacker msgs reaching full crypto (all B/C/D _on trials) | 0 of 20,674,282 | 0 of 8,114,748 | 0 of 8,132,755 | 0 of 8,067,888 |
| B_off attacker full-crypto frac (mean) | 0.999992 | 0.999992 | 0.999992 | 0.999992 |
| C_off attacker full-crypto frac (mean) | 0.999992 | 0.999992 | 0.999992 | 0.999992 |
| D_off attacker full-crypto frac (mean) | 0.999959 | 0.999962 | 0.999959 | 0.999962 |

**Effect on legitimate traffic (pooled over cells)**

| Group (pooled trials) | Metric | L=2 | L=4 | L=6 | L=9 |
|---|---|---|---|---|---|
| A: no attacker (A_off + A_on) | trials / non-startup legit msgs | 150 / 89,700 | 60 / 71,760 | 60 / 107,640 | 60 / 161,460 |
| | legit drops (rate) | 0 (0.0000%) | 0 (0.0000%) | 0 (0.0000%) | 0 (0.0000%) |
| | late legit msgs >100 ms (rate) | 0 (0.0000%) | 0 (0.0000%) | 0 (0.0000%) | 8 (0.0050%) |
| | trials with any drop or late msg | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2 (3.3%) |
| attacker, filter OFF (B/C/D_off) | trials / non-startup legit msgs | 225 / 134,550 | 90 / 107,640 | 90 / 161,460 | 90 / 242,190 |
| | legit drops (rate) | 0 (0.0000%) | 0 (0.0000%) | 0 (0.0000%) | 0 (0.0000%) |
| | late legit msgs >100 ms (rate) | 4 (0.0030%) | 4 (0.0037%) | 0 (0.0000%) | 5 (0.0021%) |
| | trials with any drop or late msg | 3 (1.3%) | 2 (2.2%) | 0 (0.0%) | 1 (1.1%) |
| attacker, filter ON (B/C/D_on) | trials / non-startup legit msgs | 225 / 134,550 | 90 / 107,640 | 90 / 161,460 | 90 / 242,190 |
| | legit drops (rate) | 2 (0.0015%) | 1 (0.0009%) | 0 (0.0000%) | 7 (0.0029%) |
| | late legit msgs >100 ms (rate) | 3 (0.0022%) | 2 (0.0019%) | 0 (0.0000%) | 9 (0.0037%) |
| | trials with any drop or late msg | 3 (1.3%) | 1 (1.1%) | 0 (0.0%) | 2 (2.2%) |

**Other metrics**

| Metric | L=2 | L=4 | L=6 | L=9 |
|---|---|---|---|---|
| A_off legit VALID-latency p99, ms (mean) | 2.10 | 3.14 | 3.30 | 3.45 |
| A_on legit VALID-latency p99, ms (mean) | 1.38 | 2.57 | 2.75 | 2.45 |
| B_off receiver loop cost, ms/msg (mean) | L=2 not recorded in the Update 21 export | 0.238 | 0.241 | 0.240 |
| C_off receiver loop cost, ms/msg (mean) | L=2 not recorded in the Update 21 export | 0.245 | 0.241 | 0.238 |
| B_off measured attacker send rate, msg/s (mean) | 4165 | 4165 | 4095 | 4072 |
| B_on measured attacker send rate, msg/s (mean) | 4164 | 4102 | 4045 | 4034 |
| C_off measured attacker send rate, msg/s (mean) | 4203 | 4038 | 4086 | 4117 |
| C_on measured attacker send rate, msg/s (mean) | 4194 | 4008 | 4057 | 4012 |
| D_off measured attacker send rate, msg/s (mean) | 805 | 881 | 809 | 881 |
| D_on measured attacker send rate, msg/s (mean) | 778 | 875 | 861 | 864 |
| UNPARSED `stop_reason` (attacker-bearing trials) | 15/450 (3.3%) | 5/180 (2.8%) | 7/180 (3.9%) | 9/180 (5.0%) |
| clock steps inside trials' messaging windows (trials with ≥1 step) | 552 (552/600) | 215 (215/240) | 10 (10/240) | 144 (144/240) |
| trials with a late/dropped legit message (events) | 6 | 3 | 0 | 5 |
| events per exposed clock step (Wilson 95% CI) | 1.09% (0.50-2.35%) | 1.40% (0.48-4.02%) | 0/10 (no information) | 3.47% (1.49-7.87%) |
| legit late msgs per event (mean; range) | 1.2; 1-2 | 2.0; 2-2 | n/a | 4.4; 2-6 |

### What deviated: every late or dropped legit message is a wall-clock step, not a delay (corrected 2026-09-19)

An earlier version of this section called these a shared ~0.4-0.75 s "stall" and attributed them to a host/VM scheduling pause, describing
the `STALE` drops as the filter dropping messages that "sat" 0.4-0.6 s. **That was wrong** (CORRECTIONS.md #21). Cross-checking each event's
wall-clock time against the resource sampler and the system journal shows they are forward steps of the machine's wall clock.

- **Every event coincides with a clock step.** All 17 events (the 14 full-run trials plus the 3 pilot ones) fall within ±0.5 s (the resolution of the 1-second
  send timestamp) of a `systemd-resolved: Clock change detected` journal entry. For a random moment inside a trial the chance of landing that close to an entry is 1.7-2.9% (Update 21 boot / sweep boot); all 17 by chance: ~10⁻²⁹.
- **The size of the step equals the "latency".** Each journal entry carries a realtime and a monotonic timestamp, so the step size is the jump in their
  difference. At the matched entry it equals the event's late-message latency to within 0-2 ms (mean −1.0 ms, SD 0.6 ms) in all 17 cases (table).
- **The steps are periodic and always forward.** Between entries: 32.25 s (SD 0.02 s); 100% of the 1,157 steps in the two run windows were
  forward, +565 ms (sweep) to +627 ms (Update 21) on average. The cadence and size (typically 0.4-0.75 s; 81% of Update 21's and 98% of the sweep's 32-s steps) fit `systemd-timesyncd`
  (enabled, NTP=yes, default 32 s minimum poll, stepping rather than slewing for offsets above ~0.4 s), but the journal names only `systemd-resolved`
  (the detector), so attributing the steps to timesyncd is an inference.
- **Why a step looks like a delay.** The receiver's latency and the filter's `STALE` test are both `received_time − send_ts`, and both read
  `system_clock` (sender and receiver are two processes on the same machine). A forward step makes every message that was sent before it and
  received after it look 0.4-0.75 s old. Only messages in flight at that instant are affected (a millisecond or so of each 100 ms tick), which is why
  it hits ~1-3% of trials rather than all of them, why the affected messages share one latency (within ~1 ms), and why more vehicles
  means more messages hit. The cluster sizes below include attacker messages in the B/C/D cells; the legit-only counts are in the last two columns.
- **No relation to load, memory or kernel scheduling.** Sampler load1 at the events was at the 45th percentile on average (median 36th; 1 of 17 at or above the 90th),
  memory 771-911 MB, swap 0. The kernel journal has no scheduling warnings (`vmstat_shepherd`, "hogged CPU", lockups, RCU) in either boot; the
  only kernel lines during the runs are WSL's `drop_caches` messages, the nearest 92 s from any event.

| Event | Wall-clock time (CDT) | Late-message latency (ms) | Clock offset jump at the matched `Clock change detected` entry (ms) | Entry time minus event time (s)¹ | Messages in cluster (all senders) | Legit late msgs | Legit `STALE` drops |
|---|---|---|---|---|---|---|---|
| L=2 B_off #53 | 09-18 03:39:24 | 527.3 | +527 | -0.45 | 3 | 1 | 0 |
| L=2 B_on #15 | 09-18 04:02:18 | 495.9 | +496 | +0.10 | 3 | 1 | 1 |
| L=2 C_off #24 | 09-18 04:54:14 | 597.3 | +597 | -0.43 | 2 | 1 | 0 |
| L=2 D_off #46 | 09-18 06:40:45 | 737.9 | +737 | +0.11 | 2 | 2 | 0 |
| L=2 D_on #13 | 09-18 07:07:05 | 602.6 | +601 | +0.08 | 1 | 1 | 0 |
| L=2 D_on #47 | 09-18 07:27:49 | 467.8 | +467 | -0.39 | 1 | 1 | 1 |
| L=4 B_off #1 | 09-19 01:45:05 | 442.5 | +442 | -0.33 | 6 | 2 | 0 |
| L=4 B_on #9 | 09-19 02:09:09 | 584.7 | +584 | -0.47 | 3 | 2 | 1 |
| L=4 D_off #12 | 09-19 03:07:31 | 721.8 | +721 | -0.01 | 2 | 2 | 0 |
| L=9 A_off #10 | 09-19 06:57:06 | 508.8 | +507 | -0.08 | 2 | 2 | 0 |
| L=9 A_off #20 | 09-19 07:01:59 | 478.6 | +476 | +0.43 | 6 | 6 | 0 |
| L=9 B_off #2 | 09-19 07:24:24 | 532.9 | +531 | -0.18 | 9 | 5 | 0 |
| L=9 B_on #18 | 09-19 07:53:24 | 586.6 | +586 | +0.16 | 7 | 5 | 4 |
| L=9 C_on #7 | 09-19 08:23:55 | 403.4 | +403 | +0.20 | 6 | 4 | 3 |
| L=4 B_on #5 (pilot) | 09-19 01:00:22 | 527.4 | +526 | -0.21 | 2 | 1 | 1 |
| L=4 D_on #3 (pilot) | 09-19 01:11:33 | 559.4 | +558 | -0.12 | 1 | 1 | 0 |
| L=6 A_on #3 (pilot) | 09-19 03:43:25 | 508.2 | +507 | -0.30 | 5 | 5 | 4 |

¹ The event's wall-clock time is only known to ±0.5 s (send timestamp truncated to seconds), so this column is +/-0.5 s by construction.

**When the stepping was active.** The journal shows the 32.25 s regime running continuously for the whole Update 21 run (2026-09-18 00:31-07:33)
and, in the sweep boot, in blocks: on 23:17-01:37, 01:40-04:09 and 06:49-08:22, **off 04:09-06:49 while the sweep was still running**. Hence exposure differs by
level: 552/600 (92%) of Update 21's trials, 215/240 (90%) at L=4, **10/240 (4%) at L=6** and 144/240 (60%) at L=9 had at least one step inside their messaging window.

**Not established.** Why the guest clock falls behind by 0.4-0.75 s per 32 s in multi-hour blocks. It was not reproducible afterwards: idle, a 3-process CPU
load and one real simulator trial (all run while the regime was off) showed no drift against the Windows host clock and no `Clock change` entries, and the Windows System
event log has no power or sleep events at any transition. It does not appear to be caused by this project's workload, since it toggled independently of it (off for 2 h 40 min mid-sweep, on before the sweep started). See `context/BUGS.md`
for the recurrence guidance.

### Measured attacker rates, and two between-level differences to keep in mind

- Rates below are **measured** (receiver `attacker_total` ÷ the attacker's own send time), not the
  startup-constant `achieved_rate_per_sec` (CORRECTIONS.md #20). B/C run at ~4,000-4,200 msg/s at
  every level, drifting down about 2-4% from L=2 to L=9. D runs at 778-805 msg/s (D_on to D_off means) at L=2, 875-881 at L=4, 809-861 at L=6 and 864-881 at
  L=9: higher at L=4 and L=9 than at L=2, i.e. up to ~10% more D volume at some levels
  (`attacker_total` ≈ 23,935 at L=2 vs ≈ 26,455 at L=4/26,369 at L=9). All stayed inside the
  gate's ±15% band and below the 1010/s cap; the cheap-reject fractions did not move with it.
- **The attacker's trace file changes with level** (`trace_files/<numVehicles>.csv`): stationary
  100,000-row files at L=2 and L=9, but a *moving* 2,299-row trace at L=4 and L=6 (wraps ~55× for
  B/C, ~10× for D; the wrap is harmless per `generate_bsm`'s existing comment). BSM content does not
  feed the metrics and L=4/6 look the same as L=2/9, but it is a difference between levels.
- UNPARSED `stop_reason` (whole `[AttackerRunSummary]` line lost to the transmitter's unsynchronized
  `std::cout`, CORRECTIONS.md #19): 15/450 (3.3%) at L=2, 5/180 (2.8%), 7/180 (3.9%), 9/180 (5.0%)
  at L=4/6/9. Not statistically distinguishable from the 3.3% baseline. Per the corrected criterion,
  an UNPARSED trial was **not** treated as a failure by itself; each was cross-checked (no
  `[AttackerBackstopFired]`, `attacker_total` not ~2× the reference) and logged as
  probable-completion. They are counted, not folded into "completion".

### Pilots (N=5/cell, gated before each full run)

All three pilots passed every gate (as-run verdicts PASS). Notable: L=6 pilot `A_on` trial 3 (no
attacker) was hit by a clock step (4 `STALE` drops, 5 late messages), so these artifacts are not unique
to L=9 or to attacker cells; the L=4 pilot had two small ones (B_on trial 5, D_on trial 3); all three are in the table above. The A-cell rule (stop above 1%
per trial or 0.2% cell mean) never came close; the largest A-cell trial was 6/2,700 = 0.22%.

### As-run verdict vs corrected verdict (one false positive in my gate)

The driver completed all three levels but **exited in REVIEW state (rc=3)**: at L=9 its gate
reported one hard failure, `C_on trial 13: stop_reason=compl`. **That was a defect in my parser,
not a real failure.** The raw line is
`[AttackerRunSummary] vehicle=9 stop_reason=compl mess backstop_duration_ms=60000 actual_elapsed_ms=30273.3 messages_sent=121107 ... completion_lag_ms=0.011877`:
the word `completion` was cut by an interleaved `mess…` from a legit vehicle's `[FalconSignCost]`
line (the same stdout race as #19), and my regex accepted any partial word as a stop reason.
Independent evidence the trial ended normally: `completion_lag_ms` is only printed on a
completion stop, there is no `[AttackerBackstopFired]`, elapsed was 30.27 s (a backstop stop
would be ~60 s), `attacker_total` 121,107 is in range, driver exit codes were 0/0, and every
receiver-side number is clean (2,691/2,700 VALID, 0 drops, 0 late). I fixed the parser to accept
only `completion`/`backstop_timeout` (anything else is UNPARSED and goes through the same
cross-checks), added self-test cases for a truncated word (must be probable-completion) and a
real `backstop_timeout` (must still stop), and the gate self-test is 21/21. The driver's as-run
outputs (`n*/full/gate_*.txt`, `per_trial.csv`, its REVIEW verdict, `STOP_REPORT.txt`) are
**left as they were**; the corrected re-parse of all 720 trials (read from the compressed logs) is in
`phase4_raw_logs/phase4_vehicle_scaling_sweep/reanalysis/` and is what the tables above use:
0 hard failures at all three levels. Nothing else changed classification.

### Resource contention: none, and none that scales with vehicle count

Sampled every ~15 s for the whole ~8.5 h (`/proc/loadavg`, `free -m`; `nproc=28`, 15,841 MB RAM).
Mean 1-minute load while trials ran: 0.68 (L=4), 0.72 (L=6), 0.69 (L=9); p95 ≤ 1.6, peak 1.96;
used memory peaked at 848 / 896 / 901 MB; swap 0 throughout. It did **not** climb with vehicle
count. Trials flagged or deviating had a slightly higher mean peak load than clean ones (0.85 vs
0.70), but that "deviating" group includes UNPARSED-flagged trials and every value is far below
28 cores, and load1 at the 17 late-message events averaged the 45th percentile of all samples (1 of 17 at or above the 90th),
so there is no sign the events coincide with load; they are clock steps (see "What deviated").

### Method notes and safeguards added

- WSL restarted at ~23:13 on 2026-09-18 and reset `net.core.rmem_max` to 212992 (it silently
  clamps the receiver's 32 MiB `SO_RCVBUF`, with no error and possibly no visible symptom). This
  sweep therefore re-read `rmem_max` **before every trial** and required the receiver's own
  `[SocketConfig] ... actual=67108864` line in every log (hard failure otherwise). All 840
  receive logs (pilot + full) carry 67108864, and Update 21's 600 do too.
- Gates that were never triggered in the real run (so only the self-test evidence covers them):
  clamped buffer, backstop marker, attacker_total ~2× reference, INCOMPLETE RUN, D rate out of
  bounds, UNPARSED rate > 15%.
- Every trial's raw logs are kept, gzip-compressed and integrity-checked, in
  `phase4_raw_logs/phase4_vehicle_scaling_sweep/n{4,6,9}/{pilot,full}/` (gitignored).

### Explicit confirmations
- Update 15/20/21 **data** is untouched; nothing here re-runs or reinterprets those trials.
  Update 21's *text* changed only by the #19 (`stop_reason`), #20 (send rate) and #21 (clock-step
  artifacts, footnote ³) wording corrections; no Update 21 number changed.
- `phase4_run_trials.sh`, `phase4_sweep_params.sh`, `phase4_pilot_cheap_invalid.sh` and
  `phase4_run_trials_match_duration.sh` were not touched or run for this sweep (mtimes unchanged).
- No source change and no rebuild: the binary is the one Update 21 used.
- New (gitignored) tooling: `phase4_vehicle_scaling_sweep.sh`, `phase4_vehicle_scaling_aggregate.py`,
  `phase4_vehicle_scaling_resources.py`, `selftest_vehicle_scaling_gates.py`; the Update 21
  aggregator gained CSV export earlier (`--csv-per-trial/--csv-summary`).
- `config.json` restored to its baseline by the driver's exit trap (verified byte-identical).

### Config
`config.json` restored to production defaults after the run, matching every prior Update's convention.

## Update 23

## Per-message verification timing + verify-once mode (Fig. 3 version B) for the segmentation study — STATUS: COMPLETE (implemented, smoke-tested, grid run 2026-09-25 16:21–19:49, all 116 combos PASS)

**Scope change (2026-09-25).** The paper is now only about how certificate segmentation (m segment-carrying +
n hash-only messages per cycle) affects verification timing, using A_off (no attacker, filter off). Under A_off
the counts are fully predictable (valid = L·(numMessages+1−m), NO_CERT_YET = L·(m−1)), so **the timing data is the
result**. Until now the receiver kept per-call timings only in memory and printed avg/p95/max per trial. This Update
adds per-message timing CSVs, a verify-once mode, and the aggregation/sweep plumbing for them. No sweep was run.

### What was added (all opt-in; defaults reproduce the old behavior and counts)
- **Per-message probes** (env `PQV2V_TIMING_PREFIX=<path prefix>`; unset = nothing recorded, output unchanged).
  steady_clock ns relative to a reference captured at `receive()` start:
  - **t0**: right after `recvfrom` returns (Falcon `read_frame`), before any parsing, for every message.
  - **t1**: right after `ccons_falcon` succeeds (reassembly + 8-byte full-hash match). Only on the message that
    completes a cycle's m segments. **Filter-off rebuilds the cert every cycle**, so t1 appears once per cycle
    per sender, not only the first time.
  - **t2**: right after the cert `falcon_verify` (VERIFIED_NOW rows only).
  - **t3**: right after the message `falcon_verify` and outcome classification.
  - `cert_verify_ns` and `msg_verify_ns` time only the two `falcon_verify` calls. They reuse the existing
    steady_clock brackets, which already fed `falcon_{cert,message}_verify_times_ms`.
  - Output `<prefix>_msgtiming.csv`:
    `sender_id,seq,kind,outcome,cert_path,t0_ns,t1_ns,t2_ns,t3_ns,cert_verify_ns,msg_verify_ns` (NA where undefined).
  - Output `<prefix>_ttfv.csv`:
    `sender_id,first_t0_ns,t1_ns,first_valid_t3_ns,ttfv_ms,n_unverifiable_before_first_valid`.
  - Transmitter output `<prefix>_sendtimes.csv`: `sender_id,seq,send_ns`, legit vehicles only, absolute steady
    time taken just before `sendto`, one vector per vehicle, written after the threads join.
  - Buffer: the receiver reserves `num_msgs + 1024` rows. `num_msgs` is already the grand total L·numMessages
    (`main.cpp`). Open-ended attack runs reserve `+400000`. The receiver logs
    `[TimingBuffer] rows= reserved= reallocated=0|1`, and no smoke trial reallocated.
  - The receiver is single-threaded, so one buffer is safe. No file I/O happens until the loop ends.
- **NO_CERT_YET rows record what actually ran.** On the filter-off path, the message `falcon_verify` runs even when
  no cert is held. Those rows therefore have t3 and msg_verify_ns, and NA for t1, t2 and cert_verify_ns
  (cert_path = NA).
- **Receiver summary** gains 4 lines (nothing above them changed): `wall_clock_step=0|1`,
  `receiver_steady_ref_ns=<abs>` (the reference for the send_ns join), `cert_verify_mode=every|once`, and
  `cert_verified_set_size=<n>`.
- **Clock guard:** `wall_clock_step=1` when the steady and system elapsed times over the receive run differ by more
  than 100 ms. It flags the trial and never drops it.
- **Quieter logs when probes are on:** the receiver's per-message `[FalconCertCycle]` RX / "Reconstructed cert OK" /
  DROP stdout lines are suppressed only when `PQV2V_TIMING_PREFIX` is set. They sat inside the t0–t3 window and no
  harness parses them; the aggregators read the transmitter's TX lines. The rare seg-hash-mismatch and
  reconstruction-failed lines stay.
- **Verify-once mode** (env `PQV2V_CERT_VERIFY_MODE=every|once`, default `every`, filter-off path only):
  - A cert whose full SHA-256 digest is in `falcon_verified_cert_digests` skips the cert `falcon_verify`. Those rows
    get cert_path = CACHED, t2 = NA and cert_verify_ns = NA.
  - The set is filled only after a cert verify succeeds (VERIFIED_NOW).
  - The digest is the one `ccons_falcon` already computes: its 8-byte check is the first 8 bytes of the same
    in-process OpenSSL SHA-256. A new optional `full_digest_out` parameter hands the full 32 bytes back, so no
    second hash runs. Filter-on callers pass nothing.
  - t1 is stamped immediately after `ccons_falcon` returns in both modes. The only once-mode cost inside
    t0..t3 is a `std::set` lookup at the cert-verify site, which lands in overhead_ns.
  - **"once" is a testbed switch, not a protocol change.** Nothing changes on the wire, in config.json, in the
    STALE/100 ms logic or on the filter-on path.

### What Fig. 3 means vs. what the testbed does (read before writing about Fig. 3)
- The testbed stores the rebuilt cert per **plaintext `vehicle_id`**: the first byte of `falcon_spdu`, sent in the
  clear and unauthenticated. That's also how every message, NO_CERT_YET included, gets a sender_id; no validated
  state is involved. On the filter-off path, a hash-only message's `full_hash` is **never compared** to the stored
  cert. Fig. 3's "sender cert held?" lookup by hash is the protocol design, not what the testbed does.
- The cert is verified on **every message, segment or hash-only**, against whatever entry is stored for that
  sender. It is not verified once per reconstruction. That's why the verify-once check sits at the cert-verify
  site, keyed on the stored entry's digest.
- The cert-verify key is loaded from disk by sender_id (`load_falcon_key`, called on every message); it isn't taken
  from the cert. The message verify runs even when no cert is held.
- The verified set is keyed on the digest alone, so it can't tell senders apart. That's fine under A_off, where
  each sender has one cert.

### Metric framing for the paper
- **Primary metrics: `cert_verify_ns` and `msg_verify_ns`**, the pure crypto cost.
- `t3−t0` is end-to-end receive-path time including testbed overhead. The aggregator also reports
  `overhead_ns = (t3−t0) − cert_verify_ns − msg_verify_ns`, counting NA cert as 0.
- t0→t2 includes `load_falcon_key`, which reads and hex-decodes a key file on every message, plus bookkeeping.
- t3−t0 excludes time spent queued in the socket buffer. The send→t3 join covers that.
- **Verify costs here are cold-core costs.** Every-mode A_off median msg_verify is about 75–92 µs and cert verify
  about 81–92 µs. The machine was idle (load 0.1, 99.8% idle, 28 cores), and repeat runs gave the same numbers.
- The old m×n sweep's A_off trials show the same 0.067–0.086 ms averages, so nothing drifted. The ~0.015–0.046 ms
  figures in older logs are **attack-cell numbers**: under flood the receiver core never idles (B_off
  ~0.044 ms), and in C_off invalid signatures are rejected early (message verify ~0.014 ms).
- Legit traffic arrives about every 17 ms at L=6, so the core idles between messages. Don't compare A_off verify
  costs with flood-cell verify costs as if they were the same quantity.

### Harness changes
- `phase4_mn_sweep.sh`:
  - New variables `SWEEP_L` (6), `SWEEP_NUM_MSGS` (300), `SWEEP_CELLS` (all 8) and `SWEEP_CERT_VERIFY_MODE`
    (every). With the defaults, behavior is unchanged. Otherwise ROOT becomes
    `phase4_raw_logs/phase4_seg_sweep/L<L>_msgs<N>[_verifyonce]`, one gate runs over SWEEP_CELLS, there's no
    m2_n4 regression gate, and exports are named `exports/seg_sweep_L<L>_msgs<N>[_verifyonce]_*.csv`.
  - Each trial exports `PQV2V_TIMING_PREFIX` and `PQV2V_CERT_VERIFY_MODE`. Timing CSVs are gzipped and
    `gzip -t`-checked like the logs.
  - **Resume rule:** a combo is skipped only if `summary.csv` exists and every trial has `_msgtiming` and
    `_ttfv` (plus `_sendtimes` for A_* cells) with a matching `cert_verify_mode=` line. Trials from before this
    Update, or in the other mode, are rerun.
  - **Coarse-first order:** n ∈ `SWEEP_COARSE_N` (default 0 2 4 6) first, with m2_n4 first when it's present.
- New `phase4_seg_grid.sh` (**not run**):
  - Settings: A_off, numMessages=200, N=5, verify-once.
  - Pass 1: n ∈ {0,2,4,6} × m ∈ {2..5}. Pass 2: n ∈ {1,3,5}. Each pass runs for L = 6, 4, 3, 5.
  - Optional pass 3 (`SEG_GRID_PASS3=1`): every mode at L=6, m ∈ {2,5} × n ∈ {0,4}, as the A-vs-B reference.
  - It has an NTP preflight and is safe to rerun.
- `phase4_vehicle_scaling_aggregate.py` (the gate): `--msgs-per-vehicle` (default 300).
- `phase4_mn_sweep_aggregate.py`:
  - New options `--msgs-per-vehicle` and `--cells`. The prediction is L·(msgs+1−m), identical at the defaults.
  - Per-combo timing columns are appended after the existing ones:
    - mean / median / p95 / p99 / max for cert_verify_ns, msg_verify_ns, t1−t0, t2−t0, t3−t0, overhead_ns and
      send→t3, split by kind, first cycle vs steady state, and (for t3−t0, msg_verify and overhead) cert_path;
    - fractions of t3−t0 and of send→t3 above 100 ms;
    - ttfv mean/min/max and the `n_unverifiable == m−1` check;
    - `msg_verify_ns_median`, a drift check across the sweep that should not depend on m or n, and is also a
      report pivot;
    - `cert_verify_mode`, `verified_now_rows`, `wall_clock_step_trials` (excluded from timing stats),
      `sendjoin_skipped_trials`, and `cert_verify_count_check` (once: == L; every: == predicted VALID; A_off only).
  - In once mode, cert_verify_ns and t2−t0 are reported **pooled** across the run
    (`<summary>_pooled_cert_verify.csv`), because there are only L rows per trial.
  - **send→t3 join guard:** seq is the receiver's arrival index, so a trial is left out of send→t3 whenever any
    sender's receiver row count differs from its sendtimes row count.
  - `--ab-reference <every-mode root>` writes `<summary>_ab_check.csv` with each combo's median t3−t0 (every
    and once), their difference, and the ratio of that difference to the every-mode median cert_verify.
    Rows with a ratio outside [0.5, 1.5] are flagged WARN, which never fails the run.
  - Missing timing files give NA.
  - Fixed: n=0 (no hash-only frames) previously made every segment line count as "garbled" in the wire-byte parse.
- A bug caught in the smoke test: receiver logs can contain stray binary bytes, so `grep` suppressed the
  `cert_verify_mode=` line and the resume rule reran complete combos. Fixed with `grep -a`.

### Smoke-test results (2026-09-25; scratchpad outputs, not kept in the repo)
- **Every mode reproduces the baseline counts exactly.** Pre-change baselines: 1794/6/1794 at L=6/m2/n4/300 msgs;
  1194/6/1194, 597/3/597 and 1176/24/1176 at 200 msgs (L6m2n4, L3m2n0, L6m5n6). The numbers are valid /
  NO_CERT_YET / cert verifications.
- **Once mode:** valid and NO_CERT_YET are unchanged, the cert-verify count equals L in every trial (6 / 3 / 6),
  and `cert_verified_set_size` equals L.
- **All 19 hand-run timed trials pass the CSV checks** (plus the 6 driver-smoke trials, which passed their gates):
  - exactly numMessages rows per sender, and msgtiming rows == sendtimes rows per sender;
  - t0 ≤ t1 ≤ t2 ≤ t3 on every row;
  - n_unverifiable_before_first_valid = m−1;
  - once mode: exactly one VERIFIED_NOW per sender, all other verified rows CACHED;
  - no buffer reallocation.
- **Medians (single trials; numbers vary trial to trial):**

  | Trial | t3−t0 | msg_verify | cert_verify | ttfv |
  |---|---|---|---|---|
  | once L3 m2 n0 | 239 µs | 88 µs | 140 µs (pooled, n=3) | 102.7 ms |
  | once L6 m5 n6 | 236 µs | 92 µs | 73 µs (n=6) | 403 ms |
  | every L6 m2 n4 | 282–308 µs | 75–90 µs | 81–90 µs | ~102 ms |

  - ttfv ≈ (m−1)·100 ms + 1–4 ms.
  - t1−t0 is 120–150 µs in both modes (reusing the digest added nothing measurable).
  - send→t3 median is about 0.6–0.9 ms.
- **A-vs-B check (L6 m2 n4, 4 clean every-mode and 3 clean once-mode trials):** the median t3−t0 difference is
  62.4 µs against an every-mode median cert_verify of 89.6 µs, a ratio of 0.70 (OK).
- **Driver smoke** with the real, unmodified driver: `SWEEP_ROOT` in the scratchpad, L=3, 200 msgs, A_off, N=1,
  once mode, combos `2:1 2:0`.
  - The order ran as 2:0 then 2:1.
  - Gate PASS and the prediction check PASS (including cert-verify == L).
  - Logs and timing CSVs were gzipped and verified; `config.json` was restored byte-identical.
  - An identical rerun skipped both combos.
  - Deleting one `_ttfv.csv.gz` reran only that combo.
  - Switching to every mode reran both.
  - The default ROOT and export names are separate per mode.
- **Environment:** `net.core.rmem_max` had reset to 212992 after a WSL restart. The gate correctly hard-failed a
  clamped-buffer trial until the user ran `sudo sysctl -w net.core.rmem_max=33554432`. After that, receivers
  showed `actual=67108864` as in every earlier sweep.

### Clock steps with NTP off (open)
The user ran `sudo timedatectl set-ntp false` at 15:47:38; `systemd-timesyncd` stopped.
- Before that, `Clock change detected` entries came about every 34 s, and a 40 s probe measured a +1.86 s step.
  About half of the NTP-on smoke trials flagged `wall_clock_step=1`.
- After it, one step still happened, at 15:49:30, and it hit one driver-smoke trial. There were no further steps
  through at least 15:55. A 1 Hz realtime-vs-monotonic logger saw none from 15:50 on, and all 4 later NTP-off
  repetitions were clean.
- So NTP-off makes steps much rarer but does **not** remove them. The Hyper-V host time sync
  (`hv_utils.timesync_implicit=1`) is the likely remaining source (see BUGS.md).
- The per-trial `wall_clock_step` flag and its exclusion from the timing stats are the safeguard. The t0–t3 and
  verify timings use steady_clock and are unaffected either way.
- **Undo after the grid run with `sudo timedatectl set-ntp true`.** Unlike rmem_max, the NTP setting persists
  across WSL restarts.

### Clock-step trials are soft warnings, never stops (gate change, 2026-09-25)
**Before this change, a wall-clock step could abort the driver.** The per-combo gate has two A-cell STOP rules:
a trial whose deadline-miss or drop fraction exceeds 1% (`A_TRIAL_STOP`), and a cell mean above 0.2%
(`A_MEAN_STOP`). Both are system-clock differences. A forward step turns every message in flight into a deadline
miss, and under the filter into a `STALE` drop. Either STOP made the driver `stop_run` (exit 2). Under A_off only
the few messages in flight at the instant are affected, so this was unlikely but possible, most easily at small L
(1% of 600 messages is 6).

Everything else was already soft:
- The prediction check only marks a combo REVIEW (exit 3), and the driver continues.
- The resume rule looks only at timing files and mode.
- The resume rerun list (`--bad-trials`) only includes hard failures: missing log, clamped socket, lost
  messages, non-zero exit code.
- The cert-verify count check can't be moved by a clock step: under A_off the count doesn't depend on time.

**Changes:**
- `phase4_vehicle_scaling_aggregate.py`:
  - `parse_recv` reads the receiver's `wall_clock_step=` line.
  - In an A cell, a trial flagged `wall_clock_step=1` that exceeds 1% becomes a
    `SOFT_WALL_CLOCK_STEP` flag, not an immediate STOP.
  - The 0.2% cell-mean STOP test excludes flagged trials. If the mean exceeds 0.2% only when they're included,
    that's also a soft flag.
  - The reported means still include every trial.
  - The gate summary gains `wall_clock_step_trials`.
  - Logs without the line (everything before Update 23) behave exactly as before.
- `phase4_mn_sweep_aggregate.py`:
  - The VALID / NO_CERT_YET deviation test uses only unflagged trials.
  - Flagged trials are reported in two new summary columns, `clock_step_trials` and
    `clock_step_trials_valid_ne_pred`, plus a `WARNING (soft, not a deviation)` line in the per-combo check.
  - Flagged trials never produce a DEVIATION or REVIEW.
- `phase4_mn_sweep.sh` copies those warning lines into `events.log` as `SOFT_WARNING`.

**Tested** by editing a real L=3 trial's summary to 8 drops, 10 deadline misses (1.67%) and VALID 589 (predicted
597):
- **Flagged `wall_clock_step=1`:** gate exit 0 (PASS, 3 soft flags), prediction check exit 0 (WARNING only), and
  the real driver completes the combo with exit 0. `SOFT_WARNING` is in `events.log`; `clock_step_trials=1`,
  `clock_step_trials_valid_ne_pred=1` and an empty `deviation_label` are in the combo summary. A rerun skipped
  the combo.
- **Identical numbers with `wall_clock_step=0`:** gate exit 2 (STOP), and the driver aborts with exit 2. Strict
  behavior is unchanged for trials without a clock step.

A real delay that happens to coincide with a flagged step is now only a soft warning, not a stop. That's the
intended trade-off; the flagged trials stay listed in the per-trial CSV and the message file for inspection.

### Post-grid merge (`phase4_seg_postgrid.py`)
Run after the grid: `python3 scripts/phase4_harness/phase4_seg_postgrid.py`. The defaults are grid root
`phase4_raw_logs/phase4_seg_sweep` and output `exports/seg_grid/`. It finds every `L<L>_msgs<N>[_verifyonce]`
run and writes:
- `seg_grid_summary.csv`: every aggregator summary column plus `L`, `cert_verify_mode`, `msgs_per_vehicle`,
  `run_dir`.
- `seg_grid_messages.csv.gz`: one row per received message across all runs and trials, with L, mode, m, n, tau,
  cell, trial, `wall_clock_step`, sender, seq, first/steady phase, kind, outcome, cert_path, t0–t3, both
  verify_ns, t1−t0, t2−t0, t3−t0, overhead_ns, send_ns, send→t3 and `sendjoin_ok`. Clock-step trials are kept
  and flagged.
- `seg_grid_pooled_cert_verify.csv`: per mode, over all L and per L.
- `seg_grid_ab_check.csv`: every L that has both modes.
- `data_dictionary.md`: every column with its unit, generated from the actual headers. The script warns if a
  summary column has no description.

It reuses the aggregator's functions; `write_ab_check` was split into `ab_rows` / `ab_lines`, with identical
output. **Tested on today's smoke outputs**, arranged as L3 and L6 in both modes, including a combo with no timing
files and a gzipped driver root:
- 7 summary rows × 272 columns and 19,800 message rows from 19 trials, with the one trial lacking timing files
  counted separately;
- every derived column is consistent on every row;
- cert_path counts match (once mode: one VERIFIED_NOW per sender per trial);
- `cert_verify_count_check` PASS on all 7 rows;
- every-vs-once ratio 1.24 (L3 m2 n0) and 0.70 (L6 m2 n4), both OK;
- it runs in about 1 s.

### Grid results (2026-09-25)
**Run.** `SEG_GRID_PASS3=1 bash scripts/phase4_harness/phase4_seg_grid.sh`, launched in the background with
`nohup setsid`, logging to `logs/seg_grid.log`. It started at 16:21:53 CDT and finished at 19:49 (about 3.5 h,
~107 s per combo).
- Pre-launch checks: `rmem_max=33554432`, NTP off, no WSL restart since 12:57.
- Coverage: A_off, numMessages=200, N=5:
  - passes 1+2 in verify-once mode, m ∈ {2..5} × n ∈ {0..6} × L ∈ {3,4,5,6} (112 combos);
  - pass 3 in every mode, L=6, m ∈ {2,5} × n ∈ {0,4} (4 combos).
- Totals: 116 combos, 580 trials, 528,000 message rows.
- Raw logs are in `phase4_raw_logs/phase4_seg_sweep/`. The merged outputs (`phase4_seg_postgrid.py`) are in
  `exports/seg_grid/`: `seg_grid_summary.csv` (116 × 274), `seg_grid_messages.csv.gz`,
  `seg_grid_pooled_cert_verify.csv`, `seg_grid_ab_check.csv` and `data_dictionary.md`.

**Run health.**
- All 9 driver invocations exited 0; every combo's gate and prediction check passed.
- No STOP, soft warning or deviation. No WSL restart or rmem reset during the run, and `config.json` was
  restored.
- `cert_verify_count_check` (once mode: L per trial) and `ttfv_unverifiable_check` (m−1) both PASS on all 116.
- **0 of 580 trials flagged `wall_clock_step`**, the first full run with NTP off, so every combo has all 5 trials
  clean. The send→t3 join succeeded in every trial (0 skipped).
- No message exceeded 100 ms, either for t3−t0 or for send→t3.

**Findings.** These are descriptive ranges of per-combo medians, with no formal test.
1. **Time-to-first-verified grows by 100 ms per extra segment and doesn't depend on n or L.** It is
   (m−1)·100 ms, the BSM interval, plus ~1.5–4.5 ms:

   | m | Mean ttfv | Range across combos |
   |---|---|---|
   | 2 | 101.6 ms | 99.4–104.6 ms |
   | 3 | 202.7 ms | 201.0–207.5 ms |
   | 4 | 303.7 ms | 301.8–319.5 ms |
   | 5 | 404.6 ms | 402.4–414.4 ms |

   This is the dominant segmentation cost at the receiver.
2. **Per-message verify cost doesn't depend on m or n.** Median `msg_verify_ns` per combo is 69.7–98.5 µs
   (median of medians 82.2 µs), with no trend in m, n or L. That makes it a usable drift check across the 3.5 h
   run. Pooled cert verify: every mode median 82.3 µs, p99 256.6 µs (n=23,700); once mode median 85.9 µs,
   p99 269.8 µs (n=2,520).
3. **End-to-end receive-path time is flat.** Median t3−t0 per combo is about 180–256 µs, with ranges that overlap
   across every m, n and L. Median send→t3 rises slightly with L: 0.43–0.57 ms at L=3 and 0.54–0.81 ms at L=6.
4. **n only trades frame size.** Mean wire bytes per message fall from 1183–1672 B at n=0 to 1001–1052 B at n=6.
   In filter-off A_off, n changes nothing about verification.
5. **Every-vs-once (A-vs-B) check, L=6:**

   | Combo | t3−t0 every → once | Saving | Every-mode cert verify | Ratio |
   |---|---|---|---|---|
   | m2_n0 | 274.6 → 208.9 µs | 65.7 µs | 80.6 µs | 0.82 |
   | m2_n4 | 281.6 → 220.2 µs | 61.4 µs | 82.6 µs | 0.74 |
   | m5_n0 | 310.1 → 241.1 µs | 69.0 µs | 89.7 µs | 0.77 |
   | m5_n4 | 276.0 → 231.2 µs | 44.9 µs | 81.4 µs | 0.55 |

   All four are OK (inside 0.5–1.5). **All four are below 1**, though: verify-once saves 55–82% of a median cert
   verify per message, not the whole amount. The per-verify cost is the same in both modes (82.3 vs 85.9 µs
   pooled), so the shortfall is either run-to-run variation between the two separate runs, or a real
   warm-cache/CPU effect of running two verifies per message. This data can't tell which, so don't claim the
   saving equals exactly one cert verify.

**Caveats for the paper.**
- Verify costs are cold-core costs: the receiver idles between legit messages (~17 ms at L=6).
- t3−t0 includes testbed overhead (`load_falcon_key` on every message) and excludes socket queueing; send→t3
  includes it.
- See "What Fig. 3 means vs. what the testbed does" above.
- N=5 per combo supports these descriptive ranges but not tight confidence intervals on per-combo percentiles.

### Not done / next
- **Re-enable NTP** (`sudo timedatectl set-ntp true`). It was turned off for the grid, and the setting persists
  across WSL restarts.
- Any figures and statistics for the paper come from `exports/seg_grid/`. The per-message file keeps a
  `wall_clock_step` column, which is 0 for every trial in this run.
