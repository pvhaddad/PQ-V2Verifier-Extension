# Files Reference

Generated from the actual codebase (`src/`, `include/`), not from `context/UPDATES.md` —
read this when you need to know what a file is for and how it relates to the rest of the
codebase, before opening it. For function-level detail, see `context/FUNCTIONS.md`.

Build composition, confirmed via `CMakeLists.txt`: one executable (`v2verifier`) built
from exactly `src/main.cpp`, `src/Vehicle.cpp`, `src/AttackerVehicle.cpp`,
`src/v2vcrypto.cpp`, `src/bsm.cpp`, linked against OpenSSL (`crypto`) and a static
`liboqs.a`. No other `.cpp`/`.h` files exist in this repo.

## `src/v2vcrypto.cpp` + `include/v2vcrypto.h`

**Purpose:** Thin crypto-primitives wrapper — the only files that touch OpenSSL
ECDSA/SHA-256 and liboqs Falcon-512 APIs directly. Every other file signs, verifies, or
hashes only through these functions. No project-defined structs; pure free functions over
`EC_KEY`/`SHA256_CTX` (OpenSSL) and `OQS_SIG_falcon_512_*` (liboqs).

**Depends on:** OpenSSL, liboqs. **Depended on by:** `Vehicle.cpp` (every sign/verify/hash
call site).

## `src/bsm.cpp` + `include/bsm.h`

**Purpose:** Smallest file in `src/` — pure-math helpers deriving a BSM's kinematic
fields (speed, heading) from two consecutive trace positions, plus the BSM payload struct
and its GUI-forwarding wire format.

**Structs (in `bsm.h`):** `bsm` (latitude/longitude/elevation/speed/heading, all
`float` — the actual signed application content); `packed_bsm_for_gui`
(`__attribute__((packed))`, adds `authenticated`/`on_time`/`elapsed_time`/`vehicle_id` —
sent to an external GUI process over a second UDP socket that doesn't exist in this repo;
no in-repo consumer).

**Depends on:** nothing else in `src/`. **Depended on by:** `Vehicle.cpp`'s
`generate_bsm` (calls the two kinematic functions) and `forward_bsm_to_gui` (packs
`packed_bsm_for_gui`).

## `src/AttackerVehicle.cpp` + `include/AttackerVehicle.h`

**Purpose:** A minimal `Vehicle` subclass that reuses 100% of `Vehicle`'s
socket/transmit/receive machinery and customizes behavior only via three protected
virtual hook overrides — no duplicated loop logic. Extremely small; each override is a
one-line body.

**Class:** `AttackerVehicle : public Vehicle` — private `attack_mode mode`,
`int flood_delay_ms`. Constructor forwards `number` to `Vehicle`'s constructor (an
attacker still loads real keys/certs/trace — it's distinguished by behavior, not key
material) and stores `mode`/`flood_delay_ms`.

**Depends on:** `Vehicle` (base class), `arguments.h`'s `attack_mode` enum. **Depended on
by:** `main.cpp` (the only place it's constructed — `std::make_unique<AttackerVehicle>`,
once per `numAttackers`, IDs starting at `numVehicles`).

## `src/main.cpp`

**Purpose:** CLI entry point and scenario driver. Parses argv + `config.json`, then
either spins up a fleet of transmitter threads (legitimate `Vehicle`s + `AttackerVehicle`s)
or runs a single receiver `Vehicle`.

**Key responsibilities:**
- Parses positional args (`dsrc|cv2x`, `transmitter|receiver`, `tkgui|webgui|nogui`,
  optional `--test`) into a `program_arguments` struct.
- Reads all 12 `config.json` fields (see `arguments.h`'s config table below) via `boost::
  property_tree`, each with a backward-compatible default.
- **Transmitter mode:** builds a `std::vector<std::unique_ptr<Vehicle>>` — plain
  `Vehicle`s first (ids `0..numVehicles-1`), then `AttackerVehicle`s (ids continuing from
  `numVehicles`) — spawns one `std::thread` per vehicle running `Vehicle::transmit_static`,
  joins all threads.
- **Receiver mode:** constructs a single `Vehicle v1(0)` and calls `v1.receive(...)` with
  the total expected message count and every spam-filter/scheme parameter.
- **Update 23:** if env `PQV2V_TIMING_PREFIX` is set, marks legit vehicles `record_send_times`
  and, after every transmitter thread has joined, writes `<prefix>_sendtimes.csv`.

**Depends on:** `Vehicle`, `AttackerVehicle` (constructs both — the sole place either is
instantiated), `arguments.h`. **Depended on by:** nothing (entry point).

## `src/Vehicle.cpp` + `include/Vehicle.h` (the core — 1705 lines / 520-line header)

**Purpose:** The entire `Vehicle` class: key/cert loading, BSM/trace generation, both
ECDSA and Falcon-512 SPDU construction/signing/transmission/reception/verification, the
Falcon certificate-fragmentation/cycle protocol, the Phase 3 spam-filter defense
pipeline, and all built-in benchmarking instrumentation. Templated so one transmit/receive
loop body serves both signature schemes.

**Owns these wire-format structs:**
- `ecdsa_spdu` — always sent whole (`wire_length()` = `sizeof(spdu)`); byte-for-byte
  unchanged since before this project's extensions began (a standing constraint).
- `falcon_spdu` — cert moved *out* of the struct into a separate `cert_cycle`
  (`falcon_cert_cycle_envelope`, from `ieee16092.h`) envelope, which **must stay the
  struct's last field** — `wire_length()` computes actual send size by pointer-address
  truncation into `cert_cycle`, so reordering any field breaks that truncation logic.

**Owns these state structures** (deliberately kept in two separate families so the
filter-OFF and filter-ON code paths can never interfere with each other):
- Phase 1 (naive, filter-OFF): `falcon_cert_reconstruction_state`,
  `falcon_reconstructed_cert_entry` (reconstructed cert stored as **opaque bytes**, never
  a live struct — see `context/UPDATES.md` Update 5 for the dormant-UB reason why).
- Phase 3 (spam filter, filter-ON): `spam_filter_fragment_buffer` (cap = 1 open buffer
  per sender, structurally guaranteed by being keyed in an `unordered_map<uint8_t, ...>`),
  `spam_filter_cert_cache_entry` (holds only cert-sig-verified certs — see
  `context/BUGS.md`'s "Resolved" section for the verified caching gate).

**Per-message timing + verify-once (Update 23), both env-var switches, not config fields:**
`PQV2V_TIMING_PREFIX` turns on the t0–t3 probes (`falcon_timing_record` buffer, reserved up front,
written after the receive loop as `<prefix>_msgtiming.csv` / `<prefix>_ttfv.csv`) and suppresses
the receiver's per-message `[FalconCertCycle]` stdout lines; `PQV2V_CERT_VERIFY_MODE=once` makes the
filter-OFF path skip cert `falcon_verify` for a cert whose full digest is in
`falcon_verified_cert_digests`. The receiver summary always ends with `wall_clock_step=`,
`receiver_steady_ref_ns=`, `cert_verify_mode=`, `cert_verified_set_size=`.

**Depends on:** `v2vcrypto.cpp` (every crypto call), `bsm.cpp` (`calculate_speed_kph`/
`calculate_heading`, only from `generate_bsm`), `certificates.h`/`ieee16092.h` (cert and
wire-format structs), `arguments.h` (scheme/config enums). **Depended on by:** `main.cpp`
(constructs `Vehicle`, calls `transmit`/`receive`), `AttackerVehicle` (subclasses it,
overrides its virtual hooks — never touches its internals directly).

**Notable design points worth knowing before extending this file:**
- The scheme-dispatch template design (`transmit_loop<SpduT>`, `receive_loop<SpduT>`)
  means adding a third signature scheme requires a new spdu struct + four scheme-specific
  functions + one new dispatch branch — the loop bodies themselves need no changes.
- Three protected virtual hooks (`post_process_spdu`, `inter_message_delay_ms`,
  `bypass_falcon_signing`) are deliberately type-erased to `(pointer, length)` rather than
  templated on `SpduT`, because C++ disallows virtual member function templates. This is
  the entire mechanism by which `AttackerVehicle` customizes behavior without touching
  `Vehicle`'s internals.
- Two dead/legacy declarations exist and are safe to ignore when searching for call
  sites: `ecdsa_implicit_certificate` (declared, never used — only the `_explicit` variant
  is exercised) and `scheme_frame_size()` (`arguments.h`, computed but never consumed by
  anything — reserved for a fragmentation stage that ended up not needing it directly).

## `include/certificates.h`

**Purpose:** Certificate payload structs shared by both signature schemes, all built
from a common base struct.

**Structs:** `common_cert_fields` (shared header incl. the dead `hostname` field — see
`context/BUGS.md`); `ecdsa_implicit_certificate` (declared, unused); `ecdsa_explicit_certificate`
(the one actually used, sent inline in every ECDSA SPDU); `falcon_explicit_certificate`
(the one actually used — unlike ECDSA's, **never sent inline**; travels via the
fragmentation/cycle mechanism in `ieee16092.h` because it's too large for one frame).

**Depends on:** nothing project-specific. **Depended on by:** `Vehicle.h`/`.cpp`
(embeds these in `ecdsa_spdu`/`falcon_spdu`'s `data` field, via `ieee16092.h`'s wrappers).

## `include/ieee16092.h`

**Purpose:** IEEE 1609.2-flavored "SPDU data" wrapper structs, plus (its most novel
content) the entire Falcon certificate-fragmentation/cycle wire format built for this
project.

**Key contents:** `header_info`/`to_be_signed_data` (the anti-replay/freshness basis used
everywhere — 30s window in both verify paths, 100ms admission deadline in the spam
filter, `[DeadlineMiss]`/latency metrics); `signed_data_*`/`ieee1609dot2data_*` wrapper
variants (only the `_explicit` ones are actually used); `cert_message_kind` enum
(`HASH_ONLY`/`SEGMENT_CARRYING`); `FALCON_CERT_CYCLE_M_MAX = 16` (upper bound on the configurable `m`,
`certCycleSegmentCount`) and `FALCON_CERT_CYCLE_M_MIN_FEASIBLE = 2` (sizes `segment_data`;
the authoritative minimum-`m` check is a computed wire-size check in `main.cpp`);
`DSRC_MAX_FRAME_BYTES = 2304`; `falcon_cert_cycle_envelope` (the fragmentation wire struct:
`fragment_set_id`, `message_kind`, `full_hash[8]`, `fragment_index`, `fragment_count`,
`seg_hash[8]`, `segment_length`, `segment_data[...]`), with standing `static_assert`s on the
segment-size math and on the `offsetof` layout of the segment-carrying fields.
`ieee1609dot2data` (generic/legacy wrapper) is declared but never instantiated anywhere —
dead code, not a bug.

**Depends on:** `certificates.h` (embeds cert structs). **Depended on by:** `Vehicle.h`/
`.cpp` (every wire-format struct and constant used throughout).

## `include/arguments.h`

**Purpose:** All CLI/config enums and the `program_arguments` struct — the seam between
`main.cpp`'s argv/`config.json` parsing and the rest of the program. Small,
dependency-light.

**Enums:** `mode` (TRANSMITTER/RECEIVER), `technology` (DSRC/CV2X — stored but not
observably branched on outside the non-test `read_frame` framing path), `signature_scheme`
(ECDSA/FALCON — the top-level scheme-dispatch selector), `attack_mode`
(EXPENSIVE_VALID/INVALID_SIGNATURE/CHEAP_INVALID_SIGNATURE). `scheme_frame_size()` is
declared but unused (see above).

**The full `config.json` surface** (all fields, read in `main.cpp`, each with a
backward-compatible default):

| JSON key | Default | Controls |
|---|---|---|
| `scenario.numVehicles` | required | legitimate vehicle count; also the legit/attacker `vehicle_id` boundary used throughout metrics |
| `scenario.numMessages` | required | messages sent per legitimate vehicle |
| `scenario.signatureScheme` | `"ecdsa"` | ECDSA vs. FALCON dispatch |
| `scenario.numAttackers` | 0 | number of `AttackerVehicle`s, IDs `[numVehicles, numVehicles+numAttackers)` |
| `scenario.attackerMode` | `"expensive_valid"` | which `attack_mode` all attacker vehicles use |
| `scenario.numAttackerMessages` | 0 | messages sent per attacker vehicle |
| `scenario.certCycleHashOnlyCount` | 4 | `n` in the Falcon cert cycle `τ = M(2) + n`; Falcon-only |
| `scenario.spamFilterEnabled` | `false` | turns on the Phase 3 receive-side spam filter (Falcon-only) |
| `scenario.spamFilterMinGapMs` | 50.0 | per-sender minimum send-timestamp gap (cheap check: RATE) — see `context/BUGS.md` for the constraint vs. the 100ms BSM interval |
| `scenario.spamFilterAdmitMs` | 100.0 | max staleness (arrival − send timestamp) for admission (cheap check: STALE), distinct from the 30s anti-replay window |
| `scenario.bufferTtlMs` | 500.0 | TTL for an incomplete fragment-reconstruction buffer before eviction |
| `scenario.spamFilterGlobalStateCap` | 512 | global cap on combined buffer + cache entries, LRU-evicted |

**Depends on:** nothing (only `<cstddef>`). **Depended on by:** `main.cpp` (parses into
these types), `Vehicle.h`/`.cpp` and `AttackerVehicle.h`/`.cpp` (consume the enums).

**Environment variables (Update 23; deliberately not `config.json` fields):**

| Variable | Default | Controls |
|---|---|---|
| `PQV2V_TIMING_PREFIX` | unset (off) | per-message timing CSVs: receiver `<prefix>_msgtiming.csv` + `<prefix>_ttfv.csv`, transmitter `<prefix>_sendtimes.csv` (legit only); also silences the receiver's per-message `[FalconCertCycle]` lines |
| `PQV2V_CERT_VERIFY_MODE` | `every` | `once` = filter-OFF path verifies each distinct cert (by full SHA-256) once, then skips cert `falcon_verify` (Fig. 3 version B); any other value is a startup error |

## Harness scripts (`scripts/phase4_harness/`, gitignored) touched by Update 23

- `phase4_mn_sweep.sh` — m × n sweep driver; now parameterized by `SWEEP_L`, `SWEEP_NUM_MSGS`,
  `SWEEP_CELLS`, `SWEEP_CERT_VERIFY_MODE` (defaults = the original L=6/300/all-8-cells/every run),
  exports the two env vars per trial, gzips timing CSVs, resumes only on summary.csv + timing files in
  the same mode, orders combos coarse-first (`SWEEP_COARSE_N`).
- `phase4_seg_grid.sh` — new; pass-major wrapper for the segmentation grid (A_off, 200 msgs, N=5,
  verify-once; L = 6, 4, 3, 5; optional every-mode pass 3). Calls `phase4_mn_sweep.sh` only.
- `phase4_mn_sweep_aggregate.py` — prediction check + report; now also per-combo timing columns,
  pooled once-mode cert stats, `--ab-reference` A-vs-B check (reads the timing CSVs, NA if absent).
- `phase4_vehicle_scaling_aggregate.py` — the per-combo gate; gained `--msgs-per-vehicle`.
- `phase4_seg_postgrid.py` — new; post-grid merge across every L/mode run: cross-L summary, one gzipped
  per-message CSV, pooled cert-verify stats, every-vs-once check, and a generated `data_dictionary.md`
  (default output `exports/seg_grid/`). Imports `phase4_mn_sweep_aggregate.py`; read-only on the logs.
