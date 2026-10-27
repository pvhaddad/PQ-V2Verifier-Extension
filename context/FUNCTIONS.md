# Functions Reference

Generated from the actual codebase, not from `context/UPDATES.md` — one entry per
major/non-trivial function: what it does, what it calls, what calls it. Read
`context/FILES.md` first for the per-file overview; this is the drill-down. Organized by
file, in the same order as `context/FILES.md`.

## `v2vcrypto.cpp` / `v2vcrypto.h`

- **`sha256sum(data, length, md)`** — SHA-256 over an arbitrary byte range into a 32-byte
  digest. Called by `sign_message_ecdsa`, `verify_message_ecdsa` (hashes
  `to_be_signed_data`/the cert before ECDSA sign/verify), and `truncated_sha256_8`
  (Falcon cert/segment hashing, truncated to 8 bytes for hashedId8-style IDs).
- **`ecdsa_sign(hash, signing_key, signature_buffer_length, signature)`** — wraps
  `ECDSA_sign()`; exits the process on OpenSSL failure. Called by `sign_message_ecdsa` and
  `generate_ecdsa_spdu` (cert self-signing).
- **`ecdsa_verify(hash, signature, signature_buffer_length, verification_key)`** — wraps
  `ECDSA_verify()`; treats OpenSSL's `-1` (malformed input) as **fatal**, calling `exit()`
  rather than returning it. This is why `AttackerVehicle`'s `INVALID_SIGNATURE` mode flips
  the *last* signature byte, not the first — flipping the DER SEQUENCE tag byte would trip
  this fatal path. Called by `verify_message_ecdsa`.
- **`falcon_sign(signature, signature_len, message, message_len, private_key)`** — wraps
  `OQS_SIG_falcon_512_sign()`; exits on failure. Called by `sign_message_falcon`
  (per-message) and `generate_falcon_spdu` (once-per-vehicle-lifetime cert signing).
- **`falcon_verify(message, message_len, signature, signature_len, public_key)`** — wraps
  `OQS_SIG_falcon_512_verify()`, returns `bool` (non-fatal on mismatch, unlike ECDSA's
  verify). Called throughout `verify_message_falcon`, `spam_filter_admit`, and
  `spam_filter_verify_falcon`'s cert-sig check.
- **`hex_to_bytes(hex, out, out_len)`** — decodes a hex string into raw bytes; exits if
  too short. Called only by `Vehicle::load_falcon_key` to parse the hex-encoded key files
  under `falcon_keys/<n>/`.

## `bsm.cpp` / `bsm.h`

- **`calculate_speed_kph(x1, x2, y1, y2, time_msec)`** — Euclidean distance between two
  trace points, converted to km/h. Called only by `Vehicle::generate_bsm`, using the
  current and previous trace rows (fixed 100ms interval hardcoded at the call site).
- **`calculate_heading(x1, x2, y1, y2)`** — `atan2`-based bearing in degrees. Called only
  by `generate_bsm`.

## `AttackerVehicle.cpp` / `AttackerVehicle.h`

- **`inter_message_delay_ms()`** (override) — returns `flood_delay_ms` (0, set by
  `main.cpp`) instead of `Vehicle`'s default hardcoded `100`. Called via virtual dispatch
  from `Vehicle::transmit_loop`.
- **`post_process_spdu(signature, signature_length)`** (override) — if
  `mode == INVALID_SIGNATURE`, XORs the last signature byte with `0xFF`. No-op for the
  other two modes (deliberately — `CHEAP_INVALID_SIGNATURE`'s bypass happens earlier, in
  `generate_falcon_spdu`, since by the time `post_process_spdu` runs the real signing cost
  has already been paid). Called from `Vehicle::transmit_loop` right after `generate_spdu`.
- **`bypass_falcon_signing()`** (override) — returns `true` only for
  `CHEAP_INVALID_SIGNATURE`. Called from `Vehicle::generate_falcon_spdu`, which is the
  only place that can actually skip the `falcon_sign()` call.

## `main.cpp`

- **`print_usage()`** — prints the CLI usage string on any argument-parsing failure.
- **`main(argc, argv)`** — parses args + all 12 `config.json` fields (see
  `context/FILES.md`'s table); in transmitter mode builds
  `std::vector<std::unique_ptr<Vehicle>>` (plain `Vehicle`s then `AttackerVehicle`s),
  spawns one thread per vehicle via `Vehicle::transmit_static`, joins; in receiver mode
  constructs one `Vehicle v1(0)` and calls `v1.receive(...)`. Update 23: with
  `PQV2V_TIMING_PREFIX` set, flags legit vehicles `record_send_times` before the threads start
  and writes `<prefix>_sendtimes.csv` from each vehicle's `falcon_send_times` after the join. Calls
  `std::ios_base::sync_with_stdio(false)` once at the top (pure performance — see
  `context/UPDATES.md` Update 6).

## `Vehicle.cpp` / `Vehicle.h` (the core)

### Lifecycle / dispatch
- **`Vehicle(int number)`** (ctor) — loads EC and Falcon keys/certs and the vehicle's GPS
  trace file via `load_key`, `load_falcon_key`, `load_trace`.
- **`transmit(num_msgs, test, scheme, cert_cycle_hash_only_count)`** — opens a UDP socket
  (port 6666 `--test` / 52001 else), dispatches to `transmit_loop<ecdsa_spdu>` or
  `transmit_loop<falcon_spdu>`; Falcon path also prints `[FloodRateCheck]`,
  `[FalconSignCost]`, `[FalconSendGapTrend]` diagnostics after the loop. Called by
  `Vehicle::transmit_static` (main.cpp's `std::thread` trampoline).
- **`transmit_loop<SpduT>(sockfd, servaddr, num_msgs, generate_spdu)`** (template) — the
  scheme-agnostic send loop: builds a fresh `SpduT`, calls the injected `generate_spdu`
  member-function pointer, calls the virtual hook `post_process_spdu` (this is the entire
  mechanism `AttackerVehicle` uses to corrupt signatures), sends exactly
  `wire_length(next_spdu)` bytes, sleeps `inter_message_delay_ms()` (also virtual). No
  attacker-specific code lives here at all. If `record_send_times` (Update 23), pushes
  `(i, absolute steady_clock ns)` into `falcon_send_times` right before `sendto`.
- **`receive(num_msgs, test, tkgui, webgui, scheme, num_vehicles, spam_filter_*...)`** —
  opens the receive socket (port 6666 `--test` / 4444 else) with a 32MiB `SO_RCVBUF` and
  5s `SO_RCVTIMEO` (survives startup CPU-contention bursts without hanging forever, see
  `context/UPDATES.md` Update 6), opens a second GUI-forwarding socket, builds a
  scheme-specific `read_frame` lambda, dispatches to `receive_loop<ecdsa_spdu>` or
  `receive_loop<falcon_spdu>`. Falcon path also calls
  `print_falcon_verify_metrics_summary` at the end. Update 23: at entry captures
  `falcon_steady_ref`/`falcon_system_ref`, reads `PQV2V_TIMING_PREFIX` / `PQV2V_CERT_VERIFY_MODE`
  (exits on an unknown mode), reserves `falcon_timing` (`num_msgs + 1024`, or `+400000` open-ended);
  the Falcon `read_frame` stamps t0 (`falcon_rx_t0_ns`) from the same `now()` that ends the
  `recvfrom` timing; after the loop sets `falcon_wall_clock_step` (steady vs. system elapsed differ
  by >100 ms), then prints the summary and calls `write_falcon_timing_files`. Terminates via `exit(0)` — the
  receiver is single-shot per run. Called only by `main.cpp`.
- **`receive_loop<SpduT>(...)`** (template) — calls `read_frame` (returns `false` on
  `SO_RCVTIMEO` timeout instead of hanging), timestamps arrival, calls the injected
  `verify` member-function pointer, forwards to GUI if requested, prints via
  `print_spdu`/`print_bsm`.
- **`forward_bsm_to_gui<SpduT>(...)`** (template) — packs a `packed_bsm_for_gui` and
  sends it to the GUI socket.

### Wire-format helpers
- **`wire_length(const ecdsa_spdu&)`** — always `sizeof(spdu)` (unchanged, preserved for
  regression testing).
- **`wire_length(const falcon_spdu&)`** — pointer-arithmetic truncation (not `offsetof`,
  since the struct isn't standard-layout due to a `chrono::time_point` member): truncates
  to just past `cert_cycle.full_hash` for `HASH_ONLY`, or through
  `cert_cycle.segment_data[0..segment_length)` for `SEGMENT_CARRYING`. This is what makes
  the Falcon cert-cycle protocol genuinely frame-size-constrained on the wire. Depends on
  `cert_cycle` staying the struct's last field.

### SPDU generation / signing
- **`generate_ecdsa_spdu(spdu, timestep)`** — fills id/BSM/timestamp/cert, hashes+signs
  the cert via `sha256sum`+`ecdsa_sign`, then calls `sign_message_ecdsa`.
- **`generate_falcon_spdu(spdu, timestep)`** — the most complex function in the file.
  Tracks send-gap timing; implements the cert cycle (`τ = falcon_cycle_segment_count_m +
  falcon_cycle_hash_only_count_n`, both set from `transmit()`'s parameters): at cycle position 0, signs the cert exactly once per
  vehicle lifetime (guarded by `falcon_cert_prepared`, so `full_hash` stays stable across
  cycles for spam-filter caching), builds the cert bundle blob, fragments it via
  `cfrag_falcon`; emits `SEGMENT_CARRYING` (with `fragment_count = m`) or `HASH_ONLY`
  depending on position; finally
  either bypasses real signing (`bypass_falcon_signing()` hook → `RAND_bytes`, used by
  `CHEAP_INVALID_SIGNATURE`) or calls `sign_message_falcon`.
- **`generate_bsm(timestep)`** — pulls lat/lon/elevation from the loaded trace; for
  `timestep != 0` computes speed/heading via `bsm.cpp` against the previous timestep (row
  0 always reports speed=0, heading=0).
- **`sign_message_ecdsa(spdu)`** — hashes `tbsData` via `sha256sum`, signs via
  `ecdsa_sign`.
- **`sign_message_falcon(spdu)`** — signs raw `tbsData` bytes directly (no pre-hash) via
  `falcon_sign`, timed into `falcon_message_sign_times_ms`.

### Verification
- **`verify_message_ecdsa(spdu, received_time, vehicle_id)`** — loads the claimed
  sender's keys fresh every call, verifies cert signature + message signature + 30s
  freshness window, returns AND of all three.
- **`verify_message_falcon(spdu, received_time, vehicle_id)`** — tracks loop-iteration
  timing and periodic `[ReceiverProgress]` logging; **dispatches immediately to
  `spam_filter_verify_falcon` if `spam_filter_enabled`** — everything after that dispatch
  check is the untouched Phase 2 path: logs cycle diagnostics, on `SEGMENT_CARRYING`
  validates the segment hash and buffers it (`falcon_cert_buffers`, naive reset-on-mismatch
  — not flood-resistant, that's what Phase 3 replaces; resets when `fragment_set_id` or
  `fragment_count` changes, and ignores a `fragment_count` outside
  `[M_MIN_FEASIBLE, M_MAX]`), reconstructs via `ccons_falcon` once all `fragment_count`
  segments are present and caches into `falcon_reconstructed_certs` **on
  full-hash integrity alone, with no cert-sig check** (this is the Phase-1 baseline path;
  see `context/BUGS.md` for why that's correct undefended-baseline behavior, not a
  residual defect); then verifies the cached cert (if any) and the message signature,
  classifies the outcome, records metrics, logs `[DeadlineMiss]` if latency > 100ms.
  Update 23: sets `falcon_rx_kind` before the filter dispatch; stamps t1 right after a successful
  `ccons_falcon` (every cycle's completing segment), t2 / `cert_verify_ns` and `msg_verify_ns` from
  the existing steady_clock verify brackets, t3 after outcome classification, then
  `record_falcon_timing`. The cert verify runs **per message** against the entry stored for
  `sender_id` (hash-only messages' `full_hash` is never compared to it); in verify-once mode a
  stored entry whose `full_digest` is in `falcon_verified_cert_digests` skips that verify
  (`cert_path` CACHED), and a successful verify inserts it (VERIFIED_NOW). The per-message
  `[FalconCertCycle]` RX/Reconstructed/DROP lines print only when timing is off.

### Falcon cert fragmentation helpers (static, private)
- **`truncated_sha256_8(data, length, out[8])`** — `sha256sum` truncated to 8 bytes
  (hashedId8 convention).
- **`build_falcon_cert_bundle_blob(cert, cert_sig_len, cert_sig)`** — concatenates raw
  cert bytes + sig-length + sig bytes into a blob.
- **`cfrag_falcon(blob, m, segments_out)`** — splits the blob into `m` segments of
  `ceil(size/m)` bytes (remainder in the last).
- **`all_segments_present(segments, count)` / `collect_segments(segments, count)`** —
  reassembly completeness check / gather of slots `0..count-1`, shared by both receive paths.
- **`falcon_segment_wire_bytes(segment_len)`** (public) — on-wire size of a segment-carrying
  frame with that segment length; `main.cpp` uses it to reject infeasible `m`.
- **`ccons_falcon(segments, expected_full_hash, cert_out, cert_sig_len_out,
  cert_sig_out, full_digest_out = nullptr)`** — concatenates segments, verifies the combined hash matches, unpacks
  cert/sig bytes. Computes one in-process SHA-256 (`sha256sum`) and compares its first 8 bytes
  (same as `truncated_sha256_8`); if `full_digest_out` is given (verify-once mode only), copies all
  32 bytes out on success, so no second hash is needed. Deliberately writes into a raw `unsigned char[...]` buffer rather than a
  live `falcon_explicit_certificate` object — see `context/BUGS.md`'s dormant-UB entry for
  why (a `std::string` member makes live-object reconstruction from raw bytes unsafe).

### Phase 3 spam filter (self-contained subsystem)
- **`falcon_full_hash_to_key(full_hash[8])`** — reinterprets the 8-byte hash as a
  `uint64_t` map key.
- **`enforce_spam_filter_global_cap()`** — global LRU-style eviction across **both**
  `spam_filter_buffers` and `spam_filter_cert_cache` combined, evicting the globally-oldest
  entry until under `spam_filter_global_state_cap`.
- **`spam_filter_drop(sender_id, is_attacker, reason, reason_label, send_ts)`** — the
  shared "reject" path: increments per-reason drop counters (split legit/attacker,
  Update 16), pushes a `SPAM_FILTERED` metrics record, logs, returns `false`.
- **`spam_filter_record_outcome(sender_id, outcome, send_ts)`** — the shared
  "non-drop, non-final-admit" path (`NO_CERT_YET` pending, or terminal
  `INVALID_CERT_SIGNATURE`) — pushes metrics without counting as a drop-reason.
- **`spam_filter_admit(spdu, sender_id, send_ts, received_time)`** — the actual crypto
  gate, reached only after cheap checks pass: runs `falcon_verify` on the message
  signature plus the 30s freshness check, classifies outcome, records it.
- **`spam_filter_verify_falcon(spdu, received_time, vehicle_id)`** — the full filter
  state machine, two paths:
  - **Path A (`HASH_ONLY`)**: cache-membership check → rate-gap check (`RATE`, keyed on
    the message's own **send** timestamp, not arrival time — deliberately, to avoid
    false-dropping legit traffic bunched by scheduler jitter) → length check → staleness
    check (100ms admission deadline, separate from the 30s anti-replay window) → admit via
    `spam_filter_admit`.
  - **Path B (`SEGMENT_CARRYING`)**: rate + length cheap checks (length check also bounds
    `segment_length` against `FALCON_CERT_SEGMENT_MAX_BYTES` — an out-of-bounds-read fix
    the Phase-1/filter-OFF path lacks) → cache-hit fast path (skip reconstruction if
    already cached) → on cache miss, `FRAG_INDEX` check (`fragment_count` in
    `[M_MIN_FEASIBLE, M_MAX]`, `fragment_index < fragment_count`, and later fragments must
    match the count the buffer opened with) → buffer-cap-enforced reconstruction (cap = 1 per
    sender, structurally guaranteed by the `unordered_map` key, + TTL eviction) →
    `ccons_falcon` → **cert-sig `falcon_verify`** → on success, cache and admit; on
    failure, terminal `INVALID_CERT_SIGNATURE` with **no message-sig verify attempted**
    (no trusted key exists to check it against).

### Metrics / printing
- **`percentile_ms(values, p)`** (static) — nearest-rank percentile over a
  copied+sorted vector.
- **`print_falcon_verify_metrics_summary(num_vehicles, expected_total)`** — end-of-run
  report: legit vs. attacker outcome breakdowns (split by `vehicle_id < num_vehicles`),
  valid/drop rates, deadline-miss ratios, latency percentiles, sign/verify cost
  breakdowns, full-loop-iteration vs. isolated `recvfrom()` cost, and (if
  `spam_filter_enabled`) per-reason drop-count tables split legit/attacker plus final
  buffer/cache occupancy. Called once at the end of `receive()`, Falcon only.
  Update 23: ends with `wall_clock_step=`, `receiver_steady_ref_ns=`, `cert_verify_mode=`,
  `cert_verified_set_size=` lines (always printed).
- **`record_falcon_timing(sender_id, outcome, cert_path, t1, t2, t3, cert_verify_ns, msg_verify_ns)`**
  (Update 23) — no-op unless `PQV2V_TIMING_PREFIX` is set; appends one `falcon_timing_record`
  with t0 = `falcon_rx_t0_ns`, kind = `falcon_rx_kind`, seq = per-sender arrival index. Called
  from `verify_message_falcon` (filter-off, full probes) and from `spam_filter_drop` /
  `spam_filter_record_outcome` (filter-on, t0 + outcome only), so rows match `falcon_metrics`.
- **`write_falcon_timing_files()`** (Update 23) — after the receive loop only: logs
  `[TimingBuffer] rows= reserved= reallocated=`, writes `<prefix>_msgtiming.csv` and the per-sender
  `<prefix>_ttfv.csv` (first t0, first t1, first VALID t3, ttfv_ms, count of non-VALID messages
  before the first VALID one).
- **`print_bsm<SpduT>` / `print_spdu<SpduT>`** (templates) — debug console dumps.
  Deliberately use `'\n'` instead of `std::endl` in the hot receive path to avoid a
  forced-flush syscall per message (Update 8's investigation, not a content change).

### Key/trace loading (static, private)
- **`load_key(number, certificate, key_to_store)`** — loads a PEM EC private key from
  `keys/<n>/p256.key` or `cert_keys/<n>/p256.key`; exits on failure. Called from the ctor
  and re-loaded fresh per verification in `verify_message_ecdsa`.
- **`load_falcon_key(number, public_key, key_to_store)`** — reads a hex-encoded key from
  `falcon_keys/<n>/falcon.{pub,key}`, decoded via `hex_to_bytes`. Called from the ctor and
  repeatedly during Falcon verification.
- **`load_trace(number)`** — reads `trace_files/<n>.csv` into `timestep`; only the first
  3 columns (lat/lon/elevation) are read (see the trace-format notes in `README.md`);
  exits fatally if the file has fewer rows than the requested message count.
