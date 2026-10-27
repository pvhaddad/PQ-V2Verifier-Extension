# Bugs, Limitations, and Deferred Work

Code defects, known limitations, and deferred features found across `context/UPDATES.md`
— things about the *code*, not undecided design choices (those are in
`context/OPEN_QUESTIONS.md`). Read this before touching any of the areas below, and
before claiming a clean/complete result that one of these might undercut.

## Outstanding — present in the code today

- **Falcon uses a single keypair for both cert-signing and message-signing** (no
  `cert_falcon_keys/` directory exists). Stated scoping simplification, not an oversight
  — ECDSA's independent-key separation is a real security property from the Partially
  Hybrid paper's threat model that Falcon's path doesn't replicate. Must appear in the
  report's limitations section. (Update 1)
- **Non-`--test` (SDR/DSRC hardware) mode**: Falcon exits with an explicit error (no
  frame layout defined for its larger, variable-length struct). ECDSA's non-test path
  exists but has an independent transmit/receive port mismatch (52001 vs. 4444) that
  makes it non-functional for multi-vehicle traffic. Use `--test` for everything. (Update
  1, 2)
- **`scripts/generate_keys.py` is hardcoded to exactly 10 identities** (IDs 0-9, both the
  loop bound and directory bootstrap). Needs parameterizing before any experiment needs
  `numVehicles + numAttackers > 10`. (Update 3)
- **Attacker flood delay is hardcoded to 0ms in `main.cpp`**, not a config field — an
  attacker always sends as fast as it can produce messages; no per-run delay tuning
  exists. (Update 3)
- **Attack variants #3 (certificate-churn as a dedicated `AttackerVehicle` mode) and #4
  (algorithm-choice-as-cost-multiplier) are deferred, not started.** `AttackerVehicle`'s
  two-mode (later three-mode) design doesn't block adding them but wasn't built to
  anticipate them. (Update 1, 3)
- **`common_cert_fields::hostname` is a dead field** (~32 bytes per cert
  transmission/segment) — set once via a default member initializer, never read anywhere
  in the codebase, yet baked into both schemes' cryptographic cert signatures (whole-struct
  signing), so it can't be dropped from the wire bundle without also changing what gets
  signed. Removing it would touch ECDSA's cert struct layout too, which is out of scope
  for the "ECDSA byte-for-byte unchanged" constraint. Not resolved — see
  `context/OPEN_QUESTIONS.md` for the pending decision on whether/how to remove it.
  (Update 5)
- **Dormant UB**: structs containing `std::string` (`common_cert_fields::hostname`,
  transitively in every cert struct) are sent whole, raw, across UDP between two OS
  processes — technically undefined behavior, since a `std::string`'s SSO self-pointer is
  invalidated by the raw copy. Silently harmless today because the received struct is
  only ever used as an opaque byte range (no `std::string` method ever called on it) and
  `receive()` terminates via `exit(0)`, skipping destructors. Fixed specifically for the
  Falcon cert-reconstruction path (`ccons_falcon`, which now stores/passes reconstructed
  certs as opaque bytes after this exact bug caused a real segfault via
  `unordered_map` copy-construction) — **not an action item for ECDSA or the
  pre-fragmentation Falcon path**, but latent if a future change ever copy-constructs a
  received cert struct or `receive()` stops calling `exit()`. (Update 5)
- **`net.core.rmem_max` (OS UDP receive buffer ceiling) resets to the ~208KB default on
  every VM reboot**, deliberately not persisted to `/etc/sysctl.conf` (shared VM).
  Must be manually re-applied (`sudo sysctl -w net.core.rmem_max=33554432`) before any
  flood-scale (thousands of messages) benchmark run, confirmed to recur for real across
  multiple reboots, not just a theoretical risk. (Update 6, 15)
- **Wall-clock steps every ~32 s (observed on this WSL2 box, in multi-hour blocks) corrupt any
  cross-process timestamp comparison for messages in flight.** The receiver's latency and the spam
  filter's `STALE` test are `system_clock` now minus the sender's embedded `system_clock` send time, so a
  forward `CLOCK_REALTIME` step of +0.4-0.75 s makes every message in flight at that instant look that
  old: spurious `[DeadlineMiss]` lines, spurious `STALE` filter drops, ~1-3% of trials per exposed step
  (higher with more vehicles). Seen in Update 21 (steps ran for the whole run, 92% of trials exposed)
  and in the Update 22 sweep (on 23:17-01:37, 01:40-04:09, 06:49-08:22; off 04:09-06:49), and on the
  first evening of use (2026-09-17); it produced all 14 late/dropped-message trials (CORRECTIONS.md #21).
  `systemd-timesyncd` is enabled by default here (`/etc/wsl.conf` `systemd=true`, `NTP=yes`, 32 s minimum
  poll); the steps' 32.25 s cadence and size fit it, and it backs off to a ~17 min poll when the clock
  isn't lagging (only 5 entries in 11 idle hours). **Why the guest clock lags in blocks is not
  established** (not reproduced with idle, synthetic load or a real trial while the regime was off; no
  Windows power events), so do not assume it is a WSL2 default: treat it as "will recur intermittently
  on any long unattended run on this machine", like `rmem_max` above. **Prevention** (needs the user's sudo;
  approved 2026-09-19 but NOT applied until they run it; its effect on the stepping is not yet observed):
  `sudo timedatectl set-ntp false` (persistent across WSL restarts; undo with `set-ntp true`). The
  vehicle-scaling sweep driver (`phase4_vehicle_scaling_sweep.sh`) now **refuses to start (exit 4) while
  `timedatectl show -p NTP` is `yes`** (`SWEEP_ALLOW_NTP=1` overrides, for smoke tests only). Note the Hyper-V
  host time sync (`hv_utils.timesync_implicit=1`) is a separate mechanism and may still adjust the clock.
  **Applied 2026-09-25 15:47:38 (Update 23):** steps dropped from ~every 34 s to one in the next ~7 min
  (15:49:30, after timesyncd had stopped), so NTP-off reduces but does not eliminate them - the Hyper-V sync
  is the likely remaining source. Update 23's receiver prints `wall_clock_step=0|1` per trial (steady vs.
  system elapsed differ by >100 ms) and the m x n aggregator excludes flagged trials from timing stats.
  **Detection (no sudo; the user is in `adm`)** is now in the harness as a safety net: the aggregator's
  `--trial-times` option reads the journal's `Clock change detected` entries, computes each step's size from the
  realtime-minus-monotonic jump, counts the steps inside every trial's messaging window, and classifies each
  trial with a late/dropped *legit* message as explained (a step of the same size in its window), step-size
  mismatch, or **NO step in window (candidate real delay, flagged loudly)**; per-trial CSV columns
  `clock_steps_in_window`, `clock_step_max_jump_ms`, `event_explained_by_clock_step`.
  `scripts/phase4_harness/phase4_clockstep_detect.py` does the same standalone, also for older log directories
  (windows from log mtimes). Validated against the known data (Update 21: 552/600 trials exposed; sweep:
  215/10/144 of 240 at L=4/6/9; all 8 full-run events explained). Any deadline-miss, latency-tail or
  `STALE` figure from this machine is suspect for trials where a step landed in flight. (Update 22)
- **`spamFilterMinGapMs` (50ms default) must stay below the hardcoded BSM send interval
  (100ms)**, or legitimate cert reconstruction breaks by the same mechanism that (partly)
  blocks a fast attacker: a sender whose own segment-0-to-segment-1 gap falls under
  `spamFilterMinGapMs` can structurally never complete a cert reconstruction. Nothing in
  the code enforces or checks this relationship — it holds today only because the chosen
  defaults happen to satisfy it. No startup assertion has been added (documentation-only
  per explicit instruction). Raise this before anyone tunes `spamFilterMinGapMs` upward.
  (Update 11, 14)
- **Cert-cycle phase offset is not implemented** — `falcon_cycle_position` is a fixed
  in-class default of 0, never varied. Every benchmark result to date reflects
  synchronized cert-cycle start across every vehicle; realistic mid-cycle receiver entry
  is untested. A full, ready-to-implement design (new config field, constructor
  parameter, normalization) is worked out but not built. (Update 18)
- **Environment-level scheduling/wake-latency spikes** (occasionally over 1 second, on
  both blocking `recvfrom()` calls and `sleep_for()`-based send pacing) cause rare
  backlog growth and occasional legitimate deadline misses. Root-caused to the specific
  2-core test VM, not a code defect — but the *exact* OS/virtualization mechanism (steal
  time vs. CFS scheduler latency vs. something else) was never pinned down; see
  `context/OPEN_QUESTIONS.md`. Affects how every benchmark result in this project should
  be reported (never claim a flat "0% across the board" without checking the permanent
  `[DeadlineMiss]`/loop-iteration-cost instrumentation first). (Update 8)

- **`phase4_aggregate.py` is not duration-mode aware.** Its per-trial reconciliation
  (`expected_total = numMessages*numVehicles + numAttackerMessages*numAttackers`) would
  flag every `attackerMatchLegitDuration: true` trial as a metrics-size mismatch, since
  the attacker count is now an output. It would need to take the attacker count from the
  transmitter's `[AttackerRunSummary] messages_sent` (or the receiver's attacker total)
  instead. The Phase 4 harness never sets the flag, so existing results are unaffected.
- **Trace wraparound makes a position jump in moving traces.** `generate_bsm` indexes
  modulo the trace length (added for `attackerMatchLegitDuration`), so on wrap the
  speed/heading are computed from the last row to row 0. Harmless for the stationary
  attacker trace (`2.csv`), and BSM content doesn't affect latency/drop metrics.
- **Duration-mode receiver ends on the 5s `SO_RCVTIMEO`** (`[ReceiveEndOfRun]`), so a
  legit-traffic stall longer than 5s mid-run would end the run early. The legit-only
  `INCOMPLETE RUN` check still reports it.
- **The duration-mode backstop only covers a *hung* legit thread, not a crashed one.** The
  attacker normally stops on legit completion (`legit_completion_signal`); the
  `attackerDurationMargin` deadline is a backstop. But a legit thread that fails via
  `exit()` takes the whole transmitter process down, attacker included, so the backstop
  never gets the chance to fire in that case.
- **Legit completion is signaled ~100ms after a vehicle's last message.** The increment
  happens when `transmit_loop` returns, which is after the final post-send 100ms sleep, so
  the attacker floods for about that long past the last legit send.
- **Transmitter console output can tear mid-line under concurrent vehicle threads.**
  `main.cpp` runs one `std::thread` per vehicle, and all of them write to `std::cout`
  with no shared mutex — a genuine data race on the stream, not just cosmetic
  interleaving of whole lines. Confirmed directly: in a 3-vehicle `attackerMatchLegitDuration`
  trial, vehicle=0's `[LegitDone] vehicle=0 legit_vehicles_done=1/2` line was split
  mid-write, leaving a bare `1/2` on its own line elsewhere in the log while another
  thread's `[FalconCertCycle] TX ...` line absorbed the rest. The underlying event still
  happened correctly (vehicle=1's counter only reaches `2/2` if vehicle=0's `fetch_add`
  already ran, and vehicle=0's own `[FloodRateCheck] num_msgs=300` confirms it completed
  its full send) — this is a logging/display defect, not a correctness defect in the
  transmit/verify path. Matters for anyone `grep`-parsing transmitter logs (a torn line
  won't match the expected pattern) or aggregating trial results programmatically.
  Not fixed; no code change proposed yet.
- **Receiver log embeds raw control bytes instead of decimal vehicle IDs.**
  `Vehicle.cpp:277` (`std::cout << incoming_spdu.vehicle_id << '\n';`) prints a
  `uint8_t` field directly through `operator<<`, which treats `unsigned char` as a
  *character*, not a number — for small vehicle IDs (0, 1, 2, ...) this writes literal
  control bytes (vehicle 0 → a raw NUL byte) into the log instead of the digit `"0"`.
  Confirmed directly: a receiver log's bytes were clean ASCII everywhere `sed`/`od`
  checked, yet plain `grep "SocketConfig" <log>` silently returned zero matches on a
  line that was visibly present (`grep -a`, forcing text mode, matched it
  immediately) — the embedded NUL from an earlier `vehicle_id=0` print had already
  made `grep` classify the file as binary before reaching that line. Same root cause
  would affect any other line-oriented tool (`awk`, naive log parsers) applied past the
  first NUL. Purely a log-readability/tooling-interop issue — does not affect
  verification results or any metric in the `Falcon Verify Metrics Summary`. Not fixed
  yet (deliberately deferred); the fix is a one-line cast
  (`(int) incoming_spdu.vehicle_id`) at `src/Vehicle.cpp:277`.

## Resolved (kept for historical traceability — so an older understanding of these isn't relayed as current)

- **`transmit()`'s destination address was silently going to the wrong host.** Update
  2 documented this as "`transmit()`'s destination uses `INADDR_ANY` (0.0.0.0)... works
  on Linux... fragile if ever ported off Linux" — that description is now stale
  regardless of the fix below: the source had since been changed to
  `INADDR_LOOPBACK` (undocumented, no matching `UPDATES.md` entry), but the fix was
  incomplete and introduced a *worse*, silent bug: `INADDR_LOOPBACK` (`0x7f000001`) is
  a **host-byte-order** constant and must be passed through `htonl()` before assigning
  to `sin_addr.s_addr` (network/big-endian). Without it, on this (little-endian x86-64)
  hardware, every transmitted packet's destination byte-swapped to `1.0.0.127` instead
  of `127.0.0.1` — a real but wrong unicast address that gets routed out over the
  default gateway instead of looping back, so `sendto()` still reports success (no way
  for the caller to notice) while every packet vanishes. Confirmed via `strace -e
  sendto` on the transmitter while the receiver was listening
  (`sin_addr=inet_addr("1.0.0.127")`), and via a raw Python UDP packet to
  `127.0.0.1:6666` proving the receiver's bind/recvfrom path was fine all along. This
  is not WSL2-specific — it would misbehave identically on any little-endian Linux
  box; `INADDR_ANY` (`0x00000000`) never exposed it because zero is byte-order-
  invariant. Fixed: `src/Vehicle.cpp:125` now reads
  `servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);`. Verified end-to-end: the
  `dsrc receiver/transmitter nogui --test` two-terminal walkthrough now delivers all
  150 expected messages (0 `ReceiveTimeout`, 0 `INCOMPLETE RUN`) where it previously
  received 0. See `context/CORRECTIONS.md` for the walk-back on the stale Update 2
  description.
- **`(socklen_t*)` bad-pointer-cast bug**, found independently twice at different call
  sites, silently harmless until timeout-detection logic needed `recvfrom()`'s real
  return value. Fixed at all 3 `recvfrom()` call sites in the codebase; a full-codebase
  grep for the cast pattern now returns nothing. (Update 6)
- **No receive timeout** — `receive_loop`'s exact-count blocking wait could hang forever
  on real packet loss. Fixed via `SO_RCVTIMEO` (5s) and a `read_frame` contract change
  (`void` → `bool`, `false` = timed out) so a partial run now reports "received X of Y"
  instead of hanging. (Update 6)
- **Cert-cache poisoning gap** (Update 9: the Phase-1 baseline reconstruction path cached
  a reconstructed cert on full-hash integrity alone, with no cert-signature check —
  meaning a churn attacker's fabricated cert would be cached and silently poison the
  hashedId8 fast path). **Confirmed via direct source read this session** (`grep` on
  `src/Vehicle.cpp`) that the fix landed in the Phase 3 spam-filter path:
  `spam_filter_verify_falcon` requires a successful `cert_sig_ok` (`falcon_verify`) before
  writing to `spam_filter_cert_cache`; a failed cert-sig verify is now a terminal
  rejection that never reaches message-sig verify. The *original* baseline path
  (`ccons_falcon` → `falcon_reconstructed_certs`, exercised only when
  `spamFilterEnabled:false`) still caches on hash alone — but that's correctly the
  documented undefended-baseline behavior (Update 9's own framing), not an outstanding
  defect. See `context/CORRECTIONS.md` for the full note.

## Cross-reference

The `common_cert_fields::hostname` dead-field removal is listed here as a defect but is
also a **pending decision** ("raise with Geoff/Hassan before touching it, since it's an
ECDSA-affecting change") — see `context/OPEN_QUESTIONS.md` for that side of it.
