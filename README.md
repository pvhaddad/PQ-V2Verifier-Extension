# PQ-V2Verifier Extension: Verify-Exhaustion Defense for Post-Quantum V2V

[![Paper DOI](https://img.shields.io/badge/DOI-10.1145%2F3839338.3857260-blue)](https://doi.org/10.1145/3839338.3857260)
[![Base artifact DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.10189528.svg)](https://doi.org/10.5281/zenodo.10189528)

This repository extends the NDSS 2024 PQ-V2Verifier artifact with a verify-flooding attacker simulation, a
spam-filter defense with hashed certificate caching, and a benchmark harness for studying verify-exhaustion
denial-of-service attacks on post-quantum V2V authentication. See "Extension Notice" below for what changed and how to
cite this work; the original artifact's description follows.

The base artifact is a preliminary version of PQ-V2Verifier, an extension of [V2Verifier](https://github.com/twardokus/v2verifier) 
that enables experimentation with post-quantum (PQ) authentication algorithms and protocols for vehicle-to-vehicle (V2V)
communication. Please note that over the next few months, PQ-V2Verifier will be integrated with [V2Verifier](https://github.com/twardokus/v2verifier),
our main V2V security testbed project.

This artifact repository is made available as part of an artifact submission to the 2024 Network and Distributed 
System Security Symposium (NDSS), associated with the following paper:

Geoff Twardokus, Nina Bindel, Hanif Rahbari, and Sarah McCarthy, "When Cryptography Needs a Hand: Practical Post-Quantum Authentication for V2V Communications," _Network and Distributed System Security Symposium (NDSS 2024)_, San Diego, CA, Feb. 2024.

Bibtex:

    @inproceedings{twardokus2024when,
        author = "Geoff Twardokus and Nina Bindel and Hanif Rahbari and Sarah McCarthy",
        title = "When Cryptography Needs a Hand: Practical Post-Quantum Authentication for {V2V} Communications",
        booktitle = "Proc. Network and Distributed System Security Symposium (NDSS)",
        month = feb,
        year = "2024",
        address = "San Diego, CA",
        pages = ""
    }

## Extension Notice

**This checkout has been substantially extended beyond the NDSS artifact described below** to study
verify-exhaustion denial-of-service risk introduced by post-quantum signatures in V2X. The citation, DOI, and
installation/environment instructions above and below remain accurate for the base artifact.

The extension is associated with the following paper
([DOI: 10.1145/3839338.3857260](https://doi.org/10.1145/3839338.3857260)):

Philip Haddad, Hassan Mahmoud, Mahmoud Nabil Mahmoud, and Ahmad Alsharif, "Poster: V2V Spam Filter with Hashed
Certificate Caching: A Verify-Exhaustion Defense for Post-Quantum V2V Communication," _Proceedings of the 2026 ACM
Conference on Post-Quantum and Quantum-based Security_, Nov. 2026.

Bibtex:

    @inproceedings{haddad2026v2v,
        author = "Philip Haddad and Hassan Mahmoud and Mahmoud Nabil Mahmoud and Ahmad Alsharif",
        title = "Poster: {V2V} Spam Filter with Hashed Certificate Caching: A Verify-Exhaustion Defense for Post-Quantum {V2V} Communication",
        booktitle = "Proc. ACM Conference on Post-Quantum and Quantum-based Security",
        month = nov,
        year = "2026",
        doi = "10.1145/3839338.3857260",
        publisher = "ACM"
    }

What's new, in brief (full engineering rationale, decisions, and verification evidence for all of it live in
`context/UPDATES.md`, organized as dated "Update" sections, with an index of the other notes in `context/`):

- **A real Falcon-512 message path** (sign/verify wired into the actual transmit/receive flow — the base artifact
  ships Falcon-512 as starter cryptographic primitives only, not a finished protocol).
- **Falcon certificate fragmentation and a periodic transmission cycle**, so a Falcon-512 BSM's on-wire size fits
  the DSRC MAC-layer frame cap, instead of re-sending the whole certificate on every message.
- **A verify-flooding attacker simulation** (`AttackerVehicle`), with three attack variants, for studying the
  DoS vector this project is about.
- **In-process benchmarking instrumentation**: tail latency, legitimate-message drop rate, deadline-miss ratio,
  flood-rate verification, and Falcon sign/verify cost isolation — printed as a summary at the end of a receiver
  run, no external analysis tooling required.
- **A spam filter defense** (fragment-index validation, segment-hash checking, a capped/TTL'd
  certificate-reconstruction buffer, and a fast-path cache for repeat senders), implemented and verified —
  see "Project Status" below.

See "Customizing Experiments" and the new sections below for how to use any of this. See `context/ARCHITECTURE.md` and `context/UPDATES.md` for why
each design decision was made, what was measured, and what's still open.

## Repository Structure
This repository is organized in several directories, as follows:

- `cert_keys` - ten ECDSA keypairs to be used for signing BSMs
- `falcon_keys` - ten Falcon-512 keypairs to be used for signing certificates (in the context of the paper,
these are the keys a CA would use to sign its certificates and guarantee their integrity under the _Partially Hybrid_
protocol for V2V). **Extension note:** in this checkout, Falcon uses a single keypair per identity for both certificate
signing and message signing (no separate `cert_falcon_keys/`) — a known, stated scoping simplification, not an
oversight; see `context/BUGS.md`.
- `include` - C++ header (.h) library files, including `AttackerVehicle.h` (added in this extension — verify-flooding
attacker simulation)
- `keys` - ten ECDSA keypairs to be used for signing certificates (to be used for guaranteeing certificate integrity
under both classical and _Partially Hybrid_ designs)
- `scripts` - a Python script to generate keypairs for ECDSA and various post-quantum algorithms. **Extension note:**
`generate_keys.py` is currently hardcoded to exactly 10 identities (IDs 0-9) — regenerate/parameterize it first if
an experiment needs more simulated vehicles + attackers than that.
- `src` - C++ source files (.cpp) for PQ-V2Verifier, including `AttackerVehicle.cpp` (added in this extension)
- `trace_files` - sample coordinate trace files for vehicles to use for location data in simulated BSMs. **Extension
note:** `Vehicle::generate_bsm()` indexes into the trace by message count **modulo the trace length**, so a
trace shorter than the number of messages an identity sends wraps back to row 0 (logged once as `[TraceWrap]`)
instead of crashing. This matters mainly for `attackerMatchLegitDuration`, where the attacker's message count isn't
known in advance. At the wrap, speed/heading are computed from the last row to row 0, so a moving trace shows one
position jump; BSM content doesn't affect the latency/drop metrics, and a stationary trace is unaffected. Trace files
for IDs beyond `0.csv` were added/extended for this extension's experiments: `1.csv`/`2.csv` originally duplicated `0.csv`'s
299-row moving trajectory; `2.csv` (the standard attacker ID in most example configs below) was later extended to
a much longer stationary trace (constant position - a parked/roadside attacker device doesn't need to be
"driving" to flood messages) to support large-scale flood benchmarking.

## Minimum Working Example
An Ubuntu 22.04 virtual machine that is pre-configured to compile and run the artifact is archived in OVA format
at [doi:10.5281/zenodo.10160535](https://doi.org/10.5281/zenodo.10160535). This virtual machine was
created and evaluated using Virtualbox version 7.0.8 r156879 (Qt5.15.2), which is freely available from Oracle at
https://www.virtualbox.org. We recommend users and evaluators use the same version to ensure consistency.

## Evaluation Requirements and Supported Environments

### Supported operating system
Ubuntu 22.04 is the only supported operating system.

### Software
Libraries that can be installed through the Ubuntu package manager:
- astyle
- cmake
- doxygen
- gcc
- git
- graphviz
- libboost-dev
- libssl-dev
- ninja-build
- python3-pytest 
- python3-pytest-xdist 
- python3-yaml
- unzip 
- valgrind
- xsltproc

Libraries that need to be built from source (using the below instructions - validated for most recent versions
of these libraries as of September 2023):
- liboqs, a post-quantum algorithm library from Open Quantum Safe (https://github.com/open-quantum-safe/liboqs.git)

No additional software dependencies are required.

### Hardware
No hardware is required beyond a "commodity PC." As defined by the
[NDSS 2024 Call for Artifacts](https://web.archive.org/web/20230930035437/https://secartifacts.github.io/ndss2024/call),
"[a] commodity desktop machine is defined as one with an x86-64 CPU with 8 cores and 16 GB of RAM running a recent Linux
or Windows operating system." **Extension note:** the environment these experiments actually ran on has only 2 CPU cores,
which is directly relevant context for any throughput/timing numbers reported in `context/UPDATES.md` — CPU contention
between concurrently-transmitting simulated vehicles was a measured factor there.


## Installation
It is recommended to begin with a fresh installation of Ubuntu 22.04.

### Setup
Begin by updating all Ubuntu packages to their latest versions:

    sudo apt update
    sudo apt upgrade -y

Next, install dependencies that are required for *PQ-V2Verifier*:

    sudo apt install -y libboost-dev git
    sudo apt install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

### Installing liboqs

Start by creating a placeholder directory for liboqs to be installed into:

    mkdir liboqs-x86

Now, obtain the liboqs source code from GitHub:

    cd $HOME
    git clone -b main https://github.com/open-quantum-safe/liboqs.git

Now, build liboqs:

    cd $HOME
    git clone -b main https://github.com/open-quantum-safe/liboqs.git
    mv liboqs liboqs-intel
    cd liboqs-intel
    mkdir build && cd build
    cmake -GNinja -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX=$HOME/liboqs-x86 ..
    ninja
    ninja install

### Install *PQ-V2Verifier*

Obtain the *PQ-V2Verifier* source code:

    cd $HOME
    git clone https://github.com/pvhaddad/PQ-V2Verifier-Extension.git pq-v2verifier

  Build *PQ-V2Verifier*:

    cd pq-v2verifier
    mkdir build && cd build
    cmake ../
    make

## Running *PQ-V2Verifier* in test mode 
*These instructions are specifically for artifact evaluation or other scenarios where no software-defined radio are available 
for over-the-air experiments*

*PQ-V2Verifier* is released to the community in open source in order to support study of the integration of post-quantum cryptography into V2V
environments that use the IEEE 1609.2 standard protocols for security. The base artifact does not come with pre-built post-quantum protocols;
rather, it supplies the starter code needed to rapidly prototype and implement post-quantum V2V authentication protocols of indefinite design using
NIST-approved post-quantum algorithms, including starter code to support signing and verifying messages using the Falcon-512
algorithm (see `src/v2vcrypto.cpp`), as this algorithm is very likely the only NIST-approved post-quantum algorithm that can feasibly 
be used in real-world V2V applications (see the NDSS 2024 paper for details). **Extension note:** in this checkout, that
starter code has been built out into an actual working Falcon-512 message path with certificate fragmentation -
see "Running with Falcon-512" below.

*PQ-V2Verifier* comes set up to run with the current IEEE 1609.2 protocol, which uses ECDSA P.256 digital signatures for message signing and
verification. A functional example can be run as follows:

Open two terminal windows (in simulation with no radio devices, one will play the role of a vehicle transmitting signed messages and the other 
will play the role of receiving and verifying those messages).

In the first terminal, start the receiver:

    cd $HOME/pq-v2verifier
    ./build/pq-v2verifier dsrc receiver nogui --test

The last command will start a *PQ-V2Verifier* instance configured to use the DSRC communication protocol (ignored in this simulation mode), play the role of the receiver, avoid using any graphical user interface (such interfaces are inherited from *V2Verifier* and not yet supported in *PQ-V2Verifier*), and run in test mode (i.e., with no radio devices).

In the second terminal, start the transmitter:

    cd $HOME/pq-v2verifier
    ./build/pq-v2verifier dsrc transmitter nogui --test

This will start a second *PQ-V2Verifier* instance that again uses DSRC, this time plays the role of the transmitter, does not use a graphical interface, and runs in test mode.

In the transmitter terminal, you should immediately see output indicating that messages are being transmitted. In an experimental setup with radio devices, this would send the V2V messages to a radio for over-the-air transmission; here, they are simply sent through a network pipe to the receiving terminal.

In the receiver terminal window, you should see output indicating that messages are being received, the contents of those messages (e.g., the stated heading of the transmitting "vehicle"), and an indication of whether or not the digital signature on each received message has been successfully verified.

If all has gone as described above, the availability and functionality of *PQ-V2Verifier* has been demonstrated. 

**Note on `--test` mode:** for any experiment with more than one simulated vehicle (`numVehicles` + `numAttackers`
> 1), `--test` mode is not optional. Non-`--test` mode uses mismatched UDP ports between the transmitter (52001)
and receiver (4444) for ECDSA, and Falcon's non-`--test` framing path is not implemented at all (it exits with an
explicit error) - so `--test` is the only mode in which multi-vehicle traffic, and Falcon in general, actually
work.

## Running with Falcon-512

Set `"signatureScheme": "falcon"` in `config.json` (default is `"ecdsa"` if the field is omitted) and run the same
two-terminal receiver/transmitter example above. The Falcon-512 path signs and verifies both the BSM and a
certificate, using the same two-terminal, `--test`-mode flow as ECDSA.

### Certificate fragmentation cycle

A Falcon-512 certificate (public key + its own signature) is too large to re-send whole on every BSM without
exceeding the 2304-byte DSRC MAC-layer frame cap. Instead, the certificate is split into `m` segments and
broadcast on a repeating cycle: `m` segment-carrying messages, then `n` hash-only messages (every message, segment
or hash-only, also carries a truncated hash of the full certificate for cache-lookup/integrity purposes). Both are
configurable in `config.json`: `certCycleSegmentCount` (`m`, default `2`) and `certCycleHashOnlyCount` (`n`,
default `4`), giving a 6-message cycle by default. Each segment-carrying message also carries `fragment_count`
(= `m`) on the wire, so the receiver learns `m` from the sender rather than from its own config. The receiver
reconstructs the certificate from all `m` segments before it can verify a sender's messages - the first `m - 1`
messages from any given sender will report as invalid with an explicit "no reconstructed certificate yet" reason in
the log (distinct from a real signature failure) until reconstruction completes; this is expected, fail-closed
behavior, not a bug.

This fragmentation/reconstruction logic is now defended against fragment-buffer-flooding attacks by the spam
filter (per-sender buffer cap + TTL eviction, plus a global cap across all senders - see "Project Status"
below). Certificate-churn (an attacker rotating fabricated sender identities) is a distinct, still-deferred
attack variant - see `context/CORRECTIONS.md` and `context/ARCHITECTURE.md` for the corrected threat model.

## Simulating Verify-Flooding Attacks

The base artifact simulates only well-behaved (legitimate) transmitting vehicles. This checkout adds
`AttackerVehicle`, a simulated malicious/compromised vehicle that floods the receiver with expensive-to-verify or
invalid messages - the DoS vector this extension studies. Configure via `config.json` (see "Customizing
Experiments" below for the exact fields): set `numAttackers` > 0, choose an `attackerMode`
(`"expensive_valid"` - valid Falcon-512 signatures sent as fast as possible, or `"invalid_signature"` - corrupted
signatures, still costing a full verify attempt before rejection), and set `numAttackerMessages`.

Attacker vehicle IDs occupy the range immediately above the legitimate vehicle IDs (`[numVehicles, numVehicles +
numAttackers)`), so legitimate vs. attacker role is always derivable from the sender ID alone. Attacker trace
files (for BSM location content) are required the same as for any other vehicle ID - see the `trace_files` note
above.

**Measured finding (see `context/UPDATES.md` Updates 6-7 for full detail and evidence):** at the scales tested (up to a
single attacker sending 20,000 messages as fast as possible), this attack shows no measurable degradation to
legitimate traffic - 0% additional drop rate, 0% deadline-miss ratio. This traces directly to Falcon-512's
sign/verify cost asymmetry: signing (what the attacker's own thread must do to produce each message) measured at
~3.58ms/message average, versus verification (what the receiver does) at ~0.033ms/message average - roughly
109x. A single attacker's own signing cost self-limits it to roughly 279 messages/second, far below what would be
needed to meaningfully stress the receiver's measured ~30,000 messages/second theoretical verify capacity.
Multi-attacker/distributed flooding was considered and deliberately excluded as out of scope - this project's
threat model is a single malicious/compromised vehicle, not a coordinated multi-sender DDoS.

## Customizing Experiments
The generic experiment described above can be adjusted in the following ways, via `config.json`:

### Original fields
1. `numVehicles` - the number of simulated legitimate vehicles sending BSMs.
2. `numMessages` - the number of BSMs each legitimate vehicle transmits before the simulation terminates.

### Extension fields
3. `signatureScheme` - `"ecdsa"` (default) or `"falcon"`. Selects the signature algorithm for the whole run (both
legitimate and attacker traffic).
4. `numAttackers` - number of simulated attacker vehicles (default `0`, i.e. no attack - an old `config.json`
without this field behaves identically to the base artifact). Additive to `numVehicles`, not carved out of it, so
the legitimate traffic volume stays fixed across an attacker-ratio sweep.
5. `attackerMode` - `"expensive_valid"` (default) or `"invalid_signature"`. See "Simulating Verify-Flooding
Attacks" above.
6. `numAttackerMessages` - number of messages each attacker vehicle sends (default `0`).
7. `certCycleHashOnlyCount` - Falcon-only; `n` in the certificate transmission cycle (default `4`). Ignored when
`signatureScheme` is `"ecdsa"`.
7a. `certCycleSegmentCount` - Falcon-only; `m`, the number of segments the certificate is split into (default `2`).
Used by the transmitter, which puts it on the wire as `fragment_count` (a 1-byte field that adds 2 bytes to every
segment-carrying frame, including alignment padding; hash-only frames are unchanged). Valid range: from the
smallest `m` whose worst-case segment-carrying frame fits the 2304-byte DSRC cap (checked at startup by computed wire
size; for Falcon-512 that is `m >= 2`, and `m = 1` is rejected at 2582 B) up to 16. Out-of-range values exit with an
error. **Interaction with `bufferTtlMs`:** a legitimate sender's segments arrive `(m - 1) * 100` ms apart, and the spam
filter checks the buffer's age when the last one arrives, so the TTL needs headroom. Startup prints a warning when
`bufferTtlMs <= (m - 1) * 100 + 50`, along with the largest safe `m` for that TTL. The TTL is never scaled automatically.
**The default `bufferTtlMs` of 500 ms supports roughly `m <= 5`.**
8. `attackerMatchLegitDuration` - `false` (default) or `true`. When `true`, each attacker keeps flooding until every
legitimate vehicle has finished transmitting, instead of stopping after `numAttackerMessages` (which is then ignored),
so the flood overlaps the whole legitimate run. Each legitimate vehicle reports completion (`[LegitDone]`) as its send
loop returns, and the attacker checks before each message (and again just before sending it). A wall-clock backstop,
`ceil(numMessages * 100 * attackerDurationMargin)` ms (100ms = nominal legit inter-message delay), stops the attacker
only if a legit thread hangs without reporting. The attacker's transmitter prints `[AttackerRunSummary]` with
`stop_reason` (`completion` or `backstop_timeout`), the actual `messages_sent`, `actual_elapsed_ms`, and
`completion_lag_ms` (attacker stop time minus the last legit vehicle's completion). A `backstop_timeout` also prints
`[AttackerBackstopFired]` and should be treated as a suspect run, not normal variation. The receiver reads the same
flag: it expects only `numMessages * numVehicles` legit messages, keeps receiving until 5s pass with no message
(`[ReceiveEndOfRun]`, so each run ends ~5s after the last send), and its `INCOMPLETE RUN` check counts legitimate
messages only. Applies identically to every `attackerMode`.
9. `attackerDurationMargin` - backstop multiplier on the nominal legit run length (default `2.0`); only used when
`attackerMatchLegitDuration` is `true`. The slowest legit run measured under a full-length flood (300 messages) took
44,842ms (1.495x nominal), so the 60s default leaves +15.2s (34%) headroom, while a backstop-terminated run (~60s plus
the 5s receiver tail) still finishes well inside the Phase 4 harness's 120s per-process timeout.
10. `attackerFloodRateCapPerSec` - opt-in send-rate cap in messages/second, default `0` (disabled/unthrottled - no
change from prior behavior for any mode when left unset). Only takes effect when `attackerMode` is
`"cheap_invalid_signature"`: that mode skips real signing entirely, so its send rate is otherwise bounded only by
CPU, not by anything resembling a real attacker (who is bounded by the physical channel). `expensive_valid` and
`invalid_signature` ignore this field - their real per-message signing cost is itself the variable being measured
for those modes. The requested rate is converted to a per-message delay in whole milliseconds (rounded, floored at
1ms), so it can't be hit exactly: `[AttackerFloodRateCap]` prints the *nominal* rate (`1000/delay_ms`, a constant
computed at startup, labelled `achieved_rate_per_sec` in the log), and the actual rate is lower because `sleep_for`
overshoots and each message takes time (measured ~790 msg/sec at the 1010 setting on the Update 21 machine). See
`context/UPDATES.md` Update 21 for the ~1010 msg/sec derivation used in the Phase 4 duration-mode re-run, and
`context/CORRECTIONS.md` #20 for the nominal-vs-measured correction.

The data that vehicles use to fill BSMs (e.g., with their location, speed, heading) is based on the trace files
found in the `trace_files` directory. For the minimum working example, where `config.json` specifies one transmitting
vehicle, one trace file (`0.csv`) is provided. If more vehicles (or attackers) are desired, more trace files must be provided (the 
total number of trace files should match the number of vehicles plus attackers specified in `config.json`, and
each file needs at least as many rows as that identity's message count - see the `trace_files` note above). Each trace file
consists of comma-separated lines in the format `latitude,longitude,elevation,speed,heading`; for example, 
`10,25,0,60,90` indicates a location at coordinates 10N, 25E with zero elevation, a speed of 60 km/hr, and 
a heading of 90 degrees (due west). **Extension note:** only the first three columns (`latitude,longitude,elevation`)
are actually read by `Vehicle::load_trace()`/`generate_bsm()` - `speed` and `heading` in the trace file are
ignored; they're recomputed from consecutive position rows instead, assuming a fixed 100ms interval between rows
regardless of the vehicle's actual transmit rate (this fixed-100ms assumption is a modeling simplification, not
derived from real elapsed time - see `context/BUGS.md` if this matters for an experiment involving a fast/unpaced
sender, such as an attacker).

## Benchmarking Output

When running with `signatureScheme: "falcon"`, the receiver prints diagnostic and benchmarking information not
present in the base artifact, all in `--test` mode, no external tooling required:

- **`[FalconCertCycle]`** lines - per-message certificate cycle state (segment vs. hash-only, fragment set ID,
reconstruction success/failure).
- **`[FloodRateCheck]`** (transmitter) - actual measured wall-clock send rate per vehicle, independent of the
configured nominal delay - useful for confirming an attacker's flood is genuinely unpaced.
- **`[FalconSignCost]`** (transmitter) / the verify-cost line in the metrics summary (receiver) - isolated
Falcon `sign()`/`verify()` call timing (average and p95), separate from surrounding socket/bookkeeping overhead.
- **`Falcon Verify Metrics Summary`** (receiver, printed once at the end of a run) - legitimate-vehicle message
counts by outcome (valid / invalid signature / no cert yet / expired / invalid cert signature), drop rate
(excluding the "no cert yet" startup artifact), deadline-miss ratio (>100ms), and tail latency (p50/p95/p99/max)
for legitimate valid messages. Self-reports if the run ended early (see the socket-timeout note below) so partial
results can't be mistaken for a complete run.

## Known Limitations and Environment Notes

- **Falcon uses one keypair per identity** for both certificate signing and message signing (no independent
`cert_falcon_keys/`) - a stated scoping simplification, not an oversight.
- **Non-`--test` (SDR/DSRC hardware) mode does not support Falcon** - it exits with an explicit error. ECDSA's
non-`--test` framing path exists but is independently broken for multi-vehicle traffic due to a transmitter/receiver
port mismatch (52001 vs. 4444) - use `--test` mode for everything.
- **Large-scale flood benchmarking requires raising the OS UDP receive buffer ceiling**, or transient kernel-level
packet loss can occur under a fast, bursty attacker (this is a network-layer artifact, distinct from this
project's verify-exhaustion/compute-layer thesis - see `context/UPDATES.md` Update 6). Run
`sudo sysctl -w net.core.rmem_max=33554432` before any flood test sending thousands of messages. This setting is
intentionally not persisted to `/etc/sysctl.conf` and resets on reboot.
- **On the WSL2 development machine, `systemd-timesyncd` stepped the wall clock forward ~0.4-0.75 s every 32 s
in multi-hour blocks (cause not established), which shows up as spurious late messages (`[DeadlineMiss]`) and spurious
`STALE` filter drops for messages in flight at a step (~1-3% of trials).** Expect it to recur on long unattended runs;
see `context/BUGS.md` and `context/CORRECTIONS.md` #21. Before a long run disable NTP (`sudo timedatectl set-ntp false`; the
sweep driver refuses to start otherwise); the harness also flags trials whose late/dropped messages coincide with a
journal-detected clock step (`phase4_clockstep_detect.py`).
- **`scripts/generate_keys.py` is hardcoded to exactly 10 identities** (IDs 0-9) - needs parameterizing before an
experiment can use more than 10 total vehicles + attackers.
- Legitimate vehicle trace files (`1.csv` onward) currently duplicate `0.csv`'s trace content - a known
simplification (non-diverse BSM content across legitimate vehicles), fine for latency/drop-rate measurement but
worth noting if trace diversity matters for a given experiment.

## Project Status

As of this README revision: Falcon-512 message path, certificate fragmentation, and a spam filter defense
(fragment-index validation, segment-hash checking, a capped/TTL'd certificate-reconstruction buffer, and a
fast-path cache for repeat senders) are all implemented and verified — the spam filter passed all 5 of its
functional/correctness checkpoints. A full defended-vs-undefended benchmark matrix has been run at N=75 trials
per cell across three attack conditions (no attack, valid-but-expensive flooding, invalid-signature flooding)
times filter on/off, plus a fourth attack-mode pair (cheap/unsigned-cost flooding) also run at N=75. Headline
result: enabling the spam filter collapses certificate-signature verification from essentially every message
under flood (~2597/2600) to exactly 2 — a ~99.9% reduction in attacker-driven crypto cost — at a small,
self-healing cost to legitimate traffic. See `context/PROJECTDESC.md` (and `context/UPDATES.md` for the full dated log) for
the complete engineering history, all measured evidence, corrections to earlier findings, and every open
question.

**Current scope (Update 23):** the paper now focuses on how certificate segmentation (m segments + n hash-only
messages per cycle) affects verification timing. The full m x n grid (L=3-6, m=2-5, n=0-6, N=5) is complete;
merged results live in `exports/seg_grid/` (see `exports/seg_grid/data_dictionary.md`). Details and caveats are in
`context/UPDATES.md` Update 23.

## Reproducing Results

The benchmark harness lives in `scripts/phase4_harness/`. Scripts locate the repository from their own path, so
they run from any clone; shell drivers also accept a `REPO=/path/to/checkout` override. The segmentation grid is
driven by `phase4_seg_grid.sh` (wrapping `phase4_mn_sweep.sh`) and merged with `phase4_seg_postgrid.py`. Raw
per-trial logs are written to `phase4_raw_logs/`, which is not tracked (tens of GB); the merged, analysis-ready
outputs are committed under `exports/`. See "Known Limitations and Environment Notes" above for the required
`rmem_max` and NTP preflight settings.

## Note on Committed Keys

The private keys under `keys/`, `cert_keys/`, and `falcon_keys/` are **test-only** keys, carried over from the
upstream artifact so the testbed runs out of the box. They secure nothing and must never be used outside this
testbed. Regenerate them with `scripts/generate_keys.py` if needed.
