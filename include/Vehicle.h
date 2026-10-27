// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

//
// Created by geoff on 10/14/21.
//

#ifndef CPP_VEHICLE_H
#define CPP_VEHICLE_H

#include <string>
#include <vector>
#include <array>
#include <optional>
#include <set>
#include <limits>
#include <unordered_map>
#include <cstring>
#include <chrono>
#include <functional>
#include <atomic>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>

#include "ieee16092.h"
#include "bsm.h"
#include "v2vcrypto.h"
#include "arguments.h"


// attackerMatchLegitDuration: legit threads report completion here; attacker threads poll it
// from inside their own transmit_loop (thread join can't be observed until everything is done).
// One instance, owned by main.cpp's transmitter branch, outlives every thread that uses it.
struct legit_completion_signal {
    const int num_legit_vehicles;                 // from config numVehicles, not assumed
    std::atomic<int> legit_vehicles_done{0};
    std::atomic<int64_t> all_done_steady_ns{0};   // steady_clock time the LAST legit vehicle finished
    explicit legit_completion_signal(int n) : num_legit_vehicles(n) {}
    bool all_done() const { return legit_vehicles_done.load() >= num_legit_vehicles; }
};

enum class transmit_stop_reason { COUNT_REACHED, COMPLETION, BACKSTOP_TIMEOUT };

// Plain aggregate on purpose - no conversion operator or constructors, so any leftover code
// still expecting transmit_loop's old int return fails to compile instead of converting.
struct transmit_result {
    int sent;
    transmit_stop_reason reason;
    std::chrono::steady_clock::time_point stopped_at;
};


class Vehicle {

private:
    std::string hostname;
    uint8_t number;
    EC_KEY *private_ec_key = nullptr, *cert_private_ec_key = nullptr;
    ecdsa_explicit_certificate vehicle_certificate_ecdsa;

    unsigned char certificate_signature[72];
    unsigned int certificate_buffer_length;

    uint8_t falcon_secret_key[OQS_SIG_falcon_512_length_secret_key];   // this vehicle's Falcon signing key, loaded from falcon_keys/<n>/falcon.key
    uint8_t falcon_public_key[OQS_SIG_falcon_512_length_public_key];   // this vehicle's own Falcon public key, embedded into its cert
    falcon_explicit_certificate vehicle_certificate_falcon;

    unsigned char certificate_signature_falcon[OQS_SIG_falcon_512_length_signature];
    unsigned int certificate_signature_buffer_length_falcon;

    // Falcon cert transmission cycle — transmit-side state (Update 4 / Phase 1). Per-instance,
    // no locking needed: each Vehicle/AttackerVehicle only ever transmits from one thread.
    uint32_t falcon_cycle_position = 0;             // 0..(M+n-1), position within current cycle
    uint32_t falcon_cycle_fragment_set_id = 0;       // increments once per NEW cycle
    uint32_t falcon_cycle_hash_only_count_n = 4;     // n, set from transmit()'s parameter
    uint32_t falcon_cycle_segment_count_m = 2;       // m, set from transmit()'s parameter
    std::vector<std::vector<uint8_t>> falcon_cycle_segments; // cached CFrag output (m entries), valid for one whole cycle
    std::array<uint8_t, 8> falcon_cycle_full_hash{}; // cached Full Hash, valid for one whole cycle
    // Sign-once-per-vehicle-lifetime guard (Phase 3 prerequisite fix, context/UPDATES.md Update 9):
    // once true, generate_falcon_spdu never re-signs the cert / rebuilds the blob / re-derives
    // full_hash / re-fragments again for this vehicle - full_hash must stay byte-stable across
    // cycles for the spam filter's hashedId8 cache to ever hit across cycles.
    bool falcon_cert_prepared = false;

    // Backlog-mechanism investigation (Phase 2 follow-up): per-message wall-clock gap between
    // successive generate_falcon_spdu calls on THIS vehicle's own send thread - lets a trend
    // (steady vs. degrading send rate over a long run) be distinguished from a one-time average,
    // which FloodRateCheck's total-elapsed/count figure cannot reveal on its own.
    std::chrono::steady_clock::time_point falcon_last_send_start;
    bool falcon_last_send_start_set = false;
    std::vector<double> falcon_send_gap_ms;

    // Falcon cert transmission cycle — receive-side state (Update 4 / Phase 1). Naive
    // reset-on-mismatched-fragment_set_id, NOT yet flood-resistant — Phase 3 wraps this same
    // buffer with a cap=1-per-sender/TTL/reject-on-mismatch defense.
    struct falcon_cert_reconstruction_state {
        uint32_t fragment_set_id = 0;
        uint8_t fragment_count = 0; // m of the cycle being reassembled
        std::array<std::optional<std::vector<uint8_t>>, FALCON_CERT_CYCLE_M_MAX> segments;
    };
    struct falcon_reconstructed_cert_entry {
        // Stored as raw bytes, NOT a live falcon_explicit_certificate object: that struct embeds
        // a std::string (common_cert_fields::hostname), and reconstructing one via memcpy from
        // wire bytes leaves its internal (SSO) pointer referring to the sender-side object's
        // address. It looks fine until something copy-constructs the "reconstructed" struct
        // (e.g. inserting this entry into an unordered_map) - that recursively invokes
        // std::string's copy constructor, which dereferences the stale pointer and crashes.
        // Treating it as opaque bytes end-to-end (matching how falcon_verify/sha256sum already
        // treat certs elsewhere in this codebase) sidesteps the issue entirely.
        unsigned char cert_bytes[sizeof(falcon_explicit_certificate)] = {};
        unsigned int cert_sig_len = 0;
        unsigned char cert_sig[OQS_SIG_falcon_512_length_signature] = {};
        // Full SHA-256 of the reconstructed blob (the digest ccons_falcon already computes to
        // check the 8-byte full_hash). Filled only in verify-once mode (Update 23); key into
        // falcon_verified_cert_digests.
        std::array<uint8_t, 32> full_digest{};
    };
    std::unordered_map<uint8_t, falcon_cert_reconstruction_state> falcon_cert_buffers;
    std::unordered_map<uint8_t, falcon_reconstructed_cert_entry> falcon_reconstructed_certs;

    // Receiver-side throughput trend tracking (Phase 2 diagnostic follow-up: transient-burst
    // vs sustained-rate-mismatch investigation). Falcon-only. Prints periodically, not
    // per-message, so a killed/timed-out run's log still contains a real time-series of
    // achieved processing rate rather than only a start/end snapshot.
    std::chrono::steady_clock::time_point falcon_receive_progress_start;
    bool falcon_receive_progress_started = false;
    uint64_t falcon_receive_progress_count = 0;

    // Backlog-mechanism investigation (Phase 2 follow-up: why does receive-side non-crypto
    // overhead sit close enough to real-time capacity to let a backlog accumulate under
    // sustained flood?). Measures wall-clock gap between successive verify_message_falcon call
    // starts - since receive_loop's only per-iteration work is read_frame + this verify call +
    // a few print statements, this gap captures the FULL loop iteration cost (recv + all
    // prints + verify), not just the isolated crypto cost already tracked by
    // falcon_message_verify_times_ms. Falcon-only; doesn't touch receive_loop's shared body.
    std::chrono::steady_clock::time_point falcon_last_verify_start;
    bool falcon_last_verify_start_set = false;
    std::vector<double> falcon_loop_iteration_gap_ms;
    // Isolates just the recvfrom() syscall duration, to split the loop-iteration gap above into
    // "blocked waiting for the next packet" (legitimate, if the receiver is keeping pace) vs.
    // "real CPU-bound processing" (the actual bottleneck, if this is small while the total gap
    // is large).
    std::vector<double> falcon_recvfrom_times_ms;

    // Sign/verify cost isolation (Phase 2 diagnostic: is the attacker's observed ~220 msg/sec
    // ceiling set by Falcon SIGNING cost on the attacker's own thread, or by the receiver's
    // Falcon VERIFY capacity? Falcon sign/verify cost is asymmetric - signing is typically far
    // more expensive - so this can't be inferred from combined throughput alone). Falcon-only,
    // wraps just the falcon_sign()/falcon_verify() calls themselves, not the surrounding
    // socket/print overhead already captured by FloodRateCheck/ReceiverProgress.
    std::vector<double> falcon_message_sign_times_ms;   // transmit side, every message
    std::vector<double> falcon_cert_sign_times_ms;      // transmit side, once per cycle (position 0)
    std::vector<double> falcon_message_verify_times_ms; // receive side, every message
    std::vector<double> falcon_cert_verify_times_ms;    // receive side, whenever a cached cert exists
    static double percentile_ms(std::vector<double> values, double p);

    // Phase 2 (Update 4 step 2) baseline-benchmark instrumentation — Falcon-only, accumulated
    // in-process during receive_loop and summarized once at the end of the run (see
    // print_falcon_verify_metrics_summary). No external analysis script: this same process
    // already holds every message's outcome/timing in memory as it verifies, so there's nothing
    // to gain from printing it out and parsing it back in from a log.
    enum class falcon_verify_outcome : uint8_t {
        VALID = 0, INVALID_SIGNATURE = 1, NO_CERT_YET = 2, EXPIRED = 3, INVALID_CERT_SIGNATURE = 4,
        SPAM_FILTERED = 5, // Phase 3: dropped by a cheap check before any crypto ran
        COUNT = 6
    };
    struct falcon_verify_metrics_record {
        uint8_t vehicle_id;
        falcon_verify_outcome outcome;
        double latency_ms; // this BSM's own embedded send timestamp -> this verify call's completion
    };
    std::vector<falcon_verify_metrics_record> falcon_metrics;
    // num_vehicles is the legitimate/attacker boundary (vehicle_id < num_vehicles => legitimate),
    // same convention as main.cpp's existing attacker-ID-range logic (Update 3). expected_total
    // is receive()'s own num_msgs, passed through so the summary can self-report whether the run
    // actually completed or terminated early on a receive timeout (Update 6 follow-up) - the
    // summary is computed purely from whatever landed in falcon_metrics regardless, so its
    // numbers are never wrong, but without this a partial run's numbers could be mistaken for a
    // complete run's by anyone reading only this block.
    // legit_only_completeness (attackerMatchLegitDuration): the attacker count isn't known in
    // advance, so INCOMPLETE RUN compares legit_total against expected_total (legit-only) instead
    // of the whole falcon_metrics size.
    void print_falcon_verify_metrics_summary(int num_vehicles, int expected_total,
                                             bool legit_only_completeness = false);

    // Per-message timing probes (Update 23). Enabled only when env PQV2V_TIMING_PREFIX is set;
    // otherwise nothing is recorded or written and the receiver's output is unchanged. All times
    // are steady_clock ns relative to falcon_steady_ref (captured at receive() start):
    //   t0 = frame off the socket (right after recvfrom), t1 = cert reassembled + full-hash match
    //   (completing segment of a cycle only), t2 = cert falcon_verify done (VERIFIED_NOW only),
    //   t3 = message falcon_verify done and outcome classified.
    // The receiver is single-threaded (receive_loop is one sequential loop), so one buffer is safe;
    // it is reserved up front in receive() and written to CSV only after the loop ends.
    static constexpr int64_t FALCON_TIMING_NA = std::numeric_limits<int64_t>::min();
    enum class falcon_cert_path : uint8_t { NA = 0, VERIFIED_NOW = 1, CACHED = 2 };
    struct falcon_timing_record {
        uint8_t sender_id;
        uint32_t seq;               // per-sender arrival index (no seq on the wire)
        cert_message_kind kind;
        falcon_verify_outcome outcome;
        falcon_cert_path cert_path;
        int64_t t0, t1, t2, t3, cert_verify_ns, msg_verify_ns;
    };
    std::vector<falcon_timing_record> falcon_timing;
    size_t falcon_timing_reserved = 0;
    std::array<uint32_t, 256> falcon_timing_seq{};
    std::chrono::steady_clock::time_point falcon_steady_ref;
    std::chrono::system_clock::time_point falcon_system_ref;
    int64_t falcon_rx_t0_ns = FALCON_TIMING_NA;             // set by the Falcon read_frame
    cert_message_kind falcon_rx_kind = cert_message_kind::HASH_ONLY; // set at verify_message_falcon entry
    const char *falcon_timing_prefix = nullptr;             // PQV2V_TIMING_PREFIX, null = off
    bool falcon_wall_clock_step = false;
    // Verify-once mode (Update 23, Fig. 3 version B; env PQV2V_CERT_VERIFY_MODE=once, filter-off
    // path only): a cert whose full digest is in this set has already passed cert falcon_verify,
    // so later messages skip it. Populated only after a successful cert verify. Keyed by digest
    // alone - it cannot distinguish senders, which is fine under A_off (one cert per sender).
    bool falcon_cert_verify_once = false;
    std::set<std::array<uint8_t, 32>> falcon_verified_cert_digests;
    int64_t falcon_ns_since_ref(std::chrono::steady_clock::time_point tp) const {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(tp - falcon_steady_ref).count();
    }
    void record_falcon_timing(uint8_t sender_id, falcon_verify_outcome outcome, falcon_cert_path cert_path,
                              int64_t t1, int64_t t2, int64_t t3, int64_t cert_verify_ns, int64_t msg_verify_ns);
    void write_falcon_timing_files();

    // ---- Phase 3 spam filter (context/UPDATES.md Update 4/9) — entirely NEW structures/state, kept
    // separate from falcon_cert_buffers/falcon_reconstructed_certs above so the filter-ON and
    // filter-OFF paths can never interfere with each other regardless of which is active
    // (only one runs per process, per spam_filter_enabled, but the separation also makes the
    // "filter OFF is byte-identical to Phase 2" regression invariant trivially true by
    // construction rather than by careful bookkeeping). Placed after falcon_verify_outcome
    // above since spam_filter_record_outcome's declaration needs that type already visible. ----

    // Buffer: replaces the Phase-1 naive reset-on-mismatch with cap=1-per-sender + TTL
    // eviction (context/UPDATES.md Update 4's FragmentBuffer spec). Keyed by sender_id (vehicle_id) -
    // reconstruction-in-progress is inherently per-sender.
    struct spam_filter_fragment_buffer {
        uint32_t fragment_set_id = 0;
        uint8_t fragment_count = 0; // m, recorded when the buffer opens at fragment_index 0
        std::array<std::optional<std::vector<uint8_t>>, FALCON_CERT_CYCLE_M_MAX> segments;
        std::chrono::steady_clock::time_point first_seen_ts; // for bufferTtlMs eviction
    };
    // Cache: re-keyed from vehicle_id to the cert's hashedId8 (full_hash, as a uint64_t - see
    // falcon_full_hash_to_key) so cert-churn is exact (a fabricated cert's hash never matches
    // anything cached) and so a legit vehicle's cache entry survives cert-cycle re-keying.
    // Holds ONLY cert-sig-VERIFIED certs (context/UPDATES.md Update 9 correctness fix) - a cache hit
    // safely authorizes skipping cert-sig re-verify.
    struct spam_filter_cert_cache_entry {
        unsigned char cert_bytes[sizeof(falcon_explicit_certificate)] = {};
        unsigned int cert_sig_len = 0;
        unsigned char cert_sig[OQS_SIG_falcon_512_length_signature] = {};
        std::chrono::steady_clock::time_point cached_at; // refreshed on hit - LRU basis for the global cap
    };
    std::unordered_map<uint8_t, spam_filter_fragment_buffer> spam_filter_buffers;      // cap=1 open buffer per sender, enforced in logic
    std::unordered_map<uint64_t, spam_filter_cert_cache_entry> spam_filter_cert_cache; // keyed by hashedId8

    // Per-sender transmission-frequency state (cheap check #1/#2) - keyed on the BSM's own
    // embedded SEND timestamp, not receiver arrival time (Update 8: this 2-core VM bunches
    // legit arrivals after a scheduling spike: an arrival-time gate would false-drop legit
    // traffic; a flooding attacker's send-timestamps stay ~0 apart regardless).
    std::unordered_map<uint8_t, std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>> falcon_last_seen_sendts;
    // Actual datagram byte count for the message CURRENTLY being verified, set by the Falcon
    // read_frame lambda in receive() right after recvfrom() returns, read by the length cheap
    // check. Not per-sender state (only ever valid for "whatever verify_message_falcon is
    // processing right now" - receive_loop is strictly sequential, one message at a time, so
    // this is safe as a single scalar rather than needing to be threaded through call args).
    ssize_t falcon_last_rx_bytes = -1;

    // Granular drop-reason accounting (Phase 4's ablation needs to distinguish these).
    enum class spam_drop_reason : uint8_t {
        RATE = 0, LENGTH = 1, NO_CACHE = 2, STALE = 3, FRAG_INDEX = 4, SEG_HASH = 5,
        BUFFER_CAP = 6, BUFFER_TTL_EVICT_INCOMPLETE = 7,
        COUNT = 8
    };
    // Split legit/attacker (context/UPDATES.md Update 16) so the ablation can see which sender type
    // triggered which cheap-reject reason, instead of one combined total.
    std::array<int, (size_t) spam_drop_reason::COUNT> legit_spam_drop_reason_counts{};
    std::array<int, (size_t) spam_drop_reason::COUNT> attacker_spam_drop_reason_counts{};

    // Config, threaded from receive()'s new parameters (main.cpp reads these from config.json).
    bool spam_filter_enabled = false;
    double spam_filter_min_gap_ms = 50.0;
    double spam_filter_admit_ms = 100.0;
    double buffer_ttl_ms = 500.0;
    uint32_t spam_filter_global_state_cap = 512;
    // Legit/attacker boundary, usable LIVE during the receive loop (unlike receive()'s own
    // num_vehicles parameter, which only exists post-hoc at the very end, forwarded straight
    // into print_falcon_verify_metrics_summary). context/UPDATES.md Update 16.
    int spam_filter_num_vehicles = 0;

    static uint64_t falcon_full_hash_to_key(const unsigned char full_hash[8]);
    // Global LRU/TTL cap (context/UPDATES.md Update 9's resolved churn decision): bounds total
    // spam_filter_buffers + spam_filter_cert_cache entries. Called after any insertion into
    // either structure; evicts the globally-oldest entry (by first_seen_ts/cached_at) across
    // BOTH structures until back within spam_filter_global_state_cap.
    void enforce_spam_filter_global_cap();
    // Shared drop node: one push per dropped message (keeps falcon_metrics.size() ==
    // expected_total holding), counts the reason, logs one line, returns false.
    bool spam_filter_drop(uint8_t sender_id, bool is_attacker, spam_drop_reason reason, const char *reason_label,
                           std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> send_ts);
    // Shared "record a non-drop, non-admitted outcome" (NO_CERT_YET pending, or terminal
    // INVALID_CERT_SIGNATURE) - same metrics-push/DeadlineMiss consistency as the drop node,
    // but NOT counted as a spam_drop_reason since these aren't cheap-check rejections.
    bool spam_filter_record_outcome(uint8_t sender_id, falcon_verify_outcome outcome,
                                     std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> send_ts);
    // spam_filter_admit / spam_filter_verify_falcon are declared later, alongside
    // verify_message_falcon - they take falcon_spdu&, which isn't defined yet at this point
    // in the class body (a member function's PARAMETER LIST, unlike its body, is parsed in
    // an "incomplete class" context, so a nested type used there must already be visible).

    std::vector<std::vector<float>> timestep;
    std::vector<float> timestep_data;
    bool trace_wrap_logged = false; // generate_bsm logs [TraceWrap] once, on the first wraparound

    struct ecdsa_spdu {
        uint8_t vehicle_id;
        uint32_t llc_dsap_ssap = 43690;
        uint8_t  llc_control = 3;
        uint32_t llc_type = 35036;
        uint8_t wsmp_n_subtype_opt_version = 3;
        uint8_t wsmp_n_tpid = 0;
        uint8_t wsmp_t_header_length_and_psid = 32;
        uint8_t wsmp_t_length = 0;
        unsigned int signature_buffer_length;
        unsigned int certificate_signature_buffer_length;
        ieee1609dot2data_ecdsa_explicit data;
        unsigned char signature[72]; // 72 bytes is the size of the DER-encoded ECDSA signature
    };

    struct falcon_spdu {
        uint8_t vehicle_id;
        uint32_t llc_dsap_ssap = 43690;
        uint8_t  llc_control = 3;
        uint32_t llc_type = 35036;
        uint8_t wsmp_n_subtype_opt_version = 3;
        uint8_t wsmp_n_tpid = 0;
        uint8_t wsmp_t_header_length_and_psid = 32;
        uint8_t wsmp_t_length = 0;
        unsigned int signature_buffer_length; // actual length from falcon_sign's out-param
        ieee1609dot2data_falcon_explicit data;
        unsigned char signature[OQS_SIG_falcon_512_length_signature]; // 752 bytes as of liboqs 0.16.0 (666 in
                                                                       // the pre-2026-09-17 liboqs build) - see CORRECTIONS.md #22
        falcon_cert_cycle_envelope cert_cycle; // MUST stay last — wire_length() truncates the
                                                // send here for hash-only cycle messages
    };

    void generate_ecdsa_spdu(Vehicle::ecdsa_spdu &spdu, int timestep);
    void generate_falcon_spdu(Vehicle::falcon_spdu &spdu, int timestep);

    // Falcon cert fragmentation helpers (Update 4 / Phase 1). Falcon-only, no ECDSA analogue —
    // same pattern as sign_message_falcon vs sign_message_ecdsa already being separate.
    static void truncated_sha256_8(const void *data, size_t length, unsigned char out[8]);
    static std::vector<uint8_t> build_falcon_cert_bundle_blob(const falcon_explicit_certificate &cert,
                                                                unsigned int cert_sig_len,
                                                                const unsigned char *cert_sig);
    // CFrag: split the blob into m roughly-equal segments (ceil(size/m) each, remainder last).
    static void cfrag_falcon(const std::vector<uint8_t> &blob, uint32_t m,
                              std::vector<std::vector<uint8_t>> &segments_out);
    // CCons: concatenate segments in fragment_index order, verify the reconstructed blob's Full
    // Hash matches expected_full_hash, and unpack it back into cert_out/cert_sig_out on success.
    // Returns false (out-params untouched) on any mismatch. Phase 1: a correctness check, not yet
    // a security boundary — Phase 3 adds the actual defense/cache policy around this.
    // cert_out is a raw byte buffer, not a falcon_explicit_certificate& — see the comment on
    // falcon_reconstructed_cert_entry::cert_bytes for why.
    static bool ccons_falcon(const std::vector<std::vector<uint8_t>> &segments,
                              const std::array<uint8_t, 8> &expected_full_hash,
                              unsigned char cert_out[sizeof(falcon_explicit_certificate)],
                              unsigned int &cert_sig_len_out,
                              unsigned char cert_sig_out[OQS_SIG_falcon_512_length_signature],
                              std::array<uint8_t, 32> *full_digest_out = nullptr);

    // Actual on-wire byte count for one message. ecdsa_spdu always sends the whole struct
    // (unchanged behavior). falcon_spdu truncates after cert_cycle.full_hash for hash-only cycle
    // messages, and extends through cert_cycle.segment_data[0..segment_length) for
    // segment-carrying ones — this is what makes cycle traffic genuinely frame-constrained on the
    // wire, not just conceptually split.
    static size_t wire_length(const ecdsa_spdu &spdu);
    static size_t wire_length(const falcon_spdu &spdu);
    // True iff slots 0..count-1 are all filled - reassembly completeness, shared by the naive
    // and spam-filter receive paths.
    static bool all_segments_present(
        const std::array<std::optional<std::vector<uint8_t>>, FALCON_CERT_CYCLE_M_MAX> &segments, uint8_t count);
    // Collects slots 0..count-1 (caller has checked all_segments_present) for ccons_falcon.
    static std::vector<std::vector<uint8_t>> collect_segments(
        const std::array<std::optional<std::vector<uint8_t>>, FALCON_CERT_CYCLE_M_MAX> &segments, uint8_t count);

    // Per-scheme dispatch: transmit()/receive() pick one of these ONCE per call (not per
    // message) based on signature_scheme, then this templated loop body runs unchanged
    // for every scheme. Adding a new scheme means adding a new spdu type + generate/sign/
    // verify functions + one new branch here — not touching this loop body.
    // attackerMatchLegitDuration roles, both derived from the arguments main.cpp passes:
    //  - attacker (run_duration_ms > 0): num_msgs is ignored; stops when completion->all_done()
    //    (primary) or when run_duration_ms elapses (backstop for a hung legit thread).
    //  - legit (run_duration_ms == 0 && completion != nullptr): sends num_msgs as usual, then
    //    increments completion's counter right as the loop returns.
    // completion == nullptr and run_duration_ms == 0 is the original fixed-count behavior.
    // Returns the number actually sent plus why/when it stopped, since in duration mode the
    // count is an output, not an input.
    template<typename SpduT>
    transmit_result transmit_loop(int sockfd, struct sockaddr_in &servaddr, int num_msgs,
                                  void (Vehicle::*generate_spdu)(SpduT&, int), int64_t run_duration_ms = 0,
                                  legit_completion_signal *completion = nullptr);

    // read_frame returns true if a real message was read, false on a receive timeout (see
    // SO_RCVTIMEO in receive()) - lets the loop report "received X of Y, timed out" instead of
    // blocking forever on a message that was already lost (Phase 2 diagnostic follow-up).
    // open_ended = true (attackerMatchLegitDuration): num_msgs is only an upper bound, and the
    // SO_RCVTIMEO timeout is the normal end of the run rather than a loss indicator.
    template<typename SpduT>
    void receive_loop(SpduT &incoming_spdu, int num_msgs, int sockfd2, struct sockaddr_in &servaddr2,
                       bool tkgui, bool webgui,
                       const std::function<bool(SpduT&)> &read_frame,
                       bool (Vehicle::*verify)(SpduT&, std::chrono::time_point<std::chrono::system_clock,
                                                std::chrono::microseconds>, int),
                       bool open_ended = false);

    bsm generate_bsm(int timestep);
    template<typename SpduT>
    static void print_bsm(SpduT &spdu);
    template<typename SpduT>
    static void print_spdu(SpduT &spdu, bool valid);
    template<typename SpduT>
    static void forward_bsm_to_gui(SpduT &spdu, bool valid_spdu, int vehicle_id_number, int sockfd2,
                                    struct sockaddr_in &servaddr2);

    static void load_key(int number, bool certificate, EC_KEY *&key_to_store);
    static void load_falcon_key(int number, bool public_key, uint8_t *key_to_store);
    void load_trace(int number);

    void sign_message_ecdsa(Vehicle::ecdsa_spdu &spdu);
    bool verify_message_ecdsa(Vehicle::ecdsa_spdu &spdu, std::chrono::time_point<std::chrono::system_clock,
                              std::chrono::microseconds> received_time, int vehicle_id);

    void sign_message_falcon(Vehicle::falcon_spdu &spdu);
    bool verify_message_falcon(Vehicle::falcon_spdu &spdu, std::chrono::time_point<std::chrono::system_clock,
                              std::chrono::microseconds> received_time, int vehicle_id);

    // Phase 3 spam filter (context/UPDATES.md Update 4/9). spam_filter_verify_falcon is dispatched to
    // from the very top of verify_message_falcon when spam_filter_enabled is true; when
    // false, verify_message_falcon's existing Phase-2 body runs untouched (see Vehicle.cpp).
    // Still uses the disk-loaded key (load_falcon_key), not the cert's embedded key -
    // preserves the existing one-keypair limitation, doesn't expand scope.
    bool spam_filter_admit(Vehicle::falcon_spdu &spdu, uint8_t sender_id,
                            std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> send_ts,
                            std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> received_time);
    bool spam_filter_verify_falcon(Vehicle::falcon_spdu &spdu,
                                    std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> received_time,
                                    int vehicle_id);

protected:
    // Hooks for subclasses (e.g. an attacker vehicle) to alter per-message transmit behavior
    // without duplicating transmit_loop's socket/loop logic. Type-erased to (pointer, length)
    // rather than the full SpduT so they can stay virtual (member function templates can't be
    // virtual) while still working for any current or future scheme's spdu type uniformly.
    // No-op / unchanged-default here: Vehicle's own behavior is identical with or without them.
    virtual void post_process_spdu(unsigned char *signature, unsigned int signature_length) {}
    virtual int inter_message_delay_ms() { return NOMINAL_LEGIT_INTER_MESSAGE_DELAY_MS; }
    // No-op / unchanged-default: false means "sign for real", identical to today for Vehicle
    // and any subclass that doesn't override it (including AttackerVehicle's other two
    // modes). context/UPDATES.md Update 17.
    virtual bool bypass_falcon_signing() { return false; }

public:
    // Nominal legit BSM pacing - also the base of the attackerMatchLegitDuration formula in
    // main.cpp, so the two can't drift apart.
    static constexpr int NOMINAL_LEGIT_INTER_MESSAGE_DELAY_MS = 100;

    virtual ~Vehicle() = default;

    Vehicle(int number) {
        hostname = "null_hostname";
        this->number = number;
        Vehicle::load_key(number, false, private_ec_key);
        Vehicle::load_key(number, true, cert_private_ec_key);
        Vehicle::load_falcon_key(number, false, falcon_secret_key);
        Vehicle::load_falcon_key(number, true, falcon_public_key);
        memcpy(vehicle_certificate_falcon.signing_public_key, falcon_public_key, OQS_SIG_falcon_512_length_public_key);
        Vehicle::load_trace(number);
    };

    std::string get_hostname();
    // cert_cycle_hash_only_count / cert_cycle_segment_count are Falcon-only (n and m in
    // tau = m + n); ignored by the ECDSA path.
    // Defaulted so old call sites keep compiling unchanged. run_duration_ms / completion: see
    // transmit_loop (0 / nullptr = the original fixed num_msgs count).
    void transmit(int num_msgs, bool test, signature_scheme scheme, uint32_t cert_cycle_hash_only_count = 4,
                  int64_t run_duration_ms = 0, legit_completion_signal *completion = nullptr,
                  uint32_t cert_cycle_segment_count = 2);
    static void transmit_static(void* arg, int num_msgs, bool test, signature_scheme scheme,
                                 uint32_t cert_cycle_hash_only_count = 4, int64_t run_duration_ms = 0,
                                 legit_completion_signal *completion = nullptr,
                                 uint32_t cert_cycle_segment_count = 2) {
        auto* v = (Vehicle*) arg;
        v->transmit(num_msgs, test, scheme, cert_cycle_hash_only_count, run_duration_ms, completion,
                    cert_cycle_segment_count);
    };
    // On-wire bytes of a segment-carrying Falcon frame whose segment is segment_len bytes long
    // (same measure as wire_length). Integer offset arithmetic only - safe for segment_len
    // beyond segment_data's capacity, which main.cpp relies on to reject infeasible m.
    static size_t falcon_segment_wire_bytes(size_t segment_len);
    // Send-time log for the offline send->t3 join (Update 23). Set by main.cpp for legit vehicles
    // only, when PQV2V_TIMING_PREFIX is set; each vehicle owns its own vector (one send thread per
    // vehicle), written by main.cpp after every thread has joined. send_ns is absolute steady_clock
    // (CLOCK_MONOTONIC, shared across processes on this host); seq = transmit_loop's index.
    bool record_send_times = false;
    std::vector<std::pair<uint32_t, int64_t>> falcon_send_times;
    // num_vehicles is Falcon-only (legitimate/attacker boundary for the metrics summary);
    // ignored by the ECDSA path. spam_filter_* params are Phase 3, Falcon-only, ignored by
    // ECDSA. All defaulted so old call sites keep compiling unchanged.
    void receive(int num_msgs, bool test, bool tkgui, bool webgui, signature_scheme scheme, int num_vehicles = 0,
                 bool spam_filter_enabled_param = false, double spam_filter_min_gap_ms_param = 50.0,
                 double spam_filter_admit_ms_param = 100.0, double buffer_ttl_ms_param = 500.0,
                 uint32_t spam_filter_global_state_cap_param = 512,
                 // true (attackerMatchLegitDuration): num_msgs is the LEGIT-only expected count,
                 // and receiving continues until SO_RCVTIMEO rather than stopping at num_msgs.
                 bool open_ended_attacker_count = false);
};


#endif //CPP_VEHICLE_H
