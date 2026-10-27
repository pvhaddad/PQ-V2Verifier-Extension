// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#ifndef CPP_IEEE16092_H
#define CPP_IEEE16092_H

#include "bsm.h"
#include "certificates.h"

#include <cstddef>
#include <cstdint>

struct header_info {
    uint8_t psid = 32;
    std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> timestamp;
};

struct to_be_signed_data {
    uint8_t protocol_version = 3;
    bsm message;
    header_info headerInfo;
};

struct signed_data_ecdsa_implicit_certificate {
    uint8_t hashID = 0; // SHA-256
    to_be_signed_data tbsData;
    ecdsa_implicit_certificate cert = {};
};

struct signed_data_ecdsa_explicit_certificate {
    uint8_t hashID = 0; // SHA-256
    to_be_signed_data tbsData;
    ecdsa_explicit_certificate cert = {};
};

struct signed_data {
    uint8_t hashID = 0;
    to_be_signed_data tbsData;
};

struct ieee1609dot2data_ecdsa_implicit {
    uint8_t protocol_version = 3;
    signed_data_ecdsa_implicit_certificate signedData;
};

struct ieee1609dot2data_ecdsa_explicit {
    uint8_t protocol_version = 3;
    signed_data_ecdsa_explicit_certificate signedData;
    unsigned char certificate_signature[72];
};

// Certificate no longer travels inline here (Update 4 / Phase 1: certificate fragmentation).
// It is signed/sent via falcon_cert_cycle_envelope below instead, on a periodic cycle.
struct signed_data_falcon_explicit_certificate {
    uint8_t hashID = 0; // unused for Falcon (no external pre-hash); kept only for structural parity with the ECDSA variant
    to_be_signed_data tbsData;
};

struct ieee1609dot2data_falcon_explicit {
    uint8_t protocol_version = 3;
    signed_data_falcon_explicit_certificate signedData;
};

// Falcon certificate transmission cycle (Update 4 / Phase 1): the cert (public key + its own
// signature, ~1.6KB) is too large to resend whole on every BSM without blowing past the 2304B
// DSRC MAC-layer cap, so it's split into m segments and broadcast on a repeating cycle: m
// segment-carrying messages, then n hash-only messages. m is configurable
// (scenario.certCycleSegmentCount, validated at startup in main.cpp) and carried on the wire in
// fragment_count, so the receiver never needs to agree on it out of band. Every message carries
// Full Hash (hashedId8 convention: SHA-256 of the full cert+cert-sig blob, truncated to 8 bytes);
// only the m segment-carrying messages additionally carry Seg Hash (SHA-256 of that individual
// segment, truncated to 8 bytes).
// DSRC MAC-layer frame cap (bytes) that every Falcon frame must fit under.
constexpr size_t DSRC_MAX_FRAME_BYTES = 2304;

enum class cert_message_kind : uint8_t { HASH_ONLY = 0, SEGMENT_CARRYING = 1 };

// Upper bound on m (fixed-size receive buffers are sized to this).
constexpr uint32_t FALCON_CERT_CYCLE_M_MAX = 16;
static_assert(FALCON_CERT_CYCLE_M_MAX <= UINT8_MAX, "fragment_count is a uint8_t on the wire");

// Smallest m whose segment-carrying frame fits the 2304B DSRC cap FOR FALCON-512's bundle size
// (m=1 would put the whole ~1.6KB bundle in one frame, ~2.4KB). Used only to size segment_data
// below - the authoritative feasibility check is the computed wire-size check in main.cpp. A
// different algorithm (different bundle size) would have a different minimum.
constexpr uint32_t FALCON_CERT_CYCLE_M_MIN_FEASIBLE = 2;

// Cert bundle = raw bytes of falcon_explicit_certificate + a length field + the actual
// (not padded-to-max) cert signature. Split into m roughly-equal segments.
constexpr size_t FALCON_CERT_BUNDLE_MAX_BYTES =
    sizeof(falcon_explicit_certificate) + sizeof(unsigned int) + OQS_SIG_falcon_512_length_signature;
// Largest segment any feasible m can produce: ceil(bundle / M_MIN_FEASIBLE).
constexpr size_t FALCON_CERT_SEGMENT_MAX_BYTES =
    (FALCON_CERT_BUNDLE_MAX_BYTES + FALCON_CERT_CYCLE_M_MIN_FEASIBLE - 1) / FALCON_CERT_CYCLE_M_MIN_FEASIBLE;

struct falcon_cert_cycle_envelope {
    uint32_t fragment_set_id;        // identifies THIS cycle's segment-transmission instance;
                                      // changes every new cycle
    cert_message_kind message_kind;  // discriminant — read this before touching anything below
    unsigned char full_hash[8];      // hashedId8 — always sent, every message in the cycle

    // Everything below is only meaningful, and only actually placed on the wire (see
    // Vehicle::wire_length), when message_kind == SEGMENT_CARRYING.
    uint8_t fragment_index;                             // 0..fragment_count-1
    uint8_t fragment_count;                             // m for this cycle
    unsigned char seg_hash[8];                           // SHA-256(this segment) truncated
    uint16_t segment_length;                             // actual valid bytes in segment_data
    unsigned char segment_data[FALCON_CERT_SEGMENT_MAX_BYTES];
};

// Standing sanity check (Phase 1 checkpoint requirement): catches a silent regression in the
// segment-size math (e.g. from a struct field reorder or alignment change) rather than relying
// only on a one-time manual confirmation.
static_assert(FALCON_CERT_SEGMENT_MAX_BYTES * FALCON_CERT_CYCLE_M_MIN_FEASIBLE >= FALCON_CERT_BUNDLE_MAX_BYTES,
              "FALCON_CERT_SEGMENT_MAX_BYTES * FALCON_CERT_CYCLE_M_MIN_FEASIBLE must cover the full cert bundle");

// Wire-layout guards (nothing here is packed; values are for the x86-64 GCC/Clang ABI this
// testbed builds on). fragment_count took no spare padding: it pushes segment_length from 22 to
// 24 (1 pad byte at 23), so segment-carrying frames grow by 2B. Hash-only frames truncate at the
// end of full_hash and are unaffected.
static_assert(offsetof(falcon_cert_cycle_envelope, fragment_count) == 14, "envelope layout changed");
static_assert(offsetof(falcon_cert_cycle_envelope, segment_length) == 24, "envelope layout changed");
static_assert(offsetof(falcon_cert_cycle_envelope, segment_data) == 26, "envelope layout changed");

struct ieee1609dot2data {
    uint8_t protocol_version = 3;
    signed_data signedData;
};

#endif //CPP_IEEE16092_H
