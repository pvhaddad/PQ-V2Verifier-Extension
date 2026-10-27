// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#include "AttackerVehicle.h"

int AttackerVehicle::inter_message_delay_ms() {
    return flood_delay_ms;
}

void AttackerVehicle::post_process_spdu(unsigned char *signature, unsigned int signature_length) {
    // Called after the real signature is already computed (transmit_loop invokes this right
    // after generate_spdu, which signs internally at the end) - corrupting here, rather than
    // touching BSM/cert construction, means the verifier still runs its full check and pays
    // the full verify cost before rejecting, matching the invalid-signature-flooding variant.
    //
    // Flips the LAST byte, not the first: ECDSA signatures are DER-encoded, and byte[0] is the
    // ASN.1 SEQUENCE tag (0x30) - corrupting it breaks structural parsing, not just the
    // cryptographic value, which makes ECDSA_verify() return -1 (malformed input) instead of a
    // normal invalid-signature result. v2vcrypto.cpp's ecdsa_verify() treats -1 as a fatal,
    // unrecoverable error and calls exit() - confirmed by hitting it. The last byte is always
    // deep inside the DER value content (the low byte of the "s" integer) for ECDSA, and is
    // just an opaque content byte for Falcon, so flipping it invalidates the signature value
    // without ever tripping ECDSA's DER structural parser.
    if(mode == attack_mode::INVALID_SIGNATURE && signature_length > 0) {
        signature[signature_length - 1] ^= 0xFF;
    }
}

// context/UPDATES.md Update 17: real falcon_sign() is skipped entirely for this mode - the bypass
// happens in generate_falcon_spdu (Vehicle.cpp), not here, since post_process_spdu only ever
// sees an already-signed buffer and can't change signature_buffer_length (passed by value).
bool AttackerVehicle::bypass_falcon_signing() {
    return mode == attack_mode::CHEAP_INVALID_SIGNATURE;
}
