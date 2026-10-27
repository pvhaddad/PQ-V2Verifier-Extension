// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

//
// Created by geoff on 5/6/22.
//

#ifndef V2VERIFIER_ARGUMENTS_H
#define V2VERIFIER_ARGUMENTS_H

#include <cstddef>

enum mode {
    TRANSMITTER,
    RECEIVER
};

enum technology {
    DSRC,
    CV2X
};

enum class signature_scheme {
    ECDSA,
    FALCON
};

// On-wire frame size per scheme, per NDSS 2024 (Twardokus & Rahbari) Table III.
// Not consumed anywhere yet - reserved for the planned Spam Filter fragmentation stage.
// Adding a scheme here is the one place its frame size needs to be recorded.
constexpr size_t scheme_frame_size(signature_scheme scheme) {
    if (scheme == signature_scheme::FALCON) return 2435;
    return 350; // ECDSA
}

// Verify-flooding attack variants (Hassan's scoped order, items 1-2; 3-4 deferred).
enum class attack_mode {
    EXPENSIVE_VALID,         // valid signatures, high send rate - exercises verify-cost exhaustion directly
    INVALID_SIGNATURE,       // corrupted signatures - still costs a full verify attempt before rejection
    CHEAP_INVALID_SIGNATURE  // bypasses falcon_sign() entirely for the message signature - random
                              // bytes at a plausible length, isolates achievable flood rate from
                              // attacker-side signing cost (context/UPDATES.md Update 17)
};

struct program_arguments {
    mode sim_mode = RECEIVER;
    technology tech_choice = DSRC;
    bool test = false;
    bool tkgui = false;
    bool webgui = false;
    signature_scheme scheme = signature_scheme::ECDSA;
};

#endif //V2VERIFIER_ARGUMENTS_H
