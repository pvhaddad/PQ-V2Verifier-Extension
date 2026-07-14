// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

//
// Created by geoff on 10/14/21.
//

#ifndef CPP_VEHICLE_H
#define CPP_VEHICLE_H

#include <string>
#include <vector>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>

#include "ieee16092.h"
#include "bsm.h"
#include "v2vcrypto.h"
#include "arguments.h"


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

    std::vector<std::vector<float>> timestep;
    std::vector<float> timestep_data;

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
        unsigned char signature[OQS_SIG_falcon_512_length_signature]; // 666 bytes max
    };

    void generate_ecdsa_spdu(Vehicle::ecdsa_spdu &spdu, int timestep);
    void generate_falcon_spdu(Vehicle::falcon_spdu &spdu, int timestep);

    bsm generate_bsm(int timestep);
    static void print_bsm(Vehicle::ecdsa_spdu &spdu);
    static void print_bsm(Vehicle::falcon_spdu &spdu);
    static void print_spdu(Vehicle::ecdsa_spdu &spdu, bool valid);
    static void print_spdu(Vehicle::falcon_spdu &spdu, bool valid);

    static void load_key(int number, bool certificate, EC_KEY *&key_to_store);
    static void load_falcon_key(int number, bool public_key, uint8_t *key_to_store);
    void load_trace(int number);

    void sign_message_ecdsa(Vehicle::ecdsa_spdu &spdu);
    bool verify_message_ecdsa(Vehicle::ecdsa_spdu &spdu, std::chrono::time_point<std::chrono::system_clock,
                              std::chrono::microseconds> received_time, int vehicle_id);

    void sign_message_falcon(Vehicle::falcon_spdu &spdu);
    bool verify_message_falcon(Vehicle::falcon_spdu &spdu, std::chrono::time_point<std::chrono::system_clock,
                              std::chrono::microseconds> received_time, int vehicle_id);

public:
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
    void transmit(int num_msgs, bool test, signature_scheme scheme);
    static void transmit_static(void* arg, int num_msgs, bool test, signature_scheme scheme) {
        auto* v = (Vehicle*) arg;
        v->transmit(num_msgs, test, scheme);
    };
    void receive(int num_msgs, bool test, bool tkgui, bool webgui, signature_scheme scheme);
};


#endif //CPP_VEHICLE_H
