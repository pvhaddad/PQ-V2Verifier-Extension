// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#ifndef CPP_V2VCRYPTO_H
#define CPP_V2VCRYPTO_H

#include <string>

void sha256sum(void* data, unsigned long length, unsigned char* md);
void ecdsa_sign(unsigned char *hash, EC_KEY *signing_key, unsigned int* signature_buffer_length, unsigned char *signature);
int ecdsa_verify(unsigned char *hash, unsigned char *signature, const unsigned int* signature_buffer_length, EC_KEY *verification_key);
void falcon_sign(uint8_t *signature, size_t &signature_len, uint8_t *message, size_t message_len, uint8_t *private_key);
bool falcon_verify(uint8_t *message, size_t message_len, uint8_t *signature, size_t signature_len, uint8_t *public_key);
void hex_to_bytes(const std::string &hex, uint8_t *out, size_t out_len);

#endif //CPP_V2VCRYPTO_H
