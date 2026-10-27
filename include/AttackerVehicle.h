// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#ifndef CPP_ATTACKERVEHICLE_H
#define CPP_ATTACKERVEHICLE_H

#include "Vehicle.h"
#include "arguments.h"

class AttackerVehicle : public Vehicle {

private:
    attack_mode mode;
    int flood_delay_ms;

protected:
    int inter_message_delay_ms() override;
    void post_process_spdu(unsigned char *signature, unsigned int signature_length) override;
    bool bypass_falcon_signing() override;

public:
    AttackerVehicle(int number, attack_mode mode, int flood_delay_ms)
        : Vehicle(number), mode(mode), flood_delay_ms(flood_delay_ms) {};

};

#endif //CPP_ATTACKERVEHICLE_H
