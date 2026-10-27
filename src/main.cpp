// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#include <iostream>
#include <cmath>
#include <memory>
#include <thread>
#include <fstream>
#include <cstdlib>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "Vehicle.h"
#include "AttackerVehicle.h"
#include "arguments.h"


void print_usage() {
    std::cout << "Usage: v2verifer {dsrc | cv2x} {transmitter | receiver} {tkgui | webgui | nogui} [--test]" << std::endl;
}

int main(int argc, char *argv[]) {

    // Untangles cout/cerr from C stdio's synchronization, which meaningfully speeds up the
    // heavy per-message console logging at benchmark scale (thousands of messages) without
    // changing a single byte of WHAT gets printed - pure performance, zero content/output
    // change, so this can't affect the ECDSA "byte-for-byte unchanged" output-matching
    // regression evidence from Phase 1.
    std::ios_base::sync_with_stdio(false);

    if(argc < 3 || argc > 5) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    program_arguments args;

    if(std::string(argv[1]) == "dsrc")
        args.tech_choice = DSRC;
    else if(std::string(argv[1]) == "cv2x")
        args.tech_choice = CV2X;
    else {
        std::cout << "Error: first argument must be DSRC or C_V2X" << std::endl;
        print_usage();
        exit(EXIT_FAILURE);
    }

    if(std::string(argv[2]) == "transmitter") {
        args.sim_mode = TRANSMITTER;
    }
    else if(std::string(argv[2]) == "receiver")
        args.sim_mode = RECEIVER;
    else {
        std::cout << R"(Error: second argument must be "transmitter" or "receiver")" << std::endl;
        print_usage();
        exit(EXIT_FAILURE);
    }

    if(std::string(argv[3]) == "tkgui")
    args.tkgui = true;
    else if(std::string(argv[3]) == "webgui")
        args.webgui = true;
    else if(std::string(argv[3]) == "nogui")
        args.tkgui, args.webgui = false;
    else {
        std::cout << R"(Error: third argument must be "tkgui, webgui, or nogui")" << std::endl;
        print_usage();
        exit(EXIT_FAILURE);
    }

    if(argc >= 4) {
        if(argc == 5) {
            if (std::string(argv[4]) == "--test")
                args.test = true;
            else {
                std::cout << R"(Error: optional third argument can only be "--test")" << std::endl;
                print_usage();
                exit(EXIT_FAILURE);
            }
        }
    }

    boost::property_tree::ptree tree;
    boost::property_tree::json_parser::read_json("config.json",tree);

    auto num_vehicles = tree.get<uint8_t>("scenario.numVehicles");
    auto num_msgs = tree.get<uint16_t>("scenario.numMessages");
    auto scheme_str = tree.get<std::string>("scenario.signatureScheme", "ecdsa");
    args.scheme = (scheme_str == "falcon") ? signature_scheme::FALCON : signature_scheme::ECDSA;

    // Attacker vehicles are additive: total vehicles = numVehicles + numAttackers, with
    // numVehicles staying the fixed legitimate-traffic baseline across a ratio sweep.
    // Attacker IDs occupy [numVehicles, numVehicles + numAttackers) - a new range, not
    // carved out of the legitimate range - so legitimate/attacker role is still derivable
    // from vehicle_id alone (vehicle_id < numVehicles => legitimate) with no wire changes.
    // Defaults (0 attackers, "expensive_valid") make an old config.json with none of these
    // fields behave identically to before.
    auto num_attackers = tree.get<uint8_t>("scenario.numAttackers", 0);
    auto num_attacker_msgs = tree.get<uint16_t>("scenario.numAttackerMessages", 0);
    auto attacker_mode_str = tree.get<std::string>("scenario.attackerMode", "expensive_valid");
    attack_mode attacker_mode = (attacker_mode_str == "invalid_signature") ? attack_mode::INVALID_SIGNATURE
                               : (attacker_mode_str == "cheap_invalid_signature") ? attack_mode::CHEAP_INVALID_SIGNATURE
                               : attack_mode::EXPENSIVE_VALID;

    // n and m in the Falcon cert cycle (tau = m + n) - Falcon-only, ignored by ECDSA. m is only
    // used by the transmitter (it travels on the wire as fragment_count), but both sides
    // validate it so a bad config fails fast wherever it's launched.
    auto cert_cycle_hash_only_count = tree.get<uint32_t>("scenario.certCycleHashOnlyCount", 4);
    auto cert_cycle_segment_count = tree.get<uint32_t>("scenario.certCycleSegmentCount", 2);
    if(cert_cycle_segment_count < 1 || cert_cycle_segment_count > FALCON_CERT_CYCLE_M_MAX) {
        std::cerr << "certCycleSegmentCount=" << cert_cycle_segment_count << " out of range [1, "
                  << FALCON_CERT_CYCLE_M_MAX << "]" << std::endl;
        exit(EXIT_FAILURE);
    }
    {
        // Feasibility by computed wire size, not a hardcoded minimum: worst-case (max-length
        // cert signature) segment-carrying frame for this m must fit the DSRC cap.
        size_t worst_seg = (FALCON_CERT_BUNDLE_MAX_BYTES + cert_cycle_segment_count - 1) / cert_cycle_segment_count;
        size_t worst_frame = Vehicle::falcon_segment_wire_bytes(worst_seg);
        if(worst_frame > DSRC_MAX_FRAME_BYTES) {
            std::cerr << "certCycleSegmentCount=" << cert_cycle_segment_count
                      << ": worst-case segment-carrying frame = " << worst_frame
                      << " B exceeds DSRC cap " << DSRC_MAX_FRAME_BYTES << " B" << std::endl;
            exit(EXIT_FAILURE);
        }
        // Defensive: segment_data is sized for FALCON_CERT_CYCLE_M_MIN_FEASIBLE. Only reachable
        // if the cap or the bundle size changes and lets a smaller m through the check above.
        if(worst_seg > FALCON_CERT_SEGMENT_MAX_BYTES) {
            std::cerr << "certCycleSegmentCount=" << cert_cycle_segment_count << ": segment of " << worst_seg
                      << " B exceeds segment_data capacity " << FALCON_CERT_SEGMENT_MAX_BYTES
                      << " B (sized for m >= " << FALCON_CERT_CYCLE_M_MIN_FEASIBLE << ")" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // Attack D (cheap_invalid_signature) bypasses signing, so nothing throttles its send rate
    // except this laptop's CPU - not a realistic threat model (a real attacker is bounded by the
    // physical DSRC channel, not compute). Opt-in cap, default 0 (disabled/unthrottled - matches
    // existing behavior exactly for every mode when unset). Gated to CHEAP_INVALID_SIGNATURE only:
    // B/C's real per-message signing cost is itself part of what's being measured for those modes.
    // context/UPDATES.md Update 21: derived from Twardokus & Rahbari Table IV, vmax=101 vehicles under
    // worst-case 6 Mbps DSRC capacity x 10 BSM/sec/vehicle (100ms cadence) = ~1010 BSM/sec ceiling.
    auto attacker_flood_rate_cap_per_sec = tree.get<double>("scenario.attackerFloodRateCapPerSec", 0.0);
    int attacker_flood_delay_ms = 0;
    if(attacker_flood_rate_cap_per_sec > 0 && attacker_mode == attack_mode::CHEAP_INVALID_SIGNATURE) {
        // Millisecond-granularity sleep_for can't hit an arbitrary rate exactly; rounds to the
        // nearest ms, floored at 1ms (0ms would mean unthrottled). At the 1010/sec target this
        // yields 1ms -> an actual ~1000/sec, ~1% under the requested cap - logged so it's never
        // silently assumed exact.
        attacker_flood_delay_ms = (int) std::llround(1000.0 / attacker_flood_rate_cap_per_sec);
        if(attacker_flood_delay_ms < 1) attacker_flood_delay_ms = 1;
        double achieved_rate = 1000.0 / attacker_flood_delay_ms;
        std::cout << "[AttackerFloodRateCap] requested_rate_per_sec=" << attacker_flood_rate_cap_per_sec
                  << " flood_delay_ms=" << attacker_flood_delay_ms
                  << " achieved_rate_per_sec=" << achieved_rate << std::endl;
    }

    // Completion-based attacker stop condition (opt-in; default false keeps the fixed
    // numAttackerMessages count). When on, each attacker floods until every legit vehicle has
    // finished transmitting (primary stop, via legit_completion_signal), so the flood overlaps
    // the whole legit run. attacker_run_duration_ms is only a BACKSTOP for a hung legit thread:
    //   attacker_run_duration_ms = ceil(numMessages * nominal legit delay * margin)
    // Margin default 2.0: the slowest legit run seen under a full-length flood (300 msgs) was
    // 44,842ms (1.495x nominal), so 60s leaves +15.2s (34%) headroom; a backstop-terminated run
    // (~60s + 5s receiver tail + startup) still ends well inside the harness's 120s timeout.
    auto attacker_match_legit_duration = tree.get<bool>("scenario.attackerMatchLegitDuration", false);
    auto attacker_duration_margin = tree.get<double>("scenario.attackerDurationMargin", 2.0);
    int64_t attacker_run_duration_ms = 0;
    if(attacker_match_legit_duration && num_attackers > 0) {
        attacker_run_duration_ms = (int64_t) std::ceil((double) num_msgs
                                                       * Vehicle::NOMINAL_LEGIT_INTER_MESSAGE_DELAY_MS
                                                       * attacker_duration_margin);
        std::cout << "[AttackerDurationConfig] attackerMatchLegitDuration=true mode=" << attacker_mode_str
                  << " numMessages=" << num_msgs << " margin=" << attacker_duration_margin
                  << " backstop_duration_ms=" << attacker_run_duration_ms
                  << " (numAttackerMessages ignored)" << std::endl;
        if(num_vehicles == 0) {
            std::cout << "[AttackerDurationConfig] WARNING: numVehicles=0 - no legit vehicle can report "
                         "completion, so attackers will run until the backstop" << std::endl;
        }
    }

    // Phase 3 spam filter (Falcon-only, receive-side; ignored by ECDSA and by the
    // transmitter). Default false so an old config.json behaves exactly as before.
    auto spam_filter_enabled = tree.get<bool>("scenario.spamFilterEnabled", false);
    auto spam_filter_min_gap_ms = tree.get<double>("scenario.spamFilterMinGapMs", 50.0);
    auto spam_filter_admit_ms = tree.get<double>("scenario.spamFilterAdmitMs", 100.0);
    auto buffer_ttl_ms = tree.get<double>("scenario.bufferTtlMs", 500.0);
    {
        // Legit reassembly spans (m-1) inter-message gaps, and the TTL check runs when the
        // completing fragment arrives, so the TTL needs headroom over (m-1)*interval. Warning
        // only - the TTL is never scaled automatically.
        constexpr double margin_ms = 50.0;
        const double interval_ms = Vehicle::NOMINAL_LEGIT_INTER_MESSAGE_DELAY_MS;
        if(buffer_ttl_ms <= (cert_cycle_segment_count - 1) * interval_ms + margin_ms) {
            long max_safe_m = (long) std::floor((buffer_ttl_ms - margin_ms) / interval_ms) + 1;
            std::cerr << "WARNING: bufferTtlMs=" << buffer_ttl_ms << " leaves < " << margin_ms
                      << " ms headroom for certCycleSegmentCount=" << cert_cycle_segment_count
                      << " (legit reassembly ~" << (cert_cycle_segment_count - 1) * interval_ms
                      << " ms); largest safe m for this TTL = " << max_safe_m << std::endl;
        }
    }
    auto spam_filter_global_state_cap = tree.get<uint32_t>("scenario.spamFilterGlobalStateCap", 512);

    if(args.sim_mode == TRANSMITTER) {
        std::vector<std::unique_ptr<Vehicle>> vehicles;
        std::vector<std::thread> workers;

        // initialize vehicles - has to be in a separate loop to prevent vector issues
        // Update 23: PQV2V_TIMING_PREFIX turns on per-vehicle send-time logging (legit only).
        const char *timing_prefix = std::getenv("PQV2V_TIMING_PREFIX");
        bool log_send_times = timing_prefix && *timing_prefix;
        for(int i = 0; i < num_vehicles; i++) {
            vehicles.emplace_back(std::make_unique<Vehicle>(i));
            vehicles.back()->record_send_times = log_send_times;
        }
        for(int i = 0; i < num_attackers; i++) {
            // flood_delay_ms: 0 unless attackerFloodRateCapPerSec paces CHEAP_INVALID_SIGNATURE
            // (see attacker_flood_delay_ms above) - every other mode keeps sending unthrottled.
            vehicles.emplace_back(std::make_unique<AttackerVehicle>(num_vehicles + i, attacker_mode,
                                                                     attacker_flood_delay_ms));
        }

        // Shared by all threads in duration mode; declared before they start and they're all
        // joined below before it goes out of scope. Only handed out when duration mode is on
        // (and there's at least one legit vehicle to report), so with the flag off every thread
        // gets nullptr and 0 - the original fixed-count path.
        legit_completion_signal completion(num_vehicles);
        legit_completion_signal *completion_ptr =
            (attacker_run_duration_ms > 0 && num_vehicles > 0) ? &completion : nullptr;

        // start a thread for each vehicle - legitimate vehicles send numMessages (and, in
        // duration mode, report completion: completion != nullptr with run_duration_ms == 0);
        // attacker vehicles send numAttackerMessages, or in duration mode run until completion
        // with attacker_run_duration_ms as the backstop (run_duration_ms > 0)
        for(size_t i = 0; i < vehicles.size(); i++) {
            bool is_legit = i < num_vehicles;
            int msgs_for_this_vehicle = is_legit ? num_msgs : num_attacker_msgs;
            workers.emplace_back(std::thread(Vehicle::transmit_static, vehicles.at(i).get(),
                                              msgs_for_this_vehicle, args.test, args.scheme,
                                              cert_cycle_hash_only_count,
                                              is_legit ? 0 : attacker_run_duration_ms,
                                              completion_ptr, cert_cycle_segment_count));
        }

        // wait for each vehicle thread to finish
        for(size_t i = 0; i < vehicles.size(); i++) {
            workers.at(i).join();
        }

        // Every send thread has joined, so each vehicle's send-time vector is final.
        if(log_send_times) {
            std::ofstream out(std::string(timing_prefix) + "_sendtimes.csv");
            out << "sender_id,seq,send_ns\n";
            for(int i = 0; i < num_vehicles; i++) {
                for(const auto &[seq, send_ns] : vehicles.at(i)->falcon_send_times) {
                    out << i << ',' << seq << ',' << send_ns << '\n';
                }
            }
        }

    }
    else if (args.sim_mode == RECEIVER) {
        Vehicle v1(0);
        // Duration mode: the attacker total isn't known in advance, so pass the legit-only
        // count and let receive() run until SO_RCVTIMEO (see Vehicle::receive).
        bool open_ended = attacker_run_duration_ms > 0;
        int expected = open_ended ? num_msgs * num_vehicles
                                  : num_msgs * num_vehicles + num_attacker_msgs * num_attackers;
        v1.receive(expected,
                   args.test, args.tkgui, args.webgui, args.scheme, num_vehicles,
                   spam_filter_enabled, spam_filter_min_gap_ms, spam_filter_admit_ms,
                   buffer_ttl_ms, spam_filter_global_state_cap, open_ended);
    }



}
