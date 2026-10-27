// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "Vehicle.h"
#include <openssl/pem.h>
#include <thread>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <limits>
#include <map>
#include <cstdlib>


std::string Vehicle::get_hostname() {
   return hostname;
}

template<typename SpduT>
transmit_result Vehicle::transmit_loop(int sockfd, struct sockaddr_in &servaddr, int num_msgs,
                                       void (Vehicle::*generate_spdu)(SpduT&, int), int64_t run_duration_ms,
                                       legit_completion_signal *completion) {
    bool attacker_duration_mode = run_duration_ms > 0;
    auto backstop_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(run_duration_ms);
    transmit_stop_reason reason = transmit_stop_reason::COUNT_REACHED;
    int i = 0;
    for(;; i++) {
        // Attacker stop check, before generating each message: legit completion is the primary
        // condition and is checked first, so if both hold it's recorded as completion. The
        // backstop deadline only matters if a legit thread hangs without reporting.
        if(attacker_duration_mode) {
            if(completion && completion->all_done()) { reason = transmit_stop_reason::COMPLETION; break; }
            if(std::chrono::steady_clock::now() >= backstop_deadline) { reason = transmit_stop_reason::BACKSTOP_TIMEOUT; break; }
        }
        else if(i >= num_msgs) {
            break;
        }

        SpduT next_spdu;
        (this->*generate_spdu)(next_spdu, i);
        post_process_spdu(next_spdu.signature, next_spdu.signature_buffer_length);

        // Re-check right before sending: if the legit vehicles finished while this message was
        // being signed, drop it (not counted as sent) so nothing goes out after completion.
        if(attacker_duration_mode && completion && completion->all_done()) {
            reason = transmit_stop_reason::COMPLETION;
            break;
        }

        if(record_send_times) {
            falcon_send_times.emplace_back((uint32_t) i, (int64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        }
        sendto(sockfd, (SpduT *) &next_spdu, wire_length(next_spdu), MSG_CONFIRM,
               (const struct sockaddr *) &servaddr, sizeof(servaddr));

        std::this_thread::sleep_for(std::chrono::milliseconds(inter_message_delay_ms()));

    }
    auto stopped_at = std::chrono::steady_clock::now();

    // Legit side of the completion signal: report right as this loop returns (still inside the
    // thread), so a running attacker loop can observe it. Exactly one thread sees
    // done == num_legit_vehicles (fetch_add is atomic) and records the all-done time.
    if(completion && !attacker_duration_mode) {
        int done = completion->legit_vehicles_done.fetch_add(1) + 1;
        if(done == completion->num_legit_vehicles) {
            completion->all_done_steady_ns.store(
                std::chrono::duration_cast<std::chrono::nanoseconds>(stopped_at.time_since_epoch()).count());
        }
        std::cout << "[LegitDone] vehicle=" << (int) this->number
                  << " legit_vehicles_done=" << done << "/" << completion->num_legit_vehicles << std::endl;
    }

    return transmit_result{i, reason, stopped_at};
}

size_t Vehicle::wire_length(const ecdsa_spdu &spdu) {
    return sizeof(spdu); // unchanged behavior — ECDSA always sends the whole struct
}

size_t Vehicle::wire_length(const falcon_spdu &spdu) {
    // Address-difference rather than offsetof: falcon_spdu transitively contains a
    // std::chrono::time_point member (via to_be_signed_data/header_info), so it isn't guaranteed
    // standard-layout; taking addresses of actual subobjects and diffing their byte
    // representations is well-defined regardless (same convention the codebase already relies on
    // when it hashes/signs these structs as raw bytes elsewhere).
    const auto *base = reinterpret_cast<const unsigned char*>(&spdu);
    const auto *end_of_full_hash = reinterpret_cast<const unsigned char*>(&spdu.cert_cycle.full_hash)
                                    + sizeof(spdu.cert_cycle.full_hash);
    if(spdu.cert_cycle.message_kind == cert_message_kind::HASH_ONLY) {
        return static_cast<size_t>(end_of_full_hash - base);
    }
    const auto *end_of_segment = reinterpret_cast<const unsigned char*>(&spdu.cert_cycle.segment_data[0])
                                  + spdu.cert_cycle.segment_length;
    return static_cast<size_t>(end_of_segment - base);
}

size_t Vehicle::falcon_segment_wire_bytes(size_t segment_len) {
    // Same address-diff convention as wire_length above, but adds segment_len as an integer so
    // it never forms a pointer past segment_data (main.cpp calls this with infeasible lengths).
    static const falcon_spdu probe{};
    const auto *base = reinterpret_cast<const unsigned char*>(&probe);
    const auto *seg_start = reinterpret_cast<const unsigned char*>(&probe.cert_cycle.segment_data[0]);
    return static_cast<size_t>(seg_start - base) + segment_len;
}

bool Vehicle::all_segments_present(
        const std::array<std::optional<std::vector<uint8_t>>, FALCON_CERT_CYCLE_M_MAX> &segments, uint8_t count) {
    for(uint8_t i = 0; i < count; i++) {
        if(!segments[i].has_value()) return false;
    }
    return true;
}

std::vector<std::vector<uint8_t>> Vehicle::collect_segments(
        const std::array<std::optional<std::vector<uint8_t>>, FALCON_CERT_CYCLE_M_MAX> &segments, uint8_t count) {
    std::vector<std::vector<uint8_t>> out;
    out.reserve(count);
    for(uint8_t i = 0; i < count; i++) out.push_back(*segments[i]);
    return out;
}

void Vehicle::transmit(int num_msgs, bool test, signature_scheme scheme, uint32_t cert_cycle_hash_only_count,
                       int64_t run_duration_ms, legit_completion_signal *completion,
                       uint32_t cert_cycle_segment_count) {

    falcon_cycle_hash_only_count_n = cert_cycle_hash_only_count;
    falcon_cycle_segment_count_m = cert_cycle_segment_count;
    if(record_send_times) falcon_send_times.reserve(num_msgs);

    // create socket and send data
    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    if(test)
        servaddr.sin_port = htons(6666);
    else
        servaddr.sin_port = htons(52001);
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // Duration mode (attackerMatchLegitDuration) attacker only: message count is an output, so
    // report what was actually sent, how long it took, and which condition stopped it. Nothing
    // extra is printed in count mode, so ECDSA's regression output is unaffected when the flag
    // is off.
    auto run_start = std::chrono::steady_clock::now();
    transmit_result result{};
    auto print_duration_run_summary = [&]() {
        if(run_duration_ms <= 0) return;
        double elapsed_ms = std::chrono::duration<double, std::milli>(result.stopped_at - run_start).count();
        bool by_completion = result.reason == transmit_stop_reason::COMPLETION;
        std::cout << "[AttackerRunSummary] vehicle=" << (int) this->number
                  << " stop_reason=" << (by_completion ? "completion" : "backstop_timeout")
                  << " backstop_duration_ms=" << run_duration_ms
                  << " actual_elapsed_ms=" << elapsed_ms
                  << " messages_sent=" << result.sent
                  << " avg_actual_gap_ms=" << (result.sent > 0 ? elapsed_ms / result.sent : 0.0);
        if(by_completion) {
            // Both timestamps are steady_clock in this process: attacker stop minus the moment
            // the last legit vehicle reported done.
            int64_t stopped_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(result.stopped_at.time_since_epoch()).count();
            std::cout << " completion_lag_ms=" << (stopped_ns - completion->all_done_steady_ns.load()) / 1e6;
        }
        std::cout << std::endl;
        if(!by_completion) {
            std::cout << "[AttackerBackstopFired] vehicle=" << (int) this->number << " legit_vehicles_done="
                      << (completion ? completion->legit_vehicles_done.load() : 0) << "/"
                      << (completion ? completion->num_legit_vehicles : 0)
                      << " - a legit thread did not report completion; treat this run as suspect" << std::endl;
        }
    };

    if(scheme == signature_scheme::ECDSA) {
        result = transmit_loop<ecdsa_spdu>(sockfd, servaddr, num_msgs, &Vehicle::generate_ecdsa_spdu,
                                           run_duration_ms, completion);
        print_duration_run_summary();
    }
    else {
        std::cout << "[FalconCertCycle] sizeof(falcon_spdu)=" << sizeof(falcon_spdu)
                  << " sizeof(falcon_cert_cycle_envelope)=" << sizeof(falcon_cert_cycle_envelope)
                  << " m=" << falcon_cycle_segment_count_m
                  << " n=" << falcon_cycle_hash_only_count_n
                  << " FALCON_CERT_SEGMENT_MAX_BYTES=" << FALCON_CERT_SEGMENT_MAX_BYTES
                  << " (DSRC cap=2304)" << std::endl;

        // Flood-rate verification: measures the ACTUAL wall-clock inter-send gap, independent
        // of the nominal inter_message_delay_ms() setting, to directly confirm (not just infer
        // from reading the code) whether this vehicle's send loop is genuinely paced or
        // unpaced. Falcon-only, added at this existing per-scheme branch point rather than
        // inside transmit_loop's shared body, so it never touches ECDSA's console output -
        // ECDSA's Phase 1 "byte-for-byte unchanged" regression evidence depended on exact
        // output matching, and this would have broken that comparison.
        auto flood_check_start = std::chrono::steady_clock::now();
        result = transmit_loop<falcon_spdu>(sockfd, servaddr, num_msgs, &Vehicle::generate_falcon_spdu,
                                            run_duration_ms, completion);
        auto flood_check_end = std::chrono::steady_clock::now();
        print_duration_run_summary();
        // result.sent == num_msgs in count mode, so this line is unchanged there.
        double total_ms = std::chrono::duration<double, std::milli>(flood_check_end - flood_check_start).count();
        double avg_gap_ms = result.sent > 0 ? total_ms / result.sent : 0.0;
        std::cout << "[FloodRateCheck] vehicle=" << (int) this->number
                  << " num_msgs=" << result.sent
                  << " nominal_inter_message_delay_ms=" << inter_message_delay_ms()
                  << " total_send_time_ms=" << total_ms
                  << " avg_actual_gap_ms=" << avg_gap_ms << std::endl;

        // Sign/verify cost isolation (Phase 2 diagnostic follow-up): isolates just the
        // falcon_sign() call cost from the surrounding cycle bookkeeping/sendto/sleep overhead
        // already reflected in FloodRateCheck above, so it can be compared directly against the
        // receiver's [FalconVerifyCost]-equivalent numbers (see print_falcon_verify_metrics_summary)
        // to determine whether the observed flood ceiling is set by attacker signing cost or
        // receiver verify capacity.
        double msg_sign_avg = falcon_message_sign_times_ms.empty() ? 0.0 :
            std::accumulate(falcon_message_sign_times_ms.begin(), falcon_message_sign_times_ms.end(), 0.0) / falcon_message_sign_times_ms.size();
        double cert_sign_avg = falcon_cert_sign_times_ms.empty() ? 0.0 :
            std::accumulate(falcon_cert_sign_times_ms.begin(), falcon_cert_sign_times_ms.end(), 0.0) / falcon_cert_sign_times_ms.size();
        std::cout << "[FalconSignCost] vehicle=" << (int) this->number
                  << " message_sign_avg_ms=" << msg_sign_avg
                  << " message_sign_p95_ms=" << percentile_ms(falcon_message_sign_times_ms, 95)
                  << " (n=" << falcon_message_sign_times_ms.size() << ")"
                  << " | cert_sign_avg_ms=" << cert_sign_avg
                  << " cert_sign_p95_ms=" << percentile_ms(falcon_cert_sign_times_ms, 95)
                  << " (n=" << falcon_cert_sign_times_ms.size() << ")" << std::endl;

        // Backlog-mechanism investigation: is the send-side per-message gap steady over the
        // whole run, or does it trend upward (which would mean the SENDER's own rate degrades
        // over a long run, rather than the receiver falling behind an otherwise-steady sender)?
        // Split into first/second half rather than just an overall average, which can't reveal
        // a trend on its own.
        if(!falcon_send_gap_ms.empty()) {
            size_t half = falcon_send_gap_ms.size() / 2;
            double first_half_avg = std::accumulate(falcon_send_gap_ms.begin(), falcon_send_gap_ms.begin() + (long) half, 0.0) / (double) half;
            double second_half_avg = std::accumulate(falcon_send_gap_ms.begin() + (long) half, falcon_send_gap_ms.end(), 0.0) / (double) (falcon_send_gap_ms.size() - half);
            std::cout << "[FalconSendGapTrend] vehicle=" << (int) this->number
                      << " first_half_avg_ms=" << first_half_avg
                      << " second_half_avg_ms=" << second_half_avg
                      << " max=" << *std::max_element(falcon_send_gap_ms.begin(), falcon_send_gap_ms.end())
                      << " (n=" << falcon_send_gap_ms.size() << ")" << std::endl;
        }
    }

    close(sockfd);

}

template<typename SpduT>
void Vehicle::forward_bsm_to_gui(SpduT &spdu, bool valid_spdu, int vehicle_id_number, int sockfd2,
                                  struct sockaddr_in &servaddr2) {
    std::cout << "Heading:\t" << spdu.data.signedData.tbsData.message.heading << std::endl;
    packed_bsm_for_gui data_for_gui = {spdu.data.signedData.tbsData.message.latitude,
                                       spdu.data.signedData.tbsData.message.longitude,
                                       spdu.data.signedData.tbsData.message.elevation,
                                       spdu.data.signedData.tbsData.message.speed,
                                       spdu.data.signedData.tbsData.message.heading,
                                       valid_spdu,
                                       true,
                                       7,
                                       (float) vehicle_id_number};
    sendto(sockfd2, (struct packed_bsm_for_gui *) &data_for_gui, sizeof(data_for_gui),
            MSG_CONFIRM, (const struct sockaddr *) &servaddr2, sizeof(servaddr2));
}

template<typename SpduT>
void Vehicle::receive_loop(SpduT &incoming_spdu, int num_msgs, int sockfd2, struct sockaddr_in &servaddr2,
                            bool tkgui, bool webgui,
                            const std::function<bool(SpduT&)> &read_frame,
                            bool (Vehicle::*verify)(SpduT&, std::chrono::time_point<std::chrono::system_clock,
                                                     std::chrono::microseconds>, int),
                            bool open_ended) {
    using timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

    // this is to prevent a truly infinite loop
    for(int received_message_counter = 0; received_message_counter < num_msgs; received_message_counter++) {

        if(!read_frame(incoming_spdu)) {
            if(open_ended) {
                // Duration mode: the attacker's message count isn't known in advance, so a quiet
                // SO_RCVTIMEO period is the expected end of the run. Genuine legit loss is still
                // caught by the legit-only INCOMPLETE RUN check in the metrics summary.
                std::cout << "[ReceiveEndOfRun] no message for SO_RCVTIMEO after "
                          << received_message_counter << " messages (duration mode)" << std::endl;
                break;
            }
            // Receive timed out (SO_RCVTIMEO) waiting for a message that was already lost -
            // previously this would block forever. Report what was actually received instead
            // of hanging (Phase 2 diagnostic follow-up).
            std::cout << "[ReceiveTimeout] received " << received_message_counter << " of "
                      << num_msgs << " expected messages before timing out" << std::endl;
            break;
        }

        // for getting times when BSMs are received (security check for replay attacks)
        timestamp received_time = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());

        std::cout << incoming_spdu.vehicle_id << '\n';
        int vehicle_id_number = incoming_spdu.vehicle_id;

        bool valid_spdu = (this->*verify)(incoming_spdu, received_time, vehicle_id_number);

        // forward to GUI if applicable
        if(tkgui || webgui) {
            forward_bsm_to_gui(incoming_spdu, valid_spdu, vehicle_id_number, sockfd2, servaddr2);
        }
        // print results ('\n' not std::endl - see print_bsm's comment on why)
        for(int i = 0; i < 80; i++) std::cout << "-"; std::cout << '\n';
        print_spdu(incoming_spdu, valid_spdu);
        print_bsm(incoming_spdu);

    }
}

void Vehicle::receive(int num_msgs, bool test, bool tkgui, bool webgui, signature_scheme scheme, int num_vehicles,
                       bool spam_filter_enabled_param, double spam_filter_min_gap_ms_param,
                       double spam_filter_admit_ms_param, double buffer_ttl_ms_param,
                       uint32_t spam_filter_global_state_cap_param, bool open_ended_attacker_count) {

    // Duration mode (attackerMatchLegitDuration): num_msgs is the legit-only expected count, and
    // the loop runs until SO_RCVTIMEO instead of stopping at a total it can't know in advance.
    int loop_bound = open_ended_attacker_count ? std::numeric_limits<int>::max() : num_msgs;

    spam_filter_enabled = spam_filter_enabled_param;
    spam_filter_min_gap_ms = spam_filter_min_gap_ms_param;
    spam_filter_admit_ms = spam_filter_admit_ms_param;
    buffer_ttl_ms = buffer_ttl_ms_param;
    spam_filter_global_state_cap = spam_filter_global_state_cap_param;
    spam_filter_num_vehicles = num_vehicles;

    // Update 23: per-message timing (env PQV2V_TIMING_PREFIX) and verify-once mode (env
    // PQV2V_CERT_VERIFY_MODE). Neither is a config.json field; both default to today's behavior.
    falcon_steady_ref = std::chrono::steady_clock::now();
    falcon_system_ref = std::chrono::system_clock::now();
    const char *timing_prefix_env = std::getenv("PQV2V_TIMING_PREFIX");
    falcon_timing_prefix = (timing_prefix_env && *timing_prefix_env) ? timing_prefix_env : nullptr;
    const char *verify_mode_env = std::getenv("PQV2V_CERT_VERIFY_MODE");
    std::string verify_mode = (verify_mode_env && *verify_mode_env) ? verify_mode_env : "every";
    if(verify_mode != "every" && verify_mode != "once") {
        std::cerr << "PQV2V_CERT_VERIFY_MODE=" << verify_mode << " (expected every|once)" << std::endl;
        exit(EXIT_FAILURE);
    }
    falcon_cert_verify_once = verify_mode == "once";
    if(falcon_timing_prefix) {
        // num_msgs is already the grand total (numMessages * numVehicles [+ attacker msgs]; see
        // main.cpp), so a fixed-count run never outgrows this; open-ended (attack) runs may.
        falcon_timing.reserve(open_ended_attacker_count ? (size_t) num_msgs + 400000 : (size_t) num_msgs + 1024);
        falcon_timing_reserved = falcon_timing.capacity();
    }

    int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;

    uint16_t port = test ? 6666 : 4444;
    servaddr.sin_port = htons(port);

    if(bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Socket bind failed");
        exit(EXIT_FAILURE);
    }

    // Phase 2 diagnostic follow-up (transient-burst flood loss, context/UPDATES.md Update 6). Applies to
    // both schemes (one shared socket) - safe for ECDSA under any realistic test load: SO_RCVBUF
    // is purely additional headroom (never harmful), and the 5s SO_RCVTIMEO is enormously larger
    // than any real inter-message gap (100ms nominal, ~134ms observed even under heavy CPU
    // contention), so it only ever trips on genuine loss, never during normal operation.
    int rcvbuf_size = 32 * 1024 * 1024; // 32MiB - comfortably covers a full ~20k-message flood
                                          // at worst-case Falcon segment-carrying size (~1585B),
                                          // so a startup CPU-contention burst doesn't overflow
                                          // the kernel socket buffer. Requires net.core.rmem_max
                                          // raised to at least this value - setsockopt silently
                                          // clamps to the current ceiling otherwise.
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));

    struct timeval recv_timeout{};
    recv_timeout.tv_sec = 5;
    recv_timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

    /***********************************/
    // gui socket
    int sockfd2;
    struct sockaddr_in servaddr2;

    if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr2, 0, sizeof(servaddr2));

    servaddr2.sin_family = AF_INET;

    int gui_port = -1;
    if(tkgui)
        gui_port = 9999;
    else
        gui_port = 8888;

    servaddr2.sin_port = htons(gui_port);
    servaddr2.sin_addr.s_addr = INADDR_ANY;
    /***********************************/


    unsigned int len;
    len = sizeof(cliaddr);

    ecdsa_spdu incoming_spdu;
    falcon_spdu incoming_falcon_spdu;

    if(scheme == signature_scheme::ECDSA) {

        std::function<bool(ecdsa_spdu&)> read_frame = [&](ecdsa_spdu &s) -> bool {
            if(test) {

                // Correctly-typed addrlen out-param, not the (socklen_t*) direct-integer-cast of
                // `len` used to sit here: that cast turns the VALUE 16 (sizeof(cliaddr)) into a
                // POINTER (address 0x10), which the kernel then rejects when trying to write the
                // negotiated addrlen back, causing recvfrom() to return -1/EFAULT on every call.
                // Silently harmless as long as nothing checked the return value (the payload
                // still lands in the buffer despite the failed addrlen write) - but this phase's
                // new timeout detection needs to trust recvfrom()'s return value to tell a real
                // receive apart from a genuine SO_RCVTIMEO timeout, so the bug had to be fixed
                // here, not just worked around (Phase 2 diagnostic follow-up).
                socklen_t ecdsa_addrlen = sizeof(cliaddr);
                ssize_t n = recvfrom(sockfd, (struct ecdsa_spdu *) &s, sizeof(ecdsa_spdu), 0, (struct sockaddr *) &cliaddr,
                         &ecdsa_addrlen);
                return n >= 0;
            }
            else {
                // with DSRC headers (when data is from SDR), we have an extra 57 bytes (304 + 57 = 361)
                uint8_t buffer[361];
                socklen_t ecdsa_addrlen2 = sizeof(cliaddr);
                ssize_t n = recvfrom(sockfd,  &buffer, 361, 0, (struct sockaddr *) &cliaddr,
                         &ecdsa_addrlen2);
                if(n < 0) return false;

                uint8_t spdu_buffer[sizeof(s)];
                for(int i = 360, j = sizeof(s) - 1; i > 57; i--, j--) {
                    spdu_buffer[j] = buffer[i];
                }

                memcpy(&s, spdu_buffer, sizeof(s));
                return true;

            }
        };

        receive_loop<ecdsa_spdu>(incoming_spdu, loop_bound, sockfd2, servaddr2, tkgui, webgui,
                                  read_frame, &Vehicle::verify_message_ecdsa, open_ended_attacker_count);

    }
    else {

        int actual_rcvbuf_size = 0;
        socklen_t actual_rcvbuf_size_len = sizeof(actual_rcvbuf_size);
        getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf_size, &actual_rcvbuf_size_len);
        std::cout << "[SocketConfig] requested SO_RCVBUF=" << rcvbuf_size
                  << " actual (post-clamp; kernel doubles the requested value internally)="
                  << actual_rcvbuf_size << std::endl;

        std::function<bool(falcon_spdu&)> read_frame = [&](falcon_spdu &s) -> bool {
            if(test) {

                // s is reused across iterations; a hash-only datagram's shorter recvfrom() leaves
                // bytes past what was actually sent untouched, so the tail must be cleared first
                // or a later message could show stale segment data from a prior segment-carrying
                // receipt (Update 4 / Phase 1).
                memset(&s.cert_cycle, 0, sizeof(s.cert_cycle));
                // Local, correctly-typed addrlen out-param — the shared `len` variable above is
                // cast directly to (socklen_t*) at its other call sites (a pre-existing bug,
                // untouched here since ECDSA must stay byte-for-byte unchanged), which made
                // recvfrom's return value here unreliable for the wire-byte-count logging this
                // phase's checkpoint depends on.
                socklen_t falcon_addrlen = sizeof(cliaddr);
                auto recvfrom_start = std::chrono::steady_clock::now();
                ssize_t bytes_received = recvfrom(sockfd, (struct falcon_spdu *) &s, sizeof(falcon_spdu), 0, (struct sockaddr *) &cliaddr,
                         &falcon_addrlen);
                auto recvfrom_end = std::chrono::steady_clock::now(); // also t0 (Update 23)
                falcon_rx_t0_ns = falcon_ns_since_ref(recvfrom_end);
                falcon_recvfrom_times_ms.push_back(std::chrono::duration<double, std::milli>(recvfrom_end - recvfrom_start).count());
                if(!falcon_timing_prefix) std::cout << "[FalconCertCycle] RX wire_bytes=" << bytes_received << '\n';
                falcon_last_rx_bytes = bytes_received; // Phase 3 spam filter's length cheap check reads this
                return bytes_received >= 0;
            }
            else {
                perror("Non-test (SDR/DSRC hardware) framing not yet defined for the Falcon path");
                exit(EXIT_FAILURE);
            }
        };

        receive_loop<falcon_spdu>(incoming_falcon_spdu, loop_bound, sockfd2, servaddr2, tkgui, webgui,
                                   read_frame, &Vehicle::verify_message_falcon, open_ended_attacker_count);

        // Clock guard (Update 23): a wall-clock step (e.g. WSL2's recurring ~32 s timesyncd step)
        // shows up as steady and system elapsed times disagreeing. Flag, never drop.
        auto steady_elapsed = std::chrono::steady_clock::now() - falcon_steady_ref;
        auto system_elapsed = std::chrono::system_clock::now() - falcon_system_ref;
        falcon_wall_clock_step = std::llabs((long long) std::chrono::duration_cast<std::chrono::milliseconds>(
                                      steady_elapsed - system_elapsed).count()) > 100;

        print_falcon_verify_metrics_summary(num_vehicles, num_msgs, open_ended_attacker_count);
        write_falcon_timing_files();

    }

    close(sockfd2);
    exit(0);

}

void Vehicle::generate_ecdsa_spdu(Vehicle::ecdsa_spdu &spdu, int timestep) {
    spdu.vehicle_id = this->number;

    // BSM
    spdu.data.signedData.tbsData.message = generate_bsm(timestep);

    // timestamp
    using timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;
    timestamp ts = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    spdu.data.signedData.tbsData.headerInfo.timestamp = ts;

    spdu.data.signedData.cert = vehicle_certificate_ecdsa;

    // sign the certificate
    unsigned char certificate_digest[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.cert,sizeof(spdu.data.signedData.cert), certificate_digest);
    ecdsa_sign(certificate_digest, cert_private_ec_key, &certificate_buffer_length, certificate_signature);

    // copy the certificate signature buffer and certificate signature into the SPDU
    spdu.certificate_signature_buffer_length = certificate_buffer_length;
    for(int i = 0; i < certificate_buffer_length; i++) {
        spdu.data.certificate_signature[i] = certificate_signature[i];
    }

    sign_message_ecdsa(spdu);

}

void Vehicle::generate_falcon_spdu(Vehicle::falcon_spdu &spdu, int timestep) {
    auto send_call_start = std::chrono::steady_clock::now();
    if(falcon_last_send_start_set) {
        falcon_send_gap_ms.push_back(std::chrono::duration<double, std::milli>(send_call_start - falcon_last_send_start).count());
    }
    falcon_last_send_start = send_call_start;
    falcon_last_send_start_set = true;

    spdu.vehicle_id = this->number;

    // BSM
    spdu.data.signedData.tbsData.message = generate_bsm(timestep);

    // timestamp
    using timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;
    timestamp ts = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    spdu.data.signedData.tbsData.headerInfo.timestamp = ts;

    // Certificate transmission cycle (Update 4 / Phase 1): tau = m + n messages, m
    // segment-carrying then n hash-only, repeating.
    const uint32_t m = falcon_cycle_segment_count_m;
    const uint32_t tau = m + falcon_cycle_hash_only_count_n;

    if(falcon_cycle_position == 0) {
        // fragment_set_id still increments every cycle for buffer bookkeeping (Phase 3's
        // receive-side slot-cap consults it) - independent of whether the cert itself is
        // re-signed below.
        falcon_cycle_fragment_set_id++;

        // Sign-once-per-vehicle-lifetime (Phase 3 prerequisite fix, context/UPDATES.md Update 9),
        // NOT once per cycle as originally built. Falcon signing is randomized, so the
        // original per-cycle re-sign made full_hash change every cycle too (full_hash is
        // SHA-256 over cert+cert_sig, and cert_sig differs every time falcon_sign() runs) -
        // which made hashedId8 cross-cycle caching impossible by construction. Signing once
        // matches how real pseudonym certs work (CA signs once, reused for the cert's whole
        // validity period, not re-signed every ~600ms) and is what the Phase 3 spam filter's
        // cache-first fast path depends on to ever fire for segment-carrying traffic.
        // (Still satisfies the ORIGINAL reason a single per-cycle signing operation was
        // required in the first place: segment 0 and segment 1 must come from the same
        // signing operation to reconstruct into something that verifies - signing once ever
        // is a strict strengthening of that, not a relaxation of it.)
        if(!falcon_cert_prepared) {
            size_t cert_sig_len = OQS_SIG_falcon_512_length_signature;
            auto cert_sign_start = std::chrono::steady_clock::now();
            falcon_sign(certificate_signature_falcon, cert_sig_len,
                        (uint8_t*) &vehicle_certificate_falcon, sizeof(vehicle_certificate_falcon),
                        falcon_secret_key);
            falcon_cert_sign_times_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - cert_sign_start).count());
            certificate_signature_buffer_length_falcon = (unsigned int) cert_sig_len;

            auto blob = build_falcon_cert_bundle_blob(vehicle_certificate_falcon,
                            certificate_signature_buffer_length_falcon, certificate_signature_falcon);
            truncated_sha256_8(blob.data(), blob.size(), falcon_cycle_full_hash.data());
            cfrag_falcon(blob, m, falcon_cycle_segments);
            falcon_cert_prepared = true;
        }
    }

    auto &env = spdu.cert_cycle;
    env.fragment_set_id = falcon_cycle_fragment_set_id;
    memcpy(env.full_hash, falcon_cycle_full_hash.data(), sizeof(env.full_hash));

    std::string kind_str;
    if(falcon_cycle_position < m) {
        env.message_kind = cert_message_kind::SEGMENT_CARRYING;
        env.fragment_index = (uint8_t) falcon_cycle_position;
        env.fragment_count = (uint8_t) m;
        auto &seg = falcon_cycle_segments[falcon_cycle_position];
        env.segment_length = (uint16_t) seg.size();
        memcpy(env.segment_data, seg.data(), seg.size());
        truncated_sha256_8(seg.data(), seg.size(), env.seg_hash);
        kind_str = "SEGMENT_CARRYING(idx=" + std::to_string(env.fragment_index) + ")";
    }
    else {
        env.message_kind = cert_message_kind::HASH_ONLY;
        env.fragment_index = 0;
        env.fragment_count = 0; // not on the wire for hash-only messages
        env.segment_length = 0;
        kind_str = "HASH_ONLY";
    }

    std::cout << "[FalconCertCycle] TX vehicle=" << (int) spdu.vehicle_id
              << " cycle_pos=" << falcon_cycle_position
              << " fragment_set_id=" << env.fragment_set_id
              << " kind=" << kind_str
              << " wire_bytes=" << wire_length(spdu) << std::endl;

    falcon_cycle_position = (falcon_cycle_position + 1) % tau;

    // context/UPDATES.md Update 17: CHEAP_INVALID_SIGNATURE bypasses real signing entirely for the
    // MESSAGE signature only - cert-signing above (falcon_cert_prepared-gated, once per
    // vehicle lifetime) is deliberately left real, isolating per-message signing cost as the
    // only variable changed. The full signature array (OQS_SIG_falcon_512_length_signature: 752
    // bytes as of liboqs 0.16.0, 666 in the pre-2026-09-17 build) is always sent on the wire
    // regardless of declared length (wire_length() truncation only ever happens inside
    // cert_cycle, which is positioned after signature in the struct - see wire_length()'s own
    // comment), so filling the whole array and declaring the max length is both memory-safe
    // and wire-format-consistent with what already happens for every real signature today.
    if(bypass_falcon_signing()) {
        spdu.signature_buffer_length = OQS_SIG_falcon_512_length_signature;
        if(RAND_bytes(spdu.signature, (int) spdu.signature_buffer_length) != 1) {
            perror("RAND_bytes failed while filling bypass signature bytes");
            exit(EXIT_FAILURE);
        }
    }
    else {
        sign_message_falcon(spdu);
    }

}


bsm Vehicle::generate_bsm(int timestep) {
    // Wraps around modulo the trace length: with attackerMatchLegitDuration the message count
    // isn't known in advance, so it can exceed the trace's row count. Known limitation: the
    // row-(n-1) -> row-0 step at the wrap yields a speed/heading jump for moving traces (e.g.
    // 0.csv); harmless for the stationary attacker trace, and BSM content doesn't affect the
    // measured latency/drop metrics. Unreachable in count mode for all current configs.
    size_t n = this->timestep.size();
    if(n == 0) {
        std::cerr << "Trace file for vehicle " << (int) this->number << " has no rows" << std::endl;
        exit(EXIT_FAILURE);
    }
    size_t row = (size_t) timestep % n;
    if(row == 0 && timestep != 0 && !trace_wrap_logged) {
        std::cout << "[TraceWrap] vehicle=" << (int) this->number << " trace_rows=" << n << std::endl;
        trace_wrap_logged = true;
    }
    float latitude = this->timestep[row][0];
    float longitude = this->timestep[row][1];
    float elevation = this->timestep[row][2];
    float speed = 0;
    float heading = 0;
    if(timestep != 0) {
        size_t prev = (size_t) (timestep - 1) % n;
        speed = calculate_speed_kph(this->timestep[prev][0],
                                    latitude,
                                    this->timestep[prev][1],
                                    longitude,
                                    100);

        heading = calculate_heading(this->timestep[prev][0],
                                    latitude,
                                    this->timestep[prev][1],
                                    longitude);
    }
    std::cout << "Calculated heading:\t" << heading << std::endl;
    bsm new_bsm = {latitude, longitude, elevation, speed, heading};
    return new_bsm;
}

template<typename SpduT>
void Vehicle::print_bsm(SpduT &spdu) {

    // '\n' not std::endl throughout this hot per-message print path deliberately: std::endl
    // forces a stream flush (a real write() syscall) on every use. Investigated as the likely
    // cause of a large gap between isolated Falcon verify cost (~0.03ms) and total per-message
    // receive_loop iteration cost (~4.3ms) under sustained flood - see context/UPDATES.md. The final
    // flushed byte content is unaffected (exit() still flushes/destructs std::cout at process
    // exit), so this doesn't change what a --test regression comparison sees, only when it's
    // physically written.
    std::cout << "BSM received!" << '\n';
    std::cout << "\tLocation:\t";
    std::cout << spdu.data.signedData.tbsData.message.latitude;
    std::cout << ", ";
    std::cout << spdu.data.signedData.tbsData.message.longitude;
    std::cout <<", ";
    std::cout << spdu.data.signedData.tbsData.message.elevation;
    std::cout << '\n';
    std::cout << "\tSpeed:\t\t" << spdu.data.signedData.tbsData.message.speed << '\n';
    std::cout << "\tHeading:\t" << spdu.data.signedData.tbsData.message.heading << '\n';
}

/*
 * This is largely a debugging function so we can print and view received data, e.g., to make sure that things are being
 * sent and received properly.
 */
template<typename SpduT>
void Vehicle::print_spdu(SpduT &spdu, bool valid) {
    std::cout << "SPDU received!" << '\n';
    std::cout << "\tID:\t" << (int) spdu.vehicle_id << '\n';
    std::cout << "\tValid:\t";
    valid ? std::cout << "TRUE" : std::cout << "FALSE";
    std::cout << '\n';

    std::cout << "\tSent:\t" << std::chrono::system_clock::to_time_t(spdu.data.signedData.tbsData.headerInfo.timestamp) << '\n';
}

void Vehicle::sign_message_ecdsa(Vehicle::ecdsa_spdu &spdu) {

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.tbsData, sizeof(spdu.data.signedData.tbsData), hash);

    unsigned int signature_buffer_length = ECDSA_size(private_ec_key);
    auto signature = (unsigned char*) OPENSSL_malloc(signature_buffer_length);
    ecdsa_sign(hash, private_ec_key, &signature_buffer_length, signature);

    spdu.signature_buffer_length = signature_buffer_length;

    for(int i = 0; i < signature_buffer_length; i++) {
        spdu.signature[i] = signature[i];
    }

}

void Vehicle::sign_message_falcon(Vehicle::falcon_spdu &spdu) {

    size_t sig_len = OQS_SIG_falcon_512_length_signature;
    auto signature = (unsigned char*) malloc(sig_len);
    auto message_sign_start = std::chrono::steady_clock::now();
    falcon_sign(signature, sig_len,
                (uint8_t*) &spdu.data.signedData.tbsData, sizeof(spdu.data.signedData.tbsData),
                falcon_secret_key);
    falcon_message_sign_times_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - message_sign_start).count());

    spdu.signature_buffer_length = (unsigned int) sig_len;

    for(unsigned int i = 0; i < spdu.signature_buffer_length; i++) {
        spdu.signature[i] = signature[i];
    }
    free(signature);

}

bool Vehicle::verify_message_ecdsa(Vehicle::ecdsa_spdu &spdu, std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> received_time, int vehicle_id) {

    EC_KEY *verification_private_ec_key = nullptr, *verification_cert_private_ec_key = nullptr;

    load_key(vehicle_id, false, verification_private_ec_key);
    load_key(vehicle_id, true, verification_cert_private_ec_key);

    // Verify certificate signature
    unsigned char certificate_hash[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.cert, sizeof(spdu.data.signedData.cert), certificate_hash);
    bool cert_result = ecdsa_verify(certificate_hash, spdu.data.certificate_signature, &spdu.certificate_signature_buffer_length, verification_cert_private_ec_key);

    // Verify message signature
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.tbsData, sizeof(spdu.data.signedData.tbsData), hash);
    bool sig_result = ecdsa_verify(hash, spdu.signature, &spdu.signature_buffer_length, verification_private_ec_key);

    // Verify time constraint: message is valid if less than 30 seconds (30000ms) have elapsed since transmission
    std::chrono::duration<double, std::milli> elapsed_time =  received_time -  spdu.data.signedData.tbsData.headerInfo.timestamp;
    bool recent = elapsed_time.count() < 30000;

    // Return result
    return cert_result && sig_result && recent;
}

// Falcon cert fragmentation helpers (Update 4 / Phase 1).
void Vehicle::truncated_sha256_8(const void *data, size_t length, unsigned char out[8]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    sha256sum(const_cast<void*>(data), length, digest);
    memcpy(out, digest, 8);
}

std::vector<uint8_t> Vehicle::build_falcon_cert_bundle_blob(const falcon_explicit_certificate &cert,
                                                              unsigned int cert_sig_len,
                                                              const unsigned char *cert_sig) {
    std::vector<uint8_t> blob(sizeof(cert) + sizeof(cert_sig_len) + cert_sig_len);
    size_t offset = 0;
    memcpy(blob.data() + offset, &cert, sizeof(cert));
    offset += sizeof(cert);
    memcpy(blob.data() + offset, &cert_sig_len, sizeof(cert_sig_len));
    offset += sizeof(cert_sig_len);
    memcpy(blob.data() + offset, cert_sig, cert_sig_len);
    return blob;
}

void Vehicle::cfrag_falcon(const std::vector<uint8_t> &blob, uint32_t m,
                            std::vector<std::vector<uint8_t>> &segments_out) {
    size_t chunk = (blob.size() + m - 1) / m;
    segments_out.assign(m, {});
    for(uint32_t i = 0; i < m; i++) {
        size_t start = std::min(blob.size(), (size_t) i * chunk);
        size_t end = std::min(blob.size(), start + chunk);
        segments_out[i].assign(blob.begin() + (long) start, blob.begin() + (long) end);
    }
}

bool Vehicle::ccons_falcon(const std::vector<std::vector<uint8_t>> &segments,
                            const std::array<uint8_t, 8> &expected_full_hash,
                            unsigned char cert_out[sizeof(falcon_explicit_certificate)],
                            unsigned int &cert_sig_len_out,
                            unsigned char cert_sig_out[OQS_SIG_falcon_512_length_signature],
                            std::array<uint8_t, 32> *full_digest_out) {
    std::vector<uint8_t> blob;
    for(const auto &seg : segments) {
        blob.insert(blob.end(), seg.begin(), seg.end());
    }

    // Same single SHA-256 truncated_sha256_8 would do; the full digest is kept so verify-once
    // mode (Update 23) can reuse it instead of hashing the blob a second time.
    unsigned char digest[SHA256_DIGEST_LENGTH];
    sha256sum(blob.data(), blob.size(), digest);
    if(memcmp(digest, expected_full_hash.data(), 8) != 0) {
        return false;
    }

    if(blob.size() < sizeof(falcon_explicit_certificate) + sizeof(unsigned int)) {
        return false;
    }

    // Raw byte copy only — never materialize a live falcon_explicit_certificate object from wire
    // bytes (see falcon_reconstructed_cert_entry::cert_bytes for why).
    size_t offset = 0;
    memcpy(cert_out, blob.data() + offset, sizeof(falcon_explicit_certificate));
    offset += sizeof(falcon_explicit_certificate);
    unsigned int sig_len;
    memcpy(&sig_len, blob.data() + offset, sizeof(unsigned int));
    offset += sizeof(unsigned int);

    if(sig_len > OQS_SIG_falcon_512_length_signature || blob.size() < offset + sig_len) {
        return false;
    }
    memcpy(cert_sig_out, blob.data() + offset, sig_len);
    cert_sig_len_out = sig_len;
    if(full_digest_out) memcpy(full_digest_out->data(), digest, full_digest_out->size());

    return true;
}

bool Vehicle::verify_message_falcon(Vehicle::falcon_spdu &spdu, std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> received_time, int vehicle_id) {

    auto verify_call_start = std::chrono::steady_clock::now();
    if(falcon_last_verify_start_set) {
        falcon_loop_iteration_gap_ms.push_back(std::chrono::duration<double, std::milli>(verify_call_start - falcon_last_verify_start).count());
    }
    falcon_last_verify_start = verify_call_start;
    falcon_last_verify_start_set = true;

    // Receiver-side throughput trend (transient-burst vs sustained-rate-mismatch check).
    // Periodic, not per-message, to keep overhead negligible.
    if(!falcon_receive_progress_started) {
        falcon_receive_progress_start = std::chrono::steady_clock::now();
        falcon_receive_progress_started = true;
    }
    falcon_receive_progress_count++;
    if(falcon_receive_progress_count % 1000 == 0) {
        auto now = std::chrono::steady_clock::now();
        double elapsed_s = std::chrono::duration<double>(now - falcon_receive_progress_start).count();
        double rate = elapsed_s > 0 ? (double) falcon_receive_progress_count / elapsed_s : 0.0;
        std::cout << "[ReceiverProgress] processed=" << falcon_receive_progress_count
                  << " elapsed_s=" << elapsed_s
                  << " achieved_rate_msgs_per_sec=" << rate << std::endl;
    }

    // Phase 3 spam filter dispatch (context/UPDATES.md Update 4/9). Filter OFF (default) falls
    // straight through to the unmodified Phase-2 body below - byte-for-byte identical to
    // before Phase 3 existed, by construction, not by careful editing. Filter ON hands off
    // entirely to a self-contained dual-path implementation; nothing below this point runs
    // for a filter-ON message.
    falcon_rx_kind = spdu.cert_cycle.message_kind; // Update 23 timing record (both paths)
    if(spam_filter_enabled) {
        return spam_filter_verify_falcon(spdu, received_time, vehicle_id);
    }

    uint8_t verification_public_key[OQS_SIG_falcon_512_length_public_key];
    load_falcon_key(vehicle_id, true, verification_public_key);

    auto &env = spdu.cert_cycle;
    uint8_t sender_id = (uint8_t) vehicle_id;

    // Per-message [FalconCertCycle] RX/Reconstructed/DROP lines are suppressed when timing
    // probes are on (Update 23): they sit inside the t0..t3 window and no harness parses them.
    if(!falcon_timing_prefix) {
        std::string kind_str = (env.message_kind == cert_message_kind::SEGMENT_CARRYING)
            ? ("SEGMENT_CARRYING(idx=" + std::to_string((int) env.fragment_index) + ")")
            : "HASH_ONLY";
        std::cout << "[FalconCertCycle] RX vehicle=" << vehicle_id
                  << " fragment_set_id=" << env.fragment_set_id
                  << " kind=" << kind_str << '\n';
    }

    int64_t t1 = FALCON_TIMING_NA, t2 = FALCON_TIMING_NA, cert_verify_ns = FALCON_TIMING_NA;
    falcon_cert_path cert_path = falcon_cert_path::NA;

    if(env.message_kind == cert_message_kind::SEGMENT_CARRYING
       && env.fragment_count >= FALCON_CERT_CYCLE_M_MIN_FEASIBLE && env.fragment_count <= FALCON_CERT_CYCLE_M_MAX
       && env.fragment_index < env.fragment_count) {
        unsigned char actual_seg_hash[8];
        truncated_sha256_8(env.segment_data, env.segment_length, actual_seg_hash);

        if(memcmp(actual_seg_hash, env.seg_hash, sizeof(actual_seg_hash)) != 0) {
            std::cout << "[FalconCertCycle] Seg Hash mismatch, vehicle=" << vehicle_id
                       << " fragment_set_id=" << env.fragment_set_id
                       << " fragment_index=" << (int) env.fragment_index
                       << " -- dropped, not stored" << std::endl;
        }
        else {
            auto &buf = falcon_cert_buffers[sender_id];

            // Phase 1: naive reset-on-mismatched-fragment_set_id, NOT yet a defense (Phase 3
            // wraps this same buffer with cap=1-per-sender/TTL/reject policy).
            if(buf.fragment_set_id != env.fragment_set_id || buf.fragment_count != env.fragment_count) {
                buf.fragment_set_id = env.fragment_set_id;
                buf.fragment_count = env.fragment_count;
                for(auto &slot : buf.segments) slot.reset();
            }
            buf.segments[env.fragment_index] = std::vector<uint8_t>(env.segment_data, env.segment_data + env.segment_length);

            if(all_segments_present(buf.segments, buf.fragment_count)) {
                auto segs = collect_segments(buf.segments, buf.fragment_count);
                std::array<uint8_t, 8> expected_hash{};
                memcpy(expected_hash.data(), env.full_hash, expected_hash.size());

                falcon_reconstructed_cert_entry entry;
                if(ccons_falcon(segs, expected_hash, entry.cert_bytes, entry.cert_sig_len, entry.cert_sig,
                                falcon_cert_verify_once ? &entry.full_digest : nullptr)) {
                    t1 = falcon_ns_since_ref(std::chrono::steady_clock::now());
                    falcon_reconstructed_certs[sender_id] = entry;
                    if(!falcon_timing_prefix)
                        std::cout << "[FalconCertCycle] Reconstructed cert OK, vehicle=" << vehicle_id
                                  << " fragment_set_id=" << env.fragment_set_id << std::endl;
                }
                else {
                    std::cout << "[FalconCertCycle] Reconstruction FAILED (Full Hash mismatch), vehicle=" << vehicle_id
                              << " fragment_set_id=" << env.fragment_set_id << std::endl;
                }
                for(auto &slot : buf.segments) slot.reset();
            }
        }
    }

    bool cert_result;
    bool no_cert_yet = false;
    auto cert_it = falcon_reconstructed_certs.find(sender_id);
    if(cert_it == falcon_reconstructed_certs.end()) {
        cert_result = false;
        no_cert_yet = true;
        if(!falcon_timing_prefix)
            std::cout << "[FalconCertCycle] DROP vehicle=" << vehicle_id
                      << ": no reconstructed certificate yet (not a signature failure)" << std::endl;
    }
    else if(falcon_cert_verify_once && falcon_verified_cert_digests.count(cert_it->second.full_digest)) {
        // Verify-once mode (Fig. 3 version B): this exact cert already passed falcon_verify.
        cert_result = true;
        cert_path = falcon_cert_path::CACHED;
    }
    else {
        auto &entry = cert_it->second;
        auto cert_verify_start = std::chrono::steady_clock::now();
        cert_result = falcon_verify(entry.cert_bytes, sizeof(entry.cert_bytes),
                                     entry.cert_sig, entry.cert_sig_len,
                                     verification_public_key);
        auto cert_verify_end = std::chrono::steady_clock::now();
        falcon_cert_verify_times_ms.push_back(std::chrono::duration<double, std::milli>(cert_verify_end - cert_verify_start).count());
        t2 = falcon_ns_since_ref(cert_verify_end);
        cert_verify_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(cert_verify_end - cert_verify_start).count();
        cert_path = falcon_cert_path::VERIFIED_NOW;
        if(falcon_cert_verify_once && cert_result) falcon_verified_cert_digests.insert(entry.full_digest);
    }

    // Verify message signature - raw bytes, no sha256sum()
    auto message_verify_start = std::chrono::steady_clock::now();
    bool sig_result = falcon_verify((uint8_t*) &spdu.data.signedData.tbsData, sizeof(spdu.data.signedData.tbsData),
                                     spdu.signature, spdu.signature_buffer_length,
                                     verification_public_key);
    auto message_verify_end = std::chrono::steady_clock::now();
    falcon_message_verify_times_ms.push_back(std::chrono::duration<double, std::milli>(message_verify_end - message_verify_start).count());
    int64_t msg_verify_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(message_verify_end - message_verify_start).count();

    // Verify time constraint: message is valid if less than 30 seconds (30000ms) have elapsed since transmission
    std::chrono::duration<double, std::milli> elapsed_time = received_time - spdu.data.signedData.tbsData.headerInfo.timestamp;
    bool recent = elapsed_time.count() < 30000;

    bool overall_valid = cert_result && sig_result && recent;

    // Phase 2 (Update 4 step 2) metrics instrumentation. Latency is measured end-to-end from this
    // BSM's own embedded send timestamp through to the moment THIS verify call finishes - not
    // just packet-arrival time - so it captures both queueing delay (receive_loop is a single
    // sequential loop; a message stuck behind others in the OS socket buffer only gets dequeued
    // once the prior iteration's full verify+print work completes) and this message's own verify
    // processing cost. That matches what the ~100ms deadline is actually about: a BSM isn't
    // "usable" until verification completes, not when the packet merely arrives.
    auto verify_complete_time = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    std::chrono::duration<double, std::milli> latency = verify_complete_time - spdu.data.signedData.tbsData.headerInfo.timestamp;

    falcon_verify_outcome outcome;
    if(no_cert_yet) outcome = falcon_verify_outcome::NO_CERT_YET;
    else if(!sig_result) outcome = falcon_verify_outcome::INVALID_SIGNATURE;
    else if(!recent) outcome = falcon_verify_outcome::EXPIRED;
    else if(!cert_result) outcome = falcon_verify_outcome::INVALID_CERT_SIGNATURE;
    else outcome = falcon_verify_outcome::VALID;
    int64_t t3 = falcon_ns_since_ref(std::chrono::steady_clock::now());

    falcon_metrics.push_back({sender_id, outcome, latency.count()});
    record_falcon_timing(sender_id, outcome, cert_path, t1, t2, t3, cert_verify_ns, msg_verify_ns);

    if(latency.count() > 100.0) {
        std::cout << "[DeadlineMiss] vehicle=" << vehicle_id
                  << " outcome=" << (int) outcome
                  << " latency_ms=" << latency.count() << std::endl;
    }

    return overall_valid;
}

// ============================================================================================
// Phase 3 Spam Filter (context/UPDATES.md Update 4/9). Dispatched to from the top of
// verify_message_falcon only when spam_filter_enabled is true - the code above this point in
// the file is the untouched Phase-2 body, never reached when the filter is on.
// ============================================================================================

uint64_t Vehicle::falcon_full_hash_to_key(const unsigned char full_hash[8]) {
    uint64_t key;
    memcpy(&key, full_hash, sizeof(key));
    return key;
}

void Vehicle::enforce_spam_filter_global_cap() {
    while(spam_filter_buffers.size() + spam_filter_cert_cache.size() > spam_filter_global_state_cap) {
        bool have_oldest = false;
        std::chrono::steady_clock::time_point oldest_ts{};
        bool oldest_is_buffer = false;
        uint8_t oldest_buffer_key = 0;
        uint64_t oldest_cache_key = 0;

        for(auto &kv : spam_filter_buffers) {
            if(!have_oldest || kv.second.first_seen_ts < oldest_ts) {
                have_oldest = true;
                oldest_ts = kv.second.first_seen_ts;
                oldest_is_buffer = true;
                oldest_buffer_key = kv.first;
            }
        }
        for(auto &kv : spam_filter_cert_cache) {
            if(!have_oldest || kv.second.cached_at < oldest_ts) {
                have_oldest = true;
                oldest_ts = kv.second.cached_at;
                oldest_is_buffer = false;
                oldest_cache_key = kv.first;
            }
        }
        if(!have_oldest) break; // both empty - shouldn't happen given the while condition, but don't spin

        if(oldest_is_buffer) {
            std::cout << "[SpamFilter] GLOBAL_CAP_EVICT buffer sender=" << (int) oldest_buffer_key << std::endl;
            spam_filter_buffers.erase(oldest_buffer_key);
        }
        else {
            std::cout << "[SpamFilter] GLOBAL_CAP_EVICT cache hash=" << oldest_cache_key << std::endl;
            spam_filter_cert_cache.erase(oldest_cache_key);
        }
    }
}

bool Vehicle::spam_filter_drop(uint8_t sender_id, bool is_attacker, spam_drop_reason reason, const char *reason_label,
                                std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> send_ts) {
    if(is_attacker) attacker_spam_drop_reason_counts[(size_t) reason]++;
    else legit_spam_drop_reason_counts[(size_t) reason]++;

    auto now = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    std::chrono::duration<double, std::milli> latency = now - send_ts;

    falcon_metrics.push_back({sender_id, falcon_verify_outcome::SPAM_FILTERED, latency.count()});
    // Filter-on path is not probed beyond t0/outcome (Update 23); keeps row count == falcon_metrics.
    record_falcon_timing(sender_id, falcon_verify_outcome::SPAM_FILTERED, falcon_cert_path::NA,
                         FALCON_TIMING_NA, FALCON_TIMING_NA, FALCON_TIMING_NA, FALCON_TIMING_NA, FALCON_TIMING_NA);

    if(latency.count() > 100.0) {
        std::cout << "[DeadlineMiss] vehicle=" << (int) sender_id
                  << " outcome=" << (int) falcon_verify_outcome::SPAM_FILTERED
                  << " latency_ms=" << latency.count() << std::endl;
    }

    std::cout << "[SpamFilter] DROP reason=" << reason_label << " vehicle=" << (int) sender_id << std::endl;

    return false;
}

bool Vehicle::spam_filter_record_outcome(uint8_t sender_id, falcon_verify_outcome outcome,
                                          std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> send_ts) {
    auto now = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    std::chrono::duration<double, std::milli> latency = now - send_ts;

    falcon_metrics.push_back({sender_id, outcome, latency.count()});
    record_falcon_timing(sender_id, outcome, falcon_cert_path::NA,
                         FALCON_TIMING_NA, FALCON_TIMING_NA, FALCON_TIMING_NA, FALCON_TIMING_NA, FALCON_TIMING_NA);

    if(latency.count() > 100.0) {
        std::cout << "[DeadlineMiss] vehicle=" << (int) sender_id
                  << " outcome=" << (int) outcome
                  << " latency_ms=" << latency.count() << std::endl;
    }

    return false; // NO_CERT_YET (pending) and INVALID_CERT_SIGNATURE (terminal) are both non-valid
}

bool Vehicle::spam_filter_admit(Vehicle::falcon_spdu &spdu, uint8_t sender_id,
        std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> send_ts,
        std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> received_time) {

    uint8_t verification_public_key[OQS_SIG_falcon_512_length_public_key];
    load_falcon_key(sender_id, true, verification_public_key);

    auto message_verify_start = std::chrono::steady_clock::now();
    bool sig_result = falcon_verify((uint8_t*) &spdu.data.signedData.tbsData, sizeof(spdu.data.signedData.tbsData),
                                     spdu.signature, spdu.signature_buffer_length,
                                     verification_public_key);
    falcon_message_verify_times_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - message_verify_start).count());

    std::chrono::duration<double, std::milli> elapsed_time = received_time - send_ts;
    bool recent = elapsed_time.count() < 30000;

    bool overall_valid = sig_result && recent;

    falcon_verify_outcome outcome;
    if(!sig_result) outcome = falcon_verify_outcome::INVALID_SIGNATURE;
    else if(!recent) outcome = falcon_verify_outcome::EXPIRED;
    else outcome = falcon_verify_outcome::VALID;

    spam_filter_record_outcome(sender_id, outcome, send_ts); // side effects only (metrics push, DeadlineMiss)
    return overall_valid;
}

bool Vehicle::spam_filter_verify_falcon(Vehicle::falcon_spdu &spdu,
        std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> received_time,
        int vehicle_id) {

    uint8_t sender_id = (uint8_t) vehicle_id;
    bool is_attacker = (int) sender_id >= spam_filter_num_vehicles;
    auto &env = spdu.cert_cycle;
    auto send_ts = spdu.data.signedData.tbsData.headerInfo.timestamp;
    uint64_t hash_key = falcon_full_hash_to_key(env.full_hash);

    // Permanent instrumentation (added during Checkpoint 2, context/UPDATES.md Update 11) - mirrors
    // the filter-OFF path's line 728 print, which this path never reaches. Needed to trace
    // per-message fragment_set_id/kind/idx under filter-ON; Checkpoint 3's buffer-cap
    // investigation depends on this same visibility.
    std::cout << "[SpamFilterDiag] RX vehicle=" << (int) sender_id
              << " fragment_set_id=" << env.fragment_set_id
              << " kind=" << (env.message_kind == cert_message_kind::HASH_ONLY ? "HASH_ONLY" : "SEGMENT_CARRYING")
              << " idx=" << (int) env.fragment_index << '\n';

    if(env.message_kind == cert_message_kind::HASH_ONLY) {
        // ---- Path A: HASH_ONLY BSMs. Cache-first ordering (user-directed reorder, made
        // explicitly): cache membership is determinative - a miss can never be admitted
        // regardless of what frequency/length/timestamp say - so it's resolved first rather
        // than spending cycles on checks that can't change the outcome. ----

        // 1. Hash ID in cache
        auto cache_it = spam_filter_cert_cache.find(hash_key);
        if(cache_it == spam_filter_cert_cache.end()) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::NO_CACHE, "NO_CACHE", send_ts);
        }

        // 2. Transmission frequency (send-timestamp basis - see falcon_last_seen_sendts's
        // declaration comment in Vehicle.h for why arrival-time would false-drop legit traffic)
        auto last_it = falcon_last_seen_sendts.find(sender_id);
        if(last_it != falcon_last_seen_sendts.end()) {
            std::chrono::duration<double, std::milli> gap = send_ts - last_it->second;
            if(gap.count() < spam_filter_min_gap_ms) {
                return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::RATE, "RATE", send_ts);
            }
        }

        // 3. Message length - wire_length() for a HASH_ONLY message is a fixed struct-layout
        // offset independent of any attacker-controlled field, so this is a genuine check here
        // (contrast Path B's length check below, which is frame-integrity, not authentication).
        if(falcon_last_rx_bytes != (ssize_t) wire_length(spdu)) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::LENGTH, "LENGTH", send_ts);
        }

        // 4. Timestamp freshness (100ms admission deadline) - distinct from the 30s anti-replay
        // window, which stays as the security gate inside spam_filter_admit below.
        std::chrono::duration<double, std::milli> since_send = received_time - send_ts;
        if(since_send.count() >= spam_filter_admit_ms) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::STALE, "STALE", send_ts);
        }

        // 5. Default fail is implicit: anything not explicitly admitted above already returned.
        // Admit: cached trust - no cert reconstruction, no cert-sig re-verify.
        falcon_last_seen_sendts[sender_id] = send_ts;
        cache_it->second.cached_at = std::chrono::steady_clock::now(); // refresh LRU position
        return spam_filter_admit(spdu, sender_id, send_ts, received_time);
    }
    else {
        // ---- Path B: SEGMENT_CARRYING BSMs. Cache-hit fast path first (mirrors Path A's cache
        // check placement), so an already-cached vehicle's segment-carrying messages skip
        // reconstruction and cert-sig verify entirely, exactly like its hash-only messages.
        // Fragment handling/buffering is the fall-through taken only on a cache miss. ----

        // Cheap checks: frequency, then length.
        auto last_it = falcon_last_seen_sendts.find(sender_id);
        if(last_it != falcon_last_seen_sendts.end()) {
            std::chrono::duration<double, std::milli> gap = send_ts - last_it->second;
            if(gap.count() < spam_filter_min_gap_ms) {
                return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::RATE, "RATE", send_ts);
            }
        }
        // Length here validates FRAME INTEGRITY (actual datagram size matches what its own
        // declared segment_length implies via wire_length()) - not independent ground truth,
        // since segment_length is itself attacker-controlled for a fabricated packet. Still a
        // meaningful cheap check (catches truncated/malformed/padded datagrams before further
        // processing), and critically the segment_length bound below is a real, load-bearing
        // fix: the existing Phase-1 code (verify_message_falcon's untouched body above) has NO
        // bound on segment_length before using it as a read length into the fixed-size
        // segment_data buffer for the seg-hash check - an attacker-controlled uint16_t up to
        // 65535 against an ~819-byte buffer is a latent out-of-bounds read. That pre-existing
        // path is untouched by design (filter-OFF must stay byte-identical), but this NEW
        // filter-ON path must not blindly inherit it.
        if(env.segment_length > FALCON_CERT_SEGMENT_MAX_BYTES || falcon_last_rx_bytes != (ssize_t) wire_length(spdu)) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::LENGTH, "LENGTH", send_ts);
        }

        // Full-hash cache check (fast path)
        auto cache_it = spam_filter_cert_cache.find(hash_key);
        if(cache_it != spam_filter_cert_cache.end()) {
            std::chrono::duration<double, std::milli> since_send = received_time - send_ts;
            if(since_send.count() >= spam_filter_admit_ms) {
                return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::STALE, "STALE", send_ts);
            }
            falcon_last_seen_sendts[sender_id] = send_ts;
            cache_it->second.cached_at = std::chrono::steady_clock::now();
            return spam_filter_admit(spdu, sender_id, send_ts, received_time);
        }

        // ---- Cache MISS: reconstruction fall-through (cached senders never reach here) ----
        std::chrono::duration<double, std::milli> since_send2 = received_time - send_ts;
        if(since_send2.count() >= spam_filter_admit_ms) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::STALE, "STALE", send_ts);
        }

        // Fragment metadata: count must be a feasible m and index must fall inside it. Checked
        // before any buffer is touched, so an out-of-range count never reaches reconstruction.
        if(env.fragment_count < FALCON_CERT_CYCLE_M_MIN_FEASIBLE || env.fragment_count > FALCON_CERT_CYCLE_M_MAX
           || env.fragment_index >= env.fragment_count) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::FRAG_INDEX, "FRAG_INDEX", send_ts);
        }

        unsigned char actual_seg_hash[8];
        truncated_sha256_8(env.segment_data, env.segment_length, actual_seg_hash);
        if(memcmp(actual_seg_hash, env.seg_hash, sizeof(actual_seg_hash)) != 0) {
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::SEG_HASH, "SEG_HASH", send_ts);
        }

        // TTL eviction housekeeping - runs before deciding attach/open/cap-drop below, so a
        // stale buffer never blocks a legitimate fresh start next cycle.
        auto buf_it = spam_filter_buffers.find(sender_id);
        if(buf_it != spam_filter_buffers.end()) {
            std::chrono::duration<double, std::milli> age = std::chrono::steady_clock::now() - buf_it->second.first_seen_ts;
            if(age.count() > buffer_ttl_ms) {
                std::cout << "[SpamFilter] BUFFER_TTL_EVICT sender=" << (int) sender_id << " (incomplete)" << std::endl;
                if(is_attacker) attacker_spam_drop_reason_counts[(size_t) spam_drop_reason::BUFFER_TTL_EVICT_INCOMPLETE]++;
                else legit_spam_drop_reason_counts[(size_t) spam_drop_reason::BUFFER_TTL_EVICT_INCOMPLETE]++;
                spam_filter_buffers.erase(buf_it);
                buf_it = spam_filter_buffers.end();
            }
        }

        if(buf_it == spam_filter_buffers.end()) {
            // No open buffer for this sender (never had one, or just evicted above).
            if(env.fragment_index != 0) {
                // Can't open a buffer starting mid-sequence - nothing to attach to.
                return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::BUFFER_CAP, "BUFFER_CAP", send_ts);
            }
            spam_filter_fragment_buffer newbuf;
            newbuf.fragment_set_id = env.fragment_set_id;
            newbuf.fragment_count = env.fragment_count;
            newbuf.segments[0] = std::vector<uint8_t>(env.segment_data, env.segment_data + env.segment_length);
            newbuf.first_seen_ts = std::chrono::steady_clock::now();
            spam_filter_buffers[sender_id] = newbuf;
            enforce_spam_filter_global_cap();
            falcon_last_seen_sendts[sender_id] = send_ts;
            return spam_filter_record_outcome(sender_id, falcon_verify_outcome::NO_CERT_YET, send_ts);
        }

        auto &buf = buf_it->second;
        if(buf.fragment_set_id != env.fragment_set_id) {
            // cap enforcement: a DIFFERENT fragment_set_id while an incomplete buffer is open
            // is DROPPED, not reset (replaces Phase 1's naive reset-on-mismatch).
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::BUFFER_CAP, "BUFFER_CAP", send_ts);
        }
        if(buf.fragment_count != env.fragment_count) {
            // Same fragment_set_id but a different m than the buffer was opened with: a
            // fragment-metadata violation. Dropped; the open buffer is left as-is.
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::FRAG_INDEX, "FRAG_INDEX", send_ts);
        }
        buf.segments[env.fragment_index] = std::vector<uint8_t>(env.segment_data, env.segment_data + env.segment_length);

        if(!all_segments_present(buf.segments, buf.fragment_count)) {
            falcon_last_seen_sendts[sender_id] = send_ts;
            return spam_filter_record_outcome(sender_id, falcon_verify_outcome::NO_CERT_YET, send_ts);
        }

        // Complete: reconstruct -> full-hash integrity check -> cert-sig verify -> branch.
        // The two branches below are mutually exclusive and BOTH terminal (see the invariant
        // documented on spam_filter_admit's declaration: only a successful cert-sig verify or
        // a cache hit ever reaches message-sig verify).
        auto segs = collect_segments(buf.segments, buf.fragment_count);
        std::array<uint8_t, 8> expected_hash{};
        memcpy(expected_hash.data(), env.full_hash, expected_hash.size());
        spam_filter_buffers.erase(buf_it); // free the slot regardless of outcome below

        falcon_reconstructed_cert_entry recon{}; // reused struct SHAPE only, NOT the Phase-1 map
        bool recon_ok = ccons_falcon(segs, expected_hash, recon.cert_bytes, recon.cert_sig_len, recon.cert_sig);
        if(!recon_ok) {
            // Both individual seg-hashes passed but the COMBINED full-hash check failed -
            // shouldn't normally happen; treated as an integrity failure (closest existing
            // bucket: SEG_HASH) rather than introducing a new reason category for an edge case
            // the plan's granular breakdown doesn't separately enumerate.
            falcon_last_seen_sendts[sender_id] = send_ts;
            return spam_filter_drop(sender_id, is_attacker, spam_drop_reason::SEG_HASH, "SEG_HASH", send_ts);
        }

        uint8_t verification_public_key[OQS_SIG_falcon_512_length_public_key];
        load_falcon_key(vehicle_id, true, verification_public_key);
        auto cert_verify_start = std::chrono::steady_clock::now();
        bool cert_sig_ok = falcon_verify(recon.cert_bytes, sizeof(recon.cert_bytes),
                                          recon.cert_sig, recon.cert_sig_len,
                                          verification_public_key);
        falcon_cert_verify_times_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - cert_verify_start).count());

        falcon_last_seen_sendts[sender_id] = send_ts;

        if(!cert_sig_ok) {
            // TERMINAL: churn/fabricated-cert case (context/UPDATES.md Update 9). No cache write. NO
            // message-sig verify - there is no trusted key to check a message signature
            // against once cert-sig verification has failed.
            return spam_filter_record_outcome(sender_id, falcon_verify_outcome::INVALID_CERT_SIGNATURE, send_ts);
        }

        // cert-sig VALID -> cache under hashedId8 -> THEN message-sig verify
        spam_filter_cert_cache_entry cache_entry;
        memcpy(cache_entry.cert_bytes, recon.cert_bytes, sizeof(cache_entry.cert_bytes));
        cache_entry.cert_sig_len = recon.cert_sig_len;
        memcpy(cache_entry.cert_sig, recon.cert_sig, sizeof(cache_entry.cert_sig));
        cache_entry.cached_at = std::chrono::steady_clock::now();
        spam_filter_cert_cache[hash_key] = cache_entry;
        enforce_spam_filter_global_cap();

        std::cout << "[SpamFilter] Reconstructed+cached cert OK, vehicle=" << vehicle_id
                  << " fragment_set_id=" << env.fragment_set_id << std::endl;

        return spam_filter_admit(spdu, sender_id, send_ts, received_time);
    }
}

// Nearest-rank percentile: no external stats dependency needed for these sample sizes.
double Vehicle::percentile_ms(std::vector<double> values, double p) {
    if(values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    size_t idx = (size_t) std::ceil(p / 100.0 * (double) values.size()) - 1;
    if(idx >= values.size()) idx = values.size() - 1;
    return values[idx];
}

void Vehicle::print_falcon_verify_metrics_summary(int num_vehicles, int expected_total,
                                                  bool legit_only_completeness) {
    std::vector<double> legit_valid_latencies;
    std::array<int, (size_t) falcon_verify_outcome::COUNT> legit_outcome_counts{};
    std::array<int, (size_t) falcon_verify_outcome::COUNT> attacker_outcome_counts{};
    int legit_total = 0, legit_deadline_miss = 0, attacker_total = 0;

    for(auto &rec : falcon_metrics) {
        if(rec.vehicle_id < num_vehicles) {
            legit_total++;
            legit_outcome_counts[(size_t) rec.outcome]++;
            if(rec.latency_ms > 100.0) legit_deadline_miss++;
            if(rec.outcome == falcon_verify_outcome::VALID) legit_valid_latencies.push_back(rec.latency_ms);
        }
        else {
            attacker_total++;
            attacker_outcome_counts[(size_t) rec.outcome]++;
        }
    }

    int legit_valid_count = legit_outcome_counts[(size_t) falcon_verify_outcome::VALID];
    int legit_no_cert_yet = legit_outcome_counts[(size_t) falcon_verify_outcome::NO_CERT_YET];
    int legit_non_startup = legit_total - legit_no_cert_yet;
    int legit_dropped_excl_startup = legit_non_startup - legit_valid_count;

    std::cout << "\n================ Falcon Verify Metrics Summary (Phase 2 baseline) ================" << std::endl;
    int64_t actual_total = legit_only_completeness ? (int64_t) legit_total : (int64_t) falcon_metrics.size();
    if(actual_total < expected_total) {
        // Duration mode ends on [ReceiveEndOfRun] by design, so a shortfall there means messages
        // were lost in transit (e.g. receive-buffer overflow), not that the loop stopped early.
        if(legit_only_completeness) {
            std::cout << "*** INCOMPLETE RUN: only " << actual_total << " of " << expected_total
                       << " expected legitimate messages were processed ***" << std::endl
                       << "*** (the run ended normally at [ReceiveEndOfRun], so the missing messages were"
                       << " lost before reaching the receiver - the numbers below reflect only what was"
                       << " actually received, not a full run) ***" << std::endl;
        }
        else {
            std::cout << "*** INCOMPLETE RUN: only " << actual_total << " of " << expected_total
                       << " expected messages were processed before receive_loop ended early ***"
                       << std::endl
                       << "*** (see the [ReceiveTimeout] line above - the numbers below reflect"
                       << " only what was actually received, not a full run) ***" << std::endl;
        }
    }
    std::cout << "Legitimate messages processed: " << legit_total << std::endl;
    std::cout << "Attacker messages processed:    " << attacker_total << std::endl;
    // Attacker-side outcome breakdown (context/UPDATES.md Update 16) - metrics only, mirrors the
    // legit-side breakdown below. falcon_metrics already records an outcome for every
    // message regardless of sender type, so this is pure aggregation, no new admission logic.
    std::cout << "Attacker outcome breakdown:" << std::endl;
    std::cout << "  VALID:                  " << attacker_outcome_counts[(size_t) falcon_verify_outcome::VALID] << std::endl;
    std::cout << "  INVALID_SIGNATURE:      " << attacker_outcome_counts[(size_t) falcon_verify_outcome::INVALID_SIGNATURE] << std::endl;
    std::cout << "  EXPIRED (>30s):         " << attacker_outcome_counts[(size_t) falcon_verify_outcome::EXPIRED] << std::endl;
    std::cout << "  INVALID_CERT_SIGNATURE: " << attacker_outcome_counts[(size_t) falcon_verify_outcome::INVALID_CERT_SIGNATURE] << std::endl;
    std::cout << "  NO_CERT_YET (pending):  " << attacker_outcome_counts[(size_t) falcon_verify_outcome::NO_CERT_YET] << std::endl;
    std::cout << "  SPAM_FILTERED:          " << attacker_outcome_counts[(size_t) falcon_verify_outcome::SPAM_FILTERED] << std::endl;
    // full_crypto includes EXPIRED (falcon_verify() ran and succeeded, just stale) - not just
    // VALID/INVALID_SIGNATURE/INVALID_CERT_SIGNATURE. cheap_reject uses SPAM_FILTERED directly,
    // not sum(attacker_spam_drop_reason_counts), which double-counts BUFFER_TTL_EVICT_INCOMPLETE
    // (a side-effect of evicting a stale PRIOR buffer, not this message's own outcome).
    int attacker_full_crypto = attacker_outcome_counts[(size_t) falcon_verify_outcome::VALID]
                              + attacker_outcome_counts[(size_t) falcon_verify_outcome::INVALID_SIGNATURE]
                              + attacker_outcome_counts[(size_t) falcon_verify_outcome::EXPIRED]
                              + attacker_outcome_counts[(size_t) falcon_verify_outcome::INVALID_CERT_SIGNATURE];
    int attacker_cheap_reject = attacker_outcome_counts[(size_t) falcon_verify_outcome::SPAM_FILTERED];
    int attacker_pending = attacker_outcome_counts[(size_t) falcon_verify_outcome::NO_CERT_YET];
    std::cout << "Attacker reached full crypto (>=1 falcon_verify paid): " << attacker_full_crypto << "/" << attacker_total << std::endl;
    std::cout << "Attacker rejected cheaply (SPAM_FILTERED, zero crypto): " << attacker_cheap_reject << "/" << attacker_total << std::endl;
    std::cout << "Attacker still pending (NO_CERT_YET at run end): " << attacker_pending << "/" << attacker_total << std::endl;
    std::cout << "Legitimate VALID: " << legit_valid_count << "/" << legit_total
              << " (" << (legit_total ? 100.0 * legit_valid_count / legit_total : 0.0) << "%)" << std::endl;
    std::cout << "Legitimate NO_CERT_YET (startup artifact, excluded from drop rate below): "
              << legit_no_cert_yet << std::endl;
    std::cout << "Legitimate drop rate, excluding startup: " << legit_dropped_excl_startup << "/" << legit_non_startup
              << " (" << (legit_non_startup ? 100.0 * legit_dropped_excl_startup / legit_non_startup : 0.0)
              << "% of non-startup legitimate messages)" << std::endl;
    std::cout << "  of which INVALID_SIGNATURE: " << legit_outcome_counts[(size_t) falcon_verify_outcome::INVALID_SIGNATURE] << std::endl;
    std::cout << "  of which EXPIRED (>30s):    " << legit_outcome_counts[(size_t) falcon_verify_outcome::EXPIRED] << std::endl;
    std::cout << "  of which INVALID_CERT_SIG:  " << legit_outcome_counts[(size_t) falcon_verify_outcome::INVALID_CERT_SIGNATURE] << std::endl;
    std::cout << "Legitimate deadline-miss ratio (>100ms, ALL legitimate messages, valid or not): "
              << legit_deadline_miss << "/" << legit_total
              << " (" << (legit_total ? 100.0 * legit_deadline_miss / legit_total : 0.0) << "%)" << std::endl;
    std::cout << "Legitimate VALID-message latency (ms): p50=" << percentile_ms(legit_valid_latencies, 50)
              << " p95=" << percentile_ms(legit_valid_latencies, 95)
              << " p99=" << percentile_ms(legit_valid_latencies, 99)
              << " max=" << (legit_valid_latencies.empty() ? 0.0 : *std::max_element(legit_valid_latencies.begin(), legit_valid_latencies.end()))
              << std::endl;

    // Sign/verify cost isolation (Phase 2 diagnostic follow-up): isolates just the
    // falcon_verify() call cost from the surrounding recv/print/reconstruction overhead
    // already reflected in the latency numbers above, so it can be compared directly against
    // the transmit side's [FalconSignCost] numbers to determine which side actually bottlenecks
    // the observed flood ceiling.
    std::cout << "Receiver-side falcon_verify() cost (ms): message avg="
              << (falcon_message_verify_times_ms.empty() ? 0.0 : std::accumulate(falcon_message_verify_times_ms.begin(), falcon_message_verify_times_ms.end(), 0.0) / falcon_message_verify_times_ms.size())
              << " p95=" << percentile_ms(falcon_message_verify_times_ms, 95)
              << " (n=" << falcon_message_verify_times_ms.size() << ")"
              << " | cert avg="
              << (falcon_cert_verify_times_ms.empty() ? 0.0 : std::accumulate(falcon_cert_verify_times_ms.begin(), falcon_cert_verify_times_ms.end(), 0.0) / falcon_cert_verify_times_ms.size())
              << " p95=" << percentile_ms(falcon_cert_verify_times_ms, 95)
              << " (n=" << falcon_cert_verify_times_ms.size() << ")" << std::endl;

    // Backlog-mechanism investigation: full per-message loop iteration cost (recv + all prints
    // + verify), for comparison against the isolated crypto verify cost just above. A large gap
    // between the two points at non-crypto overhead (I/O, bookkeeping) as the real bottleneck.
    double loop_gap_avg = falcon_loop_iteration_gap_ms.empty() ? 0.0 :
        std::accumulate(falcon_loop_iteration_gap_ms.begin(), falcon_loop_iteration_gap_ms.end(), 0.0) / falcon_loop_iteration_gap_ms.size();
    std::cout << "Receiver-side FULL loop iteration cost (ms, recv+prints+verify combined): avg="
              << loop_gap_avg
              << " p95=" << percentile_ms(falcon_loop_iteration_gap_ms, 95)
              << " max=" << (falcon_loop_iteration_gap_ms.empty() ? 0.0 : *std::max_element(falcon_loop_iteration_gap_ms.begin(), falcon_loop_iteration_gap_ms.end()))
              << " (n=" << falcon_loop_iteration_gap_ms.size() << ")" << std::endl;

    double recvfrom_avg = falcon_recvfrom_times_ms.empty() ? 0.0 :
        std::accumulate(falcon_recvfrom_times_ms.begin(), falcon_recvfrom_times_ms.end(), 0.0) / falcon_recvfrom_times_ms.size();
    std::cout << "  of which recvfrom() syscall duration: avg=" << recvfrom_avg
              << " p95=" << percentile_ms(falcon_recvfrom_times_ms, 95)
              << " max=" << (falcon_recvfrom_times_ms.empty() ? 0.0 : *std::max_element(falcon_recvfrom_times_ms.begin(), falcon_recvfrom_times_ms.end()))
              << " (n=" << falcon_recvfrom_times_ms.size() << ")" << std::endl;

    // Phase 3 spam filter additions - guarded so a filter-OFF run's summary is byte-identical
    // to Phase 2's (this whole block, and everything in it, is simply absent when the filter
    // is off). Crypto-verify accounting itself needs no NEW lines here: the "falcon_verify()
    // cost" (n=...) counts above are already populated by spam_filter_admit/Path B's own
    // timing pushes, so they already show the reduced call counts under filter-ON without any
    // separate bookkeeping - the "X of Y" story is visible directly in those existing counts.
    if(spam_filter_enabled) {
        int spam_filtered_count = legit_outcome_counts[(size_t) falcon_verify_outcome::SPAM_FILTERED];
        std::cout << "Legitimate SPAM_FILTERED (dropped by a cheap check, no crypto run): "
                  << spam_filtered_count << std::endl;
        static const char *reason_labels[(size_t) spam_drop_reason::COUNT] = {
            "RATE", "LENGTH", "NO_CACHE", "STALE", "FRAG_INDEX", "SEG_HASH",
            "BUFFER_CAP", "BUFFER_TTL_EVICT_INCOMPLETE"
        };
        std::cout << "Spam-filter drop reasons (legit senders):" << std::endl;
        for(size_t i = 0; i < (size_t) spam_drop_reason::COUNT; i++) {
            std::cout << "  " << reason_labels[i] << ": " << legit_spam_drop_reason_counts[i] << std::endl;
        }
        std::cout << "Spam-filter drop reasons (attacker senders):" << std::endl;
        for(size_t i = 0; i < (size_t) spam_drop_reason::COUNT; i++) {
            std::cout << "  " << reason_labels[i] << ": " << attacker_spam_drop_reason_counts[i] << std::endl;
        }
        std::cout << "Spam filter final state: " << spam_filter_buffers.size() << " open buffers, "
                  << spam_filter_cert_cache.size() << " cached certs (cap="
                  << spam_filter_global_state_cap << ")" << std::endl;
    }
    // Update 23 lines (always printed; nothing above changes). receiver_steady_ref_ns is the
    // absolute steady_clock value the timing CSVs are relative to, for the send_ns join.
    std::cout << "wall_clock_step=" << (falcon_wall_clock_step ? 1 : 0) << std::endl;
    std::cout << "receiver_steady_ref_ns="
              << std::chrono::duration_cast<std::chrono::nanoseconds>(falcon_steady_ref.time_since_epoch()).count() << std::endl;
    std::cout << "cert_verify_mode=" << (falcon_cert_verify_once ? "once" : "every") << std::endl;
    std::cout << "cert_verified_set_size=" << falcon_verified_cert_digests.size() << std::endl;
    std::cout << "====================================================================================\n" << std::endl;
}

void Vehicle::record_falcon_timing(uint8_t sender_id, falcon_verify_outcome outcome, falcon_cert_path cert_path,
                                   int64_t t1, int64_t t2, int64_t t3, int64_t cert_verify_ns, int64_t msg_verify_ns) {
    if(!falcon_timing_prefix) return;
    falcon_timing.push_back({sender_id, falcon_timing_seq[sender_id]++, falcon_rx_kind, outcome, cert_path,
                             falcon_rx_t0_ns, t1, t2, t3, cert_verify_ns, msg_verify_ns});
}

// Update 23: written once, after receive_loop has ended - never from the hot path.
void Vehicle::write_falcon_timing_files() {
    if(!falcon_timing_prefix) return;
    static const char *outcome_names[(size_t) falcon_verify_outcome::COUNT] = {
        "VALID", "INVALID_SIGNATURE", "NO_CERT_YET", "EXPIRED", "INVALID_CERT_SIGNATURE", "SPAM_FILTERED"
    };
    static const char *cert_path_names[] = {"NA", "VERIFIED_NOW", "CACHED"};
    auto na = [](int64_t v) { return v == FALCON_TIMING_NA ? std::string("NA") : std::to_string(v); };

    bool reallocated = falcon_timing.capacity() != falcon_timing_reserved;
    std::cout << "[TimingBuffer] rows=" << falcon_timing.size() << " reserved=" << falcon_timing_reserved
              << " reallocated=" << (reallocated ? 1 : 0) << std::endl;

    std::string prefix(falcon_timing_prefix);
    std::ofstream msg(prefix + "_msgtiming.csv");
    msg << "sender_id,seq,kind,outcome,cert_path,t0_ns,t1_ns,t2_ns,t3_ns,cert_verify_ns,msg_verify_ns\n";
    for(const auto &r : falcon_timing) {
        msg << (int) r.sender_id << ',' << r.seq << ','
            << (r.kind == cert_message_kind::SEGMENT_CARRYING ? "SEGMENT" : "HASH_ONLY") << ','
            << outcome_names[(size_t) r.outcome] << ',' << cert_path_names[(size_t) r.cert_path] << ','
            << na(r.t0) << ',' << na(r.t1) << ',' << na(r.t2) << ',' << na(r.t3) << ','
            << na(r.cert_verify_ns) << ',' << na(r.msg_verify_ns) << '\n';
    }

    // Per sender: time-to-first-verified = first VALID t3 - first received t0.
    struct sender_summary {
        int64_t first_t0 = FALCON_TIMING_NA, first_t1 = FALCON_TIMING_NA, first_valid_t3 = FALCON_TIMING_NA;
        uint32_t unverifiable_before_first_valid = 0;
    };
    std::map<int, sender_summary> senders;
    for(const auto &r : falcon_timing) {
        auto &ss = senders[r.sender_id];
        if(ss.first_t0 == FALCON_TIMING_NA) ss.first_t0 = r.t0;
        if(ss.first_t1 == FALCON_TIMING_NA && r.t1 != FALCON_TIMING_NA) ss.first_t1 = r.t1;
        if(ss.first_valid_t3 != FALCON_TIMING_NA) continue;
        if(r.outcome == falcon_verify_outcome::VALID) ss.first_valid_t3 = r.t3;
        else ss.unverifiable_before_first_valid++;
    }
    std::ofstream ttfv(prefix + "_ttfv.csv");
    ttfv << "sender_id,first_t0_ns,t1_ns,first_valid_t3_ns,ttfv_ms,n_unverifiable_before_first_valid\n";
    for(const auto &[id, ss] : senders) {
        ttfv << id << ',' << na(ss.first_t0) << ',' << na(ss.first_t1) << ',' << na(ss.first_valid_t3) << ',';
        if(ss.first_valid_t3 != FALCON_TIMING_NA) ttfv << (ss.first_valid_t3 - ss.first_t0) / 1e6;
        else ttfv << "NA";
        ttfv << ',' << ss.unverifiable_before_first_valid << '\n';
    }
}

void Vehicle::load_key(int number,  bool certificate, EC_KEY *&key_to_store){

    std::string temp = certificate ? "cert_keys/" + std::to_string(number) + "/p256.key" :
            "keys/" + std::to_string(number) + "/p256.key";

    const char* filepath = temp.c_str();

    FILE *fp = fopen(filepath,"r");
    if(fp != nullptr) {
        EVP_PKEY *key = nullptr;
        PEM_read_PrivateKey(fp, &key, nullptr, nullptr);
        key_to_store = nullptr;
        if (!key) {
            perror("Error while loading the key from file\n");
            exit(EXIT_FAILURE);
        }
        if (!(key_to_store = EVP_PKEY_get1_EC_KEY(key))) {
            perror("Error while getting EC key from loaded key\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        std::cout << filepath << std::endl;
        std::cout << "Error while opening file from path. Error number : " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

}

void Vehicle::load_falcon_key(int number, bool public_key, uint8_t *key_to_store) {

    std::string temp = "falcon_keys/" + std::to_string(number) + (public_key ? "/falcon.pub" : "/falcon.key");

    const char* filepath = temp.c_str();

    FILE *fp = fopen(filepath, "r");
    if(fp != nullptr) {
        size_t expected_len = public_key ? OQS_SIG_falcon_512_length_public_key : OQS_SIG_falcon_512_length_secret_key;
        std::string hex_string(expected_len * 2, '\0');
        if(fread(&hex_string[0], 1, expected_len * 2, fp) != expected_len * 2) {
            perror("Error while reading Falcon key file\n");
            exit(EXIT_FAILURE);
        }
        hex_to_bytes(hex_string, key_to_store, expected_len);
        fclose(fp);
    }
    else {
        std::cout << filepath << std::endl;
        std::cout << "Error while opening file from path. Error number : " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

}

// trace_files/1.csv is currently a duplicate of 0.csv (no distinct per-vehicle legit traces
// exist yet); 2.csv - loaded by the attacker when numVehicles=2 - is instead 100,000 identical
// stationary rows (10,5,0,0,0). Known simplification, not a bug: legitimate vehicles share identical
// trace data in these runs, so BSM content (position/speed/heading) is non-diverse across
// them. Fine for what's measured here (verification latency, drop rate - content-independent);
// call out as a limitation if these results reach the report.
void Vehicle::load_trace(int number) {
    std::string line;
    std::string word;

    std::fstream file("trace_files/" + std::to_string(number) + ".csv", std::ios::in);
    if(file.is_open()) {
        while(getline(file, line)) {
            timestep_data.clear();
            std::stringstream str(line);
            while(getline(str, word, ',')) {
                timestep_data.push_back(std::stof(word));
            }
            timestep.push_back(timestep_data);
        }
    }
    else {
        perror(("Error opening trace file for vehicle " + std::to_string(number)).c_str());
        exit(EXIT_FAILURE);
    }
}
