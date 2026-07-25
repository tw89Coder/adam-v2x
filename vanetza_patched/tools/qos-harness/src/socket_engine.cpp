#include "qos_harness/socket_engine.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#include <chrono>
#include <thread>
#include <iostream>
#include <vector>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <memory>

#include "qos_harness/pre_filter.hpp"
#include "qos_harness/queue_simulator.hpp"
#include "qos_harness/metrics_collector.hpp"
#include "qos_harness/router_fuzzing_context.hpp"
#include "qos_harness/file_manager.hpp"

#ifndef REPO_ROOT
#define REPO_ROOT "."
#endif

static const std::string LOCAL_REPO_ROOT_STR = REPO_ROOT;
static const std::string LOCAL_NORMAL_FOLDER = LOCAL_REPO_ROOT_STR + "/inputs/base_packets";
static const std::string LOCAL_ATTACK_FOLDER = LOCAL_REPO_ROOT_STR + "/inputs/attack_vectors/malware";

namespace qos_harness {

int UDPSocketEngine::run_receiver(int port, const std::string& build_type, bool no_taskset) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "[UDP RECEIVER ERROR] Failed to create socket.\n";
        return 1;
    }

    // Set large receive buffer size (4MB) to prevent kernel packet drops during high pps bursts
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[UDP RECEIVER ERROR] Failed to bind to port " << port << ".\n";
        close(sockfd);
        return 1;
    }

    std::cout << "======================================================================\n";
    std::cout << "[UDP RECEIVER DAEMON] Started on port " << port << " | Target Kernel: " << build_type << "\n";
    std::cout << "[UDP RECEIVER DAEMON] Listening for incoming session handshakes from Laptop...\n";
    std::cout << "======================================================================\n";

    std::vector<uint8_t> buffer(65536);
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    bool batch_active = true;

    while (batch_active) {
        // Step 1: Wait for START_SESSION control packet
        ssize_t nbytes = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&client_addr, &client_len);
        if (nbytes < 0) continue;

        if (nbytes == sizeof(UDPControlHeader)) {
            UDPControlHeader header;
            std::memcpy(&header, buffer.data(), sizeof(UDPControlHeader));

            if (header.magic == MAGIC_BATCH_END) {
                std::cout << "\n[UDP RECEIVER] Received BATCH_END control signal. Exiting receiver loop.\n";
                break;
            }

            if (header.magic == MAGIC_SESSION_START) {
                int mode = header.mode;
                double rate = header.pollution_rate;
                int total_pkts = header.total_packets;
                double lambda_pps = header.lambda_pps;
                uint32_t filter_mode = header.filter_mode; // 0=OFF, 1=ADAPTIVE, 2=STATIC100

                std::cout << "\n[UDP SESSION INIT] Mode: " << mode
                          << " | Rate: " << rate << "%"
                          << " | Total: " << total_pkts
                          << " | Lambda: " << lambda_pps << " pps"
                          << " | Filter: " << (filter_mode == 0 ? "OFF" : (filter_mode == 2 ? "STATIC 100%" : "ADAPTIVE FSM"))
                          << "\n";

                // Resolve output CSV filename
                std::string base_out_dir = LOCAL_REPO_ROOT_STR + "/outputs";
                std::string csv_base_dir = base_out_dir + "/csv_raw";
                std::string csv_target_dir = csv_base_dir + "/" + build_type;

                mkdir(base_out_dir.c_str(), 0755);
                mkdir(csv_base_dir.c_str(), 0755);
                mkdir(csv_target_dir.c_str(), 0755);

                char out_filename[512];
                if (rate == 0.0) {
                    std::snprintf(out_filename, sizeof(out_filename), "%s/qos_baseline.csv", csv_target_dir.c_str());
                } else if (filter_mode != 0) {
                    if (filter_mode == 2) {
                        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_full100.csv",
                                      csv_target_dir.c_str(), rate, mode);
                    } else {
                        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_filtered.csv",
                                      csv_target_dir.c_str(), rate, mode);
                    }
                } else {
                    std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d.csv",
                                  csv_target_dir.c_str(), rate, mode);
                }

                // Setup FSM Filter
                AdaptiveFilterFSM filter_fsm;
                if (filter_mode == 2) {
                    filter_fsm.set_execution_mode(AdaptiveFilterFSM::FilterExecutionMode::STATIC_FIXED_RATE);
                    filter_fsm.update_policy_params(0.05, 50.0, 600, 1.0);
                } else if (filter_mode == 1) {
                    filter_fsm.set_execution_mode(AdaptiveFilterFSM::FilterExecutionMode::DYNAMIC_ADAPTIVE_FSM);
                }

                MetricsCollector collector;
                collector.reserve(total_pkts);

                vanetza::RouterFuzzingContext context;
                context.initialize();

                int received_pkts = 0;
                bool session_running = true;

                long long inter_arrival_ns = (lambda_pps > 0) ? static_cast<long long>(1e9 / lambda_pps) : 0;
                long long accumulated_queue_ns = 0;

                while (session_running) {
                    ssize_t pkt_len = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&client_addr, &client_len);
                    if (pkt_len < 0) continue;

                    // Check for control packet
                    if (pkt_len == sizeof(UDPControlHeader)) {
                        UDPControlHeader ctrl;
                        std::memcpy(&ctrl, buffer.data(), sizeof(UDPControlHeader));
                        if (ctrl.magic == MAGIC_SESSION_END) {
                            session_running = false;
                            break;
                        } else if (ctrl.magic == MAGIC_BATCH_END) {
                            session_running = false;
                            batch_active = false;
                            break;
                        }
                    }

                    // Process Data Packet
                    vanetza::ByteBuffer packet_data(buffer.begin(), buffer.begin() + pkt_len);

                    auto start_t = std::chrono::high_resolution_clock::now();
                    bool is_drop = false;
                    if (filter_mode != 0) {
                        is_drop = filter_fsm.process_packet(packet_data);
                    }

                    if (!is_drop) {
                        vanetza::ByteBuffer pkt_copy = packet_data;
                        context.indicate(std::move(pkt_copy));
                    }
                    auto end_t = std::chrono::high_resolution_clock::now();

                    long long service_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_t - start_t).count();
                    long long total_latency_ns = service_ns;

                    if (inter_arrival_ns > 0) {
                        accumulated_queue_ns = std::max(0LL, accumulated_queue_ns + service_ns - inter_arrival_ns);
                        total_latency_ns += accumulated_queue_ns;
                    }

                    // Record metric
                    collector.recordPacket(received_pkts, false, is_drop, total_latency_ns);
                    received_pkts++;

                    if (received_pkts % (total_pkts / 10) == 0 || received_pkts == total_pkts) {
                        std::cout << "  [*] UDP Streaming Progress: " << received_pkts << " / " << total_pkts
                                  << " (" << (received_pkts * 100 / total_pkts) << "%)\n";
                    }
                }

                // Export CSV Log
                collector.exportToCSV(out_filename);
                std::cout << "[+] [SESSION SAVED] Target: " << out_filename << " | Total Received: " << received_pkts << "\n";
                std::cout << "----------------------------------------------------------------------\n";
            }
        }
    }

    close(sockfd);
    return 0;
}

int UDPSocketEngine::run_sender(const std::string& dest_ip, int port,
                                const std::vector<int>& modes,
                                const std::vector<double>& rates,
                                int total_packets, double lambda_pps,
                                int filter_mode, bool is_patched) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "[UDP SENDER ERROR] Failed to create socket.\n";
        return 1;
    }

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "[UDP SENDER ERROR] Invalid destination IP: " << dest_ip << "\n";
        close(sockfd);
        return 1;
    }

    // Load payload templates
    auto normals = qos_harness::FileManager::loadPacketsFromFolder(LOCAL_NORMAL_FOLDER);
    auto attacks = qos_harness::FileManager::loadPacketsFromFolder(LOCAL_ATTACK_FOLDER);

    if (normals.empty() || attacks.empty()) {
        std::cerr << "[UDP SENDER ERROR] Normal or Attack packet datasets missing in inputs/\n";
        close(sockfd);
        return 1;
    }

    std::cout << "======================================================================\n";
    std::cout << "[UDP SENDER TRANSMITTER] Target Receiver: " << dest_ip << ":" << port << "\n";
    std::cout << "[UDP SENDER TRANSMITTER] Batch Matrix Sweep: " << modes.size() << " modes x " << rates.size() << " rates\n";
    std::cout << "======================================================================\n";

    auto send_control = [&](uint32_t magic, int mode, float rate) {
        UDPControlHeader header{};
        header.magic = magic;
        header.mode = mode;
        header.pollution_rate = rate;
        header.total_packets = total_packets;
        header.lambda_pps = lambda_pps;
        header.filter_mode = filter_mode;
        header.is_patched = is_patched ? 1 : 0;

        for (int retry = 0; retry < 3; ++retry) {
            sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };

    uint64_t interval_ns = (lambda_pps > 0) ? static_cast<uint64_t>(1e9 / lambda_pps) : 0;

    for (int mode : modes) {
        for (double rate : rates) {
            std::cout << "\n[UDP SCRIPT STREAMING] Launching Session: Mode=" << mode << " | Rate=" << rate << "% | Pacing=" << lambda_pps << " pps\n";
            send_control(MAGIC_SESSION_START, mode, static_cast<float>(rate));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            auto start_time = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < total_packets; ++i) {
                // Determine attack or normal
                bool is_malware = false;
                double p_rnd = (rand() % 10000) / 100.0;

                if (mode == 0) {
                    is_malware = (p_rnd < rate);
                } else if (mode == 1) {
                    if (i >= total_packets * 0.3 && i <= total_packets * 0.5) {
                        is_malware = (p_rnd < rate * 2.0);
                    }
                } else if (mode == 2) {
                    int cycle = (i / (total_packets / 10)) % 2;
                    if (cycle == 1) {
                        is_malware = (p_rnd < rate * 1.5);
                    }
                }

                const auto& pkt = is_malware ? attacks[i % attacks.size()] : normals[i % normals.size()];
                sendto(sockfd, pkt.data(), pkt.size(), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

                // High-precision pacing sleep
                if (interval_ns > 0) {
                    auto target_time = start_time + std::chrono::nanoseconds((i + 1) * interval_ns);
                    std::this_thread::sleep_until(target_time);
                }
            }

            std::cout << "  [+] Streamed " << total_packets << " packets for Session (Mode=" << mode << ", Rate=" << rate << "%).\n";
            send_control(MAGIC_SESSION_END, mode, static_cast<float>(rate));
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    // Batch completed
    send_control(MAGIC_BATCH_END, 0, 0.0f);
    std::cout << "\n[UDP SENDER COMPLETE] All batch sessions streamed successfully to " << dest_ip << ":" << port << "!\n";

    close(sockfd);
    return 0;
}

} // namespace qos_harness
