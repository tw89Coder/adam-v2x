#include "qos_harness/socket_engine.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>

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
#include "qos_harness/console_presenter.hpp"
#include "qos_harness/rl_bridge.hpp"

#ifndef REPO_ROOT
#define REPO_ROOT "."
#endif

static const std::string LOCAL_REPO_ROOT_STR = REPO_ROOT;
static const std::string LOCAL_NORMAL_FOLDER = LOCAL_REPO_ROOT_STR + "/inputs/base_packets";
static const std::string LOCAL_ATTACK_FOLDER = LOCAL_REPO_ROOT_STR + "/inputs/attack_vectors/malware";

namespace qos_harness {

int UDPSocketEngine::run_receiver(int port, const std::string& build_type, bool no_taskset, const std::string& default_onnx_path) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << ConsolePresenter::crit() << "[UDP RECEIVER ERROR] Failed to create socket.\n" << ConsolePresenter::reset();
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
        std::cerr << ConsolePresenter::crit() << "[UDP RECEIVER ERROR] Failed to bind to port " << port << ".\n" << ConsolePresenter::reset();
        close(sockfd);
        return 1;
    }

    // Display standardized industrial banner
    ConsolePresenter::printUDPReceiverDaemonBanner(port, build_type);

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
                std::cout << "\n" << ConsolePresenter::info() << "[UDP RECEIVER] Received BATCH_END control signal. Exiting receiver daemon loop.\n" << ConsolePresenter::reset();
                break;
            }

            if (header.magic == MAGIC_SESSION_START) {
                int mode = header.mode;
                double rate = header.pollution_rate;
                int total_pkts = header.total_packets;
                double lambda_pps = header.lambda_pps;
                uint32_t filter_mode = header.filter_mode; // 0=OFF, 1=ADAPTIVE, 2=STATIC100

                // Send Handshake ACK back to Sender
                UDPControlHeader ack_header = header;
                ack_header.magic = MAGIC_SESSION_ACK;
                for (int ack_try = 0; ack_try < 3; ++ack_try) {
                    sendto(sockfd, &ack_header, sizeof(ack_header), 0, (struct sockaddr*)&client_addr, client_len);
                }

                // Render session init header using ConsolePresenter
                ConsolePresenter::printUDPSessionHeader(mode, rate, total_pkts, lambda_pps, filter_mode);

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
                    if (filter_mode == 4) {
                        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_codel.csv",
                                      csv_target_dir.c_str(), rate, mode);
                    } else if (filter_mode == 3) {
                        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_onnx.csv",
                                      csv_target_dir.c_str(), rate, mode);
                    } else if (filter_mode == 2) {
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

                // Setup FSM Filter and ONNX RL Bridge
                AdaptiveFilterFSM filter_fsm;
                qos_harness::RLBridge rl_bridge(LOCAL_REPO_ROOT_STR);
                if (filter_mode == 3) {
                    filter_fsm.set_execution_mode(AdaptiveFilterFSM::FilterExecutionMode::ONNX_INFERENCE);
                    filter_fsm.update_policy_params(0.05, 50.0, 600, 0.10);
                    std::string model_to_use = default_onnx_path.empty() ? (LOCAL_REPO_ROOT_STR + "/checkpoints/v2x_agent_dqn.onnx") : default_onnx_path;
                    rl_bridge.initialize_onnx(true, model_to_use);
                    rl_bridge.initialize(false, rate, mode, false);
                } else if (filter_mode == 2) {
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
                int malware_count = 0;
                int total_inspected = 0;
                int true_positives = 0, false_positives = 0, true_negatives = 0, false_negatives = 0;

                bool session_running = true;

                long long inter_arrival_ns = (lambda_pps > 0) ? static_cast<long long>(1e9 / lambda_pps) : 0;
                long long accumulated_queue_ns = 0;

                int print_interval = std::max(1, total_pkts / 100);

                struct timespec session_cpu_start, session_cpu_end;
                clock_gettime(CLOCK_THREAD_CPUTIME_ID, &session_cpu_start);

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

                    // Process Data Packet with 4-byte Ground Truth header
                    if (pkt_len < 4) continue;

                    uint32_t is_malware_flag = 0;
                    std::memcpy(&is_malware_flag, buffer.data(), sizeof(uint32_t));
                    bool is_malware = (is_malware_flag == 1);

                    vanetza::ByteBuffer packet_data(buffer.begin() + 4, buffer.begin() + pkt_len);

                    auto start_t = std::chrono::high_resolution_clock::now();
                    bool is_drop = false;
                    if (filter_mode == 4) {
                        // CoDel AQM Baseline (target = 5.0ms)
                        double queue_delay_ms = accumulated_queue_ns / 1e6;
                        if (queue_delay_ms > 5.0) {
                            is_drop = true;
                        }
                        total_inspected++;
                    } else if (filter_mode != 0) {
                        is_drop = filter_fsm.process_packet(packet_data);
                        if (filter_fsm.was_inspected()) {
                            total_inspected++;
                        }
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

                    if (is_malware) malware_count++;

                    if (is_drop) {
                        if (is_malware) true_positives++; else false_positives++;
                    } else {
                        if (is_malware) false_negatives++; else true_negatives++;
                    }

                    // Record metric
                    collector.recordPacket(received_pkts, is_malware, is_drop, total_latency_ns);

                    // Sync RL telemetry and ONNX window update for DRL control plane
                    if (filter_mode == 3) {
                        rl_bridge.collect_packet_telemetry(packet_data.size(), filter_fsm.get_last_sq(), filter_fsm.current_budget,
                                                           static_cast<int>(filter_fsm.get_state()), is_drop, is_malware,
                                                           filter_fsm.was_inspected(), filter_fsm.get_last_latency_ticks());
                        if (received_pkts % 100 == 0) {
                            rl_bridge.check_and_sync_window(received_pkts, filter_fsm);
                        }
                    }
                    received_pkts++;

                    // Single-line real-time simulation progress telemetry
                    if (received_pkts % print_interval == 0 || received_pkts == total_pkts) {
                        double actual_avg_rate = (received_pkts > 0) ? (static_cast<double>(total_inspected) / received_pkts) * 100.0 : 0.0;
                        double current_target_rate = (filter_mode != 0) ? filter_fsm.get_sampling_rate() * 100.0 : 0.0;
                        ConsolePresenter::printSimulationProgress(
                            received_pkts, total_pkts, malware_count,
                            filter_mode != 0, actual_avg_rate, current_target_rate
                        );
                    }
                }

                clock_gettime(CLOCK_THREAD_CPUTIME_ID, &session_cpu_end);
                double cpu_time_sec = (session_cpu_end.tv_sec - session_cpu_start.tv_sec) + 
                                         (session_cpu_end.tv_nsec - session_cpu_start.tv_nsec) * 1e-9;

                // Export CSV Log
                collector.exportToCSV(out_filename);

                // Append session transport telemetry to summary CSV
                std::string stats_summary_dir = LOCAL_REPO_ROOT_STR + "/outputs/stats";
                mkdir(stats_summary_dir.c_str(), 0755);
                std::string summary_csv_path = stats_summary_dir + "/udp_transport_summary.csv";

                struct rusage usage;
                getrusage(RUSAGE_SELF, &usage);
                long peak_rss_kb = usage.ru_maxrss;

                int total_sent = total_pkts;
                int dropped_pkts = (total_sent > received_pkts) ? (total_sent - received_pkts) : 0;
                double drop_rate_pct = (total_sent > 0) ? (static_cast<double>(dropped_pkts) / total_sent) * 100.0 : 0.0;
                double insp_rate_pct = (received_pkts > 0) ? (static_cast<double>(total_inspected) / received_pkts) * 100.0 : 0.0;
                double fpr_pct = (false_positives + true_negatives > 0) ? (static_cast<double>(false_positives) / (false_positives + true_negatives)) * 100.0 : 0.0;
                double fnr_pct = (false_negatives + true_positives > 0) ? (static_cast<double>(false_negatives) / (false_negatives + true_positives)) * 100.0 : 0.0;

                bool exists = (access(summary_csv_path.c_str(), F_OK) == 0);
                std::ofstream sum_file(summary_csv_path, std::ios::out | std::ios::app);
                if (sum_file.is_open()) {
                    if (!exists) {
                        sum_file << "mode,rate,filter_mode,total_sent,received_pkts,dropped_pkts,drop_rate_pct,total_inspected,inspection_rate_pct,malware_count,tp,tn,fp,fn,fpr_pct,fnr_pct,cpu_time_sec,peak_rss_kb,out_filename\n";
                    }
                    sum_file << mode << "," << rate << "," << filter_mode << ","
                             << total_sent << "," << received_pkts << "," << dropped_pkts << ","
                             << drop_rate_pct << "," << total_inspected << "," << insp_rate_pct << ","
                             << malware_count << "," << true_positives << "," << true_negatives << ","
                             << false_positives << "," << false_negatives << ","
                             << fpr_pct << "," << fnr_pct << "," << cpu_time_sec << "," << peak_rss_kb << "," << out_filename << "\n";
                    sum_file.close();
                }

                // Print industrial security report if filter was active
                if (filter_mode != 0) {
                    ConsolePresenter::printSecurityReport(received_pkts, malware_count, true_positives, true_negatives, false_positives, false_negatives);
                }

                std::cout << ConsolePresenter::green() << "[+] [SESSION COMPLETE] Saved telemetry matrix to " << out_filename
                          << " | Received: " << received_pkts << " frames | Transport Loss: " << dropped_pkts << " (" << drop_rate_pct << "%)" << ConsolePresenter::reset() << "\n";
                ConsolePresenter::printHorizontalSeparator();
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
        std::cerr << ConsolePresenter::crit() << "[UDP SENDER ERROR] Failed to create socket.\n" << ConsolePresenter::reset();
        return 1;
    }

    // Set 500ms socket timeout for ACK response validation
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 500ms
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    sockaddr_in dest_addr{};
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(dest_ip.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        std::cerr << ConsolePresenter::crit() << "[UDP SENDER ERROR] Unable to resolve destination host/IP: " << dest_ip << "\n" << ConsolePresenter::reset();
        close(sockfd);
        return 1;
    }
    std::memcpy(&dest_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    // Load payload templates
    auto normals = qos_harness::FileManager::loadPacketsFromFolder(LOCAL_NORMAL_FOLDER);
    auto attacks = qos_harness::FileManager::loadPacketsFromFolder(LOCAL_ATTACK_FOLDER);

    if (normals.empty() || attacks.empty()) {
        std::cerr << ConsolePresenter::crit() << "[UDP SENDER ERROR] Normal or Attack packet datasets missing in inputs/\n" << ConsolePresenter::reset();
        close(sockfd);
        return 1;
    }

    // Print Sender Industrial Banner
    ConsolePresenter::printUDPSenderBanner(dest_ip, port, modes.size(), rates.size());

    uint64_t interval_ns = (lambda_pps > 0) ? static_cast<uint64_t>(1e9 / lambda_pps) : 0;
    int print_interval = std::max(1, total_packets / 100);

    std::vector<uint8_t> ack_buf(sizeof(UDPControlHeader));
    sockaddr_in reply_addr{};
    socklen_t reply_len = sizeof(reply_addr);

    for (int mode : modes) {
        for (double rate : rates) {
            ConsolePresenter::printUDPSessionHeader(mode, rate, total_packets, lambda_pps, filter_mode);

            UDPControlHeader start_header{};
            start_header.magic = MAGIC_SESSION_START;
            start_header.mode = mode;
            start_header.pollution_rate = static_cast<float>(rate);
            start_header.total_packets = total_packets;
            start_header.lambda_pps = lambda_pps;
            start_header.filter_mode = filter_mode;
            start_header.is_patched = is_patched ? 1 : 0;

            bool ack_received = false;
            std::cout << ConsolePresenter::warn() << "  [*] Connecting & sending START_SESSION handshake to Pi (" << dest_ip << ":" << port << ")..." << ConsolePresenter::reset() << "\n";

            for (int attempt = 1; attempt <= 20; ++attempt) {
                sendto(sockfd, &start_header, sizeof(start_header), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                ssize_t ack_bytes = recvfrom(sockfd, ack_buf.data(), ack_buf.size(), 0, (struct sockaddr*)&reply_addr, &reply_len);
                if (ack_bytes == sizeof(UDPControlHeader)) {
                    UDPControlHeader ack_hdr;
                    std::memcpy(&ack_hdr, ack_buf.data(), sizeof(UDPControlHeader));
                    if (ack_hdr.magic == MAGIC_SESSION_ACK) {
                        ack_received = true;
                        std::cout << ConsolePresenter::safe() << "  [+] Handshake ACK confirmed from Pi! Starting packet stream...\n" << ConsolePresenter::reset();
                        break;
                    }
                }
                std::cout << ConsolePresenter::warn() << "  [!] Handshake Attempt " << attempt << "/20 timeout. Retrying...\r" << ConsolePresenter::reset() << std::flush;
            }

            if (!ack_received) {
                std::cerr << "\n" << ConsolePresenter::crit() << "[-] [UDP CONNECTIVITY ERROR] Unable to reach Pi at " << dest_ip << ":" << port << "!\n"
                          << "[-] Please check: 1) Is receiver running on Pi? 2) Windows Firewall blocking UDP port " << port << "? 3) Ping " << dest_ip << " from WSL.\n"
                          << ConsolePresenter::reset();
                close(sockfd);
                return 1;
            }

            auto start_time = std::chrono::high_resolution_clock::now();
            int malware_count = 0;

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

                if (is_malware) malware_count++;

                const auto& pkt = is_malware ? attacks[i % attacks.size()] : normals[i % normals.size()];
                vanetza::ByteBuffer tx_buf(4 + pkt.size());
                uint32_t flag = is_malware ? 1 : 0;
                std::memcpy(tx_buf.data(), &flag, sizeof(uint32_t));
                std::memcpy(tx_buf.data() + 4, pkt.data(), pkt.size());
                sendto(sockfd, tx_buf.data(), tx_buf.size(), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

                // Real-time sender progress update
                if ((i + 1) % print_interval == 0 || i == total_packets - 1) {
                    ConsolePresenter::printSimulationProgress(i + 1, total_packets, malware_count, false, 0.0, 0.0);
                }

                // High-precision pacing sleep
                if (interval_ns > 0) {
                    auto target_time = start_time + std::chrono::nanoseconds((i + 1) * interval_ns);
                    std::this_thread::sleep_until(target_time);
                }
            }

            std::cout << ConsolePresenter::safe() << "  [+] Streamed " << total_packets << " packets for Session (Mode=" << mode << ", Rate=" << rate << "%).\n" << ConsolePresenter::reset();

            // Send Session End control
            UDPControlHeader end_header = start_header;
            end_header.magic = MAGIC_SESSION_END;
            for (int retry = 0; retry < 3; ++retry) {
                sendto(sockfd, &end_header, sizeof(end_header), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    // Batch completed
    UDPControlHeader batch_header{};
    batch_header.magic = MAGIC_BATCH_END;
    for (int retry = 0; retry < 3; ++retry) {
        sendto(sockfd, &batch_header, sizeof(batch_header), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::cout << "\n" << ConsolePresenter::green() << "[UDP SENDER COMPLETE] All batch sessions streamed successfully to " << dest_ip << ":" << port << "!\n" << ConsolePresenter::reset();

    close(sockfd);
    return 0;
}

} // namespace qos_harness
